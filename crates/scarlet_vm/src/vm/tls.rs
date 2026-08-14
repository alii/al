//! TLS client connections, on rustls.
//!
//! # Why rustls, and not a binding to a C library
//!
//! The deciding property is not that rustls is written in Rust — it is that it
//! is **sans-IO**. rustls never owns a socket, never calls `read(2)` and never
//! blocks; it is a state machine you feed ciphertext to and take ciphertext
//! from. That is exactly the shape this VM needs, because this VM already owns
//! the I/O: sockets are non-blocking, readiness comes from [`super::poll`], and
//! an operation that cannot finish parks its Scarlet process rather than its
//! OS thread.
//!
//! OpenSSL, BoringSSL and SChannel all want to do their own I/O. Bending one of
//! them into this loop means either a BIO pair — which is the same sans-IO
//! design with an extra copy through a C buffer and an unaudited C library
//! underneath — or a thread per connection, which gives up the property the
//! scheduler exists to provide. `native-tls` is worse again for a language
//! standard library: three implementations behind one API, so a certificate
//! error a Scarlet program matches on would mean three different things on
//! three platforms, and `TlsError` would have to degrade to a string.
//!
//! The backend is `aws-lc-rs`, rustls's default, which is faster than `ring`
//! on both handshake and bulk throughput.
//!
//! # How it maps onto the park protocol
//!
//! A TLS read may need to *write* (a handshake reply, a key update) and a TLS
//! write may need to *read*. That would be a problem if a park named a
//! direction — but it does not. [`Wait::readable`] and [`Wait::writable`] are
//! the same constructor, because interest is fixed at registration and a
//! connection is registered `READABLE | WRITABLE`. A park names the fd, and
//! readiness in either direction wakes it. So TLS composes with the existing
//! **re-run** protocol unchanged: park on the fd, re-run the instruction, and
//! let rustls re-derive what it needs next from state it kept itself.
//!
//! Nearly every park here follows a genuine `WouldBlock` from the fd, which is
//! what an edge-triggered poller requires: the edge that wakes us is the one
//! that arrives after the buffer we just found full has drained.
//!
//! **One park does not, and this paragraph used to claim they all did.**
//! [`TlsIo::write`] synthesizes a `WouldBlock` when the session refuses the
//! plaintext because its own send buffer is at its limit. It calls `flush_out`
//! first to make room — and if that flush SUCCEEDS, the last thing that touched
//! the fd was a write that worked, so there may be no edge left to arrive and
//! the park would be waiting on one. Nobody has constructed an input that
//! reaches it: the buffer is at its limit only because an earlier flush could
//! not empty it, which is the case where this one cannot either. That is an
//! argument, not a proof, so it is written down rather than relied on.
//!
//! # Why reads and writes are not new opcodes
//!
//! Encryption is a property of the connection table ENTRY ([`ConnIo::Tls`]),
//! not of the instruction. `Op::TcpRead` on a TLS entry decrypts, because the
//! entry decrypts. So `tls.read` and `tls.write` compile to the same opcodes as
//! their cleartext counterparts and inherit their parking, migration and
//! ownership behaviour for free. What stops a program reading a TLS connection
//! in the clear is Scarlet's type system: `TlsSocket` and `Socket` are
//! different types, and there is no cast between them.
//!
//! The handle carries the same distinction as a backstop
//! ([`SocketKind::Tls`]), so a handle that somehow outlived its upgrade cannot
//! be replayed against the wrong entry: [`super::io::stream_entry`] refuses a
//! handle whose kind disagrees with the entry's.

use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;

use crate::abi::AbiSlot;
use crate::bytecode::{SocketKind, SocketValue, Value};

use super::io::stale_socket;
use super::poll::{EPOCH, Parked, Wait, monotonic_now_ms};
use super::port::ConnIo;
use super::{IO_REDUCTION_COST, VM, VmError, VmResult, bin_ref, str_ref};

/// A TLS connection: the transport, and the session state over it.
///
/// Boxed because `ClientConnection` is large and a `ConnIo` is stored inline in
/// every connection-table entry, cleartext ones included.
pub(super) struct TlsIo {
    tcp: TcpStream,
    session: Box<ClientConnection>,
}

/// How a TLS operation failed. Kept apart from `io::Error` because the two
/// become different Scarlet values: a transport failure is a `NetError` inside
/// `TlsError::Transport` and may be worth retrying, a session failure is a
/// `TlsError` variant of its own and is not.
pub(super) enum TlsFail {
    /// The socket under TLS failed. `WouldBlock` travels this way too, and is
    /// the signal to park.
    Io(io::Error),
    /// The TLS session failed: a certificate that did not verify, an alert, a
    /// version or suite mismatch.
    Session(rustls::Error),
    /// The requested name is neither a DNS name nor an IP address, so there is
    /// nothing a certificate could be checked against.
    InvalidServerName,
}

impl From<io::Error> for TlsFail {
    fn from(e: io::Error) -> Self {
        TlsFail::Io(e)
    }
}

impl TlsFail {
    /// Whether this is the "not ready yet" signal rather than a real failure.
    fn is_would_block(&self) -> bool {
        matches!(self, TlsFail::Io(e) if e.kind() == ErrorKind::WouldBlock)
    }
}

impl TlsIo {
    /// The fd, for poller registration. One fd, exactly as a cleartext
    /// connection has: TLS adds no descriptor of its own.
    pub(super) fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.tcp.as_raw_fd()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.tcp.peer_addr()
    }

    /// Push whatever ciphertext rustls has queued at the socket. Returns
    /// `WouldBlock` if the socket filled before the queue emptied — the
    /// remainder stays in rustls, so re-running this is safe and never
    /// duplicates a byte.
    fn flush_out(&mut self) -> io::Result<()> {
        while self.session.wants_write() {
            self.session.write_tls(&mut self.tcp)?;
        }
        Ok(())
    }

    /// Pull one batch of ciphertext in and process it. `Ok(false)` means the
    /// peer closed the TCP connection.
    fn pump_in(&mut self) -> Result<bool, TlsFail> {
        match self.session.read_tls(&mut self.tcp) {
            Ok(0) => return Ok(false),
            Ok(_) => {}
            Err(e) => return Err(TlsFail::Io(e)),
        }
        self.session
            .process_new_packets()
            .map_err(TlsFail::Session)?;
        Ok(true)
    }

    /// Drive the handshake as far as the socket allows.
    ///
    /// Returns `Err(TlsFail::Io(WouldBlock))` when it needs the socket to
    /// become ready again; the caller parks and calls back in. rustls keeps all
    /// the state, so re-entering continues rather than restarting — which is
    /// what makes this safe under the re-run protocol.
    fn drive_handshake(&mut self) -> Result<(), TlsFail> {
        while self.session.is_handshaking() {
            // Send before receiving: the peer cannot answer a ClientHello that
            // is still sitting in our buffer, so reading first would deadlock.
            self.flush_out()?;
            if !self.session.is_handshaking() {
                break;
            }
            if !self.pump_in()? {
                // A peer that hangs up mid-handshake is not a TLS failure with
                // an alert to report; it is a truncated connection.
                return Err(TlsFail::Io(io::Error::from(ErrorKind::UnexpectedEof)));
            }
        }
        // The last flight of the handshake may still be queued.
        self.flush_out()?;
        Ok(())
    }

    /// Whether the handshake has finished.
    fn is_established(&self) -> bool {
        !self.session.is_handshaking()
    }

    /// Begin an orderly shutdown: queue `close_notify` and push it. Without the
    /// alert a peer cannot distinguish an intentional end of stream from a
    /// truncation attack, and a correct peer reports an error.
    ///
    /// `Err` means the alert did not reach the kernel, and `WouldBlock` is one
    /// of the ways — a socket that filled leaves the alert in userspace, and
    /// the caller closes the fd immediately afterwards, so it is never sent at
    /// all. That is a report, not a retry: the caller cannot make it succeed by
    /// calling again, because by then the connection is gone. Reporting it is
    /// the only thing that stops `tls.close` telling a program the peer was
    /// told when it was not.
    fn send_close_notify(&mut self) -> io::Result<()> {
        self.session.send_close_notify();
        self.flush_out()
    }
}

/// Reading decrypts. A read that needs to write first (a key update, a
/// post-handshake message) does so here, and a `WouldBlock` from either
/// direction propagates so the caller parks on the one fd.
impl Read for TlsIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.session.reader().read(buf) {
                // `Ok(0)` is a clean `close_notify`: the peer ended the stream
                // on purpose, which is the same thing a cleartext `read` of 0
                // means, and reaches Scarlet as `Read::Closed`.
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            // No plaintext buffered. Flush anything owed, then take more
            // ciphertext; either step may park us.
            self.flush_out()?;
            match self.session.read_tls(&mut self.tcp) {
                // TCP EOF without `close_notify`. Reported as end of stream
                // rather than an error: a truncation is indistinguishable from
                // a peer that simply omits the alert, and enough of them do
                // that erroring here breaks ordinary hosts.
                Ok(0) => return Ok(0),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            // Tagged `InvalidData` so the op above can tell a TLS session
            // failure from a socket failure and build the right Scarlet
            // variant. `io::Error::other` would arrive with no errno and be
            // reported as the meaningless `Transport(Errno(0))`.
            self.session
                .process_new_packets()
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
        }
    }
}

/// Writing encrypts. `write` reports the PLAINTEXT it accepted into the
/// session, which is what lets the caller's drain loop advance its offset
/// correctly; the ciphertext is pushed here on a best-effort basis and
/// finished by `flush`.
impl Write for TlsIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let accepted = self.session.writer().write(buf)?;
        if accepted == 0 && !buf.is_empty() {
            // The session's send buffer is full; it drains only by reaching
            // the socket, so make room and let the caller retry.
            self.flush_out()?;
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        match self.flush_out() {
            // Reporting the plaintext as accepted is correct even with
            // ciphertext still queued: it IS accepted, and `flush` is what
            // guarantees it reaches the kernel. Returning an error here would
            // make the caller re-send plaintext the session already holds.
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(accepted),
            Err(e) => Err(e),
            Ok(()) => Ok(accepted),
        }
    }

    /// The guarantee behind `tls.write` returning `Ok`: every byte of
    /// ciphertext is with the kernel. A `WouldBlock` here parks the writer, and
    /// the re-run flushes the rest — it does not re-send plaintext.
    fn flush(&mut self) -> io::Result<()> {
        self.flush_out()
    }
}

/// The process-wide client configuration: trust roots, and the session cache
/// that makes a second connection to a host cheaper than the first.
///
/// One config for the program, shared by every scheduler behind an `Arc`.
/// That is not only an allocation saving — rustls hangs the session store off
/// the config, so sharing it is what lets a connection resume a session that a
/// DIFFERENT Scarlet process, on a different core, established earlier.
static CLIENT_CONFIG: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();

/// Build the client config. Called once.
///
/// Trust roots come from the machine's own store first, with `webpki-roots` as
/// the fallback. That order is deliberate: a program that works in `curl` on
/// this hardware should work in Scarlet on this hardware, which means honouring
/// the CAs an administrator added — a corporate inspection proxy, an internal
/// CA, a locally trusted test root. The bundled set is the fallback so that a
/// container with no certificate store still reaches the public internet
/// instead of failing every connection at the first handshake.
///
/// Session resumption is left at rustls's default, which is enabled: TLS 1.3
/// tickets and TLS 1.2 session ids, in an in-memory store on this config. It is
/// deliberately NOT persisted to disk — a session ticket is key material, and
/// writing it to the filesystem is a decision a language runtime should not
/// make silently on a program's behalf.
fn build_client_config() -> Result<Arc<ClientConfig>, String> {
    // With exactly one backend feature enabled this is the only provider, but
    // installing it explicitly means `builder()` cannot pick up a different
    // process default that an embedder installed first.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        // A store with one unparseable certificate in it is still a usable
        // store; skipping the bad entry is what every other client does.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if roots.is_empty() {
        return Err(
            "no TLS trust roots: neither the platform store nor the bundled set \
                    yielded a usable certificate"
                .to_string(),
        );
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The shared client config, or the reason there is none.
fn client_config() -> Result<Arc<ClientConfig>, String> {
    CLIENT_CONFIG.get_or_init(build_client_config).clone()
}

impl VM {
    /// `Op::TlsHandshake`: `[socket, server_name] -> Result(TlsSocket, TlsError)`.
    ///
    /// Re-keys the connection. The cleartext entry leaves the table and a TLS
    /// entry takes its place under a NEW id, so the `Socket` handle the caller
    /// passed in is stale the moment this succeeds and every cleartext
    /// operation on it errs with `NotConnected`. That is what stops a caller
    /// keeping the plaintext handle and writing around the encryption; the type
    /// system stops the honest mistake, and this stops the determined one.
    ///
    /// Parks and re-runs while the handshake is in flight. On a re-run the
    /// entry is already `ConnIo::Tls`, so the session is continued rather than
    /// started again.
    pub(super) fn tls_handshake(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        let name_v = self.pop_str("tls.handshake")?;
        let sock_val = self.pop()?;
        let sv = stream_handle(&sock_val, "tls.handshake")?;

        // First entry: take the cleartext connection over. On a re-run after a
        // park the handle is already a TLS one and this is skipped.
        let id = if sv.kind == SocketKind::Tls {
            sv.id
        } else {
            let server_name = str_ref(&name_v).to_string();
            match self.begin_tls(sv.id, &server_name) {
                Ok(id) => id,
                Err(fail) => {
                    let err = self.tls_error_value(fail)?;
                    let v = self.make_err(err)?;
                    self.stack.push(v);
                    return Ok(None);
                }
            }
        };

        let Some(conn) = self.connections.get_mut(&id) else {
            self.push_tls_transport(stale_socket())?;
            return Ok(None);
        };
        let ConnIo::Tls(tls) = &mut conn.io else {
            return Err(VmError::internal("tls.handshake on a cleartext connection"));
        };

        match tls.drive_handshake() {
            Ok(()) => {
                let peer = tls.peer_addr();
                let established = tls.is_established();
                debug_assert!(established, "drive_handshake returned before establishing");
                let peer = match peer {
                    Ok(p) => p,
                    Err(e) => {
                        self.push_tls_transport(e)?;
                        return Ok(None);
                    }
                };
                let handle = Value::socket(SocketValue {
                    id,
                    kind: SocketKind::Tls,
                });
                let peer_v = self.templates.socket_address(&mut self.heap, peer)?;
                let name_out = Value::str_in(&mut self.heap, str_ref(&name_v));
                let record = self.abi_make(AbiSlot::TlsSocket, &[handle, peer_v, name_out])?;
                let v = self.make_ok(record)?;
                self.stack.push(v);
                Ok(None)
            }
            Err(fail) if fail.is_would_block() => {
                // Re-push the operands with the handle now naming the TLS
                // entry, so the re-run continues this session.
                self.stack.push(Value::socket(SocketValue {
                    id,
                    kind: SocketKind::Tls,
                }));
                self.stack.push(name_v);
                Ok(Some(Parked::retry(Wait::readable(id))))
            }
            Err(fail) => {
                // A failed handshake leaves nothing usable. Drop the connection
                // rather than leaving a half-open entry a caller cannot name.
                drop(self.evict_connection(id));
                let err = self.tls_error_value(fail)?;
                let v = self.make_err(err)?;
                self.stack.push(v);
                Ok(None)
            }
        }
    }

    /// Replace cleartext connection `id` with a TLS one under a fresh id.
    /// Returns the new id.
    fn begin_tls(&mut self, id: i32, server_name: &str) -> Result<i32, TlsFail> {
        let config = client_config().map_err(|e| TlsFail::Io(io::Error::other(e)))?;
        // `ServerName` parses an IP literal into `ServerName::IpAddress` rather
        // than rejecting it, so an address is verified against the certificate's
        // IP SANs like any other name and a certificate carrying none fails as
        // `HostnameMismatch`. This arm is only reached by a name that is neither
        // a DNS name nor an address, which no certificate could be checked
        // against — a caller error rather than a certificate one.
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| TlsFail::InvalidServerName)?;
        let session = ClientConnection::new(config, name).map_err(TlsFail::Session)?;

        // Retire the cleartext id WITHOUT going through `evict_connection`: the
        // fd survives into the TLS entry, so its poller registration is rebuilt
        // under the new id rather than torn down and lost. The ID does not
        // survive, though, and `retire_socket_id` is what makes those two facts
        // separate — it fails every park on the id as it removes the entry. A
        // sibling already parked in `socket.read` when a STARTTLS or a proxied
        // `CONNECT` upgrades under it is woken here onto the gone-socket error;
        // left behind, nothing could ever reach it and the program would never
        // end.
        let Some(conn) = self.retire_socket_id(id) else {
            return Err(TlsFail::Io(stale_socket()));
        };
        let owner = conn.owner;
        let ConnIo::Tcp(tcp) = conn.io else {
            // Put it back: a port is not something to secure, and losing the
            // entry would leak the child. Any waiter the retire just woke
            // re-runs, finds the entry where it left it and parks again — one
            // wasted slice on a path a Scarlet program cannot reach anyway,
            // since `tls.handshake` takes a `Socket` and a port handle carries
            // `SocketKind::Port`.
            self.connections.insert(id, conn);
            return Err(TlsFail::Io(io::Error::other(
                "tls.handshake applied to a port, not a TCP connection",
            )));
        };
        // The fd survives into the TLS entry, so its registration is rebuilt
        // under the new id by `track_connection` below rather than torn down.
        self.poller_deregister(std::os::fd::AsRawFd::as_raw_fd(&tcp));

        let tls = TlsIo {
            tcp,
            session: Box::new(session),
        };
        let new_id = self.alloc_socket_id();
        if let Err((e, _dropped)) = self.track_connection(new_id, ConnIo::Tls(tls), owner) {
            return Err(TlsFail::Io(e));
        }
        Ok(new_id)
    }

    /// `Op::TlsClose`: `[tls_socket] -> Result(Nil, TlsError)`. Sends
    /// `close_notify`, then evicts the connection exactly as `socket.close`
    /// does.
    ///
    /// **The connection closes either way, and the result says whether the peer
    /// was told.** Those are two questions and this op answers the second,
    /// because the first has no other answer: the fd is gone by the time this
    /// returns and no retry can reach it. `Err` therefore means the alert did
    /// not make it out, so the peer sees a stream that simply stops — byte for
    /// byte what a truncation looks like, which is the one thing this op exists
    /// to rule out. Swallowing that is what makes the `Err` arm of
    /// `Result(Nil, TlsError)` unreachable and the signature a promise the body
    /// never keeps.
    ///
    /// A handle the table no longer holds is still `Ok`: closing a connection
    /// that is already closed is not a failure, and whatever the peer was told
    /// was settled at the close that actually happened.
    pub(super) fn tls_close(&mut self, reds: &mut i32) -> VmResult<()> {
        *reds -= IO_REDUCTION_COST;
        let sock_val = self.pop()?;
        let sv = stream_handle(&sock_val, "tls.close")?;
        let alert = match self.connections.get_mut(&sv.id).map(|c| &mut c.io) {
            Some(ConnIo::Tls(tls)) => tls.send_close_notify(),
            // Nothing to tell anyone: the id is stale, or it names an entry
            // that was never a TLS session and so owes no alert.
            _ => Ok(()),
        };
        drop(self.evict_connection(sv.id));
        match alert {
            Ok(()) => {
                let nil = self.make_nil()?;
                let v = self.make_ok(nil)?;
                self.stack.push(v);
            }
            Err(e) => self.push_tls_transport(e)?,
        }
        Ok(())
    }

    /// `Op::TlsRead`: `[tls_socket, max] -> Result(Read, TlsError)`.
    ///
    /// The same shape as `Op::TcpRead`, and it shares the read machinery; it
    /// exists separately because its failures become `TlsError` values and
    /// `Op::TcpRead`'s become `NetError` ones. Reusing the cleartext opcode
    /// would have the VM construct a `NetError` where the Scarlet signature
    /// promises a `TlsError` — a type confusion no test would catch until a
    /// program matched on the wrong variant.
    pub(super) fn tls_read(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        let max = self.pop_int("tls.read")?;
        let sock_val = self.pop()?;
        let sv = stream_handle(&sock_val, "tls.read")?;
        let (max, read_res) = self.socket_read(sv, max);
        match read_res {
            Ok(n) => self.push_read_ok(n)?,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                self.stack.push(sock_val);
                self.stack.push(Value::small_int(max as i64));
                return Ok(Some(Parked::retry(Wait::readable(sv.id))));
            }
            Err(e) => self.push_tls_io(e)?,
        }
        Ok(None)
    }

    /// `Op::TlsReadUntil`: `[tls_socket, max, deadline_ms] -> Result(Read, TlsError)`.
    ///
    /// The same shape as `Op::TcpReadUntil`, including the deadline-captured-
    /// once-in-Scarlet discipline: a re-run re-reads the absolute monotonic ms
    /// and never resets the clock. Split from that opcode because a timeout
    /// here is `TlsError::Transport(TimedOut)`, not a bare `NetError`.
    pub(super) fn tls_read_until(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        // Stack, top first: the deadline as an absolute monotonic ms, the max
        // byte count, then the socket. Scarlet captures the deadline once, so a
        // re-run after a wake re-reads it and never resets the clock.
        let deadline_ms = self.pop_int("tls.read_within")?;
        let max = self.pop_int("tls.read_within")?;
        let sock_val = self.pop()?;
        let sv = stream_handle(&sock_val, "tls.read_within")?;
        let (max, read_res) = self.socket_read(sv, max);
        match read_res {
            // The read runs before the deadline check, so bytes that arrived
            // as the clock ran out are never discarded.
            Ok(n) => self.push_read_ok(n)?,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if monotonic_now_ms() >= deadline_ms {
                    let timed_out = self.abi_nullary(AbiSlot::NetEtimedout)?;
                    let err = self.abi_make(AbiSlot::TlsTransport, &[timed_out])?;
                    let v = self.make_err(err)?;
                    self.stack.push(v);
                } else {
                    self.stack.push(sock_val);
                    self.stack.push(Value::small_int(max as i64));
                    self.stack.push(Value::small_int(deadline_ms));
                    let deadline = *EPOCH.get_or_init(Instant::now)
                        + Duration::from_millis(deadline_ms.max(0) as u64);
                    return Ok(Some(Parked::retry(Wait::read_with_deadline(
                        sv.id, deadline,
                    ))));
                }
            }
            Err(e) => self.push_tls_io(e)?,
        }
        Ok(None)
    }

    /// `Op::TlsWrite`: `[tls_socket, data] -> Result(Nil, TlsError)`.
    ///
    /// Returns only once the ciphertext is with the kernel — see
    /// [`super::io::Drain::Flushing`] for why that needs a flush step the
    /// cleartext path does not.
    pub(super) fn tls_write(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        let bin_v = self.pop_binary("tls.write")?;
        let sock_val = self.pop()?;
        let sv = stream_handle(&sock_val, "tls.write")?;
        if !bin_ref(&bin_v).bit_len().is_multiple_of(8) {
            // Same rejection the cleartext path makes, wrapped as a transport
            // cause: a partial byte cannot be put on the wire encrypted either.
            let cause = self.abi_nullary(AbiSlot::NetUnalignedBinary)?;
            let err = self.abi_make(AbiSlot::TlsTransport, &[cause])?;
            let v = self.make_err(err)?;
            self.stack.push(v);
            return Ok(None);
        }
        let bin = bin_ref(&bin_v);
        let bytes = bin.full_bytes();
        let result = super::io::stream_entry(&mut self.connections, sv)
            .and_then(|conn| super::io::drain_and_flush(conn, std::slice::from_ref(&bytes)));
        let park_at = match &result {
            Ok(super::io::Drain::Park { offset, .. }) => Some(*offset),
            // Everything was accepted; the re-run only finishes the flush.
            Ok(super::io::Drain::Flushing) => Some(bytes.len()),
            Ok(super::io::Drain::Done) | Err(_) => None,
        };
        if let Some(offset) = park_at {
            self.stack.push(sock_val);
            let tail = self.tail_view(bin, offset);
            self.stack.push(tail);
            return Ok(Some(Parked::retry(Wait::writable(sv.id))));
        }
        match result {
            Ok(_) => {
                let nil = self.make_nil()?;
                let v = self.make_ok(nil)?;
                self.stack.push(v);
            }
            Err(e) => self.push_tls_io(e)?,
        }
        Ok(None)
    }

    /// Push the `TlsError` for an `io::Error` raised while the session was
    /// established. `InvalidData` is the tag [`TlsIo`] puts on a rustls session
    /// failure, which is a protocol error rather than a transport one.
    fn push_tls_io(&mut self, e: io::Error) -> VmResult<()> {
        let err = if e.kind() == ErrorKind::InvalidData {
            self.abi_nullary(AbiSlot::TlsProtocolError)?
        } else {
            self.tls_error_value(TlsFail::Io(e))?
        };
        let v = self.make_err(err)?;
        self.stack.push(v);
        Ok(())
    }

    /// Build the Scarlet `TlsError` for a failure.
    fn tls_error_value(&mut self, fail: TlsFail) -> VmResult<Value> {
        match fail {
            TlsFail::InvalidServerName => self.abi_nullary(AbiSlot::TlsInvalidServerName),
            TlsFail::Io(e) => {
                let cause = self.net_error_value(&e)?;
                self.abi_make(AbiSlot::TlsTransport, &[cause])
            }
            TlsFail::Session(e) => self.abi_nullary(session_error_slot(&e)),
        }
    }

    /// Push `Err(TlsError::Transport(..))` for a socket-level failure.
    fn push_tls_transport(&mut self, e: io::Error) -> VmResult<()> {
        let err = self.tls_error_value(TlsFail::Io(e))?;
        let v = self.make_err(err)?;
        self.stack.push(v);
        Ok(())
    }
}

/// Map a rustls session failure onto its `TlsError` variant.
///
/// Certificate failures are separated by cause, because a caller acts on them
/// differently: an expired certificate may be worth reporting to the peer's
/// operator, an unknown issuer usually means a missing root on THIS machine,
/// and a name mismatch means the caller asked for the wrong host — often by
/// reusing a pooled connection under the wrong key.
fn session_error_slot(e: &rustls::Error) -> AbiSlot {
    use rustls::CertificateError;
    use rustls::Error;
    match e {
        Error::InvalidCertificate(c) => match c {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                AbiSlot::TlsCertExpired
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                AbiSlot::TlsCertNotYetValid
            }
            CertificateError::Revoked => AbiSlot::TlsCertRevoked,
            CertificateError::UnknownIssuer => AbiSlot::TlsCertUnknownIssuer,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                AbiSlot::TlsHostnameMismatch
            }
            _ => AbiSlot::TlsBadCertificate,
        },
        // A peer that answers a ClientHello with something that is not TLS —
        // an `http` port, or a proxy's error page — lands here.
        Error::InvalidMessage(_)
        | Error::NoCertificatesPresented
        | Error::UnsupportedNameType
        | Error::DecryptError
        | Error::EncryptError
        | Error::PeerIncompatible(_) => AbiSlot::TlsProtocolError,
        _ => AbiSlot::TlsHandshakeFailed,
    }
}

/// Extract the handle from a `Socket` or `TlsSocket` record.
///
/// Both records keep it in field 0, and both are accepted: `tls.handshake`
/// takes the cleartext one from Scarlet, and its own re-run takes the TLS one.
///
/// A BARE handle is accepted too, and that is not laxity — it is the operand a
/// parked handshake re-pushes. The record it was handed named the connection
/// under its cleartext id, which the upgrade has already retired; re-pushing
/// that record would send the re-run back to an id that is deliberately gone.
/// So the park pushes the handle for the new TLS entry instead, and this is
/// where it is read back.
fn stream_handle(v: &Value, op: &'static str) -> VmResult<SocketValue> {
    // The re-run operand: the handle itself, with no record around it.
    if let Some(s) = v.as_socket()
        && matches!(s.kind, SocketKind::Connection | SocketKind::Tls)
    {
        return Ok(s);
    }
    if let Some(e) = v.as_enum()
        && let Some(s) = e.payload().first().and_then(Value::as_socket)
        && matches!(s.kind, SocketKind::Connection | SocketKind::Tls)
    {
        return Ok(s);
    }
    Err(VmError::type_mismatch(op, "Socket", v))
}

#[cfg(test)]
mod tests {
    //! The write path's flush step, which is the whole of `tls.write`'s
    //! documented guarantee that a returned `Ok` means the ciphertext is with
    //! the kernel.
    //!
    //! It needs a peer that has stopped reading, so nothing above this file can
    //! reach it: a Scarlet program cannot ask for a full socket, and every
    //! other TLS test moves a few hundred bytes over loopback where the flush
    //! always completes on its first try. Left uncovered, deleting the flush
    //! arm outright kept all six of them green.
    //!
    //! The verdict is the returned [`Drain`] itself rather than anything timed
    //! or counted, so a host whose socket buffers are too large to fill turns
    //! this RED — the case where the mechanism under test is a no-op is not one
    //! this can pass through.

    use std::io::Read as _;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use rustls::{ServerConfig, ServerConnection};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    use super::super::io::{Drain, drain_and_flush};
    use super::*;

    /// One chunk of plaintext per `drain_and_flush` call. Under rustls's 64 KiB
    /// send-buffer default, so a chunk is always accepted WHOLE while the
    /// session's buffer starts empty — which makes `Drain::Park` unreachable
    /// here, and every non-`Done` outcome attributable to the flush alone.
    const CHUNK: usize = 60 * 1024;

    /// Give up after this much plaintext. The peer never reads until told, so
    /// the socket must fill long before it; not filling is a broken test, not a
    /// passing one.
    const CHUNKS: usize = 256;

    /// The far end: it completes the handshake, then reads NOTHING until `go`
    /// is dropped or sent to, and finally drains to EOF and reports what it
    /// received.
    struct Peer {
        addr: SocketAddr,
        go: mpsc::Sender<()>,
        got: mpsc::Receiver<Vec<u8>>,
    }

    /// A self-signed leaf for `localhost` and the root a client trusts it by.
    fn mint() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate parameters");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let cert = params.self_signed(&key).expect("self-sign leaf");
        (
            cert.der().clone(),
            PrivateKeyDer::try_from(key.serialize_der()).expect("leaf key der"),
        )
    }

    fn provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn start_peer(leaf: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Peer {
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![leaf], key)
                .expect("server config"),
        );

        // A small receive buffer on the LISTENER, inherited by the accepted
        // socket, so the writer's window stays small and the fill is quick and
        // bounded. Without it loopback autotuning can grow the pair past
        // anything this test is willing to write.
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("listener socket");
        let _ = sock.set_recv_buffer_size(4096);
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("loopback address");
        sock.bind(&addr.into()).expect("bind");
        sock.listen(8).expect("listen");
        let listener: TcpListener = sock.into();
        let addr = listener.local_addr().expect("local_addr");

        let (go, go_rx) = mpsc::channel::<()>();
        let (got_tx, got) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let Ok(mut conn) = ServerConnection::new(config) else {
                return;
            };
            if conn.complete_io(&mut sock).is_err() {
                return;
            }
            // Hold the stream unread. Every byte the client sends from here on
            // stops in the kernel's buffers.
            let _ = go_rx.recv();
            // Spelled out rather than run through `rustls::Stream`, which folds
            // "the socket ended" and "there is decrypted plaintext left" into
            // one `Result` and drops the second when the first is an error. The
            // count below is the assertion, so the peer must not lose a byte
            // for reasons of its own.
            let mut all = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut drain = |conn: &mut ServerConnection, all: &mut Vec<u8>| {
                while let Ok(n) = conn.reader().read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    all.extend_from_slice(&buf[..n]);
                }
            };
            loop {
                drain(&mut conn, &mut all);
                match conn.read_tls(&mut sock) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if conn.process_new_packets().is_err() {
                            break;
                        }
                    }
                }
            }
            drain(&mut conn, &mut all);
            let _ = got_tx.send(all);
        });

        Peer { addr, go, got }
    }

    /// An established TLS connection to `peer`, non-blocking, in the shape the
    /// VM holds one.
    fn connect(peer: &Peer, root: CertificateDer<'static>) -> ConnIo {
        let mut roots = RootCertStore::empty();
        roots.add(root).expect("trust the leaf");
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let name = ServerName::try_from("localhost").expect("server name");
        let mut session = ClientConnection::new(config, name).expect("client session");
        let mut tcp = TcpStream::connect(peer.addr).expect("connect");
        // The handshake is not what is under test, so it runs blocking. The
        // socket goes non-blocking straight afterwards, which is the state the
        // VM's write path is written against.
        session.complete_io(&mut tcp).expect("client handshake");
        tcp.set_nonblocking(true).expect("non-blocking");
        ConnIo::Tls(TlsIo {
            tcp,
            session: Box::new(session),
        })
    }

    /// Write 60 KiB chunks at the stalled peer until the socket refuses one,
    /// and return how much plaintext the session accepted before that.
    ///
    /// Every chunk is either wholly accepted and wholly flushed (`Done`) or
    /// wholly accepted and left owing ciphertext (`Flushing`); the second is
    /// what this is looking for, and reaching it leaves the connection with a
    /// full socket underneath, which is the state both tests below need.
    fn fill_until_flushing(conn: &mut ConnIo) -> usize {
        let chunk = vec![0x5au8; CHUNK];
        let mut sent = 0usize;
        for _ in 0..CHUNKS {
            match drain_and_flush(conn, std::slice::from_ref(&chunk)).expect("write") {
                Drain::Done => sent += CHUNK,
                Drain::Flushing => return sent + CHUNK,
                Drain::Park { idx, offset } => panic!(
                    "a chunk under rustls's send-buffer limit is accepted whole, \
                     so `drain_write` cannot park; parking at ({idx}, {offset}) \
                     after {sent} bytes means the session's buffer was left full \
                     from the previous call — which is what happens when the \
                     write path stops flushing"
                ),
            }
        }
        panic!(
            "{} bytes went to a peer that is not reading without the socket ever \
             filling: this host's buffers are too large for this test to \
             exercise the flush at all",
            CHUNKS * CHUNK
        )
    }

    /// A write whose plaintext the session accepted whole, but whose ciphertext
    /// the socket would not take, reports `Flushing` and NOT `Done` — and
    /// `Flushing` is a park, so `tls.write` has not returned `Ok` yet.
    ///
    /// This is the difference between the documented guarantee and a lie: under
    /// `Done` the caller is told the bytes are with the kernel while the
    /// session is still holding them, and the only thing that would ever push
    /// them is a later call the caller has no reason to make.
    #[test]
    fn a_write_the_socket_cannot_take_reports_flushing_not_done() {
        provider();
        let (leaf, key) = mint();
        let peer = start_peer(leaf.clone(), key);
        let mut conn = connect(&peer, leaf);

        let total = fill_until_flushing(&mut conn);

        let ConnIo::Tls(tls) = &conn else {
            panic!("the connection under test is a TLS one");
        };
        assert!(
            tls.session.wants_write(),
            "`Flushing` means ciphertext is still owed; a session with nothing \
             left to write should have come back `Done`"
        );

        // The resume path: the peer drains, and the re-run carries an EMPTY
        // remainder — there is no plaintext left to send, so re-sending any
        // would duplicate it — and only finishes the flush.
        peer.go.send(()).expect("release the peer");
        let empty: [&[u8]; 0] = [];
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match drain_and_flush(&mut conn, &empty).expect("flush") {
                Drain::Done => break,
                _ => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the flush never completed against a draining peer"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }

        // End the stream with `close_notify` and a half-close, and collect the
        // peer's count BEFORE dropping the socket.
        //
        // A bare `close(2)` here loses a deterministic 44 KiB of what was
        // already on the wire, and none of it is about the flush: a rustls
        // server sends session tickets straight after the handshake, this test
        // never reads them, and Linux answers a close with unread data in the
        // receive queue by sending RST — which discards the peer's queue along
        // with it. `shutdown(Write)` sends FIN instead, so everything ahead of
        // it is delivered.
        let ConnIo::Tls(tls) = &mut conn else {
            panic!("the connection under test is a TLS one");
        };
        tls.tcp
            .set_nonblocking(false)
            .expect("blocking for the alert");
        tls.send_close_notify().expect("close_notify");
        tls.tcp
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close");
        let got = peer
            .got
            .recv_timeout(Duration::from_secs(30))
            .expect("peer");
        drop(conn);
        assert_eq!(
            got.len(),
            total,
            "the flush completed, so every byte of every accepted write must \
             have reached the peer before the socket closed"
        );
        assert!(
            got.iter().all(|&b| b == 0x5a),
            "the plaintext must arrive unaltered"
        );
    }

    /// `tls.close` over a socket too full to take the alert reports `Err`, and
    /// closes anyway.
    ///
    /// This is the input the `Err` arm of `Result(Nil, TlsError)` had never
    /// had. `send_close_notify` used to map `WouldBlock` to `Ok` as "best
    /// effort", and the very next line closed the fd — so the alert was not
    /// merely delayed, it was never sent, while the caller was told the
    /// shutdown was orderly. From the peer's side that is byte for byte a
    /// truncation, which is the one thing `close_notify` exists to rule out.
    ///
    /// Both halves are asserted, because they are separate promises: the result
    /// is `Err`, AND the connection is gone from the table regardless. A close
    /// that reported a failure by not closing would be worse than the bug.
    #[test]
    fn a_close_notify_the_socket_refuses_is_reported_and_still_closes() {
        use super::super::halt_test_vm;
        use super::super::inspect::inspect;

        provider();
        let (leaf, key) = mint();
        let peer = start_peer(leaf.clone(), key);
        let mut conn = connect(&peer, leaf);
        fill_until_flushing(&mut conn);

        let mut vm = halt_test_vm();
        let id = vm.alloc_socket_id();
        assert!(
            vm.track_connection(id, conn, 0).is_ok(),
            "the poller must accept the connection"
        );
        vm.stack.push(Value::socket(SocketValue {
            id,
            kind: SocketKind::Tls,
        }));

        let mut reds = 0;
        vm.tls_close(&mut reds)
            .expect("tls.close must not halt the VM");

        let result = vm.stack.last().expect("tls.close pushes a result").clone();
        let rendered = inspect(&result, &vm.program);
        // `inspect` wraps a nested variant across lines, so the shape is
        // checked in two pieces rather than as one prefix.
        assert!(
            rendered.starts_with("Err(") && rendered.contains("Transport("),
            "an alert the socket refused must be reported as the transport \
             failure it is, not swallowed; got {rendered}"
        );
        assert!(
            !vm.connections.contains_key(&id),
            "the connection must be gone whatever the alert did — the result \
             reports whether the peer was told, not whether the fd closed"
        );
        drop(peer);
    }
}

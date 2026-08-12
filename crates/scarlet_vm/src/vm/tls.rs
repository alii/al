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
//! Every park here is taken only after a genuine `WouldBlock` from the fd,
//! which is what an edge-triggered poller requires: the edge that wakes us is
//! the one that arrives after the buffer we just found full has drained.
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

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;

use crate::abi::AbiSlot;
use crate::bytecode::{SocketKind, SocketValue, Value};

use super::io::stale_socket;
use super::poll::{Parked, Wait};
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
    /// The requested name is not one a certificate can be issued for.
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

    pub(super) fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
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
    fn send_close_notify(&mut self) -> io::Result<()> {
        self.session.send_close_notify();
        match self.flush_out() {
            // The alert is best-effort: a peer that has already gone away
            // cannot be told anything, and that is not this program's failure.
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(()),
            other => other,
        }
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
        // An IP literal has no name to verify, and `ServerName` rejects it for
        // exactly that reason. Surfaced as its own variant rather than as a
        // certificate error, because the certificate is not the problem.
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| TlsFail::InvalidServerName)?;
        let session = ClientConnection::new(config, name).map_err(TlsFail::Session)?;

        // Take the cleartext entry out WITHOUT going through `evict_connection`:
        // the fd survives into the TLS entry, so its poller registration is
        // rebuilt under the new id rather than torn down and lost.
        let Some(conn) = self.connections.remove(&id) else {
            return Err(TlsFail::Io(stale_socket()));
        };
        let owner = conn.owner;
        let ConnIo::Tcp(tcp) = conn.io else {
            // Put it back: a port is not something to secure, and losing the
            // entry would leak the child.
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
    pub(super) fn tls_close(&mut self, reds: &mut i32) -> VmResult<()> {
        *reds -= IO_REDUCTION_COST;
        let sock_val = self.pop()?;
        let sv = stream_handle(&sock_val, "tls.close")?;
        if let Some(conn) = self.connections.get_mut(&sv.id)
            && let ConnIo::Tls(tls) = &mut conn.io
        {
            // Best effort: the connection is going away regardless, and a peer
            // that has already left cannot be told about it.
            let _ = tls.send_close_notify();
        }
        drop(self.evict_connection(sv.id));
        let nil = self.make_nil()?;
        let v = self.make_ok(nil)?;
        self.stack.push(v);
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
    pub(super) fn tls_error_value(&mut self, fail: TlsFail) -> VmResult<Value> {
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

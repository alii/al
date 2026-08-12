//! Ports: child processes owned by the program, driven through their stdio.
//!
//! A port is the one way a Scarlet program reaches native code — a
//! tokenizer, an exporter, a worker written in something else — and it is
//! deliberately a *process*, not a foreign call: nothing the child does can
//! block a scheduler or touch the VM's memory, and the runtime can watch it
//! end and take it down.
//!
//! In the runtime a port is a connection. Its stdin and stdout are two
//! non-blocking pipes registered with the owning scheduler's poller under one
//! socket id, and the entry lives in the same table as TCP connections, so
//! reading, writing, parking, waking, migration and the controlling-process
//! rule all come from the connection machinery unchanged: `port.read` *is*
//! `Op::TcpRead` applied to a port handle. What is port-specific is here —
//! the two ends of a port's life. Spawning and reaping are syscalls with no
//! readiness signal, so both run on the blocking pool: `spawn` parks until
//! the child exists, and `close` parks until it has been waited for. Closing
//! is graceful in stages — the pipes close, which is EOF to a well-behaved
//! child; after [`EOF_GRACE`] it is sent SIGTERM; after [`TERM_GRACE`] more
//! it is killed — and it is what the death of the controlling process does
//! too, in the background, so a program can never leave a child behind.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mio::unix::pipe::{Receiver, Sender};

use crate::abi::AbiSlot;
use crate::bytecode::{SocketKind, SocketValue, Value};

use super::poll::{Parked, Wait};
use super::sched::BlockingOp;
use super::{IO_REDUCTION_COST, VM, VmError, VmResult, str_ref};

/// How long a closed port's child gets to exit on its own after its pipes
/// close, before it is asked to with SIGTERM.
const EOF_GRACE: Duration = Duration::from_secs(1);
/// How long it then gets to act on SIGTERM before it is killed.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// The stream behind a connection-table entry. Both kinds are read, written
/// and parked on identically; they differ in what is registered with the
/// poller and in what closing them means.
pub(super) enum ConnIo {
    Tcp(TcpStream),
    Port(PortIo),
    /// A TCP stream with a TLS session over it. Reading decrypts and writing
    /// encrypts, so the ops above this layer are the cleartext ones unchanged —
    /// see [`super::tls`].
    Tls(super::tls::TlsIo),
}

/// A live child: its stdio ends, and the `Child` itself, held un-reaped so
/// its pid remains ours to signal until [`reap`] waits for it.
pub(super) struct PortIo {
    child: Child,
    stdin: Sender,
    stdout: Receiver,
}

// Entries travel between schedulers inside a `Migrant`.
const _: () = crate::assert_send::<ConnIo>();

impl ConnIo {
    /// The fds to register, each with the interest it can be parked on. A
    /// TCP stream is one fd parked on in both directions; a port is parked
    /// on for reading via the child's stdout and for writing via its stdin.
    pub(super) fn registrations(&self) -> impl Iterator<Item = (RawFd, mio::Interest)> {
        let (a, b) = match self {
            ConnIo::Tcp(s) => (
                (
                    s.as_raw_fd(),
                    mio::Interest::READABLE | mio::Interest::WRITABLE,
                ),
                None,
            ),
            // One fd, both directions — TLS adds no descriptor of its own, and
            // registering both is what lets a decrypting read be woken by the
            // writability it needed to send a handshake reply.
            ConnIo::Tls(t) => (
                (
                    t.as_raw_fd(),
                    mio::Interest::READABLE | mio::Interest::WRITABLE,
                ),
                None,
            ),
            ConnIo::Port(p) => (
                (p.stdout.as_raw_fd(), mio::Interest::READABLE),
                Some((p.stdin.as_raw_fd(), mio::Interest::WRITABLE)),
            ),
        };
        std::iter::once(a).chain(b)
    }

    /// Every fd this entry registered, for deregistration.
    pub(super) fn fds(&self) -> impl Iterator<Item = RawFd> {
        self.registrations().map(|(fd, _)| fd)
    }
}

impl Read for ConnIo {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ConnIo::Tcp(s) => s.read(buf),
            ConnIo::Port(p) => p.stdout.read(buf),
            ConnIo::Tls(t) => t.read(buf),
        }
    }
}

impl Write for ConnIo {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ConnIo::Tcp(s) => s.write(buf),
            ConnIo::Port(p) => p.stdin.write(buf),
            ConnIo::Tls(t) => t.write(buf),
        }
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            ConnIo::Tcp(s) => s.write_vectored(bufs),
            ConnIo::Port(p) => p.stdin.write_vectored(bufs),
            ConnIo::Tls(t) => t.write_vectored(bufs),
        }
    }

    /// For a cleartext stream this is the no-op `std` makes it; for TLS it is
    /// load-bearing, and is what makes a completed `tls.write` mean the
    /// ciphertext reached the kernel rather than a userspace buffer.
    fn flush(&mut self) -> io::Result<()> {
        match self {
            ConnIo::Tcp(s) => s.flush(),
            ConnIo::Port(p) => p.stdin.flush(),
            ConnIo::Tls(t) => t.flush(),
        }
    }
}

/// How a reaped child ended: raw data for the completion to carry back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ChildExit {
    /// The exit code, when it exited.
    pub code: Option<i32>,
    /// The signal that ended it, otherwise.
    pub signal: Option<i32>,
}

/// Blocking-pool half of `port.spawn`: start the child with piped stdin and
/// stdout (stderr is inherited, so a helper's diagnostics land where the
/// program's do) and switch both pipes to non-blocking. Only the raw
/// handles come back; the scheduler that asked adopts them.
pub(super) fn spawn_child(
    program: &str,
    args: &[String],
    env: &[(String, String)],
) -> io::Result<PortIo> {
    let mut child = Command::new(program)
        .args(args)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    // Both are `Some`: `Stdio::piped` was requested for each. Taking them
    // out leaves the `Child` holding nothing that would close on drop, so
    // the pipes' lifetimes are exactly the table entry's.
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(io::Error::other("spawned child is missing its stdio pipes"));
    };
    let stdin = Sender::from(stdin);
    let stdout = Receiver::from(stdout);
    stdin.set_nonblocking(true)?;
    stdout.set_nonblocking(true)?;
    Ok(PortIo {
        child,
        stdin,
        stdout,
    })
}

/// Blocking-pool half of closing a port: the pipes are gone (dropped by the
/// caller, so the child has seen EOF); wait for it, escalating on the
/// documented schedule, and report how it ended. Runs on a pool thread,
/// where sleeping is fine.
pub(super) fn reap(mut child: Child) -> io::Result<ChildExit> {
    if let Some(status) = wait_up_to(&mut child, EOF_GRACE)? {
        return Ok(exit_of(status));
    }
    terminate(&child);
    if let Some(status) = wait_up_to(&mut child, TERM_GRACE)? {
        return Ok(exit_of(status));
    }
    child.kill()?;
    child.wait().map(exit_of)
}

/// The `PortIo` half that outlives the table entry: everything but the
/// child is dropped here, closing the pipes, and the child goes to `reap`.
impl PortIo {
    fn into_child(self) -> Child {
        self.child
    }

    fn os_pid(&self) -> u32 {
        self.child.id()
    }
}

fn exit_of(status: std::process::ExitStatus) -> ChildExit {
    ChildExit {
        code: status.code(),
        signal: status.signal(),
    }
}

/// Poll `try_wait` for up to `limit`, backing off from 1ms to 20ms between
/// probes: a child that exits on EOF is usually gone by the first or second.
fn wait_up_to(child: &mut Child, limit: Duration) -> io::Result<Option<std::process::ExitStatus>> {
    let deadline = Instant::now() + limit;
    let mut pause = Duration::from_millis(1);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        std::thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(Duration::from_millis(20));
    }
}

/// Send SIGTERM. `std` offers only SIGKILL, and a helper deserves the
/// chance to flush and exit on its own terms.
#[allow(unsafe_code)]
fn terminate(child: &Child) {
    // SAFETY: `kill(2)` has no memory-safety preconditions; the only hazard
    // is signalling a pid that has been recycled, and this pid cannot have
    // been: `child` has not been waited for (every wait goes through `reap`,
    // which owns it), so the kernel still holds the pid for this child.
    // A failure (the child already exited) is harmless: the wait that
    // follows collects it.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

impl VM {
    /// `Op::PortSpawn`: `[program, args, env] -> Result(Port, IoError)`,
    /// delivered on wake by [`VM::port_spawned`].
    pub(super) fn port_spawn(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        let env_v = self.pop()?;
        let args_v = self.pop()?;
        let program_v = self.pop_str("port.spawn")?;
        let program = str_ref(&program_v).to_string();
        let args = decode_strings(&args_v)?;
        let env = decode_env(&env_v)?;
        Ok(Some(Parked::cont(Wait::offloaded(
            BlockingOp::SpawnChild { program, args, env },
        ))))
    }

    /// The wake side of `port.spawn`: adopt the child's pipes into this
    /// scheduler's table under the woken process — which is current, so it
    /// becomes the controlling process — and build the `Port` record.
    pub(super) fn port_spawned(
        &mut self,
        program: &str,
        spawned: io::Result<PortIo>,
    ) -> VmResult<Value> {
        let port = match spawned {
            Ok(port) => port,
            Err(e) => {
                let err = self.io_error_value(&e, program)?;
                return self.make_err(err);
            }
        };
        let os_pid = port.os_pid();
        let id = self.alloc_socket_id();
        let owner = self.current_pid;
        if let Err((e, io)) = self.track_connection(id, ConnIo::Port(port), owner) {
            // Unwatchable means unusable: dispose of it exactly as a port
            // whose owner died — pipes closed, child collected — and report
            // the registration failure as the spawn's error.
            self.reap_in_background(io);
            let err = self.io_error_value(&e, program)?;
            return self.make_err(err);
        }
        let handle = Value::socket(SocketValue {
            id,
            kind: SocketKind::Port,
        });
        let record = self.abi_make(
            AbiSlot::Port,
            &[handle, Value::small_int(i64::from(os_pid))],
        )?;
        self.make_ok(record)
    }

    /// `Op::PortClose`: `[port] -> Result(ExitStatus, NetError)`. Takes the
    /// entry out of the table (closing the pipes and failing any park on
    /// it), then parks until the pool has reaped the child; the result is
    /// built on wake by [`VM::port_reaped`]. A port already closed — or one
    /// whose controlling process is not the caller but has already ended —
    /// is the stale-handle error, as for sockets.
    pub(super) fn port_close(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        let port_v = self.pop()?;
        let sv = port_handle(&port_v)?;
        match self.evict_connection(sv.id).map(|c| c.io) {
            Some(ConnIo::Port(port)) => Ok(Some(Parked::cont(Wait::offloaded(
                BlockingOp::ReapChild(port.into_child()),
            )))),
            Some(ConnIo::Tcp(_)) => {
                Err(VmError::internal("port.close applied to a TCP connection"))
            }
            Some(ConnIo::Tls(_)) => {
                Err(VmError::internal("port.close applied to a TLS connection"))
            }
            None => {
                self.push_stale_handle()?;
                Ok(None)
            }
        }
    }

    /// The wake side of `port.close`.
    pub(super) fn port_reaped(&mut self, result: io::Result<ChildExit>) -> VmResult<Value> {
        match result {
            Ok(ChildExit {
                signal: Some(signal),
                ..
            }) => {
                let v = self.abi_make(
                    AbiSlot::PortSignaled,
                    &[Value::small_int(i64::from(signal))],
                )?;
                self.make_ok(v)
            }
            Ok(ChildExit { code, .. }) => {
                // `wait(2)` reports one or the other; a status with neither
                // cannot come back from a reaped child, so the fallback is
                // never taken in practice.
                let code = code.unwrap_or(-1);
                let v = self.abi_make(AbiSlot::PortExited, &[Value::small_int(i64::from(code))])?;
                self.make_ok(v)
            }
            Err(e) => {
                let err = self.net_error_value(&e)?;
                self.make_err(err)
            }
        }
    }

    /// A port leaving the table for good — closed by its controlling
    /// process's death rather than by `port.close` — still has a child to
    /// collect. Nobody is waiting for the outcome, so the job is filed under
    /// a wait id no park will ever hold and its completion is discarded.
    pub(super) fn reap_in_background(&mut self, io: ConnIo) {
        if let ConnIo::Port(port) = io {
            self.runtime.offload(
                self.scheduler_index,
                super::poll::DISCARDED_WAIT_ID,
                BlockingOp::ReapChild(port.into_child()),
            );
        }
    }
}

/// The handle inside a `Port` record: `{ conn, os_pid }`, so field 0.
fn port_handle(v: &Value) -> VmResult<SocketValue> {
    if let Some(e) = v.as_enum()
        && let Some(s) = e.payload().first().and_then(Value::as_socket)
        && s.kind == SocketKind::Port
    {
        return Ok(s);
    }
    Err(VmError::type_mismatch("port.close", "Port", v))
}

fn decode_strings(v: &Value) -> VmResult<Vec<String>> {
    let bad = || VmError::type_mismatch("port.spawn", "Array(String)", v);
    let arr = v.as_array().ok_or_else(bad)?;
    arr.iter()
        .map(|s| s.as_str().map(str::to_owned).ok_or_else(bad))
        .collect()
}

fn decode_env(v: &Value) -> VmResult<Vec<(String, String)>> {
    let bad = || VmError::type_mismatch("port.spawn", "Array((String, String))", v);
    let arr = v.as_array().ok_or_else(bad)?;
    arr.iter()
        .map(|pair| {
            let t = pair.as_tuple().ok_or_else(bad)?;
            match t {
                [k, v] => Ok((
                    k.as_str().ok_or_else(bad)?.to_owned(),
                    v.as_str().ok_or_else(bad)?.to_owned(),
                )),
                _ => Err(bad()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! The pool-side pieces, without a program: a child that exits on EOF is
    //! collected with its code, one that ignores EOF is terminated. Driving
    //! the ops end to end is `tests/programs/ports.scrl`.

    use super::*;

    #[test]
    fn a_child_that_exits_is_collected_with_its_code() {
        let port = spawn_child("/bin/sh", &["-c".into(), "exit 3".into()], &[]).expect("spawn sh");
        let exit = reap(port.into_child()).expect("reap");
        assert_eq!(
            exit,
            ChildExit {
                code: Some(3),
                signal: None
            }
        );
    }

    #[test]
    fn a_child_that_ignores_eof_is_terminated() {
        // `sleep` reads nothing, so closing its pipes does not end it; the
        // EOF grace passes and SIGTERM does.
        let port = spawn_child("/bin/sleep", &["30".into()], &[]).expect("spawn sleep");
        let started = Instant::now();
        let exit = reap(port.into_child()).expect("reap");
        assert_eq!(exit.signal, Some(libc::SIGTERM));
        assert!(started.elapsed() >= EOF_GRACE);
        assert!(started.elapsed() < EOF_GRACE + TERM_GRACE);
    }

    #[test]
    fn stdio_round_trips_and_env_is_passed() {
        let mut port = spawn_child(
            "/bin/sh",
            &[
                "-c".into(),
                "read line; echo \"$line $PORT_TEST_VAR\"".into(),
            ],
            &[("PORT_TEST_VAR".into(), "set".into())],
        )
        .expect("spawn sh");
        // The pipes are non-blocking, so wait for readiness the crude way
        // here; the VM parks on the poller instead.
        port.stdin.write_all(b"hello\n").expect("write");
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !out.ends_with(b"\n") && Instant::now() < deadline {
            let mut buf = [0u8; 64];
            match port.stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("read failed: {e}"),
            }
        }
        assert_eq!(out, b"hello set\n");
        let exit = reap(port.into_child()).expect("reap");
        assert_eq!(exit.code, Some(0));
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        match spawn_child("/nonexistent/definitely-not-here", &[], &[]) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            Ok(port) => {
                drop(reap(port.into_child()));
                panic!("spawning a missing program must fail");
            }
        }
    }
}

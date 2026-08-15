//! Parking and wake-up: how a blocked process sleeps and what brings it back.
//!
//! An opcode that cannot progress returns `Step::Parked` with a [`Wait`]. The
//! process is stashed under a fresh wait id and [`VM::poll_parked`] delivers
//! whatever became ready — I/O events, due timers, blocking-pool completions —
//! back onto the run queue.
//!
//! Parking arms nothing. A socket is registered with the poller once, when it
//! enters this scheduler's tables, with every interest it can ever park on.
//!
//! PARK-AFTER-PROBE, the reason edge-triggering loses no wakeups: a park on an
//! fd is always immediately preceded, on this same OS thread, by a syscall on
//! that fd returning `WouldBlock`, with no `Poll::poll` in between, and only
//! this thread drains this poller. An edge firing after the probe then sits in
//! the kernel's ready list until a drain that runs after the park is
//! registered. A dropped edge is NOT re-announced later, so do not add a
//! `poll_parked` between a `WouldBlock` and its park, and do not drain this
//! poller from another thread. Either reopens the classic lost wakeup.
//!
//! Invariants:
//!
//! - A wait wakes exactly once; the first of fd readiness or deadline removes
//!   the park.
//! - Timer entries are lazily deleted. A popped entry whose id is gone or
//!   re-keyed is discarded, so the nearest live deadline is an O(log n) peek.
//! - Wake-time value construction runs with the woken process swapped in, so
//!   allocation lands in its heap with its stack and frames as GC roots.
//! - A socket stays registered while it is in the VM's tables; close
//!   deregisters before dropping.
//!
//! [`EPOCH`] is the process-global monotonic origin shared by `Op::Monotonic`
//! and `socket.read_within`, so an absolute deadline means the same instant on
//! every scheduler.

use std::cmp::Reverse;
use std::io::{self, ErrorKind};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use mio::Token;
use mio::unix::SourceFd;

use crate::abi::AbiSlot;
use crate::bytecode::Value;

use super::port::ConnIo;
use super::sched::{BlockingOp, BlockingResult, Completion};
use super::{Process, VM, VmError, VmResult, lock};

/// How a parked I/O wait resumes once one of its sockets is ready.
#[derive(Debug, Clone, Copy)]
pub(super) enum WakeAction {
    /// Resume wherever the op left `ip`. Retry waits set `ip - 1` to re-run;
    /// `Sleep` leaves `ip` past itself with its result already on the stack.
    Rerun,
    /// `VM::finish_connect` (I/O wake) or `VM::timeout_connect` (deadline)
    /// builds the result and pushes it onto the process's stack instead of
    /// re-running the instruction.
    CompleteConnect,
}

/// What an offloaded job owes its process when a deadline beats it.
///
/// A deadline on an offload abandons the *wait*, never the job. `getaddrinfo`
/// has no cancellation — POSIX gives none and Darwin's resolver is reached
/// through a system daemon — so the pool thread runs on until the resolver
/// itself gives up, and the completion it finally delivers finds no park and is
/// dropped by [`VM::drain_completions`]. A bound therefore costs one pool
/// thread for the remainder of the resolve, capped by the pool's worker
/// ceiling; the process gets its bound either way. Waiting and resolving are
/// separate here in a way they are not for a socket, where dropping the fd ends
/// the attempt.
///
/// [`VM::park`] has handed the [`BlockingOp`] to the pool before any deadline
/// can fire, so the wait cannot re-read which job it was: this names the
/// completion to synthesise in its place.
#[derive(Debug, Clone, Copy)]
pub(super) enum OffloadTimeout {
    /// `Op::DnsResolveUntil`, reported as an `ETIMEDOUT` resolve.
    Resolve,
}

/// What a parked process is waiting for. Exactly one wake source per wait.
#[derive(Debug)]
pub(super) enum Wait {
    /// Socket readiness on `fd`, optionally bounded by a deadline. Whichever
    /// fires first wakes the process.
    Io {
        fd: i32,
        deadline: Option<Instant>,
        action: WakeAction,
    },
    /// A pure timer: wake at this instant, resume at the next instruction.
    Timer(Instant),
    /// A blocking-pool job. `op` is `Some` on the way into [`VM::park`], which
    /// hands it to the pool keyed by the wait id and leaves `None` behind. Only
    /// the bounded opcodes set `deadline`; see [`OffloadTimeout`].
    Offload {
        op: Option<BlockingOp>,
        deadline: Option<(Instant, OffloadTimeout)>,
    },
    /// An empty-mailbox receive: wake when a send targets the subject
    /// (delivered through the slot's wake queue), or at the deadline.
    Mailbox {
        subject: u64,
        deadline: Option<Instant>,
    },
}

impl Wait {
    /// Park until socket `id` becomes ready, then re-run the instruction.
    /// Interest direction was fixed at registration; a wait only names the fd.
    fn rerun_on(id: i32) -> Self {
        Wait::Io {
            fd: id,
            deadline: None,
            action: WakeAction::Rerun,
        }
    }

    /// Park until socket `id` becomes readable, then re-run the instruction.
    #[inline]
    pub(super) fn readable(id: i32) -> Self {
        Self::rerun_on(id)
    }

    /// Park until socket `id` becomes writable, then re-run the instruction.
    #[inline]
    pub(super) fn writable(id: i32) -> Self {
        Self::rerun_on(id)
    }

    /// Park until the pending connect on socket `id` completes (signalled by
    /// writability); on wake, finish the connect and push its result.
    pub(super) fn connecting(id: i32) -> Self {
        Wait::Io {
            fd: id,
            deadline: None,
            action: WakeAction::CompleteConnect,
        }
    }

    /// As `connecting`, but giving up at `deadline`. Both wakes land on
    /// `WakeAction::CompleteConnect`; which one fired is read from whether the
    /// socket is still pending, not from the wait.
    pub(super) fn connecting_until(id: i32, deadline: Instant) -> Self {
        Wait::Io {
            fd: id,
            deadline: Some(deadline),
            action: WakeAction::CompleteConnect,
        }
    }

    /// Park until `deadline`, then resume at the next instruction (the result
    /// is already on the stack).
    pub(super) fn until(deadline: Instant) -> Self {
        Wait::Timer(deadline)
    }

    /// Park until socket `id` is readable or `deadline` passes, then re-run the
    /// instruction, which re-derives which of the two happened.
    pub(super) fn read_with_deadline(id: i32, deadline: Instant) -> Self {
        Wait::Io {
            fd: id,
            deadline: Some(deadline),
            action: WakeAction::Rerun,
        }
    }

    /// Park until the blocking pool finishes a job. Nothing else can wake it.
    /// The job id is the wait id.
    pub(super) fn offloaded(op: BlockingOp) -> Self {
        Wait::Offload {
            op: Some(op),
            deadline: None,
        }
    }

    /// As `offloaded`, but giving up the wait at `deadline`. The job itself
    /// runs to completion regardless — see [`OffloadTimeout`].
    pub(super) fn offloaded_until(
        op: BlockingOp,
        deadline: Instant,
        on_timeout: OffloadTimeout,
    ) -> Self {
        Wait::Offload {
            op: Some(op),
            deadline: Some((deadline, on_timeout)),
        }
    }

    /// Park until a message lands on `subject`, then re-run the instruction.
    pub(super) fn mailbox(subject: u64) -> Self {
        Wait::Mailbox {
            subject,
            deadline: None,
        }
    }

    /// Park until a message lands on `subject` or `deadline` passes, then
    /// re-run the instruction, which re-derives which of the two happened.
    pub(super) fn mailbox_until(subject: u64, deadline: Instant) -> Self {
        Wait::Mailbox {
            subject,
            deadline: Some(deadline),
        }
    }

    /// The instant this wait must wake by. Timer-heap entries are validated
    /// against it to spot stale ones.
    fn deadline(&self) -> Option<Instant> {
        match self {
            Wait::Io { deadline, .. } | Wait::Mailbox { deadline, .. } => *deadline,
            Wait::Timer(d) => Some(*d),
            Wait::Offload { deadline, .. } => deadline.map(|(at, _)| at),
        }
    }
}

/// The token every scheduler's [`mio::Waker`] registers under. Drains skip it:
/// a wake ends the wait but delivers no I/O. Socket ids are small positive
/// `i32`s, so it cannot collide with a socket registration.
pub(super) const WAKER_TOKEN: Token = Token(usize::MAX);

/// Event-buffer capacity for one poll call.
pub(super) const EVENTS_CAPACITY: usize = 1024;

/// The wait id under which a blocking job nobody is parked on is filed (a
/// port's child being collected after its owner died). Real ids count up
/// from zero, so this one is never held, and `drain_completions` drops the
/// completion on finding no park.
pub(super) const DISCARDED_WAIT_ID: u64 = u64::MAX;

/// Process-global monotonic origin, pinned to the first reading taken.
pub(super) static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Milliseconds since [`EPOCH`], saturating at `i64::MAX`.
/// Where a parked op resumes once its [`Wait`] fires.
///
/// A parking op decides this, but only its caller knows how to express it: the
/// interpreter rewinds or advances `ip`, while a compiled body picks one of two
/// resume ordinals. Returning the choice as a value keeps the bytecode-specific
/// arithmetic out of the ops, so the same op body serves both backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Resume {
    /// Re-run the instruction. The op pushed its operands back before parking,
    /// so re-executing it is what finishes the operation.
    Retry,
    /// Continue past the instruction: the wake path leaves the result on the
    /// stack (`finish_connect`, the offloaded blocking ops, `sleep`).
    Continue,
}

/// A parked op's outcome: what to wait on, and where to resume.
pub(super) struct Parked {
    pub(super) wait: Wait,
    pub(super) resume: Resume,
}

impl Parked {
    /// Park and re-run the instruction on wake.
    pub(super) fn retry(wait: Wait) -> Parked {
        Parked {
            wait,
            resume: Resume::Retry,
        }
    }

    /// Park and continue past the instruction on wake.
    pub(super) fn cont(wait: Wait) -> Parked {
        Parked {
            wait,
            resume: Resume::Continue,
        }
    }
}

/// The `Instant` an absolute monotonic-ms deadline names, on the same epoch
/// `monotonic_now_ms` reads. A negative value clamps to the epoch rather than
/// wrapping, so a deadline already past fires on the next sweep.
pub(super) fn deadline_instant(ms: i64) -> Instant {
    *EPOCH.get_or_init(Instant::now) + Duration::from_millis(ms.max(0) as u64)
}

pub(super) fn monotonic_now_ms() -> i64 {
    let ms = EPOCH.get_or_init(Instant::now).elapsed().as_millis();
    ms.min(i64::MAX as u128) as i64
}

/// One wait on a scheduler's poller. mio hands `EINTR` to its caller, and a
/// signal landing on this thread (a child of a port ending, say) is nothing
/// to the scheduler: every wait here is one interruptible sleep whose caller
/// re-checks its sources on return, so an interrupted wait is a wake with
/// nothing ready. Anything else the poller reports is an OS failure.
pub(super) fn poll_wait(
    poll: &mut mio::Poll,
    events: &mut mio::Events,
    timeout: Option<Duration>,
) -> VmResult<()> {
    match poll.poll(events, timeout) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::Interrupted => Ok(()),
        Err(e) => Err(VmError::Io(e)),
    }
}

impl VM {
    /// Register `fd` under socket `id` with every interest it can ever park on.
    /// An fd number still registered from a stale entry (a close that skipped
    /// deregistration, then kernel fd reuse) is re-registered under the new id.
    fn poller_register(&self, fd: RawFd, id: i32, interests: mio::Interest) -> io::Result<()> {
        let registry = self.poll.registry();
        registry
            .register(&mut SourceFd(&fd), Token(id as usize), interests)
            .or_else(|e| {
                if e.kind() == ErrorKind::AlreadyExists {
                    // Reachable only when a close path skipped deregistration
                    // and the kernel reused the fd number. Recover by
                    // re-pointing the registration, but fail loudly in debug
                    // so the skipping path gets found — until then, events
                    // could have been delivered against the stale id.
                    debug_assert!(
                        false,
                        "fd {fd} already registered: a close path skipped poller_deregister"
                    );
                    registry.reregister(&mut SourceFd(&fd), Token(id as usize), interests)
                } else {
                    Err(e)
                }
            })
    }

    /// Drop `fd` from the poller, ignoring an fd that was never registered.
    /// Call before closing or handing off a socket.
    pub(super) fn poller_deregister(&self, fd: RawFd) {
        let _ = self.poll.registry().deregister(&mut SourceFd(&fd));
    }

    /// Register the shared listener with this scheduler's poller. Idempotent.
    /// Each scheduler's poller holds its own readiness for the shared fd, so an
    /// accept parked here wakes here.
    pub(super) fn track_listener(
        &mut self,
        id: i32,
        listener: std::sync::Arc<TcpListener>,
    ) -> io::Result<()> {
        if self.tcp_listeners.contains_key(&id) {
            return Ok(());
        }
        self.poller_register(listener.as_raw_fd(), id, mio::Interest::READABLE)?;
        self.tcp_listeners.insert(id, listener);
        Ok(())
    }

    /// Adopt a connection or port into this scheduler's table, with every fd
    /// it can be parked on registered. On a registration failure nothing is
    /// tabled — a stream that could never wake its parks must not be — and
    /// the entry comes back with the error so the caller can dispose of it
    /// properly (a port still has a child to collect).
    pub(super) fn track_connection(
        &mut self,
        id: i32,
        io: ConnIo,
        owner: u64,
    ) -> Result<(), (io::Error, ConnIo)> {
        let mut registered: Vec<RawFd> = Vec::with_capacity(2);
        let registrations: Vec<(RawFd, mio::Interest)> = io.registrations().collect();
        for (fd, interest) in registrations {
            if let Err(e) = self.poller_register(fd, id, interest) {
                for done in registered {
                    self.poller_deregister(done);
                }
                return Err((e, io));
            }
            registered.push(fd);
        }
        self.connections.insert(id, super::Conn { io, owner });
        self.conns_by_owner.entry(owner).or_default().push(id);
        Ok(())
    }

    /// Adopt an in-progress non-blocking connect, watched for the writability
    /// that signals completion.
    pub(super) fn track_pending(&mut self, id: i32, socket: socket2::Socket) -> io::Result<()> {
        self.poller_register(socket.as_raw_fd(), id, mio::Interest::WRITABLE)?;
        self.pending_connects.insert(id, socket);
        Ok(())
    }

    /// Stash a suspended process under a fresh wait id and register the side
    /// effects its `Wait` implies: the `io_waiters` reverse index, the timer
    /// heap, the blocking-pool dispatch. The only way into `parked`.
    pub(super) fn park(&mut self, mut wait: Wait, p: Process) -> u64 {
        let id = self.next_wait_id;
        self.next_wait_id += 1;
        match &mut wait {
            Wait::Io { fd, deadline, .. } => {
                let waiters = self.io_waiters.entry(*fd).or_default();
                if !waiters.contains(&id) {
                    waiters.push(id);
                }
                if let Some(d) = *deadline {
                    self.timer_heap.push(Reverse((d, id)));
                }
            }
            Wait::Timer(d) => self.timer_heap.push(Reverse((*d, id))),
            Wait::Mailbox { subject, deadline } => {
                // Register the waiter under the registry lock, which re-checks
                // the queue: a send that raced the park is seen there, and the
                // process stays runnable instead of missing its wakeup.
                if !self
                    .runtime
                    .subject_park_waiter(*subject, self.scheduler_index, id)
                {
                    self.run_queue.push_back(p);
                    return id;
                }
                if let Some(d) = *deadline {
                    self.timer_heap.push(Reverse((d, id)));
                }
            }
            Wait::Offload { op, deadline } => {
                if let Some((d, _)) = *deadline {
                    self.timer_heap.push(Reverse((d, id)));
                }
                // Both `Wait::offloaded` constructors always yield `Some`. A
                // `None` would dispatch no job and hang the process forever,
                // so panic instead of swallowing it.
                #[allow(clippy::expect_used)]
                let op = op.take().expect("offload park carries an op");
                self.runtime.offload(self.scheduler_index, id, op);
            }
        }
        self.parked.insert(id, (wait, p));
        id
    }

    /// Remove a park and its socket reverse-index entries. Every wake path goes
    /// through here so `io_waiters` stays in lockstep with `parked`.
    pub(super) fn park_remove(&mut self, id: u64) -> Option<(Wait, Process)> {
        let (wait, p) = self.parked.remove(&id)?;
        if let Wait::Io { fd, .. } = &wait
            && let Some(waiters) = self.io_waiters.get_mut(fd)
        {
            waiters.retain(|w| *w != id);
            if waiters.is_empty() {
                self.io_waiters.remove(fd);
            }
        }
        Some((wait, p))
    }

    /// Wake a parked process with a value built in its own context: `p` is made
    /// current so `build` allocates in its arena with its stack and frames as
    /// GC roots. The one place that invariant is enforced.
    fn wake_with(
        &mut self,
        p: Process,
        build: impl FnOnce(&mut Self) -> VmResult<Value>,
    ) -> VmResult<()> {
        let interrupted = self.suspend_current();
        self.resume(p);
        let result = build(self);
        // Restore scheduler state before propagating a build failure so the
        // error surfaces through the normal top-level path.
        let value = match result {
            Ok(v) => v,
            Err(e) => {
                let woken = self.suspend_current();
                self.run_queue.push_back(woken);
                self.resume(interrupted);
                return Err(e);
            }
        };
        self.stack.push(value);
        let woken = self.suspend_current();
        self.run_queue.push_back(woken);
        self.resume(interrupted);
        Ok(())
    }

    /// Move parked processes whose I/O is ready or whose timer has expired
    /// back onto the run queue.
    ///
    /// With `block`, performs one interruptible wait — I/O readiness, the
    /// nearest timer deadline, or a `notify()` from another scheduler all end
    /// it — then returns so the caller can re-check for remote work.
    pub(super) fn poll_parked(&mut self, block: bool) -> VmResult<()> {
        // Must run before the parked-empty early-out: this scheduler's
        // registration and Arc clone have to go before the shared fd can close,
        // even with nothing parked here.
        let retired_woke = self.process_retired_listeners();
        if self.parked.is_empty() {
            return Ok(());
        }

        // wake_due_timers before drain_completions, the same order the tail
        // of this function already uses and the same order Wait::Io gets
        // from wake_due_timers running ahead of drain_io_events below: an
        // expired deadline claims the park first, so a completion that only
        // finished late is dropped by drain_completions' own park_remove
        // finding nothing there (T-644). Reversed, this raced: a completion
        // sitting in the queue when the scheduler got back to it could win
        // over a deadline that had already passed, and which side won
        // depended on nothing more principled than which of poll_parked's
        // two call sites happened to run.
        let mut woke = retired_woke | self.wake_due_timers()?;
        woke |= self.drain_completions()?;
        woke |= self.drain_wakes();

        let waiting_on_io = !self.io_waiters.is_empty();

        if !block || woke {
            if waiting_on_io {
                self.drain_io_events(Some(Duration::ZERO))?;
            }
            return Ok(());
        }

        // One blocking wait, bounded by the nearest live timer deadline. The
        // poller is used even for timer-only waits so `notify()` can interrupt
        // it. Stale heap tops are dropped while looking.
        let next_deadline = loop {
            let Some(&Reverse((deadline, id))) = self.timer_heap.peek() else {
                break None;
            };
            if matches!(self.parked.get(&id), Some((w, _)) if w.deadline() == Some(deadline)) {
                break Some(deadline);
            }
            self.timer_heap.pop();
        };
        let timeout = next_deadline.map(|d| d.saturating_duration_since(Instant::now()));
        self.drain_io_events(timeout)?;
        self.wake_due_timers()?;
        // A completion or send notify may be what ended the wait above.
        self.drain_completions()?;
        self.drain_wakes();
        Ok(())
    }

    /// Wake the processes whose wait ids a `process.send` queued on this
    /// slot. A stale id — the wait already ended on its deadline — is skipped.
    pub(super) fn drain_wakes(&mut self) -> bool {
        let drained: Vec<u64> = {
            let mut q = lock(&self.runtime.slots[self.scheduler_index].wakes);
            if q.is_empty() {
                return false;
            }
            q.drain(..).collect()
        };
        let mut woke = false;
        for id in drained {
            if let Some((_wait, p)) = self.park_remove(id) {
                self.run_queue.push_back(p);
                woke = true;
            }
        }
        woke
    }

    /// Deliver finished blocking-pool jobs, waking the process parked under
    /// each `job_id`. Returns whether anything was woken. Whatever process was
    /// current is detached around the delivery and restored after.
    fn drain_completions(&mut self) -> VmResult<bool> {
        let drained: Vec<Completion> = {
            let mut q = lock(&self.runtime.slots[self.scheduler_index].completions);
            if q.is_empty() {
                return Ok(false);
            }
            q.drain(..).collect()
        };
        let mut woke = false;
        for c in drained {
            let Some((_wait, p)) = self.park_remove(c.job_id) else {
                continue;
            };
            self.wake_with(p, |vm| vm.completion_result(c.result))?;
            woke = true;
        }
        Ok(woke)
    }

    /// Construct a blocking-pool result in the current process's heap. A
    /// completion carries only `Send` raw data, never a `Value`.
    fn completion_result(&mut self, result: BlockingResult) -> VmResult<Value> {
        match result {
            BlockingResult::ReadFile { path, result } => match result {
                Ok(bytes) => {
                    let bin = Value::binary_in(&mut self.heap, bytes);
                    self.make_ok(bin)
                }
                Err(e) => {
                    let err = self.io_error_value(&e, &path)?;
                    self.make_err(err)
                }
            },
            BlockingResult::WriteFile { path, result } => match result {
                Ok(()) => {
                    let nil = self.make_nil()?;
                    self.make_ok(nil)
                }
                Err(e) => {
                    let err = self.io_error_value(&e, &path)?;
                    self.make_err(err)
                }
            },
            BlockingResult::ResolveDns { result } => match result {
                Ok(addr) => {
                    let ip = self.templates.ip_address(&mut self.heap, addr)?;
                    self.make_ok(ip)
                }
                Err(e) => {
                    let err = self.net_error_value(&e)?;
                    self.make_err(err)
                }
            },
            BlockingResult::SpawnChild { program, result } => self.port_spawned(&program, result),
            BlockingResult::ReapChild { result } => self.port_reaped(result),
        }
    }

    /// Wake parked processes whose deadline has passed. A popped entry whose id
    /// is gone, or whose live deadline no longer matches, already woke on I/O.
    pub(super) fn wake_due_timers(&mut self) -> VmResult<bool> {
        let now = Instant::now();
        let mut woke = false;
        while let Some(&Reverse((deadline, id))) = self.timer_heap.peek() {
            if deadline > now {
                break;
            }
            self.timer_heap.pop();
            if !matches!(self.parked.get(&id), Some((w, _)) if w.deadline() == Some(deadline)) {
                continue;
            }
            let Some((wait, p)) = self.park_remove(id) else {
                continue;
            };
            // Nothing to disarm: an fd's registration belongs to the socket,
            // not to this wait.
            match wait {
                // A connect that ran out of time resumes *past* the
                // instruction, like the one that completed, so the result it
                // reads has to be pushed here. Waking it bare would resume it
                // with whatever was underneath on the stack.
                Wait::Io {
                    fd,
                    action: WakeAction::CompleteConnect,
                    ..
                } => self.wake_with(p, |vm| vm.timeout_connect(fd))?,
                // Same shape as the connect above: an offload resumes past its
                // instruction, so the result has to be pushed here rather than
                // left to the job that is still running.
                Wait::Offload {
                    deadline: Some((_, kind)),
                    ..
                } => self.wake_with(p, |vm| vm.timed_out_offload(kind))?,
                // An unbounded offload never entered the timer heap, so it
                // cannot reach this arm: the deadline check above admits only
                // waits that named this instant.
                Wait::Io {
                    action: WakeAction::Rerun,
                    ..
                }
                | Wait::Timer(_)
                | Wait::Offload { deadline: None, .. }
                | Wait::Mailbox { .. } => self.run_queue.push_back(p),
            }
            woke = true;
        }
        Ok(woke)
    }

    /// Wait on the poller for at most `timeout` (None = until something
    /// happens) and wake every process parked on a socket that became ready.
    fn drain_io_events(&mut self, timeout: Option<Duration>) -> VmResult<()> {
        // Take the reusable buffer out because the wake paths below need
        // `&mut self`. The capacity-0 placeholder allocates nothing.
        let mut events = std::mem::replace(&mut self.poll_events, mio::Events::with_capacity(0));
        if let Err(e) = poll_wait(&mut self.poll, &mut events, timeout) {
            self.poll_events = events;
            return Err(e);
        }
        for ev in events.iter() {
            if ev.token() == WAKER_TOKEN {
                // A `notify()` from another scheduler. No I/O behind it.
                continue;
            }
            let key = ev.token().0 as i32;
            // Clone first: `park_remove` edits the index.
            let Some(woken) = self.io_waiters.get(&key).cloned() else {
                continue;
            };
            for wid in woken {
                let Some((wait, p)) = self.park_remove(wid) else {
                    continue;
                };
                match wait {
                    // A finished connect pushes its result straight onto the
                    // woken process's stack; the instruction is not re-run.
                    Wait::Io {
                        fd,
                        action: WakeAction::CompleteConnect,
                        ..
                    } => self.wake_with(p, |vm| vm.finish_connect(fd))?,
                    Wait::Io {
                        action: WakeAction::Rerun,
                        ..
                    }
                    | Wait::Timer(_)
                    | Wait::Offload { .. }
                    | Wait::Mailbox { .. } => self.run_queue.push_back(p),
                }
                // The fd stays registered: the registration belongs to the
                // socket, which is still in the tables.
            }
        }
        self.poll_events = events;
        Ok(())
    }

    /// Give up on a pending connect whose deadline passed: drop the socket and
    /// report `TimedOut`.
    ///
    /// Dropping it is what makes the deadline mean anything. The fd is still
    /// mid-handshake in the kernel, and nothing in Scarlet can name it — the
    /// `Socket` value is only ever minted by `finish_connect`'s success arm —
    /// so an entry left behind is an fd no program could ever close.
    ///
    /// An absent entry means the connect completed and was already taken by
    /// `finish_connect` on an I/O wake; the timer then lost a race it cannot
    /// win, and the process has its result. Waking it a second time would push
    /// a second value, so this reports the loss rather than fabricating one.
    fn timeout_connect(&mut self, id: i32) -> VmResult<Value> {
        let Some(socket) = self.pending_connects.remove(&id) else {
            let aborted = self.abi_nullary(AbiSlot::NetEconnaborted)?;
            return self.make_err(aborted);
        };
        self.poller_deregister(socket.as_raw_fd());
        drop(socket);
        let timed_out = self.abi_nullary(AbiSlot::NetEtimedout)?;
        self.make_err(timed_out)
    }

    /// The completion an abandoned offload owes its process, synthesised
    /// because the real one is still on a pool thread and may be for a while.
    /// `failed_blocking_result` does the same for a job no worker could run.
    ///
    /// Built through `completion_result` so a timed-out resolve is the same
    /// value a resolver-side timeout produces; `classify_net` reads the raw
    /// errno, so an `ErrorKind`-only error would land on the `Other(-1)`
    /// residual instead of `TimedOut`.
    fn timed_out_offload(&mut self, kind: OffloadTimeout) -> VmResult<Value> {
        let result = match kind {
            OffloadTimeout::Resolve => BlockingResult::ResolveDns {
                result: Err(io::Error::from_raw_os_error(libc::ETIMEDOUT)),
            },
        };
        self.completion_result(result)
    }

    /// Complete a pending non-blocking connect whose socket became writable:
    /// either adopt the connection or report the error it ended with.
    fn finish_connect(&mut self, id: i32) -> VmResult<Value> {
        let Some(socket) = self.pending_connects.remove(&id) else {
            let aborted = self.abi_nullary(AbiSlot::NetEconnaborted)?;
            return self.make_err(aborted);
        };
        self.poller_deregister(socket.as_raw_fd());
        // Writability after EINPROGRESS means the connect finished. SO_ERROR
        // says whether it succeeded.
        match socket.take_error() {
            Ok(None) => {
                let stream: TcpStream = socket.into();
                match stream.peer_addr() {
                    Ok(peer) => match self.adopt_connection(stream, peer)? {
                        Ok(sock) => self.make_ok(sock),
                        Err(err) => self.make_err(err),
                    },
                    Err(e) => {
                        let err = self.net_error_value(&e)?;
                        self.make_err(err)
                    }
                }
            }
            Ok(Some(e)) | Err(e) => {
                let err = self.net_error_value(&e)?;
                self.make_err(err)
            }
        }
    }
}

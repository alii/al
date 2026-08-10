//! Mailboxes behind `Subject(msg)` values: typed message passing between
//! processes.
//!
//! A subject is created by (and owned by) one process; any process holding the
//! handle may send to it, only the owner may receive. Each subject has its own
//! FIFO queue, so a receive is a queue pop — there is no mailbox scan and no
//! selective-receive pathology: wanting two kinds of message handled
//! differently means two subjects.
//!
//! Messages are deep-copied at send ([`ProcHeap::spawn`], the same copy a
//! spawned closure gets) so sender and receiver never share mutable memory;
//! `Binary` backings ride their `Arc` zero-copy. The copied graph is
//! exclusively owned, which is what makes queueing it across scheduler
//! threads sound under non-atomic refcounts, and the receiver adopts it whole.
//!
//! Blocking follows the socket pattern: an empty-queue receive parks the
//! process under [`Wait::Mailbox`](super::poll::Wait). The lost-wakeup race is
//! closed by `VM::park` re-checking the queue when it registers the waiter
//! under the registry lock; a send that lands in between is seen by that
//! re-check, and a send that lands after finds the waiter and delivers a wake
//! through the owner scheduler's wake queue ([`Runtime::deliver_wake`]).
//!
//! A subject dies with its owner: process death drops its mailboxes and every
//! queued message. Sending to a dead subject silently drops the message —
//! fire-and-forget, the BEAM rule.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::bytecode::Value;
use crate::heap::ProcHeap;

use super::poll::{EPOCH, Parked, Wait, monotonic_now_ms};
use super::sched::Runtime;
use super::{IO_REDUCTION_COST, VM, VmError, VmResult, lock};

/// Every live mailbox, keyed by subject id. One program-wide table (like
/// `Runtime::shared_listeners`) because a sender on any scheduler must reach
/// the queue; the id in the `Subject` value is the key.
pub(super) struct Mailboxes {
    next_id: u64,
    by_id: HashMap<u64, Mailbox>,
    /// Subject ids by owning pid — the death path's index, so ending a
    /// process does not scan every mailbox in the program.
    by_owner: HashMap<u64, Vec<u64>>,
}

impl Mailboxes {
    pub(super) fn new() -> Mailboxes {
        Mailboxes {
            // Id 0 is never minted, so a zeroed subject word is always dead.
            next_id: 1,
            by_id: HashMap::new(),
            by_owner: HashMap::new(),
        }
    }
}

/// One subject's queue. Queued values are exclusively owned deep copies;
/// dropping the mailbox drops them, on whichever thread ends the owner.
struct Mailbox {
    owner: u64,
    queue: VecDeque<Value>,
    /// The owner parked in a receive, as `(scheduler index, wait id)`.
    /// Registered by `VM::park` under the registry lock, taken by the first
    /// send. A registration left behind by a deadline wake is stale; the
    /// owner's next receive clears it, and a wake delivered against it is
    /// skipped by `drain_wakes`.
    waiter: Option<(usize, u64)>,
}

/// The outcome of a receive probe.
pub(super) enum TryReceive {
    Msg(Value),
    Empty,
    /// The calling process does not own the subject (or it is dead, which
    /// with a live caller means the same thing: someone else's subject).
    NotOwner,
}

impl Runtime {
    /// Mint a mailbox owned by `owner` and return its subject id.
    pub(super) fn subject_create(&self, owner: u64) -> u64 {
        let mut reg = lock(&self.mailboxes);
        let id = reg.next_id;
        reg.next_id += 1;
        reg.by_id.insert(
            id,
            Mailbox {
                owner,
                queue: VecDeque::new(),
                waiter: None,
            },
        );
        reg.by_owner.entry(owner).or_default().push(id);
        self.live_subjects.fetch_add(1, Ordering::Relaxed);
        id
    }

    /// Queue `msg` (an exclusively owned graph) on subject `id` and wake a
    /// parked receiver. A dead subject drops the message.
    pub(super) fn subject_send(&self, id: u64, msg: Value) {
        let waiter = {
            let mut reg = lock(&self.mailboxes);
            let Some(mb) = reg.by_id.get_mut(&id) else {
                // Drop outside the lock: the graph can be arbitrarily large.
                drop(reg);
                drop(msg);
                return;
            };
            mb.queue.push_back(msg);
            mb.waiter.take()
        };
        if let Some((sched, wait_id)) = waiter {
            self.deliver_wake(sched, wait_id);
        }
    }

    /// Pop the oldest message for the owner's receive, clearing any stale
    /// waiter registration first — this call IS the owner receiving, so no
    /// send may target the old wait id.
    pub(super) fn subject_try_receive(&self, id: u64, pid: u64) -> TryReceive {
        let mut reg = lock(&self.mailboxes);
        let Some(mb) = reg.by_id.get_mut(&id) else {
            return TryReceive::NotOwner;
        };
        if mb.owner != pid {
            return TryReceive::NotOwner;
        }
        mb.waiter = None;
        match mb.queue.pop_front() {
            Some(v) => TryReceive::Msg(v),
            None => TryReceive::Empty,
        }
    }

    /// Register the owner as parked on subject `id`, re-checking the queue
    /// under the registry lock. Returns false — park nothing, stay runnable —
    /// when a message is already queued (a send raced the park) or the
    /// subject is gone (the re-run surfaces that as an error).
    pub(super) fn subject_park_waiter(&self, id: u64, sched: usize, wait_id: u64) -> bool {
        let mut reg = lock(&self.mailboxes);
        let Some(mb) = reg.by_id.get_mut(&id) else {
            return false;
        };
        if !mb.queue.is_empty() {
            return false;
        }
        mb.waiter = Some((sched, wait_id));
        true
    }

    /// Drop every mailbox `owner` created, with its queued messages. Called
    /// on process death; the counter gate keeps subject-free programs at one
    /// atomic load per death.
    pub(super) fn subject_close_all(&self, owner: u64) {
        if self.live_subjects.load(Ordering::Relaxed) == 0 {
            return;
        }
        let dead: Vec<Mailbox> = {
            let mut reg = lock(&self.mailboxes);
            let Some(ids) = reg.by_owner.remove(&owner) else {
                return;
            };
            ids.into_iter()
                .filter_map(|id| reg.by_id.remove(&id))
                .collect()
        };
        self.live_subjects.fetch_sub(dead.len(), Ordering::Relaxed);
        // The queued graphs are freed here, outside the lock. The owner
        // cannot be parked on any of these (it just died), so no waiter is
        // stranded.
        drop(dead);
    }

    /// Queue a wait id on scheduler `sched`'s wake list and interrupt its
    /// poller. The cross-thread half of waking a parked receiver.
    pub(super) fn deliver_wake(&self, sched: usize, wait_id: u64) {
        lock(&self.slots[sched].wakes).push(wait_id);
        self.notify(sched);
    }
}

impl VM {
    /// `Op::SubjectNew`: push a fresh subject owned by the current process.
    pub(super) fn subject_new(&mut self) -> VmResult<()> {
        let id = self.runtime.subject_create(self.current_pid);
        self.stack.push(Value::subject(id));
        Ok(())
    }

    /// `Op::SubjectSend`: copy the message to the subject's queue. The charge
    /// covers the graph copy and the registry crossing.
    pub(super) fn subject_send(&mut self, reds: &mut i32) -> VmResult<()> {
        *reds -= IO_REDUCTION_COST;
        let msg = self.pop()?;
        let subj = self.pop()?;
        let Some(id) = subj.as_subject() else {
            return Err(VmError::type_mismatch("scheduler.send", "Subject", &subj));
        };
        // The receiver adopts the copy; the sender's original drops with
        // `msg`. The heap handle is zero-sized, so the root alone carries the
        // graph.
        let (_heap, root) = ProcHeap::spawn(&msg);
        self.runtime.subject_send(id, root);
        let nil = self.make_nil()?;
        self.stack.push(nil);
        Ok(())
    }

    /// `Op::SubjectReceive`: pop the oldest message, parking until one
    /// arrives.
    pub(super) fn subject_receive(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        let subj = self.pop()?;
        let id = receive_subject(&subj)?;
        match self.runtime.subject_try_receive(id, self.current_pid) {
            TryReceive::Msg(v) => {
                self.stack.push(v);
                Ok(None)
            }
            TryReceive::Empty => {
                // Park until a send wakes us, then re-run this instruction.
                self.stack.push(subj);
                Ok(Some(Parked::retry(Wait::mailbox(id))))
            }
            TryReceive::NotOwner => Err(VmError::ForeignReceive),
        }
    }

    /// `Op::SubjectReceiveUntil`: as `subject_receive`, bounded by an
    /// absolute monotonic-ms deadline, after which it errs with `Nil`.
    pub(super) fn subject_receive_until(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        // Stack, top first: the deadline, then the subject. The deadline is
        // absolute, so a re-run after a wake never resets the clock.
        let deadline_ms = self.pop_int("scheduler.receive_within")?;
        let subj = self.pop()?;
        let id = receive_subject(&subj)?;
        match self.runtime.subject_try_receive(id, self.current_pid) {
            TryReceive::Msg(v) => {
                let ok = self.make_ok(v)?;
                self.stack.push(ok);
                Ok(None)
            }
            TryReceive::Empty => {
                // The probe runs before the deadline check, so a message that
                // arrived as the clock ran out is never discarded.
                if monotonic_now_ms() >= deadline_ms {
                    let err = self.make_err_nil()?;
                    self.stack.push(err);
                    return Ok(None);
                }
                self.stack.push(subj);
                self.stack.push(Value::small_int(deadline_ms));
                let deadline = *EPOCH.get_or_init(Instant::now)
                    + Duration::from_millis(deadline_ms.max(0) as u64);
                Ok(Some(Parked::retry(Wait::mailbox_until(id, deadline))))
            }
            TryReceive::NotOwner => Err(VmError::ForeignReceive),
        }
    }
}

/// The subject id of a receive operand, or the type mismatch a well-typed
/// program never produces.
fn receive_subject(v: &Value) -> VmResult<u64> {
    v.as_subject()
        .ok_or_else(|| VmError::type_mismatch("scheduler.receive", "Subject", v))
}

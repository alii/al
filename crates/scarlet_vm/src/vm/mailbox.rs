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
//! under the subject's shard lock; a send that lands in between is seen by
//! that re-check, and a send that lands after finds the waiter and delivers a
//! wake through the owner scheduler's wake queue ([`Runtime::deliver_wake`]).
//!
//! A subject dies with its owner: process death drops its mailboxes and every
//! queued message. Sending to a dead subject silently drops the message —
//! fire-and-forget, the BEAM rule. The exception is a *durable* subject, the
//! address of a supervised worker ([`super::supervision`]): it is not indexed
//! under any process, so an incarnation's death leaves it in place for the
//! next incarnation to be given ([`Runtime::subject_rehome`], which also
//! empties it — a fresh incarnation does not inherit the backlog that may
//! have killed the last one), and it is closed explicitly
//! ([`Runtime::subject_close`]) when the worker's slot is retired. That is
//! what makes a supervised worker's address stable across restarts.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::bytecode::Value;
use crate::heap::ProcHeap;

use super::poll::{EPOCH, Parked, Wait, monotonic_now_ms};
use super::sched::Runtime;
use super::{Crash, IO_REDUCTION_COST, VM, VmError, VmResult, lock};

/// Slots per lazily-allocated segment of the subject table.
const SEGMENT_SLOTS: usize = 8192;

/// Bits of a subject id that index a slot; the rest is the slot's serial.
/// 28 bits is a capacity commitment: 2^28 subjects live at once, far past
/// what memory can hold, and it keeps the segment-pointer table small enough
/// to zero at startup without a measurable cost.
const SLOT_BITS: u32 = 28;
const NUM_SEGMENTS: usize = (1 << SLOT_BITS) / SEGMENT_SLOTS;

/// The subject table: every live mailbox, reached directly from the id in
/// the `Subject` value. Program-wide (like `Runtime::shared_listeners`)
/// because a sender on any scheduler must reach the queue.
///
/// The id is a slot index plus a serial — the slotmap BEAM uses for pids —
/// so the message path is an array index and one per-slot lock: no hash, no
/// table-wide lock, and senders on different subjects never contend. The
/// serial changes on every slot reuse, which is what keeps a send to a dead
/// subject a silent drop instead of a delivery to the slot's next tenant.
///
/// The park/wake protocol needs only per-subject serialization: a park and a
/// send on the same id take the same slot lock, which is all the lost-wakeup
/// re-check relies on.
pub(super) struct Mailboxes {
    /// Segments, allocated on first touch and never moved, so a slot
    /// reference stays valid without holding any table-wide lock.
    segments: Vec<OnceLock<Segment>>,
    /// High-water slot index; slots below it not on the free list are live.
    next_slot: AtomicU64,
    /// Retired slot indices awaiting reuse. FIFO, so reuse spreads across
    /// slots and a serial needs its full 2^20 laps of one slot to alias.
    /// Taken at create and death, never per message.
    free: Mutex<VecDeque<u64>>,
    /// Subject ids by owning pid — the death path's index, so ending a
    /// process does not scan every mailbox in the program. Its own lock:
    /// taken at create and death, never per message.
    /// Durable subjects are absent from it, which is what makes them durable.
    by_owner: Mutex<HashMap<u64, Vec<u64>>>,
}

/// One lazily-allocated block of slots, always `SEGMENT_SLOTS` long.
type Segment = Vec<Mutex<Slot>>;

/// One slot of the subject table: the serial of its current (or next) tenant
/// and the mailbox itself. The mutex is the subject's own lock — everything
/// on the message path serializes here and nowhere else.
struct Slot {
    /// Matches the id's serial bits while the tenant is live; bumped when the
    /// tenant dies, so a stale id misses. Never zero, so id 0 (a zeroed
    /// subject word) is always dead.
    serial: u64,
    mb: Option<Mailbox>,
}

impl Mailboxes {
    pub(super) fn new() -> Mailboxes {
        let mut segments = Vec::with_capacity(NUM_SEGMENTS);
        segments.resize_with(NUM_SEGMENTS, OnceLock::new);
        Mailboxes {
            segments,
            next_slot: AtomicU64::new(0),
            free: Mutex::new(VecDeque::new()),
            by_owner: Mutex::new(HashMap::new()),
        }
    }

    /// The slot at `index`, allocating its segment if this is the first
    /// touch. The lock is NOT taken and the serial is NOT checked; every
    /// caller does both.
    fn slot(&self, index: u64) -> &Mutex<Slot> {
        let index = index as usize;
        let seg = self.segments[index / SEGMENT_SLOTS].get_or_init(|| {
            let mut v = Vec::with_capacity(SEGMENT_SLOTS);
            v.resize_with(SEGMENT_SLOTS, || {
                Mutex::new(Slot {
                    serial: 0,
                    mb: None,
                })
            });
            v
        });
        &seg[index % SEGMENT_SLOTS]
    }
}

/// Which end of the queue a send lands on. Everything a program sends goes
/// to the back; only the runtime's own stop requests go to the front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Delivery {
    Back,
    Front,
}

/// What a subject is the address of; see [`Runtime::subject_place`].
pub(super) enum SubjectPlace {
    Worker(u64),
    Process(u64),
}

/// One subject's queue. Queued values are exclusively owned deep copies;
/// dropping the mailbox drops them, on whichever thread ends the owner.
struct Mailbox {
    owner: u64,
    /// For a durable subject, the supervised worker it is the address of
    /// (an entry id in the process table); what `process.supervised(addr)`
    /// looks up. Named to keep clear of this file's own table slots.
    worker: Option<u64>,
    queue: VecDeque<Value>,
    /// The owner parked in a receive, as `(scheduler index, wait id)`.
    /// Registered by `VM::park` under the shard lock, taken by the first
    /// send. A registration left behind by a deadline wake is stale; the
    /// owner's next receive clears it, and a wake delivered against it is
    /// skipped by `drain_wakes`.
    waiter: Option<(usize, u64)>,
}

/// The slot index half of a subject id.
fn slot_index(id: u64) -> u64 {
    id & ((1 << SLOT_BITS) - 1)
}

/// The serial half of a subject id.
fn slot_serial(id: u64) -> u64 {
    id >> SLOT_BITS
}

/// The serial after `serial`, wrapping within the id's serial bits and
/// skipping 0 so a zeroed subject word can never match a live slot.
fn next_serial(serial: u64) -> u64 {
    let wrapped = (serial + 1) & ((1 << (48 - SLOT_BITS)) - 1);
    if wrapped == 0 { 1 } else { wrapped }
}

/// The outcome of a receive probe.
enum TryReceive {
    Msg(Value),
    Empty,
    /// The calling process does not own the subject (or it is dead, which
    /// with a live caller means the same thing: someone else's subject).
    NotOwner,
}

impl Runtime {
    /// Mint a mailbox owned by `owner`, indexed so it dies with `owner`, and
    /// return its subject id.
    fn subject_create(&self, owner: u64) -> u64 {
        let id = self.alloc_mailbox(owner);
        lock(&self.mailboxes.by_owner)
            .entry(owner)
            .or_default()
            .push(id);
        id
    }

    /// Mint a durable mailbox: received on by `receiver` for now, surviving
    /// its death, closed only by [`Runtime::subject_close`]. The caller owns
    /// that close.
    pub(super) fn subject_create_durable(&self, receiver: u64, worker: u64) -> u64 {
        let id = self.alloc_mailbox(receiver);
        if let Some(mb) = lock(self.mailboxes.slot(slot_index(id))).mb.as_mut() {
            mb.worker = Some(worker);
        }
        id
    }

    /// Where a subject sits in the tree: the worker it is the address of, or
    /// else the process that owns it. `None` once it is dead.
    pub(super) fn subject_place(&self, id: u64) -> Option<SubjectPlace> {
        let slot = lock(self.mailboxes.slot(slot_index(id)));
        let live = slot.serial == slot_serial(id);
        slot.mb.as_ref().filter(|_| live).map(|mb| match mb.worker {
            Some(worker) => SubjectPlace::Worker(worker),
            None => SubjectPlace::Process(mb.owner),
        })
    }

    /// Hand a durable subject to a new incarnation, dropping whatever queued
    /// since the last one and any waiter it left. A subject already closed
    /// (the slot was retired meanwhile) is a no-op. The dropped queue is
    /// freed outside the slot lock.
    pub(super) fn subject_rehome(&self, id: u64, receiver: u64) {
        let stale = {
            let mut slot = lock(self.mailboxes.slot(slot_index(id)));
            let live = slot.serial == slot_serial(id);
            match slot.mb.as_mut().filter(|_| live) {
                Some(mb) => {
                    mb.owner = receiver;
                    mb.waiter = None;
                    std::mem::take(&mut mb.queue)
                }
                None => VecDeque::new(),
            }
        };
        drop(stale);
    }

    /// Close one durable subject, dropping its queue. Later sends are
    /// dropped, as to any dead subject.
    pub(super) fn subject_close(&self, id: u64) {
        let dead = {
            let mut slot = lock(self.mailboxes.slot(slot_index(id)));
            let live = slot.serial == slot_serial(id);
            if live { slot.mb.take() } else { None }
        };
        if dead.is_some() {
            self.live_subjects.fetch_sub(1, Ordering::Relaxed);
            lock(&self.mailboxes.free).push_back(slot_index(id));
        }
        drop(dead);
    }

    /// Take a slot and install an empty mailbox for `owner` in it. Shared by
    /// both kinds of subject; indexing is the caller's decision.
    fn alloc_mailbox(&self, owner: u64) -> u64 {
        let index = match lock(&self.mailboxes.free).pop_front() {
            Some(i) => i,
            None => {
                let i = self.mailboxes.next_slot.fetch_add(1, Ordering::Relaxed);
                if i >= 1 << SLOT_BITS {
                    // BEAM's system_limit: this many live subjects is far
                    // past any real memory budget, so the program is broken.
                    // Die loudly rather than corrupt the id space.
                    eprintln!("scarlet: subject table exhausted (2^{SLOT_BITS} subjects live)");
                    std::process::abort();
                }
                i
            }
        };
        let id = {
            let mut slot = lock(self.mailboxes.slot(index));
            slot.serial = next_serial(slot.serial);
            slot.mb = Some(Mailbox {
                owner,
                worker: None,
                queue: VecDeque::new(),
                waiter: None,
            });
            (slot.serial << SLOT_BITS) | index
        };
        self.live_subjects.fetch_add(1, Ordering::Relaxed);
        id
    }

    /// Queue `msg` (an exclusively owned graph) on subject `id` and wake a
    /// parked receiver. A dead subject drops the message.
    fn subject_send(&self, id: u64, msg: Value, delivery: Delivery) {
        let waiter = {
            let mut slot = lock(self.mailboxes.slot(slot_index(id)));
            let live = slot.serial == slot_serial(id);
            let Some(mb) = slot.mb.as_mut().filter(|_| live) else {
                // Drop outside the lock: the graph can be arbitrarily large.
                drop(slot);
                drop(msg);
                return;
            };
            match delivery {
                Delivery::Back => mb.queue.push_back(msg),
                Delivery::Front => mb.queue.push_front(msg),
            }
            mb.waiter.take()
        };
        if let Some((sched, wait_id)) = waiter {
            self.deliver_wake(sched, wait_id);
        }
    }

    /// Pop the oldest message for the owner's receive, clearing any stale
    /// waiter registration first — this call IS the owner receiving, so no
    /// send may target the old wait id.
    fn subject_try_receive(&self, id: u64, pid: u64) -> TryReceive {
        let mut slot = lock(self.mailboxes.slot(slot_index(id)));
        let live = slot.serial == slot_serial(id);
        let Some(mb) = slot.mb.as_mut().filter(|_| live) else {
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
    /// under the slot lock. Returns false — park nothing, stay runnable —
    /// when a message is already queued (a send raced the park) or the
    /// subject is gone (the re-run surfaces that as an error).
    pub(super) fn subject_park_waiter(&self, id: u64, sched: usize, wait_id: u64) -> bool {
        let mut slot = lock(self.mailboxes.slot(slot_index(id)));
        let live = slot.serial == slot_serial(id);
        let Some(mb) = slot.mb.as_mut().filter(|_| live) else {
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
        let Some(ids) = lock(&self.mailboxes.by_owner).remove(&owner) else {
            return;
        };
        // The serial stays until the slot's next tenant bumps it, so a
        // straggler send between here and reuse misses on `mb` being gone.
        let mut retired = Vec::with_capacity(ids.len());
        let dead: Vec<Mailbox> = ids
            .into_iter()
            .filter_map(|id| {
                let mut slot = lock(self.mailboxes.slot(slot_index(id)));
                let live = slot.serial == slot_serial(id);
                let mb = if live { slot.mb.take() } else { None };
                if mb.is_some() {
                    retired.push(slot_index(id));
                }
                mb
            })
            .collect();
        self.live_subjects.fetch_sub(dead.len(), Ordering::Relaxed);
        lock(&self.mailboxes.free).extend(retired);
        // The queued graphs are freed here, outside the lock. The owner
        // cannot be parked on any of these (it just died), so no waiter is
        // stranded.
        drop(dead);
    }

    /// Queue a wait id on scheduler `sched`'s wake list and interrupt its
    /// poller. The cross-thread half of waking a parked receiver.
    ///
    /// The poller interrupt (a syscall) is skipped when the target scheduler
    /// is running: it drains its wake queue at every yield. This cannot lose
    /// a wake — the target raises its parked flag *before* draining the queue
    /// one last time, and both sides cross the queue's mutex, so either the
    /// drain sees this push or this thread sees the raised flag and notifies.
    fn deliver_wake(&self, sched: usize, wait_id: u64) {
        lock(&self.slots[sched].wakes).push(wait_id);
        if self.is_parked(sched) {
            self.notify(sched);
        }
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
    pub(super) fn subject_send(&mut self, reds: &mut i32, delivery: Delivery) -> VmResult<()> {
        *reds -= IO_REDUCTION_COST;
        let msg = self.pop()?;
        let subj = self.pop()?;
        let Some(id) = subj.as_subject() else {
            return Err(VmError::type_mismatch("process.send", "Subject", &subj));
        };
        // The receiver adopts the copy; the sender's original drops with
        // `msg`. The heap handle is zero-sized, so the root alone carries the
        // graph.
        let (_heap, root) = ProcHeap::spawn(&msg);
        self.runtime.subject_send(id, root, delivery);
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
            TryReceive::NotOwner => Err(VmError::Crash(Crash::ForeignReceive)),
        }
    }

    /// `Op::SubjectReceiveUntil`: as `subject_receive`, bounded by an
    /// absolute monotonic-ms deadline, after which it errs with `Nil`.
    pub(super) fn subject_receive_until(&mut self, reds: &mut i32) -> VmResult<Option<Parked>> {
        *reds -= IO_REDUCTION_COST;
        // Stack, top first: the deadline, then the subject. The deadline is
        // absolute, so a re-run after a wake never resets the clock.
        let deadline_ms = self.pop_int("process.receive_within")?;
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
            TryReceive::NotOwner => Err(VmError::Crash(Crash::ForeignReceive)),
        }
    }
}

/// The subject id of a receive operand, or the type mismatch a well-typed
/// program never produces.
fn receive_subject(v: &Value) -> VmResult<u64> {
    v.as_subject()
        .ok_or_else(|| VmError::type_mismatch("process.receive", "Subject", v))
}

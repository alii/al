//! The process table: which pids are alive and where, the links between
//! them, the monitors on them, and the three ways a process ends.
//!
//! A pid is minted by [`Runtime::alloc_pid`], which is also what makes the
//! process exist here; [`VM::terminate`] is the one exit. The table is the
//! only source of liveness, and it is kept from birth, not from the first
//! monitor: `monitor` on a pid that has already ended must fire at once,
//! and `kill` of one must be a no-op, and neither is answerable unless every
//! death was recorded. It is sharded by pid so the per-spawn and per-death
//! touch is one mostly-uncontended lock and one hash operation, and no two
//! shard locks are ever held together.
//!
//! # Ending
//!
//! A process ends by returning ([`Exit::Normal`]), by a runtime error in its
//! own code ([`Exit::Crashed`] — an index out of range is that process's
//! problem and nobody else's), or by being killed ([`Exit::Killed`]),
//! either explicitly or through a link. Whichever way, the same things
//! happen: its connections and ports close, its subjects die, its monitors
//! fire, and — for the two abnormal exits — everything linked to it is
//! killed in turn. A crash therefore propagates through the linked tree
//! until it reaches a process that was spawned unlinked; a supervisor is a
//! process that spawns its children unlinked and monitors them instead. Only
//! a fault of the runtime itself ([`super::VmError::Internal`],
//! [`super::VmError::Io`]) still ends the whole program.
//!
//! # Links
//!
//! Links are made only by `spawn`, so every process has at most one link
//! upward (its parent, kept inline in its record) and a set downward (its
//! children). That keeps a linked spawn to one insert on each side, and it
//! is why the record is two words plus a lazily-boxed remainder: almost no
//! process is ever monitored, but every one is spawned.
//!
//! # Killing
//!
//! A process to be killed may be queued or parked on any scheduler, running
//! on one, or in transit between two. `kill` marks the record and pokes the
//! scheduler the record names; that scheduler ends the process if it holds
//! it, and any scheduler adopting a process consults the mark first, so a
//! process cannot dodge a kill by moving. A running process is ended when
//! its slice ends. Nothing on the context-switch path reads the table.
//!
//! # Monitors
//!
//! A monitor is a closure. `process.monitor(pid, inbox, wrap)` builds
//! `fn(down) send(inbox, wrap(down))` and hands it here, where it is
//! deep-copied exactly as a message would be ([`ProcHeap::spawn`]) and parked
//! on the target's record. When the target ends, each parked closure is
//! started as a process of its own with the `Down` value as its argument —
//! so a death notice is delivered by ordinary sends, in the watcher's own
//! message type, and needs no receive machinery beyond `receive`. It is sent
//! after everything the dead process itself sent, since those sends were
//! queued while it ran. Every process also records the monitors it holds,
//! so a watcher that ends first takes its registrations with it.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::abi::AbiSlot;
use crate::bytecode::Value;
use crate::bytecode::value::proof_violation;
use crate::heap::ProcHeap;

use super::sched::Runtime;
use super::{Crash, IO_REDUCTION_COST, Process, VM, VmError, VmResult, lock};

/// The live-process table. See the module docs.
pub(super) struct ProcessTable {
    /// Always a power of two, so a pid picks its shard by mask.
    shards: Vec<Mutex<Shard>>,
    /// Program-unique monitor ids, so a `Monitor` value names one
    /// registration for the whole run.
    next_monitor: AtomicU64,
}

pub(super) type PidHash = BuildHasherDefault<PidHasher>;

/// One shard: the records of the live processes hashed here.
type Shard = HashMap<u64, ProcRecord, PidHash>;

/// Hashes a pid (or a monitor id) by one multiplication. Both are sequential
/// integers minted by the runtime, not attacker-chosen keys, so SipHash's
/// protection buys nothing and its cost would be paid twice per process
/// lifetime; the odd multiplier (2^64 / φ) spreads consecutive ids across
/// the high bits, which is what `HashMap` indexes by.
#[derive(Default)]
pub(super) struct PidHasher(u64);

impl Hasher for PidHasher {
    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.0 = id.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn write(&mut self, _bytes: &[u8]) {
        // Every key hashed here is a `u64`, which goes through `write_u64`.
        proof_violation("PidHasher fed a non-u64 key");
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// One live process.
struct ProcRecord {
    /// The scheduler currently holding the process, as a hint for `kill`:
    /// updated on every adoption, so at worst it lags one hop, which the
    /// adopter's own check covers.
    sched: u32,
    /// Set by `kill`; honoured by whichever scheduler next holds the
    /// process. Never cleared — a killed process only ever ends.
    killed: bool,
    /// The process this one is linked to upward, while it is alive.
    parent: Option<u64>,
    /// Everything only some processes have.
    more: Option<Box<More>>,
}

#[derive(Default)]
struct More {
    /// The supervision slot this process is the incarnation of
    /// ([`super::supervision`]); its death is reported there.
    slot: Option<u64>,
    /// Whether the supervision tree wants to hear about this process's
    /// death: it declared top-level supervisors (torn down if it fails) or
    /// holds watches (released either way).
    in_tree: bool,
    /// Linked children still alive.
    children: HashSet<u64, PidHash>,
    /// Death notices to fire when this process ends, by monitor id.
    watched_by: HashMap<u64, Notice, PidHash>,
    /// Monitors this process holds on others: monitor id → target pid.
    holds: HashMap<u64, u64, PidHash>,
}

impl ProcRecord {
    fn more(&mut self) -> &mut More {
        self.more.get_or_insert_default()
    }
}

/// A parked death notice: the watcher's closure, copied into a heap of its
/// own so it can be started as a process on whichever scheduler the target
/// ends on.
struct Notice {
    /// The process that registered it, so firing can also retire the entry
    /// in that process's `holds` — otherwise a supervisor restarting
    /// children for ever would accumulate one dead entry per child.
    holder: u64,
    heap: ProcHeap,
    closure: Value,
}

// A notice crosses to the scheduler that ends the target, so it must stay a
// plain move like a seed.
const _: () = crate::assert_send::<Notice>();

/// A monitor registration as the program sees it: the `Monitor` value's
/// payload. `target` is what locates the record; `id` names the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MonitorRef {
    target: u64,
    id: u64,
}

/// Whether a spawn links the child to its spawner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Link {
    ToParent,
    None,
}

/// How a process ended. What the notices report, and what decides whether
/// the exit spreads over links.
#[derive(Debug, Clone)]
pub(super) enum Exit {
    Normal,
    Killed,
    Crashed(Crash),
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Exit::Normal => f.write_str("returned"),
            Exit::Killed => f.write_str("killed"),
            Exit::Crashed(crash) => write!(f, "crashed: {crash}"),
        }
    }
}

impl Exit {
    fn spreads_over_links(&self) -> bool {
        match self {
            Exit::Normal => false,
            Exit::Killed | Exit::Crashed(_) => true,
        }
    }
}

/// What a dead process leaves for the scheduler that ended it to act on.
struct Aftermath {
    notices: Vec<Notice>,
    /// The processes linked to it — parent and children — which an abnormal
    /// exit kills. Empty for a normal exit, whose links are simply undone.
    linked: Vec<u64>,
    /// The supervision slot it was running in, to be told of the exit.
    slot: Option<u64>,
    /// Whether the tree is to be told of the death (see `More::in_tree`),
    /// and whether the death was a failure, which is what tears down the
    /// supervisors it declared: they follow the link rule, dying with the
    /// process when it fails and outliving it when it merely returns — a
    /// script that sets up a server and falls off the end of the file has
    /// started a server, not torn one down.
    in_tree: bool,
    failed: bool,
}

impl Aftermath {
    fn empty() -> Aftermath {
        Aftermath {
            notices: Vec::new(),
            linked: Vec::new(),
            slot: None,
            in_tree: false,
            failed: false,
        }
    }
}

impl ProcessTable {
    pub(super) fn new(schedulers: usize) -> ProcessTable {
        let count = schedulers.max(1).next_power_of_two();
        let mut shards = Vec::with_capacity(count);
        shards.resize_with(count, || Mutex::new(HashMap::default()));
        ProcessTable {
            shards,
            next_monitor: AtomicU64::new(1),
        }
    }

    fn shard(&self, pid: u64) -> &Mutex<Shard> {
        &self.shards[(pid as usize) & (self.shards.len() - 1)]
    }
}

/// What `Runtime::monitor` did with a registration.
enum Registered {
    /// The target is alive; the notice is parked on it.
    Parked,
    /// The target had already ended. The notice comes straight back for the
    /// caller to fire.
    TargetDead(Notice),
}

impl Runtime {
    /// Bring `pid` into existence on scheduler `sched`, linked to `parent`
    /// or not. Called by `alloc_pid` for every process, so a pid is
    /// monitorable and killable from the moment it is handed out. The parent
    /// is the running process, so it is alive; its side of the link is the
    /// second insert.
    pub(super) fn register_process(&self, pid: u64, sched: usize, parent: Option<u64>) {
        lock(self.processes.shard(pid)).insert(
            pid,
            ProcRecord {
                sched: sched as u32,
                killed: false,
                parent,
                more: None,
            },
        );
        if let Some(parent) = parent
            && let Some(p) = lock(self.processes.shard(parent)).get_mut(&parent)
        {
            p.more().children.insert(pid);
        }
    }

    /// Mint the pid of a process that will run in supervision slot `slot`.
    /// Linked to nothing: its failure is the slot's business.
    pub(super) fn alloc_incarnation(&self, sched: usize, slot: u64) -> u64 {
        let pid = self.alloc_pid(sched, None);
        if let Some(r) = lock(self.processes.shard(pid)).get_mut(&pid) {
            r.more().slot = Some(slot);
        }
        pid
    }

    /// `pid` declared a top-level supervisor or placed a watch; the tree
    /// must hear of its death.
    pub(super) fn note_in_tree(&self, pid: u64) {
        if let Some(r) = lock(self.processes.shard(pid)).get_mut(&pid) {
            r.more().in_tree = true;
        }
    }

    pub(super) fn process_is_live(&self, pid: u64) -> bool {
        lock(self.processes.shard(pid)).contains_key(&pid)
    }

    /// What is above a process: the slot it incarnates, else the process it
    /// is linked under. `None` for a root or a dead pid.
    pub(super) fn process_parent(&self, pid: u64) -> Option<u64> {
        let shard = lock(self.processes.shard(pid));
        let r = shard.get(&pid)?;
        r.more.as_ref().and_then(|m| m.slot).or(r.parent)
    }

    /// A process has arrived on scheduler `sched` (by donation or as a
    /// pinned seed). Records where it is and reports whether a kill reached
    /// the table while it was in transit, which the adopter must then carry
    /// out. A dead pid — impossible for a process being adopted — reads as
    /// killed, which is the safe answer.
    pub(super) fn note_adopted(&self, pid: u64, sched: usize) -> bool {
        match lock(self.processes.shard(pid)).get_mut(&pid) {
            Some(r) => {
                r.sched = sched as u32;
                r.killed
            }
            None => true,
        }
    }

    /// Ask for `pid` to be ended. Marks the record — the mark is what makes
    /// the kill stick whatever the process is doing — then pokes the
    /// scheduler last known to hold it. A pid that has already ended is a
    /// no-op. Returns whether the process was alive.
    pub(super) fn kill(&self, pid: u64) -> bool {
        let sched = {
            let mut shard = lock(self.processes.shard(pid));
            let Some(r) = shard.get_mut(&pid) else {
                return false;
            };
            r.killed = true;
            r.sched as usize
        };
        self.request_kill_on(sched, pid);
        true
    }

    /// Take `pid` out of the table as it ends, undoing or (for an abnormal
    /// exit) arming its links, and detaching every monitor in both
    /// directions. Each step holds one shard lock at a time; a peer that has
    /// itself ended (including `pid`, for a self-monitor) is simply absent.
    ///
    /// The exit comes back possibly amended: a process that was killed while
    /// alive but managed to return before the kill was applied — a process
    /// killing itself, typically — ended by being killed, and its monitors
    /// and links are told so. A crash is not downgraded; it is the more
    /// specific fact.
    fn unregister_process(&self, pid: u64, exit: Exit) -> (Exit, Aftermath) {
        let Some(record) = lock(self.processes.shard(pid)).remove(&pid) else {
            return (exit, Aftermath::empty());
        };
        let exit = match exit {
            Exit::Normal if record.killed => Exit::Killed,
            Exit::Normal | Exit::Killed | Exit::Crashed(_) => exit,
        };
        let spread = exit.spreads_over_links();
        let mut aftermath = Aftermath::empty();
        if let Some(parent) = record.parent {
            if let Some(p) = lock(self.processes.shard(parent)).get_mut(&parent)
                && let Some(more) = p.more.as_mut()
            {
                more.children.remove(&pid);
            }
            if spread {
                aftermath.linked.push(parent);
            }
        }
        let Some(more) = record.more else {
            return (exit, aftermath);
        };
        aftermath.slot = more.slot;
        aftermath.in_tree = more.in_tree;
        aftermath.failed = spread;
        for child in more.children {
            if spread {
                aftermath.linked.push(child);
            } else if let Some(c) = lock(self.processes.shard(child)).get_mut(&child) {
                c.parent = None;
            }
        }
        for (id, target) in more.holds {
            if let Some(t) = lock(self.processes.shard(target)).get_mut(&target)
                && let Some(t) = t.more.as_mut()
            {
                t.watched_by.remove(&id);
            }
        }
        aftermath.notices.reserve(more.watched_by.len());
        for (id, notice) in more.watched_by {
            if let Some(h) = lock(self.processes.shard(notice.holder)).get_mut(&notice.holder)
                && let Some(h) = h.more.as_mut()
            {
                h.holds.remove(&id);
            }
            aftermath.notices.push(notice);
        }
        (exit, aftermath)
    }

    /// Park `notice` on `target`, minting the monitor id. A target that has
    /// already ended hands the notice back instead: the caller fires it
    /// immediately, which is what closes the gap between a death and a
    /// monitor placed just after it.
    fn monitor(&self, target: u64, notice: Notice) -> (MonitorRef, Registered) {
        let holder = notice.holder;
        let id = self.processes.next_monitor.fetch_add(1, Ordering::Relaxed);
        let m = MonitorRef { target, id };
        {
            let mut shard = lock(self.processes.shard(target));
            let Some(t) = shard.get_mut(&target) else {
                drop(shard);
                return (m, Registered::TargetDead(notice));
            };
            t.more().watched_by.insert(id, notice);
        }
        // The holder is the running process, so it is alive; a holder
        // monitoring itself is the same record twice, taken in two separate
        // critical sections.
        if let Some(h) = lock(self.processes.shard(holder)).get_mut(&holder) {
            h.more().holds.insert(id, target);
        }
        (m, Registered::Parked)
    }

    /// Cancel `m`. A notice already taken by the target's death may still be
    /// on its way; a monitor that never existed or already fired is a no-op.
    /// The dropped notice's closure graph is freed outside both locks.
    fn demonitor(&self, holder: u64, m: MonitorRef) {
        let removed = lock(self.processes.shard(m.target))
            .get_mut(&m.target)
            .and_then(|t| t.more.as_mut()?.watched_by.remove(&m.id));
        if let Some(h) = lock(self.processes.shard(holder)).get_mut(&holder)
            && let Some(h) = h.more.as_mut()
        {
            h.holds.remove(&m.id);
        }
        drop(removed);
    }

    /// The scheduler last recorded as holding `pid`, or `None` once it has
    /// ended. What `net.give` uses to refuse to hand a connection to a
    /// process that could not use it from here.
    pub(super) fn process_scheduler(&self, pid: u64) -> Option<usize> {
        lock(self.processes.shard(pid))
            .get(&pid)
            .map(|r| r.sched as usize)
    }
}

impl VM {
    /// `Op::ProcessMonitor`: `[pid, closure] -> Monitor`. Charged like a send:
    /// the closure graph is copied.
    pub(super) fn process_monitor(&mut self, reds: &mut i32) -> VmResult<()> {
        *reds -= IO_REDUCTION_COST;
        let closure = self.pop()?;
        let pid_v = self.pop()?;
        let Some(target) = pid_v.as_pid() else {
            return Err(VmError::type_mismatch("process.monitor", "Pid", &pid_v));
        };
        self.check_notice_closure(&closure)?;
        let (heap, root) = ProcHeap::spawn(&closure);
        let notice = Notice {
            holder: self.current_pid,
            heap,
            closure: root,
        };
        let (m, registered) = self.runtime.monitor(target, notice);
        if let Registered::TargetDead(notice) = registered {
            let reason = self.abi_nullary(AbiSlot::ExitNoProcess)?;
            self.fire_notice(target, reason, notice);
        }
        let handle = self.abi_make(
            AbiSlot::Monitor,
            &[Value::pid(m.target), Value::small_int(m.id as i64)],
        )?;
        self.stack.push(handle);
        Ok(())
    }

    /// `Op::ProcessDemonitor`: `[Monitor] -> Nil`.
    pub(super) fn process_demonitor(&mut self) -> VmResult<()> {
        let handle = self.pop()?;
        let m = decode_monitor(&handle)?;
        self.runtime.demonitor(self.current_pid, m);
        let nil = self.make_nil()?;
        self.stack.push(nil);
        Ok(())
    }

    /// `Op::ProcessKill`: `[pid] -> Nil`. Asynchronous, like a send: the
    /// process ends when the scheduler holding it next looks, and a process
    /// killing itself ends when its slice does. Charged like I/O so a kill
    /// storm is preemptible.
    pub(super) fn process_kill(&mut self, reds: &mut i32) -> VmResult<()> {
        *reds -= IO_REDUCTION_COST;
        let pid_v = self.pop()?;
        let Some(pid) = pid_v.as_pid() else {
            return Err(VmError::type_mismatch("process.kill", "Pid", &pid_v));
        };
        self.runtime.kill(pid);
        let nil = self.make_nil()?;
        self.stack.push(nil);
        Ok(())
    }

    /// The one exit. Called on whichever scheduler holds the process as it
    /// ends, after its stack and heap have been dealt with (or are about to
    /// be dropped: nothing here reads them). Closes what it owned, fires its
    /// monitors, spreads an abnormal exit over its links, and takes it out
    /// of the live count — in that order, so a notice can never be delivered
    /// to one of the dead process's own subjects, and the program cannot be
    /// observed as finished while notices are still to be started.
    /// The exit as it was finally recorded is handed back: main's crash
    /// becomes the run's outcome, and a return that turned out to be a kill
    /// is reported as one.
    pub(super) fn terminate(&mut self, pid: u64, exit: Exit) -> VmResult<Exit> {
        self.release_connections_of(pid);
        let (exit, aftermath) = self.runtime.unregister_process(pid, exit);
        for notice in aftermath.notices {
            let reason = self.exit_reason(&exit)?;
            self.fire_notice(pid, reason, notice);
        }
        for linked in aftermath.linked {
            self.runtime.kill(linked);
        }
        // Supervision last, and before the live count drops: a restart it
        // orders is started here, so the program cannot be seen as finished
        // between a supervised worker's death and its re-incarnation.
        if let Some(slot) = aftermath.slot {
            let actions = self.runtime.slot_incarnation_exited(slot, &exit);
            self.run_supervision_actions(actions)?;
        }
        if aftermath.in_tree {
            let actions = self.runtime.tree_process_exited(pid, aftermath.failed);
            self.run_supervision_actions(actions)?;
        }
        self.runtime.process_finished();
        Ok(exit)
    }

    /// End a process this scheduler holds but is not running: dropping `p`
    /// frees everything it owned on the heap.
    pub(super) fn discard_killed(&mut self, p: Process) -> VmResult<()> {
        let pid = p.pid;
        if p.is_main {
            // Main never migrates, so this is scheduler 0, whose outcome it
            // is; the value it would have returned no longer exists.
            self.note_main_killed();
        }
        drop(p);
        self.terminate(pid, Exit::Killed)?;
        Ok(())
    }

    /// The `ExitReason` value for `exit`, built fresh per notice: each notice
    /// becomes a separate process, and processes share no mortal values.
    pub(super) fn exit_reason(&mut self, exit: &Exit) -> VmResult<Value> {
        match exit {
            Exit::Normal => self.abi_nullary(AbiSlot::ExitNormal),
            Exit::Killed => self.abi_nullary(AbiSlot::ExitKilled),
            Exit::Crashed(crash) => {
                let crash = self.crash_value(crash)?;
                self.abi_make(AbiSlot::ExitCrashed, &[crash])
            }
        }
    }

    fn crash_value(&mut self, crash: &Crash) -> VmResult<Value> {
        match crash {
            Crash::IndexOutOfBounds { idx, len, .. } => {
                let fields = [
                    Value::int_in(&mut self.heap, *idx),
                    Value::int_in(&mut self.heap, *len),
                ];
                self.abi_make(AbiSlot::CrashIndexOutOfBounds, &fields)
            }
            Crash::SliceOutOfBounds { lo, hi, len } => {
                let fields = [
                    Value::int_in(&mut self.heap, *lo),
                    Value::int_in(&mut self.heap, *hi),
                    Value::int_in(&mut self.heap, *len),
                ];
                self.abi_make(AbiSlot::CrashSliceOutOfBounds, &fields)
            }
            Crash::ForeignReceive => self.abi_nullary(AbiSlot::CrashForeignReceive),
            Crash::Supervision(refusal) => {
                let why = Value::str_in(&mut self.heap, &refusal.to_string());
                self.abi_make(AbiSlot::CrashSupervision, &[why])
            }
            Crash::Panicked(message) => {
                let message = Value::str_in(&mut self.heap, message);
                self.abi_make(AbiSlot::CrashPanicked, &[message])
            }
            Crash::TypeMismatch { op, expected, got } => {
                let fields = [
                    Value::str_in(&mut self.heap, op),
                    Value::str_in(&mut self.heap, expected),
                    Value::str_in(&mut self.heap, got),
                ];
                self.abi_make(AbiSlot::CrashTypeMismatch, &fields)
            }
        }
    }

    /// Start `notice`'s closure as a process, applied to `Down(target,
    /// reason)`. The `Down` is referenced only by the new process's frame,
    /// so nothing is shared with the process that ended (or, for an
    /// immediate fire, with the caller). Notices are never linked to
    /// anything: a watcher's own exit must not take its notices down.
    fn fire_notice(&mut self, target: u64, reason: Value, notice: Notice) {
        // Building `Down` cannot fail once `reason` exists: the two slots
        // are bound together (`slots_for`), and `reason` came from one.
        let down = match self.abi_make(AbiSlot::Down, &[Value::pid(target), reason]) {
            Ok(down) => down,
            Err(_) => proof_violation("Down slot unbound while an ExitReason slot is bound"),
        };
        self.runtime.process_started();
        self.spawn_process_with_heap_args(notice.heap, notice.closure, &[down]);
    }

    /// A notice closure takes exactly the `Down` argument. The stdlib wrapper
    /// fixes the type, so anything else is a compiler invariant breach.
    fn check_notice_closure(&self, f: &Value) -> VmResult<()> {
        let Some(cl) = f.as_closure() else {
            return Err(VmError::internal("monitor requires a function"));
        };
        if self.program.functions[cl.func_idx() as usize].arity != 1 {
            return Err(VmError::internal(
                "a monitor's notice function takes exactly one argument",
            ));
        }
        Ok(())
    }
}

/// Read a `Monitor` value: the record `{ target Pid, id Int }` the VM built
/// in `process_monitor`. The type is opaque to programs, so a malformed one
/// is a compiler invariant breach.
fn decode_monitor(v: &Value) -> VmResult<MonitorRef> {
    let bad = || VmError::type_mismatch("process.demonitor", "Monitor", v);
    let e = v.as_enum().ok_or_else(bad)?;
    let payload = e.payload();
    let target = payload.first().and_then(Value::as_pid).ok_or_else(bad)?;
    let id = payload.get(1).and_then(Value::as_int).ok_or_else(bad)?;
    Ok(MonitorRef {
        target,
        id: id as u64,
    })
}

#[cfg(test)]
mod tests {
    //! The table's own guarantees, driven without a program: liveness from
    //! birth, notices moving from the target's record to its death, holder
    //! death cleaning up after itself, and links armed or undone by the kind
    //! of exit. End-to-end behaviour lives in `tests/programs/monitors.scrl`
    //! and `tests/programs/exits.scrl`.

    use super::super::halt_test_vm;
    use super::*;

    fn notice(vm: &mut VM, holder: u64) -> Notice {
        // Any closure will do for the table: the arity check is the op's,
        // not the table's.
        let closure = Value::closure_in(&mut vm.heap, 0, &[]);
        let (heap, root) = ProcHeap::spawn(&closure);
        Notice {
            holder,
            heap,
            closure: root,
        }
    }

    fn spawn_linked(vm: &VM, parent: u64) -> u64 {
        vm.runtime.alloc_pid(0, Some(parent))
    }

    /// How many monitors `pid` holds: `None` if it is not live, 0 for a
    /// live process that was never involved in one.
    fn holds_of(vm: &VM, pid: u64) -> Option<usize> {
        lock(vm.runtime.processes.shard(pid))
            .get(&pid)
            .map(|r| r.more.as_ref().map_or(0, |m| m.holds.len()))
    }

    fn is_watched_by(vm: &VM, pid: u64, monitor_id: u64) -> bool {
        lock(vm.runtime.processes.shard(pid))
            .get(&pid)
            .and_then(|r| r.more.as_ref())
            .is_some_and(|m| m.watched_by.contains_key(&monitor_id))
    }

    fn parent_of(vm: &VM, pid: u64) -> Option<Option<u64>> {
        lock(vm.runtime.processes.shard(pid))
            .get(&pid)
            .map(|r| r.parent)
    }

    fn children_of(vm: &VM, pid: u64) -> usize {
        lock(vm.runtime.processes.shard(pid))
            .get(&pid)
            .and_then(|r| r.more.as_ref())
            .map_or(0, |m| m.children.len())
    }

    fn is_marked_killed(vm: &VM, pid: u64) -> bool {
        lock(vm.runtime.processes.shard(pid))
            .get(&pid)
            .is_some_and(|r| r.killed)
    }

    #[test]
    fn a_pid_is_live_from_alloc_until_unregister() {
        let vm = halt_test_vm();
        let rt = &vm.runtime;
        let pid = rt.alloc_pid(0, None);
        assert!(rt.process_is_live(pid));
        assert!(
            rt.unregister_process(pid, Exit::Normal)
                .1
                .notices
                .is_empty()
        );
        assert!(!rt.process_is_live(pid));
        // Ending it twice is harmless: nothing races on this, but the table
        // should not care either way.
        assert!(
            rt.unregister_process(pid, Exit::Normal)
                .1
                .notices
                .is_empty()
        );
    }

    #[test]
    fn notices_parked_on_a_target_come_back_at_its_death() {
        let mut vm = halt_test_vm();
        let holder = vm.runtime.alloc_pid(0, None);
        let target = vm.runtime.alloc_pid(0, None);
        let n1 = notice(&mut vm, holder);
        let n2 = notice(&mut vm, holder);
        let (m1, r1) = vm.runtime.monitor(target, n1);
        let (m2, r2) = vm.runtime.monitor(target, n2);
        assert!(matches!(r1, Registered::Parked));
        assert!(matches!(r2, Registered::Parked));
        assert_ne!(m1.id, m2.id, "monitor ids are distinct registrations");
        assert_eq!(holds_of(&vm, holder), Some(2));

        vm.runtime.demonitor(holder, m1);
        assert_eq!(holds_of(&vm, holder), Some(1));
        let (_, fired) = vm.runtime.unregister_process(target, Exit::Normal);
        assert_eq!(fired.notices.len(), 1, "the cancelled notice must not fire");
        assert_eq!(
            holds_of(&vm, holder),
            Some(0),
            "a fired notice must retire from its holder, or churn leaks"
        );
    }

    #[test]
    fn monitoring_a_dead_pid_hands_the_notice_straight_back() {
        let mut vm = halt_test_vm();
        let holder = vm.runtime.alloc_pid(0, None);
        let target = vm.runtime.alloc_pid(0, None);
        drop(vm.runtime.unregister_process(target, Exit::Normal));
        let n = notice(&mut vm, holder);
        let (_, r) = vm.runtime.monitor(target, n);
        assert!(matches!(r, Registered::TargetDead(_)));
        // Nothing was parked anywhere, and the holder holds nothing.
        assert_eq!(holds_of(&vm, holder), Some(0));
    }

    #[test]
    fn a_holders_death_removes_the_monitors_it_held() {
        let mut vm = halt_test_vm();
        let holder = vm.runtime.alloc_pid(0, None);
        let target = vm.runtime.alloc_pid(0, None);
        let n = notice(&mut vm, holder);
        let (m, _) = vm.runtime.monitor(target, n);
        assert!(is_watched_by(&vm, target, m.id));
        drop(vm.runtime.unregister_process(holder, Exit::Normal));
        assert!(
            !is_watched_by(&vm, target, m.id),
            "a dead holder's registration must not linger on the target"
        );
        assert!(
            vm.runtime
                .unregister_process(target, Exit::Normal)
                .1
                .notices
                .is_empty()
        );
    }

    #[test]
    fn a_process_may_monitor_itself() {
        let mut vm = halt_test_vm();
        let me = vm.runtime.alloc_pid(0, None);
        let n = notice(&mut vm, me);
        let (_, r) = vm.runtime.monitor(me, n);
        assert!(matches!(r, Registered::Parked));
        // Its own death fires the notice; the holds cleanup finds the
        // record already gone and must not mind.
        assert_eq!(
            vm.runtime
                .unregister_process(me, Exit::Normal)
                .1
                .notices
                .len(),
            1
        );
    }

    #[test]
    fn a_linked_spawn_is_recorded_on_both_sides() {
        let vm = halt_test_vm();
        let parent = vm.runtime.alloc_pid(0, None);
        let child = spawn_linked(&vm, parent);
        let loner = vm.runtime.alloc_pid(0, None);
        assert_eq!(parent_of(&vm, child), Some(Some(parent)));
        assert_eq!(parent_of(&vm, loner), Some(None));
        assert_eq!(children_of(&vm, parent), 1);
    }

    #[test]
    fn a_normal_exit_undoes_links_and_arms_nothing() {
        let vm = halt_test_vm();
        let parent = vm.runtime.alloc_pid(0, None);
        let child = spawn_linked(&vm, parent);
        let grandchild = spawn_linked(&vm, child);

        let (exit, after) = vm.runtime.unregister_process(child, Exit::Normal);
        assert!(matches!(exit, Exit::Normal));
        assert!(after.linked.is_empty());
        assert_eq!(children_of(&vm, parent), 0, "the parent forgets it");
        assert_eq!(
            parent_of(&vm, grandchild),
            Some(None),
            "an orphan is unlinked, not doomed"
        );
        assert!(!is_marked_killed(&vm, parent));
        assert!(!is_marked_killed(&vm, grandchild));
    }

    #[test]
    fn an_abnormal_exit_names_parent_and_children_for_killing() {
        let vm = halt_test_vm();
        let parent = vm.runtime.alloc_pid(0, None);
        let child = spawn_linked(&vm, parent);
        let a = spawn_linked(&vm, child);
        let b = spawn_linked(&vm, child);
        let unlinked = vm.runtime.alloc_pid(0, None);

        let (_, mut after) = vm
            .runtime
            .unregister_process(child, Exit::Crashed(Crash::ForeignReceive));
        after.linked.sort_unstable();
        let mut expected = vec![parent, a, b];
        expected.sort_unstable();
        assert_eq!(after.linked, expected);
        assert!(vm.runtime.process_is_live(unlinked));
        // Killing what it named marks them; their own ends spread further.
        for pid in after.linked {
            assert!(vm.runtime.kill(pid));
            assert!(is_marked_killed(&vm, pid));
        }
        assert!(!is_marked_killed(&vm, unlinked));
    }

    #[test]
    fn kill_marks_the_record_and_is_a_no_op_on_the_dead() {
        let vm = halt_test_vm();
        let pid = vm.runtime.alloc_pid(0, None);
        assert!(vm.runtime.kill(pid));
        assert!(is_marked_killed(&vm, pid));
        assert!(
            vm.runtime.note_adopted(pid, 0),
            "an adopter must learn of a kill that arrived in transit"
        );
        drop(vm.runtime.unregister_process(pid, Exit::Killed));
        assert!(!vm.runtime.kill(pid), "killing a dead pid is nothing");
    }

    #[test]
    fn a_return_after_a_kill_counts_as_the_kill() {
        let vm = halt_test_vm();
        let parent = vm.runtime.alloc_pid(0, None);
        let pid = spawn_linked(&vm, parent);
        assert!(vm.runtime.kill(pid));
        let (exit, after) = vm.runtime.unregister_process(pid, Exit::Normal);
        assert!(matches!(exit, Exit::Killed));
        assert_eq!(after.linked, vec![parent], "and it spreads like one");
        let crashed = vm.runtime.alloc_pid(0, None);
        assert!(vm.runtime.kill(crashed));
        let (exit, _) = vm
            .runtime
            .unregister_process(crashed, Exit::Crashed(Crash::ForeignReceive));
        assert!(
            matches!(exit, Exit::Crashed(_)),
            "a crash is not downgraded"
        );
    }
}

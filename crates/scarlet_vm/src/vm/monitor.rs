//! Process identity and monitors: `Pid` values, the table that knows which
//! pids are alive, and the death notices registered against them.
//!
//! A pid is minted by [`Runtime::alloc_pid`], which is also what makes the
//! process exist in the [`ProcessTable`]; ending a process removes it. That
//! table is the only source of liveness, and it must be kept from birth,
//! not from the first monitor: `monitor` on a pid that has already ended must
//! fire at once, which is only answerable if every death was recorded. The
//! table is sharded by pid so the per-spawn and per-death touch is one
//! mostly-uncontended lock and one hash operation, and no two shard locks are
//! ever held together.
//!
//! A monitor is a closure. `process.monitor(pid, inbox, wrap)` builds
//! `fn(down) send(inbox, wrap(down))` and hands it here, where it is
//! deep-copied exactly as a message would be ([`ProcHeap::spawn`]) and parked
//! on the target's record. When the target ends, each parked closure is
//! started as a process of its own with the `Down` value as its argument —
//! so a death notice is delivered by ordinary sends, in the watcher's own
//! message type, and needs no receive machinery beyond `receive`. It is sent
//! after everything the dead process itself sent, since those sends were
//! queued while it ran.
//!
//! Every process also records the monitors it holds, so a watcher that ends
//! first takes its registrations with it instead of leaving them on
//! long-lived targets.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::abi::AbiSlot;
use crate::bytecode::Value;
use crate::bytecode::value::proof_violation;
use crate::heap::ProcHeap;

use super::sched::Runtime;
use super::{IO_REDUCTION_COST, VM, VmError, VmResult, lock};

/// The live-process table. See the module docs.
pub(super) struct ProcessTable {
    /// Always a power of two, so a pid picks its shard by mask.
    shards: Vec<Mutex<Shard>>,
    /// Program-unique monitor ids, so a `Monitor` value names one
    /// registration for the whole run.
    next_monitor: AtomicU64,
}

/// One shard: the records of the live processes hashed here.
type Shard = HashMap<u64, ProcRecord, BuildHasherDefault<PidHasher>>;

/// Hashes a pid by one multiplication. Pids are sequential integers minted
/// by the runtime, not attacker-chosen keys, so SipHash's protection buys
/// nothing here and its cost is paid twice per process lifetime; the odd
/// multiplier (2^64 / φ) spreads consecutive pids across the table's high
/// bits, which is what `HashMap` indexes by.
#[derive(Default)]
struct PidHasher(u64);

impl Hasher for PidHasher {
    #[inline]
    fn write_u64(&mut self, pid: u64) {
        self.0 = pid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn write(&mut self, _bytes: &[u8]) {
        // `u64` keys hash through `write_u64` alone; nothing else is ever
        // keyed by this hasher.
        proof_violation("PidHasher fed a non-u64 key");
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// The runtime state attached to one live process. Almost every process is
/// never involved in a monitor, and every process pays for its record twice
/// (birth and death), so the record is one word — `None` — until the first
/// monitor touches it. That keeps the per-process cost to the two table
/// operations themselves and the table's memory to a few bytes per process.
type ProcRecord = Option<Box<Monitors>>;

#[derive(Default)]
struct Monitors {
    /// Death notices to fire when this process ends, by monitor id.
    watched_by: HashMap<u64, Notice>,
    /// Monitors this process holds on others: monitor id → target pid. Taken
    /// down when this process ends.
    holds: HashMap<u64, u64>,
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
    /// Bring `pid` into existence in the table. Called by `alloc_pid` for
    /// every process, so a pid is monitorable from the moment it is handed
    /// out.
    pub(super) fn register_process(&self, pid: u64) {
        lock(self.processes.shard(pid)).insert(pid, None);
    }

    /// Take `pid` out of the table as it ends. Returns the notices to fire,
    /// after removing every monitor `pid` itself held from its targets and
    /// retiring each returned notice from its holder's `holds`. Each step
    /// holds one shard lock at a time; a holder or target that has itself
    /// ended (including `pid`, for a self-monitor) is simply absent.
    fn unregister_process(&self, pid: u64) -> Vec<Notice> {
        let Some(Some(record)) = lock(self.processes.shard(pid)).remove(&pid) else {
            // Absent, or present but never monitored: nothing to fire and
            // nothing held.
            return Vec::new();
        };
        for (id, target) in record.holds {
            if let Some(Some(t)) = lock(self.processes.shard(target)).get_mut(&target) {
                t.watched_by.remove(&id);
            }
        }
        let mut notices = Vec::with_capacity(record.watched_by.len());
        for (id, notice) in record.watched_by {
            if let Some(Some(h)) = lock(self.processes.shard(notice.holder)).get_mut(&notice.holder)
            {
                h.holds.remove(&id);
            }
            notices.push(notice);
        }
        notices
    }

    /// Park `notice` on `target` on behalf of `holder`, minting the monitor
    /// id. A target that has already ended hands the notice back instead:
    /// the caller fires it immediately, which is what closes the gap between
    /// a death and a monitor placed just after it.
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
            t.get_or_insert_default().watched_by.insert(id, notice);
        }
        // The holder is the running process, so it is alive and its record
        // exists; a holder monitoring itself is the same record twice, taken
        // in two separate critical sections.
        if let Some(h) = lock(self.processes.shard(holder)).get_mut(&holder) {
            h.get_or_insert_default().holds.insert(id, target);
        }
        (m, Registered::Parked)
    }

    /// Cancel `m`. A notice already taken by the target's death may still be
    /// on its way; a monitor that never existed or already fired is a no-op.
    /// The dropped notice's closure graph is freed outside both locks.
    fn demonitor(&self, holder: u64, m: MonitorRef) {
        let removed = lock(self.processes.shard(m.target))
            .get_mut(&m.target)
            .and_then(|t| t.as_mut()?.watched_by.remove(&m.id));
        if let Some(Some(h)) = lock(self.processes.shard(holder)).get_mut(&holder) {
            h.holds.remove(&m.id);
        }
        drop(removed);
    }

    #[cfg(test)]
    pub(super) fn is_live_process(&self, pid: u64) -> bool {
        lock(self.processes.shard(pid)).contains_key(&pid)
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
            self.fire_notice(target, AbiSlot::ExitNoProcess, notice)?;
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

    /// The death half: called as `pid` ends, on whichever scheduler that
    /// happens. Every notice parked on it becomes a runnable process here.
    pub(super) fn end_process(&mut self, pid: u64) -> VmResult<()> {
        // Cheap exit for the common case is inside `unregister_process`
        // itself: a record with nothing parked yields an empty vector.
        for notice in self.runtime.unregister_process(pid) {
            self.fire_notice(pid, AbiSlot::ExitNormal, notice)?;
        }
        Ok(())
    }

    /// Start `notice`'s closure as a process, applied to `Down(target,
    /// reason)`. The `Down` value is built here and referenced only by the
    /// new process's frame, so nothing is shared with the process that ended
    /// (or, for an immediate fire, with the caller).
    fn fire_notice(&mut self, target: u64, reason: AbiSlot, notice: Notice) -> VmResult<()> {
        let reason = self.abi_nullary(reason)?;
        let down = self.abi_make(AbiSlot::Down, &[Value::pid(target), reason])?;
        self.runtime.process_started();
        self.spawn_process_with_heap_args(notice.heap, notice.closure, &[down]);
        Ok(())
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
    //! birth, notices moving from the target's record to its death, and
    //! holder death cleaning up after itself. End-to-end delivery lives in
    //! `tests/programs/monitors.scrl`.

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

    /// How many monitors `pid` holds: `None` if it is not live, 0 for a
    /// live process that was never involved in one.
    fn holds_of(vm: &VM, pid: u64) -> Option<usize> {
        lock(vm.runtime.processes.shard(pid))
            .get(&pid)
            .map(|r| r.as_ref().map_or(0, |m| m.holds.len()))
    }

    fn is_watched_by(vm: &VM, pid: u64, monitor_id: u64) -> bool {
        lock(vm.runtime.processes.shard(pid))
            .get(&pid)
            .and_then(|r| r.as_ref())
            .is_some_and(|m| m.watched_by.contains_key(&monitor_id))
    }

    #[test]
    fn a_pid_is_live_from_alloc_until_unregister() {
        let vm = halt_test_vm();
        let rt = &vm.runtime;
        let pid = rt.alloc_pid();
        assert!(rt.is_live_process(pid));
        assert!(rt.unregister_process(pid).is_empty());
        assert!(!rt.is_live_process(pid));
        // Ending it twice is harmless: donation and death never race on
        // this, but the table should not care either way.
        assert!(rt.unregister_process(pid).is_empty());
    }

    #[test]
    fn notices_parked_on_a_target_come_back_at_its_death() {
        let mut vm = halt_test_vm();
        let holder = vm.runtime.alloc_pid();
        let target = vm.runtime.alloc_pid();
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
        let fired = vm.runtime.unregister_process(target);
        assert_eq!(fired.len(), 1, "the cancelled notice must not fire");
        assert_eq!(
            holds_of(&vm, holder),
            Some(0),
            "a fired notice must retire from its holder, or churn leaks"
        );
    }

    #[test]
    fn monitoring_a_dead_pid_hands_the_notice_straight_back() {
        let mut vm = halt_test_vm();
        let holder = vm.runtime.alloc_pid();
        let target = vm.runtime.alloc_pid();
        drop(vm.runtime.unregister_process(target));
        let n = notice(&mut vm, holder);
        let (_, r) = vm.runtime.monitor(target, n);
        assert!(matches!(r, Registered::TargetDead(_)));
        // Nothing was parked anywhere, and the holder holds nothing.
        assert_eq!(holds_of(&vm, holder), Some(0));
    }

    #[test]
    fn a_holders_death_removes_the_monitors_it_held() {
        let mut vm = halt_test_vm();
        let holder = vm.runtime.alloc_pid();
        let target = vm.runtime.alloc_pid();
        let n = notice(&mut vm, holder);
        let (m, _) = vm.runtime.monitor(target, n);
        assert!(is_watched_by(&vm, target, m.id));
        drop(vm.runtime.unregister_process(holder));
        assert!(
            !is_watched_by(&vm, target, m.id),
            "a dead holder's registration must not linger on the target"
        );
        assert!(vm.runtime.unregister_process(target).is_empty());
    }

    #[test]
    fn a_process_may_monitor_itself() {
        let mut vm = halt_test_vm();
        let me = vm.runtime.alloc_pid();
        let n = notice(&mut vm, me);
        let (_, r) = vm.runtime.monitor(me, n);
        assert!(matches!(r, Registered::Parked));
        // Its own death fires the notice; the holds cleanup finds the
        // record already gone and must not mind.
        assert_eq!(vm.runtime.unregister_process(me).len(), 1);
    }
}

//! Per-program native-code entry table: the dispatch surface between the
//! interpreter and JIT-compiled function bodies.
//!
//! [`NativeTable`] is one code-pointer slot per
//! [`Program::functions`](super::Program::functions) entry, indexed by the same
//! [`FuncIdx`] numbering that `CoreProgram.fns` and `TypedProgram::fns` use. A
//! populated slot means "call this instead of interpreting". Bytecode is kept
//! for every function regardless: it is the fallback and the
//! resume-after-suspension path.
//!
//! The slice is behind an `Arc`, so every worker scheduler's private [`Program`]
//! clone shares one table. Slots are [`AtomicPtr`]s so the table can be sized
//! once the function list is final and populated afterwards, without threading
//! `&mut Program` through the backend.
//!
//! Compiled code is never freed — processes migrate across scheduler threads
//! mid-flight, so no thread can prove a code address unreachable. That is what
//! makes handing raw code pointers across threads sound.
//!
//! [`Program`]: super::Program

use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use crate::FuncIdx;
use crate::tivec::Idx;

use super::Op;

/// One-word status a native entry returns to its caller. Anything other than
/// [`NativeStatus::Done`] unwinds every native frame by plain returns, and the
/// trampoline then does what the interpreter's dispatch loop would. The status
/// carries no payload: the shim that produced it already recorded the parked
/// wait or pending error in the VM.
///
/// The discriminants are ABI, not an implementation detail — JIT-compiled code
/// materialises these exact machine words in the return register.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStatus {
    /// Ran to completion; the result is in the frame slot the calling
    /// convention assigns.
    Done = 0,
    /// Reduction budget exhausted. The yielding frame's `ip` names its resume
    /// point (0 = re-enter from the top).
    Yield = 1,
    /// A callee parked the process on I/O or a timer. Resume re-enters the
    /// interpreter at the parked frame's `ip`.
    Parked = 2,
    /// A runtime error was raised; the VM holds the error value.
    Error = 3,
    /// A cross-function tail call collapsed the top frame in place, so the
    /// trampoline must dispatch the NEW top frame. Tail chains therefore
    /// unwind to one driver loop instead of stacking machine frames. Never
    /// reaches the interpreter boundary: every entry invocation runs under a
    /// trampoline that consumes it.
    TailCall = 4,
}

/// How compiled code covers each opcode.
///
/// Exhaustive by construction: [`op_coverage`] matches every `Op` variant, so
/// adding an opcode without deciding how native code runs it is a compile
/// error rather than a `unsupported primop` panic discovered at runtime. The
/// three `is_native_*_op` predicates are views of this one classification, so
/// they cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCoverage {
    /// The emitter lowers it directly — an inline instruction sequence or a
    /// dedicated shim.
    Inline,
    /// One `al_shim_op` call: pure, single-result, cannot fail.
    Bridge,
    /// One `al_shim_try_op` call: can raise a runtime error on user data, so
    /// the caller unwinds on a non-`Done` status.
    Try,
    /// One `al_shim_park_op` call guarded by two resume ordinals: can suspend
    /// the process.
    Park,
    /// Never reaches the native backend as a Core IR primop. The bytecode
    /// backend emits these for a Core *construct* — a call, a match, a drop, a
    /// constructor, a closure — or the peephole pass fuses them, and the
    /// emitter compiles the construct, not the opcode.
    NotAPrimOp,
}

/// The native lowering strategy for `op`. See [`OpCoverage`].
fn op_coverage(op: Op) -> OpCoverage {
    match op {
        Op::PushGlobal
        | Op::PushTrue
        | Op::PushFalse
        | Op::AddInt
        | Op::SubInt
        | Op::MulInt
        | Op::DivInt
        | Op::ModInt
        | Op::NegInt
        | Op::Eq
        | Op::Neq
        | Op::Lt
        | Op::Gt
        | Op::Lte
        | Op::Gte
        | Op::LtInt
        | Op::GtInt
        | Op::LteInt
        | Op::GteInt
        | Op::EqInt
        | Op::NeqInt
        | Op::Not
        | Op::MakeArray
        | Op::MakeTuple
        | Op::TupleIndex
        | Op::ArrayLen
        | Op::Prepend
        | Op::Append
        | Op::GetFieldUnchecked
        | Op::PushCapture
        | Op::PushSelf
        | Op::BinByteSize
        | Op::HttpParseHead
        | Op::HttpFraming
        | Op::HttpHeaderHas
        | Op::HttpHeadersValid
        | Op::HttpSerializeHead => OpCoverage::Inline,
        Op::Add
        | Op::Sub
        | Op::Mul
        | Op::Div
        | Op::Mod
        | Op::Neg
        | Op::AddFloat
        | Op::SubFloat
        | Op::MulFloat
        | Op::DivFloat
        | Op::NegFloat
        | Op::AddStr
        | Op::LtFloat
        | Op::GtFloat
        | Op::LteFloat
        | Op::GteFloat
        | Op::MakeRange
        | Op::Index
        | Op::IndexOr
        | Op::ElemAt
        | Op::ArrayConcat
        | Op::SeqDrop
        | Op::GetField
        | Op::ToString
        | Op::StrConcatN
        | Op::StrSplit
        | Op::StrLen
        | Op::StrContains
        | Op::StrTrim
        | Op::IntToString
        | Op::BinFromString
        | Op::BinToString
        | Op::BinBitSize
        | Op::BinSlice
        | Op::BinAppend
        | Op::BinConcatN
        | Op::BinFromInt
        | Op::BinReadInt
        | Op::BinTake
        | Op::BinReadUtf8
        | Op::BinMatchPrefix
        | Op::BinView
        | Op::BinIndexOf
        | Op::BinByteAt
        | Op::BinParseInt
        | Op::BinEqIgnoreAsciiCase
        | Op::BinToAsciiLower
        | Op::BinFromIntAscii
        | Op::HttpChunkDecode
        | Op::HttpHeaderGet
        | Op::FloatFloor
        | Op::FloatCeil
        | Op::FloatRound
        | Op::FloatTruncate
        | Op::FloatFromInt
        | Op::FloatToString
        | Op::Print
        | Op::StackDepth
        | Op::TcpListen
        | Op::TcpClose
        | Op::TcpCloseServer
        | Op::TcpLocalAddr
        | Op::IpParse
        | Op::ProcessSpawn
        | Op::SpawnLocal
        | Op::SpawnOnEach
        | Op::SubjectNew
        | Op::SubjectSend
        | Op::Monotonic
        | Op::Argv
        | Op::EnvMap
        | Op::MapGet
        | Op::MapHas
        | Op::MapKeys
        | Op::MapValues
        | Op::MapSize
        | Op::MapNew
        | Op::MapSet
        | Op::MapDelete
        | Op::MapToList => OpCoverage::Bridge,
        Op::ArraySlice => OpCoverage::Try,
        Op::FileRead
        | Op::FileWrite
        | Op::TcpAccept
        | Op::TcpConnect
        | Op::TcpRead
        | Op::TcpReadUntil
        | Op::TcpWrite
        | Op::TcpWriteParts
        | Op::DnsResolve
        | Op::Sleep
        | Op::SubjectReceive
        | Op::SubjectReceiveUntil => OpCoverage::Park,
        Op::PushConst
        | Op::PushLocal
        | Op::StoreLocal
        | Op::PushNil
        | Op::Pop
        | Op::Dup
        | Op::Jump
        | Op::JumpIfFalse
        | Op::Call
        | Op::TailCall
        | Op::CallSelf
        | Op::TailCallSelf
        | Op::CallKnown
        | Op::TailCallKnown
        | Op::Ret
        | Op::SubIntLC
        | Op::AddIntLC
        | Op::JumpGeIntLC
        | Op::JumpNeIntLC
        | Op::Nop
        | Op::MakeEnumPayload
        | Op::MatchEnum
        | Op::UnwrapEnum
        | Op::SwitchTag
        | Op::MakeClosure
        | Op::Drop
        | Op::Reuse
        | Op::Halt => OpCoverage::NotAPrimOp,
    }
}

/// The opcodes lowered to one `al_shim_op` call: pure, single-result, and
/// unable to fail. Each runs the interpreter's own op method over the value
/// stack, so native and interpreted execution share one implementation and
/// cannot diverge.
pub fn is_native_bridge_op(op: Op) -> bool {
    op_coverage(op) == OpCoverage::Bridge
}

/// The opcodes with a reachable runtime error — as opposed to the type
/// mismatches the checker already excludes. Lowered to one `al_shim_try_op`
/// call that unwinds on a non-`Done` status, like a failing call.
pub fn is_native_try_op(op: Op) -> bool {
    op_coverage(op) == OpCoverage::Try
}

/// The opcodes that can suspend the process. Lowered to one `al_shim_park_op`
/// call guarded by two resume ordinals — one that re-runs the op, one that
/// continues past it — chosen by the `Resume` the op returns.
pub fn is_native_park_op(op: Op) -> bool {
    op_coverage(op) == OpCoverage::Park
}

/// What the pinned register (x86_64 r15, aarch64 x21) points at while a
/// compiled body runs, and the argument every [`NativeEntry`] receives.
/// `repr(C)` because generated code bakes the field offsets in as load offsets.
///
/// The indirection exists so nothing scheduler-derived is resident in a
/// compiled frame across a suspension point. The VM pointer lives here,
/// re-published by every `VM::call_native`, and compiled code reloads it before
/// each runtime call — so a resume on another scheduler reads that scheduler's
/// VM by construction.
#[repr(C)]
#[derive(Debug)]
pub struct NativeCtx {
    /// Offset 0, the hottest load. Dormant today: shims spend the VM's own
    /// counter until reds checks move into generated code.
    reds: i64,
    /// Offset 8. This scheduler's `&mut VM`, opaque at codegen time.
    pub vm: *mut core::ffi::c_void,
}

impl NativeCtx {
    /// Load offset baked into generated code (`core_ir::clif`). Computed from
    /// the struct itself, so reordering the fields cannot desynchronize it.
    pub const VM_OFFSET: i32 = core::mem::offset_of!(NativeCtx, vm) as i32;

    pub fn new() -> NativeCtx {
        NativeCtx {
            reds: 0,
            vm: core::ptr::null_mut(),
        }
    }
}

impl Default for NativeCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// The compiled-function calling convention: arguments are already in the
/// callee's frame slots (`[base_slot, base_slot + arity)`, the interpreter
/// layout) and the `CallFrame` is pushed before the entry runs. `ctx` is a
/// [`NativeCtx`], opaque so both sides cast through this alias; the prologue
/// moves it into the pinned register.
///
/// Entries are compiled under Cranelift's TAIL calling convention (that is
/// what admits `return_call` between bodies), so Rust never invokes one
/// directly: every call goes `call_entry_preserving_pinned` -> the module's
/// SystemV [`entry trampoline`](NativeTable::trampoline) -> the entry.
pub type NativeEntry = *const u8;

/// The per-program entry table. `Clone` is shallow on purpose: per-scheduler
/// `Program` clones must observe one table.
/// Compiles one body and publishes its entry. The driver installs one; this
/// crate must not name the compiler.
pub type Compiler = Arc<dyn Fn(FuncIdx) + Send + Sync>;

#[derive(Clone, Default)]
pub struct NativeTable {
    entries: Arc<[AtomicPtr<()>]>,
    /// Calls seen for a body that has no entry yet. Once one crosses
    /// [`WARM_CALLS`], [`NativeTable::note_interpreted_call`] asks `compile`
    /// for that body, so a short-lived program never pays to compile the
    /// hundreds of stdlib bodies it does not run.
    warmth: Arc<[AtomicU32]>,
    /// Compiles one body and publishes its entry. Installed by the driver:
    /// this crate must not name the compiler.
    ///
    /// Behind the same `Arc` as the entries, because every scheduler holds a
    /// `Program` clone of this table and all of them must see it.
    compile: Arc<OnceLock<Compiler>>,
    /// The module's SystemV->tail bridge (`al_entry_trampoline`), published by
    /// `finalize_into` before any entry. Null iff no entry is published.
    trampoline: Arc<AtomicPtr<()>>,
}

impl NativeTable {
    /// A table with `fn_count` empty slots. Size it from the FINAL
    /// `Program::functions` length; [`FuncIdx`] is minted against that
    /// numbering.
    /// Calls a body is interpreted for before it is worth compiling. Low
    /// enough that a hot loop is compiled almost at once, high enough that a
    /// body run a handful of times never is.
    const WARM_CALLS: u32 = 8;

    /// Count one call of `fn_idx` made while it had no entry, and ask the
    /// installed compiler for it on the call that crosses [`Self::WARM_CALLS`].
    ///
    /// Exactly one call crosses the threshold, so the compile is requested
    /// once however many schedulers race here.
    pub(crate) fn note_interpreted_call(&self, fn_idx: FuncIdx) {
        let Some(compile) = self.compile.get() else {
            return;
        };
        let Some(slot) = self.warmth.get(fn_idx.index()) else {
            return;
        };
        if slot.fetch_add(1, Ordering::Relaxed) + 1 == Self::WARM_CALLS {
            compile(fn_idx);
        }
    }

    /// Install the compiler this table asks for warm bodies. Called once, by
    /// the driver, before any process runs.
    pub fn set_compiler(&self, compile: Compiler) {
        let _ = self.compile.set(compile);
    }

    pub fn new(fn_count: usize) -> NativeTable {
        NativeTable {
            entries: (0..fn_count)
                .map(|_| AtomicPtr::new(std::ptr::null_mut()))
                .collect(),
            warmth: (0..fn_count).map(|_| AtomicU32::new(0)).collect(),
            compile: Arc::new(OnceLock::new()),
            trampoline: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
        }
    }

    /// Publish the module's entry trampoline. Must happen before the first
    /// [`NativeTable::set`], so a scheduler that sees an entry sees the
    /// bridge it must be called through.
    pub(crate) fn set_trampoline(&self, code: *const u8) {
        self.trampoline
            .store(code.cast_mut().cast(), Ordering::Release);
    }

    /// The SystemV bridge entries are called through, null when nothing was
    /// compiled.
    #[inline]
    pub(crate) fn trampoline(&self) -> *const u8 {
        self.trampoline.load(Ordering::Acquire).cast_const().cast()
    }

    /// Number of slots (== the function count the table was sized for).
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Publish `entry` as `fn_idx`'s compiled body. Panics if `fn_idx` is
    /// outside the numbering the table was sized for — that means the caller
    /// compiled against a different function list.
    ///
    /// `Release` pairs with [`NativeTable::get`]'s `Acquire`: a scheduler that
    /// observes the pointer also observes the finalised code and icache flush.
    pub(crate) fn set(&self, fn_idx: FuncIdx, entry: NativeEntry) {
        debug_assert!(
            !self.trampoline().is_null(),
            "publish the trampoline before the first entry"
        );
        self.entries[fn_idx.index()].store(entry.cast_mut().cast(), Ordering::Release);
    }

    /// The compiled body for `fn_idx`, or `None` when the function is
    /// interpreter-only. Out-of-range is `None`, not a panic: a REPL session
    /// grows `Program::functions` past a table sized for an earlier line, and
    /// those newer functions simply interpret.
    #[inline]
    pub fn get(&self, fn_idx: FuncIdx) -> Option<NativeEntry> {
        let ptr = self.entries.get(fn_idx.index())?.load(Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            Some(ptr.cast_const().cast())
        }
    }

    /// Every populated slot, in `FuncIdx` order — the perf-map writer and
    /// `dis --native` walk this.
    fn compiled(&self) -> impl Iterator<Item = (FuncIdx, NativeEntry)> + '_ {
        (0..self.entries.len())
            .map(FuncIdx::from_usize)
            .filter_map(|idx| self.get(idx).map(|entry| (idx, entry)))
    }
}

impl std::fmt::Debug for NativeTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let compiled = self.compiled().count();
        write!(f, "NativeTable({compiled}/{} compiled)", self.len())
    }
}

/// Whether `SCARLET_NATIVE_DEBUG` asked for native-backend diagnostics. Read once.
pub fn debug() -> bool {
    static DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DEBUG.get_or_init(|| std::env::var_os("SCARLET_NATIVE_DEBUG").is_some())
}

/// One debug line per planned function.
pub fn log_selected(idx: FuncIdx, name: &str) {
    if debug() {
        eprintln!("al-native: selected {idx} {name}");
    }
}

/// Whole-unit accounting for the compile-all-at-load pass, checked against the
/// 100ms-per-unit budget.
#[derive(Debug, Default)]
pub struct UnitStats {
    selected: usize,
    elapsed: std::time::Duration,
}

impl UnitStats {
    pub fn record(&mut self, elapsed: std::time::Duration) {
        self.selected += 1;
        self.elapsed += elapsed;
    }

    /// The whole-unit summary, printed only under `SCARLET_NATIVE_DEBUG`.
    pub fn log_summary(&self, instrs: usize) {
        if !debug() {
            return;
        }
        let ms = self.elapsed.as_secs_f64() * 1000.0;
        let over = if self.elapsed > std::time::Duration::from_millis(100) {
            " OVER BUDGET"
        } else {
            ""
        };
        eprintln!(
            "al-native: planned {} fns; in-compile hook {ms:.2}ms \
             over {instrs} instrs (unit budget 100ms){over}",
            self.selected,
        );
    }
}

/// Call a JIT entry through the module's SystemV trampoline, preserving the
/// pinned register the JIT clobbers.
///
/// `enable_pinned_reg` gives generated code the pinned register (r15 on
/// x86_64, x21 on aarch64) by dropping it from Cranelift's callee-save list,
/// so a compiled entry's prologue writes it and no epilogue puts it back —
/// while every Rust caller on the path is entitled by the platform ABI to
/// assume it survives. This bracket restores that assumption. The trampoline
/// (SystemV, Cranelift-compiled) handles every OTHER callee-saved register
/// the tail-cc entry clobbers.
///
/// # Safety
/// `tramp` must be the module's finalized `al_entry_trampoline`, `entry` a
/// finalized tail-cc JIT entry from the same module, and `ctx` a live context
/// of the shape the entry was compiled against.
#[allow(unsafe_code)] // the pinned-register bracket the JIT ABI requires; contract above
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub unsafe extern "C" fn call_entry_preserving_pinned(
    ctx: *mut core::ffi::c_void,
    tramp: *const u8,
    entry: NativeEntry,
    resume: i64,
) -> NativeStatus {
    // rdi = ctx, rsi = tramp, rdx = entry, rcx = resume. The trampoline takes
    // (ctx, entry, resume), so entry and resume shift down one register.
    // Entry rsp is 8 (mod 16); one push makes it 0, which is what the
    // callee's `call` requires.
    core::arch::naked_asm!(
        "push r15",
        "mov rax, rsi",
        "mov rsi, rdx",
        "mov rdx, rcx",
        "call rax",
        "pop r15",
        "ret",
    )
}

/// See the x86_64 sibling. AAPCS64 makes x19-x28 callee-saved; the pinned
/// register is x21.
///
/// # Safety
/// As the x86_64 sibling.
#[allow(unsafe_code)] // the pinned-register bracket the JIT ABI requires; contract above
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
pub unsafe extern "C" fn call_entry_preserving_pinned(
    ctx: *mut core::ffi::c_void,
    tramp: *const u8,
    entry: NativeEntry,
    resume: i64,
) -> NativeStatus {
    // x0 = ctx, x1 = tramp, x2 = entry, x3 = resume; the trampoline takes
    // (ctx, entry, resume).
    core::arch::naked_asm!(
        "stp x21, x30, [sp, #-16]!",
        "mov x9, x1",
        "mov x1, x2",
        "mov x2, x3",
        "blr x9",
        "ldp x21, x30, [sp], #16",
        "ret",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn stub(_vmx: *mut core::ffi::c_void) -> NativeStatus {
        NativeStatus::Done
    }

    fn stub_entry() -> NativeEntry {
        stub as *const u8
    }

    /// A table with a dummy trampoline published, so `set` is usable.
    fn table(n: usize) -> NativeTable {
        let t = NativeTable::new(n);
        t.set_trampoline(stub as *const u8);
        t
    }

    #[test]
    fn empty_table_answers_none_for_any_idx() {
        let t = NativeTable::default();
        assert!(t.is_empty());
        assert!(t.get(FuncIdx(0)).is_none());
        assert!(t.get(FuncIdx(41)).is_none());
    }

    #[test]
    fn set_then_get_round_trips_the_entry() {
        let t = table(3);
        assert!(t.get(FuncIdx(1)).is_none());
        t.set(FuncIdx(1), stub_entry());
        let entry = t.get(FuncIdx(1)).expect("just set");
        assert!(std::ptr::eq(entry, stub_entry()));
        assert!(t.get(FuncIdx(0)).is_none());
        assert!(t.get(FuncIdx(2)).is_none());
    }

    #[test]
    fn clones_share_one_table() {
        let a = table(2);
        let b = a.clone();
        a.set(FuncIdx(0), stub_entry());
        assert!(b.get(FuncIdx(0)).is_some());
        assert!(std::ptr::eq(b.trampoline(), stub as *const u8));
    }

    #[test]
    fn out_of_range_get_is_none_not_a_panic() {
        let t = NativeTable::new(1);
        assert!(t.get(FuncIdx(7)).is_none());
    }

    #[test]
    fn compiled_walks_populated_slots_in_order() {
        let t = table(4);
        t.set(FuncIdx(2), stub_entry());
        t.set(FuncIdx(0), stub_entry());
        let idxs: Vec<FuncIdx> = t.compiled().map(|(i, _)| i).collect();
        assert_eq!(idxs, vec![FuncIdx(0), FuncIdx(2)]);
    }

    #[test]
    fn status_discriminants_are_abi() {
        assert_eq!(NativeStatus::Done as u64, 0);
        assert_eq!(NativeStatus::Yield as u64, 1);
        assert_eq!(NativeStatus::Parked as u64, 2);
        assert_eq!(NativeStatus::Error as u64, 3);
        assert_eq!(NativeStatus::TailCall as u64, 4);
        assert_eq!(std::mem::size_of::<NativeStatus>(), 8);
    }
}

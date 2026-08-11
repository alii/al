//! JIT module construction and runtime-symbol resolution: the layering seam
//! between `scarlet_core`'s CLIF construction and this crate's runtime.
//!
//! `scarlet_core` depends on this crate, never the reverse, but compiled bodies
//! must call runtime services owned here. Runtime symbols therefore cross
//! the crate boundary **by name**: CLIF emitted anywhere declares them
//! `Linkage::Import` under the canonical names in [`runtime_symbols`], which
//! [`jit_module`] registers with the `JITBuilder`, and Cranelift binds them
//! during relocation in [`finalize_into`] — at finalize time, not Rust link
//! time. Adding a runtime call is one shim, one [`runtime_symbols`] entry,
//! one [`RuntimeFns`] import.
//!
//! One [`JITModule`] holds one executable mapping shared by every scheduler.
//! Published entry pointers are raw code addresses and processes migrate
//! across scheduler threads mid-flight, so the mapping must be immortal:
//! nothing calls `free_memory`, and dropping the module after
//! [`finalize_into`] leaks the code pages deliberately.

// Publishing a finalized code address as a typed `NativeEntry` transmutes a
// `*const u8`, justified by `finalize_into`'s signature check.
#![allow(unsafe_code)]

use crate::FuncIdx;
use crate::bytecode::NativeTable;
use crate::bytecode::value::{
    NATIVE_HOLLOW_FOR_REUSE_SYMBOL, NATIVE_RELEASE_AT_ZERO_SYMBOL, native_hollow_for_reuse,
    native_release_at_zero,
};
use cranelift_codegen::ir::{AbiParam, Signature, types};
use cranelift_codegen::isa::CallConv;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleError, default_libcall_names};

use super::{native, native_shims, perf_map};

/// Why JIT construction or publication failed. Every variant is recoverable
/// the same way: leave the [`NativeTable`] slots empty and interpret.
///
/// An unresolved runtime symbol is not one of these — cranelift-jit panics
/// inside `finalize_definitions` instead. The correspondence test in this
/// module keeps that path unreachable.
#[derive(Debug)]
pub enum JitError {
    /// The host has no Cranelift backend, or ISA construction failed.
    Host(String),
    /// Declaration, definition or finalization failed inside the module.
    /// Boxed because `ModuleError` is >100 bytes.
    Module(Box<ModuleError>),
    /// [`finalize_into`] was handed a function not declared with the
    /// [`crate::bytecode::NativeEntry`] signature; publishing it would type-confuse every
    /// caller of the entry table.
    EntrySignature { name: String },
}

impl std::fmt::Display for JitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JitError::Host(msg) => write!(f, "native backend unavailable on this host: {msg}"),
            JitError::Module(err) => write!(f, "native backend module error: {err}"),
            JitError::EntrySignature { name } => write!(
                f,
                "native entry {name:?} was not declared with the NativeEntry signature"
            ),
        }
    }
}

impl std::error::Error for JitError {}

impl From<ModuleError> for JitError {
    fn from(err: ModuleError) -> JitError {
        JitError::Module(Box::new(err))
    }
}

/// Every runtime symbol JIT-compiled code may reference, as
/// `(canonical name, shim address)` pairs. [`RuntimeFns::declare`]'s imports
/// resolve against these names. An unused entry is harmless; a declared name
/// missing here panics inside `finalize_definitions`.
fn runtime_symbols() -> Vec<(&'static str, *const u8)> {
    let mut syms = vec![
        (
            NATIVE_RELEASE_AT_ZERO_SYMBOL,
            native_release_at_zero as *const u8,
        ),
        (
            NATIVE_HOLLOW_FOR_REUSE_SYMBOL,
            native_hollow_for_reuse as *const u8,
        ),
    ];
    syms.extend(native_shims::shim_symbols());
    syms.extend(native::rt_symbols());
    syms
}

/// The C-ABI vocabulary of the runtime seam: every parameter and return of
/// every runtime symbol is one of these two machine types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AbiTy {
    Ptr,
    I64,
}

/// One runtime symbol's canonical name and C signature.
///
/// This table is the single source both declaration sites build from: the
/// backend's imports ([`declare_runtime_imports`]) and the drift test, which
/// pins each entry to its `extern "C"` definition with a typed fn-pointer
/// coercion. A signature written anywhere else can drift from the Rust
/// definition silently — a drifted C signature is ABI corruption, not an
/// error.
pub struct RtSig {
    pub name: &'static str,
    pub params: &'static [AbiTy],
    pub rets: &'static [AbiTy],
}

/// Every runtime symbol compiled code can reference, 1:1 with
/// [`runtime_symbols`] (the drift test enforces both directions).
#[rustfmt::skip]
pub const RT_SIGS: &[RtSig] = &{
    use AbiTy::{I64, Ptr};
    [
        RtSig { name: NATIVE_RELEASE_AT_ZERO_SYMBOL, params: &[Ptr], rets: &[] },
        RtSig { name: NATIVE_HOLLOW_FOR_REUSE_SYMBOL, params: &[Ptr], rets: &[] },
        RtSig { name: "al_shim_enum_alloc", params: &[Ptr, I64, I64, I64, I64, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_make_array", params: &[Ptr, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_make_tuple", params: &[Ptr, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_seq_len", params: &[Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_seq_append", params: &[Ptr, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_seq_prepend", params: &[Ptr, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_bin_byte_size", params: &[Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_http_parse_head", params: &[Ptr, I64, I64], rets: &[I64] },
        RtSig { name: "al_shim_http_headers_valid", params: &[I64], rets: &[I64] },
        RtSig { name: "al_shim_http_header_has", params: &[I64, I64], rets: &[I64] },
        RtSig { name: "al_shim_http_serialize_head", params: &[Ptr, I64, I64, I64], rets: &[I64] },
        RtSig { name: "al_shim_http_framing", params: &[Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_push_global", params: &[Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_push_capture", params: &[Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_push_self", params: &[Ptr], rets: &[I64] },
        RtSig { name: "al_shim_int_box", params: &[Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_div_int", params: &[I64, I64], rets: &[I64] },
        RtSig { name: "al_shim_mod_int", params: &[I64, I64], rets: &[I64] },
        RtSig { name: "al_shim_op", params: &[Ptr, I64, I64, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_shim_park_op", params: &[Ptr, I64, Ptr, I64, I64, I64], rets: &[I64] },
        RtSig { name: "al_shim_try_op", params: &[Ptr, I64, I64, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_rt_prepare_call", params: &[Ptr, I64, I64, Ptr, I64], rets: &[Ptr, I64] },
        RtSig { name: "al_rt_prepare_call_value", params: &[Ptr, I64, I64, Ptr, I64], rets: &[Ptr, I64] },
        RtSig { name: "al_rt_prepare_tail", params: &[Ptr, I64, Ptr, I64], rets: &[Ptr, I64] },
        RtSig { name: "al_rt_prepare_tail_value", params: &[Ptr, I64, Ptr, I64], rets: &[Ptr, I64] },
        RtSig { name: "al_rt_ret_transfer", params: &[Ptr, I64], rets: &[Ptr, I64] },
        RtSig { name: "al_rt_pop", params: &[Ptr], rets: &[I64] },
        RtSig { name: "al_rt_make_closure", params: &[Ptr, I64, Ptr, I64], rets: &[I64] },
        RtSig { name: "al_rt_checkpoint", params: &[Ptr], rets: &[I64] },
        RtSig { name: "al_rt_frame_base", params: &[Ptr], rets: &[Ptr] },
    ]
};

/// Declare every [`RT_SIGS`] symbol into `module` as an import, keyed by
/// name. The backend resolves its `FuncRef`s from this map, so no caller
/// ever writes a signature of its own.
pub fn declare_runtime_imports<M: Module>(
    module: &mut M,
) -> Result<std::collections::HashMap<&'static str, FuncId>, Box<ModuleError>> {
    let ptr = module.target_config().pointer_type();
    let mut out = std::collections::HashMap::with_capacity(RT_SIGS.len());
    for e in RT_SIGS {
        let ty = |t: &AbiTy| match t {
            AbiTy::Ptr => ptr,
            AbiTy::I64 => types::I64,
        };
        let mut sig = module.make_signature();
        sig.params
            .extend(e.params.iter().map(|t| AbiParam::new(ty(t))));
        sig.returns
            .extend(e.rets.iter().map(|t| AbiParam::new(ty(t))));
        out.insert(
            e.name,
            module.declare_function(e.name, Linkage::Import, &sig)?,
        );
    }
    Ok(out)
}

/// Build the one JIT module compiled bodies are defined into, with every
/// [`runtime_symbols`] pair pre-registered.
///
/// Errors only when the host has no Cranelift backend; the caller's fallback
/// is to interpret everything.
/// The JIT module the driver holds open. Aliased so callers need not depend on
/// `cranelift_jit` directly.
pub type JitModule = JITModule;

/// A `JITBuilder` carrying every Cranelift flag compiled Scarlet requires —
/// the one source of truth. Tests that substitute mock runtime symbols must
/// still build on this: a hand-copied flag list drifts, and a missing flag is
/// a miscompile that only surfaces on the other architecture (x64 refuses
/// `return_call` without frame pointers; a missing probestack steps over the
/// guard page silently).
pub fn jit_builder() -> Result<JITBuilder, JitError> {
    let mut flags = settings::builder();
    // JIT'd code and the shims sit at arbitrary addresses in one process, so
    // calls need absolute addresses rather than colocated PLT-style stubs.
    for (name, value) in [
        ("use_colocated_libcalls", "false"),
        ("is_pic", "false"),
        ("opt_level", "speed"),
        // Compiled frames live on 256K per-process stacks with one guard
        // page ([`super::stack`]). Without probing, a frame bigger than a
        // page does one `sub rsp, N` that steps clean over the guard and
        // writes into the next process's stack: silent corruption, no fault.
        ("enable_probestack", "true"),
        ("probestack_strategy", "inline"),
        // The context argument stays in the pinned register (r15/x21) and is
        // re-read at every use. A frame must never hold a scheduler-derived
        // word across a suspension point.
        ("enable_pinned_reg", "true"),
        // Cranelift's x64 backend refuses `return_call` without frame
        // pointers (aarch64 does not care). The rbp push/pop per frame is
        // part of the tail-call price on x64.
        ("preserve_frame_pointers", "true"),
    ] {
        flags
            .set(name, value)
            .map_err(|e| JitError::Host(e.to_string()))?;
    }
    let isa = cranelift_native::builder()
        .map_err(|e| JitError::Host(e.to_string()))?
        .finish(settings::Flags::new(flags))
        .map_err(|e| JitError::Host(e.to_string()))?;
    Ok(JITBuilder::with_isa(isa, default_libcall_names()))
}

pub fn jit_module() -> Result<JitModule, JitError> {
    let mut builder = jit_builder()?;
    for (name, addr) in runtime_symbols() {
        builder.symbol(name, addr);
    }
    Ok(JITModule::new(builder))
}

/// The [`NativeEntry`] signature in CLIF terms: one pointer parameter, one
/// `i64` status return. Written once so body declarations and
/// [`finalize_into`]'s check cannot drift apart.
fn native_entry_signature(module: &JITModule) -> Signature {
    let mut sig = module.make_signature();
    // The tail calling convention is what admits `return_call`: an Scarlet-level
    // transfer between compiled bodies stays in machine code instead of
    // bouncing through the trampoline. Rust never calls a tail-cc pointer
    // directly — every entry goes through [`entry_trampoline`].
    sig.call_conv = CallConv::Tail;
    sig.params
        .push(AbiParam::new(module.target_config().pointer_type()));
    // The resume ordinal: 0 enters at the head, k enters continuation k.
    sig.params.push(AbiParam::new(types::I64));
    sig.returns.push(AbiParam::new(types::I64));
    sig
}

/// Compile the one SystemV bridge the VM calls entries through:
/// `fn(ctx, entry) -> status`. Cranelift emits the callee-save spills the
/// tail-cc callee (which preserves nothing) requires, so the assembly bracket
/// in `bytecode::native` only has to keep the pinned register alive.
pub fn entry_trampoline(module: &mut JITModule) -> Result<FuncId, JitError> {
    use cranelift_codegen::ir::InstBuilder;
    use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
    let ptr = module.target_config().pointer_type();
    let mut sig = module.make_signature();
    sig.params.push(AbiParam::new(ptr)); // ctx
    sig.params.push(AbiParam::new(ptr)); // tail-cc entry to invoke
    sig.params.push(AbiParam::new(types::I64)); // resume ordinal
    sig.returns.push(AbiParam::new(types::I64));
    let id = module.declare_function("al_entry_trampoline", Linkage::Export, &sig)?;
    let mut ctx = module.make_context();
    ctx.func.signature = sig;
    let callee_sig = native_entry_signature(module);
    let mut fbc = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut ctx.func, &mut fbc);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);
        let params = b.block_params(entry).to_vec();
        let sig_ref = b.import_signature(callee_sig);
        let call = b
            .ins()
            .call_indirect(sig_ref, params[1], &[params[0], params[2]]);
        let status = b.inst_results(call)[0];
        b.ins().return_(&[status]);
        b.finalize();
    }
    module.define_function(id, &mut ctx)?;
    module.clear_context(&mut ctx);
    Ok(id)
}

/// One compiled body handed to [`finalize_into`].
///
/// `func_id` must name a *defined* function, not a bare declaration:
/// construct a `JitDef` only after a successful `define_function`.
/// [`JITModule`] exposes no code-size accessor after finalization, so
/// `code_size` must be captured from the compiled context at that same point.
pub struct JitDef {
    pub fn_idx: FuncIdx,
    pub func_id: FuncId,
    /// Source-level function name; perf-map symbols are `al::<name>`.
    pub name: String,
    /// Finalized machine-code size in bytes.
    pub code_size: u32,
}

/// Resolve every pending relocation (where [`runtime_symbols`] names bind to
/// their shim addresses), then publish each def's code address into the
/// program's entry table, plus a [`perf_map`] line under `SCARLET_PERF_MAP=1`.
///
/// Every declaration is checked against [`native_entry_signature`] first;
/// that check is what keeps the `*const u8` → [`NativeEntry`] transmute
/// sound for later `table.get` callers. It cannot see whether a declaration
/// carries a definition, so a declared-but-never-defined `func_id` panics in
/// `get_finalized_function`; [`JitDef`]'s contract rules that out.
///
/// The module must outlive the table's pointers, i.e. forever.
pub fn finalize_into(
    module: &mut JITModule,
    defs: &[JitDef],
    table: &NativeTable,
) -> Result<(), JitError> {
    let entry_sig = native_entry_signature(module);
    for def in defs {
        let decl = module.declarations().get_function_decl(def.func_id);
        if decl.signature != entry_sig {
            return Err(JitError::EntrySignature {
                name: decl.name.clone().unwrap_or_default(),
            });
        }
    }
    // The trampoline is one per module, defined on the first publish. Later
    // publishes — a lazily compiled body joining a module that is already
    // running — must not redefine it.
    if table.trampoline().is_null() {
        let tramp = entry_trampoline(module)?;
        module.finalize_definitions()?;
        table.set_trampoline(module.get_finalized_function(tramp));
    } else {
        module.finalize_definitions()?;
    }
    for def in defs {
        let code = module.get_finalized_function(def.func_id);
        table.set(def.fn_idx, code);
        perf_map::record(code as usize, def.code_size as usize, &def.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::bytecode::NativeStatus;
    use crate::bytecode::Value;
    use crate::bytecode::value::take_freed_objects;
    use crate::heap::ProcHeap;
    use crate::native_rc::emit_dynamic_drop;
    use crate::tivec::Idx;
    use cranelift_codegen::ir::InstBuilder;
    use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};

    use super::super::{VM, halt_test_vm};
    use super::*;

    /// Define one exported function whose body `build` writes, then finalize
    /// the module and hand back the code address.
    fn define_and_finalize(
        module: &mut JITModule,
        name: &str,
        sig: Signature,
        build: impl FnOnce(&mut JITModule, &mut FunctionBuilder),
    ) -> *const u8 {
        let id = module
            .declare_function(name, Linkage::Export, &sig)
            .unwrap();
        let mut ctx = module.make_context();
        ctx.func.signature = sig;
        let mut fbc = FunctionBuilderContext::new();
        {
            let mut b = FunctionBuilder::new(&mut ctx.func, &mut fbc);
            let entry = b.create_block();
            b.append_block_params_for_function_params(entry);
            b.switch_to_block(entry);
            b.seal_block(entry);
            build(module, &mut b);
            b.finalize();
        }
        module.define_function(id, &mut ctx).unwrap();
        module.clear_context(&mut ctx);
        module.finalize_definitions().unwrap();
        module.get_finalized_function(id)
    }

    #[test]
    fn runtime_table_matches_the_rust_definitions() {
        use AbiTy::{I64, Ptr};
        type P2 = crate::vm::native::PreparedCall;

        // Uniqueness and non-null addresses.
        let syms = runtime_symbols();
        for (i, (name, addr)) in syms.iter().enumerate() {
            assert!(!addr.is_null(), "{name} has a null address");
            assert!(
                syms[..i].iter().all(|(n, _)| n != name),
                "duplicate runtime symbol {name}"
            );
        }

        // Each pin coerces the shim to an explicit `extern "C"` type — a
        // signature edit is a compile error here — and states the CLIF shape
        // that type corresponds to. The asserts below tie pin ↔ table ↔
        // registered address, so all four copies of the fact must agree.
        struct Pin(&'static str, *const u8, &'static [AbiTy], &'static [AbiTy]);
        let release: unsafe extern "C" fn(*mut u64) = native_release_at_zero;
        let hollow: unsafe extern "C" fn(*mut u64) = native_hollow_for_reuse;
        let enum_alloc: unsafe extern "C" fn(*mut VM, u64, u64, u64, u64, *const u64, i64) -> u64 =
            native_shims::al_shim_enum_alloc;
        let make_array: unsafe extern "C" fn(*mut VM, *const u64, i64) -> u64 =
            native_shims::al_shim_make_array;
        let make_tuple: unsafe extern "C" fn(*mut VM, *const u64, i64) -> u64 =
            native_shims::al_shim_make_tuple;
        let seq_len: unsafe extern "C" fn(*mut VM, u64) -> u64 = native_shims::al_shim_seq_len;
        let seq_append: unsafe extern "C" fn(*mut VM, *const u64, i64) -> u64 =
            native_shims::al_shim_seq_append;
        let seq_prepend: unsafe extern "C" fn(*mut VM, *const u64, i64) -> u64 =
            native_shims::al_shim_seq_prepend;
        let bin_byte_size: unsafe extern "C" fn(*mut VM, u64) -> u64 =
            native_shims::al_shim_bin_byte_size;
        let http_parse_head: unsafe extern "C" fn(*mut VM, u64, i64) -> u64 =
            native_shims::al_shim_http_parse_head;
        let http_headers_valid: unsafe extern "C" fn(u64) -> u64 =
            native_shims::al_shim_http_headers_valid;
        let http_header_has: unsafe extern "C" fn(u64, u64) -> u64 =
            native_shims::al_shim_http_header_has;
        let http_serialize_head: unsafe extern "C" fn(*mut VM, i64, u64, u64) -> u64 =
            native_shims::al_shim_http_serialize_head;
        let http_framing: unsafe extern "C" fn(*mut VM, u64) -> u64 =
            native_shims::al_shim_http_framing;
        let push_global: unsafe extern "C" fn(*mut VM, i64) -> u64 =
            native_shims::al_shim_push_global;
        let push_capture: unsafe extern "C" fn(*mut VM, i64) -> u64 =
            native_shims::al_shim_push_capture;
        let push_self: unsafe extern "C" fn(*mut VM) -> u64 = native_shims::al_shim_push_self;
        let int_box: unsafe extern "C" fn(*mut VM, i64) -> u64 = native_shims::al_shim_int_box;
        let div_int: extern "C" fn(i64, i64) -> i64 = native_shims::al_shim_div_int;
        let mod_int: extern "C" fn(i64, i64) -> i64 = native_shims::al_shim_mod_int;
        let shim_op: unsafe extern "C" fn(*mut VM, i64, i64, *const u64, i64) -> u64 =
            native_shims::al_shim_op;
        let park_op: unsafe extern "C" fn(*mut VM, i64, *const u64, i64, i64, i64) -> u64 =
            native_shims::al_shim_park_op;
        let try_op: unsafe extern "C" fn(*mut VM, i64, i64, *const u64, i64) -> u64 =
            native_shims::al_shim_try_op;
        let prepare_call: unsafe extern "C" fn(*mut VM, i64, i64, *const u64, i64) -> P2 =
            native::al_rt_prepare_call;
        let prepare_call_value: unsafe extern "C" fn(*mut VM, u64, i64, *const u64, i64) -> P2 =
            native::al_rt_prepare_call_value;
        let prepare_tail: unsafe extern "C" fn(*mut VM, i64, *const u64, i64) -> P2 =
            native::al_rt_prepare_tail;
        let prepare_tail_value: unsafe extern "C" fn(*mut VM, u64, *const u64, i64) -> P2 =
            native::al_rt_prepare_tail_value;
        let ret_transfer: unsafe extern "C" fn(*mut VM, u64) -> P2 = native::al_rt_ret_transfer;
        let rt_pop: unsafe extern "C" fn(*mut VM) -> u64 = native::al_rt_pop;
        let make_closure: unsafe extern "C" fn(*mut VM, i64, *const u64, i64) -> u64 =
            native::al_rt_make_closure;
        let rt_checkpoint: unsafe extern "C" fn(*mut VM) -> NativeStatus = native::al_rt_checkpoint;
        let rt_frame_base: unsafe extern "C" fn(*mut VM) -> *mut u64 = native::al_rt_frame_base;

        let pins = [
            Pin(
                NATIVE_RELEASE_AT_ZERO_SYMBOL,
                release as *const u8,
                &[Ptr],
                &[],
            ),
            Pin(
                NATIVE_HOLLOW_FOR_REUSE_SYMBOL,
                hollow as *const u8,
                &[Ptr],
                &[],
            ),
            Pin(
                "al_shim_enum_alloc",
                enum_alloc as *const u8,
                &[Ptr, I64, I64, I64, I64, Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_make_array",
                make_array as *const u8,
                &[Ptr, Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_make_tuple",
                make_tuple as *const u8,
                &[Ptr, Ptr, I64],
                &[I64],
            ),
            Pin("al_shim_seq_len", seq_len as *const u8, &[Ptr, I64], &[I64]),
            Pin(
                "al_shim_seq_append",
                seq_append as *const u8,
                &[Ptr, Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_seq_prepend",
                seq_prepend as *const u8,
                &[Ptr, Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_bin_byte_size",
                bin_byte_size as *const u8,
                &[Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_http_parse_head",
                http_parse_head as *const u8,
                &[Ptr, I64, I64],
                &[I64],
            ),
            Pin(
                "al_shim_http_headers_valid",
                http_headers_valid as *const u8,
                &[I64],
                &[I64],
            ),
            Pin(
                "al_shim_http_header_has",
                http_header_has as *const u8,
                &[I64, I64],
                &[I64],
            ),
            Pin(
                "al_shim_http_serialize_head",
                http_serialize_head as *const u8,
                &[Ptr, I64, I64, I64],
                &[I64],
            ),
            Pin(
                "al_shim_http_framing",
                http_framing as *const u8,
                &[Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_push_global",
                push_global as *const u8,
                &[Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_push_capture",
                push_capture as *const u8,
                &[Ptr, I64],
                &[I64],
            ),
            Pin("al_shim_push_self", push_self as *const u8, &[Ptr], &[I64]),
            Pin("al_shim_int_box", int_box as *const u8, &[Ptr, I64], &[I64]),
            Pin("al_shim_div_int", div_int as *const u8, &[I64, I64], &[I64]),
            Pin("al_shim_mod_int", mod_int as *const u8, &[I64, I64], &[I64]),
            Pin(
                "al_shim_op",
                shim_op as *const u8,
                &[Ptr, I64, I64, Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_shim_park_op",
                park_op as *const u8,
                &[Ptr, I64, Ptr, I64, I64, I64],
                &[I64],
            ),
            Pin(
                "al_shim_try_op",
                try_op as *const u8,
                &[Ptr, I64, I64, Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_rt_prepare_call",
                prepare_call as *const u8,
                &[Ptr, I64, I64, Ptr, I64],
                &[Ptr, I64],
            ),
            Pin(
                "al_rt_prepare_call_value",
                prepare_call_value as *const u8,
                &[Ptr, I64, I64, Ptr, I64],
                &[Ptr, I64],
            ),
            Pin(
                "al_rt_prepare_tail",
                prepare_tail as *const u8,
                &[Ptr, I64, Ptr, I64],
                &[Ptr, I64],
            ),
            Pin(
                "al_rt_prepare_tail_value",
                prepare_tail_value as *const u8,
                &[Ptr, I64, Ptr, I64],
                &[Ptr, I64],
            ),
            Pin(
                "al_rt_ret_transfer",
                ret_transfer as *const u8,
                &[Ptr, I64],
                &[Ptr, I64],
            ),
            Pin("al_rt_pop", rt_pop as *const u8, &[Ptr], &[I64]),
            Pin(
                "al_rt_make_closure",
                make_closure as *const u8,
                &[Ptr, I64, Ptr, I64],
                &[I64],
            ),
            Pin(
                "al_rt_checkpoint",
                rt_checkpoint as *const u8,
                &[Ptr],
                &[I64],
            ),
            Pin(
                "al_rt_frame_base",
                rt_frame_base as *const u8,
                &[Ptr],
                &[Ptr],
            ),
        ];

        assert_eq!(pins.len(), RT_SIGS.len(), "every table entry needs a pin");
        assert_eq!(
            syms.len(),
            RT_SIGS.len(),
            "table and symbol registry must be 1:1"
        );
        for Pin(name, addr, params, rets) in &pins {
            let e = RT_SIGS
                .iter()
                .find(|e| e.name == *name)
                .unwrap_or_else(|| panic!("{name} pinned but not in RT_SIGS"));
            assert_eq!(
                e.params, *params,
                "{name}: table params drifted from the pinned ABI"
            );
            assert_eq!(
                e.rets, *rets,
                "{name}: table rets drifted from the pinned ABI"
            );
            let (_, registered) = syms
                .iter()
                .find(|(n, _)| n == name)
                .unwrap_or_else(|| panic!("{name} is not in runtime_symbols()"));
            assert_eq!(
                *registered, *addr,
                "{name} resolves to a different function than the one whose ABI is pinned"
            );
        }

        // And every declaration a module would make must succeed.
        let mut module = jit_module().unwrap();
        declare_runtime_imports(&mut module).unwrap();
    }
    #[test]
    fn by_name_import_resolves_to_the_registered_shim() {
        let mut module = jit_module().unwrap();
        let ids = declare_runtime_imports(&mut module).unwrap();
        let ptr_ty = module.target_config().pointer_type();
        let mut sig = module.make_signature();
        sig.params.push(AbiParam::new(ptr_ty));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(types::I64));
        let code = define_and_finalize(&mut module, "box_caller", sig, |module, b| {
            let entry = b.current_block().unwrap();
            let vmx = b.block_params(entry)[0];
            let i = b.block_params(entry)[1];
            let int_box = module.declare_func_in_func(ids["al_shim_int_box"], b.func);
            let call = b.ins().call(int_box, &[vmx, i]);
            let bits = b.inst_results(call)[0];
            b.ins().return_(&[bits]);
        });
        // SAFETY: compiled with exactly this signature above.
        let box_caller = unsafe {
            std::mem::transmute::<*const u8, unsafe extern "C" fn(*mut VM, i64) -> u64>(code)
        };

        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;
        // In-range: identical bits to the interpreter's immediate encoding.
        let bits = unsafe { box_caller(vmp, 42) };
        assert_eq!(bits, Value::small_int(42).to_bits());
        // Out of range: a live BigInt box in the running process heap.
        let bits = unsafe { box_caller(vmp, i64::MAX) };
        let spilled = unsafe { Value::from_bits(bits) };
        assert!(spilled.is_heap() && !spilled.is_immortal());
        assert_eq!(spilled.as_int(), Some(i64::MAX));
    }

    /// CLIF emitted by `emit_dynamic_drop` calls a runtime symbol it never
    /// links against, resolved through this registry. The same path
    /// `scarlet_core`'s CLIF construction takes to reach the runtime.
    #[test]
    fn front_end_emitted_clif_resolves_through_this_registry() {
        let mut module = jit_module().unwrap();
        let ids = declare_runtime_imports(&mut module).unwrap();
        let mut sig = module.make_signature();
        sig.params.push(AbiParam::new(types::I64));
        let code = define_and_finalize(&mut module, "drop_bits", sig, |module, b| {
            let entry = b.current_block().unwrap();
            let bits = b.block_params(entry)[0];
            let release = module.declare_func_in_func(ids[NATIVE_RELEASE_AT_ZERO_SYMBOL], b.func);
            emit_dynamic_drop(b, bits, release);
            b.ins().return_(&[]);
        });
        // SAFETY: compiled with exactly this signature above.
        let drop_bits =
            unsafe { std::mem::transmute::<*const u8, unsafe extern "C" fn(u64)>(code) };

        let mut heap = ProcHeap::new();
        let v = Value::int_in(&mut heap, i64::MAX); // mortal BigInt, rc = 1
        assert!(v.is_heap() && !v.is_immortal());
        take_freed_objects();
        unsafe { drop_bits(v.to_bits()) }; // 1 -> 0: freed through the shim
        assert_eq!(take_freed_objects(), 1);
        std::mem::forget(v); // the JIT'd gate released the last reference
    }

    /// `finalize_into` publishes runnable entries into a `NativeTable` and
    /// refuses declarations that do not carry the entry signature.
    #[test]
    fn finalize_into_publishes_entries_and_checks_the_signature() {
        let mut module = jit_module().unwrap();
        let sig = native_entry_signature(&module);
        let id = module
            .declare_function("al_fn_0", Linkage::Export, &sig)
            .unwrap();
        let mut ctx = module.make_context();
        ctx.func.signature = sig;
        let mut fbc = FunctionBuilderContext::new();
        {
            let mut b = FunctionBuilder::new(&mut ctx.func, &mut fbc);
            let entry = b.create_block();
            b.append_block_params_for_function_params(entry);
            b.switch_to_block(entry);
            b.seal_block(entry);
            let done = b.ins().iconst(types::I64, NativeStatus::Done as u64 as i64);
            b.ins().return_(&[done]);
            b.finalize();
        }
        module.define_function(id, &mut ctx).unwrap();
        module.clear_context(&mut ctx);

        // A wrong-signature declaration is refused up front, before anything
        // is published.
        let mut bad_sig = module.make_signature();
        bad_sig.returns.push(AbiParam::new(types::I64));
        let bad = module
            .declare_function("wrong_shape", Linkage::Import, &bad_sig)
            .unwrap();
        let table = NativeTable::new(2);
        let def = |fn_idx: usize, func_id: FuncId, name: &str| JitDef {
            fn_idx: FuncIdx::from_usize(fn_idx),
            func_id,
            name: name.to_string(),
            code_size: 0,
        };
        match finalize_into(&mut module, &[def(1, bad, "wrong_shape")], &table) {
            Err(JitError::EntrySignature { name }) => assert_eq!(name, "wrong_shape"),
            other => panic!("expected EntrySignature error, got {other:?}"),
        }
        assert!(table.get(FuncIdx::from_usize(1)).is_none());

        finalize_into(&mut module, &[def(0, id, "al_fn_0")], &table).unwrap();
        let entry = table.get(FuncIdx::from_usize(0)).expect("published");
        let tramp = table.trampoline();
        assert!(
            !tramp.is_null(),
            "finalize_into must publish the trampoline"
        );
        // SAFETY: finalized trampoline + entry from this module; the body
        // ignores its ctx.
        let status = unsafe {
            crate::bytecode::native::call_entry_preserving_pinned(
                std::ptr::null_mut(),
                tramp,
                entry,
                0,
            )
        };
        assert_eq!(status, NativeStatus::Done);
        assert!(table.get(FuncIdx::from_usize(1)).is_none());
    }
}

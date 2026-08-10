//! Runtime shims compiled code calls, matching the interpreter's semantics.
//!
//! A proven-`Int` value lives as a raw `i64` in registers, so only the boxing
//! seams need help. Scarlet Ints are 47-bit NaN-boxed immediates: a result outside
//! `[-2^47, 2^47)` spills to an arena `BigInt`, and an Int-typed frame slot may
//! already hold one. Compiled code inlines the fast paths and branches here on
//! the cold side.
//!
//! Div and mod are total like the interpreter (`x / 0 == 0`, `x % 0 == x`,
//! `MIN / -1` wraps), where a bare `sdiv`/`srem` would trap.
//!
//! The `al_shim_*_int_val` shims are the one-call cold path over value bits:
//! decode, release the operand references the caller transfers, apply, re-box.
//!
//! Generated code finds these by symbol name; the JIT registers every
//! [`shim_symbols`] pair, so the CLIF emitter names them without depending on
//! this crate.

// Generated code cannot pass `&mut VM` or `Value`, so this boundary works in
// raw pointers and raw NaN-box bits.
#![allow(unsafe_code)]

use crate::TypeId;
use crate::bytecode::value::{ReuseAddr, proof_violation, range_len};
use crate::bytecode::{NativeStatus, Op, Value, ValueView, seq};

use super::poll::{Parked, Resume};
use super::{Step, VM, VmResult};

/// Escape raw bits from an owned value without running its destructor. The
/// reference it carries transfers to the returned bits.
#[inline]
fn into_bits(v: Value) -> u64 {
    std::mem::ManuallyDrop::new(v).to_bits()
}

/// Truncating division, total like `Op::DivInt`: `x / 0 == 0`, `MIN / -1`
/// wraps instead of trapping.
#[inline]
fn div_int(a: i64, b: i64) -> i64 {
    if b == 0 { 0 } else { a.wrapping_div(b) }
}

/// Remainder, total like `Op::ModInt`: `x % 0 == x`, `MIN % -1 == 0`. The
/// result takes the dividend's sign.
#[inline]
fn mod_int(a: i64, b: i64) -> i64 {
    if b == 0 { a } else { a.wrapping_rem(b) }
}

/// Shared body of the whole-op shims.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `a` and `b` must
/// each be the bits of an Int-typed `Value` whose reference the caller owns
/// and transfers to this call.
unsafe fn bin_int_val(vmx: *mut VM, a: u64, b: u64, op: impl FnOnce(i64, i64) -> i64) -> u64 {
    // SAFETY: both operand references are transferred per the contract above;
    // the drops below balance them exactly once.
    let (a, b) = unsafe { (Value::from_bits(a), Value::from_bits(b)) };
    let r = op(a.as_int_typed(), b.as_int_typed());
    drop(a);
    drop(b);
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    into_bits(vm.boxed_int(r))
}

/// Box a full-range `i64` as an Int value, spilling past the 47-bit immediate
/// range to an arena `BigInt`. The returned bits carry one owned reference the
/// caller must store or release exactly once.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`.
#[cold]
pub unsafe extern "C" fn al_shim_int_box(vmx: *mut VM, i: i64) -> u64 {
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    into_bits(vm.boxed_int(i))
}

/// Decode an Int-typed value's bits to the full `i64`. Borrow-only: the caller
/// keeps its reference.
///
/// # Safety
/// `bits` must be the bits of an Int-typed `Value`; a `BigInt` box must be
/// live for the duration of the call.
#[cold]
pub unsafe extern "C" fn al_shim_int_unbox(bits: u64) -> i64 {
    // SAFETY: borrowed read per the contract above; ManuallyDrop keeps the
    // caller's reference count untouched.
    let v = std::mem::ManuallyDrop::new(unsafe { Value::from_bits(bits) });
    v.as_int_typed()
}

/// `Op::AddInt` over value bits. Consumes both operand references.
///
/// # Safety
/// As [`bin_int_val`].
#[cold]
pub unsafe extern "C" fn al_shim_add_int_val(vmx: *mut VM, a: u64, b: u64) -> u64 {
    // SAFETY: forwarded contract.
    unsafe { bin_int_val(vmx, a, b, i64::wrapping_add) }
}

/// `Op::SubInt` over value bits. Consumes both operand references.
///
/// # Safety
/// As [`bin_int_val`].
#[cold]
pub unsafe extern "C" fn al_shim_sub_int_val(vmx: *mut VM, a: u64, b: u64) -> u64 {
    // SAFETY: forwarded contract.
    unsafe { bin_int_val(vmx, a, b, i64::wrapping_sub) }
}

/// `Op::MulInt` over value bits. Consumes both operand references.
///
/// # Safety
/// As [`bin_int_val`].
#[cold]
pub unsafe extern "C" fn al_shim_mul_int_val(vmx: *mut VM, a: u64, b: u64) -> u64 {
    // SAFETY: forwarded contract.
    unsafe { bin_int_val(vmx, a, b, i64::wrapping_mul) }
}

/// `Op::DivInt` over value bits. Consumes both operand references.
///
/// # Safety
/// As [`bin_int_val`].
#[cold]
pub unsafe extern "C" fn al_shim_div_int_val(vmx: *mut VM, a: u64, b: u64) -> u64 {
    // SAFETY: forwarded contract.
    unsafe { bin_int_val(vmx, a, b, div_int) }
}

/// `Op::ModInt` over value bits. Consumes both operand references.
///
/// # Safety
/// As [`bin_int_val`].
#[cold]
pub unsafe extern "C" fn al_shim_mod_int_val(vmx: *mut VM, a: u64, b: u64) -> u64 {
    // SAFETY: forwarded contract.
    unsafe { bin_int_val(vmx, a, b, mod_int) }
}

/// `Op::NegInt` over value bits: wrapping negation, so `MIN` stays `MIN` and
/// `-SMALL_INT_MIN` spills (the immediate range is asymmetric). Consumes the
/// operand reference.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `a` must be the
/// bits of an Int-typed `Value` whose reference the caller transfers.
#[cold]
pub unsafe extern "C" fn al_shim_neg_int_val(vmx: *mut VM, a: u64) -> u64 {
    // SAFETY: the operand reference is transferred per the contract above; the
    // drop balances it exactly once.
    let a = unsafe { Value::from_bits(a) };
    let r = a.as_int_typed().wrapping_neg();
    drop(a);
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    into_bits(vm.boxed_int(r))
}

/// `Op::MakeEnumPayload`'s allocation path behind the C ABI. Must mirror
/// `VM::make_enum_payload` bit for bit: `packed` is the emitter's
/// `type_id | variant_idx << 32` word, the name and label bits are frozen
/// immortal constants stored verbatim, and the hash word is written `0`
/// because 0 means "not yet hashed" to `EnumRef::hash`.
///
/// `payload` points at `len` value words, each carrying one owned reference
/// the caller transfers. The cell takes its own reference per field and this
/// shim releases the transferred ones.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `enum_name` and
/// `variant_name` must be the bits of live frozen `Str` values, `labels` of a
/// live frozen `Tuple` of `Str`s (all immortal, outliving the program);
/// `payload` must point at `len` initialized value words whose references
/// the caller owns and transfers to this call.
#[cold]
pub unsafe extern "C" fn al_shim_enum_alloc(
    vmx: *mut VM,
    packed: u64,
    enum_name: u64,
    variant_name: u64,
    labels: u64,
    payload: *const u64,
    len: i64,
) -> u64 {
    let type_id = TypeId(packed as i32);
    let variant_idx = (packed >> 32) as u16;
    let n = len as usize;
    // SAFETY: immortal frozen constants per the contract above. Treating the
    // bits as owned is sound because immortal clone/drop never touches memory.
    let (en, vn, lb) = unsafe {
        (
            Value::from_bits(enum_name),
            Value::from_bits(variant_name),
            Value::from_bits(labels),
        )
    };
    debug_assert!(en.is_immortal() && vn.is_immortal() && lb.is_immortal());
    // SAFETY: `payload` points at `n` initialized value words and `Value` is
    // repr(transparent) over u64. Borrowed: the cell takes its own reference.
    let fields: &[Value] = if n == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(payload.cast::<Value>(), n) }
    };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let v = Value::enum_reuse_in(
        &mut vm.heap,
        ReuseAddr::none(),
        type_id,
        variant_idx,
        0,
        en,
        vn,
        lb,
        fields,
    );
    for i in 0..n {
        // SAFETY: each word carries one owned reference, released once here.
        drop(unsafe { Value::from_bits(payload.add(i).read()) });
    }
    into_bits(v)
}

/// `Op::MakeArray` behind the C ABI. `elems` points at `len` value words, each
/// carrying one owned reference the caller transfers; the array takes its own
/// reference per element and this shim releases the transferred ones.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `elems` must point
/// at `len` initialized value words whose references the caller owns and
/// transfers to this call.
#[cold]
pub unsafe extern "C" fn al_shim_make_array(vmx: *mut VM, elems: *const u64, len: i64) -> u64 {
    let n = len as usize;
    // SAFETY: `elems` points at `n` initialized value words and `Value` is
    // repr(transparent) over u64. Borrowed: the array takes its own reference.
    let vals: &[Value] = if n == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(elems.cast::<Value>(), n) }
    };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let v = Value::array_in(&mut vm.heap, vals);
    for i in 0..n {
        // SAFETY: each word carries one owned reference, released once here.
        drop(unsafe { Value::from_bits(elems.add(i).read()) });
    }
    into_bits(v)
}

/// `Op::MakeTuple` behind the C ABI: [`al_shim_make_array`] over `tuple_in`.
///
/// # Safety
/// Same contract as [`al_shim_make_array`].
#[cold]
pub unsafe extern "C" fn al_shim_make_tuple(vmx: *mut VM, elems: *const u64, len: i64) -> u64 {
    let n = len as usize;
    // SAFETY: see `al_shim_make_array`; identical contract.
    let vals: &[Value] = if n == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(elems.cast::<Value>(), n) }
    };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let v = Value::tuple_in(&mut vm.heap, vals);
    for i in 0..n {
        // SAFETY: each word carries one owned reference, released once here.
        drop(unsafe { Value::from_bits(elems.add(i).read()) });
    }
    into_bits(v)
}

/// `VM::seq_root`, made total. The coverage gate only admits these ops on a
/// proven `Array`-typed operand, so the interpreter's error arm is
/// unreachable; a stray value passes through untouched.
fn seq_root_total(vm: &mut VM, v: Value) -> Value {
    match v.kind() {
        ValueView::Array(_) => v,
        ValueView::Range(s, e) => seq::from_int_range(&mut vm.heap, s, e),
        _ => crate::bytecode::value::proof_violation("seq op on a non-sequence value"),
    }
}

/// `Op::ArrayLen` behind the C ABI, on a proven `Array`-typed word. The result
/// is boxed because a lazy range's length can exceed the small-int payload.
/// The transferred reference is released.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `seq` must carry
/// one owned reference the caller transfers.
pub unsafe extern "C" fn al_shim_seq_len(vmx: *mut VM, seq: u64) -> u64 {
    // SAFETY: owned word per the contract above.
    let v = unsafe { Value::from_bits(seq) };
    let n = match v.kind() {
        ValueView::Array(a) => a.len() as i64,
        ValueView::Range(s, e) => range_len(s, e),
        ValueView::Tuple(t) => t.len() as i64,
        _ => crate::bytecode::value::proof_violation("ArrayLen on a non-sequence value"),
    };
    drop(v);
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    into_bits(vm.boxed_int(n))
}

/// `Op::BinByteSize` behind the C ABI, on a proven `Binary`-typed word. The
/// transferred reference is released.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `bin` must carry
/// one owned reference the caller transfers.
pub unsafe extern "C" fn al_shim_bin_byte_size(vmx: *mut VM, bin: u64) -> u64 {
    // SAFETY: owned word per the contract above.
    let v = unsafe { Value::from_bits(bin) };
    let n = match v.kind() {
        ValueView::Binary(b) => b.bit_len().div_ceil(8) as i64,
        _ => crate::bytecode::value::proof_violation("BinByteSize on a non-binary value"),
    };
    drop(v);
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    into_bits(vm.boxed_int(n))
}

/// `Op::Append` behind the C ABI. `buf[0]` is the sequence and `buf[1..len]`
/// the pushed elements, matching the interpreter's operand order. Every
/// transferred reference is released.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `buf` must point
/// at `len >= 1` initialized value words whose references the caller owns
/// and transfers to this call.
pub unsafe extern "C" fn al_shim_seq_append(vmx: *mut VM, buf: *const u64, len: i64) -> u64 {
    let n = len as usize;
    // SAFETY: `buf` points at `n` initialized value words, borrowed here; the
    // tree takes its own reference per element.
    let words: &[Value] = unsafe { std::slice::from_raw_parts(buf.cast::<Value>(), n) };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let mut root = seq_root_total(vm, words[0].clone());
    for e in &words[1..] {
        root = seq::push_back(&mut vm.heap, &root, e.clone());
    }
    for i in 0..n {
        // SAFETY: each word carries one owned reference, released once here.
        drop(unsafe { Value::from_bits(buf.add(i).read()) });
    }
    into_bits(root)
}

/// `Op::Prepend` behind the C ABI. `buf[..len-1]` are the elements in source
/// order and `buf[len-1]` the sequence, matching the interpreter's operand
/// order. Pushes front in reverse so the result is `[e0, .., ek-1, ..seq]`.
///
/// # Safety
/// Same contract as [`al_shim_seq_append`].
pub unsafe extern "C" fn al_shim_seq_prepend(vmx: *mut VM, buf: *const u64, len: i64) -> u64 {
    let n = len as usize;
    // SAFETY: see `al_shim_seq_append`; identical contract.
    let words: &[Value] = unsafe { std::slice::from_raw_parts(buf.cast::<Value>(), n) };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let mut root = seq_root_total(vm, words[n - 1].clone());
    for e in words[..n - 1].iter().rev() {
        root = seq::push_front(&mut vm.heap, &root, e.clone());
    }
    for i in 0..n {
        // SAFETY: each word carries one owned reference, released once here.
        drop(unsafe { Value::from_bits(buf.add(i).read()) });
    }
    into_bits(root)
}

/// `Op::HttpParseHead` behind the C ABI: parse a request head out of a proven
/// `Binary`-typed buffer at `off`. Infallible here, since malformed input comes
/// back as an Scarlet enum value. The transferred buffer reference is released.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `buf` must carry
/// one owned reference the caller transfers.
pub unsafe extern "C" fn al_shim_http_parse_head(vmx: *mut VM, buf: u64, off: i64) -> u64 {
    // SAFETY: owned word per the contract above.
    let v = unsafe { Value::from_bits(buf) };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let r = match vm.templates.h1() {
        Ok(t) => super::http::parse_head(t, &mut vm.heap, &super::bin_ref(&v), off),
        // Unreachable: compiled code exists only for programs that bound the
        // H1 slots (validated at load).
        Err(_) => crate::bytecode::value::proof_violation("HttpParseHead with unbound H1 slots"),
    };
    drop(v);
    into_bits(r)
}

/// `Op::HttpHeadersValid` behind the C ABI, on a proven `Array(Header)`-typed
/// word. The shape error is unreachable under the proof; release answers
/// `false`.
///
/// # Safety
/// `headers` must carry one owned reference the caller transfers.
pub unsafe extern "C" fn al_shim_http_headers_valid(headers: u64) -> u64 {
    // SAFETY: owned word per the contract above.
    let v = unsafe { Value::from_bits(headers) };
    let r = super::http::headers_valid(&v).unwrap_or_else(|_| {
        crate::bytecode::value::proof_violation("HttpHeadersValid on a non-header array")
    });
    drop(v);
    into_bits(r)
}

/// `Op::HttpHeaderHas` behind the C ABI, on proven `Array(Header)` + `Binary`
/// words. Both transferred references are released.
///
/// # Safety
/// `headers` and `name` must each carry one owned reference the caller
/// transfers.
pub unsafe extern "C" fn al_shim_http_header_has(headers: u64, name: u64) -> u64 {
    // SAFETY: owned words per the contract above.
    let (h, n) = unsafe { (Value::from_bits(headers), Value::from_bits(name)) };
    let r = super::http::header_has(&h, &super::bin_ref(&n)).unwrap_or_else(|_| {
        crate::bytecode::value::proof_violation("HttpHeaderHas on a non-header array")
    });
    drop(h);
    drop(n);
    into_bits(r)
}

/// `Op::HttpSerializeHead` behind the C ABI: one fresh binary over the
/// serialized head. `code` is passed unboxed. The shape error is unreachable
/// under the proofs; release answers nil.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `reason` and
/// `headers` must each carry one owned reference the caller transfers.
pub unsafe extern "C" fn al_shim_http_serialize_head(
    vmx: *mut VM,
    code: i64,
    reason: u64,
    headers: u64,
) -> u64 {
    // SAFETY: owned words per the contract above.
    let (rv, hv) = unsafe { (Value::from_bits(reason), Value::from_bits(headers)) };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let r = super::http::serialize_head(&mut vm.heap, code, &super::bin_ref(&rv), &hv)
        .unwrap_or_else(|_| {
            crate::bytecode::value::proof_violation("HttpSerializeHead on a non-header array")
        });
    drop(rv);
    drop(hv);
    into_bits(r)
}

/// `Op::HttpFraming` behind the C ABI, on a proven `Array(Header)`-typed word:
/// classify the body framing. The shape error is unreachable under the proof;
/// release answers nil.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `headers` must
/// carry one owned reference the caller transfers.
pub unsafe extern "C" fn al_shim_http_framing(vmx: *mut VM, headers: u64) -> u64 {
    // SAFETY: owned word per the contract above.
    let v = unsafe { Value::from_bits(headers) };
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    let r = vm
        .templates
        .h1()
        .and_then(|t| super::http::framing(t, &mut vm.heap, &v))
        .unwrap_or_else(|_| {
            crate::bytecode::value::proof_violation("HttpFraming on a non-header array")
        });
    drop(v);
    into_bits(r)
}

/// [`div_int`] on unboxed `i64`s.
pub extern "C" fn al_shim_div_int(a: i64, b: i64) -> i64 {
    div_int(a, b)
}

/// [`mod_int`] on unboxed `i64`s.
pub extern "C" fn al_shim_mod_int(a: i64, b: i64) -> i64 {
    mod_int(a, b)
}

/// `Op::PushGlobal`: the entry frame's slot `slot`, borrowed. Globals are
/// written once before any body reads them and never reassigned, so the word
/// stays live for the program; the caller retains only where it keeps one. A
/// shim rather than an inline load because the array is a `Vec` with no
/// ABI-stable base.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`, and `slot` must be
/// in range for its global area; the emitter guarantees both. The returned
/// word carries no reference the caller owns.
pub unsafe extern "C" fn al_shim_push_global(vmx: *mut VM, slot: i64) -> u64 {
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    vm.globals[slot as usize].to_bits()
}

/// The generic bridge for [`is_native_bridge_op`](crate::bytecode::is_native_bridge_op)
/// opcodes. `buf` holds `argc` owned operand words in interpreter push order
/// (`buf[0]` deepest, `buf[argc-1]` on top); each reference is transferred to
/// this call. The shim pushes them onto the value stack, runs the interpreter's
/// own op method (which pops them and pushes one result), and returns the owned
/// result bits.
///
/// The op methods' only `Err` arms are typed-pop mismatches the type checker
/// already excludes for well-typed bytecode, so a failure here is a proof
/// violation, not a recoverable error — no status word is needed.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `buf` must point at
/// `argc` initialized value words whose references the caller owns and
/// transfers; `op_code` must be `op as u8` for an op
/// [`is_native_bridge_op`](crate::bytecode::is_native_bridge_op) admits.
pub unsafe extern "C" fn al_shim_op(
    vmx: *mut VM,
    op_code: i64,
    operand: i64,
    buf: *const u64,
    argc: i64,
) -> u64 {
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    for i in 0..argc as usize {
        // SAFETY: `buf` holds `argc` initialized owned words; each transfers
        // its reference onto the value stack here, balanced by the op's pops.
        vm.stack
            .push(unsafe { Value::from_bits(buf.add(i).read()) });
    }
    // The ops that charge reductions take a budget; compiled code spends the
    // same counter the entry prologue and checkpoints use.
    let mut reds = vm.native_reds;
    let out = vm.run_bridge_op(op_code as u8, operand as i32, &mut reds);
    vm.native_reds = reds;
    match out {
        Ok(()) => match vm.stack.pop() {
            Some(v) => into_bits(v),
            None => proof_violation("bridge op produced no result"),
        },
        // The type checker excludes every reachable error arm of these ops.
        Err(_) => proof_violation("bridge op hit a type-proof-excluded error"),
    }
}

/// The bridge for [`is_native_park_op`](crate::bytecode::is_native_park_op)
/// opcodes: the ops that can suspend the process.
///
/// Runs like [`al_shim_op`], but reports back a [`NativeStatus`] instead of a
/// value, because the op may not finish. On completion the op has left its one
/// result on the value stack and the caller pops it. On a park, the op's
/// [`Resume`] picks which of the caller's two resume ordinals the frame
/// re-enters at.
///
/// The value stack is left exactly as the op arranged it, which is what makes
/// the retry protocol work: a retrying op pushes its operands back, and the
/// caller's retry attempt passes `argc == 0` so this call consumes those same
/// words instead of re-supplying them. Compiled code could not re-supply them
/// anyway — a parking op's operands are often slotless temps with no home to
/// reload from once the machine frame is gone.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`; `buf` must point at
/// `argc` initialized value words whose references the caller transfers;
/// `op_code` must be one [`is_native_park_op`](crate::bytecode::is_native_park_op)
/// admits, and both ordinals must name resume points of the running body.
pub unsafe extern "C" fn al_shim_park_op(
    vmx: *mut VM,
    op_code: i64,
    buf: *const u64,
    argc: i64,
    retry_ordinal: i64,
    cont_ordinal: i64,
) -> u64 {
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    for i in 0..argc as usize {
        // SAFETY: `buf` holds `argc` initialized owned words, transferred here.
        vm.stack
            .push(unsafe { Value::from_bits(buf.add(i).read()) });
    }
    let mut reds = vm.native_reds;
    let out = vm.run_park_op(op_code as u8, &mut reds);
    vm.native_reds = reds;
    match out {
        Ok(None) => NativeStatus::Done as u64,
        Ok(Some(parked)) => {
            let ordinal = match parked.resume {
                Resume::Retry => retry_ordinal,
                Resume::Continue => cont_ordinal,
            };
            vm.frame_mut().ip = ordinal as i32;
            vm.status_from_outcome(Ok(Step::Parked(parked.wait))) as u64
        }
        Err(e) => vm.status_from_outcome(Err(e)) as u64,
    }
}

impl VM {
    /// Dispatch an [`is_native_park_op`](crate::bytecode::is_native_park_op)
    /// opcode to its interpreter method. Mirrors the interpreter's `park!`
    /// arms; the two share the method bodies.
    pub(super) fn run_park_op(&mut self, op_code: u8, reds: &mut i32) -> VmResult<Option<Parked>> {
        match op_code {
            c if c == Op::FileRead as u8 => self.file_read(reds),
            c if c == Op::FileWrite as u8 => self.file_write(reds),
            c if c == Op::TcpAccept as u8 => self.tcp_accept(reds),
            c if c == Op::TcpConnect as u8 => self.tcp_connect(reds),
            c if c == Op::TcpRead as u8 => self.tcp_read(reds),
            c if c == Op::TcpReadUntil as u8 => self.tcp_read_until(reds),
            c if c == Op::TcpWrite as u8 => self.tcp_write(reds),
            c if c == Op::TcpWriteParts as u8 => self.tcp_write_parts(reds),
            c if c == Op::DnsResolve as u8 => self.dns_resolve(reds),
            c if c == Op::Sleep as u8 => self.sleep(),
            _ => proof_violation("run_park_op on an op is_native_park_op excludes"),
        }
    }
}

impl VM {
    /// Dispatch an [`is_native_bridge_op`](crate::bytecode::is_native_bridge_op)
    /// opcode to its interpreter method. `operand` is the op's flattened
    /// immediate (unused by ops without one). Mirrors the interpreter's
    /// `run_slice` arms exactly; the two share the method bodies.
    pub(super) fn run_bridge_op(
        &mut self,
        op_code: u8,
        operand: i32,
        reds: &mut i32,
    ) -> VmResult<()> {
        match op_code {
            c if c == Op::Index as u8 => self.seq_index(),
            c if c == Op::IndexOr as u8 => self.seq_index_or(operand),
            c if c == Op::ElemAt as u8 => self.elem_at(operand),
            c if c == Op::SeqDrop as u8 => self.seq_drop(),
            c if c == Op::ArrayConcat as u8 => self.seq_concat(),
            c if c == Op::MakeRange as u8 => self.make_range(),
            c if c == Op::MapGet as u8 => self.map_get(),
            c if c == Op::MapHas as u8 => self.map_has(),
            c if c == Op::MapKeys as u8 => self.map_keys(),
            c if c == Op::MapValues as u8 => self.map_values(),
            c if c == Op::MapSize as u8 => self.map_size(),
            c if c == Op::MapNew as u8 => self.map_new(),
            c if c == Op::MapSet as u8 => self.map_set(),
            c if c == Op::MapDelete as u8 => self.map_delete(),
            c if c == Op::MapToList as u8 => self.map_to_list(),
            c if c == Op::EnvMap as u8 => self.env_map(),
            c if c == Op::StrSplit as u8 => self.str_split(),
            c if c == Op::StrLen as u8 => self.str_len(),
            c if c == Op::StrContains as u8 => self.str_contains(),
            c if c == Op::StrTrim as u8 => self.str_trim(),
            c if c == Op::IntToString as u8 => self.int_to_string(),
            c if c == Op::ToString as u8 => self.op_to_string(),
            c if c == Op::StrConcatN as u8 => self.str_concat_n(operand as usize),
            c if c == Op::BinFromString as u8 => self.bin_from_string(),
            c if c == Op::BinToString as u8 => self.bin_to_string(),
            c if c == Op::BinBitSize as u8 => self.bin_bit_size(),
            c if c == Op::BinSlice as u8 => self.bin_slice(),
            c if c == Op::BinAppend as u8 => self.bin_append(),
            c if c == Op::BinConcatN as u8 => self.bin_concat_n(operand as usize),
            c if c == Op::BinMatchPrefix as u8 => self.bin_match_prefix(),
            c if c == Op::BinIndexOf as u8 => self.bin_index_of(),
            c if c == Op::BinByteAt as u8 => self.bin_byte_at(),
            c if c == Op::BinParseInt as u8 => self.bin_parse_int(),
            c if c == Op::BinEqIgnoreAsciiCase as u8 => self.bin_eq_ignore_ascii_case(),
            c if c == Op::BinToAsciiLower as u8 => self.bin_to_ascii_lower(),
            c if c == Op::BinFromIntAscii as u8 => self.bin_from_int_ascii(),
            c if c == Op::AddFloat as u8 => self.add_float(),
            c if c == Op::SubFloat as u8 => self.sub_float(),
            c if c == Op::MulFloat as u8 => self.mul_float(),
            c if c == Op::DivFloat as u8 => self.div_float(),
            c if c == Op::NegFloat as u8 => self.neg_float(),
            c if c == Op::LtFloat as u8 => self.lt_float(),
            c if c == Op::GtFloat as u8 => self.gt_float(),
            c if c == Op::LteFloat as u8 => self.lte_float(),
            c if c == Op::GteFloat as u8 => self.gte_float(),
            c if c == Op::FloatFloor as u8 => self.float_floor(),
            c if c == Op::FloatCeil as u8 => self.float_ceil(),
            c if c == Op::FloatRound as u8 => self.float_round(),
            c if c == Op::FloatTruncate as u8 => self.float_truncate(),
            c if c == Op::FloatFromInt as u8 => self.float_from_int(),
            c if c == Op::FloatToString as u8 => self.float_to_string(),
            c if c == Op::Monotonic as u8 => self.monotonic(),
            c if c == Op::IpParse as u8 => self.ip_parse(),
            c if c == Op::HttpChunkDecode as u8 => self.http_chunk_decode(),
            c if c == Op::Add as u8 => self.add(),
            c if c == Op::Sub as u8 => self.sub(),
            c if c == Op::Mul as u8 => self.mul(),
            c if c == Op::Div as u8 => self.div(),
            c if c == Op::Mod as u8 => self.rem(),
            c if c == Op::Neg as u8 => self.neg(),
            // The polymorphic comparisons: the emitter sends these here only
            // when it could not prove both operands Int (the Int case lowers
            // inline via `nop_of`).
            c if c == Op::Eq as u8 => self.eq_values(),
            c if c == Op::Neq as u8 => self.neq_values(),
            c if c == Op::Lt as u8 => self.compare_push(|o| o.is_lt()),
            c if c == Op::Gt as u8 => self.compare_push(|o| o.is_gt()),
            c if c == Op::Lte as u8 => self.compare_push(|o| o.is_le()),
            c if c == Op::Gte as u8 => self.compare_push(|o| o.is_ge()),
            c if c == Op::TcpListen as u8 => self.tcp_listen(),
            c if c == Op::TcpClose as u8 => self.tcp_close(reds),
            c if c == Op::TcpCloseServer as u8 => self.tcp_close_server(),
            c if c == Op::SpawnLocal as u8 => self.process_spawn_local(reds),
            c if c == Op::SpawnOnEach as u8 => self.process_spawn_on_each(reds),
            // `Print` is the one void op: it pushes nothing, and the bytecode
            // emitter supplies the `()` with a following `PushNil`. The bridge
            // returns exactly one value, so it must do the same.
            c if c == Op::Print as u8 => {
                self.print_op(reds)?;
                self.stack.push(Value::nil());
                Ok(())
            }
            _ => proof_violation("run_bridge_op on an op is_native_bridge_op excludes"),
        }
    }
}

/// `Op::PushCapture`: capture `idx` of the closure this frame is running,
/// borrowed. The frame's `captures` handle is the closure itself, and it is
/// rooted for the frame's whole life, so the word stays live; the caller
/// retains only where it keeps one. A shim rather than an inline load because
/// the frame is not in the value stack's ABI-stable region.
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`, and `idx` must be in
/// range for the running closure; the emitter guarantees both. The returned
/// word carries no reference the caller owns.
pub unsafe extern "C" fn al_shim_push_capture(vmx: *mut VM, idx: i64) -> u64 {
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    match vm
        .frame()
        .captures
        .as_closure()
        .and_then(|cl| cl.captures().get(idx as usize))
    {
        Some(v) => v.to_bits(),
        // The compiler mints capture indices from the closure it built.
        None => proof_violation("PushCapture index out of range for the running closure"),
    }
}

/// `Op::PushSelf`: the closure this frame is running, borrowed. Same rooting
/// argument as [`al_shim_push_capture`].
///
/// # Safety
/// `vmx` must point at the running scheduler's live `VM`. The returned word
/// carries no reference the caller owns.
pub unsafe extern "C" fn al_shim_push_self(vmx: *mut VM) -> u64 {
    // SAFETY: `vmx` is the running scheduler's VM per the contract above.
    let vm = unsafe { &mut *vmx };
    vm.frame().captures.to_bits()
}

/// Every shim as `(symbol name, address)` for `JITBuilder::symbol`. These
/// names are what the CLIF emitter's declared externals resolve against.
pub fn shim_symbols() -> [(&'static str, *const u8); 27] {
    [
        ("al_shim_push_global", al_shim_push_global as *const u8),
        ("al_shim_int_box", al_shim_int_box as *const u8),
        ("al_shim_int_unbox", al_shim_int_unbox as *const u8),
        ("al_shim_enum_alloc", al_shim_enum_alloc as *const u8),
        ("al_shim_make_array", al_shim_make_array as *const u8),
        ("al_shim_make_tuple", al_shim_make_tuple as *const u8),
        ("al_shim_seq_len", al_shim_seq_len as *const u8),
        ("al_shim_seq_append", al_shim_seq_append as *const u8),
        ("al_shim_seq_prepend", al_shim_seq_prepend as *const u8),
        ("al_shim_bin_byte_size", al_shim_bin_byte_size as *const u8),
        (
            "al_shim_http_parse_head",
            al_shim_http_parse_head as *const u8,
        ),
        (
            "al_shim_http_headers_valid",
            al_shim_http_headers_valid as *const u8,
        ),
        (
            "al_shim_http_header_has",
            al_shim_http_header_has as *const u8,
        ),
        (
            "al_shim_http_serialize_head",
            al_shim_http_serialize_head as *const u8,
        ),
        ("al_shim_http_framing", al_shim_http_framing as *const u8),
        ("al_shim_add_int_val", al_shim_add_int_val as *const u8),
        ("al_shim_sub_int_val", al_shim_sub_int_val as *const u8),
        ("al_shim_mul_int_val", al_shim_mul_int_val as *const u8),
        ("al_shim_div_int_val", al_shim_div_int_val as *const u8),
        ("al_shim_mod_int_val", al_shim_mod_int_val as *const u8),
        ("al_shim_neg_int_val", al_shim_neg_int_val as *const u8),
        ("al_shim_div_int", al_shim_div_int as *const u8),
        ("al_shim_mod_int", al_shim_mod_int as *const u8),
        ("al_shim_op", al_shim_op as *const u8),
        ("al_shim_push_capture", al_shim_push_capture as *const u8),
        ("al_shim_push_self", al_shim_push_self as *const u8),
        ("al_shim_park_op", al_shim_park_op as *const u8),
    ]
}

#[cfg(test)]
mod tests {
    use crate::bytecode::value::HeapTag;

    use super::super::halt_test_vm;
    use super::*;

    const SMALL_MIN: i64 = -(1i64 << 47);
    const SMALL_MAX: i64 = (1i64 << 47) - 1;

    fn unbox_and_release(bits: u64) -> i64 {
        unsafe { Value::from_bits(bits) }.as_int_typed()
    }

    fn is_bigint(bits: u64) -> bool {
        let v = std::mem::ManuallyDrop::new(unsafe { Value::from_bits(bits) });
        v.heap_tag() == Some(HeapTag::BigInt)
    }

    #[test]
    fn small_int_range_bounds_match_the_value_encoding() {
        assert!(Value::fits_small_int(SMALL_MIN));
        assert!(Value::fits_small_int(SMALL_MAX));
        assert!(!Value::fits_small_int(SMALL_MIN - 1));
        assert!(!Value::fits_small_int(SMALL_MAX + 1));
    }

    #[test]
    fn div_shim_matches_interpreter_edges() {
        assert_eq!(al_shim_div_int(7, 2), 3);
        assert_eq!(al_shim_div_int(-7, 2), -3); // truncates toward zero
        assert_eq!(al_shim_div_int(7, -2), -3);
        assert_eq!(al_shim_div_int(5, 0), 0); // x / 0 == 0, no error
        assert_eq!(al_shim_div_int(0, 0), 0);
        assert_eq!(al_shim_div_int(i64::MIN, -1), i64::MIN); // wraps, no trap
        assert_eq!(al_shim_div_int(i64::MIN, 1), i64::MIN);
    }

    #[test]
    fn mod_shim_matches_interpreter_edges() {
        assert_eq!(al_shim_mod_int(7, 2), 1);
        assert_eq!(al_shim_mod_int(-7, 2), -1); // takes the dividend's sign
        assert_eq!(al_shim_mod_int(7, -2), 1);
        assert_eq!(al_shim_mod_int(5, 0), 5); // x % 0 == x, no error
        assert_eq!(al_shim_mod_int(-5, 0), -5);
        assert_eq!(al_shim_mod_int(i64::MIN, -1), 0); // wraps, no trap
    }

    #[test]
    fn box_keeps_in_range_ints_immediate() {
        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;
        for i in [0, 1, -1, 42, SMALL_MIN, SMALL_MAX] {
            let bits = unsafe { al_shim_int_box(vmp, i) };
            assert_eq!(bits, Value::small_int(i).to_bits());
            assert_eq!(unsafe { al_shim_int_unbox(bits) }, i);
        }
    }

    #[test]
    fn box_spills_past_the_small_int_range_and_unbox_round_trips() {
        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;
        for i in [SMALL_MAX + 1, SMALL_MIN - 1, i64::MAX, i64::MIN] {
            let bits = unsafe { al_shim_int_box(vmp, i) };
            assert!(is_bigint(bits));
            assert_eq!(unsafe { al_shim_int_unbox(bits) }, i);
            assert_eq!(unbox_and_release(bits), i);
        }
    }

    #[test]
    fn add_spills_at_the_small_boundary_and_wraps_at_i64() {
        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;

        // A sum that leaves the immediate range spills to BigInt.
        let a = Value::small_int(SMALL_MAX).to_bits();
        let b = Value::small_int(1).to_bits();
        let r = unsafe { al_shim_add_int_val(vmp, a, b) };
        assert!(is_bigint(r));
        assert_eq!(unbox_and_release(r), SMALL_MAX + 1);

        // A boxed operand at i64::MAX wraps to i64::MIN, staying a BigInt.
        let a = into_bits(Value::int_in(&mut vm.heap, i64::MAX));
        let b = Value::small_int(1).to_bits();
        let r = unsafe { al_shim_add_int_val(vmp, a, b) };
        assert_eq!(unbox_and_release(r), i64::MIN);
    }

    #[test]
    fn sub_and_mul_wrap_like_the_interpreter() {
        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;

        let a = into_bits(Value::int_in(&mut vm.heap, i64::MIN));
        let b = Value::small_int(1).to_bits();
        let r = unsafe { al_shim_sub_int_val(vmp, a, b) };
        assert_eq!(unbox_and_release(r), i64::MAX);

        let a = Value::small_int(SMALL_MAX).to_bits();
        let b = Value::small_int(SMALL_MAX).to_bits();
        let r = unsafe { al_shim_mul_int_val(vmp, a, b) };
        assert_eq!(unbox_and_release(r), SMALL_MAX.wrapping_mul(SMALL_MAX));
    }

    #[test]
    fn div_and_mod_val_shims_cover_the_boxed_edges() {
        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;

        // MIN / -1 wraps to MIN (still a BigInt), MIN % -1 is 0 (small).
        let a = into_bits(Value::int_in(&mut vm.heap, i64::MIN));
        let b = Value::small_int(-1).to_bits();
        let r = unsafe { al_shim_div_int_val(vmp, a, b) };
        assert!(is_bigint(r));
        assert_eq!(unbox_and_release(r), i64::MIN);

        let a = into_bits(Value::int_in(&mut vm.heap, i64::MIN));
        let b = Value::small_int(-1).to_bits();
        let r = unsafe { al_shim_mod_int_val(vmp, a, b) };
        assert_eq!(r, Value::small_int(0).to_bits());

        // x / 0 == 0 and x % 0 == x even for a boxed x; the mod result is a
        // fresh box.
        let a = into_bits(Value::int_in(&mut vm.heap, i64::MAX));
        let b = Value::small_int(0).to_bits();
        let r = unsafe { al_shim_div_int_val(vmp, a, b) };
        assert_eq!(r, Value::small_int(0).to_bits());

        let a = into_bits(Value::int_in(&mut vm.heap, i64::MAX));
        let b = Value::small_int(0).to_bits();
        let r = unsafe { al_shim_mod_int_val(vmp, a, b) };
        assert!(is_bigint(r));
        assert_eq!(unbox_and_release(r), i64::MAX);
    }

    #[test]
    fn neg_wraps_at_i64_min_and_spills_at_the_asymmetric_edge() {
        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;

        // -SMALL_MIN == 2^47 does not fit the immediate range: spill.
        let a = Value::small_int(SMALL_MIN).to_bits();
        let r = unsafe { al_shim_neg_int_val(vmp, a) };
        assert!(is_bigint(r));
        assert_eq!(unbox_and_release(r), -SMALL_MIN);

        let a = into_bits(Value::int_in(&mut vm.heap, i64::MIN));
        let r = unsafe { al_shim_neg_int_val(vmp, a) };
        assert_eq!(unbox_and_release(r), i64::MIN);
    }

    #[test]
    fn enum_alloc_builds_an_interpreter_shaped_cell() {
        use std::sync::Arc;

        use crate::bytecode::value::take_freed_objects;
        use crate::frozen::FrozenArea;

        let mut vm = halt_test_vm();
        let vmp = &raw mut vm;

        // Frozen name/label constants, what the emitter bakes.
        let area = Arc::new(FrozenArea::new());
        let mut fb = area.builder();
        let en = fb.str("Shape").into_value();
        let vn = fb.str("Point").into_value();
        let labels = {
            let x = fb.str("x");
            let y = fb.str("y");
            fb.tuple(vec![x, y]).into_value()
        };

        let packed: u64 = 42u64 | (1u64 << 32);
        let a = Value::small_int(7).to_bits();
        // A boxed field proves the reference transfer.
        let b = into_bits(Value::int_in(&mut vm.heap, i64::MAX));
        let payload = [a, b];

        take_freed_objects();
        let bits = unsafe {
            al_shim_enum_alloc(
                vmp,
                packed,
                en.to_bits(),
                vn.to_bits(),
                labels.to_bits(),
                payload.as_ptr(),
                2,
            )
        };
        // Nothing freed: the transferred field references moved into the cell.
        assert_eq!(take_freed_objects(), 0);

        let v = unsafe { Value::from_bits(bits) };
        let e = v.as_enum().expect("shim must build an Enum cell");
        assert_eq!(e.type_id(), TypeId(42));
        assert_eq!(e.variant_idx(), 1);
        assert_eq!(e.enum_name(), "Shape");
        assert_eq!(e.variant_name(), "Point");
        assert_eq!(e.payload().len(), 2);
        assert_eq!(e.payload()[0].as_int(), Some(7));
        assert_eq!(e.payload()[1].as_int(), Some(i64::MAX));

        // The hash word is written 0 and computed on first use.
        assert_ne!(v.as_enum().unwrap().hash(), 0);

        drop(v);
        assert_eq!(take_freed_objects(), 2);
    }

    #[test]
    fn symbol_table_names_are_unique_and_addresses_non_null() {
        let syms = shim_symbols();
        for (i, (name, addr)) in syms.iter().enumerate() {
            assert!(!addr.is_null(), "{name} has a null address");
            assert!(
                syms[..i].iter().all(|(n, _)| n != name),
                "duplicate symbol {name}"
            );
        }
    }
}

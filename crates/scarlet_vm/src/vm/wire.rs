//! `scarlet/wire`: values as bytes, under a descriptor of the type the call
//! site was inferred at.
//!
//! Both halves live here. [`encode_value`] walks a value under a
//! [`WireDesc`](crate::wire::WireDesc) and writes the bytes
//! `scarlet/wire.scrl`'s module doc specifies, and [`VM::decode_wire`] reads
//! them back, treating every byte as hostile.
//!
//! The descriptor itself is program data and lives in [`crate::wire`]; each
//! instruction names one by index into
//! [`Program::wire_descs`](crate::bytecode::Program::wire_descs). The front end
//! builds it (`scarlet_core::typed_ir::wire`, which this crate may not depend
//! on) and converts on the way out.
//!
//! # Decoding refuses; encoding cannot
//!
//! Encode is total because the compiler proved the value matches the
//! descriptor. Decode has proved nothing: the bytes may be truncated, forged,
//! or written against a different version of the type. So every count is
//! checked against the input that remains before anything is allocated, every
//! string is UTF-8 validated, and every variant tag is range-checked — and the
//! two ways a decode can stop are kept apart by [`Stop`], because a refusal is
//! the peer's fault and an internal error is ours.
//!
//! What is already fixed here is the outcome vocabulary. `DecodeError`'s five
//! constructors are bound as [`AbiSlot`](crate::abi::AbiSlot)s, so the decoder
//! builds its refusals the same way every other stdlib error is built, and a
//! renamed constructor is a compile diagnostic rather than a mis-built value.
//!
//! # Why the descriptor is duplicated rather than shared
//!
//! `scarlet_core::typed_ir::wire::Desc` is the compiler's descriptor and cannot
//! cross the crate boundary: this crate must never depend on a language crate.
//! [`WireDesc`] is the runtime's own, and it deliberately carries **less** — no
//! type names, no constructor names, no field labels. The encoder needs
//! structure and nothing else, and a decoder rebuilds a variant through
//! `Program::wire_templates`, which is keyed on `(TypeId, variant_idx)` rather
//! than on any name. A name in here would be a second identity for a
//! constructor that already has one.
//!
//! # Nothing here recurses
//!
//! The value being encoded is unbounded — a 100k-element list of lists is an
//! ordinary Scarlet value — so a native frame per level is a stack overflow
//! reachable from user code. The walk carries its own work stack, the same rule
//! [`values_equal`](crate::bytecode::values_equal) and the JSON encoder already
//! follow. `wire_encode_deep_chain_is_iterative` below is what holds it.

use std::sync::Arc;

use crate::TypeId;
use crate::abi::AbiSlot;
use crate::bytecode::{MapBacking, Value, ValueView, hamt, hash_value};
use crate::wire::{WireDesc, WireNode, WireNodeIdx};

use super::map::env_entries;
use super::{VM, VmError, VmResult, bin_ref, range_len};

/// Format version, written as the third header byte and folded into every
/// fingerprint. `scarlet/wire.scrl`'s module doc is normative on why the two
/// move together: the fingerprint travels in every message, so an algorithm
/// change that left this alone would surface at a peer as a `SchemaMismatch`
/// on a type nobody had touched.
const VERSION: u8 = 1;

/// Leading bytes of every encoded value, so bytes from somewhere else are
/// `NotWire` rather than a misread.
const MAGIC: [u8; 2] = *b"SW";

/// `MAGIC` · `VERSION` · fingerprint u64.
const HEADER_LEN: usize = MAGIC.len() + 1 + 8;

/// Units of wire work that cost one reduction, where a unit is **one byte
/// moved or one node walked**.
///
/// Matched to [`FREES_PER_REDUCTION`](super::exec) at 256 rather than chosen
/// afresh: freeing one object, copying one byte and visiting one descriptor
/// node are the same order of cost, and the reclamation charge is already
/// tuned so that only work in the thousands touches a 4000-reduction budget.
///
/// **The charge is `max(bytes, nodes)`, and each half is there because the
/// other is blind to a real payload:**
///
/// - **Bytes alone under-charge a node-heavy value.** An `Array` whose element
///   type occupies zero bytes — `Nil`, or any single-constructor record whose
///   fields are all themselves zero-byte — is a count and nothing else, so
///   millions of nodes arrive as about four bytes. `MAX_ZERO_COST_ELEMS` caps
///   that at 2^24, which is 16.7 million nodes for a byte count near zero.
/// - **Nodes alone under-charge a byte-heavy value.** One `Binary` field is a
///   single node and an arbitrarily large `memcpy`.
///
/// `max` rather than the sum, because for an ordinary payload the two counts
/// are within a small factor of each other and adding them would double the
/// charge for no reason; the sum is only interesting where one term is
/// negligible, and there `max` already gives the other.
///
/// **THIS DOES NOT CLOSE THE STARVATION ROUTE, and must not be read as if it
/// did.** A wire op is one instruction, and the interpreter's preemption
/// checkpoints sit only at a function application — three sites, none of them
/// inside an op. Charging here cannot interrupt an encode in progress; it
/// makes the process yield at its *next* application instead of running a
/// further full slice, so a large payload stops being billed as though it were
/// idle. Interrupting one long encode needs either a size cap or a resumable
/// op that parks. That is T-766, and it is deliberately not this.
const WIRE_WORK_PER_REDUCTION: u64 = 256;

/// Charge `reds` for a wire call that moved `bytes` and walked `nodes`.
///
/// Saturating, and one call site for both ops so the two cannot drift apart.
fn charge_wire(reds: &mut i32, bytes: usize, nodes: u64) {
    let work = (bytes as u64).max(nodes);
    *reds = reds.saturating_sub((work / WIRE_WORK_PER_REDUCTION) as i32);
}

// --- primitives -----------------------------------------------------------

/// LEB128.
fn put_u64(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Zigzag + LEB128. `Int` is 64-bit, so every Scarlet integer fits.
fn put_i64(out: &mut Vec<u8>, v: i64) {
    put_u64(out, ((v << 1) ^ (v >> 63)) as u64);
}

/// `len LEB128 · UTF-8 bytes`.
fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u64(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

// --- the walk -------------------------------------------------------------

/// Encode `root` under `desc`, header included.
///
/// Total: every type that reaches here was accepted by the descriptor builder,
/// so there is no failure to report and no `Result` to unwrap. Where a value
/// could disagree with the descriptor the disagreement is a `debug_assert` and
/// not a runtime branch — the compiler proved they match, and paying for a
/// check per node in release would be paying for the proof twice. Each such
/// site still writes something defined, so a release build cannot produce a
/// truncated container whose count promises bytes that are not there.
///
/// Iterative: children go onto an explicit work stack, so nesting depth costs
/// heap rather than native frames.
fn encode_value(desc: &WireDesc, root: &Value) -> (Vec<u8>, u64) {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&desc.fingerprint().to_le_bytes());
    let nodes = write_body(&mut out, desc, root);
    (out, nodes)
}

/// The body half of [`encode_value`]: the value under `desc.root`, with no
/// header. Split out because the header is written once and the walk is the
/// part with an invariant worth naming.
fn write_body(out: &mut Vec<u8>, desc: &WireDesc, root: &Value) -> u64 {
    // A container pushes its children and they are popped before anything
    // queued beside it, so a 100k-deep chain costs O(1) entries here rather
    // than one per level. A 100k-wide container does cost one entry per
    // element — that is heap, which is the trade this exists to make.
    let mut pending: Vec<(WireNodeIdx, Value)> = vec![(desc.root(), root.clone())];
    // One per value visited, which is what the node half of the reduction
    // charge counts. Incremented before the arm so a `continue` still pays.
    let mut nodes: u64 = 0;

    while let Some((at, v)) = pending.pop() {
        nodes += 1;
        let Some(node) = desc.node(at) else {
            // Only an index from another descriptor reaches this, which the
            // builder cannot mint. Writing nothing keeps the walk total.
            debug_assert!(false, "wire descriptor node {} is out of range", at.0);
            continue;
        };
        match node {
            WireNode::Int => {
                debug_assert!(matches!(v.kind(), ValueView::Int(_)), "descriptor says Int");
                put_i64(out, v.as_int().unwrap_or(0));
            }
            WireNode::Float => {
                debug_assert!(
                    matches!(v.kind(), ValueView::Float(_)),
                    "descriptor says Float"
                );
                let f = match v.kind() {
                    ValueView::Float(f) => f,
                    _ => 0.0,
                };
                out.extend_from_slice(&f.to_bits().to_le_bytes());
            }
            WireNode::String => {
                debug_assert!(
                    matches!(v.kind(), ValueView::Str(_)),
                    "descriptor says String"
                );
                put_str(out, v.as_str().unwrap_or_default());
            }
            WireNode::Binary => match v.kind() {
                // `to_aligned_vec` is exactly the specified payload: the
                // trailing partial byte's spare low bits are masked to zero, so
                // two binaries with equal bits encode alike whatever backing
                // window they came from.
                ValueView::Binary(b) => {
                    put_u64(out, b.bit_len());
                    out.extend_from_slice(&b.to_aligned_vec());
                }
                _ => {
                    debug_assert!(false, "descriptor says Binary");
                    put_u64(out, 0);
                }
            },
            WireNode::Array(elem) => match v.kind() {
                ValueView::Array(arr) => {
                    let n = arr.len();
                    put_u64(out, n as u64);
                    // Back to front, so the stack pops in emission order.
                    for i in (0..n).rev() {
                        let Some(item) = arr.get(i) else {
                            // `get` is total below `len`; unreachable today,
                            // and it keeps the element count honest if that
                            // ever changes.
                            debug_assert!(false, "array element {i} below len is missing");
                            continue;
                        };
                        pending.push((*elem, item));
                    }
                }
                // A `Range` is an `Array(Int)` value with no elements stored.
                // Its elements are Ints by construction, with nothing under
                // them to nest, so they are written here rather than boxed one
                // at a time onto the work stack.
                ValueView::Range(s, e) => {
                    debug_assert!(
                        matches!(desc.node(*elem), Some(WireNode::Int)),
                        "a Range value needs an Array(Int) descriptor"
                    );
                    let n = range_len(s, e);
                    put_u64(out, n as u64);
                    for i in 0..n {
                        put_i64(out, s.wrapping_add(i));
                    }
                }
                _ => {
                    debug_assert!(false, "descriptor says Array");
                    put_u64(out, 0);
                }
            },
            WireNode::Map(key, val) => match v.kind() {
                ValueView::Map(m) => match m.backing() {
                    MapBacking::Hamt => {
                        let entries = hamt::collect_entries(&v);
                        put_u64(out, entries.len() as u64);
                        // Entry order is whatever the trie yields. It is
                        // deterministic for a given key set, and decode rebuilds
                        // through the ordinary insert path, so a round trip does
                        // not depend on it — but two maps that are `==` are not
                        // promised the same bytes.
                        for (k, val_v) in entries.into_iter().rev() {
                            pending.push((*val, val_v));
                            pending.push((*key, k));
                        }
                    }
                    // The process environment, typed `Map(String, String)`. It
                    // stores no `Value`s to walk, and both halves of an entry
                    // are scalars, so it is written in place.
                    MapBacking::Env => {
                        debug_assert!(
                            matches!(desc.node(*key), Some(WireNode::String))
                                && matches!(desc.node(*val), Some(WireNode::String)),
                            "an Env map is Map(String, String)"
                        );
                        let entries = env_entries();
                        put_u64(out, entries.len() as u64);
                        for (k, val_s) in entries {
                            put_str(out, &k);
                            put_str(out, &val_s);
                        }
                    }
                },
                _ => {
                    debug_assert!(false, "descriptor says Map");
                    put_u64(out, 0);
                }
            },
            // Arity is in the descriptor, so nothing is written for the tuple
            // itself. `zip` is what keeps this total if the two ever disagree:
            // it writes min(arity, payload) elements rather than indexing past
            // one of them.
            WireNode::Tuple(elems) => {
                let fields = v.as_tuple().unwrap_or_default();
                debug_assert_eq!(elems.len(), fields.len(), "descriptor fixes tuple arity");
                for (n, f) in elems.iter().zip(fields).rev() {
                    pending.push((*n, f.clone()));
                }
            }
            WireNode::Data(ctors) => {
                let Some(e) = v.as_enum() else {
                    debug_assert!(false, "descriptor says Data");
                    continue;
                };
                let tag = e.variant_idx() as usize;
                let Some(ctor) = ctors.get(tag) else {
                    debug_assert!(false, "variant {tag} is not in the descriptor");
                    continue;
                };
                debug_assert_eq!(ctor.type_id, e.type_id(), "descriptor names another type");
                debug_assert_eq!(
                    ctor.variant_idx as usize, tag,
                    "the tag is the declared index"
                );
                // Omitted entirely for a single-constructor type, so a record
                // costs only its fields and `Nil` costs zero bytes.
                if ctors.len() > 1 {
                    put_u64(out, tag as u64);
                }
                let payload = e.payload();
                debug_assert_eq!(ctor.fields.len(), payload.len(), "descriptor fixes arity");
                for (n, f) in ctor.fields.iter().zip(payload).rev() {
                    pending.push((*n, f.clone()));
                }
            }
        }
    }
    nodes
}

// --- decoding -------------------------------------------------------------

/// Why a decode refused, in the runtime's own vocabulary. Turned into a
/// Scarlet `DecodeError` by [`VM::wire_refusal`], which is the only thing here
/// that can reach the ABI.
///
/// Deliberately separate from [`Stop`]: a refusal is a statement about the
/// BYTES, and every arm of it is something a hostile or stale peer can
/// legitimately provoke.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    Truncated,
    NotWire,
    /// Both sides, so a log line can say which end changed. `expected` is the
    /// reader's own fingerprint, `found` is the one in the bytes.
    SchemaMismatch {
        expected: u64,
        found: u64,
    },
    Malformed {
        offset: usize,
        what: &'static str,
    },
    TrailingBytes {
        count: usize,
    },
}

/// What stopped a decode. The split is the point: a [`Refusal`] is the bytes'
/// fault and becomes an `Err(DecodeError)` the program can match on, while
/// `Internal` is this runtime's own — a descriptor naming a constructor the
/// program minted no template for — and becomes a VM error. Folding the second
/// into the first would report a compiler bug as hostile input, and the peer
/// that sent perfectly good bytes would get the blame.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stop {
    Refused(Refusal),
    Internal(&'static str),
}

impl From<Refusal> for Stop {
    fn from(r: Refusal) -> Stop {
        Stop::Refused(r)
    }
}

/// A cursor over untrusted bytes. Every read is bounds-checked and every
/// failure names an offset; nothing here can panic on a short or hostile
/// input.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        if n > self.remaining() {
            return Err(Refusal::Truncated);
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }

    /// LEB128. Refuses a varint that runs past ten groups or whose top group
    /// carries bits past 64 — an overlong encoding is a second spelling of a
    /// number the encoder never writes, and accepting it would make the format
    /// non-canonical.
    fn uleb(&mut self) -> Result<u64, Refusal> {
        let start = self.at;
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            let payload = u64::from(b & 0x7f);
            if shift == 63 && payload > 1 {
                return Err(Refusal::Malformed {
                    offset: start,
                    what: "varint does not fit in 64 bits",
                });
            }
            v |= payload << shift;
            if b & 0x80 == 0 {
                // The encoder emits the shortest form, so a non-zero
                // continuation that contributed nothing is a forgery.
                if shift > 0 && b == 0 {
                    return Err(Refusal::Malformed {
                        offset: start,
                        what: "overlong varint",
                    });
                }
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                return Err(Refusal::Malformed {
                    offset: start,
                    what: "varint does not fit in 64 bits",
                });
            }
        }
    }

    /// Zigzag + LEB128, the inverse of [`put_i64`].
    fn ileb(&mut self) -> Result<i64, Refusal> {
        let u = self.uleb()?;
        Ok(((u >> 1) as i64) ^ -((u & 1) as i64))
    }
}

/// A node whose values occupy zero bytes has exactly one inhabitant — it is an
/// empty tuple, or a one-constructor type all of whose fields are themselves
/// zero-byte — so a container of them is bounded by nothing in the input at
/// all: the count IS the whole encoding. `count * min <= remaining` is vacuous
/// there, and this is the one number in the decoder that is chosen rather than
/// derived from the input. 2^24 elements is 128 MiB of `Value` words, which no
/// program reaches by accident and a forged count reaches immediately.
///
/// Recorded rather than hidden: every OTHER count is bounded exactly, with no
/// policy number involved.
const MAX_ZERO_COST_ELEMS: u64 = 1 << 24;

/// The fewest bytes a value of each node can occupy, indexed as
/// [`WireDesc::nodes`] is.
///
/// This is what makes the count guard exact rather than a guess: an `Array`
/// claiming `n` elements needs at least `n * min_bytes(elem)` bytes after its
/// count, and anything more than that is refused before a single element is
/// allocated.
///
/// Computed as a fixed point from "unknown", because a recursive type's node
/// refers to itself: `List(Int)`'s `Cons.tail` is the `List(Int)` node, so a
/// single pass would need its own answer. Successive rounds shrink each entry
/// until nothing moves, which is at most one round per node.
fn min_bytes(desc: &WireDesc) -> Vec<u64> {
    // `u64::MAX` reads "not yet known", and every arm below saturates, so an
    // unknown never wraps into a small number and lets a count through.
    let mut min = vec![u64::MAX; desc.len()];
    let at = |m: &Vec<u64>, i: WireNodeIdx| -> u64 { *m.get(i.0 as usize).unwrap_or(&u64::MAX) };
    loop {
        let mut moved = false;
        for i in 0..desc.len() {
            let was = min[i];
            let Some(node) = desc.node(WireNodeIdx(i as u32)) else {
                continue;
            };
            let now = match node {
                // A zigzag LEB128 of 0, an empty string, an empty binary and
                // an empty container are all one byte.
                WireNode::Int | WireNode::String | WireNode::Binary => 1,
                WireNode::Array(_) | WireNode::Map(_, _) => 1,
                WireNode::Float => 8,
                WireNode::Tuple(elems) => elems
                    .iter()
                    .fold(0u64, |a, e| a.saturating_add(at(&min, *e))),
                WireNode::Data(ctors) => {
                    let tag = if ctors.len() > 1 { 1 } else { 0 };
                    let body = ctors
                        .iter()
                        .map(|c| {
                            c.fields
                                .iter()
                                .fold(0u64, |a, f| a.saturating_add(at(&min, *f)))
                        })
                        .min()
                        .unwrap_or(0);
                    body.saturating_add(tag)
                }
            };
            if now < was {
                min[i] = now;
                moved = true;
            }
        }
        if !moved {
            return min;
        }
    }
}

/// Refuse a count the remaining input cannot possibly satisfy, BEFORE anything
/// is allocated. This is the check that stands between a four-byte message
/// claiming a 2^40-element array and the allocator.
fn guard_count(
    count: u64,
    min_each: u64,
    remaining: usize,
    offset: usize,
) -> Result<usize, Refusal> {
    let need = count.saturating_mul(min_each);
    let fits = if min_each == 0 {
        count <= MAX_ZERO_COST_ELEMS
    } else {
        need <= remaining as u64
    };
    if !fits {
        return Err(Refusal::Malformed {
            offset,
            what: "count is larger than the remaining input can hold",
        });
    }
    Ok(count as usize)
}

/// One pending piece of decoder work.
enum Step {
    /// Read a value of this node from the input.
    Read(WireNodeIdx),
    /// Combine already-built values into one.
    Finish(Finish),
}

/// A container whose children are built and are waiting to be joined. The
/// child count is fixed when the container's count is read and guarded, so a
/// `Finish` can never ask for more values than the walk put there.
enum Finish {
    Array(usize),
    /// `n` key/value pairs, so `2 * n` values, plus the offset the count was
    /// read at so a duplicate-key refusal names a real byte.
    Map(usize, usize),
    Tuple(usize),
    Ctor {
        type_id: TypeId,
        variant_idx: u16,
        arity: usize,
    },
}

/// Take the last `n` finished values, in the order they were built.
fn take_last(done: &mut Vec<Value>, n: usize) -> Result<Vec<Value>, Stop> {
    if done.len() < n {
        // The count that sized this `Finish` is the same one that pushed the
        // reads, so this is unreachable by construction rather than by input.
        return Err(Stop::Internal("wire decoder finished a container short"));
    }
    Ok(done.split_off(done.len() - n))
}

/// Magic, version, fingerprint — the first eleven bytes, and the whole schema
/// check.
///
/// Order matters: magic and version are judged before the fingerprint, so
/// bytes from somewhere else are `NotWire` rather than a `SchemaMismatch`
/// against whatever their bytes 3..11 happen to spell. An input too short to
/// hold even the magic has nothing to judge and is `Truncated`.
fn read_header(r: &mut Reader<'_>, expected: u64) -> Result<(), Refusal> {
    if r.take(MAGIC.len())? != MAGIC {
        return Err(Refusal::NotWire);
    }
    if r.u8()? != VERSION {
        return Err(Refusal::NotWire);
    }
    let mut fp = [0u8; 8];
    fp.copy_from_slice(r.take(8)?);
    let found = u64::from_le_bytes(fp);
    if found != expected {
        return Err(Refusal::SchemaMismatch { expected, found });
    }
    Ok(())
}

impl VM {
    /// The Scarlet `DecodeError` a [`Refusal`] names. Built through the ABI,
    /// so a renamed constructor is a compile diagnostic rather than a
    /// mis-built value.
    fn wire_refusal(&mut self, r: Refusal) -> VmResult<Value> {
        match r {
            Refusal::Truncated => self.abi_nullary(AbiSlot::WireTruncated),
            Refusal::NotWire => self.abi_nullary(AbiSlot::WireNotWire),
            Refusal::SchemaMismatch { expected, found } => {
                // `DecodeError` carries these as `Int`, which is signed, so a
                // fingerprint above `i64::MAX` arrives negative. Both sides go
                // through the same reinterpretation, so the pair in one
                // message still tells a reader which end changed.
                let e = Value::int_in(&mut self.heap, expected as i64);
                let f = Value::int_in(&mut self.heap, found as i64);
                self.abi_make(AbiSlot::WireSchemaMismatch, &[e, f])
            }
            Refusal::Malformed { offset, what } => {
                let o = Value::int_in(&mut self.heap, offset as i64);
                let w = Value::str_in(&mut self.heap, what);
                self.abi_make(AbiSlot::WireMalformed, &[o, w])
            }
            Refusal::TrailingBytes { count } => {
                let c = Value::int_in(&mut self.heap, count as i64);
                self.abi_make(AbiSlot::WireTrailingBytes, &[c])
            }
        }
    }

    /// `bytes` at `desc`, as the `Result(a, DecodeError)` the op pushes.
    ///
    /// The only door: a decoded value is built here by the ordinary
    /// constructors — `EnumTemplate::instantiate`, `tuple_in`, `array_in`, the
    /// map insert path — so it is indistinguishable from a constructed one,
    /// and that plus the descriptor being the type is the whole type-safety
    /// argument. Nothing writes a field directly.
    fn decode_wire(&mut self, desc: &WireDesc, bytes: &[u8], reds: &mut i32) -> VmResult<Value> {
        // Charged whatever the outcome: a refusal has already walked whatever
        // the bytes claimed before finding them wanting, and a peer must not be
        // able to buy scheduler time by sending input that fails late.
        match self.decode_checked(desc, bytes, reds) {
            Ok(v) => self.make_ok(v),
            Err(Stop::Refused(r)) => {
                let e = self.wire_refusal(r)?;
                self.make_err(e)
            }
            // This runtime's own fault, not the peer's — see [`Stop`].
            Err(Stop::Internal(why)) => Err(VmError::internal(why)),
        }
    }

    fn decode_checked(
        &mut self,
        desc: &WireDesc,
        bytes: &[u8],
        reds: &mut i32,
    ) -> Result<Value, Stop> {
        // Every charge below is against `bytes.len()`, never `r.at`: the
        // caller (`wire_decode`) already paid an O(len) copy of the whole
        // input before this function runs, so that cost is owed however far
        // the parse gets — including a padded buffer whose parse succeeds on
        // a small prefix and only then refuses with `TrailingBytes`, which
        // `r.at` would bill as though the copy had never happened.
        let mut r = Reader::new(bytes);
        if let Err(e) = read_header(&mut r, desc.fingerprint()) {
            charge_wire(reds, bytes.len(), 0);
            return Err(e.into());
        }
        let mut nodes: u64 = 0;
        let out = self.decode_body(desc, &mut r, &mut nodes);
        // Both arms, identically: a refusal has already built whatever it got
        // through before finding the bytes wanting, and charging only the
        // successful path lets a peer buy scheduler time with input that fails
        // late. `nodes` is an out-parameter precisely so the error arm can see
        // it — charging a refusal by bytes alone would be blind to a
        // node-heavy payload in the same way the rejected bytes-only rule is.
        charge_wire(reds, bytes.len(), nodes);
        let v = out?;
        // Reported rather than ignored: a caller that framed its own messages
        // and has extra bytes left has lost sync, and silently returning the
        // value would hide that until the next message parsed as garbage.
        if r.remaining() > 0 {
            return Err(Refusal::TrailingBytes {
                count: r.remaining(),
            }
            .into());
        }
        Ok(v)
    }

    /// Build the value under `desc.root` from `r`.
    ///
    /// Iterative for the same reason the encoder is: the value is unbounded,
    /// so a native frame per level is a stack overflow reachable from any peer
    /// that sends a long list. `work` carries the walk and `done` carries the
    /// values built so far; a container pushes its `Finish` first and its
    /// children after, so the children are popped and built before the parent
    /// that joins them.
    fn decode_body(
        &mut self,
        desc: &WireDesc,
        r: &mut Reader<'_>,
        nodes: &mut u64,
    ) -> Result<Value, Stop> {
        let mins = min_bytes(desc);
        let min_at = |i: WireNodeIdx| -> Result<u64, Stop> {
            mins.get(i.0 as usize)
                .copied()
                .ok_or(Stop::Internal("wire descriptor node index out of range"))
        };

        let mut work: Vec<Step> = vec![Step::Read(desc.root())];
        let mut done: Vec<Value> = Vec::new();

        while let Some(step) = work.pop() {
            match step {
                Step::Read(at) => {
                    // One per value built — the `Read` steps, not the `Finish`
                    // joins: a join is bounded by children already paid for.
                    *nodes += 1;
                    let Some(node) = desc.node(at) else {
                        return Err(Stop::Internal("wire descriptor node index out of range"));
                    };
                    match node {
                        WireNode::Int => {
                            let n = r.ileb()?;
                            let v = Value::int_in(&mut self.heap, n);
                            done.push(v);
                        }
                        WireNode::Float => {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(r.take(8)?);
                            // `Value::float` is what maps a non-finite reading
                            // to 0.0 — the VM never holds NaN/Inf and a real
                            // NaN's bits collide with the tag space. Decode
                            // inherits that rather than repeating it.
                            done.push(Value::float(f64::from_le_bytes(b)));
                        }
                        WireNode::String => {
                            let off = r.at;
                            let n = r.uleb()?;
                            let n = guard_count(n, 1, r.remaining(), off)?;
                            let bytes = r.take(n)?;
                            let Ok(s) = std::str::from_utf8(bytes) else {
                                return Err(Refusal::Malformed {
                                    offset: off,
                                    what: "string is not UTF-8",
                                }
                                .into());
                            };
                            let v = Value::str_in(&mut self.heap, s);
                            done.push(v);
                        }
                        WireNode::Binary => {
                            let off = r.at;
                            let bit_len = r.uleb()?;
                            let n = guard_count(bit_len.div_ceil(8), 1, r.remaining(), off)?;
                            let mut buf = r.take(n)?.to_vec();
                            // The spare low bits of the trailing byte are not
                            // part of the value. Encode writes them as zero;
                            // masking here keeps one value to one encoding
                            // rather than trusting a peer to have done it. A
                            // whole-byte binary shifts by nothing, so the mask
                            // is 0xff and this costs a no-op rather than a
                            // branch.
                            let spare = (n as u64 * 8) - bit_len;
                            if let Some(last) = buf.last_mut() {
                                *last &= !0u8 << spare;
                            }
                            let v = Value::binary_bits_in(&mut self.heap, buf, bit_len);
                            done.push(v);
                        }
                        WireNode::Array(elem) => {
                            let off = r.at;
                            let n = r.uleb()?;
                            let n = guard_count(n, min_at(*elem)?, r.remaining(), off)?;
                            work.push(Step::Finish(Finish::Array(n)));
                            for _ in 0..n {
                                work.push(Step::Read(*elem));
                            }
                        }
                        WireNode::Map(key, val) => {
                            let off = r.at;
                            let n = r.uleb()?;
                            let each = min_at(*key)?.saturating_add(min_at(*val)?);
                            let n = guard_count(n, each, r.remaining(), off)?;
                            work.push(Step::Finish(Finish::Map(n, off)));
                            // Pushed as (value, key) pairs, so each key pops
                            // before its own value and `done` ends up
                            // k0 v0 k1 v1 …
                            for _ in 0..n {
                                work.push(Step::Read(*val));
                                work.push(Step::Read(*key));
                            }
                        }
                        WireNode::Tuple(elems) => {
                            work.push(Step::Finish(Finish::Tuple(elems.len())));
                            for e in elems.iter().rev() {
                                work.push(Step::Read(*e));
                            }
                        }
                        WireNode::Data(ctors) => {
                            let off = r.at;
                            // Omitted entirely for a one-constructor type, so
                            // there is nothing to read and nothing to check.
                            let tag = if ctors.len() > 1 {
                                usize::try_from(r.uleb()?).unwrap_or(usize::MAX)
                            } else {
                                0
                            };
                            let Some(c) = ctors.get(tag) else {
                                return Err(Refusal::Malformed {
                                    offset: off,
                                    what: "variant tag out of range",
                                }
                                .into());
                            };
                            work.push(Step::Finish(Finish::Ctor {
                                type_id: c.type_id,
                                variant_idx: c.variant_idx,
                                arity: c.fields.len(),
                            }));
                            for f in c.fields.iter().rev() {
                                work.push(Step::Read(*f));
                            }
                        }
                    }
                }
                Step::Finish(f) => match f {
                    Finish::Array(n) => {
                        let items = take_last(&mut done, n)?;
                        let v = Value::array_in(&mut self.heap, &items);
                        done.push(v);
                    }
                    Finish::Tuple(n) => {
                        let items = take_last(&mut done, n)?;
                        let v = Value::tuple_in(&mut self.heap, &items);
                        done.push(v);
                    }
                    Finish::Map(n, off) => {
                        let items = take_last(&mut done, 2 * n)?;
                        let mut m = hamt::empty(&mut self.heap);
                        for (i, pair) in items.chunks_exact(2).enumerate() {
                            let (k, v) = (pair[0].clone(), pair[1].clone());
                            let h = hash_value(&k);
                            m = hamt::insert(&mut self.heap, m, k, v, h);
                            // An insert that did not grow the map overwrote an
                            // existing binding. Encode never writes a duplicate
                            // key, so the input is claiming a map it did not
                            // get from encode — and silently keeping the last
                            // one would return a map shorter than its own count.
                            if hamt::size(&m) != i + 1 {
                                return Err(Refusal::Malformed {
                                    offset: off,
                                    what: "duplicate map key",
                                }
                                .into());
                            }
                        }
                        done.push(m);
                    }
                    Finish::Ctor {
                        type_id,
                        variant_idx,
                        arity,
                    } => {
                        let payload = take_last(&mut done, arity)?;
                        let Some(&idx) = self.program.wire_templates.get(&(type_id, variant_idx))
                        else {
                            return Err(Stop::Internal(
                                "the descriptor names a constructor this program minted no wire template for",
                            ));
                        };
                        let Some(t) = self.program.templates.get(idx).cloned() else {
                            return Err(Stop::Internal("a wire template index is out of range"));
                        };
                        let v = t.instantiate(&mut self.heap, &payload);
                        done.push(v);
                    }
                },
            }
        }

        match done.pop() {
            Some(v) if done.is_empty() => Ok(v),
            _ => Err(Stop::Internal(
                "wire decoder ended with the wrong value count",
            )),
        }
    }
}

impl VM {
    /// The descriptor an instruction's operand names.
    ///
    /// `Arc`-held, so this is a refcount bump rather than a copy of the node
    /// table — and, more to the point, it ends the borrow of `self.program`
    /// before the walk needs `self.heap`.
    ///
    /// A missing index is this runtime's own fault, never a program's: emit
    /// writes the operand from the same list it fills the table from.
    fn wire_desc(&self, operand: i32, op: &'static str) -> VmResult<Arc<WireDesc>> {
        usize::try_from(operand)
            .ok()
            .and_then(|i| self.program.wire_descs.get(i).cloned())
            .ok_or_else(|| {
                VmError::internal(format!(
                    "{op} names wire descriptor {operand}, which is not in the program"
                ))
            })
    }

    /// `Op::WireEncode` — `[value] -> Binary`.
    pub(super) fn wire_encode(&mut self, operand: i32, reds: &mut i32) -> VmResult<()> {
        let desc = self.wire_desc(operand, "wire.encode")?;
        let v = self.pop()?;
        let (bytes, nodes) = encode_value(&desc, &v);
        charge_wire(reds, bytes.len(), nodes);
        let out = Value::binary_in(&mut self.heap, bytes);
        self.stack.push(out);
        Ok(())
    }

    /// `Op::WireDecode` — `[bytes Binary] -> Result(a, DecodeError)`.
    pub(super) fn wire_decode(&mut self, operand: i32, reds: &mut i32) -> VmResult<()> {
        let desc = self.wire_desc(operand, "wire.decode")?;
        let src = self.pop_binary("wire.decode")?;
        // Own the bytes: the walk allocates into the same heap the borrow
        // would be pinned to.
        let bytes = bin_ref(&src).full_bytes().into_owned();
        let out = self.decode_wire(&desc, &bytes, reds)?;
        self.stack.push(out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Two things are witnessed here: that the bytes match `wire.scrl`'s format
    //! table row by row, and that the walk is iterative. Nothing witnesses the
    //! op — it has no descriptor operand — nor decoding, which does not exist.

    use super::super::halt_test_vm;
    use super::*;

    /// The bytes only. Shadows [`super::encode_value`], which also reports the
    /// nodes it walked for the reduction charge; every byte-format test below
    /// wants the first half and none of them wants the second.
    fn encode_value(desc: &WireDesc, root: &Value) -> Vec<u8> {
        super::encode_value(desc, root).0
    }

    /// Reductions spent by one `wire.encode` through the op, budget-in minus
    /// budget-out. Goes through `wire_encode` rather than `charge_wire` so a
    /// charge that is computed and then not applied cannot pass.
    fn encode_cost(vm: &mut VM, d: WireDesc, v: Value) -> i32 {
        vm.program.wire_descs.push(Arc::new(d));
        let operand = (vm.program.wire_descs.len() - 1) as i32;
        vm.stack.push(v);
        let mut reds = 1_000_000i32;
        vm.wire_encode(operand, &mut reds).expect("encode runs");
        vm.stack.pop();
        1_000_000 - reds
    }
    // Only the tests build a constructor by hand; the walks match on one.
    use crate::bytecode::values_equal;
    use crate::template::EnumTemplate;
    use crate::wire::WireCtor;

    fn variant_of(v: &Value) -> String {
        v.as_enum()
            .expect("an ABI slot builds an enum")
            .variant_name()
            .to_string()
    }

    fn payload(v: &Value) -> Vec<Value> {
        v.as_enum()
            .expect("an ABI slot builds an enum")
            .payload()
            .to_vec()
    }

    /// A descriptor over `nodes` rooted at node 0, with a fingerprint the
    /// tests can recognise in the header.
    fn desc(nodes: Vec<WireNode>) -> WireDesc {
        WireDesc::new(nodes, WireNodeIdx(0), 0x0807_0605_0403_0201)
    }

    /// The eleven header bytes every value carries: `SW`, version, then the
    /// fingerprint little-endian.
    fn header() -> Vec<u8> {
        let mut h = vec![b'S', b'W', 1];
        h.extend_from_slice(&0x0807_0605_0403_0201u64.to_le_bytes());
        h
    }

    /// Body only, so a row of the format table can be read without eleven
    /// bytes of preamble in front of it.
    fn body(d: &WireDesc, v: &Value) -> Vec<u8> {
        let all = encode_value(d, v);
        assert_eq!(all[..HEADER_LEN], header()[..], "header is fixed");
        all[HEADER_LEN..].to_vec()
    }

    #[test]
    fn the_header_is_magic_version_and_fingerprint() {
        let d = desc(vec![WireNode::Int]);
        let out = encode_value(&d, &Value::small_int(0));
        assert_eq!(HEADER_LEN, 11);
        assert_eq!(out[..HEADER_LEN], header()[..]);
        // Zigzag of 0 is one byte.
        assert_eq!(out.len(), HEADER_LEN + 1);
    }

    #[test]
    fn int_is_zigzag_leb128() {
        let d = desc(vec![WireNode::Int]);
        let case = |n: i64| body(&d, &Value::small_int(n));
        assert_eq!(case(0), vec![0x00]);
        assert_eq!(case(-1), vec![0x01]);
        assert_eq!(case(1), vec![0x02]);
        assert_eq!(case(-2), vec![0x03]);
        assert_eq!(case(63), vec![0x7e]);
        assert_eq!(case(64), vec![0x80, 0x01]);
    }

    /// The extremes exist as boxed `BigInt`s rather than small ints, and the
    /// format promises they fit: ten LEB128 groups carry 70 bits, so the
    /// zigzag of a 64-bit value never overflows the encoding.
    #[test]
    fn int_covers_the_whole_i64_range() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);
        let max = Value::int_in(&mut vm.heap, i64::MAX);
        let min = Value::int_in(&mut vm.heap, i64::MIN);
        assert_eq!(
            body(&d, &max),
            vec![0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
        assert_eq!(
            body(&d, &min),
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    #[test]
    fn float_is_eight_bytes_of_f64_bits() {
        let d = desc(vec![WireNode::Float]);
        assert_eq!(body(&d, &Value::float(1.0)), 1.0f64.to_bits().to_le_bytes());
        assert_eq!(
            body(&d, &Value::float(-0.5)),
            (-0.5f64).to_bits().to_le_bytes()
        );
    }

    #[test]
    fn string_is_length_then_utf8() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::String]);
        let empty = Value::str_in(&mut vm.heap, "");
        assert_eq!(body(&d, &empty), vec![0x00]);
        let hi = Value::str_in(&mut vm.heap, "hi");
        assert_eq!(body(&d, &hi), vec![0x02, b'h', b'i']);
        // Length is bytes, not characters: a length in characters would make a
        // decoder read past the end of every non-ASCII string.
        let two_chars = Value::str_in(&mut vm.heap, "é€");
        assert_eq!(
            body(&d, &two_chars),
            vec![0x05, 0xc3, 0xa9, 0xe2, 0x82, 0xac]
        );
    }

    #[test]
    fn binary_is_bit_length_then_ceil_bytes() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Binary]);
        let whole = Value::binary_in(&mut vm.heap, vec![0xde, 0xad]);
        assert_eq!(body(&d, &whole), vec![16, 0xde, 0xad]);
        let empty = Value::binary_in(&mut vm.heap, Vec::new());
        assert_eq!(body(&d, &empty), vec![0]);
    }

    /// The row's parenthesis — "bit-level binaries round-trip" — is the whole
    /// reason `bit_len` is written rather than a byte count. The spare low bits
    /// of the trailing byte are masked, so the bytes depend on the value's bits
    /// and not on the buffer it was cut from.
    #[test]
    fn binary_carries_its_bit_length_and_masks_the_partial_byte() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Binary]);
        let twelve = Value::binary_bits_in(&mut vm.heap, vec![0xab, 0xcf], 12);
        // ceil(12/8) = 2 bytes, and the four spare bits are zero, not 0xf.
        assert_eq!(body(&d, &twelve), vec![12, 0xab, 0xc0]);
    }

    #[test]
    fn array_is_count_then_elements() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        let items = [Value::small_int(1), Value::small_int(2)];
        let arr = Value::array_in(&mut vm.heap, &items);
        assert_eq!(body(&d, &arr), vec![2, 0x02, 0x04]);
        let empty = Value::array_in(&mut vm.heap, &[]);
        assert_eq!(body(&d, &empty), vec![0]);
    }

    /// A `Range` is an `Array(Int)` whose elements are never stored, and it
    /// must produce the same bytes as the array it equals — otherwise
    /// `0..3` and `[0, 1, 2]` are the same Scarlet value with two encodings.
    #[test]
    fn a_range_encodes_as_the_array_it_equals() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        let range = Value::range_in(&mut vm.heap, 0, 3);
        let items = [
            Value::small_int(0),
            Value::small_int(1),
            Value::small_int(2),
        ];
        let arr = Value::array_in(&mut vm.heap, &items);
        assert_eq!(body(&d, &range), body(&d, &arr));
        assert_eq!(body(&d, &range), vec![3, 0x00, 0x02, 0x04]);
    }

    #[test]
    fn tuple_writes_its_elements_and_no_arity() {
        let mut vm = halt_test_vm();
        let d = desc(vec![
            WireNode::Tuple(vec![WireNodeIdx(1), WireNodeIdx(2)]),
            WireNode::Int,
            WireNode::String,
        ]);
        let s = Value::str_in(&mut vm.heap, "a");
        let t = Value::tuple_in(&mut vm.heap, &[Value::small_int(7), s]);
        assert_eq!(body(&d, &t), vec![0x0e, 0x01, b'a']);
    }

    #[test]
    fn map_is_count_then_key_value_pairs() {
        let mut vm = halt_test_vm();
        let d = desc(vec![
            WireNode::Map(WireNodeIdx(1), WireNodeIdx(2)),
            WireNode::String,
            WireNode::Int,
        ]);
        let empty = hamt::empty(&mut vm.heap);
        assert_eq!(body(&d, &empty), vec![0]);

        let k = Value::str_in(&mut vm.heap, "k");
        let kh = hash_value(&k);
        let one = hamt::insert(&mut vm.heap, empty, k, Value::small_int(9), kh);
        assert_eq!(body(&d, &one), vec![1, 0x01, b'k', 0x12]);
    }

    /// The single-constructor case: no tag, so a record costs only its fields
    /// and a nullary constructor costs nothing at all.
    #[test]
    fn a_one_variant_type_writes_no_tag() {
        let mut vm = halt_test_vm();
        let nil = desc(vec![WireNode::Data(vec![WireCtor {
            type_id: TypeId(3),
            variant_idx: 0,
            fields: Vec::new(),
        }])]);
        let v = Value::enum_with_names_in(&mut vm.heap, TypeId(3), 0, "Unit", "Unit", &[], &[]);
        assert_eq!(body(&nil, &v), Vec::<u8>::new());

        let rec = desc(vec![
            WireNode::Data(vec![WireCtor {
                type_id: TypeId(4),
                variant_idx: 0,
                fields: vec![WireNodeIdx(1)],
            }]),
            WireNode::Int,
        ]);
        let r = Value::enum_with_names_in(
            &mut vm.heap,
            TypeId(4),
            0,
            "Wrapper",
            "Wrapper",
            &["n"],
            &[Value::small_int(5)],
        );
        assert_eq!(body(&rec, &r), vec![0x0a]);
    }

    /// Issue #35's worked example, byte for byte.
    ///
    /// ```scarlet
    /// type Event {
    ///     Joined(user String, at Int)
    ///     Said(user String, text String, tags Array(String))
    /// }
    /// ```
    ///
    /// `Event` has two constructors, so `Said` carries its tag. The issue's own
    /// arithmetic for this example is wrong twice over — it spells the body
    /// `3 ali 2 hi 1 1 a`, which omits the tag and is 10 bytes, and then calls
    /// it 12. Under the format table it is 11: `1 3 ali 2 hi 1 1 a`. The header
    /// is 11 as the issue says.
    #[test]
    fn the_said_example_from_issue_35() {
        let mut vm = halt_test_vm();
        let d = desc(vec![
            WireNode::Data(vec![
                WireCtor {
                    type_id: TypeId(9),
                    variant_idx: 0,
                    fields: vec![WireNodeIdx(1), WireNodeIdx(2)],
                },
                WireCtor {
                    type_id: TypeId(9),
                    variant_idx: 1,
                    fields: vec![WireNodeIdx(1), WireNodeIdx(1), WireNodeIdx(3)],
                },
            ]),
            WireNode::String,
            WireNode::Int,
            WireNode::Array(WireNodeIdx(1)),
        ]);

        let ali = Value::str_in(&mut vm.heap, "ali");
        let hi = Value::str_in(&mut vm.heap, "hi");
        let a = Value::str_in(&mut vm.heap, "a");
        let tags = Value::array_in(&mut vm.heap, &[a]);
        let said = Value::enum_with_names_in(
            &mut vm.heap,
            TypeId(9),
            1,
            "Event",
            "Said",
            &["user", "text", "tags"],
            &[ali, hi, tags],
        );

        let out = encode_value(&d, &said);
        assert_eq!(
            out[HEADER_LEN..],
            [1, 3, b'a', b'l', b'i', 2, b'h', b'i', 1, 1, b'a'],
            "tag, then user, text and tags in declared order"
        );
        assert_eq!(HEADER_LEN, 11, "11 bytes of header, as issue #35 says");
        assert_eq!(
            out.len() - HEADER_LEN,
            11,
            "11 bytes of body, NOT the 12 issue #35 and T-338 both state"
        );
    }

    /// The walk must not put a native frame on the stack per level. Built at
    /// the depth `values_equal`'s own guard uses, which is the depth a
    /// recursive implementation was measured to overflow at.
    ///
    /// It witnesses the encoder only: `wire_encode` never runs it, because the
    /// op has no descriptor.
    #[test]
    fn wire_encode_deep_chain_is_iterative() {
        let mut vm = halt_test_vm();
        // `List(Int)`: Nil, then Cons(head Int, tail List(Int)) — `tail` is the
        // index of the node it sits in, which is what makes the table finite.
        let d = desc(vec![
            WireNode::Data(vec![
                WireCtor {
                    type_id: TypeId(7),
                    variant_idx: 0,
                    fields: Vec::new(),
                },
                WireCtor {
                    type_id: TypeId(7),
                    variant_idx: 1,
                    fields: vec![WireNodeIdx(1), WireNodeIdx(0)],
                },
            ]),
            WireNode::Int,
        ]);

        const DEPTH: i64 = 100_000;
        let mut v = Value::enum_with_names_in(&mut vm.heap, TypeId(7), 0, "List", "Nil", &[], &[]);
        for _ in 0..DEPTH {
            v = Value::enum_with_names_in(
                &mut vm.heap,
                TypeId(7),
                1,
                "List",
                "Cons",
                &["head", "tail"],
                &[Value::small_int(1), v],
            );
        }

        let out = encode_value(&d, &v);
        // Every level is `tag 1` + `zigzag 1`, and the innermost Nil is `tag 0`.
        assert_eq!(out.len(), HEADER_LEN + (DEPTH as usize * 2) + 1);
        assert_eq!(out[HEADER_LEN..HEADER_LEN + 2], [1, 2]);
        assert_eq!(out[out.len() - 1], 0);
    }

    /// 100k siblings rather than 100k levels: the count is written once and
    /// every element follows it.
    ///
    /// This does NOT witness that the walk is iterative, and was named as
    /// though it did until a recursive plant left it green — a wide array is a
    /// loop in either implementation, so only
    /// `wire_encode_deep_chain_is_iterative` above can go red for that reason.
    /// What it does witness is that a container far past the work stack's
    /// inline capacity still writes count-then-elements in order.
    #[test]
    fn a_wide_array_writes_its_count_then_every_element() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        let items: Vec<Value> = (0..100_000i64).map(Value::small_int).collect();
        let arr = Value::array_in(&mut vm.heap, &items);
        let out = encode_value(&d, &arr);
        // Count is 100_000, which is three LEB128 bytes.
        assert_eq!(out[HEADER_LEN..HEADER_LEN + 3], [0xa0, 0x8d, 0x06]);
        assert_eq!(out[HEADER_LEN + 3], 0, "the first element is zigzag(0)");
    }

    #[test]
    fn the_vm_builds_every_decode_error_through_the_abi() {
        let mut vm = halt_test_vm();

        let truncated = vm.abi_nullary(AbiSlot::WireTruncated).expect("bound");
        assert_eq!(variant_of(&truncated), "Truncated");
        assert!(payload(&truncated).is_empty());

        let not_wire = vm.abi_nullary(AbiSlot::WireNotWire).expect("bound");
        assert_eq!(variant_of(&not_wire), "NotWire");
        assert!(payload(&not_wire).is_empty());

        let mismatch = vm
            .abi_make(
                AbiSlot::WireSchemaMismatch,
                &[Value::small_int(11), Value::small_int(22)],
            )
            .expect("bound");
        assert_eq!(variant_of(&mismatch), "SchemaMismatch");
        assert_eq!(
            payload(&mismatch)
                .iter()
                .map(|v| v.as_int().expect("Int payload"))
                .collect::<Vec<_>>(),
            vec![11, 22],
            "payload order is normative: expected then found"
        );

        let what = Value::str_in(&mut vm.heap, "variant tag out of range");
        let malformed = vm
            .abi_make(AbiSlot::WireMalformed, &[Value::small_int(7), what])
            .expect("bound");
        assert_eq!(variant_of(&malformed), "Malformed");
        let m = payload(&malformed);
        assert_eq!(m[0].as_int().expect("Int payload"), 7);
        assert_eq!(
            m[1].as_str().expect("Str payload"),
            "variant tag out of range"
        );

        let trailing = vm
            .abi_make(AbiSlot::WireTrailingBytes, &[Value::small_int(3)])
            .expect("bound");
        assert_eq!(variant_of(&trailing), "TrailingBytes");
        assert_eq!(payload(&trailing)[0].as_int().expect("Int payload"), 3);
    }

    /// The whole path, through the ops rather than through the walks: a
    /// descriptor in `Program.wire_descs`, an instruction operand naming it,
    /// a value on the stack, bytes back, and the value again.
    ///
    /// This is what the unit tests above could not witness while the operand
    /// did not exist — every one of them calls `encode_value`/`decode_wire`
    /// directly, so all of them would still pass with both op bodies trapping.
    #[test]
    fn the_ops_round_trip_through_their_operand() {
        let mut vm = list_vm();
        let d = list_desc();
        vm.program.wire_descs.push(Arc::new(d));
        let operand = 0i32;

        let nil = Value::enum_with_names_in(&mut vm.heap, TypeId(7), 0, "List", "Nil", &[], &[]);
        let one = Value::enum_with_names_in(
            &mut vm.heap,
            TypeId(7),
            1,
            "List",
            "Cons",
            &["head", "tail"],
            &[Value::small_int(5), nil],
        );

        vm.stack.push(one.clone());
        vm.wire_encode(operand, &mut 1_000_000)
            .expect("encode runs");
        let bytes = vm.stack.pop().expect("encode left a Binary");
        assert!(matches!(bytes.kind(), ValueView::Binary(_)));

        vm.stack.push(bytes);
        vm.wire_decode(operand, &mut 1_000_000)
            .expect("decode runs");
        let res = vm.stack.pop().expect("decode left a Result");
        let e = res.as_enum().expect("Result");
        assert_eq!(e.variant_name(), "Ok");
        assert!(values_equal(&one, &e.payload()[0]));
    }

    /// An operand naming no descriptor is this runtime's fault, not a
    /// program's, so it is a VM error rather than a decode refusal.
    #[test]
    fn an_operand_with_no_descriptor_is_a_vm_error() {
        let mut vm = halt_test_vm();
        assert!(vm.program.wire_descs.is_empty());
        vm.stack.push(Value::small_int(1));
        assert!(vm.wire_encode(0, &mut 1_000_000).is_err());
        assert!(vm.wire_encode(-1, &mut 1_000_000).is_err());
    }

    // --- decoding ---------------------------------------------------------

    /// A VM that can build the constructors a descriptor names.
    ///
    /// This is by hand what `Compiler::mint_wire_templates` does for a real
    /// program: one `EnumTemplate` per constructor identity, recorded under
    /// `(TypeId, variant_idx)`. Building them the same way is what makes the
    /// "indistinguishable from a constructed one" claim testable at all.
    fn vm_with_ctors(specs: &[(TypeId, u16, &str, &str, &[&str])]) -> VM {
        let mut vm = halt_test_vm();
        for (tid, vi, tn, vn, labels) in specs {
            let t = EnumTemplate::build(&mut vm.frozen, *tid, *vi, tn, vn, labels);
            let idx = vm.program.templates.push(t);
            vm.program.wire_templates.insert((*tid, *vi), idx);
        }
        vm
    }

    /// The payload of `Ok`, or a panic naming what came back instead.
    fn ok_of(vm: &mut VM, d: &WireDesc, bytes: &[u8]) -> Value {
        let v = vm
            .decode_wire(d, bytes, &mut 1_000_000)
            .expect("decode reached the ABI");
        let e = v.as_enum().expect("decode returns a Result");
        assert_eq!(e.variant_name(), "Ok", "expected Ok, got {:?}", e.payload());
        e.payload()[0].clone()
    }

    /// The `DecodeError` constructor name and its payload.
    fn refusal_of(vm: &mut VM, d: &WireDesc, bytes: &[u8]) -> (String, Vec<Value>) {
        let v = vm
            .decode_wire(d, bytes, &mut 1_000_000)
            .expect("decode reached the ABI");
        let e = v.as_enum().expect("decode returns a Result");
        assert_eq!(e.variant_name(), "Err", "expected Err, got Ok");
        let inner = e.payload()[0].clone();
        let ie = inner.as_enum().expect("DecodeError is an enum");
        (ie.variant_name().to_string(), ie.payload().to_vec())
    }

    /// Encode then decode, and assert the value survived. `values_equal` is
    /// Scarlet's own `==`, so this asserts what a program would observe rather
    /// than that two heap graphs happen to match.
    fn round_trips(vm: &mut VM, d: &WireDesc, v: &Value) {
        let bytes = encode_value(d, v);
        let back = ok_of(vm, d, &bytes);
        assert!(
            values_equal(v, &back),
            "round trip changed the value; bytes were {bytes:?}"
        );
    }

    #[test]
    fn scalars_round_trip() {
        let mut vm = halt_test_vm();

        let ints = desc(vec![WireNode::Int]);
        for n in [0i64, 1, -1, 63, 64, -64, i64::MAX, i64::MIN] {
            let v = Value::int_in(&mut vm.heap, n);
            round_trips(&mut vm, &ints, &v);
        }

        let floats = desc(vec![WireNode::Float]);
        for f in [0.0f64, 1.0, -0.5, f64::MAX, f64::MIN_POSITIVE] {
            round_trips(&mut vm, &floats, &Value::float(f));
        }

        let strings = desc(vec![WireNode::String]);
        for s in ["", "hi", "é€", "a longer string with spaces"] {
            let v = Value::str_in(&mut vm.heap, s);
            round_trips(&mut vm, &strings, &v);
        }
    }

    /// Including the bit-level case, which is the whole reason `bit_len` is on
    /// the wire rather than a byte count.
    #[test]
    fn binaries_round_trip_including_a_partial_trailing_byte() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Binary]);

        let empty = Value::binary_in(&mut vm.heap, Vec::new());
        round_trips(&mut vm, &d, &empty);
        let whole = Value::binary_in(&mut vm.heap, vec![0xde, 0xad, 0xbe, 0xef]);
        round_trips(&mut vm, &d, &whole);

        let twelve = Value::binary_bits_in(&mut vm.heap, vec![0xab, 0xc0], 12);
        let bytes = encode_value(&d, &twelve);
        let back = ok_of(&mut vm, &d, &bytes);
        let b = match back.kind() {
            ValueView::Binary(b) => b,
            _ => panic!("expected a Binary"),
        };
        assert_eq!(b.bit_len(), 12, "bit length survives, not just the bytes");
        assert!(values_equal(&twelve, &back));
    }

    #[test]
    fn containers_round_trip() {
        let mut vm = halt_test_vm();

        let arr = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        let empty = Value::array_in(&mut vm.heap, &[]);
        round_trips(&mut vm, &arr, &empty);
        let items = [
            Value::small_int(1),
            Value::small_int(-2),
            Value::small_int(3),
        ];
        let three = Value::array_in(&mut vm.heap, &items);
        round_trips(&mut vm, &arr, &three);

        let tup = desc(vec![
            WireNode::Tuple(vec![WireNodeIdx(1), WireNodeIdx(2)]),
            WireNode::Int,
            WireNode::String,
        ]);
        let s = Value::str_in(&mut vm.heap, "a");
        let t = Value::tuple_in(&mut vm.heap, &[Value::small_int(7), s]);
        round_trips(&mut vm, &tup, &t);

        let map = desc(vec![
            WireNode::Map(WireNodeIdx(1), WireNodeIdx(2)),
            WireNode::String,
            WireNode::Int,
        ]);
        let mut m = hamt::empty(&mut vm.heap);
        round_trips(&mut vm, &map, &m);
        for (k, n) in [("one", 1i64), ("two", 2), ("three", 3)] {
            let kv = Value::str_in(&mut vm.heap, k);
            let h = hash_value(&kv);
            m = hamt::insert(&mut vm.heap, m, kv, Value::small_int(n), h);
        }
        round_trips(&mut vm, &map, &m);
    }

    /// A `Range` and the `Array` it equals encode alike, so both decode to the
    /// same value — decode has no Range to rebuild and does not need one.
    #[test]
    fn a_range_decodes_as_the_array_it_equals() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        let range = Value::range_in(&mut vm.heap, 0, 3);
        round_trips(&mut vm, &d, &range);
    }

    /// The `List(Int)` descriptor, whose `Cons.tail` is the index of the node
    /// it sits in. Two constructors, so the tag is written.
    fn list_desc() -> WireDesc {
        desc(vec![
            WireNode::Data(vec![
                WireCtor {
                    type_id: TypeId(7),
                    variant_idx: 0,
                    fields: Vec::new(),
                },
                WireCtor {
                    type_id: TypeId(7),
                    variant_idx: 1,
                    fields: vec![WireNodeIdx(1), WireNodeIdx(0)],
                },
            ]),
            WireNode::Int,
        ])
    }

    fn list_vm() -> VM {
        vm_with_ctors(&[
            (TypeId(7), 0, "List", "Nil", &[]),
            (TypeId(7), 1, "List", "Cons", &["head", "tail"]),
        ])
    }

    #[test]
    fn a_data_value_round_trips_through_both_constructors() {
        let mut vm = list_vm();
        let d = list_desc();
        let nil = Value::enum_with_names_in(&mut vm.heap, TypeId(7), 0, "List", "Nil", &[], &[]);
        round_trips(&mut vm, &d, &nil);
        let one = Value::enum_with_names_in(
            &mut vm.heap,
            TypeId(7),
            1,
            "List",
            "Cons",
            &["head", "tail"],
            &[Value::small_int(5), nil.clone()],
        );
        round_trips(&mut vm, &d, &one);
    }

    /// The claim that makes decode type-safe: a decoded variant is built by
    /// `EnumTemplate::instantiate`, the same call a constructed one goes
    /// through, so nothing downstream can tell them apart.
    #[test]
    fn a_decoded_variant_is_indistinguishable_from_a_constructed_one() {
        let mut vm = list_vm();
        let d = list_desc();
        let nil = Value::enum_with_names_in(&mut vm.heap, TypeId(7), 0, "List", "Nil", &[], &[]);
        let built = Value::enum_with_names_in(
            &mut vm.heap,
            TypeId(7),
            1,
            "List",
            "Cons",
            &["head", "tail"],
            &[Value::small_int(5), nil],
        );
        let bytes = encode_value(&d, &built);
        let decoded = ok_of(&mut vm, &d, &bytes);

        let (b, dd) = (
            built.as_enum().expect("enum"),
            decoded.as_enum().expect("enum"),
        );
        assert_eq!(b.type_id(), dd.type_id());
        assert_eq!(b.variant_idx(), dd.variant_idx());
        assert_eq!(b.variant_name(), dd.variant_name());
        assert_eq!(hash_value(&built), hash_value(&decoded));
        assert!(values_equal(&built, &decoded));
    }

    /// The decode half of the rule that matters: native recursion here would
    /// be a stack overflow any peer could reach by sending a long list.
    #[test]
    fn wire_decode_deep_chain_is_iterative() {
        let mut vm = list_vm();
        let d = list_desc();

        const DEPTH: i64 = 100_000;
        let mut v = Value::enum_with_names_in(&mut vm.heap, TypeId(7), 0, "List", "Nil", &[], &[]);
        for _ in 0..DEPTH {
            v = Value::enum_with_names_in(
                &mut vm.heap,
                TypeId(7),
                1,
                "List",
                "Cons",
                &["head", "tail"],
                &[Value::small_int(1), v],
            );
        }
        let bytes = encode_value(&d, &v);
        let back = ok_of(&mut vm, &d, &bytes);
        assert!(values_equal(&v, &back));
    }

    // --- every DecodeError arm -------------------------------------------

    #[test]
    fn a_short_input_is_truncated() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);
        // Header present, body missing.
        let (name, payload) = refusal_of(&mut vm, &d, &header());
        assert_eq!(name, "Truncated");
        assert!(payload.is_empty());
        // Not even the magic.
        assert_eq!(refusal_of(&mut vm, &d, b"S").0, "Truncated");
        assert_eq!(refusal_of(&mut vm, &d, &[]).0, "Truncated");
    }

    /// The FIRST case is the one that pins the order the header is judged in,
    /// and it has to carry a foreign fingerprint as well as a foreign magic.
    /// Bytes that corrupt only the magic cannot tell the two orderings apart:
    /// a decoder that read the fingerprint first would find the right one,
    /// fall through, and still answer `NotWire`. Real foreign bytes are wrong
    /// in both places at once, and there the orderings differ — checking the
    /// fingerprint first reports `SchemaMismatch` about a file that was never
    /// wire at all.
    ///
    /// Written this way because the weaker version of this test was GREEN
    /// under a plant that reordered the two checks.
    #[test]
    fn foreign_bytes_and_an_unknown_version_are_not_wire() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);

        // A PNG's opening bytes: foreign magic, and bytes 3..11 spell a
        // number that is not this descriptor's fingerprint.
        let png = [
            0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13,
        ];
        assert_eq!(
            refusal_of(&mut vm, &d, &png).0,
            "NotWire",
            "bytes that were never wire are not a schema disagreement"
        );

        // A version this runtime does not read, with everything else right.
        let mut bad_version = header();
        bad_version[2] = VERSION + 1;
        bad_version.push(0);
        assert_eq!(refusal_of(&mut vm, &d, &bad_version).0, "NotWire");

        // Magic alone. Kept because it is a real case, not because it
        // discriminates: see the note above.
        let mut bad_magic = header();
        bad_magic[0] = b'X';
        bad_magic.push(0);
        assert_eq!(refusal_of(&mut vm, &d, &bad_magic).0, "NotWire");
    }

    /// Both fingerprints travel, so a log line can say which end changed.
    #[test]
    fn a_different_shape_is_schema_mismatch_carrying_both_sides() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);
        let mut bytes = encode_value(&d, &Value::small_int(0));
        // Flip the low fingerprint byte: same framing, different shape.
        bytes[3] ^= 0xff;

        let (name, payload) = refusal_of(&mut vm, &d, &bytes);
        assert_eq!(name, "SchemaMismatch");
        let got: Vec<i64> = payload
            .iter()
            .map(|v| v.as_int().expect("Int payload"))
            .collect();
        assert_eq!(
            got,
            vec![d.fingerprint() as i64, (d.fingerprint() ^ 0xff) as i64],
            "expected is the reader's own, found is the one in the bytes"
        );
    }

    /// The one that must not be got wrong: a four-byte message claiming a
    /// 2^40-element array is refused BEFORE anything is allocated.
    #[test]
    fn a_forged_2_40_count_is_refused_before_anything_is_allocated() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        let mut bytes = header();
        put_u64(&mut bytes, 1u64 << 40);

        let (name, payload) = refusal_of(&mut vm, &d, &bytes);
        assert_eq!(name, "Malformed");
        assert_eq!(
            payload[1].as_str().expect("Str payload"),
            "count is larger than the remaining input can hold"
        );
    }

    /// The same guard at a size that is safe to run WITHOUT it, which is what
    /// makes this the plantable arm of the pair above. With the guard removed
    /// the decoder discovers the lie by running out of bytes — `Truncated`,
    /// several allocations later — instead of refusing it up front.
    #[test]
    fn a_forged_small_count_is_malformed_rather_than_discovered_as_truncated() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        let mut bytes = header();
        put_u64(&mut bytes, 5);

        let (name, payload) = refusal_of(&mut vm, &d, &bytes);
        assert_eq!(
            name, "Malformed",
            "a count the input cannot hold is refused, not discovered later"
        );
        assert_eq!(payload[0].as_int().expect("Int payload"), HEADER_LEN as i64);
    }

    /// The hole the guard cannot close, asserted rather than left implicit: a
    /// zero-byte element type makes `count * min <= remaining` vacuous, so the
    /// count is bounded by `MAX_ZERO_COST_ELEMS` and by nothing in the input.
    #[test]
    fn a_zero_byte_element_type_is_capped_rather_than_bounded_by_the_input() {
        let mut vm = vm_with_ctors(&[(TypeId(3), 0, "Unit", "Unit", &[])]);
        // `Array(Unit)`, and `Unit` is one constructor with no fields, so
        // every element occupies zero bytes.
        let d = desc(vec![
            WireNode::Array(WireNodeIdx(1)),
            WireNode::Data(vec![WireCtor {
                type_id: TypeId(3),
                variant_idx: 0,
                fields: Vec::new(),
            }]),
        ]);
        assert_eq!(min_bytes(&d)[1], 0, "the element really is zero-byte");

        let mut over = header();
        put_u64(&mut over, MAX_ZERO_COST_ELEMS + 1);
        assert_eq!(refusal_of(&mut vm, &d, &over).0, "Malformed");

        // And a small one still decodes from the same three bytes of body,
        // which is what makes the cap necessary rather than incidental.
        let mut small = header();
        put_u64(&mut small, 3);
        let v = ok_of(&mut vm, &d, &small);
        match v.kind() {
            ValueView::Array(a) => assert_eq!(a.len(), 3),
            _ => panic!("expected an Array"),
        }
    }

    #[test]
    fn a_string_that_is_not_utf8_is_malformed() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::String]);
        let mut bytes = header();
        put_u64(&mut bytes, 2);
        bytes.extend_from_slice(&[0xff, 0xfe]);

        let (name, payload) = refusal_of(&mut vm, &d, &bytes);
        assert_eq!(name, "Malformed");
        assert_eq!(
            payload[1].as_str().expect("Str payload"),
            "string is not UTF-8"
        );
    }

    #[test]
    fn a_variant_tag_out_of_range_is_malformed() {
        let mut vm = list_vm();
        let d = list_desc();
        let mut bytes = header();
        put_u64(&mut bytes, 9);

        let (name, payload) = refusal_of(&mut vm, &d, &bytes);
        assert_eq!(name, "Malformed");
        assert_eq!(
            payload[1].as_str().expect("Str payload"),
            "variant tag out of range"
        );
    }

    /// Encode never writes a duplicate key, so bytes that claim one did not
    /// come from encode — and keeping the last would return a map shorter than
    /// its own count.
    #[test]
    fn a_duplicate_map_key_is_malformed() {
        let mut vm = halt_test_vm();
        let d = desc(vec![
            WireNode::Map(WireNodeIdx(1), WireNodeIdx(2)),
            WireNode::String,
            WireNode::Int,
        ]);
        let mut bytes = header();
        put_u64(&mut bytes, 2);
        for n in [1i64, 2] {
            put_str(&mut bytes, "k");
            put_i64(&mut bytes, n);
        }

        let (name, payload) = refusal_of(&mut vm, &d, &bytes);
        assert_eq!(name, "Malformed");
        assert_eq!(
            payload[1].as_str().expect("Str payload"),
            "duplicate map key"
        );
    }

    /// A second spelling of a number the encoder never writes. Accepting it
    /// would make the format non-canonical, so two peers could disagree on
    /// whether two messages are the same bytes.
    #[test]
    fn an_overlong_varint_is_malformed() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);
        let mut bytes = header();
        // zigzag(0) written in two groups instead of one.
        bytes.extend_from_slice(&[0x80, 0x00]);
        assert_eq!(refusal_of(&mut vm, &d, &bytes).0, "Malformed");

        let mut wide = header();
        wide.extend_from_slice(&[0xff; 11]);
        assert_eq!(refusal_of(&mut vm, &d, &wide).0, "Malformed");
    }

    #[test]
    fn extra_bytes_after_a_complete_value_are_trailing_bytes() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);
        let mut bytes = encode_value(&d, &Value::small_int(1));
        bytes.extend_from_slice(&[0, 0, 0]);

        let (name, payload) = refusal_of(&mut vm, &d, &bytes);
        assert_eq!(name, "TrailingBytes");
        assert_eq!(payload[0].as_int().expect("Int payload"), 3);
    }

    /// Not decode's own clamp: `Value::float` is what refuses to hold a
    /// non-finite, and a real NaN's bits collide with the tag space. Pinned
    /// here because the wire format lets a peer send one.
    #[test]
    fn a_non_finite_float_reading_becomes_zero() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Float]);
        for bits in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut bytes = header();
            bytes.extend_from_slice(&bits.to_bits().to_le_bytes());
            let v = ok_of(&mut vm, &d, &bytes);
            assert_eq!(v.as_float().expect("Float"), 0.0);
        }
    }

    /// The `Stop` split, and it is not cosmetic: a descriptor naming a
    /// constructor the program minted no template for is a compiler bug, and
    /// reporting it as a `DecodeError` would blame a peer whose bytes were
    /// perfectly good.
    #[test]
    fn a_missing_wire_template_is_a_vm_error_not_a_decode_error() {
        // Same descriptor, but no templates minted.
        let mut vm = halt_test_vm();
        let d = list_desc();
        let mut bytes = header();
        put_u64(&mut bytes, 0);
        assert!(
            vm.decode_wire(&d, &bytes, &mut 1_000_000).is_err(),
            "a missing template is a VM error, not an Err(DecodeError)"
        );

        // And with the template present the same bytes decode.
        let mut ok_vm = list_vm();
        assert_eq!(
            ok_of(&mut ok_vm, &d, &bytes)
                .as_enum()
                .expect("enum")
                .variant_name(),
            "Nil"
        );
    }

    /// Issue #35's worked example, all the way back.
    #[test]
    fn the_said_example_round_trips() {
        let mut vm = vm_with_ctors(&[
            (TypeId(9), 0, "Event", "Joined", &["user", "at"]),
            (TypeId(9), 1, "Event", "Said", &["user", "text", "tags"]),
        ]);
        let d = desc(vec![
            WireNode::Data(vec![
                WireCtor {
                    type_id: TypeId(9),
                    variant_idx: 0,
                    fields: vec![WireNodeIdx(1), WireNodeIdx(2)],
                },
                WireCtor {
                    type_id: TypeId(9),
                    variant_idx: 1,
                    fields: vec![WireNodeIdx(1), WireNodeIdx(1), WireNodeIdx(3)],
                },
            ]),
            WireNode::String,
            WireNode::Int,
            WireNode::Array(WireNodeIdx(1)),
        ]);

        let ali = Value::str_in(&mut vm.heap, "ali");
        let hi = Value::str_in(&mut vm.heap, "hi");
        let a = Value::str_in(&mut vm.heap, "a");
        let tags = Value::array_in(&mut vm.heap, &[a]);
        let said = Value::enum_with_names_in(
            &mut vm.heap,
            TypeId(9),
            1,
            "Event",
            "Said",
            &["user", "text", "tags"],
            &[ali, hi, tags],
        );
        round_trips(&mut vm, &d, &said);

        // The other constructor too, so the tag is not decoded by luck.
        let bo = Value::str_in(&mut vm.heap, "bo");
        let joined = Value::enum_with_names_in(
            &mut vm.heap,
            TypeId(9),
            0,
            "Event",
            "Joined",
            &["user", "at"],
            &[bo, Value::small_int(3)],
        );
        round_trips(&mut vm, &d, &joined);
    }

    /// A recursive type's minimum is finite because at least one constructor
    /// does not recurse — that is what the fixed point finds, and a single
    /// pass could not.
    #[test]
    fn min_bytes_terminates_on_a_recursive_type() {
        let m = min_bytes(&list_desc());
        assert_eq!(m[0], 1, "tag byte, then Nil's zero fields");
        assert_eq!(m[1], 1, "zigzag LEB128 of 0");
    }

    // --- the reduction charge --------------------------------------------

    /// An ordinary small value costs the scheduler nothing.
    ///
    /// The charge exists to stop a *large* payload being billed as idle; if it
    /// taxed every call it would be a tax on using `wire` at all.
    #[test]
    fn a_small_value_charges_nothing() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);
        assert_eq!(encode_cost(&mut vm, d, Value::small_int(7)), 0);
    }

    /// **This test is what rules out charging by bytes alone.**
    ///
    /// `Array(Unit)` where `Unit` is one constructor with no fields: every
    /// element occupies zero bytes, so a thousand of them is a two-byte count
    /// and nothing else. Bytes say 13; nodes say 1001. A bytes-only rule would
    /// charge 0 for a thousand-element walk.
    #[test]
    fn a_node_heavy_value_is_charged_by_its_nodes_not_its_bytes() {
        let mut vm = halt_test_vm();
        let d = desc(vec![
            WireNode::Array(WireNodeIdx(1)),
            WireNode::Data(vec![WireCtor {
                type_id: TypeId(3),
                variant_idx: 0,
                fields: Vec::new(),
            }]),
        ]);
        let unit = Value::enum_with_names_in(&mut vm.heap, TypeId(3), 0, "Unit", "Unit", &[], &[]);
        let items: Vec<Value> = (0..1000).map(|_| unit.clone()).collect();
        let arr = Value::array_in(&mut vm.heap, &items);

        // 11 header + 2 count bytes = 13; 1 array node + 1000 elements = 1001.
        assert_eq!(encode_value(&d, &arr).len(), 13, "the bytes really are few");
        assert_eq!(
            encode_cost(&mut vm, d, arr),
            (1001 / WIRE_WORK_PER_REDUCTION) as i32,
            "charged by nodes; a bytes-only rule would charge 0 here"
        );
    }

    /// **This test is what rules out charging by nodes alone.**
    ///
    /// One `Binary` field is a single node and an arbitrarily large `memcpy`.
    /// Nodes say 1; bytes say 4110. A nodes-only rule would charge 0 for four
    /// kilobytes of copying.
    #[test]
    fn a_byte_heavy_value_is_charged_by_its_bytes_not_its_nodes() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Binary]);
        let big = Value::binary_in(&mut vm.heap, vec![0xa5; 4096]);

        // 11 header + 3 bit-length bytes + 4096 payload = 4110; nodes = 1.
        assert_eq!(
            encode_value(&d, &big).len(),
            4110,
            "the nodes really are few"
        );
        assert_eq!(
            encode_cost(&mut vm, d, big),
            (4110 / WIRE_WORK_PER_REDUCTION) as i32,
            "charged by bytes; a nodes-only rule would charge 0 here"
        );
    }

    /// A decode that refuses **partway through the walk** still pays for what
    /// it built.
    ///
    /// The input is TRUNCATED mid-array, which is the shape that matters: the
    /// walk gets several hundred elements in and then runs out, so the refusal
    /// comes from inside `decode_body` and the error arm is what has to
    /// charge. **An earlier version of this test appended a trailing byte to a
    /// well-formed array instead — and that made `decode_body` SUCCEED, with
    /// `TrailingBytes` raised afterwards, so the Ok arm paid and the error arm
    /// was never entered.** It passed with the error-arm charge deleted. The
    /// name was right and the input was not.
    #[test]
    fn a_refusal_partway_through_the_walk_is_still_charged() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Array(WireNodeIdx(1)), WireNode::Int]);
        // Values above 63 zigzag to two bytes each, so the count clears the
        // remaining-bytes guard while the data runs out long before the end.
        let items: Vec<Value> = (0..1000).map(|_| Value::small_int(1000)).collect();
        let arr = Value::array_in(&mut vm.heap, &items);
        let full = encode_value(&d, &arr);
        let cut = HEADER_LEN + 2 + 1200;
        assert!(cut < full.len(), "the input must really be truncated");
        let bytes = &full[..cut];

        let mut reds = 1_000_000i32;
        let out = vm
            .decode_wire(&d, bytes, &mut reds)
            .expect("decode reached the ABI");
        let e = out.as_enum().expect("Result");
        assert_eq!(e.variant_name(), "Err", "truncated input must refuse");
        assert_eq!(
            e.payload()[0]
                .as_enum()
                .expect("DecodeError")
                .variant_name(),
            "Truncated",
            "and it must refuse from inside the walk, not after it"
        );
        assert!(
            1_000_000 - reds > 0,
            "a refusal that built ~600 elements must not be free"
        );
    }

    /// `wire_decode` copies the whole input `Binary` before parsing starts
    /// (`wire.rs:933`), so a buffer padded with trailing junk must be
    /// charged for that copy even though the parse itself only touches a
    /// tiny prefix before refusing with `TrailingBytes`. Charging by `r.at`
    /// (bytes actually parsed) instead of `bytes.len()` billed this near
    /// zero — found by a critic reviewing T-763 before it landed (T-778).
    #[test]
    fn a_padded_buffer_that_refuses_with_trailing_bytes_is_charged_for_the_whole_copy() {
        let mut vm = halt_test_vm();
        let d = desc(vec![WireNode::Int]);
        let mut padded = encode_value(&d, &Value::small_int(7));
        let parsed_len = padded.len();
        padded.resize(parsed_len + 100_000, 0u8);
        assert!(
            parsed_len < padded.len() / 1000,
            "the parsed prefix must be negligible next to the padding"
        );

        let mut reds = 1_000_000i32;
        let out = vm
            .decode_wire(&d, &padded, &mut reds)
            .expect("decode reached the ABI");
        let e = out.as_enum().expect("Result");
        assert_eq!(e.variant_name(), "Err", "padding must refuse");
        assert_eq!(
            e.payload()[0]
                .as_enum()
                .expect("DecodeError")
                .variant_name(),
            "TrailingBytes",
            "and it must refuse for exactly this reason"
        );
        let charged = 1_000_000 - reds;
        assert_eq!(
            charged,
            (padded.len() as u64 / WIRE_WORK_PER_REDUCTION) as i32,
            "billed for the whole copied buffer, not just the parsed prefix"
        );
    }
}

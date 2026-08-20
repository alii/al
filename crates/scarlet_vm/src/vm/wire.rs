//! `scarlet/wire`: values as bytes, under a descriptor of the type the call
//! site was inferred at.
//!
//! Two halves live here. The **encoder** is complete: [`WireDesc`] is the
//! runtime shape of a type, and [`encode_value`] walks a value under one and
//! writes the bytes `scarlet/wire.scrl`'s module doc specifies. The **decoder**
//! is not, and [`VM::wire_decode`] still traps.
//!
//! Neither op body runs yet, because nothing puts a [`WireDesc`] in front of
//! them. The descriptor is built in the compiler
//! (`scarlet_core::typed_ir::wire`, which this crate may not depend on) and has
//! to arrive as a program constant; elaboration attaching it, and the constant's
//! runtime form, are still being cut. So the ops trap and the encoder is
//! reachable only from the tests below.
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

use crate::TypeId;
use crate::bytecode::{MapBacking, Value, ValueView, hamt};

use super::map::env_entries;
use super::{VM, VmError, VmResult, range_len};

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

/// Index into [`WireDesc::nodes`]. Only meaningful for the `WireDesc` that
/// minted it, which is what lets a recursive type be a finite table: a
/// `List(Int)` is two nodes, and `Cons.tail` is the index of the node it sits
/// in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// No production caller yet, here and on every item below: the descriptor
// reaches the VM as an op operand, and nothing mints that operand. Retire these
// with the code that does. Not `expect`, which would be unfulfilled in the lib
// target and fulfilled in lib test, and `cargo clippy --all-targets` fails on
// the difference.
#[allow(dead_code)]
struct WireNodeIdx(u32);

/// One constructor a value may be, as the runtime needs it.
///
/// The position of a `WireCtor` in its [`WireNode::Data`] list **is** the tag
/// the peer receives, so reordering a type's constructors is a wire break.
/// `variant_idx` is the same number seen from the other side — a constructor's
/// declaration order within its type — and they coincide because the descriptor
/// builder lists constructors in declared order. Both are kept: the tag is what
/// goes on the wire, and `(type_id, variant_idx)` is what a decoder hands
/// `Program::wire_templates` to get the constructor back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct WireCtor {
    type_id: TypeId,
    variant_idx: u16,
    /// Field types in declared order, which is the order the payload is
    /// written in.
    fields: Vec<WireNodeIdx>,
}

/// One node of a [`WireDesc`]. Children are [`WireNodeIdx`] rather than nested
/// nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum WireNode {
    Int,
    Float,
    String,
    Binary,
    Array(WireNodeIdx),
    Map(WireNodeIdx, WireNodeIdx),
    Tuple(Vec<WireNodeIdx>),
    Data(Vec<WireCtor>),
}

/// The runtime descriptor of one type: a node table, the node the type itself
/// is, and the 64-bit hash of that shape.
///
/// The fingerprint is carried, never recomputed here. It folds constructor and
/// field names as text, and this table holds no names — by design, see the
/// module doc. The compiler computes it in `scarlet_core::typed_ir::wire` and
/// it travels with the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct WireDesc {
    nodes: Vec<WireNode>,
    root: WireNodeIdx,
    fingerprint: u64,
}

impl WireDesc {
    /// The node at `i`. `None` only for an index from another `WireDesc`,
    /// which the builder cannot produce.
    #[allow(dead_code)]
    fn node(&self, i: WireNodeIdx) -> Option<&WireNode> {
        self.nodes.get(i.0 as usize)
    }
}

// --- primitives -----------------------------------------------------------

/// LEB128.
#[allow(dead_code)]
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
#[allow(dead_code)]
fn put_i64(out: &mut Vec<u8>, v: i64) {
    put_u64(out, ((v << 1) ^ (v >> 63)) as u64);
}

/// `len LEB128 · UTF-8 bytes`.
#[allow(dead_code)]
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
#[allow(dead_code)]
fn encode_value(desc: &WireDesc, root: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&desc.fingerprint.to_le_bytes());
    write_body(&mut out, desc, root);
    out
}

/// The body half of [`encode_value`]: the value under `desc.root`, with no
/// header. Split out because the header is written once and the walk is the
/// part with an invariant worth naming.
#[allow(dead_code)]
fn write_body(out: &mut Vec<u8>, desc: &WireDesc, root: &Value) {
    // A container pushes its children and they are popped before anything
    // queued beside it, so a 100k-deep chain costs O(1) entries here rather
    // than one per level. A 100k-wide container does cost one entry per
    // element — that is heap, which is the trade this exists to make.
    let mut pending: Vec<(WireNodeIdx, Value)> = vec![(desc.root, root.clone())];

    while let Some((at, v)) = pending.pop() {
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
}

impl VM {
    /// `Op::WireEncode` — `[value] -> Binary`.
    pub(super) fn wire_encode(&mut self) -> VmResult<()> {
        Err(VmError::internal(
            "wire.encode has no descriptor to walk: the encoder is implemented, \
             but the op's descriptor operand is not minted yet",
        ))
    }

    /// `Op::WireDecode` — `[bytes Binary] -> Result(a, DecodeError)`.
    pub(super) fn wire_decode(&mut self) -> VmResult<()> {
        Err(VmError::internal(
            "wire.decode has no decoder yet: the op is declared, not implemented",
        ))
    }
}

#[cfg(test)]
mod tests {
    //! Two things are witnessed here: that the bytes match `wire.scrl`'s format
    //! table row by row, and that the walk is iterative. Nothing witnesses the
    //! op — it has no descriptor operand — nor decoding, which does not exist.

    use super::super::halt_test_vm;
    use super::*;
    use crate::abi::AbiSlot;
    use crate::bytecode::hash_value;

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
        WireDesc {
            nodes,
            root: WireNodeIdx(0),
            fingerprint: 0x0807_0605_0403_0201,
        }
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

    /// Both ops still have no reachable body: `wire_decode` has no decoder, and
    /// `wire_encode` has an encoder but no descriptor operand to feed it.
    /// Pinned so the day either is wired up, this test is what says so.
    #[test]
    fn both_ops_trap_until_a_descriptor_reaches_them() {
        let mut vm = halt_test_vm();
        assert!(vm.wire_encode().is_err());
        assert!(vm.wire_decode().is_err());
    }
}

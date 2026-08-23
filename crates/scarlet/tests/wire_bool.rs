//! `Bool` across the typed wire, end to end through `al run`. `True` and
//! `False` are a two-constructor `Data` type to the descriptor and an
//! immediate to the runtime, and until 2026-08-22 the typed encoder's `Data`
//! arm asserted a cell: `wire.encode(True)` panicked in debug (`descriptor
//! says Data`, `vm/wire.rs:447`, measured on 890b3dd with rc 101 for both
//! polarities) and in release wrote no body, so `decode` reported
//! `Truncated`. Inside a closure's captures `Bool` always worked — it has a
//! tag of its own there (`wire_closures.rs`) — so this is the typed path
//! alone.
//!
//! `Nil` is the control: the prelude's `Nil` is a frozen cell at runtime
//! (`Op::PushNil` pushes the `Unit` ABI slot's pre-built constructor), so it
//! took the ordinary `Data` path all along and round-tripped before this
//! change, at zero body bytes.

mod common;

use common::run_outputs;

/// Each polarity, and `Nil`. The tag is pinned as a byte too: `True` is
/// variant 0 because `scarlet.scrl` declares it first, so the body of
/// `wire.encode(True)` is the single byte 0 behind the eleven-byte header,
/// and `Nil` — one constructor — has no body at all.
#[test]
fn true_false_and_nil_round_trip_and_the_tag_is_the_declared_index() {
    run_outputs(
        "import scarlet/binary\n\
         import scarlet/wire\n\
         pub fn main() {\n\
         \tprintln(wire.decode(wire.encode(True)) == Ok(True))\n\
         \tprintln(wire.decode(wire.encode(False)) == Ok(False))\n\
         \tprintln(wire.decode(wire.encode(Nil)) == Ok(Nil))\n\
         \tprintln(binary.slice_bytes(wire.encode(True), 11, 1) == Ok(<<0>>))\n\
         \tprintln(binary.slice_bytes(wire.encode(False), 11, 1) == Ok(<<1>>))\n\
         \tprintln(binary.byte_size(wire.encode(Nil)))\n\
         }\n",
        "True\nTrue\nTrue\nTrue\nTrue\n11\n",
    );
}

/// A record holding a `Bool` beside an `Int`, and an `Array(Bool)`: the
/// immediate under a `Data` node that is a field and an element rather than
/// the root. The decoded `Bool` is used as one — branched on, not only
/// compared — which a cell standing in for it could not be.
#[test]
fn a_record_with_a_bool_field_and_an_array_of_bools_round_trip() {
    run_outputs(
        "import scarlet/wire\n\
         type Flag {\n\
         \tFlag(on Bool, n Int)\n\
         }\n\
         pub fn main() {\n\
         \tf = Flag(True, 3)\n\
         \tmatch wire.decode(wire.encode(f)) {\n\
         \t\tOk(back) -> {\n\
         \t\t\tprintln(back == f)\n\
         \t\t\tprintln(if back.on { back.n } else { 0 })\n\
         \t\t}\n\
         \t\tErr(_) -> println('refused')\n\
         \t}\n\
         \txs = [True, False, True]\n\
         \tmatch wire.decode(wire.encode(xs)) {\n\
         \t\tOk(ys) -> {\n\
         \t\t\tprintln(ys == xs)\n\
         \t\t\tprintln(ys == [True, True, True])\n\
         \t\t}\n\
         \t\tErr(_) -> println('refused')\n\
         \t}\n\
         }\n",
        "True\n3\nTrue\nFalse\n",
    );
}

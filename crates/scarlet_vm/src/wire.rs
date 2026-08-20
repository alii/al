//! The runtime descriptor of a type: what `Op::WireEncode` walks a value
//! against and `Op::WireDecode` builds one from.
//!
//! This is **program data**, not interpreter code, which is why it sits beside
//! [`template`](crate::template) rather than inside [`vm`](crate::vm). A
//! [`bytecode::Program`](crate::bytecode::Program) carries a table of these and
//! each wire instruction names one by index; the walks that read them live in
//! `vm::wire`.
//!
//! # Why the runtime has its own descriptor at all
//!
//! The compiler has one already — `scarlet_core::typed_ir::wire::Desc` — and it
//! cannot cross the boundary: this crate must never depend on a language crate,
//! and Cargo enforces it. So the front end converts, and what it converts *to*
//! deliberately carries **less**. No type names, no constructor names, no field
//! labels. The walks need structure; a decoder rebuilds a constructor through
//! [`Program::wire_templates`](crate::bytecode::Program::wire_templates), which
//! is keyed on `(TypeId, variant_idx)` and never on a name. A name in here
//! would be a second identity for a constructor that already has one.
//!
//! # Why a typed table, and not the two alternatives
//!
//! The descriptor has to reach the VM somehow, and three shapes were on the
//! table (T-732). Recorded here because the next reader will wonder about the
//! two that were not taken:
//!
//! - **As a frozen `Binary` constant the VM parses.** It keeps the instruction
//!   operand a plain `ConstId` and needs no new `Program` field, but it buys
//!   that with a *second* byte format — one to specify, one to test, one to
//!   keep in step with the first — and a parse to cache or repeat per call.
//!   The wire format already has one hostile parser; a second, for data the
//!   compiler itself just wrote, is machinery bought with nothing.
//! - **As an ordinary frozen tuple/array `Value` graph.** No new format, and
//!   the front end can build it with the constructors it already has. But then
//!   the VM walks an untyped graph and must *trust* what it finds — every node
//!   kind an integer to re-check, every child an index with nothing declaring
//!   it is one. That is precisely the shape these types exist to replace, and
//!   it would put a fallible read in front of an encoder whose whole contract
//!   is that it cannot fail.
//!
//! A typed table costs one `Program` field and one immediate variant, and in
//! exchange the walks index a `Vec` and match an enum. That is the trade.

use crate::TypeId;

/// Index into a [`WireDesc`]'s node table. Only meaningful for the descriptor
/// that minted it.
///
/// Children are indices rather than nested nodes, which is what lets a
/// recursive type be a finite table: `List(Int)` is two nodes, and `Cons.tail`
/// is the index of the node it sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireNodeIdx(pub u32);

/// One constructor a value of a [`WireNode::Data`] may be.
///
/// The position of a `WireCtor` in its node's list **is** the tag the peer
/// receives, so reordering a type's constructors is a wire break.
/// `variant_idx` is the same number seen from the other side — a constructor's
/// declaration order within its type — and they coincide because the front end
/// lists constructors in declared order. Both are kept: the position is what
/// goes on the wire, and `(type_id, variant_idx)` is what a decoder hands
/// `Program::wire_templates` to get the constructor back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireCtor {
    pub type_id: TypeId,
    pub variant_idx: u16,
    /// Field types in declared order, which is the order the payload is
    /// written in.
    pub fields: Vec<WireNodeIdx>,
}

/// One node of a [`WireDesc`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireNode {
    Int,
    Float,
    String,
    Binary,
    Array(WireNodeIdx),
    Map(WireNodeIdx, WireNodeIdx),
    Tuple(Vec<WireNodeIdx>),
    Data(Vec<WireCtor>),
}

/// The descriptor of one type: a node table, the node the type itself is, and
/// the 64-bit hash of that shape.
///
/// The fingerprint is carried, never recomputed here. It folds constructor and
/// field names as text and this table holds no names — by design, see the
/// module doc — so the front end computes it and it travels with the
/// descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireDesc {
    nodes: Vec<WireNode>,
    root: WireNodeIdx,
    fingerprint: u64,
}

impl WireDesc {
    /// Build a descriptor. The front end's converter is the only caller: it
    /// holds the `Desc` this mirrors and the `WireCtx` that resolved it.
    pub fn new(nodes: Vec<WireNode>, root: WireNodeIdx, fingerprint: u64) -> WireDesc {
        WireDesc {
            nodes,
            root,
            fingerprint,
        }
    }

    /// The node the described type itself is.
    pub(crate) fn root(&self) -> WireNodeIdx {
        self.root
    }

    /// The 64-bit hash of this type's shape. Two peers agree they are talking
    /// about the same shape by comparing these; `scarlet/wire.scrl`'s module
    /// doc specifies how it is computed and what moves it.
    pub(crate) fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// The node at `i`. `None` only for an index from another descriptor,
    /// which the converter cannot produce.
    pub(crate) fn node(&self, i: WireNodeIdx) -> Option<&WireNode> {
        self.nodes.get(i.0 as usize)
    }

    /// How many nodes the table holds. The minimum-size table in `vm::wire` is
    /// sized from this.
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }
}

//! `wire`'s descriptor builder: a resolved type in, the descriptor that
//! `wire.encode`/`wire.decode` walk out, or a refusal naming the sub-type that
//! cannot cross and the path down to it.
//!
//! The descriptor is a **finite table** describing a value that is not: a
//! `List(Int)` is unbounded, but its descriptor is two nodes, and `Cons.tail`
//! is an index back at the node it sits in. That closure is bought by memoising
//! a nominal node under [`Key::Nominal`] *before* its fields are walked, so the
//! recursive occurrence finds the node already under construction. The memo is
//! keyed on the arguments' **descriptor nodes**, never on their [`RTy`]s:
//! substitution mints a fresh `RTy` for `Cons.tail`'s `List(Int)` every time,
//! so an `RTy`-keyed memo would never hit and the walk would not terminate.
//!
//! Encoding refuses exactly what decoding refuses. The asymmetry is tempting —
//! bytes can be written for things that cannot be read back — and it is
//! precisely what must not be allowed: a program that can write what it can
//! never read has been handed a corruption it will find later, elsewhere.
//!
//! Type identity is always [`TypeId`], never `Con.name`: a user's `type Parsed`
//! and `scarlet/http/h1.Parsed` share a name and are different types.

use std::collections::HashMap;

use smallvec::SmallVec;

use super::elaborate::subst_rty;
use super::rty::{RTy, ResolvedNode, ResolvedPool};
use crate::core_ir::VariantRef;
use crate::type_def::TypeId;
use crate::types::StrId;

/// Abort: the checker admitted a type whose shape the descriptor builder
/// cannot read, e.g. an `Array` with no element type. The span-free counterpart
/// to [`super::elaborate::elaborator_bug`] — a resolved type carries none.
///
/// No program reaches this. Inventing a descriptor instead would encode a value
/// the peer then rebuilds wrong, which is the one failure this module exists to
/// make impossible.
#[allow(clippy::panic)]
#[cold]
#[inline(never)]
fn wire_bug(why: &'static str) -> ! {
    panic!(
        "internal compiler error: {why} is well-typed but has no wire descriptor. \
         Report this as a compiler bug."
    )
}

/// Index into [`Desc::nodes`]. Only meaningful for the `Desc` that minted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeIdx(pub u32);

impl std::fmt::Display for NodeIdx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One field of one constructor: the label a decoder rebuilds it under, and the
/// descriptor of its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireField {
    pub label: StrId,
    pub node: NodeIdx,
}

/// One constructor a decoder may build.
///
/// Carries `VariantRef` plus the declared labels — exactly the arguments
/// `EnumTemplate::build` consumes — so a decoded variant is built by the same
/// call that builds a constructed one. It deliberately does **not** carry a
/// `TemplateIdx`: `bind_abi` rebuilds `Program.templates` from scratch on every
/// emit, so an index minted here would name a different template, or none, by
/// the time anything read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireVariant {
    pub variant: VariantRef,
    /// Declared order, which is the order a decoder fills the payload in.
    pub fields: Vec<WireField>,
}

/// One node of a [`Desc`]. Children are [`NodeIdx`] rather than nested nodes,
/// which is what lets a recursive type be a finite table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Int,
    Float,
    String,
    Binary,
    Array(NodeIdx),
    Map(NodeIdx, NodeIdx),
    Tuple(Vec<NodeIdx>),
    /// Constructors in declared order: a variant's position here is the tag the
    /// peer receives, so reordering a type's constructors is a wire break.
    Data(Vec<WireVariant>),
}

/// The descriptor of one type: a node table, the node the type itself is, and
/// the fingerprint of that shape.
///
/// `fingerprint` is not recomputable from the other two fields: it folds
/// constructor and field names as **text**, and a [`Desc`] holds only the
/// [`StrId`]s. It is minted in [`build_desc`], which has the [`WireCtx`] that
/// can resolve them, and there is no second way to arrive at one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desc {
    nodes: Vec<Node>,
    root: NodeIdx,
    fingerprint: u64,
}

impl Desc {
    /// The node the described type itself is.
    pub fn root(&self) -> NodeIdx {
        self.root
    }

    /// The 64-bit hash of this type's shape. Two peers agree they are talking
    /// about the same shape by comparing these; `wire.scrl`'s module doc
    /// specifies how it is computed and what moves it.
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// The node at `i`, or `None` for an index from another `Desc`.
    pub fn node(&self, i: NodeIdx) -> Option<&Node> {
        self.nodes.get(i.0 as usize)
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A scalar or container the wire format writes directly, rather than as a
/// tagged constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    Int,
    Float,
    String,
    Binary,
    /// `Array(elem)`.
    Array,
    /// `Map(key, value)`.
    Map,
}

/// One constructor as declared, before instantiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtorDecl {
    pub variant: VariantRef,
    /// Declared order. Types are **closed** over the owning type's parameters:
    /// `Bound(i)` is the `i`th argument of the `Con` being described, which is
    /// the form `close_body` stores a `VariantField` in.
    pub fields: Vec<(StrId, RTy)>,
}

/// What a [`TypeId`] denotes to `wire`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nominal {
    Builtin(Builtin),
    /// `type Name(params) = Target`. Closed over the type's parameters, and
    /// looked through rather than refused — an alias to an encodable type is
    /// encodable.
    Alias(RTy),
    Data {
        /// `pub` and not `opaque`. False for a private type too, which is why
        /// it is read together with `declared_here`.
        ctors_public: bool,
        /// Whether the module being compiled is the one that declared this
        /// type. A module may always encode its own types.
        declared_here: bool,
        ctors: Vec<CtorDecl>,
    },
    /// `pub type Name` with no body — host-backed. There is no representation
    /// to write and nothing a decoder could rebuild.
    Bodiless,
}

/// What the descriptor builder must ask about a nominal type.
///
/// A [`ResolvedPool`] carries a type's shape but not its declaration, and
/// `ElabCtx` deliberately exposes no inference engine, so this is the one seam
/// between the two. Same split, and for the same reason, as
/// [`super::elaborate_pat::PatCtx`]: every type crossing it is an [`RTy`], so
/// the builder is exercised against hand-built types without an engine.
pub trait WireCtx {
    /// What `id` denotes. Field and alias-target types come back closed over
    /// the declaring type's own parameters.
    fn nominal(&mut self, id: TypeId) -> Nominal;

    /// Display text for an interned name, for a refusal's path.
    fn name(&self, s: StrId) -> String;
}

/// One step from the described type down towards the sub-type that refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The variant is named as well as the label because two constructors of
    /// one type may each have a field called `value`, and a path that said only
    /// `value` would not say which.
    Field {
        variant: StrId,
        label: StrId,
    },
    Element,
    Key,
    Value,
    TupleElem(usize),
}

/// Why a type cannot cross the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Function,
    TypeVariable,
    NoRepresentation,
    ConstructorsNotVisible,
}

impl Reason {
    /// The prose a diagnostic carries. Present tense, naming the property that
    /// fails rather than the syntax that has it.
    pub fn describe(self) -> &'static str {
        match self {
            // NOT "a function has no wire representation" — it has several, and
            // Erlang writes one. What fails is reconstruction: a closure is a
            // function index plus an untyped capture array, and the static type
            // `fn(Int) Int` fixes neither. Every other type here works because
            // its type fixes its layout; this is the one where it does not.
            Reason::Function => {
                "a closure's captures are not fixed by its type, so a decoder cannot rebuild one"
            }
            Reason::TypeVariable => {
                "the type is still polymorphic here, so its representation is not known"
            }
            Reason::NoRepresentation => {
                "the type is host-backed and has no representation outside this program"
            }
            Reason::ConstructorsNotVisible => {
                "the type's constructors are not visible here, and decoding builds values by \
                 constructor without running the declaring module's code"
            }
        }
    }
}

/// A type that cannot cross the wire, and where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRefusal {
    /// The offending sub-type — not the type the call named. Rendering it is
    /// the caller's job; it holds the pool.
    pub ty: RTy,
    pub reason: Reason,
    /// Outermost first. Empty when the described type is itself the refusal.
    pub path: Vec<Step>,
}

impl WireRefusal {
    /// The path text a diagnostic quotes: `Outer.mid -> Middle.inner ->
    /// Inner.f`. Empty when the refusal is the described type itself.
    ///
    /// This is the half of the diagnostic that makes it useful: a refusal three
    /// levels down a record that says only "cannot encode" leaves the reader to
    /// find which field it meant.
    pub fn path_text<C: WireCtx + ?Sized>(&self, cx: &C) -> String {
        self.path
            .iter()
            .map(|s| match *s {
                Step::Field { variant, label } => {
                    format!("{}.{}", cx.name(variant), cx.name(label))
                }
                Step::Element => "[element]".to_string(),
                Step::Key => "[key]".to_string(),
                Step::Value => "[value]".to_string(),
                Step::TupleElem(i) => format!("[{i}]"),
            })
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

/// What makes two descriptor nodes the same node.
///
/// A nominal is keyed on its `TypeId` and its arguments' *nodes*, not on the
/// variant list it will expand into — that is what lets the key exist before
/// the variants do, which is what closes recursion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Int,
    Float,
    String,
    Binary,
    Array(NodeIdx),
    Map(NodeIdx, NodeIdx),
    Tuple(SmallVec<[NodeIdx; 4]>),
    Nominal(TypeId, SmallVec<[NodeIdx; 4]>),
}

/// Version of the fingerprint algorithm, folded in first so that a change to
/// what is hashed cannot produce a value a peer would mistake for the old one.
///
/// **Bumping this is bumping the format version byte**, and `wire.scrl`'s
/// module doc says so as a rule rather than as a note: the fingerprint travels
/// in every message, so an algorithm change that kept the version would show up
/// at a peer as a `SchemaMismatch` on a type nobody had touched.
const FINGERPRINT_VERSION: u64 = 1;

const FINGERPRINT_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FINGERPRINT_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a over one `u64` at a time. The same construction the VM's value hash
/// uses, restated here because these two hashes must be free to move
/// independently: that one is an equality fast-reject inside one program and
/// samples long inputs, this one is a compatibility surface between two
/// programs and may never sample anything.
#[inline]
fn mix(h: u64, v: u64) -> u64 {
    (h ^ v).wrapping_mul(FINGERPRINT_PRIME)
}

/// Length first, then the UTF-8 bytes — so `("ab", "c")` and `("a", "bc")` do
/// not fold to the same hash.
fn mix_str(h: u64, s: &str) -> u64 {
    let mut h = mix(h, s.len() as u64);
    for b in s.as_bytes() {
        h = mix(h, u64::from(*b));
    }
    h
}

/// Fold the node table in index order.
///
/// A child is folded as its **index**, never by descending into it, which is
/// what lets a recursive type hash without recursing: `Cons.tail` is the number
/// 1, and node 1's own row is folded when the loop reaches it. That makes the
/// fingerprint a hash of the table as [`build_desc`] canonically lays it out —
/// so a change to the walk order is a change to the algorithm, and takes
/// [`FINGERPRINT_VERSION`] with it.
///
/// What is folded, and the reasoning, is specified for a second implementation
/// in `wire.scrl`'s module doc; this function is that spec in Rust.
fn fingerprint_of<C: WireCtx + ?Sized>(cx: &C, nodes: &[Node], root: NodeIdx) -> u64 {
    let mut h = mix(FINGERPRINT_BASIS, FINGERPRINT_VERSION);
    h = mix(h, nodes.len() as u64);
    h = mix(h, u64::from(root.0));

    for n in nodes {
        h = match n {
            Node::Int => mix(h, 1),
            Node::Float => mix(h, 2),
            Node::String => mix(h, 3),
            Node::Binary => mix(h, 4),
            Node::Array(e) => mix(mix(h, 5), u64::from(e.0)),
            Node::Map(k, v) => mix(mix(mix(h, 6), u64::from(k.0)), u64::from(v.0)),
            Node::Tuple(es) => {
                let mut h = mix(mix(h, 7), es.len() as u64);
                for e in es {
                    h = mix(h, u64::from(e.0));
                }
                h
            }
            Node::Data(vs) => {
                let mut h = mix(mix(h, 8), vs.len() as u64);
                for v in vs {
                    // The tag the peer receives, and the constructor name. The
                    // owning type's id and NAME are deliberately absent: two
                    // programs that declare this shape independently, under
                    // whatever name and in whatever module, must agree.
                    h = mix(h, u64::from(v.variant.variant_idx));
                    h = mix_str(h, &cx.name(v.variant.variant_name));
                    h = mix(h, v.fields.len() as u64);
                    for f in &v.fields {
                        h = mix_str(h, &cx.name(f.label));
                        h = mix(h, u64::from(f.node.0));
                    }
                }
                h
            }
        };
    }
    h
}

/// Build the descriptor of `root`, or refuse.
///
/// Total over the checker's output: every resolved type either describes or
/// refuses, and the refusal names the sub-type and the path to it.
///
/// `pool` is taken mutably because instantiating a variant's field types at the
/// type's arguments mints nodes — `Option(Int)`'s `Some.value` is an `Int` that
/// the declared body, which says `Bound(0)`, does not contain.
pub fn build_desc<C: WireCtx + ?Sized>(
    pool: &mut ResolvedPool,
    cx: &mut C,
    root: RTy,
) -> Result<Desc, WireRefusal> {
    let mut b = Build {
        pool,
        cx,
        nodes: Vec::new(),
        memo: HashMap::new(),
    };
    let mut path = Vec::new();
    let root = b.walk(root, &mut path)?;
    let fingerprint = fingerprint_of(b.cx, &b.nodes, root);
    Ok(Desc {
        nodes: b.nodes,
        root,
        fingerprint,
    })
}

struct Build<'a, C: WireCtx + ?Sized> {
    pool: &'a mut ResolvedPool,
    cx: &'a mut C,
    nodes: Vec<Node>,
    memo: HashMap<Key, NodeIdx>,
}

impl<C: WireCtx + ?Sized> Build<'_, C> {
    /// The node for `key`, minting `mk()` on first ask.
    fn intern(&mut self, key: Key, mk: impl FnOnce() -> Node) -> NodeIdx {
        if let Some(&i) = self.memo.get(&key) {
            return i;
        }
        let i = NodeIdx(self.nodes.len() as u32);
        self.nodes.push(mk());
        self.memo.insert(key, i);
        i
    }

    fn refuse(&self, ty: RTy, reason: Reason, path: &[Step]) -> WireRefusal {
        WireRefusal {
            ty,
            reason,
            path: path.to_vec(),
        }
    }

    /// Descend into `t` with `step` appended to the path.
    ///
    /// The step is not popped on the error path: the refusal has already copied
    /// the path it needs, and every frame above returns immediately.
    fn child(&mut self, t: RTy, step: Step, path: &mut Vec<Step>) -> Result<NodeIdx, WireRefusal> {
        path.push(step);
        let n = self.walk(t, path)?;
        path.pop();
        Ok(n)
    }

    fn walk(&mut self, t: RTy, path: &mut Vec<Step>) -> Result<NodeIdx, WireRefusal> {
        match self.pool.node(t) {
            ResolvedNode::Bound(_) => Err(self.refuse(t, Reason::TypeVariable, path)),
            ResolvedNode::Fun { .. } => Err(self.refuse(t, Reason::Function, path)),
            ResolvedNode::Tuple { elems } => {
                let elems: SmallVec<[RTy; 4]> = self.pool.children(elems).into();
                let mut kids: SmallVec<[NodeIdx; 4]> = SmallVec::new();
                for (i, e) in elems.iter().enumerate() {
                    kids.push(self.child(*e, Step::TupleElem(i), path)?);
                }
                Ok(self.intern(Key::Tuple(kids.clone()), || Node::Tuple(kids.to_vec())))
            }
            ResolvedNode::Con { id, args, .. } => {
                let args: SmallVec<[RTy; 4]> = self.pool.children(args).into();
                self.con(t, id, &args, path)
            }
        }
    }

    fn con(
        &mut self,
        t: RTy,
        id: TypeId,
        args: &[RTy],
        path: &mut Vec<Step>,
    ) -> Result<NodeIdx, WireRefusal> {
        match self.cx.nominal(id) {
            Nominal::Bodiless => Err(self.refuse(t, Reason::NoRepresentation, path)),

            Nominal::Builtin(b) => self.builtin(b, args, path),

            // Looked through without a path step: an alias is a spelling, not a
            // level of structure, and naming it in the path would point the
            // reader at a field that does not exist.
            Nominal::Alias(target) => {
                let at = self.instantiate(target, args);
                self.walk(at, path)
            }

            Nominal::Data {
                ctors_public,
                declared_here,
                ctors,
            } => {
                if !ctors_public && !declared_here {
                    return Err(self.refuse(t, Reason::ConstructorsNotVisible, path));
                }
                self.data(id, args, ctors, path)
            }
        }
    }

    fn builtin(
        &mut self,
        b: Builtin,
        args: &[RTy],
        path: &mut Vec<Step>,
    ) -> Result<NodeIdx, WireRefusal> {
        match b {
            Builtin::Int => Ok(self.intern(Key::Int, || Node::Int)),
            Builtin::Float => Ok(self.intern(Key::Float, || Node::Float)),
            Builtin::String => Ok(self.intern(Key::String, || Node::String)),
            Builtin::Binary => Ok(self.intern(Key::Binary, || Node::Binary)),
            Builtin::Array => {
                let Some(&elem) = args.first() else {
                    wire_bug("an array type with no element type")
                };
                let e = self.child(elem, Step::Element, path)?;
                Ok(self.intern(Key::Array(e), || Node::Array(e)))
            }
            Builtin::Map => {
                let (Some(&k), Some(&v)) = (args.first(), args.get(1)) else {
                    wire_bug("a map type without both a key and a value type")
                };
                let kn = self.child(k, Step::Key, path)?;
                let vn = self.child(v, Step::Value, path)?;
                Ok(self.intern(Key::Map(kn, vn), || Node::Map(kn, vn)))
            }
        }
    }

    /// The node for `id(args...)`, expanding its constructors.
    ///
    /// The node is minted and memoised *before* the fields are walked, and
    /// filled in afterwards. A recursive occurrence hits the memo and gets this
    /// index, which is the whole of why the table is finite.
    fn data(
        &mut self,
        id: TypeId,
        args: &[RTy],
        ctors: Vec<CtorDecl>,
        path: &mut Vec<Step>,
    ) -> Result<NodeIdx, WireRefusal> {
        let mut arg_nodes: SmallVec<[NodeIdx; 4]> = SmallVec::new();
        for a in args {
            // A type argument is described even when no constructor mentions
            // it. `Phantom(a)` still refuses at `a`, so the same type is
            // encodable or not regardless of which constructors it happens to
            // have — the alternative makes encodability depend on a body the
            // caller cannot see.
            arg_nodes.push(self.walk(*a, path)?);
        }

        let key = Key::Nominal(id, arg_nodes);
        if let Some(&i) = self.memo.get(&key) {
            return Ok(i);
        }
        let idx = NodeIdx(self.nodes.len() as u32);
        self.nodes.push(Node::Data(Vec::new()));
        self.memo.insert(key, idx);

        let mut variants = Vec::with_capacity(ctors.len());
        for c in ctors {
            let mut fields = Vec::with_capacity(c.fields.len());
            for (label, declared) in c.fields {
                let at = self.instantiate(declared, args);
                let step = Step::Field {
                    variant: c.variant.variant_name,
                    label,
                };
                fields.push(WireField {
                    label,
                    node: self.child(at, step, path)?,
                });
            }
            variants.push(WireVariant {
                variant: c.variant,
                fields,
            });
        }

        let Some(slot) = self.nodes.get_mut(idx.0 as usize) else {
            wire_bug("a descriptor node that was minted and then lost")
        };
        *slot = Node::Data(variants);
        Ok(idx)
    }

    /// A declared type, closed over its owner's parameters, at `args`.
    ///
    /// `Bound(i)` is the `i`th parameter, which is the form `close_body` stores
    /// a `VariantField` in, so the map is positional. The rewrite itself is the
    /// elaborator's — a second implementation of substitution is a second thing
    /// to keep in step with the pool's node kinds.
    fn instantiate(&mut self, declared: RTy, args: &[RTy]) -> RTy {
        if args.is_empty() {
            return declared;
        }
        let m: HashMap<u32, RTy> = args
            .iter()
            .enumerate()
            .map(|(i, &a)| (i as u32, a))
            .collect();
        subst_rty(self.pool, declared, &m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PrimIds;

    const INT: TypeId = TypeId(1);
    const FLOAT: TypeId = TypeId(2);
    const STRING: TypeId = TypeId(3);
    const ARRAY: TypeId = TypeId(4);
    const BINARY: TypeId = TypeId(5);
    const MAP: TypeId = TypeId(6);

    /// A hand-built type world: no inference engine, no module table, so a test
    /// states exactly the declarations it is about.
    struct Fixture {
        names: Vec<String>,
        types: HashMap<TypeId, Nominal>,
        pool: ResolvedPool,
    }

    impl Fixture {
        fn new() -> Fixture {
            let mut f = Fixture {
                names: Vec::new(),
                types: HashMap::new(),
                pool: ResolvedPool::new(PrimIds {
                    int: INT,
                    float: FLOAT,
                    string: STRING,
                    array: ARRAY,
                }),
            };
            f.types.insert(INT, Nominal::Builtin(Builtin::Int));
            f.types.insert(FLOAT, Nominal::Builtin(Builtin::Float));
            f.types.insert(STRING, Nominal::Builtin(Builtin::String));
            f.types.insert(BINARY, Nominal::Builtin(Builtin::Binary));
            f.types.insert(ARRAY, Nominal::Builtin(Builtin::Array));
            f.types.insert(MAP, Nominal::Builtin(Builtin::Map));
            f
        }

        fn intern(&mut self, s: &str) -> StrId {
            if let Some(i) = self.names.iter().position(|n| n == s) {
                return StrId(i as u32);
            }
            self.names.push(s.to_string());
            StrId((self.names.len() - 1) as u32)
        }

        /// `Name(args...)`.
        fn con(&mut self, id: TypeId, name: &str, args: &[RTy]) -> RTy {
            let n = self.intern(name);
            self.pool.mk_con(id, n, args)
        }

        fn int(&mut self) -> RTy {
            self.con(INT, "Int", &[])
        }

        fn string(&mut self) -> RTy {
            self.con(STRING, "String", &[])
        }

        fn bound(&mut self, i: u32) -> RTy {
            self.pool.mk_bound(i)
        }

        /// Declare `type Name(params) { ... }`, `pub` and not opaque.
        fn data(&mut self, id: TypeId, ctors: Vec<CtorDecl>) {
            self.types.insert(
                id,
                Nominal::Data {
                    ctors_public: true,
                    declared_here: false,
                    ctors,
                },
            );
        }

        fn ctor(
            &mut self,
            ty: TypeId,
            ty_name: &str,
            idx: u16,
            name: &str,
            fields: &[(&str, RTy)],
        ) -> CtorDecl {
            let type_name = self.intern(ty_name);
            let variant_name = self.intern(name);
            let fields = fields
                .iter()
                .map(|(l, t)| (self.intern(l), *t))
                .collect::<Vec<_>>();
            CtorDecl {
                variant: VariantRef {
                    type_id: ty,
                    variant_idx: idx,
                    type_name,
                    variant_name,
                },
                fields,
            }
        }

        fn build(&mut self, root: RTy) -> Result<Desc, WireRefusal> {
            // Split the borrow: the walk needs the pool mutably and the
            // declarations immutably, and they live in one fixture.
            let mut cx = Decls {
                names: &self.names,
                types: &self.types,
            };
            build_desc(&mut self.pool, &mut cx, root)
        }
    }

    struct Decls<'a> {
        names: &'a [String],
        types: &'a HashMap<TypeId, Nominal>,
    }

    impl WireCtx for Decls<'_> {
        fn nominal(&mut self, id: TypeId) -> Nominal {
            match self.types.get(&id) {
                Some(n) => n.clone(),
                // An id the test never declared is host-backed, which is what
                // an undeclared id means in a real compile too.
                None => Nominal::Bodiless,
            }
        }

        fn name(&self, s: StrId) -> String {
            self.names
                .get(s.0 as usize)
                .cloned()
                .unwrap_or_else(|| format!("?{}", s.0))
        }
    }

    fn refusal(r: Result<Desc, WireRefusal>) -> WireRefusal {
        match r {
            Ok(d) => panic!("expected a refusal, got a descriptor of {} nodes", d.len()),
            Err(e) => e,
        }
    }

    fn desc(r: Result<Desc, WireRefusal>) -> Desc {
        match r {
            Ok(d) => d,
            Err(e) => panic!(
                "expected a descriptor, refused: {:?} at {:?}",
                e.reason, e.path
            ),
        }
    }

    // --- the encodability table, accepting direction ---

    #[test]
    fn the_scalars_describe_as_themselves() {
        let mut f = Fixture::new();
        for (id, name, want) in [
            (INT, "Int", Node::Int),
            (FLOAT, "Float", Node::Float),
            (STRING, "String", Node::String),
            (BINARY, "Binary", Node::Binary),
        ] {
            let t = f.con(id, name, &[]);
            let d = desc(f.build(t));
            assert_eq!(d.node(d.root()), Some(&want), "{name}");
            assert_eq!(d.len(), 1, "{name} is one node");
        }
    }

    #[test]
    fn an_array_describes_its_element() {
        let mut f = Fixture::new();
        let int = f.int();
        let arr = f.con(ARRAY, "Array", &[int]);
        let d = desc(f.build(arr));
        let Some(&Node::Array(e)) = d.node(d.root()) else {
            panic!("root is not an Array: {:?}", d.node(d.root()))
        };
        assert_eq!(d.node(e), Some(&Node::Int));
    }

    #[test]
    fn a_map_describes_key_and_value_separately() {
        let mut f = Fixture::new();
        let int = f.int();
        let s = f.string();
        let m = f.con(MAP, "Map", &[s, int]);
        let d = desc(f.build(m));
        let Some(&Node::Map(k, v)) = d.node(d.root()) else {
            panic!("root is not a Map: {:?}", d.node(d.root()))
        };
        assert_eq!(d.node(k), Some(&Node::String));
        assert_eq!(d.node(v), Some(&Node::Int));
    }

    #[test]
    fn a_tuple_describes_its_elements_in_order() {
        let mut f = Fixture::new();
        let int = f.int();
        let s = f.string();
        let t = f.pool.mk_tuple(&[int, s]);
        let d = desc(f.build(t));
        let Some(Node::Tuple(es)) = d.node(d.root()) else {
            panic!("root is not a Tuple: {:?}", d.node(d.root()))
        };
        let es = es.clone();
        assert_eq!(es.len(), 2);
        assert_eq!(d.node(es[0]), Some(&Node::Int));
        assert_eq!(d.node(es[1]), Some(&Node::String));
    }

    #[test]
    fn a_data_type_describes_one_variant_per_constructor() {
        let mut f = Fixture::new();
        let int = f.int();
        let colour = TypeId(20);
        let red = f.ctor(colour, "Colour", 0, "Red", &[]);
        let shade = f.ctor(colour, "Colour", 1, "Shade", &[("level", int)]);
        f.data(colour, vec![red, shade]);

        let t = f.con(colour, "Colour", &[]);
        let d = desc(f.build(t));
        let Some(Node::Data(vs)) = d.node(d.root()) else {
            panic!("root is not Data: {:?}", d.node(d.root()))
        };
        let vs = vs.clone();
        assert_eq!(vs.len(), 2);
        assert_eq!(vs[0].variant.variant_idx, 0);
        assert!(vs[0].fields.is_empty(), "Red is nullary");
        assert_eq!(vs[1].variant.variant_idx, 1);
        assert_eq!(vs[1].fields.len(), 1);
        assert_eq!(d.node(vs[1].fields[0].node), Some(&Node::Int));
    }

    // --- the encodability table, refusing direction ---

    #[test]
    fn a_function_is_refused_for_its_captures_not_for_its_bytes() {
        let mut f = Fixture::new();
        let int = f.int();
        let fun = f.pool.mk_fun(&[int], int);
        let e = refusal(f.build(fun));
        assert_eq!(e.reason, Reason::Function);
        assert_eq!(e.ty, fun);
        // The corrected rationale: `fn` is refused because a closure's captures
        // are not fixed by its type, NOT because functions cannot be
        // serialised. Erlang's NEW_FUN_EXT does serialise them.
        assert!(
            !Reason::Function
                .describe()
                .contains("no wire representation"),
            "the refused-for-no-representation claim is false for `fn` and must not be quoted"
        );
        assert!(Reason::Function.describe().contains("captures"));
    }

    #[test]
    fn a_type_variable_is_refused() {
        let mut f = Fixture::new();
        let a = f.bound(0);
        let e = refusal(f.build(a));
        assert_eq!(e.reason, Reason::TypeVariable);
        assert!(
            e.path.is_empty(),
            "the described type is itself the refusal"
        );
    }

    #[test]
    fn a_bodiless_type_is_refused() {
        let mut f = Fixture::new();
        let pid = TypeId(30);
        f.types.insert(pid, Nominal::Bodiless);
        let t = f.con(pid, "Pid", &[]);
        let e = refusal(f.build(t));
        assert_eq!(e.reason, Reason::NoRepresentation);
    }

    #[test]
    fn an_opaque_type_is_refused_outside_its_module_and_allowed_inside() {
        let mut f = Fixture::new();
        let int = f.int();
        let dec = TypeId(31);
        let c = f.ctor(dec, "Decimal", 0, "Decimal", &[("units", int)]);

        f.types.insert(
            dec,
            Nominal::Data {
                ctors_public: false,
                declared_here: false,
                ctors: vec![c.clone()],
            },
        );
        let t = f.con(dec, "Decimal", &[]);
        assert_eq!(refusal(f.build(t)).reason, Reason::ConstructorsNotVisible);

        // Same type, same bit, asked from the module that declared it.
        f.types.insert(
            dec,
            Nominal::Data {
                ctors_public: false,
                declared_here: true,
                ctors: vec![c],
            },
        );
        let d = desc(f.build(t));
        assert!(matches!(d.node(d.root()), Some(Node::Data(_))));
    }

    /// `Socket { conn Connection, peer Address }` is not itself opaque — its
    /// constructors are public. It is unencodable because `Connection` is
    /// host-backed, and the refusal has to say so at the field.
    #[test]
    fn a_public_struct_over_a_host_backed_field_refuses_at_that_field() {
        let mut f = Fixture::new();
        let conn_id = TypeId(40);
        f.types.insert(conn_id, Nominal::Bodiless);
        let conn = f.con(conn_id, "Connection", &[]);

        let sock = TypeId(41);
        let c = f.ctor(sock, "Socket", 0, "Socket", &[("conn", conn)]);
        f.data(sock, vec![c]);

        let t = f.con(sock, "Socket", &[]);
        let e = refusal(f.build(t));
        assert_eq!(e.reason, Reason::NoRepresentation);
        assert_eq!(e.ty, conn);
        let cx = Decls {
            names: &f.names,
            types: &f.types,
        };
        assert_eq!(e.path_text(&cx), "Socket.conn");
    }

    // --- instantiation ---

    #[test]
    fn the_same_type_at_two_instantiations_gets_two_descriptors() {
        let mut f = Fixture::new();
        let a = f.bound(0);
        let opt = TypeId(50);
        let none = f.ctor(opt, "Option", 0, "None", &[]);
        let some = f.ctor(opt, "Option", 1, "Some", &[("value", a)]);
        f.data(opt, vec![none, some]);

        let int = f.int();
        let s = f.string();
        let opt_int = f.con(opt, "Option", &[int]);
        let opt_str = f.con(opt, "Option", &[s]);

        let di = desc(f.build(opt_int));
        let ds = desc(f.build(opt_str));

        let field_node = |d: &Desc| {
            let Some(Node::Data(vs)) = d.node(d.root()) else {
                panic!("not Data")
            };
            let n = vs[1].fields[0].node;
            d.node(n).cloned()
        };
        assert_eq!(field_node(&di), Some(Node::Int));
        assert_eq!(field_node(&ds), Some(Node::String));
        assert_ne!(di, ds, "Option(Int) and Option(String) are different types");
    }

    #[test]
    fn a_nested_generic_instantiates_through_the_spine() {
        let mut f = Fixture::new();
        let a = f.bound(0);
        let opt = TypeId(50);
        let none = f.ctor(opt, "Option", 0, "None", &[]);
        let some = f.ctor(opt, "Option", 1, "Some", &[("value", a)]);
        f.data(opt, vec![none, some]);

        let int = f.int();
        let arr_int = f.con(ARRAY, "Array", &[int]);
        let t = f.con(opt, "Option", &[arr_int]);

        let d = desc(f.build(t));
        let Some(Node::Data(vs)) = d.node(d.root()) else {
            panic!("not Data")
        };
        let inner = vs[1].fields[0].node;
        let Some(&Node::Array(e)) = d.node(inner) else {
            panic!("Some.value is not an Array: {:?}", d.node(inner))
        };
        assert_eq!(d.node(e), Some(&Node::Int));
    }

    // --- recursion and interning ---

    #[test]
    fn a_recursive_type_points_back_at_its_own_node() {
        let mut f = Fixture::new();
        let a = f.bound(0);
        let list = TypeId(60);
        let list_a = f.con(list, "List", &[a]);
        let nil = f.ctor(list, "List", 0, "Nil", &[]);
        let cons = f.ctor(list, "List", 1, "Cons", &[("head", a), ("tail", list_a)]);
        f.data(list, vec![nil, cons]);

        let int = f.int();
        let list_int = f.con(list, "List", &[int]);
        let d = desc(f.build(list_int));

        let Some(Node::Data(vs)) = d.node(d.root()) else {
            panic!("not Data")
        };
        let tail = vs[1].fields[1].node;
        assert_eq!(
            tail,
            d.root(),
            "Cons.tail must be the List(Int) node itself, not a copy"
        );
        // Two nodes only: Int and List(Int). An unrolled descriptor would grow
        // without bound.
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn identical_types_share_one_node() {
        let mut f = Fixture::new();
        let int = f.int();
        // Two distinct RTys that denote the same type: the pool does not
        // hash-cons, so this is the case interning has to catch.
        let int_again = f.int();
        assert_ne!(int, int_again, "the pool minted two nodes");
        let t = f.pool.mk_tuple(&[int, int_again]);
        let d = desc(f.build(t));
        let Some(Node::Tuple(es)) = d.node(d.root()) else {
            panic!("not a Tuple")
        };
        assert_eq!(es[0], es[1], "one Int node, referenced twice");
        assert_eq!(d.len(), 2, "Int and the tuple");
    }

    // --- the path a refusal carries ---

    #[test]
    fn a_refusal_three_levels_down_names_the_full_field_path() {
        let mut f = Fixture::new();
        let int = f.int();
        let bad = f.pool.mk_fun(&[int], int);

        let inner = TypeId(70);
        let ic = f.ctor(inner, "Inner", 0, "Inner", &[("f", bad)]);
        f.data(inner, vec![ic]);
        let inner_t = f.con(inner, "Inner", &[]);

        let middle = TypeId(71);
        let mc = f.ctor(middle, "Middle", 0, "Middle", &[("inner", inner_t)]);
        f.data(middle, vec![mc]);
        let middle_t = f.con(middle, "Middle", &[]);

        let outer = TypeId(72);
        let oc = f.ctor(outer, "Outer", 0, "Outer", &[("mid", middle_t)]);
        f.data(outer, vec![oc]);
        let outer_t = f.con(outer, "Outer", &[]);

        let e = refusal(f.build(outer_t));
        assert_eq!(e.reason, Reason::Function);
        assert_eq!(e.ty, bad, "the refusal names the offending sub-type");

        let cx = Decls {
            names: &f.names,
            types: &f.types,
        };
        assert_eq!(e.path_text(&cx), "Outer.mid -> Middle.inner -> Inner.f");
    }

    #[test]
    fn a_refusal_inside_a_container_names_the_position() {
        let mut f = Fixture::new();
        let int = f.int();
        let bad = f.pool.mk_fun(&[int], int);
        let arr = f.con(ARRAY, "Array", &[bad]);
        let m = f.con(MAP, "Map", &[int, arr]);
        let t = f.pool.mk_tuple(&[int, m]);

        let e = refusal(f.build(t));
        let cx = Decls {
            names: &f.names,
            types: &f.types,
        };
        assert_eq!(e.path_text(&cx), "[1] -> [value] -> [element]");
    }

    /// Two constructors of one type may each have a field called `value`, so
    /// the path names the variant as well as the label.
    #[test]
    fn a_path_step_names_its_variant() {
        let mut f = Fixture::new();
        let int = f.int();
        let bad = f.pool.mk_fun(&[int], int);
        let e_id = TypeId(80);
        let good = f.ctor(e_id, "Either", 0, "Left", &[("value", int)]);
        let evil = f.ctor(e_id, "Either", 1, "Right", &[("value", bad)]);
        f.data(e_id, vec![good, evil]);
        let t = f.con(e_id, "Either", &[]);

        let e = refusal(f.build(t));
        let cx = Decls {
            names: &f.names,
            types: &f.types,
        };
        assert_eq!(e.path_text(&cx), "Right.value");
    }

    // --- aliases ---

    #[test]
    fn an_alias_is_looked_through_and_adds_no_path_step() {
        let mut f = Fixture::new();
        let int = f.int();
        let name = TypeId(90);
        f.types.insert(name, Nominal::Alias(int));
        let t = f.con(name, "Name", &[]);
        let d = desc(f.build(t));
        assert_eq!(d.node(d.root()), Some(&Node::Int));
    }

    #[test]
    fn an_alias_to_an_unencodable_type_refuses_at_the_target() {
        let mut f = Fixture::new();
        let int = f.int();
        let bad = f.pool.mk_fun(&[int], int);
        let handler = TypeId(91);
        f.types.insert(handler, Nominal::Alias(bad));
        let t = f.con(handler, "Handler", &[]);
        let e = refusal(f.build(t));
        assert_eq!(e.reason, Reason::Function);
        assert!(e.path.is_empty(), "an alias is a spelling, not a level");
    }

    #[test]
    fn a_generic_alias_instantiates_its_target() {
        let mut f = Fixture::new();
        let a = f.bound(0);
        let arr_a = f.con(ARRAY, "Array", &[a]);
        let bag = TypeId(92);
        f.types.insert(bag, Nominal::Alias(arr_a));
        let s = f.string();
        let t = f.con(bag, "Bag", &[s]);
        let d = desc(f.build(t));
        let Some(&Node::Array(e)) = d.node(d.root()) else {
            panic!("not an Array")
        };
        assert_eq!(d.node(e), Some(&Node::String));
    }

    // --- the fingerprint ---

    /// Declare `type <ty_name> { ctors... }` at `id` and return its
    /// fingerprint.
    ///
    /// Every test below is two calls to this with **exactly one argument
    /// different**, so what moved the fingerprint is named by the call and not
    /// by a comment. Each property gets its own test: a single "different
    /// shapes differ" assertion would pass on a fingerprint that ignored names
    /// entirely.
    fn fp(f: &mut Fixture, id: TypeId, ty_name: &str, ctors: &[(&str, &[(&str, RTy)])]) -> u64 {
        let mut decls = Vec::new();
        for (i, (name, fields)) in ctors.iter().enumerate() {
            decls.push(f.ctor(id, ty_name, i as u16, name, fields));
        }
        f.data(id, decls);
        let t = f.con(id, ty_name, &[]);
        desc(f.build(t)).fingerprint()
    }

    /// The shape the sensitivity tests vary away from:
    /// `type Colour { Red, Shade(level Int) }`.
    fn colour(f: &mut Fixture, id: TypeId, ty_name: &str) -> u64 {
        let int = f.int();
        fp(
            f,
            id,
            ty_name,
            &[("Red", &[]), ("Shade", &[("level", int)])],
        )
    }

    const C1: TypeId = TypeId(100);
    const C2: TypeId = TypeId(101);

    /// The stability half of the DONE-WHEN, one layer below `dis`: the
    /// fingerprint may not depend on how the names happened to be interned.
    ///
    /// This is what a two-compile `dis` test would catch and the only part of
    /// it reachable before elaboration emits the constant (ticket 7). A second
    /// compile meets identifiers in a different order, so `StrId(4)` is a
    /// different string in each — a fingerprint folding `StrId.0` rather than
    /// the name text passes every other test in this file and fails here.
    #[test]
    fn the_fingerprint_survives_a_different_interning_order() {
        let mut a = Fixture::new();
        let fa = colour(&mut a, C1, "Colour");

        let mut b = Fixture::new();
        for junk in ["parse", "render", "Shade", "level", "Red"] {
            b.intern(junk);
        }
        let fb = colour(&mut b, C1, "Colour");

        // Without this the test is vacuous: if both compiles gave the names the
        // same ids, a StrId-folding fingerprint would pass it too.
        assert_ne!(
            a.intern("Shade"),
            b.intern("Shade"),
            "premise: the two compiles must disagree about Shade's StrId"
        );
        assert_eq!(fa, fb, "the same shape, interned differently");
    }

    #[test]
    fn the_fingerprint_is_the_same_on_a_second_build_of_one_type() {
        let mut f = Fixture::new();
        assert_eq!(colour(&mut f, C1, "Colour"), colour(&mut f, C1, "Colour"));
    }

    #[test]
    fn renaming_a_constructor_changes_the_fingerprint() {
        let mut f = Fixture::new();
        let int = f.int();
        let before = fp(&mut f, C1, "Colour", &[("Shade", &[("level", int)])]);
        let after = fp(&mut f, C1, "Colour", &[("Tint", &[("level", int)])]);
        assert_ne!(before, after);
    }

    #[test]
    fn reordering_variants_changes_the_fingerprint() {
        let mut f = Fixture::new();
        let int = f.int();
        let before = fp(
            &mut f,
            C1,
            "Colour",
            &[("Red", &[]), ("Shade", &[("level", int)])],
        );
        let after = fp(
            &mut f,
            C1,
            "Colour",
            &[("Shade", &[("level", int)]), ("Red", &[])],
        );
        assert_ne!(before, after);
    }

    #[test]
    fn adding_a_field_changes_the_fingerprint() {
        let mut f = Fixture::new();
        let int = f.int();
        let before = fp(&mut f, C1, "Colour", &[("Shade", &[("level", int)])]);
        let after = fp(
            &mut f,
            C1,
            "Colour",
            &[("Shade", &[("level", int), ("alpha", int)])],
        );
        assert_ne!(before, after);
    }

    #[test]
    fn changing_a_field_type_changes_the_fingerprint() {
        let mut f = Fixture::new();
        let int = f.int();
        let s = f.string();
        let before = fp(&mut f, C1, "Colour", &[("Shade", &[("level", int)])]);
        let after = fp(&mut f, C1, "Colour", &[("Shade", &[("level", s)])]);
        assert_ne!(before, after);
    }

    #[test]
    fn renaming_a_field_changes_the_fingerprint() {
        let mut f = Fixture::new();
        let int = f.int();
        let before = fp(&mut f, C1, "Colour", &[("Shade", &[("level", int)])]);
        let after = fp(&mut f, C1, "Colour", &[("Shade", &[("lvl", int)])]);
        assert_ne!(before, after);
    }

    /// The type's own name is not part of its shape, so renaming it is not a
    /// schema change and peers keep talking.
    #[test]
    fn renaming_the_type_does_not_change_the_fingerprint() {
        let mut f = Fixture::new();
        let before = colour(&mut f, C1, "Colour");
        let after = colour(&mut f, C1, "Hue");
        assert_eq!(before, after);
    }

    /// Moving a declaration to another module mints a new `TypeId`. The
    /// fingerprint must not notice — this is the property that keeps a module
    /// reshuffle from reading as a wire break at every peer.
    #[test]
    fn moving_the_type_to_another_module_does_not_change_the_fingerprint() {
        let mut f = Fixture::new();
        let before = colour(&mut f, C1, "Colour");
        let after = colour(&mut f, C2, "Colour");
        assert_eq!(before, after);
    }

    /// The interoperability claim in the module doc, asserted: two programs
    /// that never shared a declaration agree, because they agree on the shape.
    #[test]
    fn the_same_shape_declared_twice_gets_one_fingerprint() {
        let mut mine = Fixture::new();
        let a = colour(&mut mine, C1, "Colour");

        let mut theirs = Fixture::new();
        let b = colour(&mut theirs, C2, "Paint");

        assert_eq!(a, b, "same constructors, same labels, same field types");
    }

    /// The headline claim of the algorithm: children are folded as indices, so
    /// a cyclic descriptor terminates — a fingerprint that descended into
    /// `Cons.tail` would not return from this test at all.
    ///
    /// Terminating is half of it. The other half is that the element type is
    /// still reached, which `List(Int)` against `List(String)` is what asserts:
    /// a hash that stopped at the cycle would give these two one value.
    #[test]
    fn a_recursive_type_fingerprints_without_recursing() {
        let mut f = Fixture::new();
        let a = f.bound(0);
        let list = TypeId(110);
        let list_a = f.con(list, "List", &[a]);
        let nil = f.ctor(list, "List", 0, "Nil", &[]);
        let cons = f.ctor(list, "List", 1, "Cons", &[("head", a), ("tail", list_a)]);
        f.data(list, vec![nil, cons]);

        let int = f.int();
        let s = f.string();
        let li = f.con(list, "List", &[int]);
        let ls = f.con(list, "List", &[s]);

        let fi = desc(f.build(li)).fingerprint();
        assert_eq!(fi, desc(f.build(li)).fingerprint(), "stable");
        assert_ne!(
            fi,
            desc(f.build(ls)).fingerprint(),
            "List(Int) vs List(String)"
        );
    }

    /// A phantom parameter still has to be encodable: encodability is a
    /// property of the type, not of which parameters its constructors read.
    #[test]
    fn an_unused_type_argument_is_still_described() {
        let mut f = Fixture::new();
        let int = f.int();
        let bad = f.pool.mk_fun(&[int], int);
        let ph = TypeId(93);
        let c = f.ctor(ph, "Phantom", 0, "Phantom", &[("n", int)]);
        f.data(ph, vec![c]);
        let t = f.con(ph, "Phantom", &[bad]);
        assert_eq!(refusal(f.build(t)).reason, Reason::Function);
    }
}

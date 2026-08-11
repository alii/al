//! Byte codec for lowered Core IR: what lets the precompiled stdlib ship each
//! body's ANF tree in the static blob instead of re-lowering the whole stdlib
//! from source on every startup.
//!
//! The format is a plain depth-first walk — tag byte per enum variant, LEB128
//! varints for indices, zigzag for signed — with no framing beyond what the
//! structure implies. It is not a stable interchange format: encoder and
//! decoder ship in the same binary (build.rs runs this crate to produce the
//! blob the same crate later reads), so a format change is invisible outside
//! one build. Corruption is loud: every decode path returns [`DecodeError`]
//! rather than guessing.
//!
//! Consumed today by the round-trip tests alone; the blob emitter in
//! `build.rs` and the lazy-hydration path land on top of this, which is why
//! the module carries a dead-code allowance instead of `cfg(test)`.
#![allow(dead_code)]
//!
//! `RTy` fields ride through as opaque `u32`s. They index a `ResolvedPool`
//! that died at build time, and nothing downstream of planning reads them —
//! the plan records `reprs`/`proofs` precisely so codegen never needs the
//! pool. Decoding them back is fidelity, not meaning.

use scarlet_vm::bytecode::Op;
use scarlet_vm::bytecode::value::HeapTag;

use super::emit::{CtorHeader, FrameLayout};
use super::{
    Atom, Callee, ConstId, CoreBind, CoreExpr, CoreFn, CorePat, FuncIdx, Imm, JoinId, LocalId,
    ReuseShape, VariantRef,
};
use crate::tivec::Idx;
use crate::type_def::TypeId;
use crate::typed_ir::{GlobalSlot, RTy};
use crate::types::StrId;

/// Why a blob failed to decode. Every variant means the blob and this build's
/// codec disagree — a build.rs/runtime version skew or corruption, never a
/// program-dependent condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended inside a value.
    Truncated,
    /// A varint ran past its maximum width.
    Overlong,
    /// An enum tag byte no variant carries. Names the enum.
    BadTag(&'static str, u8),
    /// Bytes remained after the value was fully decoded.
    TrailingBytes,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "core-ir blob truncated"),
            DecodeError::Overlong => write!(f, "core-ir blob varint overlong"),
            DecodeError::BadTag(what, b) => {
                write!(f, "core-ir blob carries no {what} variant for tag {b}")
            }
            DecodeError::TrailingBytes => write!(f, "core-ir blob has trailing bytes"),
        }
    }
}

type Result<T> = std::result::Result<T, DecodeError>;

// --- primitives -----------------------------------------------------------

struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    fn new() -> Enc {
        Enc { buf: Vec::new() }
    }

    fn u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    /// LEB128.
    fn u64(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(b);
                return;
            }
            self.buf.push(b | 0x80);
        }
    }

    fn u32(&mut self, v: u32) {
        self.u64(u64::from(v));
    }

    fn usize(&mut self, v: usize) {
        self.u64(v as u64);
    }

    /// Zigzag + LEB128.
    fn i64(&mut self, v: i64) {
        self.u64(((v << 1) ^ (v >> 63)) as u64);
    }

    fn i32(&mut self, v: i32) {
        self.i64(i64::from(v));
    }

    fn bool(&mut self, v: bool) {
        self.u8(u8::from(v));
    }
}

struct Dec<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Dec<'a> {
    fn new(buf: &'a [u8]) -> Dec<'a> {
        Dec { buf, at: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.at).ok_or(DecodeError::Truncated)?;
        self.at += 1;
        Ok(b)
    }

    fn u64(&mut self) -> Result<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            if shift >= 64 {
                return Err(DecodeError::Overlong);
            }
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }

    fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.u64()?).map_err(|_| DecodeError::Overlong)
    }

    fn usize(&mut self) -> Result<usize> {
        usize::try_from(self.u64()?).map_err(|_| DecodeError::Overlong)
    }

    fn i64(&mut self) -> Result<i64> {
        let z = self.u64()?;
        Ok(((z >> 1) as i64) ^ -((z & 1) as i64))
    }

    fn i32(&mut self) -> Result<i32> {
        i32::try_from(self.i64()?).map_err(|_| DecodeError::Overlong)
    }

    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(DecodeError::BadTag("bool", b)),
        }
    }

    fn finish(self) -> Result<()> {
        if self.at == self.buf.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

// --- Core IR --------------------------------------------------------------

fn enc_local(e: &mut Enc, id: LocalId) {
    e.usize(id.index());
}

fn dec_local(d: &mut Dec) -> Result<LocalId> {
    Ok(LocalId::from_usize(d.usize()?))
}

fn enc_bind(e: &mut Enc, b: &CoreBind) {
    enc_local(e, b.id);
    e.u32(b.ty.0);
    match b.global {
        None => e.u8(0),
        Some(GlobalSlot(s)) => {
            e.u8(1);
            e.i32(s);
        }
    }
}

fn dec_bind(d: &mut Dec) -> Result<CoreBind> {
    let id = dec_local(d)?;
    let ty = RTy(d.u32()?);
    let global = match d.u8()? {
        0 => None,
        1 => Some(GlobalSlot(d.i32()?)),
        b => return Err(DecodeError::BadTag("Option<GlobalSlot>", b)),
    };
    Ok(CoreBind { id, ty, global })
}

fn enc_variant(e: &mut Enc, v: &VariantRef) {
    e.i32(v.type_id.0);
    e.u32(u32::from(v.variant_idx));
    e.u32(v.type_name.0);
    e.u32(v.variant_name.0);
}

fn dec_variant(d: &mut Dec) -> Result<VariantRef> {
    Ok(VariantRef {
        type_id: TypeId(d.i32()?),
        variant_idx: d.u32()? as u16,
        type_name: StrId(d.u32()?),
        variant_name: StrId(d.u32()?),
    })
}

fn enc_locals(e: &mut Enc, xs: &[LocalId]) {
    e.usize(xs.len());
    for &x in xs {
        enc_local(e, x);
    }
}

fn dec_locals(d: &mut Dec) -> Result<Vec<LocalId>> {
    let n = d.usize()?;
    let mut out = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        out.push(dec_local(d)?);
    }
    Ok(out)
}

fn enc_imm(e: &mut Enc, imm: &Imm) {
    match imm {
        Imm::None => e.u8(0),
        Imm::Index(i) => {
            e.u8(1);
            e.u32(u32::from(*i));
        }
        Imm::Argc(n) => {
            e.u8(2);
            e.u32(*n);
        }
        Imm::Const(c) => {
            e.u8(3);
            e.u32(c.0);
        }
        Imm::PushedDefault => e.u8(4),
    }
}

fn dec_imm(d: &mut Dec) -> Result<Imm> {
    Ok(match d.u8()? {
        0 => Imm::None,
        1 => Imm::Index(d.u32()? as u16),
        2 => Imm::Argc(d.u32()?),
        3 => Imm::Const(ConstId(d.u32()?)),
        4 => Imm::PushedDefault,
        b => return Err(DecodeError::BadTag("Imm", b)),
    })
}

fn enc_atom(e: &mut Enc, a: &Atom) {
    match a {
        Atom::Local(x) => {
            e.u8(0);
            enc_local(e, *x);
        }
        Atom::Const(c) => {
            e.u8(1);
            e.u32(c.0);
        }
        Atom::Ctor {
            variant,
            fields,
            reuse,
        } => {
            e.u8(2);
            enc_variant(e, variant);
            enc_locals(e, fields);
            match reuse {
                None => e.u8(0),
                Some(r) => {
                    e.u8(1);
                    enc_local(e, *r);
                }
            }
        }
        Atom::PrimOp { op, args, imm } => {
            e.u8(3);
            e.u8(*op as u8);
            enc_locals(e, args);
            enc_imm(e, imm);
        }
        Atom::Closure { func_idx, captures } => {
            e.u8(4);
            e.usize(func_idx.index());
            enc_locals(e, captures);
        }
        Atom::Call { callee, args } => {
            e.u8(5);
            match callee {
                Callee::Known(f) => {
                    e.u8(0);
                    e.usize(f.index());
                }
                Callee::Self_ => e.u8(1),
                Callee::Local(x) => {
                    e.u8(2);
                    enc_local(e, *x);
                }
            }
            enc_locals(e, args);
        }
    }
}

fn dec_atom(d: &mut Dec) -> Result<Atom> {
    Ok(match d.u8()? {
        0 => Atom::Local(dec_local(d)?),
        1 => Atom::Const(ConstId(d.u32()?)),
        2 => {
            let variant = dec_variant(d)?;
            let fields = dec_locals(d)?;
            let reuse = match d.u8()? {
                0 => None,
                1 => Some(dec_local(d)?),
                b => return Err(DecodeError::BadTag("Option<reuse>", b)),
            };
            Atom::Ctor {
                variant,
                fields,
                reuse,
            }
        }
        3 => {
            let op_byte = d.u8()?;
            let Some(op) = Op::from_u8(op_byte) else {
                return Err(DecodeError::BadTag("Op", op_byte));
            };
            let args = dec_locals(d)?;
            let imm = dec_imm(d)?;
            Atom::PrimOp { op, args, imm }
        }
        4 => Atom::Closure {
            func_idx: FuncIdx::from_usize(d.usize()?),
            captures: dec_locals(d)?,
        },
        5 => {
            let callee = match d.u8()? {
                0 => Callee::Known(FuncIdx::from_usize(d.usize()?)),
                1 => Callee::Self_,
                2 => Callee::Local(dec_local(d)?),
                b => return Err(DecodeError::BadTag("Callee", b)),
            };
            Atom::Call {
                callee,
                args: dec_locals(d)?,
            }
        }
        b => return Err(DecodeError::BadTag("Atom", b)),
    })
}

fn enc_pat(e: &mut Enc, p: &CorePat) {
    match p {
        CorePat::Wild => e.u8(0),
        CorePat::Bind(b) => {
            e.u8(1);
            enc_bind(e, b);
        }
        CorePat::Lit(c) => {
            e.u8(2);
            e.u32(c.0);
        }
        CorePat::Ctor { variant, fields } => {
            e.u8(3);
            enc_variant(e, variant);
            e.usize(fields.len());
            for f in fields {
                enc_bind(e, f);
            }
        }
    }
}

fn dec_pat(d: &mut Dec) -> Result<CorePat> {
    Ok(match d.u8()? {
        0 => CorePat::Wild,
        1 => CorePat::Bind(dec_bind(d)?),
        2 => CorePat::Lit(ConstId(d.u32()?)),
        3 => {
            let variant = dec_variant(d)?;
            let n = d.usize()?;
            let mut fields = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                fields.push(dec_bind(d)?);
            }
            CorePat::Ctor { variant, fields }
        }
        b => return Err(DecodeError::BadTag("CorePat", b)),
    })
}

fn enc_expr(e: &mut Enc, x: &CoreExpr) {
    match x {
        CoreExpr::Let { bind, rhs, body } => {
            e.u8(0);
            enc_bind(e, bind);
            enc_atom(e, rhs);
            enc_expr(e, body);
        }
        CoreExpr::LetJoin { bind, join, body } => {
            e.u8(1);
            enc_bind(e, bind);
            enc_expr(e, join);
            enc_expr(e, body);
        }
        CoreExpr::LetCont { id, cont, body } => {
            e.u8(2);
            e.usize(id.index());
            enc_expr(e, cont);
            enc_expr(e, body);
        }
        CoreExpr::Drop { local, shape, body } => {
            e.u8(3);
            enc_local(e, *local);
            match shape {
                None => e.u8(0),
                Some(s) => {
                    e.u8(1);
                    // The only shape Perceus mints today; the decoder rejects
                    // anything else, so a new shape fails the round-trip test
                    // instead of decoding wrong.
                    e.u8(s.tag as u8);
                    e.u32(u32::from(s.words));
                }
            }
            enc_expr(e, body);
        }
        CoreExpr::Match { scrut, arms, ty } => {
            e.u8(4);
            enc_local(e, *scrut);
            e.u32(ty.0);
            e.usize(arms.len());
            for (p, b) in arms {
                enc_pat(e, p);
                enc_expr(e, b);
            }
        }
        CoreExpr::If {
            cond,
            then,
            els,
            ty,
        } => {
            e.u8(5);
            enc_local(e, *cond);
            e.u32(ty.0);
            enc_expr(e, then);
            enc_expr(e, els);
        }
        CoreExpr::Tail(a) => {
            e.u8(6);
            enc_atom(e, a);
        }
        CoreExpr::Goto(j) => {
            e.u8(7);
            e.usize(j.index());
        }
    }
}

fn dec_expr(d: &mut Dec) -> Result<CoreExpr> {
    Ok(match d.u8()? {
        0 => CoreExpr::Let {
            bind: dec_bind(d)?,
            rhs: dec_atom(d)?,
            body: Box::new(dec_expr(d)?),
        },
        1 => CoreExpr::LetJoin {
            bind: dec_bind(d)?,
            join: Box::new(dec_expr(d)?),
            body: Box::new(dec_expr(d)?),
        },
        2 => CoreExpr::LetCont {
            id: JoinId::from_usize(d.usize()?),
            cont: Box::new(dec_expr(d)?),
            body: Box::new(dec_expr(d)?),
        },
        3 => {
            let local = dec_local(d)?;
            let shape = match d.u8()? {
                0 => None,
                1 => {
                    let tag = match d.u8()? {
                        t if t == HeapTag::Enum as u8 => HeapTag::Enum,
                        b => return Err(DecodeError::BadTag("ReuseShape tag", b)),
                    };
                    let words = d.u32()? as u16;
                    Some(ReuseShape { tag, words })
                }
                b => return Err(DecodeError::BadTag("Option<ReuseShape>", b)),
            };
            CoreExpr::Drop {
                local,
                shape,
                body: Box::new(dec_expr(d)?),
            }
        }
        4 => {
            let scrut = dec_local(d)?;
            let ty = RTy(d.u32()?);
            let n = d.usize()?;
            let mut arms = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                let p = dec_pat(d)?;
                let b = dec_expr(d)?;
                arms.push((p, b));
            }
            CoreExpr::Match { scrut, arms, ty }
        }
        5 => CoreExpr::If {
            cond: dec_local(d)?,
            ty: RTy(d.u32()?),
            then: Box::new(dec_expr(d)?),
            els: Box::new(dec_expr(d)?),
        },
        6 => CoreExpr::Tail(dec_atom(d)?),
        7 => CoreExpr::Goto(JoinId::from_usize(d.usize()?)),
        b => return Err(DecodeError::BadTag("CoreExpr", b)),
    })
}

// --- whole bodies ---------------------------------------------------------

/// Encode one lowered body.
pub(crate) fn encode_fn(f: &CoreFn) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(f.name.0);
    e.u32(f.ret_ty.0);
    e.usize(f.params.len());
    for p in &f.params {
        enc_bind(&mut e, p);
    }
    enc_expr(&mut e, &f.body);
    e.buf
}

/// Decode one lowered body. The blob must be exactly one [`encode_fn`] image.
pub(crate) fn decode_fn(buf: &[u8]) -> Result<CoreFn> {
    let mut d = Dec::new(buf);
    let name = StrId(d.u32()?);
    let ret_ty = RTy(d.u32()?);
    let n = d.usize()?;
    let mut params = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        params.push(dec_bind(&mut d)?);
    }
    let body = dec_expr(&mut d)?;
    d.finish()?;
    Ok(CoreFn {
        name,
        params,
        body,
        ret_ty,
    })
}

/// Encode the frame layout `emit` fixed for a body.
fn encode_layout(l: &FrameLayout) -> Vec<u8> {
    let mut e = Enc::new();
    e.usize(l.slots.len());
    for i in 0..l.slots.len() {
        match l.slots.get(LocalId::from_usize(i)).copied().flatten() {
            None => e.u8(0),
            Some(slot) => {
                e.u8(1);
                e.i32(slot);
            }
        }
    }
    e.usize(l.ctor_headers.len());
    for h in &l.ctor_headers {
        e.i32(h.packed);
        e.i32(h.enum_name);
        e.i32(h.variant_name);
        e.i32(h.labels);
        e.bool(h.reuse);
    }
    e.buf
}

/// Decode a [`FrameLayout`]. The blob must be exactly one [`encode_layout`]
/// image.
fn decode_layout(buf: &[u8]) -> Result<FrameLayout> {
    let mut d = Dec::new(buf);
    let n = d.usize()?;
    let mut slots = crate::tivec::TiVec::new();
    for _ in 0..n {
        let s = match d.u8()? {
            0 => None,
            1 => Some(d.i32()?),
            b => return Err(DecodeError::BadTag("Option<slot>", b)),
        };
        slots.push(s);
    }
    let n = d.usize()?;
    let mut ctor_headers = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        ctor_headers.push(CtorHeader {
            packed: d.i32()?,
            enum_name: d.i32()?,
            variant_name: d.i32()?,
            labels: d.i32()?,
            reuse: d.bool()?,
        });
    }
    d.finish()?;
    Ok(FrameLayout {
        slots,
        ctor_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind(i: usize) -> CoreBind {
        CoreBind {
            id: LocalId::from_usize(i),
            ty: RTy(7),
            global: if i == 0 { Some(GlobalSlot(3)) } else { None },
        }
    }

    /// A body touching every node kind once, round-tripped and compared via
    /// the golden renderer — the same notion of equality the `.core`
    /// snapshots use.
    #[test]
    fn every_node_kind_round_trips() {
        let variant = VariantRef {
            type_id: TypeId(6656),
            variant_idx: 2,
            type_name: StrId(11),
            variant_name: StrId(12),
        };
        let l = |i: usize| LocalId::from_usize(i);
        let body = CoreExpr::LetCont {
            id: JoinId::from_usize(0),
            cont: Box::new(CoreExpr::Goto(JoinId::from_usize(0))),
            body: Box::new(CoreExpr::Let {
                bind: bind(2),
                rhs: Atom::PrimOp {
                    op: Op::AddInt,
                    args: vec![l(0), l(1)],
                    imm: Imm::None,
                },
                body: Box::new(CoreExpr::LetJoin {
                    bind: bind(3),
                    join: Box::new(CoreExpr::If {
                        cond: l(2),
                        ty: RTy(7),
                        then: Box::new(CoreExpr::Tail(Atom::Const(ConstId(4)))),
                        els: Box::new(CoreExpr::Tail(Atom::Ctor {
                            variant,
                            fields: vec![l(0)],
                            reuse: Some(l(1)),
                        })),
                    }),
                    body: Box::new(CoreExpr::Drop {
                        local: l(3),
                        shape: Some(ReuseShape {
                            tag: HeapTag::Enum,
                            words: 1,
                        }),
                        body: Box::new(CoreExpr::Match {
                            scrut: l(2),
                            ty: RTy(7),
                            arms: vec![
                                (
                                    CorePat::Ctor {
                                        variant,
                                        fields: vec![bind(4)],
                                    },
                                    CoreExpr::Tail(Atom::Call {
                                        callee: Callee::Known(FuncIdx::from_usize(9)),
                                        args: vec![l(4)],
                                    }),
                                ),
                                (CorePat::Lit(ConstId(5)), CoreExpr::Tail(Atom::Local(l(2)))),
                                (
                                    CorePat::Bind(bind(5)),
                                    CoreExpr::Tail(Atom::Closure {
                                        func_idx: FuncIdx::from_usize(1),
                                        captures: vec![l(5)],
                                    }),
                                ),
                                (
                                    CorePat::Wild,
                                    CoreExpr::Tail(Atom::Call {
                                        callee: Callee::Self_,
                                        args: vec![l(2)],
                                    }),
                                ),
                            ],
                        }),
                    }),
                }),
            }),
        };
        let f = CoreFn {
            name: StrId(1),
            params: vec![bind(0), bind(1)],
            body,
            ret_ty: RTy(7),
        };
        let bytes = encode_fn(&f);
        let back = decode_fn(&bytes).expect("round trip decodes");
        assert_eq!(format!("{f}"), format!("{back}"));
    }

    #[test]
    fn layout_round_trips() {
        let mut slots = crate::tivec::TiVec::new();
        slots.push(Some(0));
        slots.push(None);
        slots.push(Some(5));
        let l = FrameLayout {
            slots,
            ctor_headers: vec![CtorHeader {
                packed: 30,
                enum_name: 31,
                variant_name: 32,
                labels: 33,
                reuse: true,
            }],
        };
        let back = decode_layout(&encode_layout(&l)).expect("round trip decodes");
        for i in 0..3 {
            let id = LocalId::from_usize(i);
            assert_eq!(
                back.slots.get(id).copied().flatten(),
                l.slots.get(id).copied().flatten()
            );
        }
        assert_eq!(back.ctor_headers.len(), 1);
        assert_eq!(back.ctor_headers[0].packed, 30);
        assert!(back.ctor_headers[0].reuse);
    }

    #[test]
    fn corrupt_blobs_fail_loudly() {
        let f = CoreFn {
            name: StrId(1),
            params: vec![],
            body: CoreExpr::Tail(Atom::Const(ConstId(0))),
            ret_ty: RTy(7),
        };
        let mut bytes = encode_fn(&f);
        // Truncation.
        assert!(decode_fn(&bytes[..bytes.len() - 1]).is_err());
        // Trailing garbage.
        bytes.push(0);
        assert!(matches!(decode_fn(&bytes), Err(DecodeError::TrailingBytes)));
        // A tag no enum carries.
        assert!(matches!(
            decode_fn(&[0, 7, 0, 250]),
            Err(DecodeError::BadTag(..) | DecodeError::Truncated)
        ));
    }
}

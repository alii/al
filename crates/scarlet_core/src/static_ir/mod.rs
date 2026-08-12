//! Static-stdlib representation: the runtime-value side (`SFunction`/`SConst`,
//! whose live counterparts carry `Rc`s), the per-module export tables, and the
//! `StaticStdlib` handle bundling every pool slice for `seed_static`.
//!
//! The type IR has no S-prefixed mirror: `Scheme`, `TypeInfo`, `Variant` and
//! friends are already `Copy` and const-constructible, so the precompiled
//! stdlib emits them directly as `&'static [_]`.

pub mod flatten;

use std::marker::PhantomData;
use std::sync::Arc;

use crate::bytecode::{Function, Instruction, PreludeBindings, Value};
use crate::frozen::FrozenBuilder;
use crate::module::{ExportedType, ExportedValue, ModuleInterface};
use crate::type_def::TypeId;
// build.rs Debug-prints `Some(GlobalSlot(n))` into the generated stdlib file,
// which glob-imports this module.
pub use crate::typed_ir::GlobalSlot;
use crate::types::{
    DefinitionLocation, QuantVar, Scheme, StrId, Ty, TypeInfo, TypeNode, TypeParam, Variant,
    VariantField,
};

/// Index into [`StaticStdlib::str_pool`]. Not interchangeable with a `StrId`:
/// `str_pool` extends `engine.strings` with names interned while flattening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StrIdx(pub u32);

/// Index into [`StaticStdlib::schemes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemeIdx(pub u32);

/// Index into [`StaticStdlib::typeinfos`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeInfoIdx(pub u32);

/// Half-open `[start, start+len)` index into the pool of `T`, so a slice can
/// only index the pool it was minted against. Differs from `ArenaSlice` only
/// in len width: string-slice pools can exceed 65 535 entries.
#[derive(Debug)]
pub struct Slice<T> {
    pub start: u32,
    pub len: u32,
    _marker: PhantomData<T>,
}

// Manual, because a derive would bound `T: Clone`/`T: Copy`.
impl<T> Clone for Slice<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Slice<T> {}

impl<T> Slice<T> {
    #[inline]
    pub const fn new(start: u32, len: u32) -> Self {
        Slice {
            start,
            len,
            _marker: PhantomData,
        }
    }

    #[inline]
    fn range(self) -> std::ops::Range<usize> {
        self.start as usize..self.start as usize + self.len as usize
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SExport {
    pub name: StrIdx,
    pub scheme: SchemeIdx,
    pub local_slot: Option<GlobalSlot>,
    /// The function's parameter names, in order.
    pub param_names: Slice<StrIdx>,
    /// The declaration's doc comment, if it has one.
    pub doc: Option<StrIdx>,
}

#[derive(Debug, Clone, Copy)]
pub struct STypeExport {
    pub name: StrIdx,
    pub info: TypeInfoIdx,
    /// The `type` declaration's location, so hydrated stdlib modules get the
    /// same reference-graph `Definition`s as source modules.
    pub def: Option<DefinitionLocation>,
    /// The declaration's doc comment.
    pub doc: Option<StrIdx>,
}

/// One name a precompiled module exports, as a name list wants it. Borrows
/// the static pools, so listing a module allocates nothing but the `Vec`.
#[derive(Debug, Clone)]
pub struct StaticExport {
    pub name: &'static str,
    /// A function's parameter names, in order; empty for a non-function.
    pub params: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct SModule {
    pub types: Slice<STypeExport>,
    pub values: Slice<SExport>,
    pub private_names: Slice<StrIdx>,
    pub path: Slice<StrIdx>,
    /// The module-level doc comment. Declaration docs live on [`SExport::doc`].
    pub doc: Option<StrIdx>,
}

#[derive(Debug, Clone, Copy)]
pub struct SFunction {
    pub name: StrIdx,
    pub arity: i32,
    pub locals: i32,
    pub capture_count: i32,
    pub code_start: i32,
    pub code_len: i32,
}

#[derive(Debug, Clone, Copy)]
pub enum SConst {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(StrIdx),
    StrArray(Slice<StrIdx>),
    /// A binary literal: bytes in `byte_pool`, plus its logical bit length.
    Binary(Slice<u8>, u64),
}

/// Single handle bundling every static pool.
#[derive(Debug, Clone, Copy)]
pub struct StaticStdlib {
    pub str_pool: &'static [&'static str],
    pub str_slice_pool: &'static [StrIdx],
    pub byte_pool: &'static [u8],

    /// The type arena and side-pools, in the live engine's own types, so
    /// `seed_static` is a memcpy.
    pub nodes: &'static [TypeNode],
    pub children: &'static [Ty],
    pub quants: &'static [QuantVar],
    pub str_slices: &'static [StrId],
    pub type_params: &'static [TypeParam],
    pub variant_fields: &'static [VariantField],
    pub variants: &'static [Variant],

    pub schemes: &'static [Scheme],
    pub typeinfos: &'static [TypeInfo],

    pub stypeexport_pool: &'static [STypeExport],
    pub sexport_pool: &'static [SExport],
    pub modules: &'static [(&'static str, SModule)],
    pub typeinfo_by_name: &'static [(&'static str, TypeInfoIdx)],

    pub code: &'static [Instruction],
    pub functions: &'static [SFunction],
    pub constants: &'static [SConst],

    pub prelude: &'static PreludeBindings,
    pub reserved: &'static [&'static str],
    pub next_type_id: TypeId,
    pub local_count: i32,
}

impl StaticStdlib {
    #[inline]
    fn s(&self, i: StrIdx) -> String {
        self.str_pool[i.0 as usize].to_string()
    }
    #[inline]
    fn modpath(&self, sl: Slice<StrIdx>) -> Vec<String> {
        self.str_slice_pool[sl.range()]
            .iter()
            .map(|&i| self.s(i))
            .collect()
    }

    fn hydrate_module(&self, m: &SModule) -> ModuleInterface {
        let mut iface = ModuleInterface::new(self.modpath(m.path));
        for te in &self.stypeexport_pool[m.types.range()] {
            iface.types.insert(
                self.s(te.name),
                ExportedType {
                    info: self.typeinfos[te.info.0 as usize],
                    def: te.def,
                    doc: te.doc.map(|i| self.s(i)),
                },
            );
        }
        for e in &self.sexport_pool[m.values.range()] {
            iface.values.insert(
                self.s(e.name),
                ExportedValue {
                    scheme: self.schemes[e.scheme.0 as usize],
                    local_slot: e.local_slot,
                    param_names: self.str_slice_pool[e.param_names.range()]
                        .iter()
                        .map(|&i| self.s(i))
                        .collect(),
                    doc: e.doc.map(|i| self.s(i)),
                },
            );
        }
        for &i in &self.str_slice_pool[m.private_names.range()] {
            iface.private_names.insert(self.s(i));
        }
        iface.doc = m.doc.map(|i| self.s(i));
        iface
    }

    /// Every precompiled module's key (`scarlet`, `scarlet/string`, ...), in
    /// key order.
    pub fn module_keys(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.modules.iter().map(|(k, _)| *k)
    }

    /// What `key`'s module exports, types first. For name lists (REPL
    /// completion, `--list`): reading the pools directly costs nothing,
    /// where [`lookup_module`](Self::lookup_module) rebuilds the whole
    /// interface. Empty for an unknown key.
    pub fn exports(&self, key: &str) -> Vec<StaticExport> {
        let Ok(i) = self.modules.binary_search_by_key(&key, |(k, _)| k) else {
            return Vec::new();
        };
        let m = &self.modules[i].1;
        let mut out: Vec<StaticExport> = Vec::new();
        for te in &self.stypeexport_pool[m.types.range()] {
            out.push(StaticExport {
                name: self.str_pool[te.name.0 as usize],
                params: Vec::new(),
            });
            // A constructor is written `module.Ctor` exactly like a value
            // export, so a name list that omitted them would be lying about
            // what the module offers.
            out.extend(self.constructors(te.info));
        }
        out.extend(self.sexport_pool[m.values.range()].iter().map(|e| {
            StaticExport {
                name: self.str_pool[e.name.0 as usize],
                params: self.str_slice_pool[e.param_names.range()]
                    .iter()
                    .map(|&i| self.str_pool[i.0 as usize])
                    .collect(),
            }
        }));
        // One name, one entry: a record type names its single constructor
        // after itself, and a type re-exported beside its own declaration
        // reaches here twice.
        let mut seen = std::collections::HashSet::new();
        out.retain(|e| seen.insert(e.name));
        out
    }

    /// The constructors of an exported type, with their field labels.
    fn constructors(&self, info: TypeInfoIdx) -> Vec<StaticExport> {
        let Some(variants) = self
            .typeinfos
            .get(info.0 as usize)
            .and_then(TypeInfo::variants)
        else {
            return Vec::new();
        };
        let start = variants.start as usize;
        self.variants[start..start + variants.len as usize]
            .iter()
            .filter_map(|v| {
                let fields = v.fields;
                let from = fields.start as usize;
                Some(StaticExport {
                    name: self.str_pool.get(v.name.idx()).copied()?,
                    params: self.variant_fields[from..from + fields.len as usize]
                        .iter()
                        .filter_map(|f| self.str_pool.get(f.label.idx()).copied())
                        .collect(),
                })
            })
            .collect()
    }

    pub(crate) fn lookup_module(&self, key: &str) -> Option<ModuleInterface> {
        self.modules
            .binary_search_by_key(&key, |(k, _)| k)
            .ok()
            .map(|i| self.hydrate_module(&self.modules[i].1))
    }

    /// Hydrate the precompiled stdlib's code/functions/constants into live
    /// form. Constants go through `frozen` so strings and label lists intern
    /// to the same allocations as the rest of the program.
    pub(crate) fn hydrate_program(
        &self,
        frozen: &mut FrozenBuilder,
    ) -> (Vec<Instruction>, Vec<Function>, Vec<Value>) {
        let code = self.code.to_vec();
        let functions: Vec<Function> = self
            .functions
            .iter()
            .map(|f| Function {
                name: Arc::from(self.str_pool[f.name.0 as usize]),
                arity: f.arity,
                locals: f.locals,
                capture_count: f.capture_count,
                code_start: f.code_start,
                code_len: f.code_len,
            })
            .collect();
        let constants: Vec<Value> = self
            .constants
            .iter()
            .map(|c| {
                match *c {
                    SConst::Int(n) => frozen.int(n),
                    SConst::Float(f) => frozen.float(f),
                    SConst::Bool(b) => frozen.bool(b),
                    SConst::Str(i) => frozen.str(self.str_pool[i.0 as usize]),
                    SConst::StrArray(sl) => {
                        let strs: Vec<&str> = self.str_slice_pool[sl.range()]
                            .iter()
                            .map(|&i| self.str_pool[i.0 as usize])
                            .collect();
                        frozen.str_array(&strs)
                    }
                    SConst::Binary(sl, bit_len) => {
                        frozen.binary_bits(self.byte_pool[sl.range()].to_vec(), bit_len)
                    }
                }
                .into_value()
            })
            .collect();
        (code, functions, constants)
    }
}

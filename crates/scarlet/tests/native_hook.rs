//! `bytecode::compile_with_native` fires its hook once per lowered function
//! body, at the one point where the body's post-perceus `CoreFn` and the
//! `ResolvedPool` its `RTy`s index are both alive, keyed by the same
//! `FuncIdx` numbering as `Program.functions`. Installing a hook must not
//! perturb that numbering.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::parse;
use scarlet::tivec::Idx;
use scarlet::types::Prim;

/// What the hook recorded for one body. The prims are resolved inside the
/// hook, through the pool it arrived with: an `RTy` indexes a per-body pool,
/// so a wrong or dropped pool panics or misresolves right there.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    idx: usize,
    arity: usize,
    param_prims: Vec<Option<Prim>>,
    ret_prim: Option<Prim>,
}

fn compile_recording(source: &str) -> (scarlet::bytecode::Program, Vec<Seen>) {
    let ast = parse(source);
    let seen = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&seen);
    let hook: scarlet::bytecode::NativeHook = Box::new(move |idx, f, pool| {
        sink.borrow_mut().push(Seen {
            idx: idx.index(),
            arity: f.params.len(),
            param_prims: f.params.iter().map(|b| pool.prim_of(b.ty)).collect(),
            ret_prim: pool.prim_of(f.ret_ty),
        });
    });
    let result = scarlet::bytecode::compile_with_native(&ast, None, Some(&scarlet::STDLIB), hook);
    assert!(
        result.success(),
        "compile failed:\n{source}\n{:#?}",
        result.diagnostics
    );
    let program = result.emitted.expect("compile emits").program;
    // The compiler dropped its `NativeHook` box, so the recording is ours.
    let seen = Rc::try_unwrap(seen).expect("hook released").into_inner();
    (program, seen)
}

const SOURCE: &str = r#"
fn add(a Int, b Int) Int {
    a + b
}

fn twice(x Int) Int {
    add(x, x)
}

twice(4)
"#;

#[test]
fn hook_fires_per_body_keyed_by_program_func_idx() {
    let (program, seen) = compile_recording(SOURCE);

    let mut idxs: Vec<usize> = seen.iter().map(|s| s.idx).collect();
    idxs.sort_unstable();
    idxs.dedup();
    assert_eq!(
        idxs.len(),
        seen.len(),
        "one hook call per FuncIdx: {seen:#?}"
    );

    for s in &seen {
        let f = &program.functions[s.idx];
        assert_eq!(
            f.arity as usize, s.arity,
            "hooked body {} disagrees with its Function entry on arity",
            f.name
        );
    }

    let name_of = |s: &Seen| program.functions[s.idx].name.to_string();
    // Stdlib bodies precede the user program and the stdlib has its own
    // `add`, so the user's bodies are the last bearers of these names.
    let add = seen
        .iter()
        .rfind(|s| name_of(s) == "add")
        .expect("hook saw `add`");
    let twice = seen
        .iter()
        .rfind(|s| name_of(s) == "twice")
        .expect("hook saw `twice`");

    // The RTys resolved through the pool the hook was handed.
    assert_eq!(add.param_prims, vec![Some(Prim::Int), Some(Prim::Int)]);
    assert_eq!(add.ret_prim, Some(Prim::Int));
    assert_eq!(twice.param_prims, vec![Some(Prim::Int)]);
    assert_eq!(twice.ret_prim, Some(Prim::Int));
}

#[test]
fn installing_the_hook_does_not_perturb_fn_numbering() {
    let (hooked, _) = compile_recording(SOURCE);

    let ast = parse(SOURCE);
    let plain = scarlet::bytecode::compile(&ast, None, Some(&scarlet::STDLIB));
    assert!(plain.success(), "compile failed: {:#?}", plain.diagnostics);
    let plain = plain.emitted.expect("compile emits").program;

    let shape = |p: &scarlet::bytecode::Program| -> Vec<(String, i32, i32)> {
        p.functions
            .iter()
            .map(|f| (f.name.to_string(), f.arity, f.capture_count))
            .collect()
    };
    assert_eq!(shape(&hooked), shape(&plain));
}

#[test]
fn toplevel_glue_is_never_hooked() {
    let (program, seen) = compile_recording(SOURCE);
    let entry = program.entry as usize;
    assert_eq!(&*program.functions[entry].name, "__main__");
    assert!(
        seen.iter().all(|s| s.idx != entry),
        "`__main__` is always-interpreted glue and must not reach the hook"
    );
}

/// Seeding is unconditional now: a hooked compile of a user program must show
/// the hook only the user's own bodies (the stdlib arrives pre-lowered in the
/// static blob), and every blob bundle must hydrate against the seeded
/// program — one decodable bundle per stdlib function, none past the table.
#[test]
fn seeded_compile_hooks_only_user_bodies_and_every_bundle_hydrates() {
    let src = r#"
import scarlet/array
import scarlet/string

fn double(x Int) Int { x * 2 }

println(array.length(array.map([1, 2, 3], double)))
println(string.length('hello'))
"#;
    let (program, seen) = compile_recording(src);
    // The user file lowers `double`, the toplevel, and nothing of the stdlib.
    assert!(
        seen.len() < 10,
        "the hook saw {} bodies; the stdlib must come from the seed, not a relower",
        seen.len()
    );
    let stdlib_fn_count = scarlet::STDLIB.functions.len();
    for s in &seen {
        assert!(
            s.idx >= stdlib_fn_count,
            "hooked body fn#{} is inside the seeded stdlib prefix",
            s.idx
        );
    }

    // Every stdlib body the seed ships has exactly one bundle, and each
    // decodes into a plan whose function renders non-trivially.
    assert_eq!(
        scarlet::STDLIB_CORE_INDEX.len(),
        stdlib_fn_count,
        "bundle count must match the seeded function table"
    );
    for (i, (idx, start, len)) in scarlet::STDLIB_CORE_INDEX.iter().enumerate() {
        assert_eq!(*idx as usize, i, "bundle index must be dense and sorted");
        let bytes = &scarlet::STDLIB_CORE_BYTES[*start as usize..(*start + *len) as usize];
        let fi = <scarlet_vm::FuncIdx as scarlet_core::tivec::Idx>::from_usize(i);
        let (plan, _layout) =
            scarlet::core_ir::clif::decode_plan_bundle(fi, bytes, scarlet::STDLIB.prelude)
                .unwrap_or_else(|e| panic!("bundle for fn#{i} failed to decode: {e}"));
        assert_eq!(plan.func_idx, fi);
    }
    // And the seeded program is what actually ran above.
    assert!(program.functions.len() >= stdlib_fn_count);
}

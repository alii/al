//! `al check` and `al build` must agree on the shape of the program they
//! elaborate: same functions, same indices, same capture counts.
//!
//! `check_only` truncates the pipeline in one place (`elaborate_body` returns
//! before `perceus`/`emit`) and elides the toplevel init and the peephole
//! pass. Everything upstream — including which `Function` slot a body owns —
//! is mode-independent, which is what these tests pin.

mod common;
use common::{Project, parse};

/// `(name, arity, capture_count)`, one per registered function.
type FnShape = Vec<(String, i32, i32)>;

/// Every registered function's `(name, arity, capture_count)`, in index
/// order. `code_start`/`code_len`/`locals` are excluded: those are the emit
/// half, which `check` legitimately leaves empty.
fn fn_shape(p: &scarlet::bytecode::Program) -> FnShape {
    p.functions
        .iter()
        .map(|f| (f.name.to_string(), f.arity, f.capture_count))
        .collect()
}

/// Compile and check the same AST; return each mode's function table shape.
fn both(source: &str) -> (FnShape, FnShape) {
    let ast = parse(source);
    let built = scarlet::bytecode::compile(&ast, None, Some(&scarlet::STDLIB));
    assert!(
        built.success(),
        "compile failed:\n{source}\n{:#?}",
        built.diagnostics
    );
    let checked = scarlet::bytecode::check(&ast, None, Some(&scarlet::STDLIB));
    assert!(
        checked.success(),
        "check failed:\n{source}\n{:#?}",
        checked.diagnostics
    );
    let built = built.into_runnable().expect("compile emits").program;
    let checked = checked
        .into_artifacts()
        .expect("check registers the function table");
    (fn_shape(&built), fn_shape(&checked.program))
}

#[test]
fn check_and_compile_register_the_same_functions() {
    let (built, checked) = both(
        r#"
fn add(a, b) {
	a + b
}
fn twice(x) {
	add(x, x)
}
pub fn main() {
	println(twice(21))
}
"#,
    );
    assert_eq!(built, checked);
    let names: Vec<&str> = built.iter().map(|(n, _, _)| n.as_str()).collect();
    assert!(names.contains(&"add"), "{names:?}");
    assert!(names.contains(&"twice"), "{names:?}");
    // The program's `main` is a function like any other; only `compile` goes
    // on to call it from the entry frame.
    assert!(names.contains(&"main"), "{names:?}");
}

/// A nested closure's `func_idx` is what `Atom::Closure` carries, so both
/// modes must reserve the lambda's slot identically.
#[test]
fn check_and_compile_agree_on_nested_closures() {
    let (built, checked) = both(
        r#"
fn adder(n) {
	fn(x) {
		x + n
	}
}
pub fn main() {
	add3 = adder(3)
	println(add3(4))
}
"#,
    );
    assert_eq!(built, checked);
    assert!(
        built.iter().any(|(_, _, caps)| *caps == 1),
        "no capturing function registered: {built:?}"
    );
}

/// An eta-wrapper (`Some` used as a value) is synthesised by `lower`, which
/// runs in both modes, so its `Function` entry exists in both at one index.
#[test]
fn check_and_compile_agree_on_eta_wrappers() {
    let (built, checked) = both(
        r#"import scarlet/array
type W { W(v Int) }
pub fn main() {
	xs = [1, 2, 3]
	ws = array.map(xs, W)
	println(array.length(ws))
}
"#,
    );
    assert_eq!(built, checked);
    assert!(
        built.iter().any(|(n, _, _)| n == "W"),
        "no eta-wrapper registered: {built:?}"
    );
}

/// Mutual recursion parks both bodies in one SCC. Their reserved slots must
/// survive that round trip identically in both modes.
#[test]
fn check_and_compile_agree_on_mutually_recursive_scc() {
    let (built, checked) = both(
        r#"
fn is_even(n) {
	if n == 0 {
		True
	} else {
		is_odd(n - 1)
	}
}
fn is_odd(n) {
	if n == 0 {
		False
	} else {
		is_even(n - 1)
	}
}
pub fn main() {
	println(is_even(10))
}
"#,
    );
    assert_eq!(built, checked);
}

/// A function's code region as `[start, end)`, its trailing `Ret` inside it —
/// `None` for a `Function` nothing was emitted for.
///
/// `code_len` spans the trailing `Ret`, so the stored range is the region.
/// This used to widen it by reading a `Ret` at the stored end as this
/// function's own, which was how it straddled the two conventions; that
/// reading would now annex the first instruction of whatever follows.
fn code_region(f: &scarlet::bytecode::Function) -> Option<(i32, i32)> {
    (f.code_start >= 0 && f.code_len > 0).then_some((f.code_start, f.code_start + f.code_len))
}

/// `base_of[pc]` is the `code_start` the operand at `code[pc]` resolves
/// against. Jump operands are frame-relative, so a bare `ins.operand` is not a
/// `program.code` index; this table turns it into one. Code spliced around the
/// bodies (jump-overs, the toplevel init) runs in the entry frame, base 0.
fn frame_bases(p: &scarlet::bytecode::Program) -> Vec<i32> {
    let entry = p.entry as usize;
    let len = p.code.len();
    let mut base_of = vec![0i32; len];
    for (i, f) in p.functions.iter().enumerate() {
        if i == entry {
            continue;
        }
        let Some((start, end)) = code_region(f) else {
            continue;
        };
        let lo = (start as usize).min(len);
        let hi = (end as usize).min(len);
        base_of[lo..hi].fill(start);
    }
    base_of
}

/// Regions do not overlap. `frame_bases` fills each body's base over its own
/// range, so two regions that overlapped would resolve one body's jumps
/// against the other's frame. This is what says so.
fn assert_bodies_are_disjoint(p: &scarlet::bytecode::Program, bodies: &[(usize, i32, i32)]) {
    let mut by_start = bodies.to_vec();
    by_start.sort_by_key(|&(_, start, _)| start);
    for w in by_start.windows(2) {
        let ((a, _, a_end), (b, b_start, _)) = (w[0], w[1]);
        assert!(
            a_end <= b_start,
            "function {a} ({}) ends at {a_end}, past the start of function {b} ({}) at {b_start}",
            p.functions[a].name,
            p.functions[b].name,
        );
    }
}

/// Every function body is a closed region: nothing outside it may jump in. A
/// deferral region emits all of an SCC's jump-overs before any of its bodies
/// (`[J_a, J_b, body_a, Ret, body_b, Ret]`), so a jump-over patched to "just
/// past my own `Ret`" lands inside the next body. Nothing else in the suite
/// looks at code layout, and the toplevel init overwrites the first jump-over,
/// hiding wrong targets behind dead code.
fn assert_no_jump_into_a_foreign_body(p: &scarlet::bytecode::Program) {
    let entry = p.entry as usize;
    let bodies: Vec<(usize, i32, i32)> = p
        .functions
        .iter()
        .enumerate()
        // The entry's own body *is* the code the toplevel `Jump base` targets,
        // and its region is the whole stream every other one sits inside.
        .filter(|(i, _)| *i != entry)
        .filter_map(|(i, f)| code_region(f).map(|(start, end)| (i, start, end)))
        .collect();
    assert!(!bodies.is_empty(), "no bodies to guard");
    assert_bodies_are_disjoint(p, &bodies);
    let base_of = frame_bases(p);
    // Guards the guard: without at least one jump-over spanning a body the
    // assertion below is trivially true.
    let mut skips = 0;
    for (pc, ins) in p.code.iter().enumerate() {
        if !matches!(ins.op, scarlet::bytecode::Op::Jump) {
            continue;
        }
        let target = base_of[pc] + ins.operand;
        // Pin the address space first: an absolute operand inside a body would
        // overshoot the stream and land in no body, which the check below would
        // wave through.
        assert!(
            target >= 0 && (target as usize) < p.code.len(),
            "Jump at {pc} resolves to {target}, outside code[0, {})",
            p.code.len(),
        );
        let pc = pc as i32;
        for &(idx, start, end) in &bodies {
            let inside = pc >= start && pc < end;
            let targets = target >= start && target < end;
            assert!(
                inside || !targets,
                "Jump at {pc} targets {target} — inside function {idx} ({}), whose body is [{start}, {end})",
                p.functions[idx].name,
            );
            if pc < start && target >= end {
                skips += 1;
            }
        }
    }
    assert!(skips > 0, "no jump-over spans a function body");
}

/// An SCC emits both bodies back to back, so `ping`'s jump-over must skip
/// `pong`'s body too. The closure pins the same for a body parked inside an
/// SCC member, emitted ahead of both.
#[test]
fn jump_overs_skip_every_body_parked_beside_them() {
    let ast = parse(
        r#"
fn ping(n) {
	if n == 0 {
		0
	} else {
		1 + pong(n - 1)
	}
}
fn pong(n) {
	if n == 0 {
		0
	} else {
		1 + ping(n - 1)
	}
}
fn outer(n) {
	bump = fn(x) {
		x + 1
	}
	bump(ping(n))
}
pub fn main() {
	println(outer(4))
}
"#,
    );
    let built = scarlet::bytecode::compile(&ast, None, Some(&scarlet::STDLIB));
    assert!(built.success(), "{:#?}", built.diagnostics);
    let built = built.into_runnable().expect("compile emits").program;
    assert_no_jump_into_a_foreign_body(&built);
}

/// Compile `source` against the stdlib and hand back the emitted program.
fn layout_of(source: &str) -> scarlet::bytecode::Program {
    let ast = parse(source);
    let built = scarlet::bytecode::compile(&ast, None, Some(&scarlet::STDLIB));
    assert!(
        built.success(),
        "compile failed:\n{source}\n{:#?}",
        built.diagnostics
    );
    built.into_runnable().expect("compile emits").program
}

/// A constructor named without being called is eta-expanded into a wrapper
/// function, and a wrapper minted for a *function body* is written inside the
/// deferral region, immediately ahead of the body that named it. Its jump-over
/// therefore has the whole rest of the region behind it, not just its own
/// `Ret`: patched to its own end it lands on `wrap`'s first instruction.
#[test]
fn an_eta_wrapper_in_a_body_clears_the_whole_region() {
    assert_no_jump_into_a_foreign_body(&layout_of(
        r#"import scarlet/array
type W { W(v Int) }
fn wrap(xs) {
	array.map(xs, W)
}
pub fn main() {
	println(array.length(wrap([1, 2, 3])))
}
"#,
    ));
}

/// The same shape reached through a `@vm` builtin as a value. It is one bug,
/// not two: `ValueKind::Builtin` and `ValueKind::Constructor` both eta-expand,
/// and it is where the wrapper is written — inside the region — that decides
/// the jump-over's target.
#[test]
fn an_eta_wrapper_over_a_builtin_clears_the_whole_region() {
    assert_no_jump_into_a_foreign_body(&layout_of(
        r#"import scarlet/array
import scarlet/string
fn lens(xs) {
	array.map(xs, string.length)
}
pub fn main() {
	println(array.length(lens(['ab', 'cde'])))
}
"#,
    ));
}

/// The other splice, which the region patch must leave alone: a wrapper the
/// *toplevel* named — which, now that a program's module scope holds only
/// declarations, means one named by a `const` initializer — is written after
/// the region has drained, ahead of the toplevel init, so "just past my own
/// `Ret`" names the next wrapper's jump-over or the init — never a body. That
/// is the `None` arm, and this pins it.
///
/// It does not witness the jump being *taken*, and neither do the two above: no
/// jump-over in either splice is reachable, because `append_toplevel_init`
/// overwrites the head of the region with a `Jump` to the init. What all three
/// pin is the layout.
#[test]
fn an_eta_wrapper_at_the_toplevel_is_spliced_past_every_body() {
    assert_no_jump_into_a_foreign_body(&layout_of(
        r#"import scarlet/array
type W { W(v Int) }
fn ident(n) {
	n
}
const ws = array.map([1, 2, 3], W)
pub fn main() {
	println(array.length(ws) + ident(1))
}
"#,
    ));
}

/// [`layout_of`] for a program that imports from a project directory, so the
/// emitted stream carries an imported module's region as well as the entry's.
fn layout_in(proj: &Project, source: &str) -> scarlet::bytecode::Program {
    let ast = parse(source);
    let built = scarlet::bytecode::compile(&ast, Some(&proj.dir), Some(&scarlet::STDLIB));
    assert!(
        built.success(),
        "compile failed:\n{source}\n{:#?}",
        built.diagnostics
    );
    built.into_runnable().expect("compile emits").program
}

/// A module's leading jump-over is what `append_toplevel_init` overwrites, and
/// that write is in place — so the instruction at `code_mark` is destroyed
/// whatever owns it. A module declaring no function and no module-scope lambda
/// parks no body, so the walk emits no jump-over of its own and the leading eta
/// wrapper's is the only expendable instruction at the mark.
///
/// Stop emitting it and the overwrite lands on the wrapper's first real
/// instruction: its `Function.code_start` slides onto the mark, the absolute
/// `Jump base` written there resolves against the wrapper's own frame, and the
/// address-space pin in [`assert_no_jump_into_a_foreign_body`] is what reports
/// it. The three tests above cannot reach this shape — they are single-file,
/// and an entry file needs `pub fn main`, whose jump-over takes the mark first.
///
/// Watched failing with the wrapper's jump-over suppressed. It does not witness
/// the jump being taken; none of them do (T-192).
#[test]
fn a_module_that_declares_no_body_keeps_its_leading_jump_over() {
    let proj = Project::new("eta_no_decl");
    proj.write(
        "lib.scrl",
        "import scarlet/array\n\npub type W {\n\tW(v Int)\n}\n\npub const ws = array.map([1, 2, 3], W)\n",
    );
    assert_no_jump_into_a_foreign_body(&layout_in(
        &proj,
        "import ./lib\nimport scarlet/array\n\npub fn main() {\n\tprintln(array.length(lib.ws))\n}\n",
    ));
}

/// The blind spot the three tests above cannot reach: a `Jump` landing exactly
/// on a body's final `Ret` is a jump into that body, and is caught only
/// because `code_len` spans the `Ret`. While a declared body's stopped one
/// instruction short, this read as outside every body and was waved through —
/// one instruction per body. Nothing the compiler emits aims there, so the
/// witness is planted rather than compiled.
///
/// The victim is a *declared* body because that is the half that was blind;
/// an eta wrapper's `code_len` spanned its `Ret` throughout.
#[test]
#[should_panic(expected = "inside function")]
fn a_jump_onto_a_foreign_bodys_final_ret_is_caught() {
    let mut p = layout_of(
        r#"
fn a(n) {
	n + 1
}
fn b(n) {
	a(n) + 1
}
pub fn main() {
	println(b(2))
}
"#,
    );
    let entry = p.entry as usize;
    // Name the victim's closing `Ret` without going through `code_len`, which
    // is the thing under test: a `code_len`-derived target tracks whatever
    // `code_len` currently means and lands inside the region either way, so
    // the plant would witness nothing. Bodies in a drain region are laid out
    // back to back, so the instruction before the next body's `code_start` is
    // the previous one's `Ret` — and the `Ret` check below is what says the
    // two really are adjacent rather than separated by a jump-over.
    let mut starts: Vec<i32> = p
        .functions
        .iter()
        .enumerate()
        .filter(|(i, f)| *i != entry && f.code_start >= 0 && f.code_len > 0)
        .map(|(_, f)| f.code_start)
        .collect();
    starts.sort_unstable();
    starts.dedup();
    let (start, ret) = starts
        .windows(2)
        .map(|w| (w[0], w[1] - 1))
        .find(|&(_, ret)| {
            p.code
                .get(ret as usize)
                .is_some_and(|ins| matches!(ins.op, scarlet::bytecode::Op::Ret))
        })
        .expect("two back-to-back declared bodies, the first closing with a Ret");
    let base_of = frame_bases(&p);
    let jump = (0..p.code.len())
        .find(|&pc| {
            matches!(p.code[pc].op, scarlet::bytecode::Op::Jump)
                && base_of[pc] == 0
                && (pc as i32) < start
        })
        .expect("a jump-over ahead of the body");
    // Base 0, so the operand is the absolute target.
    p.code[jump].operand = ret;
    assert_no_jump_into_a_foreign_body(&p);
}

/// The entry point is the entry frame (`__main__`), the last function either
/// mode registers — not the program's own `main`, which the entry frame
/// calls and which is registered like any other declaration.
#[test]
fn check_and_compile_agree_on_the_entry_index() {
    let ast = parse("fn f(x) {\n\tx\n}\npub fn main() {\n\tprintln(f(1))\n}\n");
    let built = scarlet::bytecode::compile(&ast, None, Some(&scarlet::STDLIB));
    let checked = scarlet::bytecode::check(&ast, None, Some(&scarlet::STDLIB));
    assert!(built.success() && checked.success());
    let built = built.into_runnable().expect("compile emits").program;
    let checked = checked
        .into_artifacts()
        .expect("check registers the function table");
    assert_eq!(built.entry, checked.program.entry);
    assert_eq!(&*built.functions[built.entry as usize].name, "__main__");
}

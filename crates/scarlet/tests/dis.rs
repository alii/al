//! `al dis` — the compiled bytecode as text.
//!
//! The property that matters is that every jump target lands inside its own
//! function. Jump operands are function-relative (the VM assigns one straight
//! to `ip`), so an out-of-range target means `emit` produced a jump into
//! another function's code.

mod common;

use scarlet::bytecode::{self, Op};
use scarlet::dis;
use scarlet::{STDLIB, ast, parser, scanner};

fn program_of(src: &str) -> bytecode::Program {
    let mut sc = scanner::new_scanner(src.to_string());
    let p = parser::new_parser(&mut sc);
    let parsed = p.parse_program();
    let expr = ast::Expression::BlockExpression(parsed.ast);
    let r = bytecode::compile(&expr, None, Some(&STDLIB));
    assert!(r.success(), "compile failed: {:?}", r.diagnostics);
    r.into_runnable()
        .expect("a successful compile emits")
        .program
}

const FACT: &str = "fn fact(n Int) Int {\n\tif n < 2 { 1 } else { n * fact(n - 1) }\n}\n\n\
                    pub fn main() {\n\tprintln(fact(5))\n}\n";

#[test]
fn a_function_disassembles_with_its_header_and_body() {
    let p = program_of(FACT);
    let text = dis::disassemble_fn(&p, "fact");
    assert!(text.contains("fact (arity 1, locals 2)"), "{text}");
    assert!(
        text.contains("CallSelf"),
        "the self-recursive call:\n{text}"
    );
    assert!(text.contains("Ret"), "{text}");
}

/// A `PushConst` operand indexes `constants` directly, so it renders its value.
#[test]
fn a_constant_push_shows_its_value() {
    let p = program_of(FACT);
    let text = dis::disassemble_fn(&p, "fact");
    let line = text
        .lines()
        .find(|l| l.contains("PushConst"))
        .unwrap_or_else(|| panic!("no PushConst:\n{text}"));
    assert!(line.contains("; 1"), "constant not rendered: {line}");
}

/// Zero is a real slot and a real constant id. Suppressing it would make
/// `PushLocal` (slot 0) look like it had no operand at all.
#[test]
fn a_zero_operand_is_printed_not_hidden() {
    let p = program_of(FACT);
    let text = dis::disassemble_fn(&p, "fact");
    assert!(
        text.lines()
            .any(|l| l.contains("PushLocal") && l.contains("op=0")),
        "a zero operand must print:\n{text}"
    );
}

/// `code_len - 1` is the merge point of an `if` whose arms both return: a
/// legal target, landing on the body's own terminator.
#[test]
fn every_jump_target_is_inside_its_own_function() {
    for src in [
        FACT,
        "fn pick(n Int) Int {\n\tm = if n < 2 { 1 } else { 2 }\n\tm + 1\n}\n\
         pub fn main() {\n\tprintln(pick(5))\n}\n",
        "import scarlet/array\ntype W {\n\tW(v Int)\n}\n\
         fn go(xs Array(Int)) Int {\n\tws = array.map(xs, W)\n\tif array.length(ws) > 2 { 111 } else { 222 }\n}\n\
         pub fn main() {\n\tprintln(go([1]))\n}\n",
        "fn cls(n Int) Int {\n\tmatch n {\n\t\t0 -> 1\n\t\t1 -> 2\n\t\t_ -> 3\n\t}\n}\n\
         pub fn main() {\n\tprintln(cls(1))\n}\n",
        // A branch inside `main` itself: `main` is an ordinary function the
        // entry glue calls by index, so its jumps are relative to its own body.
        "pub fn main() {\n\tn = 5\n\tprintln(if n < 2 { 1 } else { 2 })\n}\n",
    ] {
        let p = program_of(src);
        for f in &p.functions {
            let start = f.code_start as usize;
            let end = start + f.code_len as usize;
            for (ip, instr) in p.code[start..end].iter().enumerate() {
                if !instr.op.has_jump_target() {
                    continue;
                }
                assert!(
                    instr.operand >= 0 && instr.operand < f.code_len,
                    "fn {} @{ip}: {:?} jumps to {} outside 0..{}",
                    f.name,
                    instr.op,
                    instr.operand,
                    f.code_len
                );
            }
        }
    }
}

/// `--fn` exists because the stdlib compiles into the same program: without it
/// a two-line file disassembles 160-odd functions.
#[test]
fn the_fn_filter_selects_one_function() {
    let p = program_of(FACT);
    let all = dis::disassemble(&p);
    let one = dis::disassemble_fn(&p, "fact");
    assert!(
        all.len() > one.len() * 10,
        "the filter must actually filter"
    );
    assert!(one.contains("fact"), "{one}");
    assert!(
        !one.contains("constants:"),
        "a filtered dump omits the pool"
    );
}

/// The whole program renders, including the constant pool.
#[test]
fn the_full_dump_carries_a_constant_pool() {
    let p = program_of(FACT);
    let text = dis::disassemble(&p);
    assert!(text.starts_with("; "), "header first:\n{}", &text[..80]);
    assert!(text.contains("\nconstants:\n"), "no constant pool");
    assert!(text.contains("c0 = "), "no constant rendered");
    let _ = Op::PushConst; // the op the pool exists for
}

/// Two literals of the same big int must share one pool entry. Dedup must not
/// key on `Value::to_bits()`, a *pointer* for a boxed int (outside ±2^47).
///
/// The fixture value must not collide with a stdlib constant: a hydrated
/// constant points into the static frozen area and a fresh literal into the
/// program's builder, so those two are acceptably distinct allocations.
#[test]
fn a_big_int_constant_is_pooled_once() {
    let p = program_of(
        "pub fn main() {\n\ta = 4611686018427387905\n\tb = 4611686018427387905\n\tprintln(a == b)\n}\n",
    );
    let hits = p
        .constants
        .iter()
        .filter(|c| c.as_int() == Some(4611686018427387905))
        .count();
    assert_eq!(hits, 1, "one value, one pool entry");
}

/// Dedup fails MULTIPLICATIVELY — one pool entry per use site rather than one
/// per value — so the whole-pool witness is a differential: two programs that
/// differ only in how many times they name one literal must pool to the same
/// size. The stdlib contributes the same constants to both sides and cancels,
/// which is what keeps this from measuring how big the stdlib is. An absolute
/// ceiling here did measure that, and had to be raised by hand three times.
///
/// What it does not witness: a regression confined to constants only the
/// stdlib names moves both sides equally and cancels with them. The literal
/// this varies is the one it can see.
#[test]
fn pooling_is_per_value_not_per_use_site() {
    let pool_size = |uses: usize| {
        let lits = vec!["4611686018427387905"; uses].join(", ");
        program_of(&format!(
            "pub fn main() {{\n\txs = [{lits}]\n\tprintln(xs)\n}}\n"
        ))
        .constants
        .len()
    };
    let few = pool_size(2);
    let many = pool_size(32);
    assert_eq!(
        few, many,
        "pool grew with use count ({few} -> {many}): dedup is pooling per use site"
    );
}

/// The size gate for join-point match lowering: a fallible match shares one
/// fallthrough continuation across its failure edges instead of re-lowering
/// every remaining arm at each edge. Without sharing the duplication is
/// multiplicative on binary patterns — `to_method` alone compiled to 48,100
/// instructions and this program to 72,333.
#[test]
fn bench_service_compiles_without_match_arm_duplication() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/bench_service.scrl");
    let src =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let p = program_of(&src);
    assert!(
        p.code.len() < 30_000,
        "bench_service compiled to {} instructions (gate: < 30,000); \
         fallible-match lowering is duplicating arm bodies per failure edge",
        p.code.len()
    );
    let to_method = p
        .functions
        .iter()
        .find(|f| &*f.name == "to_method")
        .expect("bench_service imports scarlet/http, which defines to_method");
    assert!(
        to_method.code_len < 500,
        "to_method compiled to {} instructions (expected ~150-250); its \
         binary match is re-lowering the remaining arms at every failure edge",
        to_method.code_len
    );
}

/// One function's instructions as `(op, operand)` pairs. Constant-pool
/// operands are program-absolute and shift with the stdlib, so callers blank
/// them; jump operands are function-relative and comparable as-is.
fn fn_instructions(p: &bytecode::Program, name: &str) -> Vec<(Op, i32)> {
    // Last match: user functions are emitted after the stdlib, so a stdlib
    // function of the same name cannot shadow the fixture's.
    let f = p
        .functions
        .iter()
        .rev()
        .find(|f| &*f.name == name)
        .unwrap_or_else(|| panic!("no function {name}"));
    p.code[f.code_start as usize..(f.code_start + f.code_len) as usize]
        .iter()
        .map(|i| (i.op, i.operand))
        .collect()
}

/// A match that cannot fail keeps the flat lowering byte-for-byte: no
/// continuation blocks, no failure-edge `Goto`s, because no failure edge
/// exists. A `LetCont` sneaking in would append a block or reroute an edge,
/// and either breaks these literal sequences.
#[test]
fn an_infallible_match_keeps_the_flat_lowering() {
    use Op::*;
    let p = program_of(
        "type Shape {\n\
         \tCircle(r Int)\n\
         \tRect(w Int, h Int)\n\
         }\n\
         fn area(s Shape) Int {\n\
         \tmatch s {\n\
         \t\tCircle(r) -> r * r * 3\n\
         \t\tRect(w, h) -> w * h\n\
         \t}\n\
         }\n\
         fn single(p (Int, Int)) Int {\n\
         \tmatch p {\n\
         \t\t(a, b) -> a + b\n\
         \t}\n\
         }\n\
         fn lits(n Int) String {\n\
         \tmatch n {\n\
         \t\t1 -> 'one'\n\
         \t\t2 -> 'two'\n\
         \t\t_ -> 'many'\n\
         \t}\n\
         }\n\
         pub fn main() {\n\
         \tprintln(area(Circle(2)) + single((1, 2)))\n\
         \tprintln(lits(1))\n\
         }\n",
    );
    // Constant-pool indices move with the stdlib; blank them.
    let blanked = |name: &str| {
        fn_instructions(&p, name)
            .into_iter()
            .map(|(op, operand)| (op, if op == PushConst { -1 } else { operand }))
            .collect::<Vec<_>>()
    };

    // Exhaustive per-variant enum match: switch, jump table, each arm once.
    assert_eq!(
        blanked("area"),
        vec![
            (PushLocal, 0),
            (SwitchTag, 2), // table base: right after the switch
            (Jump, 4),      // tag 0 -> Circle arm
            (Jump, 14),     // tag 1 -> Rect arm
            (PushLocal, 0),
            (UnwrapEnum, 0),
            (StoreLocal, 1),
            (Drop, 0),
            (PushLocal, 1),
            (PushLocal, 1),
            (MulInt, 0),
            (PushConst, -1),
            (MulInt, 0),
            (Ret, 0),
            (PushLocal, 0),
            (UnwrapEnum, 0),
            // Each arm's binds get fresh slots: the native backend addresses
            // slots by local identity, so the local-to-slot map must be
            // injective (see `emit_branches`).
            (StoreLocal, 3),
            (StoreLocal, 2),
            (Drop, 0),
            (PushLocal, 2),
            (PushLocal, 3),
            (MulInt, 0),
            // The last arm's own `Ret` closes the body; the compiler no
            // longer appends a second one after it (T-576).
            (Ret, 0),
        ]
    );

    // Single irrefutable arm: straight-line projections, no branch.
    assert_eq!(
        blanked("single"),
        vec![
            (PushLocal, 0),
            (TupleIndex, 0),
            (StoreLocal, 1),
            (PushLocal, 0),
            (TupleIndex, 1),
            (StoreLocal, 2),
            (Drop, 0),
            (PushLocal, 1),
            (PushLocal, 2),
            (AddInt, 0),
            // The arm's own `Ret` closes the body.
            (Ret, 0),
            // `emit`'s unreachable fall-through trap, for a match the checker
            // proved exhaustive. The compiler no longer appends its own
            // `Ret` after it (T-576).
            (Halt, 0),
        ]
    );

    // Literal ladder: a head miss falls to the next arm's own test, with no
    // continuation minted for it.
    assert_eq!(
        blanked("lits"),
        vec![
            (PushLocal, 0),
            (PushConst, -1),
            (Eq, 0),
            (JumpIfFalse, 6),
            (PushConst, -1),
            (Ret, 0),
            (PushLocal, 0),
            (PushConst, -1),
            (Eq, 0),
            (JumpIfFalse, 12),
            (PushConst, -1),
            (Ret, 0),
            (PushConst, -1),
            (Ret, 0),
            // Same fall-through trap as `single`, and no appended `Ret`
            // after it either.
            (Halt, 0),
        ]
    );
}

// ---------------------------------------------------------------------------
// Wire fingerprint stability across two compiles (T-478, T-334's unmet arm)

/// A program with one `wire.encode` at `Event`, optionally preceded by an
/// unrelated declaration that interns identifiers ahead of `Event`'s.
///
/// The padding is the whole point: two compiles of a byte-identical source is
/// a determinism test, not a stability test, and passes even on a fingerprint
/// that folds `StrId` numbers. The pair has to differ in something that moves
/// `StrId` allocation, and a type declared before `Event` does exactly that —
/// its name, constructor and field are interned first, shifting every id that
/// follows.
fn wire_src(padding: &str) -> String {
    format!(
        "import scarlet/wire\n\
         {padding}\
         type Event {{\n\
         \x20 Said(who String, tags Array(String))\n\
         \x20 Left(who String)\n\
         }}\n\n\
         pub fn main() {{\n\
         \tb = wire.encode(Left('a'))\n\
         \tprintln(b)\n\
         }}\n"
    )
}

const PADDING: &str = "type Zzz {\n\x20 Zzz(zzz String)\n}\n\n";

/// The fingerprint constant of the single `wire.encode` in `p`, found by the
/// instruction that owns it.
///
/// NOT by searching the dump for a number. `dis` has no wire-specific arm, so
/// the fingerprint prints as an ordinary integer constant, indistinguishable
/// from any other int of the same value — a text search can match an unrelated
/// constant and agree with itself. `Op::WireEncode` carries the fingerprint's
/// `ConstId` as its own operand, which is the only identification here that
/// cannot pick up the wrong int.
fn wire_fingerprint(p: &bytecode::Program) -> i64 {
    let ops: Vec<i32> = p
        .code
        .iter()
        .filter(|i| i.op == Op::WireEncode)
        .map(|i| i.operand)
        .collect();
    assert_eq!(
        ops.len(),
        1,
        "the fixture must hold exactly one wire.encode, or the operand below \
         names an arbitrary one of them; got {}",
        ops.len()
    );
    p.constants
        .get(ops[0] as usize)
        .expect("WireEncode's operand must name a pooled constant")
        .as_int()
        .expect("the descriptor constant is the shape fingerprint, an Int")
}

/// The fingerprint of a type is the same in two compiles that intern its names
/// at different `StrId`s — the stability arm T-334 could not reach until
/// elaboration emitted the constant.
///
/// **What proves the pair is actually distinct is the plant, not an assertion
/// here.** Nothing reachable from a `Program` exposes `StrId`s, so this test
/// cannot assert that allocation moved; it asserts only that the two compiles
/// differ at all. Reverting `Desc::fingerprint` to fold `StrId.0` takes this
/// test red, and that is the witness that the padding shifts the ids this
/// fingerprint would otherwise depend on. A green here with that plant applied
/// would mean the pair was not distinct after all.
#[test]
fn the_wire_fingerprint_is_stable_across_two_compiles() {
    let plain = program_of(&wire_src(""));
    let padded = program_of(&wire_src(PADDING));

    let dump_plain = dis::disassemble(&plain);
    let dump_padded = dis::disassemble(&padded);
    assert_ne!(
        dump_plain, dump_padded,
        "the two compiles must not be the same program, or this witnesses nothing"
    );

    let fp_plain = wire_fingerprint(&plain);
    let fp_padded = wire_fingerprint(&padded);
    assert_eq!(
        fp_plain, fp_padded,
        "one shape is one fingerprint: an unrelated declaration ahead of the \
         type must not move it"
    );

    // The DONE-WHEN asks for it through `dis`, so read it back out of both
    // dumps too — identified above, then confirmed present here.
    assert!(
        dump_plain.contains(&fp_plain.to_string()),
        "the fingerprint must appear in the disassembly:\n{dump_plain}"
    );
    assert!(
        dump_padded.contains(&fp_padded.to_string()),
        "the fingerprint must appear in the disassembly:\n{dump_padded}"
    );
}

const ETA_WIRE: &str = "import scarlet/array\nimport scarlet/wire\n\n                        type S { S(s String) }\n\n                        pub fn main() {\n\t                        _first = wire.encode(S('x'))\n\t                        bs = array.map([1, 2], wire.encode)\n\t                        println(array.length(bs))\n}\n";

/// `array.map(xs, wire.encode)` reaches the VM through an eta wrapper, and the
/// wrapper is minted per use — so the descriptor has to be attached there and
/// not at the direct call. **Nothing downstream can recover it.**
/// `imm_operand` flattens a wire op's `Imm::None` to the `-1` sentinel, so a
/// program that forgets compiles clean, passes `check` silently, and is
/// refused by the VM at run time as an *internal compiler bug* — an accusation
/// against the compiler for code the user wrote. Measured on `fc11616`.
///
/// The length assert is the precondition: with only the direct call compiled
/// this would pass while witnessing nothing.
///
/// It does NOT witness that the descriptors are the *right* ones, only that
/// every wire op carries one.
#[test]
fn an_eta_wrapped_wire_op_carries_a_descriptor() {
    let p = program_of(ETA_WIRE);
    let text = dis::disassemble(&p);
    let wire: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("WireEncode") || l.contains("WireDecode"))
        .collect();
    assert!(
        wire.len() >= 2,
        "expected a direct wire call and an eta-wrapped one, got {}:\n{text}",
        wire.len()
    );
    for l in &wire {
        assert!(
            !l.contains("op=-1"),
            "a wire op reached the VM with no descriptor: {l}"
        );
    }
}

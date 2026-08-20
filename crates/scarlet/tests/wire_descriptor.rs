//! The wire descriptor at the two seams a unit test cannot stand over: the
//! LSP's `IncrementalSession`, and the REPL as a subprocess.
//!
//! Both matter because the descriptor is built during *elaboration*. `check`
//! truncates the pipeline before emission, so a refusal raised at emission
//! would be invisible here and in an editor while still failing `al run` —
//! the exact split this ticket exists to prevent. Nothing here runs a wire
//! op: neither has a body yet.

use scarlet::bytecode::IncrementalSession;

mod common;
use common::parse;

const HANDLER: &str = "import scarlet/wire\n\
                       type Handler {\n\
                       \tHandler(name String, run fn(Int) Int)\n\
                       }\n\
                       pub fn main() {\n\
                       \tprintln(wire.encode(Handler('h', fn(x) { x + 1 })))\n\
                       }\n";

const EVENT: &str = "import scarlet/wire\n\
                     type Event {\n\
                     \tSaid(who String)\n\
                     \tLeft(who String)\n\
                     }\n\
                     pub fn main() {\n\
                     \tprintln(wire.encode(Left('a')))\n\
                     }\n";

fn messages(r: &scarlet::bytecode::CompileResult) -> String {
    r.diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The LSP path is `IncrementalSession::check`, which never emits. A refusal
/// has to arrive here or an editor shows a clean file that `al run` rejects.
#[test]
fn a_refusal_is_reported_on_the_session_check_path() {
    let mut s = IncrementalSession::new(&scarlet::STDLIB);
    let r = s.check(&parse(HANDLER), None);
    assert!(!r.success(), "a fn field must be refused");
    assert!(
        messages(&r).contains("a closure's captures are not fixed by its type"),
        "got: {}",
        messages(&r)
    );
}

/// The other half, and the one that catches a refusal that fires on
/// everything: an encodable type must still check clean on the same path.
#[test]
fn an_encodable_type_still_checks_clean_on_the_session_path() {
    let mut s = IncrementalSession::new(&scarlet::STDLIB);
    let r = s.check(&parse(EVENT), None);
    assert!(r.success(), "{:?}", r.diagnostics);
}

/// A session compiles the same buffer repeatedly, rewinding between edits.
/// The descriptor is a constant of the program being built, so nothing has to
/// be carried across a rewind — asserted by running the cycle rather than by
/// arguing it: the failure this would catch is descriptors accumulating from
/// a rewound compile and being minted against a program that no longer has
/// the call site.
#[test]
fn a_session_re_checks_a_wire_call_across_an_edit() {
    let mut s = IncrementalSession::new(&scarlet::STDLIB);
    for _ in 0..2 {
        let bad = s.check(&parse(HANDLER), None);
        assert!(!bad.success());
        let good = s.check(&parse(EVENT), None);
        assert!(good.success(), "{:?}", good.diagnostics);
    }
}

/// The REPL submits one line at a time to its own session. `wire.decode` with
/// nothing to fix its payload is the refusal a REPL user hits first, and it
/// must be a diagnostic there rather than an internal error.
#[test]
fn the_repl_reports_an_unconstrained_decode() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin = env!("CARGO_BIN_EXE_scarlet");
    let mut child = Command::new(bin)
        .arg("repl")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn al repl");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(b"import scarlet/wire\nwire.decode(<<1>>)\n")
            .expect("write stdin");
    }
    let out = common::wait_or_kill(child, common::CHILD_TIMEOUT_SECS);
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        all.contains("the type `wire.decode` produces here is not known"),
        "got: {all}"
    );
}

//! End-to-end tests for the from-source stdlib session: editing
//! `src/std/**/*.scrl` in-repo gets the same session machinery (graph, hover,
//! incremental cache) as user code.

mod common;
use common::parse;

use std::path::PathBuf;

use scarlet::bytecode::IncrementalSession;

fn std_root() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scarlet_core/src/std"
    ))
    .canonicalize()
    .expect("stdlib source root exists")
}

fn read_std(rel: &str) -> String {
    std::fs::read_to_string(std_root().join(rel)).expect("stdlib source file")
}

#[test]
fn stdlib_module_checks_clean_from_source() {
    let root = std_root();
    let mut s = IncrementalSession::new_from_source(root.clone());
    let src = read_std("scarlet/http.scrl");
    let r = s.check_as(
        &parse(&src),
        Some(&root.join("scarlet")),
        vec!["scarlet".into(), "http".into()],
    );
    let errs: Vec<_> = r
        .diagnostics
        .iter()
        .filter(|d| d.severity == scarlet::diagnostic::Severity::Error)
        .collect();
    assert!(errs.is_empty(), "http.scrl from source: {errs:?}");
}

#[test]
fn prelude_self_check_then_other_module_reseeds() {
    let root = std_root();
    let mut s = IncrementalSession::new_from_source(root.clone());

    // The prelude as the entry: checked against a bare world.
    let pre = read_std("scarlet.scrl");
    let r = s.check_as(&parse(&pre), Some(&root), vec!["scarlet".into()]);
    let errs: Vec<_> = r
        .diagnostics
        .iter()
        .filter(|d| d.severity == scarlet::diagnostic::Severity::Error)
        .collect();
    assert!(errs.is_empty(), "scarlet.scrl as entry: {errs:?}");

    // A later ordinary check must re-seed the prelude.
    let src = read_std("scarlet/http.scrl");
    let r = s.check_as(
        &parse(&src),
        Some(&root.join("scarlet")),
        vec!["scarlet".into(), "http".into()],
    );
    let errs: Vec<_> = r
        .diagnostics
        .iter()
        .filter(|d| d.severity == scarlet::diagnostic::Severity::Error)
        .collect();
    assert!(
        errs.is_empty(),
        "http.scrl after prelude-self check: {errs:?}"
    );
}

#[test]
fn stdlib_edit_invalidates_dependent() {
    // Editing a stdlib module's on-disk source must be picked up through the
    // overlay, like any user module.
    let root = std_root();
    let mut s = IncrementalSession::new_from_source(root.clone());
    let src = read_std("scarlet/http.scrl");
    let module = vec!["scarlet".to_string(), "http".to_string()];
    let r = s.check_as(&parse(&src), Some(&root.join("scarlet")), module.clone());
    assert!(
        !scarlet::diagnostic::has_errors(&r.diagnostics),
        "baseline: {:?}",
        r.diagnostics
    );

    // Re-check unchanged: cached imports stay cached.
    let n = s.compile_count();
    let r = s.check_as(&parse(&src), Some(&root.join("scarlet")), module);
    assert!(!scarlet::diagnostic::has_errors(&r.diagnostics));
    assert_eq!(s.compile_count(), n, "unchanged stdlib deps are cache hits");
}

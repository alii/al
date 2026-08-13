//! `cargo xtask scrl-census` — the `.scrl` half of the illegal-state sweep.
//!
//! Mordant's `flag_cluster` reads Rust and reports a struct whose `n` `bool`
//! fields admit `2^n` states when fewer are legal. Nothing read the Scarlet
//! side, so a type declared in `.scrl` was invisible to it — including
//! `http/h1.scrl`'s `HeadFlags`, whose Rust counterpart across the same ABI had
//! already been collapsed into one enum.
//!
//! This is a census, not a lint: it prints what the corpus contains and exits 0
//! either way. Every finding is a candidate for reading, not a defect.
//!
//! It is deliberately not a CI gate. The first sweep read 3 constructors out of
//! 469 declarations across five repos and only one was a genuine illegal state
//! (`HeadFlags`, already ticketed); the other two are decoder test fixtures
//! whose width is the property under test. Scarlet has no per-item suppression,
//! so gating this would mean either a baseline file that one finding does not
//! justify, or a red build on two fixtures that are correct. It runs in the
//! hardening sweep instead.
//!
//! It parses with the compiler's own scanner and parser rather than matching
//! text, because the text-matching version of this question has been wrong here
//! before: a `type` inside a comment or a string literal is not a declaration,
//! and a field list spans lines. The scanner resolves both by construction —
//! comments become trivia and string bodies become one token.
//!
//! # What it cannot see
//!
//! - **Nested declarations.** Only top-level declarations are walked. Scarlet's
//!   grammar admits a `type` inside a block body, so the walk is checked rather
//!   than assumed: every run compares the type declarations it inspected against
//!   the `type` keywords the scanner produced, and reports any file where the
//!   two disagree. A file that nests one is reported as uninspected, never
//!   silently counted as clean.
//! - **`Bool` is matched by name**, so a locally declared `type Bool` would be
//!   counted as the prelude's and a module-qualified `m.Bool` would not be
//!   counted at all.
//! - **Whether the states are actually illegal.** That is the reading step. The
//!   `opaque` column is reported because it bounds who can build a bad value,
//!   but it does not exclude the shape: an invariant held by a private
//!   constructor is still held by a convention.
//! - **Layout fixed from outside.** `flag_cluster` skips a `repr` struct because
//!   something outside Rust dictates its states. A Scarlet type crossing the VM
//!   ABI is in that position and carries no syntactic mark, so it cannot be
//!   filtered here and must be triaged by reading.

use std::path::{Path, PathBuf};

use scarlet_syntax::ast;
use scarlet_syntax::parser::new_parser;
use scarlet_syntax::scanner::new_scanner;
use scarlet_syntax::token::{Keyword, Kind};

/// Mordant's `FlagCluster::FLOOR`. Held equal to it deliberately: `HeadFlags`
/// and the `ConnTokens` it faces across the ABI are one boundary in two
/// languages, and a census that answered at a different threshold could not be
/// compared with the Rust side's.
pub const DEFAULT_MIN_BOOLS: usize = 2;

pub struct Finding {
    pub path: PathBuf,
    pub line: i32,
    pub type_name: String,
    /// The constructor carrying the bools. Equal to `type_name` for the
    /// single-constructor types that are the Rust `struct` analogue.
    pub ctor_name: String,
    pub opaque: bool,
    pub bools: Vec<String>,
}

/// A file the walk could not account for in full, and why. Kept apart from the
/// findings because "nothing found here" and "not looked at properly here"
/// print the same empty list otherwise.
pub struct Uninspected {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Default)]
pub struct Census {
    pub findings: Vec<Finding>,
    pub uninspected: Vec<Uninspected>,
    pub files: usize,
    pub type_decls: usize,
}

pub fn run(roots: &[PathBuf], min_bools: usize) -> Census {
    let mut census = Census::default();
    let mut paths = Vec::new();
    for root in roots {
        collect_scrl(root, &mut paths);
    }
    paths.sort();
    for path in paths {
        census.files += 1;
        match std::fs::read_to_string(&path) {
            Ok(source) => inspect(&path, &source, min_bools, &mut census),
            Err(e) => census.uninspected.push(Uninspected {
                path,
                reason: format!("unreadable: {e}"),
            }),
        }
    }
    census
}

fn collect_scrl(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.is_file() {
        if dir.extension().is_some_and(|e| e == "scrl") {
            out.push(dir.to_path_buf());
        }
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            // Build output and vendored dependencies are not the corpus, and
            // `target` holds copies of the stdlib that would double every count.
            if matches!(name.as_ref(), "target" | "node_modules" | ".git") {
                continue;
            }
            collect_scrl(&path, out);
        } else if path.extension().is_some_and(|e| e == "scrl") {
            out.push(path);
        }
    }
}

fn inspect(path: &Path, source: &str, min_bools: usize, census: &mut Census) {
    let (tokens, _) = new_scanner(source).scan_all();
    // Every `type` keyword opens a declaration — an alias, an external type or
    // a variant body — and the keyword is reserved, so this is the number of
    // declarations the walk below must account for.
    let type_keywords = tokens
        .iter()
        .filter(|t| t.kind == Kind::Keyword(Keyword::Type))
        .count();

    let mut scanner = new_scanner(source);
    let parsed = new_parser(&mut scanner).parse_program();
    if !parsed.diagnostics.is_empty() {
        census.uninspected.push(Uninspected {
            path: path.to_path_buf(),
            reason: format!("{} parse diagnostic(s)", parsed.diagnostics.len()),
        });
        return;
    }

    let mut declarations = Vec::new();
    for node in &parsed.ast.body {
        if let ast::Node::Statement(statement) = node
            && let ast::Statement::Declaration { decl, .. } = statement.as_ref()
            && let ast::Declaration::Type(type_decl) = decl.as_ref()
        {
            declarations.push(type_decl);
        }
    }

    if declarations.len() != type_keywords {
        census.uninspected.push(Uninspected {
            path: path.to_path_buf(),
            reason: format!(
                "walk reached {} type declaration(s), scanner found {type_keywords} `type` \
                 keyword(s) — a declaration is nested below top level",
                declarations.len()
            ),
        });
        return;
    }

    census.type_decls += declarations.len();
    for type_decl in declarations {
        let ast::TypeBody::Variants { ctors, opaque } = &type_decl.body else {
            continue;
        };
        for ctor in ctors {
            let bools: Vec<String> = ctor
                .fields
                .iter()
                .filter(|f| is_prelude_bool(&f.typ))
                .map(|f| f.label.name.clone())
                .collect();
            if bools.len() < min_bools {
                continue;
            }
            census.findings.push(Finding {
                path: path.to_path_buf(),
                line: ctor.identifier.span.start_line + 1,
                type_name: type_decl.identifier.name.clone(),
                ctor_name: ctor.identifier.name.clone(),
                opaque: *opaque,
                bools,
            });
        }
    }
}

fn is_prelude_bool(typ: &ast::TypeIdentifier) -> bool {
    match &typ.kind {
        ast::TypeKind::NamedType(named) => {
            named.qualifier.is_none()
                && named.identifier.name == "Bool"
                && named.type_args.is_empty()
        }
        ast::TypeKind::FunctionType(_) | ast::TypeKind::TupleType(_) => false,
    }
}

/// `2^n`, or the unevaluated power when it does not fit — the same contract as
/// `flag_cluster`'s message, so the two sides print comparable numbers.
pub fn states(n: usize) -> String {
    match u32::try_from(n).ok().and_then(|n| 2u64.checked_pow(n)) {
        Some(n) => n.to_string(),
        None => format!("2^{n}"),
    }
}

pub fn report(census: &Census, min_bools: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "scrl-census: constructors with >= {min_bools} Bool fields\n\n"
    ));
    for finding in &census.findings {
        let name = if finding.type_name == finding.ctor_name {
            finding.type_name.clone()
        } else {
            format!("{}::{}", finding.type_name, finding.ctor_name)
        };
        out.push_str(&format!(
            "{}:{} {name}{} — {} Bool fields, {} states: {}\n",
            finding.path.display(),
            finding.line,
            if finding.opaque { " (opaque)" } else { "" },
            finding.bools.len(),
            states(finding.bools.len()),
            finding.bools.join(", "),
        ));
    }
    if census.findings.is_empty() {
        out.push_str("(none)\n");
    }
    out.push_str(&format!(
        "\n{} finding(s) over {} type declaration(s) in {} file(s)\n",
        census.findings.len(),
        census.type_decls,
        census.files,
    ));
    out.push_str(&format!(
        "{} file(s) not inspected\n",
        census.uninspected.len()
    ));
    for skipped in &census.uninspected {
        out.push_str(&format!(
            "  {}: {}\n",
            skipped.path.display(),
            skipped.reason
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Census, DEFAULT_MIN_BOOLS, inspect, states};

    fn census_of(source: &str) -> Census {
        let mut census = Census::default();
        inspect(
            Path::new("test.scrl"),
            source,
            DEFAULT_MIN_BOOLS,
            &mut census,
        );
        census
    }

    #[test]
    fn states_is_two_to_the_n() {
        assert_eq!(states(2), "4");
        assert_eq!(states(3), "8");
        assert_eq!(states(64), "2^64");
    }

    /// The shape the census exists to find, spelled as `h1.scrl` spells it.
    #[test]
    fn finds_a_bool_cluster() {
        let census = census_of(
            "pub opaque type HeadFlags {\n\
             \tconn_close Bool\n\
             \tconn_keep_alive Bool\n\
             \texpect_100_continue Bool\n\
             }\n",
        );
        assert_eq!(census.uninspected.len(), 0);
        assert_eq!(census.findings.len(), 1);
        let finding = &census.findings[0];
        assert_eq!(finding.type_name, "HeadFlags");
        assert!(finding.opaque);
        assert_eq!(
            finding.bools,
            ["conn_close", "conn_keep_alive", "expect_100_continue"]
        );
    }

    /// One `Bool` is under the floor, and a second field of another type does
    /// not make a cluster — the count is of `Bool` fields, not of fields.
    #[test]
    fn one_bool_is_not_a_cluster() {
        let census = census_of("pub type Flags {\n\tclose Bool\n\tcount Int\n}\n");
        assert_eq!(census.findings.len(), 0);
        assert_eq!(census.type_decls, 1);
    }

    /// Bools in two different constructors of one sum type are never
    /// simultaneously inhabited, so they are not a cluster. The Rust analogue
    /// is that `flag_cluster` reads one struct, not an enum's whole variant set.
    #[test]
    fn bools_in_separate_constructors_do_not_combine() {
        let census = census_of("pub type Step {\n\tOpen(a Bool)\n\tShut(b Bool)\n}\n");
        assert_eq!(census.findings.len(), 0);
    }

    /// The defect a text search makes here: `type` and `Bool` inside a comment
    /// or a string are not a declaration. The scanner never emits them as
    /// tokens, so neither the finding count nor the coverage cross-check moves.
    #[test]
    fn comments_and_strings_are_not_declarations() {
        let census = census_of(
            "// pub type Ghost {\n\
             //\ta Bool\n\
             //\tb Bool\n\
             // }\n\
             pub const doc = \"pub type Ghost { a Bool b Bool }\"\n",
        );
        assert_eq!(census.findings.len(), 0);
        assert_eq!(census.type_decls, 0);
        assert_eq!(census.uninspected.len(), 0);
    }

    /// A declaration nested in a block body is out of the walk's reach, so the
    /// coverage cross-check must refuse the file rather than report it clean.
    /// This is the one blind spot the instrument can detect in itself.
    #[test]
    fn a_nested_declaration_is_reported_uninspected() {
        let census = census_of(
            "pub fn make() {\n\
             \ttype Inner {\n\
             \t\tOne(a Bool, b Bool)\n\
             \t}\n\
             \t0\n\
             }\n",
        );
        assert_eq!(census.findings.len(), 0);
        assert_eq!(census.uninspected.len(), 1);
        assert!(
            census.uninspected[0].reason.contains("nested"),
            "{}",
            census.uninspected[0].reason
        );
    }

    /// A file that does not parse yields no declarations, which is the same
    /// empty list a clean file yields. It must be counted as uninspected.
    #[test]
    fn a_file_that_does_not_parse_is_not_clean() {
        let census = census_of("pub type Broken {\n\ta Bool\n\tb Bool\n");
        assert_eq!(census.findings.len(), 0);
        assert_eq!(census.uninspected.len(), 1);
    }
}

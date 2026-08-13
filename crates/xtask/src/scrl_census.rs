//! `cargo xtask scrl-census` — the `.scrl` half of the illegal-state sweep.
//!
//! Mordant's `flag_cluster` reads Rust and reports a struct whose `n` `bool`
//! fields admit `2^n` states when fewer are legal. `wildcard_local_enum` flags
//! a `_` arm over a crate-local enum, which is the only way to defeat
//! exhaustiveness. Nothing read the Scarlet side, so a type declared in `.scrl`
//! was invisible to both — the first sweep's one genuine hit was the then-
//! current `http/h1.scrl` `HeadFlags` (three Bools; T-310 later collapsed it).
//!
//! This is a census, not a lint: it prints what the corpus contains and exits 0
//! either way. Every finding is a candidate for reading, not a defect.
//!
//! It is deliberately not a CI gate. Shape 1's first sweep read 3 constructors
//! out of 469 declarations across five repos and only one was a genuine
//! illegal state (`HeadFlags`, then T-310); the other two are decoder test
//! fixtures whose width is the property under test. Shape 2 over the same
//! five-repo corpus (264 files, 476 type declarations, 1799 matches, 0
//! uninspected) printed 141 catch-alls over a local sum type and 251 others.
//! Reading them: extractors (`_ -> None`/`False`), fail-closed protocol
//! errors (redis `Value`), identity defaults (`Phase`, `Status`), and tests.
//! T-148's types (`Field`, `Parsed`, `Framing`, `ChunkBody`) have no catch-all
//! in their defining modules — `Field`'s matches already name every variant.
//! Scarlet has no per-item suppression, so gating either shape would mean a
//! baseline file the genuine class does not justify, or a red build on
//! extractors that are correct. It runs in the hardening sweep instead.
//! T-148's opt-in `@exhaustive` is still the language mechanism; this census
//! says a blanket lint is not.
//!
//! It parses with the compiler's own scanner and parser rather than matching
//! text, because the text-matching version of this question has been wrong here
//! before: a `type` inside a comment or a string literal is not a declaration,
//! and a field list spans lines. The scanner resolves both by construction —
//! comments become trivia and string bodies become one token.
//!
//! Shape 2 (catch-all over a local sum type) needs `match` expressions, which
//! live inside function bodies. The walk therefore descends every expression
//! the AST can nest, and every run compares the type declarations and matches
//! it inspected against the `type` / `match` keywords the scanner produced.
//! A file where either pair disagrees is reported as uninspected, never
//! silently counted as clean.
//!
//! # What it cannot see
//!
//! - **The subject's type.** There is no typechecker here. A catch-all is
//!   attributed to a local sum type when a sibling arm's top-level constructor
//!   is declared on a multi-constructor type in the same walk root. A match
//!   whose other arms are only literals, arrays, tuples or binary patterns is
//!   not this shape. A constructor declared in a root that was not passed is
//!   foreign, the same way `Option` is foreign to a crate that did not define
//!   it.
//! - **Qualified and aliased constructors.** `io.NotFound` is treated as
//!   foreign even when `NotFound` is declared in-root. An `import {Circle as
//!   Round}` match names `Round`, which is not the declared constructor.
//! - **Constructor-name collisions.** A type is a candidate only when every
//!   sibling head is one of its constructors; same-file candidates beat
//!   cross-file ones. Two types in the same file that share a constructor
//!   name still both fire.
//! - **`Bool` is matched by name** (shape 1), so a locally declared `type Bool`
//!   would be counted as the prelude's and a module-qualified `m.Bool` would
//!   not be counted at all.
//! - **Whether the states are actually illegal.** That is the reading step. The
//!   `opaque` column is reported because it bounds who can build a bad value,
//!   but it does not exclude the shape: an invariant held by a private
//!   constructor is still held by a convention. Shape 2 similarly cannot tell
//!   a deliberate extractor (`_ -> False`) from a silent collapse.
//! - **Layout fixed from outside.** `flag_cluster` skips a `repr` struct because
//!   something outside Rust dictates its states. A Scarlet type crossing the VM
//!   ABI is in that position and carries no syntactic mark, so it cannot be
//!   filtered here and must be triaged by reading.
//! - **Prose-carried invariants (shape 3).** An invariant stated in a comment
//!   and carried by no type has no syntactic mark. A word scan of `.scrl`
//!   comments hits module-behaviour prose (`never modified`, `always close`)
//!   at the same rate as a real invariant, and the measured instances (T-286,
//!   T-309) live next to expressions, not on type declarations. Not
//!   instrumented; re-read by hand when the comment is next to a type.

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

/// A `_` or bare-binding arm whose sibling arms name a multi-constructor type
/// declared in the same walk root. The type is inferred from those constructor
/// heads — there is no typechecker here.
pub struct CatchAll {
    pub path: PathBuf,
    pub line: i32,
    /// `_` or the binding's written name.
    pub pattern: String,
    pub type_name: String,
    pub variants: usize,
    pub sibling_ctors: Vec<String>,
    /// Body is `None` / `False` / `Nil` / `Err(..)` / `[]` — mordant's
    /// extractor exemption, reported as a column rather than filtered.
    pub extractor: bool,
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
    pub catch_alls: Vec<CatchAll>,
    pub uninspected: Vec<Uninspected>,
    pub files: usize,
    pub type_decls: usize,
    pub matches: usize,
    /// Catch-all arms whose sibling heads did not name an in-root sum type
    /// (literals, arrays, tuples, or constructors declared elsewhere).
    pub other_catch_alls: usize,
    sums: Vec<LocalSum>,
    raw_catch_alls: Vec<RawCatchAll>,
}

struct LocalSum {
    root: usize,
    path: PathBuf,
    type_name: String,
    ctors: Vec<String>,
}

struct RawCatchAll {
    root: usize,
    path: PathBuf,
    line: i32,
    pattern: String,
    sibling_ctors: Vec<String>,
    extractor: bool,
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
        let root = root_index(&path, roots);
        match std::fs::read_to_string(&path) {
            Ok(source) => inspect(&path, &source, min_bools, root, &mut census),
            Err(e) => census.uninspected.push(Uninspected {
                path,
                reason: format!("unreadable: {e}"),
            }),
        }
    }
    finalize(&mut census);
    census
}

/// First root that is a prefix of `path`. Overlapping roots are first-wins;
/// a path that matches none (a lone file passed as a root) sits in bucket 0
/// with every other unmatched path.
fn root_index(path: &Path, roots: &[PathBuf]) -> usize {
    roots
        .iter()
        .position(|root| path.starts_with(root) || path == root)
        .unwrap_or(0)
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

fn inspect(path: &Path, source: &str, min_bools: usize, root: usize, census: &mut Census) {
    let (tokens, _) = new_scanner(source).scan_all();
    // Both keywords are reserved. Every `type` opens a declaration and every
    // `match` opens a MatchExpression, so these are the numbers the walk
    // below must account for — including the ones nested inside bodies.
    let type_keywords = tokens
        .iter()
        .filter(|t| t.kind == Kind::Keyword(Keyword::Type))
        .count();
    let match_keywords = tokens
        .iter()
        .filter(|t| t.kind == Kind::Keyword(Keyword::Match))
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

    let mut types = Vec::new();
    let mut matches = Vec::new();
    walk_nodes(&parsed.ast.body, &mut types, &mut matches);

    if types.len() != type_keywords || matches.len() != match_keywords {
        census.uninspected.push(Uninspected {
            path: path.to_path_buf(),
            reason: format!(
                "walk reached {} type declaration(s) and {} match(es), scanner found \
                 {type_keywords} `type` and {match_keywords} `match` keyword(s)",
                types.len(),
                matches.len()
            ),
        });
        return;
    }

    census.type_decls += types.len();
    census.matches += matches.len();

    for type_decl in &types {
        record_sum(path, root, type_decl, census);
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

    for m in matches {
        record_catch_all(path, root, m, census);
    }
}

fn record_sum(path: &Path, root: usize, type_decl: &ast::TypeDeclaration, census: &mut Census) {
    let ast::TypeBody::Variants { ctors, .. } = &type_decl.body else {
        return;
    };
    if ctors.len() < 2 {
        return;
    }
    census.sums.push(LocalSum {
        root,
        path: path.to_path_buf(),
        type_name: type_decl.identifier.name.clone(),
        ctors: ctors.iter().map(|c| c.identifier.name.clone()).collect(),
    });
}

fn record_catch_all(path: &Path, root: usize, m: &ast::MatchExpression, census: &mut Census) {
    // A single-arm match is a destructuring, not a dispatch — same cut as
    // mordant's wildcard_local_enum.
    if m.arms.len() < 2 {
        return;
    }
    let mut sibling_ctors = Vec::new();
    let mut catch_alls = Vec::new();
    for arm in &m.arms {
        if is_unguarded_catch_all(arm) {
            catch_alls.push(arm);
        } else {
            collect_ctor_heads(&arm.pattern, &mut sibling_ctors);
        }
    }
    if catch_alls.is_empty() {
        return;
    }
    let sibling_ctors: Vec<String> = sibling_ctors
        .into_iter()
        .filter_map(|(qualifier, name)| qualifier.is_none().then_some(name))
        .collect();
    for arm in catch_alls {
        census.raw_catch_alls.push(RawCatchAll {
            root,
            path: path.to_path_buf(),
            line: arm.pattern.span().start_line + 1,
            pattern: catch_all_name(&arm.pattern),
            sibling_ctors: sibling_ctors.clone(),
            extractor: is_extractor_body(&arm.body),
        });
    }
}

/// Attribute each raw catch-all to an in-root sum type, or count it as other.
/// Called once the walk has seen every file, so a constructor declared in
/// another file of the same root is local — the `is_local()` analogue.
fn finalize(census: &mut Census) {
    // A constructor name can belong to several types in one root (`Done` is
    // on Parsed, Member and Pull). A type is a candidate only when every
    // sibling head is one of its constructors; same-file candidates then
    // beat cross-file ones, so a test file matching `Done` does not also
    // fire on every other `Done` in the repo. Two types with the same
    // *type* name (json.Kind and process.Kind) stay distinct because we
    // walk the declaration list, not a name map.
    for raw in &census.raw_catch_alls {
        if raw.sibling_ctors.is_empty() {
            census.other_catch_alls += 1;
            continue;
        }
        let mut candidates: Vec<(String, usize, bool)> = Vec::new();
        for sum in &census.sums {
            if sum.root != raw.root {
                continue;
            }
            if raw
                .sibling_ctors
                .iter()
                .all(|c| sum.ctors.iter().any(|d| d == c))
            {
                candidates.push((sum.type_name.clone(), sum.ctors.len(), sum.path == raw.path));
            }
        }
        let same_file: Vec<(String, usize, bool)> = candidates
            .iter()
            .filter(|&(_, _, local)| *local)
            .cloned()
            .collect();
        let mut chosen = if same_file.is_empty() {
            candidates
        } else {
            same_file
        };
        if chosen.is_empty() {
            census.other_catch_alls += 1;
            continue;
        }
        chosen.sort_by(|a, b| a.0.cmp(&b.0));
        chosen.dedup_by(|a, b| a.0 == b.0);
        let type_name = chosen
            .iter()
            .map(|(n, _, _)| n.as_str())
            .collect::<Vec<_>>()
            .join("|");
        let variants = chosen.iter().map(|(_, n, _)| *n).max().unwrap_or(0);
        census.catch_alls.push(CatchAll {
            path: raw.path.clone(),
            line: raw.line,
            pattern: raw.pattern.clone(),
            type_name,
            variants,
            sibling_ctors: raw.sibling_ctors.clone(),
            extractor: raw.extractor,
        });
    }
}

fn walk_nodes<'a>(
    nodes: &'a [ast::Node],
    types: &mut Vec<&'a ast::TypeDeclaration>,
    matches: &mut Vec<&'a ast::MatchExpression>,
) {
    for node in nodes {
        walk_node(node, types, matches);
    }
}

fn walk_node<'a>(
    node: &'a ast::Node,
    types: &mut Vec<&'a ast::TypeDeclaration>,
    matches: &mut Vec<&'a ast::MatchExpression>,
) {
    match node {
        ast::Node::Statement(statement) => walk_statement(statement, types, matches),
        ast::Node::Expression(expr) => walk_expr(expr, types, matches),
    }
}

fn walk_statement<'a>(
    statement: &'a ast::Statement,
    types: &mut Vec<&'a ast::TypeDeclaration>,
    matches: &mut Vec<&'a ast::MatchExpression>,
) {
    match statement {
        ast::Statement::Declaration { decl, .. } => walk_decl(decl, types, matches),
        ast::Statement::ImportDeclaration(_) => {}
        ast::Statement::TupleDestructuringBinding(b) => {
            for p in &b.patterns {
                walk_pattern(p, types, matches);
            }
            walk_expr(&b.init, types, matches);
        }
        ast::Statement::TypedDiscard(b) => walk_expr(&b.init, types, matches),
        ast::Statement::CtorDestructuringBinding(b) => {
            for arg in &b.args {
                let p = match arg {
                    ast::PatternArg::Positional(p)
                    | ast::PatternArg::Labeled { pattern: p, .. } => p,
                };
                walk_pattern(p, types, matches);
            }
            walk_expr(&b.init, types, matches);
        }
        ast::Statement::VariableBinding(b) => walk_expr(&b.init, types, matches),
        ast::Statement::Backpass(b) => walk_expr(&b.call, types, matches),
    }
}

fn walk_decl<'a>(
    decl: &'a ast::Declaration,
    types: &mut Vec<&'a ast::TypeDeclaration>,
    matches: &mut Vec<&'a ast::MatchExpression>,
) {
    match decl {
        ast::Declaration::Const(c) => walk_expr(&c.init, types, matches),
        ast::Declaration::Function(f) => match &f.body {
            ast::FnBody::Block(body) => walk_expr(body, types, matches),
            ast::FnBody::Vm(_) => {}
        },
        ast::Declaration::Type(t) => types.push(t),
    }
}

fn walk_expr<'a>(
    expr: &'a ast::Expression,
    types: &mut Vec<&'a ast::TypeDeclaration>,
    matches: &mut Vec<&'a ast::MatchExpression>,
) {
    match expr {
        ast::Expression::ArrayExpression(a) => {
            for el in &a.elements {
                match el {
                    ast::ArrayElement::Expression(e)
                    | ast::ArrayElement::SpreadElement(ast::SpreadElement {
                        expression: e, ..
                    }) => {
                        walk_expr(e, types, matches);
                    }
                }
            }
        }
        ast::Expression::ArrayIndexExpression(a) => {
            walk_expr(&a.expression, types, matches);
            walk_expr(&a.index, types, matches);
        }
        ast::Expression::BinaryExpression(b) => {
            walk_expr(&b.left, types, matches);
            walk_expr(&b.right, types, matches);
        }
        ast::Expression::BinaryLiteral(b) => {
            for seg in &b.segments {
                walk_expr(&seg.value, types, matches);
                if let Some(size) = seg.spec.size_expr() {
                    walk_expr(size, types, matches);
                }
            }
        }
        ast::Expression::BlockExpression(b) => walk_nodes(&b.body, types, matches),
        ast::Expression::ErrorNode(_) => {}
        ast::Expression::FunctionCallExpression(f) => {
            walk_expr(&f.callee, types, matches);
            for arg in &f.arguments {
                match arg {
                    ast::CallArg::Positional(e) | ast::CallArg::Spread(e) => {
                        walk_expr(e, types, matches);
                    }
                    ast::CallArg::Labeled { value, .. } => walk_expr(value, types, matches),
                }
            }
        }
        ast::Expression::FunctionExpression(f) => walk_expr(&f.body, types, matches),
        ast::Expression::Identifier(_) => {}
        ast::Expression::IfExpression(i) => {
            walk_expr(&i.condition, types, matches);
            walk_expr(&i.body, types, matches);
            walk_expr(&i.else_body, types, matches);
        }
        ast::Expression::InterpolatedString(s) => {
            for part in &s.parts {
                if let ast::InterpPart::Expr(e) = part {
                    walk_expr(e, types, matches);
                }
            }
        }
        ast::Expression::MatchExpression(m) => {
            matches.push(m);
            walk_expr(&m.subject, types, matches);
            for arm in &m.arms {
                walk_pattern(&arm.pattern, types, matches);
                if let Some(guard) = &arm.guard {
                    walk_expr(guard, types, matches);
                }
                walk_expr(&arm.body, types, matches);
            }
        }
        ast::Expression::NumberLiteral(_) => {}
        ast::Expression::OrExpression(o) => {
            walk_expr(&o.expression, types, matches);
            walk_expr(&o.body, types, matches);
        }
        ast::Expression::PropertyAccessExpression(p) => walk_expr(&p.left, types, matches),
        ast::Expression::RangeExpression(r) => {
            walk_expr(&r.start, types, matches);
            walk_expr(&r.end, types, matches);
        }
        ast::Expression::StringLiteral(_) => {}
        ast::Expression::TupleExpression(t) => {
            for e in &t.elements {
                walk_expr(e, types, matches);
            }
        }
        ast::Expression::UnaryExpression(u) => walk_expr(&u.expression, types, matches),
    }
}

fn walk_pattern<'a>(
    pattern: &'a ast::Pattern,
    types: &mut Vec<&'a ast::TypeDeclaration>,
    matches: &mut Vec<&'a ast::MatchExpression>,
) {
    match pattern {
        ast::Pattern::Var { .. } | ast::Pattern::Literal(_) | ast::Pattern::Range { .. } => {}
        ast::Pattern::Constructor { args, .. } => {
            for arg in args {
                let p = match arg {
                    ast::PatternArg::Positional(p)
                    | ast::PatternArg::Labeled { pattern: p, .. } => p,
                };
                walk_pattern(p, types, matches);
            }
        }
        ast::Pattern::Tuple { elements, .. } => {
            for p in elements {
                walk_pattern(p, types, matches);
            }
        }
        ast::Pattern::Array { elements, .. } => {
            for el in elements {
                if let ast::ArrayPatternElement::Pattern(p) = el {
                    walk_pattern(p, types, matches);
                }
            }
        }
        ast::Pattern::Binary { segments, .. } => {
            for seg in segments {
                walk_pattern(&seg.value, types, matches);
                if let Some(size) = seg.spec.size_expr() {
                    walk_expr(size, types, matches);
                }
            }
        }
        ast::Pattern::Or { first, rest, .. } => {
            walk_pattern(first, types, matches);
            for p in rest {
                walk_pattern(p, types, matches);
            }
        }
    }
}

fn is_unguarded_catch_all(arm: &ast::MatchArm) -> bool {
    arm.guard.is_none() && is_catch_all(&arm.pattern)
}

fn is_catch_all(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Var { .. } => true,
        ast::Pattern::Or { first, rest, .. } => {
            is_catch_all(first) || rest.iter().any(is_catch_all)
        }
        ast::Pattern::Constructor { .. }
        | ast::Pattern::Tuple { .. }
        | ast::Pattern::Array { .. }
        | ast::Pattern::Binary { .. }
        | ast::Pattern::Literal(_)
        | ast::Pattern::Range { .. } => false,
    }
}

fn catch_all_name(pattern: &ast::Pattern) -> String {
    match pattern {
        ast::Pattern::Var { name } => name.name.clone(),
        ast::Pattern::Or { .. } => "_|…".to_string(),
        ast::Pattern::Constructor { .. }
        | ast::Pattern::Tuple { .. }
        | ast::Pattern::Array { .. }
        | ast::Pattern::Binary { .. }
        | ast::Pattern::Literal(_)
        | ast::Pattern::Range { .. } => "_".to_string(),
    }
}

fn collect_ctor_heads(pattern: &ast::Pattern, out: &mut Vec<(Option<String>, String)>) {
    match pattern {
        ast::Pattern::Constructor {
            qualifier, name, ..
        } => {
            out.push((
                qualifier.as_ref().map(|q| q.name.clone()),
                name.name.clone(),
            ));
        }
        ast::Pattern::Or { first, rest, .. } => {
            collect_ctor_heads(first, out);
            for p in rest {
                collect_ctor_heads(p, out);
            }
        }
        ast::Pattern::Var { .. }
        | ast::Pattern::Tuple { .. }
        | ast::Pattern::Array { .. }
        | ast::Pattern::Binary { .. }
        | ast::Pattern::Literal(_)
        | ast::Pattern::Range { .. } => {}
    }
}

fn is_extractor_body(expr: &ast::Expression) -> bool {
    match expr {
        ast::Expression::Identifier(id) => {
            matches!(id.name.as_str(), "None" | "False" | "Nil")
        }
        ast::Expression::FunctionCallExpression(f) => {
            matches!(
                f.callee.as_ref(),
                ast::Expression::Identifier(id) if id.name == "Err"
            )
        }
        ast::Expression::ArrayExpression(a) => a.elements.is_empty(),
        ast::Expression::BlockExpression(b) if b.body.len() == 1 => match &b.body[0] {
            ast::Node::Expression(e) => is_extractor_body(e),
            ast::Node::Statement(_) => false,
        },
        ast::Expression::ArrayIndexExpression(_)
        | ast::Expression::BinaryExpression(_)
        | ast::Expression::BinaryLiteral(_)
        | ast::Expression::BlockExpression(_)
        | ast::Expression::ErrorNode(_)
        | ast::Expression::FunctionExpression(_)
        | ast::Expression::IfExpression(_)
        | ast::Expression::InterpolatedString(_)
        | ast::Expression::MatchExpression(_)
        | ast::Expression::NumberLiteral(_)
        | ast::Expression::OrExpression(_)
        | ast::Expression::PropertyAccessExpression(_)
        | ast::Expression::RangeExpression(_)
        | ast::Expression::StringLiteral(_)
        | ast::Expression::TupleExpression(_)
        | ast::Expression::UnaryExpression(_) => false,
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

    out.push_str("\nscrl-census: catch-all arms over a locally-declared sum type\n\n");
    for hit in &census.catch_alls {
        out.push_str(&format!(
            "{}:{} `{}` on {} ({} variants{}) — sibling constructors: {}\n",
            hit.path.display(),
            hit.line,
            hit.pattern,
            hit.type_name,
            hit.variants,
            if hit.extractor { ", extractor" } else { "" },
            if hit.sibling_ctors.is_empty() {
                "(none)".to_string()
            } else {
                hit.sibling_ctors.join(", ")
            },
        ));
    }
    if census.catch_alls.is_empty() {
        out.push_str("(none)\n");
    }
    out.push_str(&format!(
        "\n{} catch-all(s) over a local sum type, {} other catch-all(s), {} match(es) in {} file(s)\n",
        census.catch_alls.len(),
        census.other_catch_alls,
        census.matches,
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

    use super::{Census, DEFAULT_MIN_BOOLS, finalize, inspect, states};

    fn census_of(source: &str) -> Census {
        let mut census = Census::default();
        inspect(
            Path::new("test.scrl"),
            source,
            DEFAULT_MIN_BOOLS,
            0,
            &mut census,
        );
        finalize(&mut census);
        census
    }

    #[test]
    fn states_is_two_to_the_n() {
        assert_eq!(states(2), "4");
        assert_eq!(states(3), "8");
        assert_eq!(states(64), "2^64");
    }

    /// The shape the census exists to find. The fixture keeps three Bools
    /// even though T-310 collapsed the `h1.scrl` type that motivated it —
    /// this tests the finder, not the current spelling.
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

    /// A declaration nested in a block body is inside the walk. The coverage
    /// cross-check must agree, and a nested bool cluster is a finding — the
    /// top-level-only walk used to report this file uninspected instead.
    #[test]
    fn a_nested_declaration_is_inspected() {
        let census = census_of(
            "pub fn make() {\n\
             \ttype Inner {\n\
             \t\tOne(a Bool, b Bool)\n\
             \t}\n\
             \t0\n\
             }\n",
        );
        assert_eq!(census.uninspected.len(), 0);
        assert_eq!(census.type_decls, 1);
        assert_eq!(census.findings.len(), 1);
        assert_eq!(census.findings[0].type_name, "Inner");
    }

    /// A file that does not parse yields no declarations, which is the same
    /// empty list a clean file yields. It must be counted as uninspected.
    #[test]
    fn a_file_that_does_not_parse_is_not_clean() {
        let census = census_of("pub type Broken {\n\ta Bool\n\tb Bool\n");
        assert_eq!(census.findings.len(), 0);
        assert_eq!(census.uninspected.len(), 1);
    }

    /// The completeness check for expressions: a `match` inside a function
    /// body is reached, and the keyword count agrees. A walk that stopped at
    /// top level would report this file uninspected.
    #[test]
    fn a_match_inside_a_function_is_reached() {
        let census = census_of(
            "pub fn f(n Int) Int {\n\
             \tmatch n {\n\
             \t\t0 -> 1\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.uninspected.len(), 0);
        assert_eq!(census.matches, 1);
        assert_eq!(census.catch_alls.len(), 0);
        assert_eq!(census.other_catch_alls, 1);
    }

    /// `match` inside a comment or a string is not a MatchExpression. The
    /// scanner never emits the keyword, so the coverage cross-check stays
    /// quiet.
    #[test]
    fn match_in_comments_and_strings_is_not_a_match() {
        let census = census_of(
            "// match x {\n\
             //\t_ -> 0\n\
             // }\n\
             pub const doc = \"match x { _ -> 0 }\"\n",
        );
        assert_eq!(census.matches, 0);
        assert_eq!(census.uninspected.len(), 0);
    }

    /// The shape wildcard_local_enum exists to find, spelled as a local sum
    /// type with a `_` arm.
    #[test]
    fn catch_all_over_local_sum_is_found() {
        let census = census_of(
            "type Color {\n\
             \tRed\n\
             \tGreen\n\
             \tBlue\n\
             }\n\
             pub fn f(c Color) Int {\n\
             \tmatch c {\n\
             \t\tRed -> 1\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.uninspected.len(), 0);
        assert_eq!(census.catch_alls.len(), 1);
        let hit = &census.catch_alls[0];
        assert_eq!(hit.type_name, "Color");
        assert_eq!(hit.pattern, "_");
        assert_eq!(hit.variants, 3);
        assert_eq!(hit.sibling_ctors, ["Red"]);
        assert!(!hit.extractor);
    }

    /// A named binding is the same catch-all as `_`.
    #[test]
    fn binding_catch_all_over_local_sum_is_found() {
        let census = census_of(
            "type Color {\n\
             \tRed\n\
             \tGreen\n\
             }\n\
             pub fn f(c Color) Color {\n\
             \tmatch c {\n\
             \t\tRed -> Red\n\
             \t\tother -> other\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 1);
        assert_eq!(census.catch_alls[0].pattern, "other");
    }

    /// `_ -> False` is still a finding: the census does not filter extractors.
    /// The column exists so the reading step can see them.
    #[test]
    fn extractor_catch_all_is_still_a_finding() {
        let census = census_of(
            "type Color {\n\
             \tRed\n\
             \tGreen\n\
             }\n\
             pub fn is_red(c Color) Bool {\n\
             \tmatch c {\n\
             \t\tRed -> True\n\
             \t\t_ -> False\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 1);
        assert!(census.catch_alls[0].extractor);
    }

    /// Exhaustive listing of a local sum is not a catch-all.
    #[test]
    fn exhaustive_local_match_is_not_a_catch_all() {
        let census = census_of(
            "type Color {\n\
             \tRed\n\
             \tGreen\n\
             }\n\
             pub fn f(c Color) Int {\n\
             \tmatch c {\n\
             \t\tRed -> 1\n\
             \t\tGreen -> 2\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 0);
        assert_eq!(census.other_catch_alls, 0);
        assert_eq!(census.matches, 1);
    }

    /// A catch-all over Int / a string / an array is not this shape: no
    /// sibling constructor names a local sum type.
    #[test]
    fn catch_all_over_int_is_not_a_local_sum() {
        let census = census_of(
            "pub fn f(n Int) Int {\n\
             \tmatch n {\n\
             \t\t0 -> 1\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 0);
        assert_eq!(census.other_catch_alls, 1);
    }

    /// `Some` / `None` declared in another module are foreign when that
    /// module is not in the walk. The language crate's own Option is local
    /// only when option.scrl is in the same root.
    #[test]
    fn catch_all_over_undeclared_option_is_not_local() {
        let census = census_of(
            "pub fn f(o Option(Int)) Int {\n\
             \tmatch o {\n\
             \t\tSome(n) -> n\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 0);
        assert_eq!(census.other_catch_alls, 1);
    }

    /// A tuple subject with nested constructors is not a match over a sum
    /// type. The catch-all absorbs tuple shapes, not future variants.
    #[test]
    fn tuple_subject_is_not_a_sum() {
        let census = census_of(
            "type Method {\n\
             \tHead\n\
             \tGet\n\
             }\n\
             type Body {\n\
             \tFixed(n Int)\n\
             \tEmpty\n\
             }\n\
             pub fn f(m Method, b Body) Int {\n\
             \tmatch (m, b) {\n\
             \t\t(Head, Fixed(n)) -> n\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 0);
        assert_eq!(census.other_catch_alls, 1);
    }

    /// One arm is destructuring, even when the pattern is `_`.
    #[test]
    fn one_arm_is_not_a_dispatch() {
        let census = census_of(
            "type Color {\n\
             \tRed\n\
             \tGreen\n\
             }\n\
             pub fn f(c Color) Color {\n\
             \tmatch c {\n\
             \t\tx -> x\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 0);
        assert_eq!(census.other_catch_alls, 0);
        assert_eq!(census.matches, 1);
    }

    /// A match nested in a lambda is reached, and a constructor declared in
    /// the same file still attributes it.
    #[test]
    fn match_inside_a_lambda_is_reached() {
        let census = census_of(
            "type Color {\n\
             \tRed\n\
             \tGreen\n\
             }\n\
             pub fn f(c Color) Int {\n\
             \tg = fn(x) match x {\n\
             \t\tRed -> 1\n\
             \t\t_ -> 0\n\
             \t}\n\
             \tg(c)\n\
             }\n",
        );
        assert_eq!(census.uninspected.len(), 0);
        assert_eq!(census.matches, 1);
        assert_eq!(census.catch_alls.len(), 1);
        assert_eq!(census.catch_alls[0].type_name, "Color");
    }

    /// Two files in one root: a constructor declared in the other file is
    /// local. This is the crate-local analogue, and the reason finalize waits
    /// until every file has been walked.
    #[test]
    fn constructor_declared_in_another_file_of_the_same_root_is_local() {
        let mut census = Census::default();
        inspect(
            Path::new("order.scrl"),
            "pub type Order {\n\tLt\n\tEq\n\tGt\n}\n",
            DEFAULT_MIN_BOOLS,
            0,
            &mut census,
        );
        inspect(
            Path::new("eq.scrl"),
            "pub fn eq(o Order) Bool {\n\
             \tmatch o {\n\
             \t\tEq -> True\n\
             \t\t_ -> False\n\
             \t}\n\
             }\n",
            DEFAULT_MIN_BOOLS,
            0,
            &mut census,
        );
        finalize(&mut census);
        assert_eq!(census.uninspected.len(), 0);
        assert_eq!(census.catch_alls.len(), 1);
        assert_eq!(census.catch_alls[0].type_name, "Order");
        assert!(census.catch_alls[0].extractor);
    }

    /// The same two files in different roots: the constructor is foreign.
    #[test]
    fn constructor_declared_in_another_root_is_foreign() {
        let mut census = Census::default();
        inspect(
            Path::new("order.scrl"),
            "pub type Order {\n\tLt\n\tEq\n\tGt\n}\n",
            DEFAULT_MIN_BOOLS,
            0,
            &mut census,
        );
        inspect(
            Path::new("eq.scrl"),
            "pub fn eq(o Order) Bool {\n\
             \tmatch o {\n\
             \t\tEq -> True\n\
             \t\t_ -> False\n\
             \t}\n\
             }\n",
            DEFAULT_MIN_BOOLS,
            1,
            &mut census,
        );
        finalize(&mut census);
        assert_eq!(census.catch_alls.len(), 0);
        assert_eq!(census.other_catch_alls, 1);
    }

    /// `Done` is a constructor of three types in this root. A type is only a
    /// candidate when every sibling head belongs to it; same-file then wins,
    /// so a match next to `Done` in `parsed.scrl` is Parsed, not Member.
    #[test]
    fn shared_constructor_name_prefers_the_same_file() {
        let mut census = Census::default();
        inspect(
            Path::new("parsed.scrl"),
            "pub type Parsed {\n\
             \tDone\n\
             \tNeedMore\n\
             \tBad\n\
             }\n\
             pub fn f(p Parsed) Int {\n\
             \tmatch p {\n\
             \t\tDone -> 1\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
            DEFAULT_MIN_BOOLS,
            0,
            &mut census,
        );
        inspect(
            Path::new("member.scrl"),
            "pub type Member {\n\
             \tDone\n\
             \tSkip\n\
             }\n",
            DEFAULT_MIN_BOOLS,
            0,
            &mut census,
        );
        finalize(&mut census);
        assert_eq!(census.uninspected.len(), 0);
        assert_eq!(census.catch_alls.len(), 1);
        assert_eq!(census.catch_alls[0].type_name, "Parsed");
    }

    /// Sibling heads `Map, List, Set` fit Value and not BitFieldOp, even
    /// though both types share `Set`.
    #[test]
    fn a_type_must_own_every_sibling_constructor() {
        let census = census_of(
            "type Value {\n\
             \tMap\n\
             \tList\n\
             \tSet\n\
             \tNull\n\
             }\n\
             type BitFieldOp {\n\
             \tGet\n\
             \tSet\n\
             \tIncr\n\
             \tOverflow\n\
             }\n\
             pub fn f(v Value) Int {\n\
             \tmatch v {\n\
             \t\tMap -> 1\n\
             \t\tList -> 2\n\
             \t\tSet -> 3\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 1);
        assert_eq!(census.catch_alls[0].type_name, "Value");
    }

    /// Two types in the same file sharing a constructor name cannot be
    /// disambiguated; they print as one finding with both names.
    #[test]
    fn ambiguous_same_file_types_are_one_finding() {
        let census = census_of(
            "type Parsed {\n\
             \tDone\n\
             \tNeedMore\n\
             }\n\
             type Member {\n\
             \tDone\n\
             \tSkip\n\
             }\n\
             pub fn f(p Parsed) Int {\n\
             \tmatch p {\n\
             \t\tDone -> 1\n\
             \t\t_ -> 0\n\
             \t}\n\
             }\n",
        );
        assert_eq!(census.catch_alls.len(), 1);
        assert_eq!(census.catch_alls[0].type_name, "Member|Parsed");
    }
}

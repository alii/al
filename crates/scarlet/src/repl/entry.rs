//! One REPL entry, parsed on its own.
//!
//! Parsed alone, before any replay: only the entry's own diagnostics belong to
//! the user, and only the entry's own end-of-input means "ask for another
//! line". The line editor and the evaluator classify an entry the same way,
//! through here, so Enter never submits something the evaluator would then
//! call unfinished.

use crate::ast;
use crate::diagnostic::{self, Diagnostic, DiagnosticCode};
use crate::parser;
use crate::scanner;

pub enum Entry {
    /// The parser ran out of input mid-form: the entry wants another line.
    /// Carries the diagnostics anyway, for the paths that have no more input
    /// to offer it.
    Incomplete(Vec<Diagnostic>),
    /// Unparseable, with the diagnostics saying why.
    Rejected(Vec<Diagnostic>),
    Accepted(ast::BlockExpression),
}

pub fn parse(input: &str) -> Entry {
    let mut scanner = scanner::new_scanner(input.to_string());
    let parsed = parser::new_parser(&mut scanner).parse_program();
    if !diagnostic::has_errors(&parsed.diagnostics) {
        return Entry::Accepted(parsed.ast);
    }
    if parsed
        .diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::UnexpectedEof)
    {
        return Entry::Incomplete(parsed.diagnostics);
    }
    Entry::Rejected(parsed.diagnostics)
}

/// An accepted entry, split into the parts a session keeps and the part it
/// only runs once.
#[derive(Default)]
pub struct Parts {
    /// Import declarations. The language requires every import to precede all
    /// other declarations, so a session cannot replay entries in the order
    /// they were typed: the imports have to be lifted out and kept together.
    pub imports: String,
    /// Declarations and bindings, replayed ahead of every later entry.
    pub definitions: String,
    /// Bare expressions, evaluated this turn only. Replaying one would repeat
    /// its effects on every later entry.
    pub expressions: String,
}

/// Split `source` — the text `program` was parsed from — by what each
/// top-level node is.
///
/// Line-granular, and each line is claimed by the first node that reaches it,
/// so the text is only ever moved, never duplicated or rewritten. Lines ahead
/// of a node (its doc comment, blank space) travel with it.
pub fn split(source: &str, program: &ast::BlockExpression) -> Parts {
    let lines: Vec<&str> = source.lines().collect();
    let mut parts = Parts::default();
    let mut next = 0usize;

    for node in &program.body {
        let end = usize::try_from(node.span().end_line)
            .unwrap_or(0)
            .min(lines.len().saturating_sub(1));
        if next > end {
            continue;
        }
        let bucket = match node {
            ast::Node::Statement(s) if matches!(**s, ast::Statement::ImportDeclaration(_)) => {
                &mut parts.imports
            }
            ast::Node::Statement(_) => &mut parts.definitions,
            ast::Node::Expression(_) => &mut parts.expressions,
        };
        for line in &lines[next..=end] {
            bucket.push_str(line);
            bucket.push('\n');
        }
        next = end + 1;
    }
    // A trailing comment belongs to no node; keep it with the definitions so
    // nothing the user typed is silently dropped from a saved session.
    for line in lines.iter().skip(next) {
        parts.definitions.push_str(line);
        parts.definitions.push('\n');
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(src: &str) -> Parts {
        match parse(src) {
            Entry::Accepted(program) => split(src, &program),
            _ => panic!("did not parse: {src}"),
        }
    }

    #[test]
    fn an_import_is_held_apart_from_what_follows_it() {
        let p = parts("import scarlet/string\nconst x = 1\nx + 1\n");
        assert_eq!(p.imports, "import scarlet/string\n");
        assert_eq!(p.definitions, "const x = 1\n");
        assert_eq!(p.expressions, "x + 1\n");
    }

    #[test]
    fn a_multi_line_declaration_keeps_all_of_its_lines() {
        let p = parts("fn tri(n Int) Int {\n\tn * 3\n}\ntri(2)\n");
        assert_eq!(p.definitions, "fn tri(n Int) Int {\n\tn * 3\n}\n");
        assert_eq!(p.expressions, "tri(2)\n");
    }

    #[test]
    fn a_doc_comment_travels_with_its_declaration() {
        let p = parts("/// doc\nfn f() Int { 1 }\n");
        assert_eq!(p.definitions, "/// doc\nfn f() Int { 1 }\n");
        assert!(p.expressions.is_empty());
    }

    #[test]
    fn a_bare_expression_is_never_kept() {
        let p = parts("println('once')");
        assert!(p.definitions.is_empty() && p.imports.is_empty());
        assert_eq!(p.expressions, "println('once')\n");
    }
}

//! Backpass desugaring: `a, b <- call(args)` followed by the rest of its
//! block becomes `call(args, fn(a, b) { <rest> })`, the call becoming the
//! block's final node (and so its value). Multiple backpasses in one block
//! nest: a later one is part of an earlier one's `<rest>`, so it desugars
//! inside that lambda.
//!
//! Purely AST→AST and run by the compile pipeline just before type checking
//! — never by the formatter, which renders the statement as written. After
//! this pass no [`Statement::Backpass`] remains anywhere in the tree, so
//! inference and lowering never see one.
//!
//! The lowering is bind-shaped for every backpass, and it must stay that way
//! here: whether a step's binder is used later is visible from the AST, but
//! whether running the later step after this one failed is *wanted* is a
//! property of the callee, and this pass runs before imports resolve. All 19
//! backpasses in the stdlib are over `result.then`/`result.map`, and 10 bind
//! `_` — so a syntactic "independent, therefore combine" rule would reorder
//! exactly the `http.scrl` writes whose comments say the ordering is
//! load-bearing.
//! `crates/scarlet/tests/backpass_sequencing.rs` fails if that changes; T-211
//! carries the argument.

use crate::ast::*;

/// Desugar every backpass in a parsed program, in place.
pub fn desugar_program(block: &mut BlockExpression) {
    desugar_body(&mut block.body);
}

/// Desugar every backpass in `expr`, in place.
pub fn desugar_expression(expr: &mut Expression) {
    desugar_expr(expr);
}

fn is_backpass(node: &Node) -> bool {
    matches!(node, Node::Statement(s) if matches!(s.as_ref(), Statement::Backpass(_)))
}

// The Statement catch-all below moves the non-backpass node back; a new statement kind belongs there.
#[allow(unknown_lints, wildcard_local_enum)]
fn desugar_body(body: &mut Vec<Node>) {
    // Rewrite the first backpass; everything after it moves into the lambda,
    // so the generic walk below reaches any later ones inside that new node.
    if let Some(i) = body.iter().position(is_backpass) {
        let rest = body.split_off(i + 1);
        let bp = match body.pop() {
            Some(Node::Statement(s)) => match *s {
                Statement::Backpass(bp) => Some(bp),
                other => {
                    body.push(Node::Statement(Box::new(other)));
                    None
                }
            },
            Some(node) => {
                body.push(node);
                None
            }
            None => None,
        };
        match bp {
            Some(bp) => body.push(Node::Expression(rebuild_backpass(bp, rest))),
            // Unreachable: `position` found a backpass at `i`.
            None => body.extend(rest),
        }
    }
    for node in body.iter_mut() {
        desugar_node(node);
    }
}

/// `call(args)` plus the nodes after the statement → `call(args, fn(..) {
/// rest })`. A backpass ending its block passes an empty continuation: the
/// lambda body is an empty block, which evaluates to Nil.
fn rebuild_backpass(bp: BackpassBinding, rest: Vec<Node>) -> Expression {
    let BackpassBinding {
        binders,
        mut call,
        span,
    } = bp;
    // The parser only builds a backpass whose RHS is a call.
    if let Expression::FunctionCallExpression(fc) = &mut call {
        let body_span = match (rest.first(), rest.last()) {
            (Some(f), Some(l)) => f.span().union(&l.span()),
            _ => span,
        };
        let params = binders
            .into_iter()
            .map(|identifier| FunctionParameter {
                identifier,
                typ: None,
            })
            .collect();
        fc.arguments
            .push(CallArg::Positional(Expression::FunctionExpression(
                FunctionExpression {
                    return_type: None,
                    params,
                    body: Box::new(Expression::BlockExpression(BlockExpression {
                        body: rest,
                        span: body_span,
                    })),
                    span,
                },
            )));
    }
    call
}

fn desugar_node(node: &mut Node) {
    match node {
        Node::Expression(e) => desugar_expr(e),
        Node::Statement(s) => desugar_statement(s),
    }
}

fn desugar_statement(s: &mut Statement) {
    match s {
        Statement::Declaration { decl, .. } => match decl.as_mut() {
            Declaration::Const(c) => desugar_expr(&mut c.init),
            Declaration::Function(f) => {
                if let FnBody::Block(e) = &mut f.body {
                    desugar_expr(e)
                }
            }
            Declaration::Type(_) => {}
        },
        Statement::ImportDeclaration(_) => {}
        Statement::TupleDestructuringBinding(t) => {
            for p in &mut t.patterns {
                desugar_pattern(p);
            }
            desugar_expr(&mut t.init);
        }
        Statement::TypedDiscard(t) => desugar_expr(&mut t.init),
        Statement::CtorDestructuringBinding(c) => {
            for a in &mut c.args {
                desugar_pattern_arg(a);
            }
            desugar_expr(&mut c.init);
        }
        Statement::VariableBinding(v) => desugar_expr(&mut v.init),
        // `desugar_body` consumed every backpass this walk can reach; one
        // here survived a parser rejection (top level), so only its call's
        // own subtree is left to clean.
        Statement::Backpass(bp) => desugar_expr(&mut bp.call),
    }
}

fn desugar_expr(e: &mut Expression) {
    match e {
        Expression::ArrayExpression(a) => {
            for el in &mut a.elements {
                match el {
                    ArrayElement::Expression(e) => desugar_expr(e),
                    ArrayElement::SpreadElement(s) => desugar_expr(&mut s.expression),
                }
            }
        }
        Expression::ArrayIndexExpression(x) => {
            desugar_expr(&mut x.expression);
            desugar_expr(&mut x.index);
        }
        Expression::BinaryExpression(b) => {
            desugar_expr(&mut b.left);
            desugar_expr(&mut b.right);
        }
        Expression::BinaryLiteral(b) => {
            for seg in &mut b.segments {
                desugar_expr(&mut seg.value);
                desugar_bin_spec(&mut seg.spec);
            }
        }
        Expression::BlockExpression(b) => desugar_body(&mut b.body),
        Expression::ErrorNode(_)
        | Expression::Identifier(_)
        | Expression::NumberLiteral(_)
        | Expression::StringLiteral(_) => {}
        Expression::FunctionCallExpression(c) => {
            desugar_expr(&mut c.callee);
            for a in &mut c.arguments {
                match a {
                    CallArg::Positional(e) | CallArg::Spread(e) => desugar_expr(e),
                    CallArg::Labeled { value, .. } => desugar_expr(value),
                }
            }
        }
        Expression::FunctionExpression(f) => desugar_expr(&mut f.body),
        Expression::IfExpression(i) => {
            desugar_expr(&mut i.condition);
            desugar_expr(&mut i.body);
            desugar_expr(&mut i.else_body);
        }
        Expression::InterpolatedString(s) => {
            for p in &mut s.parts {
                if let InterpPart::Expr(e) = p {
                    desugar_expr(e)
                }
            }
        }
        Expression::MatchExpression(m) => {
            desugar_expr(&mut m.subject);
            for arm in &mut m.arms {
                desugar_pattern(&mut arm.pattern);
                if let Some(g) = &mut arm.guard {
                    desugar_expr(g);
                }
                desugar_expr(&mut arm.body);
            }
        }
        Expression::OrExpression(o) => {
            desugar_expr(&mut o.expression);
            desugar_expr(&mut o.body);
        }
        Expression::PropertyAccessExpression(p) => desugar_expr(&mut p.left),
        Expression::RangeExpression(r) => {
            desugar_expr(&mut r.start);
            desugar_expr(&mut r.end);
        }
        Expression::TupleExpression(t) => {
            for e in &mut t.elements {
                desugar_expr(e);
            }
        }
        Expression::UnaryExpression(u) => desugar_expr(&mut u.expression),
    }
}

// Patterns hold no statements, but binary-segment size specs hold arbitrary
// expressions, which can hold blocks.
fn desugar_pattern(p: &mut Pattern) {
    match p {
        Pattern::Var { .. } | Pattern::Literal(_) | Pattern::Range { .. } => {}
        Pattern::Constructor { args, .. } => {
            for a in args {
                desugar_pattern_arg(a);
            }
        }
        Pattern::Tuple { elements, .. } => {
            for e in elements {
                desugar_pattern(e);
            }
        }
        Pattern::Array { elements, .. } => {
            for e in elements {
                if let ArrayPatternElement::Pattern(p) = e {
                    desugar_pattern(p)
                }
            }
        }
        Pattern::Binary { segments, .. } => {
            for seg in segments {
                desugar_pattern(&mut seg.value);
                desugar_bin_spec(&mut seg.spec);
            }
        }
        Pattern::Or { first, rest, .. } => {
            desugar_pattern(first);
            for p in rest {
                desugar_pattern(p);
            }
        }
    }
}

fn desugar_pattern_arg(a: &mut PatternArg) {
    match a {
        PatternArg::Positional(p) => desugar_pattern(p),
        PatternArg::Labeled { pattern, .. } => desugar_pattern(pattern),
    }
}

fn desugar_bin_spec(spec: &mut BinSpec) {
    match spec {
        BinSpec::Int { bits: Some(e) } => desugar_expr(e),
        BinSpec::Binary { bytes: Some(e) } => desugar_expr(e),
        BinSpec::Int { bits: None } | BinSpec::Binary { bytes: None } | BinSpec::Utf8 => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parser, scanner};

    fn parse_and_desugar(src: &str) -> BlockExpression {
        let mut sc = scanner::new_scanner(src.to_string());
        let r = parser::new_parser(&mut sc).parse_program();
        assert!(
            r.diagnostics.is_empty(),
            "parse errors: {:?}",
            r.diagnostics
        );
        let mut block = r.ast;
        desugar_program(&mut block);
        block
    }

    fn contains_backpass_body(body: &[Node]) -> bool {
        body.iter().any(is_backpass)
    }

    /// The trailing lambda appended to `call`, if the node is a call.
    fn trailing_lambda(node: &Node) -> &FunctionExpression {
        let Node::Expression(Expression::FunctionCallExpression(fc)) = node else {
            panic!("expected a call node, got {node:?}");
        };
        let Some(CallArg::Positional(Expression::FunctionExpression(fe))) = fc.arguments.last()
        else {
            panic!("expected a trailing lambda, got {:?}", fc.arguments.last());
        };
        fe
    }

    #[test]
    fn single_backpass_becomes_trailing_lambda() {
        let block = parse_and_desugar("fn f() {\n\tx <- g(1)\n\tx\n}\n");
        let Node::Statement(s) = &block.body[0] else {
            panic!("expected fn decl");
        };
        let Statement::Declaration { decl, .. } = s.as_ref() else {
            panic!("expected declaration");
        };
        let Declaration::Function(fd) = decl.as_ref() else {
            panic!("expected function");
        };
        let FnBody::Block(Expression::BlockExpression(body)) = &fd.body else {
            panic!("expected block body");
        };
        assert_eq!(
            body.body.len(),
            1,
            "backpass collapsed the block to the call"
        );
        let fe = trailing_lambda(&body.body[0]);
        assert_eq!(fe.params.len(), 1);
        assert_eq!(fe.params[0].identifier.name, "x");
        let Expression::BlockExpression(rest) = fe.body.as_ref() else {
            panic!("lambda body should be a block");
        };
        assert_eq!(rest.body.len(), 1);
        assert!(!contains_backpass_body(&rest.body));
    }

    #[test]
    fn two_backpasses_nest_in_order() {
        let block = parse_and_desugar("fn f() {\n\ta <- g(1)\n\tb <- h(a)\n\ta + b\n}\n");
        let Node::Statement(s) = &block.body[0] else {
            panic!("expected fn decl");
        };
        let Statement::Declaration { decl, .. } = s.as_ref() else {
            panic!("expected declaration");
        };
        let Declaration::Function(fd) = decl.as_ref() else {
            panic!("expected function");
        };
        let FnBody::Block(Expression::BlockExpression(body)) = &fd.body else {
            panic!("expected block body");
        };
        // Outer: g(1, fn(a) { h(a, fn(b) { a + b }) }).
        let outer = trailing_lambda(&body.body[0]);
        assert_eq!(outer.params[0].identifier.name, "a");
        let Expression::BlockExpression(inner_body) = outer.body.as_ref() else {
            panic!("lambda body should be a block");
        };
        assert_eq!(inner_body.body.len(), 1);
        let inner = trailing_lambda(&inner_body.body[0]);
        assert_eq!(inner.params[0].identifier.name, "b");
    }
}

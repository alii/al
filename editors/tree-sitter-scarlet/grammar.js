// Tree-sitter grammar for Scarlet. The structural rules transcribe the
// hand-written recursive-descent parser in crates/scarlet_syntax/src/parser;
// the lexical layer (keywords, escapes, identifier/number shapes) is
// generated from the compiler's token tables into lexical.js.
//
// Fidelity notes, mirroring the reference parser:
// - The reference parser is newline-sensitive in a few spots (a call `(` or
//   index `[` on a fresh line does not chain; see parser "P7"). Tree-sitter
//   extras are whitespace-blind, so those delimiters use token.immediate:
//   stricter than the parser (no space before `(` either), but the formatter
//   never emits that space, and the corpus check keeps us honest.
// - identifier and type_identifier are disjoint tokens (lowercase vs
//   uppercase first char), modelling token::is_type_name, which is the
//   language's only case rule and drives ctor-vs-var decisions everywhere.
// - `(x)` grouping and 1-tuples do not exist; blocks `{ x }` group.

'use strict';

const lex = require('./lexical');

const KEYWORDS = new Set(lex.keywords);

// Every keyword the structural rules use must exist in the generated table,
// so a renamed keyword breaks `tree-sitter generate` instead of drifting.
function kw(text) {
  if (!KEYWORDS.has(text)) throw new Error(`not a Scarlet keyword: ${text}`);
  return text;
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(',', rule)), optional(','));
}

// parse_field_list: items on one line need commas, a newline is also a
// separator. Whitespace-blind, that means the comma is simply optional.
function fieldSep1(rule) {
  return seq(rule, repeat(seq(optional(','), rule)), optional(','));
}

function commaSep(rule) {
  return optional(commaSep1(rule));
}

module.exports = grammar({
  name: 'scarlet',

  word: ($) => $.identifier,

  extras: ($) => [/[ \t\r\n]/, $.line_comment, $.block_comment, $.doc_comment],

  externals: ($) => [$._minus_line_start],

  conflicts: ($) => [
    // `x Foo = e` (typed binding) vs `x` then `Foo = e` (typed discard):
    // only the reference parser's same-line rule separates them.
    [$.binding, $._primary_expression],
    // `Foo(x) = e` (ctor destructuring) vs `Foo(x)` (ctor call).
    [$.ctor_binding, $._primary_expression],
    // Pattern/expression twins: a GLR fork inside `(...)` or `[...]` stays
    // alive until the `=` (or its absence) after the closing delimiter
    // decides destructuring vs literal.
    [$._pattern_atom, $._primary_expression],
    [$._primary_expression, $.ctor_pattern],
    [$._primary_expression, $._number_pattern],
    [$._primary_expression, $.negative_number],
    [$._primary_expression, $.rest_pattern],
    [$.array_expression, $.array_pattern],
    [$.binary_literal, $.binary_pattern],
    [$.binary_segment, $.binary_pattern_segment],
  ],

  rules: {
    program: ($) => repeat($._node),

    _node: ($) =>
      choice(
        $.import_declaration,
        $.function_declaration,
        $.type_declaration,
        $.const_declaration,
        $.binding,
        $.tuple_binding,
        $.typed_discard,
        $.ctor_binding,
        $.backpass,
        $._expression,
      ),

    // -----------------------------------------------------------------------
    // Declarations
    // -----------------------------------------------------------------------

    attribute: ($) =>
      seq(
        '@',
        field('name', $.identifier),
        optional(seq(token.immediate('('), commaSep($.identifier), ')')),
      ),

    import_declaration: ($) =>
      seq(
        kw('import'),
        repeat($.relative_segment),
        field('module', $.identifier),
        repeat(seq('/', field('module', $.identifier))),
        optional(seq(kw('as'), field('alias', $.identifier))),
        optional($.import_items),
      ),

    relative_segment: () => seq(choice('.', '..'), '/'),

    import_items: ($) => seq('.', '{', commaSep1($.import_item), '}'),

    import_item: ($) =>
      seq(
        field('name', choice($.identifier, $.type_identifier)),
        optional(seq(kw('as'), field('alias', choice($.identifier, $.type_identifier)))),
      ),

    function_declaration: ($) =>
      prec.right(seq(
        repeat($.attribute),
        optional($.visibility_modifier),
        kw('fn'),
        field('name', $.identifier),
        field('parameters', $.parameters),
        optional(field('return_type', $._type)),
        // Absent on `@vm(...)` declarations, which have no body at all.
        optional(field('body', $.block)),
      )),

    visibility_modifier: () => kw('pub'),

    parameters: ($) => seq('(', commaSep($.parameter), ')'),

    parameter: ($) =>
      seq(field('name', $.identifier), optional(field('type', $._type))),

    type_declaration: ($) =>
      prec.right(seq(
        repeat($.attribute),
        optional($.visibility_modifier),
        optional($.opaque_modifier),
        kw('type'),
        field('name', $.type_identifier),
        optional(field('parameters', $.type_parameters)),
        // Absent entirely on an external/opaque handle type.
        optional(choice(seq('=', field('alias', $._type)), field('body', $.type_body))),
      )),

    opaque_modifier: () => kw('opaque'),

    type_parameters: ($) =>
      seq(token.immediate('('), commaSep1($.identifier), ')'),

    type_body: ($) =>
      seq(
        '{',
        choice(
          // `type Point { x Int  y Int }` desugars to one ctor named like
          // the type; a lowercase first token selects this shorthand.
          fieldSep1($.constructor_field),
          repeat1($.constructor),
        ),
        '}',
      ),

    constructor: ($) =>
      seq(
        field('name', $.type_identifier),
        optional(seq(token.immediate('('), fieldSep1($.constructor_field), ')')),
      ),

    constructor_field: ($) =>
      seq(field('name', $.identifier), field('type', $._type)),

    const_declaration: ($) =>
      seq(
        optional($.visibility_modifier),
        kw('const'),
        field('name', choice($.identifier, $.type_identifier)),
        optional(field('type', $._type)),
        '=',
        field('value', $._expression),
      ),

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    _type: ($) => choice($.function_type, $.tuple_type, $.named_type, $.type_variable),

    function_type: ($) =>
      prec.right(
        seq(kw('fn'), '(', commaSep($._type), ')', optional(field('return_type', $._type))),
      ),

    tuple_type: ($) => seq('(', $._type, ',', commaSep1($._type), ')'),

    named_type: ($) =>
      seq(
        optional(seq(field('module', $.identifier), '.')),
        field('name', $.type_identifier),
        optional(seq(token.immediate('('), commaSep1($._type), ')')),
      ),

    // A lowercase name in type position is a free type variable
    // (`fn twice(f fn(a) a, x a) a`).
    type_variable: ($) => $.identifier,

    // -----------------------------------------------------------------------
    // Statements
    // -----------------------------------------------------------------------

    binding: ($) =>
      seq(
        field('name', $.identifier),
        optional(field('type', $._type)),
        '=',
        field('value', $._expression),
      ),

    tuple_binding: ($) =>
      seq(
        '(',
        commaSep1($._pattern),
        ')',
        '=',
        field('value', $._expression),
      ),

    // `Nil = println('x')`: assert-and-discard of a zero-arg type.
    typed_discard: ($) =>
      seq(field('type', $.type_identifier), '=', field('value', $._expression)),

    // `Stat(files, dirs, ..) = walk(root)`: single-arm match sugar.
    ctor_binding: ($) =>
      seq(
        field('constructor', $.type_identifier),
        token.immediate('('),
        optional($.pattern_arguments),
        ')',
        '=',
        field('value', $._expression),
      ),

    // `a, b <- call(args)`: rewritten to `call(args, fn(a, b) { rest })`.
    backpass: ($) =>
      seq(
        field('binder', $.identifier),
        repeat(seq(',', field('binder', $.identifier))),
        '<-',
        field('call', $.call_expression),
      ),

    // -----------------------------------------------------------------------
    // Expressions (precedence ladder from parser PRECEDENCE table, loosest
    // first: or < || < && < == != < comparisons < .. < + - < * / % < unary
    // < postfix)
    // -----------------------------------------------------------------------

    _expression: ($) =>
      choice(
        $.or_expression,
        $.binary_expression,
        $.range_expression,
        $.unary_expression,
        $._postfix_expression,
      ),

    or_expression: ($) =>
      prec.right(
        1,
        seq(
          field('left', $._expression),
          kw('or'),
          optional(seq(field('binder', $.identifier), '->')),
          field('right', $._expression),
        ),
      ),

    binary_expression: ($) => {
      const table = [
        [2, '||'],
        [3, '&&'],
        [4, choice('==', '!=')],
        [5, choice('<', '>', '<=', '>=')],
        [7, choice('+', '-')],
        [8, choice('*', '/', '%')],
      ];
      return choice(
        ...table.map(([precedence, operator]) =>
          prec.left(
            precedence,
            seq(
              field('left', $._expression),
              field('operator', operator),
              field('right', $._expression),
            ),
          ),
        ),
      );
    },

    // Endpoints are additive-precedence: `-5..5` is `(-5)..(5)`, and a range
    // is a single operand of any comparison around it. No chaining.
    range_expression: ($) =>
      prec.left(
        6,
        seq(field('start', $._expression), '..', field('end', $._expression)),
      ),

    // `_minus_line_start` is the parser's "P4" rule: a fresh-line `-` starts
    // a new statement or arm rather than continuing an additive chain, so
    // unary and negative-literal rules accept it but binary subtraction
    // does not.
    unary_expression: ($) =>
      prec(
        9,
        seq(
          field('operator', choice('!', '-', alias($._minus_line_start, '-'))),
          field('operand', $._expression),
        ),
      ),

    _postfix_expression: ($) =>
      choice(
        $.call_expression,
        $.index_expression,
        $.field_expression,
        $._primary_expression,
      ),

    // token.immediate: a `(` on a fresh line starts a new expression instead
    // of chaining as a call (parser "P7").
    call_expression: ($) =>
      prec(
        10,
        seq(
          field('function', $._postfix_expression),
          token.immediate('('),
          optional($.arguments),
          ')',
        ),
      ),

    arguments: ($) => commaSep1($._argument),

    _argument: ($) => choice($.spread_argument, $.labeled_argument, $._expression),

    spread_argument: ($) => seq('..', $._expression),

    labeled_argument: ($) =>
      prec(
        1,
        seq(field('label', $.identifier), ':', field('value', $._expression)),
      ),

    index_expression: ($) =>
      prec(
        10,
        seq(
          field('value', $._postfix_expression),
          token.immediate('['),
          field('index', $._expression),
          ']',
        ),
      ),

    field_expression: ($) =>
      prec(
        10,
        seq(
          field('value', $._postfix_expression),
          '.',
          // A number field is a tuple index; `x.0.1` reaches here as the
          // single number token `0.1`, exactly as the scanner fuses it.
          field('field', choice($.identifier, $.type_identifier, $.number)),
        ),
      ),

    _primary_expression: ($) =>
      choice(
        $.number,
        $.string,
        $.identifier,
        $.type_identifier,
        $.tuple_expression,
        $.block,
        $.array_expression,
        $.binary_literal,
        $.if_expression,
        $.match_expression,
        $.function_expression,
      ),

    // 2+ elements: `(x)` grouping does not exist (blocks group instead).
    tuple_expression: ($) =>
      seq('(', $._expression, ',', commaSep1($._expression), ')'),

    block: ($) => seq('{', repeat($._node), '}'),

    array_expression: ($) =>
      seq('[', commaSep(choice($.spread_argument, $._expression)), ']'),

    binary_literal: ($) =>
      seq('<<', commaSep($.binary_segment), '>>'),

    binary_segment: ($) =>
      seq(
        field('value', choice($._expression, $.rest_pattern)),
        optional(seq(':', field('spec', $.binary_spec))),
      ),

    // Contextual identifiers, not keywords (parse_bin_spec matches by text).
    binary_spec: ($) =>
      choice(
        $.number,
        seq(
          field('name', alias(choice(...lex.binSpecSized), $.spec_identifier)),
          '(',
          $._expression,
          ')',
        ),
        field('name', alias(choice(...lex.binSpecBare), $.spec_identifier)),
      ),

    if_expression: ($) =>
      seq(
        kw('if'),
        field('condition', $._expression),
        field('consequence', $.block),
        kw('else'),
        field('alternative', choice($.if_expression, $.block)),
      ),

    match_expression: ($) =>
      seq(kw('match'), field('value', $._expression), '{', repeat($.match_arm), '}'),

    match_arm: ($) =>
      seq(
        optional('|'),
        field('pattern', $._pattern),
        optional(seq(kw('if'), field('guard', $._expression))),
        '->',
        field('value', $._expression),
      ),

    // A lambda body is a single expression; a block when it needs statements.
    function_expression: ($) =>
      prec.right(
        seq(kw('fn'), field('parameters', $.parameters), field('body', $._expression)),
      ),

    // -----------------------------------------------------------------------
    // Patterns
    // -----------------------------------------------------------------------

    _pattern: ($) => choice($.or_pattern, $.range_pattern, $._pattern_atom),

    or_pattern: ($) =>
      prec.left(seq($._pattern, '|', $._pattern)),

    // Both bounds must be number literals; end-exclusive like ranges.
    range_pattern: ($) => seq($._number_pattern, '..', $._number_pattern),

    _number_pattern: ($) => choice($.number, $.negative_number),

    negative_number: ($) =>
      seq(choice('-', alias($._minus_line_start, '-')), $.number),

    _pattern_atom: ($) =>
      choice(
        $.identifier,
        $.ctor_pattern,
        $.number,
        $.negative_number,
        $.string,
        $.tuple_pattern,
        $.array_pattern,
        $.binary_pattern,
      ),

    ctor_pattern: ($) =>
      seq(
        optional(seq(field('module', $.identifier), '.')),
        field('name', $.type_identifier),
        optional(seq(token.immediate('('), optional($.pattern_arguments), ')')),
      ),

    pattern_arguments: ($) => commaSep1($._pattern_argument),

    _pattern_argument: ($) =>
      choice($.labeled_pattern, $._pattern, $.rest_pattern),

    labeled_pattern: ($) =>
      prec(
        1,
        seq(field('label', $.identifier), ':', field('pattern', $._pattern)),
      ),

    // `..` / `..rest`: remaining fields, elements, or bytes.
    rest_pattern: ($) => prec.right(seq('..', optional(field('binder', $.identifier)))),

    tuple_pattern: ($) => seq('(', $._pattern, ',', commaSep1($._pattern), ')'),

    array_pattern: ($) =>
      seq('[', commaSep(choice($.rest_pattern, $._pattern)), ']'),

    binary_pattern: ($) => seq('<<', commaSep($.binary_pattern_segment), '>>'),

    binary_pattern_segment: ($) =>
      seq(
        field('value', choice($._pattern_atom, $.rest_pattern)),
        optional(seq(':', field('spec', $.binary_spec))),
      ),

    // -----------------------------------------------------------------------
    // Strings (single-line; both quotes; `${expr}` and `$name` interpolation)
    // -----------------------------------------------------------------------

    string: ($) =>
      choice(
        seq(
          "'",
          repeat(
            choice(
              $.escape_sequence,
              $.interpolation,
              $.short_interpolation,
              alias(token.immediate(prec(1, /[^'\\$\n]+/)), $.string_content),
              alias(token.immediate('$'), $.string_content),
            ),
          ),
          "'",
        ),
        seq(
          '"',
          repeat(
            choice(
              $.escape_sequence,
              $.interpolation,
              $.short_interpolation,
              alias(token.immediate(prec(1, /[^"\\$\n]+/)), $.string_content),
              alias(token.immediate('$'), $.string_content),
            ),
          ),
          '"',
        ),
      ),

    escape_sequence: () => token.immediate(lex.escape),

    interpolation: ($) =>
      seq(token.immediate('${'), $._expression, '}'),

    short_interpolation: ($) =>
      token.immediate(seq('$', lex.identifier)),

    // -----------------------------------------------------------------------
    // Terminals
    // -----------------------------------------------------------------------

    identifier: () =>
      token(new RegExp(`[a-z_][A-Za-z0-9_]*`)),

    // token::is_type_name: a leading uppercase letter marks a type or
    // constructor name; the language's only case rule.
    type_identifier: () => token(new RegExp(`[A-Z][A-Za-z0-9_]*`)),

    number: () => token(lex.number),

    line_comment: () => token(seq('//', /[^\n\r]*/)),

    // `/**` opens a doc comment, but `/**/` does not. Non-nesting.
    doc_comment: () => token(prec(1, /\/\*\*[^*]([^*]|\*+[^*/])*\*+\//)),

    block_comment: () => token(/\/\*([^*]|\*+[^*/])*\*+\//),
  },
});

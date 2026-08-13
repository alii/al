// GENERATED FILE - do not edit. Regenerate with: cargo xtask gen-editor-syntax
// Source of truth: crates/scarlet_syntax (token/keywords.rs, token/kind.rs,
// scanner ESCAPES). grammar.js holds the hand-written structural rules and
// consumes these tables so the lexical layer cannot drift from the compiler.
'use strict';

module.exports = {
  // Keyword::ALL. Every one is reserved: none may parse as an identifier.
  keywords: ['fn', 'import', 'type', 'in', 'match', 'const', 'if', 'else', 'or', 'pub', 'opaque', 'as'],
  // token::is_name_start / is_name_continue.
  identifier: /[A-Za-z_][A-Za-z0-9_]*/,
  // Scanner::scan_number: digits, optionally one '.' followed by digits, with
  // `_` accepted anywhere it sits between two digits (`1_000.000_1`). A `_`
  // with no digit after it ends the token, and so does a '.' with no digit
  // after it.
  number: /\d+(_\d+)*(\.\d+(_\d+)*)?/,
  // scanner::ESCAPES; anything else after a backslash is an error.
  escape: /\\[ntr0"'\\$]/,
  // Contextual identifiers in << >> segment specs (parse_bin_spec).
  binSpecSized: ['size', 'bytes'],
  binSpecBare: ['binary', 'utf8'],
};

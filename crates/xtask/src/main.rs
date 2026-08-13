//! Workspace tooling. `cargo xtask gen-editor-syntax` generates the lexical
//! layer of both editor grammars from the compiler's own token tables:
//!
//! - `scarlet.tmLanguage.json` (repo root, symlinked into the VSCode
//!   extension) is fully generated.
//! - `editors/tree-sitter-scarlet/lexical.js` feeds the tree-sitter grammar,
//!   whose structural rules are hand-written in `grammar.js`.
//!
//! Keywords come from `Keyword::ALL`, operator spellings from
//! `Kind::fixed_spelling_kinds`, and string escapes from `scanner::ESCAPES`,
//! so the editors cannot drift from the scanner. The exhaustive matches below
//! force a new keyword or token kind to be classified here before the
//! workspace compiles again, and `cargo test -p xtask` fails until the
//! checked-in files are regenerated.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use scarlet_syntax::scanner::ESCAPES;
use scarlet_syntax::token::{Keyword, Kind};
use serde_json::{Value, json};

mod scrl_census;

/// The contextual identifiers accepted as `<< expr:spec >>` segment specs.
/// They are not keywords; the parser matches them by text in
/// `parse_bin_spec` (`parser/mod.rs`), which its error message enumerates.
const BIN_SPEC_SIZED: &[&str] = &["size", "bytes"];
const BIN_SPEC_BARE: &[&str] = &["binary", "utf8"];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen-editor-syntax") => {
            let check = args.iter().any(|a| a == "--check");
            match run(check) {
                Ok(()) => ExitCode::SUCCESS,
                Err(message) => {
                    eprintln!("{message}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("scrl-census") => {
            let rest = &args[1..];
            match scrl_census_args(rest) {
                Ok((roots, min_bools)) => {
                    let census = scrl_census::run(&roots, min_bools);
                    print!("{}", scrl_census::report(&census, min_bools));
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!(
                "usage: cargo xtask gen-editor-syntax [--check]\n\
                        cargo xtask scrl-census [--min-bools N] [path ...]"
            );
            ExitCode::FAILURE
        }
    }
}

/// `[--min-bools N] [path ...]`. Paths default to this repo, and are taken as
/// given so the census can be pointed at the other two `.scrl` corpora
/// (`madder`, `website`) without the tool knowing they exist.
fn scrl_census_args(args: &[String]) -> Result<(Vec<PathBuf>, usize), CensusArgsError> {
    let mut roots = Vec::new();
    let mut min_bools = scrl_census::DEFAULT_MIN_BOOLS;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--min-bools" {
            let value = rest.next().ok_or(CensusArgsError::MissingValue)?;
            min_bools = value
                .parse()
                .map_err(|source| CensusArgsError::NotANumber {
                    value: value.clone(),
                    source,
                })?;
            if min_bools < 2 {
                return Err(CensusArgsError::BelowMin);
            }
        } else if let Some(flag) = arg.strip_prefix("--") {
            return Err(CensusArgsError::UnknownFlag(flag.to_string()));
        } else {
            roots.push(PathBuf::from(arg));
        }
    }
    if roots.is_empty() {
        roots.push(repo_root());
    }
    Ok((roots, min_bools))
}

#[derive(Debug)]
enum CensusArgsError {
    MissingValue,
    NotANumber {
        value: String,
        source: std::num::ParseIntError,
    },
    BelowMin,
    UnknownFlag(String),
}

impl std::fmt::Display for CensusArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CensusArgsError::MissingValue => write!(f, "--min-bools needs a value"),
            CensusArgsError::NotANumber { value, source } => {
                write!(f, "--min-bools: not a number: {value}: {source}")
            }
            CensusArgsError::BelowMin => write!(f, "--min-bools below 2 is meaningless"),
            CensusArgsError::UnknownFlag(flag) => write!(f, "unknown flag: --{flag}"),
        }
    }
}

enum GenError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Stale(Vec<String>),
}

impl std::fmt::Display for GenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            GenError::Stale(paths) => write!(
                f,
                "stale generated files (run `cargo xtask gen-editor-syntax`):\n  {}",
                paths.join("\n  ")
            ),
        }
    }
}

fn run(check: bool) -> Result<(), GenError> {
    let mut stale = Vec::new();
    for (path, contents) in outputs() {
        if check {
            let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
            if on_disk != contents {
                stale.push(path.display().to_string());
            }
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| GenError::Io {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
            std::fs::write(&path, contents).map_err(|e| GenError::Io {
                path: path.clone(),
                source: e,
            })?;
            println!("wrote {}", path.display());
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(GenError::Stale(stale))
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask lives at <root>/crates/xtask")
        .to_path_buf()
}

fn outputs() -> Vec<(PathBuf, String)> {
    let root = repo_root();
    vec![
        (root.join("scarlet.tmLanguage.json"), tm_language()),
        (
            root.join("editors/tree-sitter-scarlet/lexical.js"),
            lexical_js(),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Token classification
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeywordGroup {
    Control,
    Import,
    Modifier,
    Declaration,
}

fn keyword_group(kw: Keyword) -> KeywordGroup {
    match kw {
        Keyword::If | Keyword::Else | Keyword::Match | Keyword::Or | Keyword::In => {
            KeywordGroup::Control
        }
        Keyword::Import | Keyword::As => KeywordGroup::Import,
        Keyword::Pub | Keyword::Opaque => KeywordGroup::Modifier,
        Keyword::Fn | Keyword::Type | Keyword::Const => KeywordGroup::Declaration,
    }
}

fn keyword_alternation(group: KeywordGroup) -> String {
    Keyword::ALL
        .into_iter()
        .filter(|kw| keyword_group(*kw) == group)
        .map(Keyword::text)
        .collect::<Vec<_>>()
        .join("|")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpGroup {
    /// `++`, `--`, `;`, `?`: scanned, but no parser rule consumes them, so
    /// they are always a parse error.
    Invalid,
    Arrow,
    Backpass,
    Range,
    Comparison,
    Logical,
    PatternAlternation,
    Arithmetic,
    Assignment,
    Attribute,
}

enum TokenClass {
    Keyword,
    Operator(OpGroup),
    /// `<<` / `>>`, consumed by the `#binary` region rule.
    BinaryDelimiter,
    Punctuation(&'static str),
}

fn classify(kind: &Kind) -> TokenClass {
    match kind {
        // Payload-bearing or positional: not in the fixed-spelling list.
        Kind::Eof
        | Kind::Error(_)
        | Kind::Identifier(_)
        | Kind::LiteralNumber(_)
        | Kind::LiteralString(_)
        | Kind::InterpStringStart
        | Kind::InterpStringPart(_)
        | Kind::InterpStringEnd => unreachable!("{kind:?} has no fixed spelling"),
        Kind::Keyword(_) => TokenClass::Keyword,
        Kind::PuncArrow => TokenClass::Operator(OpGroup::Arrow),
        Kind::PuncBackArrow => TokenClass::Operator(OpGroup::Backpass),
        Kind::PuncDotdot => TokenClass::Operator(OpGroup::Range),
        Kind::PuncEqualsComparator
        | Kind::PuncNotEqual
        | Kind::PuncLte
        | Kind::PuncGte
        | Kind::PuncLt
        | Kind::PuncGt => TokenClass::Operator(OpGroup::Comparison),
        Kind::LogicalAnd | Kind::LogicalOr | Kind::PuncExclamationMark => {
            TokenClass::Operator(OpGroup::Logical)
        }
        Kind::BitwiseOr => TokenClass::Operator(OpGroup::PatternAlternation),
        Kind::PuncPlus | Kind::PuncMinus | Kind::PuncMul | Kind::PuncDiv | Kind::PuncMod => {
            TokenClass::Operator(OpGroup::Arithmetic)
        }
        Kind::PuncEquals => TokenClass::Operator(OpGroup::Assignment),
        Kind::PuncAt => TokenClass::Operator(OpGroup::Attribute),
        Kind::BinOpen | Kind::BinClose => TokenClass::BinaryDelimiter,
        Kind::PuncPlusplus
        | Kind::PuncMinusminus
        | Kind::PuncSemicolon
        | Kind::PuncQuestionMark => TokenClass::Operator(OpGroup::Invalid),
        Kind::PuncComma => TokenClass::Punctuation("punctuation.separator.comma.scrl"),
        Kind::PuncColon => TokenClass::Punctuation("punctuation.separator.colon.scrl"),
        Kind::PuncDot => TokenClass::Punctuation("punctuation.accessor.scrl"),
        Kind::PuncOpenParen => TokenClass::Punctuation("punctuation.section.parens.begin.scrl"),
        Kind::PuncCloseParen => TokenClass::Punctuation("punctuation.section.parens.end.scrl"),
        Kind::PuncOpenBrace => TokenClass::Punctuation("punctuation.section.braces.begin.scrl"),
        Kind::PuncCloseBrace => TokenClass::Punctuation("punctuation.section.braces.end.scrl"),
        Kind::PuncOpenBracket => TokenClass::Punctuation("punctuation.section.brackets.begin.scrl"),
        Kind::PuncCloseBracket => TokenClass::Punctuation("punctuation.section.brackets.end.scrl"),
    }
}

fn op_group_scope(group: OpGroup) -> &'static str {
    match group {
        OpGroup::Invalid => "invalid.illegal.unsupported-operator.scrl",
        OpGroup::Arrow => "keyword.operator.arrow.scrl",
        OpGroup::Backpass => "keyword.operator.backpass.scrl",
        // Historical scope name; `..` is both range and spread.
        OpGroup::Range => "keyword.operator.spread.scrl",
        OpGroup::Comparison => "keyword.operator.comparison.scrl",
        OpGroup::Logical => "keyword.operator.logical.scrl",
        OpGroup::PatternAlternation => "keyword.operator.pattern.scrl",
        OpGroup::Arithmetic => "keyword.operator.arithmetic.scrl",
        OpGroup::Assignment => "keyword.operator.assignment.scrl",
        OpGroup::Attribute => "keyword.operator.attribute.scrl",
    }
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "\\^$.|?*+()[]{}/".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// One alternation regex per operator group, longest spelling first so `<=`
/// wins over `<` inside the same rule. Rule order across groups matters the
/// same way: `Invalid` precedes `Arithmetic` so `++` wins over `+`, `Logical`
/// precedes `PatternAlternation` so `||` wins over `|`, and `Comparison`
/// precedes `Assignment` so `==` wins over `=`.
fn operator_rules() -> Vec<Value> {
    const ORDER: &[OpGroup] = &[
        OpGroup::Invalid,
        OpGroup::Arrow,
        OpGroup::Backpass,
        OpGroup::Range,
        OpGroup::Comparison,
        OpGroup::Logical,
        OpGroup::PatternAlternation,
        OpGroup::Arithmetic,
        OpGroup::Assignment,
        OpGroup::Attribute,
    ];
    let kinds = Kind::fixed_spelling_kinds();
    ORDER
        .iter()
        .map(|&group| {
            let mut spellings: Vec<String> = kinds
                .iter()
                .filter(|k| matches!(classify(k), TokenClass::Operator(g) if g == group))
                .map(Kind::to_string)
                .collect();
            spellings.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
            let alternation = spellings
                .iter()
                .map(|s| regex_escape(s))
                .collect::<Vec<_>>()
                .join("|");
            json!({
                "name": op_group_scope(group),
                "match": format!("({alternation})"),
            })
        })
        .collect()
}

fn punctuation_rules() -> Vec<Value> {
    Kind::fixed_spelling_kinds()
        .iter()
        .filter_map(|kind| match classify(kind) {
            TokenClass::Punctuation(scope) => Some(json!({
                "name": scope,
                "match": regex_escape(&kind.to_string()),
            })),
            // Routed by other sections: keywords by the keyword
            // alternations, operators by `operator_rules`, `<<`/`>>` by the
            // `#binary` region rule. A new class must pick its section.
            TokenClass::Keyword | TokenClass::Operator(_) | TokenClass::BinaryDelimiter => None,
        })
        .collect()
}

/// The regex character class matching every char valid after `\` in a string,
/// straight from the scanner's escape table.
fn escape_char_class() -> String {
    let mut class = String::new();
    for &(source, _) in ESCAPES {
        match source {
            b'\\' => class.push_str("\\\\"),
            b']' => class.push_str("\\]"),
            c => class.push(c as char),
        }
    }
    class
}

// ---------------------------------------------------------------------------
// tmLanguage (VSCode)
// ---------------------------------------------------------------------------

fn tm_language() -> String {
    let k = Keyword::text;
    let escape_rule = json!({
        "name": "constant.character.escape.scrl",
        "match": format!("\\\\[{}]", escape_char_class()),
    });
    let bad_escape_rule = json!({
        "name": "invalid.illegal.escape.scrl",
        "match": "\\\\.",
    });
    let interpolation_region = json!({
        "name": "meta.interpolation.scrl",
        "begin": "\\$\\{",
        "end": "\\}",
        "beginCaptures": { "0": { "name": "punctuation.section.interpolation.begin.scrl" } },
        "endCaptures": { "0": { "name": "punctuation.section.interpolation.end.scrl" } },
        "patterns": [{ "include": "#interpolation-expression" }]
    });
    let interpolation_shorthand = json!({
        "name": "variable.other.interpolation.scrl",
        "match": "\\$[a-zA-Z_][a-zA-Z0-9_]*",
    });
    let string_body = |quote: &str| -> Value {
        json!({
            "name": format!("string.quoted.{}.scrl", if quote == "'" { "single" } else { "double" }),
            "begin": quote,
            "end": format!("{quote}|$"),
            "patterns": [
                escape_rule,
                bad_escape_rule,
                interpolation_region,
                interpolation_shorthand,
            ]
        })
    };

    let sized_specs = BIN_SPEC_SIZED.join("|");
    let bare_specs = BIN_SPEC_BARE.join("|");

    let grammar = json!({
        "name": "Scarlet",
        "scopeName": "source.scrl",
        "patterns": [
            { "include": "#comments" },
            { "include": "#attributes" },
            { "include": "#strings" },
            { "include": "#numbers" },
            { "include": "#binary" },
            { "include": "#import-statement" },
            { "include": "#type-definition" },
            { "include": "#function-definition" },
            { "include": "#const-definition" },
            { "include": "#variable-with-type" },
            { "include": "#backpass-binding" },
            { "include": "#keywords" },
            { "include": "#constants" },
            { "include": "#module-qualified-access" },
            { "include": "#constructor-call" },
            { "include": "#function-call" },
            { "include": "#labeled-argument" },
            { "include": "#types" },
            { "include": "#operators" },
            { "include": "#punctuation" }
        ],
        "repository": {
            "attributes": {
                "patterns": [
                    {
                        "name": "meta.attribute.scrl",
                        "match": "(@)([a-zA-Z_][a-zA-Z0-9_]*)(\\()?([a-zA-Z_][a-zA-Z0-9_]*)?(\\))?",
                        "captures": {
                            "1": { "name": "punctuation.definition.attribute.scrl" },
                            "2": { "name": "entity.name.function.decorator.scrl" },
                            "3": { "name": "punctuation.brackets.round.scrl" },
                            "4": { "name": "string.unquoted.attribute.scrl" },
                            "5": { "name": "punctuation.brackets.round.scrl" }
                        }
                    }
                ]
            },
            "comments": {
                "patterns": [
                    {
                        "name": "comment.line.double-slash.scrl",
                        "match": "//.*$"
                    },
                    {
                        "comment": "`/**` opens a doc comment, but `/**/` does not.",
                        "name": "comment.block.documentation.scrl",
                        "begin": "/\\*\\*(?!/)",
                        "end": "\\*/"
                    },
                    {
                        "name": "comment.block.scrl",
                        "begin": "/\\*",
                        "end": "\\*/"
                    }
                ]
            },
            "strings": {
                "patterns": [string_body("'"), string_body("\"")]
            },
            "numbers": {
                "comment": "Scanner::scan_number. `_` is a digit separator and only valid between two digits, so it is written as a repeated `_\\d+` group rather than folded into the digit class — `1_` and `_1` are not numbers.",
                "patterns": [
                    {
                        "name": "constant.numeric.float.scrl",
                        "match": "\\b\\d+(?:_\\d+)*\\.\\d+(?:_\\d+)*\\b"
                    },
                    {
                        "name": "constant.numeric.integer.scrl",
                        "match": "\\b\\d+(?:_\\d+)*\\b"
                    }
                ]
            },
            "binary": {
                "comment": "Bit-string literal or pattern: <<expr:spec, ..rest>>. The spec names are contextual identifiers, not keywords.",
                "begin": "<<",
                "end": ">>",
                "beginCaptures": { "0": { "name": "punctuation.definition.binary.begin.scrl" } },
                "endCaptures": { "0": { "name": "punctuation.definition.binary.end.scrl" } },
                "patterns": [
                    { "include": "#comments" },
                    { "include": "#strings" },
                    { "include": "#numbers" },
                    {
                        "match": format!("(:)\\s*({sized_specs})(?=\\s*\\()"),
                        "captures": {
                            "1": { "name": "punctuation.separator.colon.scrl" },
                            "2": { "name": "storage.type.binary-spec.scrl" }
                        }
                    },
                    {
                        "match": format!("(:)\\s*({bare_specs})\\b"),
                        "captures": {
                            "1": { "name": "punctuation.separator.colon.scrl" },
                            "2": { "name": "storage.type.binary-spec.scrl" }
                        }
                    },
                    {
                        "name": "keyword.operator.spread.scrl",
                        "match": "\\.\\."
                    },
                    { "include": "#constants" },
                    { "include": "#module-qualified-access" },
                    { "include": "#constructor-call" },
                    { "include": "#function-call" },
                    { "include": "#types" },
                    { "include": "#operators" },
                    {
                        "name": "variable.other.scrl",
                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                    },
                    { "include": "#punctuation" }
                ]
            },
            "interpolation-expression": {
                "patterns": [
                    { "include": "#strings" },
                    { "include": "#numbers" },
                    { "include": "#binary" },
                    { "include": "#keywords" },
                    { "include": "#constants" },
                    { "include": "#module-qualified-access" },
                    { "include": "#constructor-call" },
                    { "include": "#function-call" },
                    { "include": "#labeled-argument" },
                    { "include": "#types" },
                    { "include": "#operators" },
                    {
                        "name": "variable.other.scrl",
                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                    },
                    { "include": "#punctuation" }
                ]
            },
            "import-statement": {
                "begin": format!("\\b({})\\b", k(Keyword::Import)),
                "beginCaptures": {
                    "1": { "name": "keyword.control.import.scrl" }
                },
                "end": "(?=$|\\n)",
                "patterns": [
                    {
                        "name": "keyword.control.import.scrl",
                        "match": format!("\\b({})\\b", k(Keyword::As))
                    },
                    {
                        "name": "punctuation.separator.path.scrl",
                        "match": "/"
                    },
                    {
                        "name": "entity.name.type.scrl",
                        "match": "\\b[A-Z][a-zA-Z0-9_]*\\b"
                    },
                    {
                        "name": "entity.name.namespace.scrl",
                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                    },
                    {
                        "name": "punctuation.accessor.scrl",
                        "match": "\\."
                    },
                    { "include": "#punctuation" }
                ]
            },
            "type-definition": {
                "patterns": [
                    {
                        "comment": "type alias: type Name(params) = Type",
                        "match": format!(
                            "\\b({pub}\\s+)?({opaque}\\s+)?({type_})\\s+([A-Z][a-zA-Z0-9_]*)(?:\\s*\\(([^)]*)\\))?\\s*(=)",
                            pub = k(Keyword::Pub), opaque = k(Keyword::Opaque), type_ = k(Keyword::Type)
                        ),
                        "captures": {
                            "1": { "name": "storage.modifier.visibility.scrl" },
                            "2": { "name": "storage.modifier.visibility.scrl" },
                            "3": { "name": "keyword.other.type.scrl" },
                            "4": { "name": "entity.name.type.scrl" },
                            "5": {
                                "patterns": [
                                    {
                                        "name": "variable.other.type.scrl",
                                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                                    }
                                ]
                            },
                            "6": { "name": "keyword.operator.assignment.scrl" }
                        }
                    },
                    {
                        "comment": "external type: type Name(params) with no body, ends at EOL",
                        "match": format!(
                            "\\b({pub}\\s+)?({opaque}\\s+)?({type_})\\s+([A-Z][a-zA-Z0-9_]*)(?:\\s*\\(([^)]*)\\))?\\s*$",
                            pub = k(Keyword::Pub), opaque = k(Keyword::Opaque), type_ = k(Keyword::Type)
                        ),
                        "captures": {
                            "1": { "name": "storage.modifier.visibility.scrl" },
                            "2": { "name": "storage.modifier.visibility.scrl" },
                            "3": { "name": "keyword.other.type.scrl" },
                            "4": { "name": "entity.name.type.scrl" },
                            "5": {
                                "patterns": [
                                    {
                                        "name": "variable.other.type.scrl",
                                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                                    }
                                ]
                            }
                        }
                    },
                    {
                        "comment": "type definition: type Name(params) { ... }",
                        "begin": format!(
                            "\\b({pub}\\s+)?({opaque}\\s+)?({type_})\\s+([A-Z][a-zA-Z0-9_]*)(?:\\s*(\\())?",
                            pub = k(Keyword::Pub), opaque = k(Keyword::Opaque), type_ = k(Keyword::Type)
                        ),
                        "beginCaptures": {
                            "1": { "name": "storage.modifier.visibility.scrl" },
                            "2": { "name": "storage.modifier.visibility.scrl" },
                            "3": { "name": "keyword.other.type.scrl" },
                            "4": { "name": "entity.name.type.scrl" },
                            "5": { "name": "punctuation.definition.typeparameters.begin.scrl" }
                        },
                        "end": "\\}",
                        "endCaptures": {
                            "0": { "name": "punctuation.definition.type.end.scrl" }
                        },
                        "patterns": [
                            { "include": "#comments" },
                            { "include": "#generic-params" },
                            { "include": "#type-body" }
                        ]
                    }
                ]
            },
            "generic-params": {
                "begin": "(?<=\\()",
                "end": "\\)",
                "endCaptures": {
                    "0": { "name": "punctuation.definition.typeparameters.end.scrl" }
                },
                "patterns": [
                    {
                        "name": "variable.other.type.scrl",
                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                    },
                    {
                        "name": "punctuation.separator.comma.scrl",
                        "match": ","
                    }
                ]
            },
            "type-body": {
                "begin": "\\{",
                "beginCaptures": {
                    "0": { "name": "punctuation.definition.type.begin.scrl" }
                },
                "end": "(?=\\})",
                "patterns": [
                    { "include": "#comments" },
                    {
                        "comment": "Constructor with payload: Ctor(label Type, ...)",
                        "begin": "\\b([A-Z][a-zA-Z0-9_]*)\\s*(\\()",
                        "beginCaptures": {
                            "1": { "name": "entity.name.function.constructor.scrl" },
                            "2": { "name": "punctuation.definition.parameters.begin.scrl" }
                        },
                        "end": "\\)",
                        "endCaptures": {
                            "0": { "name": "punctuation.definition.parameters.end.scrl" }
                        },
                        "patterns": [{ "include": "#field-decl" }]
                    },
                    {
                        "comment": "Nullary constructor",
                        "name": "entity.name.function.constructor.scrl",
                        "match": "\\b[A-Z][a-zA-Z0-9_]*\\b"
                    },
                    { "include": "#field-decl" }
                ]
            },
            "field-decl": {
                "patterns": [
                    {
                        "comment": "Field label + concrete type",
                        "match": "\\b([a-z_][a-zA-Z0-9_]*)\\s+([A-Z][a-zA-Z0-9_]*)\\b",
                        "captures": {
                            "1": { "name": "variable.other.member.scrl" },
                            "2": { "name": "entity.name.type.scrl" }
                        }
                    },
                    {
                        "comment": "Field label + type parameter",
                        "match": "\\b([a-z_][a-zA-Z0-9_]*)\\s+([a-z_][a-zA-Z0-9_]*)\\b",
                        "captures": {
                            "1": { "name": "variable.other.member.scrl" },
                            "2": { "name": "variable.other.type.scrl" }
                        }
                    },
                    {
                        "name": "entity.name.type.scrl",
                        "match": "\\b[A-Z][a-zA-Z0-9_]*\\b"
                    },
                    {
                        "name": "punctuation.separator.comma.scrl",
                        "match": ","
                    },
                    { "include": "#punctuation" }
                ]
            },
            "function-definition": {
                "begin": format!(
                    "\\b({pub}\\s+)?({fn_})\\s+([a-z_][a-zA-Z0-9_]*)",
                    pub = k(Keyword::Pub), fn_ = k(Keyword::Fn)
                ),
                "beginCaptures": {
                    "1": { "name": "storage.modifier.visibility.scrl" },
                    "2": { "name": "keyword.other.fn.scrl" },
                    "3": { "name": "entity.name.function.scrl" }
                },
                "end": "(?=\\{|\\n|$)",
                "patterns": [
                    { "include": "#comments" },
                    { "include": "#function-params" },
                    { "include": "#type-args" },
                    {
                        "name": "keyword.other.fn.scrl",
                        "match": format!("\\b{}\\b", k(Keyword::Fn))
                    },
                    {
                        "name": "entity.name.type.scrl",
                        "match": "\\b[A-Z][a-zA-Z0-9_]*\\b"
                    },
                    {
                        "name": "variable.other.type.scrl",
                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                    }
                ]
            },
            "function-params": {
                "comment": "The param list opens immediately after the function name (\\G) and closes at the matching paren. Nested type-argument parens are consumed by #type-args so the inner ) of e.g. Option(a) cannot end the list early.",
                "begin": "\\G\\s*(\\()",
                "beginCaptures": {
                    "1": { "name": "punctuation.definition.parameters.begin.scrl" }
                },
                "end": "\\)",
                "endCaptures": {
                    "0": { "name": "punctuation.definition.parameters.end.scrl" }
                },
                "patterns": [
                    { "include": "#comments" },
                    { "include": "#type-args" },
                    {
                        "match": "\\b([a-z_][a-zA-Z0-9_]*)\\s+([A-Z][a-zA-Z0-9_]*)\\b",
                        "captures": {
                            "1": { "name": "variable.parameter.scrl" },
                            "2": { "name": "entity.name.type.scrl" }
                        }
                    },
                    {
                        "match": format!("\\b([a-z_][a-zA-Z0-9_]*)\\s+({})\\b", k(Keyword::Fn)),
                        "captures": {
                            "1": { "name": "variable.parameter.scrl" },
                            "2": { "name": "keyword.other.fn.scrl" }
                        }
                    },
                    {
                        "match": "\\b([a-z_][a-zA-Z0-9_]*)\\s+([a-z_][a-zA-Z0-9_]*)\\b",
                        "captures": {
                            "1": { "name": "variable.parameter.scrl" },
                            "2": { "name": "variable.other.type.scrl" }
                        }
                    },
                    {
                        "name": "variable.parameter.scrl",
                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                    },
                    {
                        "name": "punctuation.separator.comma.scrl",
                        "match": ","
                    }
                ]
            },
            "type-args": {
                "comment": "Balanced ( ... ) for a parametrized/fn type. Recursive so Option(List(a)) and Result(a, e) nest correctly.",
                "begin": "\\(",
                "beginCaptures": {
                    "0": { "name": "punctuation.definition.typeparameters.begin.scrl" }
                },
                "end": "\\)",
                "endCaptures": {
                    "0": { "name": "punctuation.definition.typeparameters.end.scrl" }
                },
                "patterns": [
                    { "include": "#comments" },
                    {
                        "name": "keyword.other.fn.scrl",
                        "match": format!("\\b{}\\b", k(Keyword::Fn))
                    },
                    {
                        "name": "entity.name.type.scrl",
                        "match": "\\b[A-Z][a-zA-Z0-9_]*\\b"
                    },
                    { "include": "#type-args" },
                    {
                        "name": "variable.other.type.scrl",
                        "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                    },
                    {
                        "name": "punctuation.separator.comma.scrl",
                        "match": ","
                    }
                ]
            },
            "const-definition": {
                "comment": "The declared name is scoped like a fn declaration name so themes colour toplevel value declarations uniformly.",
                "match": format!(
                    "\\b({pub}\\s+)?({const_})\\s+([a-zA-Z_][a-zA-Z0-9_]*)\\s*(?:([A-Z][a-zA-Z0-9_]*)\\s*)?(=)",
                    pub = k(Keyword::Pub), const_ = k(Keyword::Const)
                ),
                "captures": {
                    "1": { "name": "storage.modifier.visibility.scrl" },
                    "2": { "name": "keyword.other.const.scrl" },
                    "3": { "name": "entity.name.function.scrl" },
                    "4": { "name": "entity.name.type.scrl" },
                    "5": { "name": "keyword.operator.assignment.scrl" }
                }
            },
            "variable-with-type": {
                "comment": "Variable declaration with type annotation: name Type = ...",
                "match": "\\b([a-z_][a-zA-Z0-9_]*)\\s+([A-Z][a-zA-Z0-9_]*)\\s*(=)",
                "captures": {
                    "1": { "name": "variable.other.scrl" },
                    "2": { "name": "entity.name.type.scrl" },
                    "3": { "name": "keyword.operator.assignment.scrl" }
                }
            },
            "backpass-binding": {
                "comment": "Backpass statement: binder(s) <- call(...)",
                "match": "\\b([a-z_][a-zA-Z0-9_]*(?:\\s*,\\s*[a-z_][a-zA-Z0-9_]*)*)\\s*(<-)",
                "captures": {
                    "1": {
                        "patterns": [
                            {
                                "name": "variable.other.scrl",
                                "match": "\\b[a-z_][a-zA-Z0-9_]*\\b"
                            }
                        ]
                    },
                    "2": { "name": "keyword.operator.backpass.scrl" }
                }
            },
            "keywords": {
                "patterns": [
                    {
                        "name": "keyword.control.scrl",
                        "match": format!("\\b({})\\b", keyword_alternation(KeywordGroup::Control))
                    },
                    {
                        "name": "keyword.control.import.scrl",
                        "match": format!("\\b({})\\b", keyword_alternation(KeywordGroup::Import))
                    },
                    {
                        "name": "storage.modifier.visibility.scrl",
                        "match": format!("\\b({})\\b", keyword_alternation(KeywordGroup::Modifier))
                    },
                    {
                        "name": "keyword.other.scrl",
                        "match": format!("\\b({})\\b", keyword_alternation(KeywordGroup::Declaration))
                    }
                ]
            },
            "constants": {
                "comment": "Prelude constructors themes expect as language constants.",
                "patterns": [
                    {
                        "name": "constant.language.boolean.scrl",
                        "match": "\\b(True|False)\\b"
                    },
                    {
                        "name": "constant.language.nil.scrl",
                        "match": "\\bNil\\b"
                    }
                ]
            },
            "module-qualified-access": {
                "comment": "module.name access (lowercase qualifier)",
                "match": "\\b([a-z_][a-zA-Z0-9_]*)(\\.)(?=[A-Za-z_])",
                "captures": {
                    "1": { "name": "entity.name.namespace.scrl" },
                    "2": { "name": "punctuation.accessor.scrl" }
                }
            },
            "constructor-call": {
                "comment": "Constructor invocation / pattern: Uppercase optionally followed by (",
                "match": "\\b([A-Z][a-zA-Z0-9_]*)(?=\\s*\\()",
                "captures": {
                    "1": { "name": "entity.name.function.constructor.scrl" }
                }
            },
            "function-call": {
                "comment": "Function calls",
                "match": "\\b([a-z_][a-zA-Z0-9_]*)(?=\\s*\\()",
                "captures": {
                    "1": { "name": "entity.name.function.scrl" }
                }
            },
            "labeled-argument": {
                "comment": "Labeled call argument: label: value",
                "match": "\\b([a-z_][a-zA-Z0-9_]*)\\s*(:)",
                "captures": {
                    "1": { "name": "variable.parameter.label.scrl" },
                    "2": { "name": "punctuation.separator.colon.scrl" }
                }
            },
            "types": {
                "patterns": [
                    {
                        "comment": "Standalone type name",
                        "name": "entity.name.type.scrl",
                        "match": "\\b[A-Z][a-zA-Z0-9_]*\\b"
                    }
                ]
            },
            "operators": {
                "patterns": operator_rules()
            },
            "punctuation": {
                "patterns": punctuation_rules()
            }
        }
    });

    let mut out = serde_json::to_string_pretty(&grammar).expect("grammar serializes");
    out.push('\n');
    out
}

// ---------------------------------------------------------------------------
// lexical.js (tree-sitter)
// ---------------------------------------------------------------------------

fn lexical_js() -> String {
    let keywords = Keyword::ALL
        .into_iter()
        .map(|kw| format!("'{}'", kw.text()))
        .collect::<Vec<_>>()
        .join(", ");
    let sized = BIN_SPEC_SIZED
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let bare = BIN_SPEC_BARE
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "\
// GENERATED FILE - do not edit. Regenerate with: cargo xtask gen-editor-syntax
// Source of truth: crates/scarlet_syntax (token/keywords.rs, token/kind.rs,
// scanner ESCAPES). grammar.js holds the hand-written structural rules and
// consumes these tables so the lexical layer cannot drift from the compiler.
'use strict';

module.exports = {{
  // Keyword::ALL. Every one is reserved: none may parse as an identifier.
  keywords: [{keywords}],
  // token::is_name_start / is_name_continue.
  identifier: /[A-Za-z_][A-Za-z0-9_]*/,
  // Scanner::scan_number: digits, optionally one '.' followed by digits, with
  // `_` accepted anywhere it sits between two digits (`1_000.000_1`). A `_`
  // with no digit after it ends the token, and so does a '.' with no digit
  // after it.
  number: /\\d+(_\\d+)*(\\.\\d+(_\\d+)*)?/,
  // scanner::ESCAPES; anything else after a backslash is an error.
  escape: /\\\\[{escape_class}]/,
  // Contextual identifiers in << >> segment specs (parse_bin_spec).
  binSpecSized: [{sized}],
  binSpecBare: [{bare}],
}};
",
        escape_class = escape_char_class(),
    )
}

#[cfg(test)]
mod tests {
    use scarlet_syntax::scanner::new_scanner;
    use scarlet_syntax::token::Kind;

    use super::{CensusArgsError, outputs, scrl_census_args};

    /// Number literals are the one part of the lexical layer written as a
    /// hand-copied regex rather than derived from a table, so
    /// `generated_files_are_up_to_date` cannot see it drift: a change to
    /// `Scanner::scan_number` regenerates byte-identical files. This pins the
    /// shape the two regexes encode instead. When it fails, the scanner has
    /// moved and both must move with it — `lexical_js`'s `number` and
    /// `tm_language`'s `numbers` patterns.
    ///
    /// Its own history: `_` digit separators were added to the scanner without
    /// either regex, and the tree-sitter corpus job went red on two examples.
    #[test]
    fn number_regexes_still_describe_the_scanner() {
        // (source, the LiteralNumber token texts it must yield, in order)
        let cases: &[(&str, &[&str])] = &[
            ("1", &["1"]),
            ("1_000_000", &["1_000_000"]),
            ("1.5", &["1.5"]),
            ("1_0.0_1", &["1_0.0_1"]),
            // A `_` or a `.` with no digit after it ends the token, which is
            // why neither regex folds `_` into the digit class.
            ("1_", &["1"]),
            ("1.", &["1"]),
            // Range bounds: the scanner must not fuse `0..10` into one token.
            ("0..10", &["0", "10"]),
        ];
        for (source, want) in cases {
            let (tokens, _) = new_scanner(*source).scan_all();
            let got: Vec<String> = tokens
                .iter()
                .filter_map(|t| match &t.kind {
                    Kind::LiteralNumber(text) => Some(text.to_string()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                got, *want,
                "Scanner::scan_number changed on {source:?}; update the `number` \
                 regex in lexical_js and the `numbers` patterns in tm_language, \
                 then regenerate with `cargo xtask gen-editor-syntax`"
            );
        }
    }

    /// `--min-bools` with a non-number wraps `ParseIntError`. Collapsing it
    /// into a `String` is mordant's `stringified_error`.
    #[test]
    fn min_bools_not_a_number_wraps_parse_int_error() {
        let args = ["--min-bools".into(), "xyz".into()];
        match scrl_census_args(&args) {
            Err(CensusArgsError::NotANumber { value, source }) => {
                assert_eq!(value, "xyz");
                assert_eq!(source.to_string(), "invalid digit found in string");
            }
            other => panic!("expected NotANumber, got {other:?}"),
        }
    }

    #[test]
    fn min_bools_missing_value_and_below_floor() {
        match scrl_census_args(&["--min-bools".into()]) {
            Err(CensusArgsError::MissingValue) => {}
            other => panic!("expected MissingValue, got {other:?}"),
        }
        match scrl_census_args(&["--min-bools".into(), "1".into()]) {
            Err(CensusArgsError::BelowMin) => {}
            other => panic!("expected BelowMin, got {other:?}"),
        }
        match scrl_census_args(&["--nope".into()]) {
            Err(CensusArgsError::UnknownFlag(flag)) => assert_eq!(flag, "nope"),
            other => panic!("expected UnknownFlag, got {other:?}"),
        }
    }

    #[test]
    fn min_bools_and_paths_parse() {
        let (roots, min_bools) =
            scrl_census_args(&["--min-bools".into(), "3".into(), "examples".into()]).unwrap();
        assert_eq!(min_bools, 3);
        assert_eq!(roots, [std::path::PathBuf::from("examples")]);
    }

    /// Regenerating must be a no-op against the checked-in files, so CI fails
    /// when the scanner's token tables change without a regeneration.
    #[test]
    fn generated_files_are_up_to_date() {
        for (path, contents) in outputs() {
            let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
            assert_eq!(
                on_disk,
                contents,
                "{} is stale; run `cargo xtask gen-editor-syntax`",
                path.display()
            );
        }
    }
}

mod common;
use common::check_rejects;

reject_case! {
    int_plus_string_is_type_error: ("pub fn main() {\n\tx = 1 + 'a'\n}\n", "Type mismatch"),
    non_exhaustive_match_is_error: (
        "pub fn main() {\n\tf = fn(x) { match x { True -> 1 } }\n\tprintln(f(False))\n}\n",
        "not exhaustive",
    ),
    unknown_identifier_is_error: ("pub fn main() {\n\tx = foo\n}\n", "Unknown identifier"),
    if_condition_must_be_bool:
        ("pub fn main() {\n\tprintln(if 1 { 2 } else { 3 })\n}\n", "Type mismatch"),

    // All three numeric-literal compile sites: expression, match pattern, range bound.
    integer_literal_overflow_is_error:
        ("pub fn main() {\n\tx = 99999999999999999999999999\n}\n", "out of range for Int"),
    integer_literal_overflow_in_match_pattern_is_error: (
        "pub fn main() {\n\tprintln(match 1 {\n\t\t99999999999999999999999999 -> 0\n\t\t_ -> 1\n\t})\n}\n",
        "out of range for Int",
    ),
    integer_literal_overflow_in_range_pattern_is_error: (
        "pub fn main() {\n\tprintln(match 1 {\n\t\t99999999999999999999999999..0 -> 0\n\t\t_ -> 1\n\t})\n}\n",
        "out of range for Int",
    ),
    hex_literal_overflow_is_error: (
        "pub fn main() {\n\tx = 0x8000000000000000\n}\n",
        "out of range for Int",
    ),
    bin_literal_overflow_is_error: (
        "pub fn main() {\n\tx = 0b1000000000000000000000000000000000000000000000000000000000000000\n}\n",
        "out of range for Int",
    ),
    hex_and_decimal_are_the_same_match_arm: (
        "pub fn main() {\n\tprintln(match 255 {\n\t\t0xFF -> 1\n\t\t255 -> 2\n\t})\n}\n",
        "unreachable",
    ),

    unused_let_binding_is_error: (
        "pub fn main() {\n\tx = 1\n\tprintln('done')\n}\n",
        "'x' is unused; prefix with '_' to ignore",
    ),
    unused_param_is_error: (
        "fn f(a Int, b Int) Int { a }\npub fn main() {\n\tprintln(f(1, 2))\n}\n",
        "'b' is unused; prefix with '_' to ignore",
    ),
    unused_match_binding_is_error: (
        "pub fn main() {\n\tprintln(match Some(1) {\n\t\tSome(x) -> 0\n\t\tNone -> 0\n\t})\n}\n",
        "'x' is unused; prefix with '_' to ignore",
    ),
}

ok_case! {
    underscore_prefix_suppresses_unused_error:
        ("pub fn main() {\n\t_x = 1\n\tprintln('done')\n}\n"),

    used_let_binding_is_ok: ("pub fn main() {\n\tx = 1\n\tprintln(x)\n}\n"),

    closure_capture_counts_as_use:
        ("pub fn main() {\n\tx = 1\n\tf = fn() { x }\n\tprintln(f())\n}\n"),
}

reject_case! {
    // A program is declarations plus `pub fn main()`. Each of the entry rule's
    // diagnostics, as `check` reports them; `check` itself does not need a
    // `main` (see the library-shaped cases below), `run` does.
    statement_at_module_scope_is_error: (
        "println('early')\n\npub fn main() {\n\tprintln('main')\n}\n",
        "Statements are not allowed at module scope: a program's code goes inside `pub fn main()`",
    ),
    binding_at_module_scope_is_error: (
        "x = 1\n\npub fn main() {\n\tprintln(x)\n}\n",
        "Statements are not allowed at module scope: a program's code goes inside `pub fn main()`",
    ),
    private_main_is_error: (
        "fn main() {\n\tprintln('hi')\n}\n",
        "`main` must be public: a program starts at `pub fn main()`",
    ),
    main_with_parameters_is_error: (
        "pub fn main(args Array(String)) {\n\tprintln(args)\n}\n",
        "`main` takes no parameters (arguments are read with `os.argv()`)",
    ),
}

run_reject_case! {
    program_without_main_does_not_run: (
        "fn helper() Int { 1 }\npub fn exported() Int { helper() }\n",
        "No `main` function: a program starts at `pub fn main()`",
    ),
}

ok_case! {
    // A library file has no `main` and still checks.
    library_without_main_checks: ("fn helper() Int { 1 }\npub fn exported() Int { helper() }\n"),
}

reject_case! {
    // Call-site mistakes, both from `match_fun_type`.
    wrong_argument_count_is_error: (
        "fn f(a Int, b Int) Int { a + b }\npub fn main() {\n\tprintln(f(1))\n}\n",
        "Expected 2 argument(s), got 1",
    ),
    calling_non_function_is_error: (
        "pub fn main() {\n\tx = 5\n\ty = x(3)\n\tprintln(y)\n}\n",
        "This value of type 'Int' is not a function and cannot be called",
    ),

    // Backpassing desugars to an appended trailing lambda before inference,
    // so a callee whose last param is not a compatible fn is an ordinary
    // call-site type error.
    backpass_into_non_function_param_is_error: (
        "fn g(a Int, b Int) Int { a + b }\nfn h() Int {\n\tx <- g(1)\n\tx + 0\n}\n\
         pub fn main() {\n\tprintln(h())\n}\n",
        "Type mismatch",
    ),
    backpass_overflows_callee_arity_is_error: (
        "fn g(a Int, b Int) Int { a + b }\nfn h() Int {\n\tx <- g(1, 2)\n\tx + 0\n}\n\
         pub fn main() {\n\tprintln(h())\n}\n",
        "Expected 2 argument(s), got 3",
    ),

    // Construction-site argument diagnostics, all from `slot_ctor_args`.
    ctor_missing_field_is_error: (
        "type P { P(name String, age Int) }\npub fn main() {\n\tprintln(P(name: 'a'))\n}\n",
        "Constructor 'P' is missing field(s): age",
    ),
    ctor_unknown_field_is_error: (
        "type P { P(name String, age Int) }\npub fn main() {\n\tprintln(P(name: 'a', bogus: 1))\n}\n",
        "Constructor 'P' has no field 'bogus'. Available: name, age",
    ),
    ctor_too_many_positional_is_error: (
        "type P { P(name String, age Int) }\npub fn main() {\n\tprintln(P('a', 'b', 'c'))\n}\n",
        "Constructor 'P' has 2 field(s) but more were supplied",
    ),
    ctor_nullary_with_args_is_error: (
        "type C {\n\tRed\n\tGreen\n}\npub fn main() {\n\tprintln(Red(1))\n}\n",
        "Constructor 'Red' has 0 field(s) but more were supplied",
    ),
    ctor_duplicate_field_is_error: (
        "type P { P(name String, age Int) }\n\
         pub fn main() {\n\tprintln(P(name: 'a', name: 'b', age: 1))\n}\n",
        "Field 'name' is specified more than once",
    ),

    /// `type_ctor_pattern` is a separate path from the construction-site checks
    /// above. Only reachable with a constructor-cased name: the parser routes a
    /// lowercase callee to a different pattern form.
    ctor_unknown_in_pattern_is_error: (
        "pub fn main() {\n\tr = match Some(1) {\n\t\tBogus(x) -> 0\n\t\t_ -> 1\n\t}\n\tprintln(r)\n}\n",
        "Unknown constructor 'Bogus' in pattern",
    ),
    ctor_nullary_with_args_in_pattern_is_error: (
        "type C {\n\tRed\n\tGreen\n}\nfn f(c C) Int { match c { Red(x) -> x\n Green -> 0 } }\n\
         pub fn main() {\n\tprintln(f(Red))\n}\n",
        "Constructor 'Red' takes no arguments but 1 were given",
    ),

    /// Inside a `{ }` block every non-last statement must be `Nil` or consumed.
    unconsumed_block_expr_statement_is_error: (
        "pub fn main() {\n\tr = {\n\t\t1 + 2\n\t\t9\n\t}\n\tprintln(r)\n}\n",
        "must be consumed",
    ),
}

ok_case! {
    // Control for the rule above: pins the `is_nil` guard against over-firing.
    nil_typed_block_expr_statement_is_ok:
        ("pub fn main() {\n\tr = {\n\t\tprintln(1)\n\t\t9\n\t}\n\tprintln(r)\n}\n"),
}

reject_case! {
    // Diagnostics from the `Hydrator`, which turns a written type into a `Ty`.

    type_arg_arity_mismatch_is_error: (
        "fn f(_x Option(Int, String)) Int { 1 }\n",
        "Type 'Option' expects 1 type argument, got 2",
    ),
    /// A field RHS hydrates with `permit_new` disabled, so an unseen var is an
    /// error rather than an implicit fresh one.
    unknown_type_variable_in_ctor_field_is_error:
        ("type Box { Box(v t) }\n", "Unknown type variable 't'"),
    type_variable_cannot_take_arguments_is_error:
        ("fn f(x a(Int)) a { x }\n", "Type variable 'a' cannot take arguments"),
    /// Without a return type there is no inference context to solve, so `fn(Int)`
    /// would mint an unconstrained var that typechecks against anything.
    fn_type_without_return_in_ctor_field_is_error: (
        "type F { F(g fn(Int)) }\n",
        "Function type in a type definition must declare a return type",
    ),
    /// Same rule on an alias RHS, which also hydrates with `permit_new` disabled.
    fn_type_without_return_in_alias_is_error: (
        "type Callback = fn(Int)\n",
        "Function type in a type definition must declare a return type",
    ),

    duplicate_type_parameter_is_error:
        ("type Box(t, t) { Box(a t) }\n", "Duplicate type parameter 't'"),
    recursive_type_alias_self_is_error: ("type A = A\n", "Recursive type alias 'A'"),
    /// Which member of the cycle gets named is up to the cycle detector, so this
    /// pins the diagnostic class only.
    mutually_recursive_type_alias_is_error: ("type A = B\ntype B = A\n", "Recursive type alias"),
}

ok_case! {
    /// The declared-return rule applies only to type definitions. Binding
    /// annotations also disable `permit_new`, so keying the rule on that flag
    /// wrongly rejects this.
    fn_type_without_return_in_binding_annotation_is_ok:
        ("pub fn main() {\n\tx fn(Int) = fn(a Int) { a }\n\tprintln(x(1))\n}\n"),
}

/// Runtime counterpart of the case above.
#[test]
fn fn_type_without_return_in_binding_annotation_runs() {
    common::run_outputs(
        "pub fn main() {\n\tf fn(Int) = fn(x Int) { x * 2 }\n\tprintln(f(3))\n}\n",
        "6\n",
    );
}

// A cycle among some aliases must not stop the acyclic ones from registering.
#[test]
fn recursive_type_alias_cycle_does_not_drop_other_aliases() {
    let src = "type Good = Int\ntype A = B\ntype B = A\nfn f(x Good) Good { x }\n\
               pub fn main() {\n\tprintln(f(1))\n}\n";
    let out = check_rejects(src, "Recursive type alias");
    assert!(
        !out.combined().contains("Unknown type"),
        "cycle in A/B must not poison C"
    );
}

// A duplicate-named constructor is reported once and dropped, like a duplicate
// fn or const: the first registration survives.
#[test]
fn duplicate_constructor_is_dropped_not_double_defined() {
    let src = "type T {\n\tDup(a Int)\n\tDup\n}\npub fn main() {\n\tprintln(Dup(1))\n}\n";
    let out = check_rejects(src, "'Dup' is already defined");
    let combined = out.combined();
    assert_eq!(
        combined.matches("'Dup' is already defined").count(),
        1,
        "expected exactly one duplicate diagnostic:\n{combined}"
    );
    assert!(
        !combined.contains("has 0 field(s)"),
        "duplicate ctor shadowed the first definition:\n{combined}"
    );
}

reject_case! {
    /// Constructor names share the value namespace with fns and consts.
    duplicate_constructor_across_types_is_error:
        ("type A { Red }\ntype B { Red }\n", "'Red' is already defined"),
    constructor_colliding_with_fn_is_error:
        ("fn Red() {}\ntype A { Red }\n", "'Red' is already defined"),

    /// Occurs-check: `x(x)` is an infinite type. Inference must reject, not loop.
    infinite_type_self_application_is_error: ("fn f(x) { x(x) }\n", "Infinite type detected"),

    // Field/tuple access diagnostics from `compile_binary` / `compile_field_access`.

    tuple_index_out_of_bounds_is_error: (
        "pub fn main() {\n\tt = (1, 2)\n\tprintln(t.5)\n}\n",
        "Tuple index 5 out of bounds (tuple has 2 elements)",
    ),
    numeric_index_on_non_tuple_is_error: (
        "pub fn main() {\n\tx = 5\n\tprintln(x.0)\n}\n",
        "Cannot index .0 on non-tuple type",
    ),
    /// The runtime variant is not statically known, so a projected label must be
    /// present on every variant.
    field_not_on_every_variant_is_error: (
        "type Shape {\n\tCircle(r Int)\n\tSquare(side Int)\n}\nfn g(s Shape) Int { s.r }\n",
        "Field 'r' is not present on every variant of 'Shape' (missing on 'Square')",
    ),
    field_access_partial_is_rejected: (
        "type Named {\n\tPerson(name String, age Int)\n\tOrg(name String, size Int)\n}\n\
         fn age_of(n Named) Int { n.age }\n\
         pub fn main() {\n\tprintln(age_of(Person(name: 'al', age: 18)))\n}\n",
        "Field 'age' is not present on every variant of 'Named' (missing on 'Org')",
    ),
    field_access_on_tuple_is_error: (
        "pub fn main() {\n\tt = (1, 2)\n\tprintln(t.x)\n}\n",
        "Type '(Int, Int)' has no field 'x'",
    ),
    field_access_on_unknown_type_is_error: (
        "fn g(x) { x.name }\n",
        "Cannot access field 'name' on a value of unknown type — add a type annotation",
    ),

    /// The did-you-mean path in `compile_identifier`. The no-suggestion path is
    /// `unknown_identifier_is_error` above.
    unknown_identifier_suggests_close_name: (
        "pub fn main() {\n\tprintln = 1\n\tfoo = prntln\n}\n",
        "Closest match: 'println'.",
    ),

    /// The tuple path. The constructor path emits a different message.
    refutable_tuple_destructuring_binding_is_error: (
        "pub fn main() {\n\t(x, 1) = (1, 2)\n\tprintln(x)\n}\n",
        "Destructuring binding pattern must be irrefutable",
    ),
}

ok_case! {
    // Control: the check above fires on refutability, not on tuple destructuring.
    irrefutable_tuple_destructuring_binding_is_ok:
        ("pub fn main() {\n\t(x, y) = (1, 2)\n\tprintln(x + y)\n}\n"),

    // A builtin in value position gets an eta wrapper (see `typed_ir::eta`).
    builtin_used_as_value_is_ok: ("pub fn main() {\n\tf = println\n\tf('done')\n}\n"),
}

reject_case! {
    /// Declarations are only legal at a module's top level.
    nested_type_declaration_is_error: (
        "fn outer() Int {\n\ttype Inner { A }\n\t1\n}\n",
        "type declarations are only allowed at the top level",
    ),
    /// `or` with a receiver binds the failure payload. `Result`'s `Err` carries
    /// one; `Option`'s `None` does not.
    or_with_receiver_on_option_is_error: (
        "pub fn main() {\n\tx = Some(5) or v -> 0\n\tprintln(x)\n}\n",
        "'or' on an Option does not bind a value",
    ),
}

ok_case! {
    // Control: the diagnostic above fires on the receiver, not on `or` over `Option`.
    or_without_receiver_on_option_is_ok:
        ("pub fn main() {\n\tx = Some(5) or 0\n\tprintln(x)\n}\n"),
}

reject_case! {
    /// A local type sharing its name with a stdlib type is still a different
    /// type. Unifying on names instead of nominal ids is a soundness hole.
    same_named_type_from_another_module_does_not_unify: (
        "import scarlet/binary\n\
         import scarlet/http/h1\n\
         type Parsed {\n\
         \tLocalDone(x Int)\n\
         \tLocalOther\n\
         }\n\
         fn f() Parsed {\n\
         \th1.parse_request(binary.from_string('GET / HTTP/1.1\\r\\n\\r\\n'), 0)\n\
         }\n\
         pub fn main() {\n\
         \tprintln(f())\n\
         }\n",
        "Type mismatch",
    ),
}

ok_case! {
    // Each `Parsed` still answers for its own constructors and exhaustiveness.
    same_named_local_and_stdlib_types_coexist: (
        "import scarlet/binary\n\
         import scarlet/http/h1.{Done, NeedMore, Bad}\n\
         type Parsed {\n\
         \tLocalDone(x Int)\n\
         \tLocalOther\n\
         }\n\
         fn local_value(p Parsed) Int {\n\
         \tmatch p {\n\
         \t\tLocalDone(x) -> x\n\
         \t\tLocalOther -> 0\n\
         \t}\n\
         }\n\
         pub fn main() {\n\
         \tremote = match h1.parse_request(binary.from_string('GET / HTTP/1.1\\r\\n\\r\\n'), 0) {\n\
         \t\tDone(_, _, _, _, _, consumed) -> consumed\n\
         \t\tNeedMore -> 0 - 1\n\
         \t\tBad(s) -> s\n\
         \t}\n\
         \tprintln(remote + local_value(LocalDone(41)))\n\
         }\n",
    ),
}

/// Constructor arguments are typechecked in declared-field order whatever order
/// the labels are written in. The elaborator records types in source order, so
/// it is easy to let that order drag the checking order along.
#[test]
fn ctor_arg_diagnostics_come_out_in_declared_field_order() {
    let out = common::run_source(
        "check",
        "type P {\n\tx Int\n\ty Int\n}\npub fn main() {\n\tprintln(P(y: 'why', x: 'ex'))\n}\n",
    );
    let text = out.combined();
    let x_at = text
        .find("6:25")
        .expect("expected a diagnostic on `x: 'ex'`");
    let y_at = text
        .find("6:15")
        .expect("expected a diagnostic on `y: 'why'`");
    assert!(
        x_at < y_at,
        "expected the `x` field's diagnostic before the `y` field's:\n{text}"
    );
}

/// A `..base` spread must unify the result type before any argument is checked,
/// so a function-literal argument still gets a concrete parameter type.
#[test]
fn ctor_spread_solves_type_params_before_lambda_args_are_hinted() {
    common::run_outputs(
        "type Pair(a) {\n\tfst a\n\tsnd fn(a) a\n}\n\
         pub fn main() {\n\
         \tp = Pair(1, fn(x) { x + 1 })\n\
         \tq = Pair(snd: fn(x) { x * 2 }, ..p)\n\
         \tprintln(q.snd(q.fst))\n\
         }\n",
        "2\n",
    );
}

// A top-level value declaration shadows an imported module qualifier
// (`resolve_qualified_member` checks `env` before `imported_qualifiers`), so
// `name.member` resolves through the declaration. Both the decl site and a
// failed member access must say so.
reject_case! {
    shadowing_fn_failed_field_access_names_the_shadowed_module: (
        "import scarlet/http\n\npub fn http() {\n    http.Unsized\n}\n",
        "'http' here is a local binding that shadows the imported module 'scarlet/http'",
    ),
    fn_shadowing_import_qualifier_gets_decl_site_hint: (
        "import scarlet/http\n\npub fn http() {\n    http.Unsized\n}\n",
        "'http' shadows the imported module 'scarlet/http'",
    ),
}

ok_case! {
    // The decl-site shadow warning is a hint, not an error: a module that
    // never touches the shadowed qualifier still checks.
    shadowing_import_qualifier_alone_is_not_an_error: (
        "import scarlet/http\n\npub fn http() {\n    2\n}\n",
    ),
    // Renaming the value away from the qualifier restores qualified access.
    qualified_member_access_works_when_not_shadowed: (
        "import scarlet/http\n\npub fn serve() {\n    http.Unsized\n}\n",
    ),
}

// Qualified type identifiers: `module.Type` resolves through the mangled
// `qualifier.Name` keys `process_import` registers for every public type of
// an imported module.
ok_case! {
    qualified_type_in_alias_position: (
        "import scarlet/http\n\ntype C = http.Method\n\npub fn new() {\n    2\n}\n",
    ),
    qualified_type_in_annotation_position: (
        "import scarlet/http\n\npub fn f(m http.Method) http.Method {\n    m\n}\n",
    ),
    qualified_type_through_import_alias: (
        "import scarlet/http as h\n\ntype C = h.Method\n\npub fn new() {\n    2\n}\n",
    ),
}

reject_case! {
    unknown_qualified_type_names_module_and_member: (
        "import scarlet/http\n\ntype C = http.Nope\n",
        "Unknown type 'http.Nope'. Import 'http' and verify it exports a type 'Nope'.",
    ),
    qualified_type_arity_error_uses_qualified_name: (
        "import scarlet/http\n\ntype C = http.Method(Int)\n",
        "Type 'http.Method' expects 0 type arguments, got 1",
    ),
    unimported_qualifier_in_type_position_is_unknown: (
        "type C = http.Method\n",
        "Unknown type 'http.Method'",
    ),
}

// Two `scarlet/json/decode` shapes the type system holds shut. Both are pinned
// here rather than in `tests/programs/json.scrl` because neither program gets
// far enough to print anything — the golden run can only witness decoders that
// compile.
reject_case! {
    /// `Failure.found` is a `Found` and not free text, so a decoder cannot put
    /// a sentence where the document's shape belongs.
    decode_failure_found_rejects_free_text: (
        "import scarlet/json/decode\n\ndecode.Failure([], 'a thing', 'a string')\n",
        "expected 'Found', got 'String'",
    ),
    /// `one_of` takes its first alternative separately, so a union with nothing
    /// to try is not a decoder that can be built.
    decode_one_of_rejects_no_alternatives: (
        "import scarlet/json/decode\n\ndecode.one_of([])\n",
        "Expected 2 argument(s), got 1",
    ),
}

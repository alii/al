# Plan: Hindley-Milner Type Checker for AL

## Context

PR #17 had the right instinct - merge checking and compilation into one pass.
But the type system itself was still ad-hoc, so it just moved the spaghetti.
This time: merge them AND use a proper HM type system.

Two passes was always wasteful: walking the AST twice, maintaining synchronized
struct/enum representations in both checker and compiler, threading a TypeEnv
intermediary between them. One pass fixes all of that.

## What We're Building

A single-pass compiler with HM type inference baked in:

- Union-find for type variable unification
- Levels-based generalization (Remy's technique)
- Let-polymorphism (generalize at bindings, instantiate at use sites)
- Constrained type variables for operators (Elm-style: addable, numeric, comparable)
- Proper occurs check
- Good error messages via spans on constraints
- Bytecode emission happens inline as types are inferred

## Architecture

```
parse -> COMPILE (infer types + emit bytecode) -> vm.run
              |
              v
       1. Register type declarations (structs, enums)
       2. Walk AST: at each node, infer type AND emit bytecode
       3. Unification via union-find (happens inline)
       4. Generalize at let/fn bindings
       5. Produce Program (bytecode) directly
```

`al check` runs the same pass with a `skip_codegen` flag - the inference
engine runs, errors are collected, but no bytecode is emitted.

`al run` does the full thing: infer + emit + run.

## Files

### Keep as-is

- `src/types/exhaustiveness.v` - solid pattern matrix algorithm, unchanged
- `src/type_def/type_def.v` - the Type sum type (used by exhaustiveness, LSP, etc.)
- `src/bytecode/opcodes.v` - instruction set, Program, Function, Value types
- `src/vm/vm.v` - unchanged

### Create new

- `src/types/infer.v` - HM inference engine (union-find, unify, generalize)
- `src/types/environment.v` - type environment with Schemes

### Rewrite

- `src/bytecode/compiler.v` - merged compiler that does inference + codegen

### Update

- `src/main.v` - remove separate check pass, wire up merged compiler
- `src/repl/repl.v` - same
- `src/lsp/analysis.v` - same

## `src/types/infer.v` - The HM Engine

This is the heart of it. Pure type inference machinery, no AST knowledge.

```
InferEngine:
  vars: []TyVarState           // union-find backing store, indexed by var ID
  next_var_id: int
  current_level: int
  diagnostics: []Diagnostic

TyVarState = Unbound { level: int, constraint: ?Constraint } | Link { ty: InferType }

Constraint = .addable | .numeric | .comparable

InferType:
  | IVar(id: int)                              // type variable (index into vars[])
  | ICon(name: string, args: []InferType)      // type constructor: Int, Array(T), etc
  | IFun(params: []InferType, ret: InferType, err: ?InferType)  // function type
  | ITuple(elements: []InferType)              // tuple type
```

All concrete types are `ICon`:

```
Int           = ICon("Int", [])
String        = ICon("String", [])
Bool          = ICon("Bool", [])
Float         = ICon("Float", [])
None          = ICon("None", [])
Array(T)      = ICon("Array", [T])
Option(T)     = ICon("Option", [T])
Result(T, E)  = ICon("Result", [T, E])
MyStruct(A,B) = ICon("MyStruct", [A, B])
MyEnum(T)     = ICon("MyEnum", [T])
```

Key operations:

```
fresh_var() -> InferType                       // new IVar at current_level, no constraint
fresh_constrained_var(Constraint) -> InferType // new IVar with a constraint tag
find(ty) -> InferType                          // chase Link pointers (path compression)
unify(a, b, span) -> bool                     // unify two types, record error on failure
occurs_in(var_id, ty) -> bool                  // prevent infinite types
enter_level() / leave_level()                  // for generalization scoping
generalize(ty) -> Scheme                       // quantify vars with level > current_level
instantiate(scheme) -> InferType               // replace quantified vars with fresh vars
resolve(ty) -> type_def.Type                    // resolve all vars to final type_def.Type
```

### Why a separate InferType?

The existing `type_def.Type` is a sum type used across the whole codebase (VM,
LSP, exhaustiveness checker, etc). It represents finalized types. The inference
engine needs mutable type variables with levels and link pointers - a different
concern. We use `InferType` during inference, then `resolve` converts to
`type_def.Type` at the end.

This keeps `type_def.v` clean and unchanged. The exhaustiveness checker, VM, and
LSP never need to know about inference internals.

### Scheme

```
Scheme:
  quantified: []int            // var IDs that are universally quantified
  ty: InferType                // the underlying type
```

`instantiate(scheme)` replaces each quantified var with a fresh var.
The fresh var inherits the constraint of the original (if any). So
`forall a{addable}. a -> a -> a` instantiates to `'t1{addable} -> 't1{addable} -> 't1{addable}`.

`generalize(ty)` finds all vars with level > current and quantifies them.
Constraints on vars are preserved — they're part of the TyVarState.

## `src/types/environment.v` - Type Environment

```
TypeEnv:
  scopes: []map[string]Scheme           // variable -> polymorphic type
  type_info: map[string]TypeInfo        // "Option" -> its TypeInfo
  definitions: map[string]DefLocation   // for LSP go-to-definition
  docs: map[string]string               // doc comments
  next_type_id: int

TypeInfo:
  id: int
  kind: .struct_ | .enum_
  type_params: []string
  fields: map[string]InferType          // for structs
  variants: map[string][]InferType      // for enums
```

Key operations:

- `define(name, Scheme)` - bind in current scope
- `lookup(name) -> ?Scheme` - search scopes from innermost out
- `push_scope() / pop_scope()`
- `register_struct(name, fields, type_params)`
- `register_enum(name, variants, type_params)`
- `lookup_type_info(name) -> ?TypeInfo`

## Merged `src/bytecode/compiler.v`

The compiler now owns an `InferEngine` and `TypeEnv`. When it visits each node:

```v
fn (mut c Compiler) compile_expr(expr ast.Expression) !InferType {
  match expr {
    ast.NumberLiteral {
      // INFER: return Int or Float
      // EMIT: push_const
      if expr.value.contains('.') {
        idx := c.add_constant(expr.value.f64())
        c.emit_arg(.push_const, idx)
        return c.engine.icon_float()
      } else {
        idx := c.add_constant(expr.value.int())
        c.emit_arg(.push_const, idx)
        return c.engine.icon_int()
      }
    }
    ast.Identifier {
      // INFER: lookup scheme, instantiate
      // EMIT: push_local or push_capture
      scheme := c.env.lookup(expr.name) or {
        c.error("Unknown identifier '${expr.name}'", expr.span)
        return c.engine.fresh_var()
      }
      ty := c.engine.instantiate(scheme)
      // ... emit load instruction ...
      return ty
    }
    // etc.
  }
}
```

Every `compile_*` method returns an `InferType`. The compiler unifies types
where they must agree, generalizes at bindings, and emits bytecode - all in one
walk.

### `al check` mode

```v
pub fn compile(expr, fl) !CompileResult {
  // ...
  // When fl.check_only:
  //   - still walk AST, still do inference
  //   - skip all emit() / emit_arg() calls
  //   - return diagnostics only
}
```

Or simpler: the emit functions check a flag and no-op. The point is inference
runs regardless.

## How Specific Features Work

### Enum constructors become functions

```al
enum Option(T) { Some(T), None }
```

On declaration, register in env:

- `Some : forall a. a -> Option(a)` (function scheme)
- `None : forall a. Option(a)` (value scheme)
- `Option.Some` / `Option.None` (qualified versions)

When compiling `Some(42)`:

1. Look up `Some`, instantiate: `'t1 -> Option('t1)`
2. Compile arg `42` -> `Int`
3. Unify `'t1 = Int`
4. Return type: `Option(Int)`
5. Emit: push 42, push enum type id, push "Option", push "Some", make_enum_payload

### Struct constructors

```al
struct Pair(A, B) { first: A, second: B }
```

When compiling `Pair { first: 1, second: "hi" }`:

1. Look up Pair's TypeInfo, create fresh vars for A, B
2. Compile `first: 1` -> Int, unify with A => A = Int
3. Compile `second: "hi"` -> String, unify with B => B = String
4. Return type: Pair(Int, String)
5. Emit: struct init bytecode

### Let-polymorphism

```al
id = fn(x) { x }
id(42)
id("hello")
```

1. Enter level
2. Compile `fn(x) { x }`:
   - Fresh var `'a` for x
   - Body returns `'a`
   - Function type: `'a -> 'a`
   - Emit: function bytecode
3. Leave level, generalize: `forall a. a -> a`
4. Bind `id` to that scheme
5. `id(42)`: instantiate to `'t1 -> 't1`, unify `'t1 = Int`, return `Int`
6. `id("hello")`: instantiate to `'t2 -> 't2`, unify `'t2 = String`, return `String`

### Binary operators (constrained type variables)

Pure HM only has parametric polymorphism (same code for all types). Operators
like `+` need ad-hoc polymorphism (different behavior per type). We solve this
with Elm-style **constrained type variables** - a small, closed extension to HM.

Type variables can carry a constraint tag:

```
Constraint:
  .addable    — can be Int, Float, or String
  .numeric    — can be Int or Float
  .comparable — can be Int, Float, or String
```

When the compiler sees `a + b`:
1. Compile `a`, get type `T_a`
2. Compile `b`, get type `T_b`
3. Create a fresh constrained var: `'r {addable}`
4. Unify `T_a` with `'r` (left operand must be addable)
5. Unify `T_b` with `'r` (right operand must match, also addable)
6. Return type: `'r` (same type as operands)

The constraint is enforced during unification:
- `IVar{constraint: .addable}` meets `ICon("Int")` → OK, resolve to Int
- `IVar{constraint: .addable}` meets `ICon("Bool")` → ERROR: Bool is not addable
- `IVar{constraint: .addable}` meets `IVar{constraint: none}` → propagate: both become addable
- `IVar{constraint: .addable}` meets `IVar{constraint: .numeric}` → tighter wins: numeric

This means `add = fn(a, b) { a + b }` infers as `addable -> addable -> addable`:
- `add(1, 2)` → addable meets Int → OK
- `add("hi", "there")` → addable meets String → OK
- `add(true, false)` → addable meets Bool → ERROR

Operator constraint mapping:
- `+`: operands `addable`, result = operand type
- `-`, `*`, `/`, `%`: operands `numeric`, result = operand type
- `<`, `>`, `<=`, `>=`: operands `comparable`, result = Bool
- `==`, `!=`: operands unconstrained (any type), result = Bool
- `&&`, `||`: operands must be Bool, result = Bool
- unary `-`: operand `numeric`, result = operand type
- unary `!`: operand must be Bool, result = Bool

This is NOT type classes. The constraint set is hardcoded and closed. Users
can't define new constraints. It's ~15 lines of extra code in the unifier.

### Pattern matching

```al
match expr {
  Some(x) -> use(x)
  None -> default
}
```

1. Compile `expr`, get type T (also emits bytecode for expr)
2. For each arm:
   - Compile pattern against T, binding variables
   - Compile body, get body type
   - Emit pattern match bytecode (same as current compiler)
3. Unify all body types
4. Feed patterns to exhaustiveness checker (uses resolved type)

### Type annotations

`x Int = expr`:

1. Resolve `Int` annotation to `InferType`
2. Compile `expr`, get inferred type
3. Unify annotation with inferred type
4. If mismatch: error. If compatible: annotation wins for the binding.

### Result types and error expressions

Functions can declare error types: `fn divide(a Int, b Int) Int!DivisionError`.
The IFun type carries an optional error type:
`IFun([Int, Int], ret: Int, err: DivisionError)`.

When calling a function with an error type, the call expression's type becomes
`ICon("Result", [ret, err])`. The caller must handle the error with `or`.

The `error` expression: `error DivisionError{ message: 'Cannot divide by zero' }`
1. Compile the inner expression, get type `E`
2. The error expression's own type is a **fresh var** `'t`
3. Record `E` as contributing to the current function's error type
4. Return type: `'t` (unifies freely with whatever context expects)
5. Emit: compile inner expr + `make_error` opcode

Why a fresh var? Because `error` is control flow — it exits the function through
the error channel. It never produces a success value. A fresh var unifies with
any sibling branch:
```al
if b == 0 {
  error DivisionError{...}   // type: 't (fresh)
} else {
  a / b                       // type: Int
}
// unify branches: 't = Int, so overall type is Int. Correct.
```

The `or` expression: `divide(10, 0) or 0`
1. Compile the left expression, get type `T_left`
2. Create fresh vars `'s` (success) and `'e` (error)
3. Unify `T_left` with `ICon("Result", ['s, 'e])` (or `ICon("Option", ['s])`)
4. Compile the `or` body, get type `T_body`
5. Unify `T_body` with `'s`
6. Return type: `'s`
7. If `or err ->` form: bind `err` with type `'e` in the body scope

For `!ErrorType` with no success type (e.g. `fn validate(x Int) !ValidationError`),
the success type is `None`.

### Recursive functions

```al
countdown = fn(n) {
  if n > 0 {
    println(n)
    countdown(n - 1)
  }
}
```

Standard HM approach for recursive let-bindings:
1. Create a fresh var `'f` for the binding name
2. Bind `countdown` to a **monomorphic** scheme (no generalization yet) with type `'f`
3. Compile the function body - self-references to `countdown` use `'f`
4. The function body infers a type `T_body`, unify `'f = T_body`
5. NOW generalize (after the body is compiled): `forall a. a -> a` etc.
6. Re-bind `countdown` to the generalized scheme

This is the standard "let-rec" approach. The key: the self-reference is monomorphic
(same type var), so recursive calls are correctly typed. Generalization happens after.

For codegen: the current compiler uses `current_binding` + `push_self` for
self-reference inside closures. This stays the same.

### `none` literal

In AL, `none` serves dual purpose:
1. The "empty" case of Option types (`?User` → returns `none` or `User`)
2. The return value of void functions (`fn greet(name String) { ... }`)

For HM inference, `none` has type `ICon("None", [])`. This is the None type.

Functions returning `?T` (i.e., `Option(T)`) need implicit lifting: when a
branch returns a bare `T` and the context expects `Option(T)`, the value is
implicitly wrapped in Some. Similarly, `none` (type `None`) is compatible
with `Option(T)` as the None case.

This implicit lifting happens during unification of the function body against
the declared return type. When the declared return is `Option(T)`:
- A branch returning `T` → compatible (implicit Some wrapping at runtime)
- A branch returning `none` → compatible (None case)
- A branch returning `Option(T)` → compatible directly

At the bytecode level, no wrapping opcode is needed — the VM's `is_failure`
opcode already checks for NoneValue at runtime.

### Interpolated strings

`'Hello, ${expr}'`:
1. Compile each part
2. Each part's type is unconstrained (the VM's `to_string` opcode handles conversion)
3. The overall type is `String`
4. Emit: compile each part, `to_string`, `str_concat` for joining

### Builtin functions

Builtins need type schemes registered in the environment at startup:

```
println    : forall a. a -> None
inspect    : forall a. a -> String
read_file  : String -> Result(String, String)
write_file : String -> String -> Result(None, String)
str_split  : String -> String -> Array(String)
tcp_listen : Int -> Result(Socket, String)
tcp_accept : Socket -> Result(Socket, String)
tcp_read   : Socket -> Result(String, String)
tcp_write  : Socket -> String -> Result(None, String)
tcp_close  : Socket -> Result(None, String)
```

These are registered as monomorphic schemes (no quantified vars) except
`println` and `inspect` which are polymorphic.

Some builtins are gated behind flags (io_enabled, expose_debug_builtins).

### TypePatternBinding (type consumption / discard)

`String = g()`:
1. Compile `g()`, get inferred type
2. Resolve the `String` annotation to `InferType`
3. Unify annotation with inferred type
4. Emit: compile expr, then `pop` (value is discarded)

### Tuple destructuring

`(a, b) = pair`:
1. Compile `pair`, get type `T`
2. Create fresh vars for each element: `'e0`, `'e1`
3. Unify `T` with `ITuple(['e0, 'e1])`
4. Bind `a` to `'e0`, `b` to `'e1`
5. Emit: dup, tuple_index, store_local for each

Mixed type-consumption destructuring: `(Bool, Int, name) = triple`:
- `Bool` and `Int` positions: resolve annotation, unify with tuple element, discard
- `name` position: bind variable to tuple element type

### Variable reassignment

`x = 10; x = x + 1`:
In AL, this is just re-binding. Each `VariableBinding` creates a new binding in the
current scope. The second `x = x + 1` looks up the old `x` (gets `Int`), computes
`x + 1` (gets `Int`), and binds a new `x` to that. The old `x` is shadowed.

In the type env, `define(name, scheme)` just overwrites in the current scope.
No special handling needed.

### Scope restrictions

The old checker enforced:
- Named function declarations only at top level
- Struct/enum declarations only at top level
- Const declarations only at top level

The merged compiler should enforce these same restrictions. Check during
`compile_statement`: if the current scope depth > 1 and the statement is a
FunctionDeclaration/StructDeclaration/EnumDeclaration/ConstBinding, emit an error.

### Import/Export declarations

- `ExportDeclaration`: just compile the inner declaration. Export info is metadata
  only (no runtime effect). Record in env for LSP/future module system.
- `ImportDeclaration`: not yet implemented in the old system either. For now,
  record the import and move on (or error if not supported yet).

### ErrorNode (parser error recovery)

`ErrorNode` is produced by the parser when it encounters a syntax error but
continues parsing. The compiler should return a fresh var (error recovery —
don't cascade type errors from parse errors). No bytecode emitted.

### TypeIdentifier as expression

`TypeIdentifier` appears in the Expression sum type because it's used in
pattern positions: `(Bool, Int, name) = triple` where `Bool` and `Int` are
TypeIdentifiers. When encountered as an expression in match patterns, it
acts as a type-matching pattern. Already covered by tuple destructuring
and TypePatternBinding sections above.

### Closures and captures

The closure codegen stays exactly as the current compiler does it:
- `outer_scopes` tracks variables from enclosing scopes
- `resolve_variable` checks locals, then captures, then outer scopes
- `push_capture` / `make_closure` opcodes handle runtime closure creation

The type system handles closures naturally: a lambda `fn(x) { x + y }` where `y`
is captured just looks up `y`'s scheme from the environment. The IFun type
includes the captured variable's type implicitly through the body's inference.

### Tail call optimization

The `in_tail_position` tracking stays as-is. It's purely a codegen concern
(emit `tail_call` instead of `call`). The type system doesn't need to know.

### When resolve() runs

resolve() converts InferType → type_def.Type. It's needed at:

1. **Exhaustiveness checking**: after compiling a match expression, resolve the
   scrutinee type to feed to `check_exhaustiveness(patterns, type_def.Type)`
2. **Error messages**: when reporting type mismatches, resolve both sides to
   get human-readable types via `type_to_string`
3. **LSP type positions**: after compiling an identifier/expression, resolve
   and record `TypeAtPosition { line, col_start, col_end, type_str, ... }`
4. **End of compilation**: unresolved type vars become `TypeVar` in the final type
   (e.g., an unused polymorphic function keeps its type params)

### Unresolved constrained type variables

If a constrained var is never unified with a concrete type (e.g., `add = fn(a, b) { a + b }`
is declared but never called), it stays constrained in the scheme. When resolve()
encounters an unbound var with constraint `.addable`, it becomes `TypeVar("addable")`
in the final type. This is fine for display purposes.

No defaulting (unlike Elm which defaults `number` → `Int`). An unresolved constrained
var just stays polymorphic.

### LSP interface

The merged compiler needs to produce data the LSP consumes:

```
CompileResult:
  program: Program              // bytecode (empty if check_only)
  diagnostics: []Diagnostic     // errors and warnings
  type_positions: []TypePosition // for hover/go-to-def
```

```
TypePosition:
  line: int
  column: int
  end_col: int
  name: string
  type_info: type_def.Type      // resolved type
  def_line: int                 // where the name was defined
  def_col: int
  def_end: int
  doc: ?string                  // doc comment if available
```

The compiler records type positions as it compiles identifiers and bindings.
After compilation, these are available for the LSP to use.

`src/lsp/analysis.v` changes from:
```
types.check(ast) → check_result
bytecode.compile(ast, check_result.env, flags)
```
to:
```
bytecode.compile(ast, flags.with_check_only()) → compile_result
```

### REPL considerations

The REPL accumulates definitions across inputs. Currently it:
1. Parses new input
2. Prepends accumulated definitions to the AST
3. Runs check + compile on the combined AST
4. Stores new definitions (statements) for next iteration

With the merged compiler, the same pattern works: re-compile the combined AST
each time. The InferEngine and TypeEnv are created fresh each iteration (since
we recompile everything). This is slightly wasteful but keeps things simple and
correct. The REPL is interactive, so the extra compile time is negligible.

### Explicit type args on struct init

`Pair(String, Int){ first: "age", second: 30 }`:
1. Look up Pair's TypeInfo
2. The explicit type args `[String, Int]` map to type params `[A, B]`
3. Create InferType vars, immediately unify with the explicit args
4. Compile fields against these now-concrete types
5. No inference needed for the type params themselves

When no explicit args: `Pair{ first: 1, second: 2 }` — create fresh vars,
let field compilation resolve them through unification.

## Implementation Order

### Phase 1: Foundation (get it compiling)

1. Create `infer.v` with InferType, union-find, fresh_var, unify, generalize,
   instantiate, resolve
2. Create `environment.v` with Scheme, TypeEnv, scopes
3. Add InferEngine + TypeEnv to Compiler struct
4. Rewrite compile_expr to return InferType for: literals, identifiers,
   variable bindings, interpolated strings, function calls to builtins
5. Register builtin function type schemes (println, inspect, etc.)
6. Wire up main.v: remove check_source, pass check_only flag
7. Goal: `al run examples/hello.al` works

### Phase 2: Core language

8. Binary/unary operators with constrained type variables
9. If expressions (unify branch types)
10. Blocks (statement sequence, last expr type)
11. Function declarations + expressions (with let-polymorphism)
12. Recursive functions (monomorphic self-reference, then generalize)
13. Type annotations on bindings and parameters
14. Variable reassignment (shadow in current scope)
15. Const bindings
16. Goal: `al run examples/basic.al` works

### Phase 3: Data types

17. Struct declarations + init expressions (with explicit type args)
18. Enum declarations + variant constructors (register as function schemes)
19. Property access (struct fields, enum qualified access, tuple index)
20. Array expressions, indexing, slicing, spread
21. Tuple expressions + tuple destructuring (including type consumption)
22. Range expressions
23. TypePatternBinding (type consumption / discard)
24. Goal: `al run examples/all_language_features.al` works

### Phase 4: Pattern matching & error handling

25. Match expressions with pattern type inference
26. Wire up exhaustiveness checker (resolve the scrutinee type)
27. Or expressions (Result/Option unwrapping)
28. Error expressions (fresh var return type, error type tracking)
29. Function error types (IFun err field, Result wrapping at call sites)
30. Goal: `al run examples/match_patterns_test.al` works

### Phase 5: Polish

31. Scope restrictions (named fn, struct, enum, const at top level only)
32. "Did you mean X?" suggestions (port levenshtein)
33. LSP type positions (record TypePosition during compilation)
34. Unconsumed expression warnings
35. All error messages from ERRORS.md verified
36. `al check` mode (skip codegen flag)
37. Import/export declarations
38. REPL (re-compile combined AST each iteration)
39. Run ALL examples, fix regressions

## Key Differences from Old System

| Old (2 passes)                              | New (1 pass + proper HM)                 |
| ------------------------------------------- | ---------------------------------------- |
| Walk AST twice (checker then compiler)      | Walk AST once                            |
| TypeEnv intermediary between passes         | No intermediary - types used inline      |
| Ad-hoc unify() that only handles TypeVar    | Real union-find over all types           |
| TypeVar with string names ("A", "B")        | TypeVar with int IDs and levels          |
| No generalization - vars leak               | Let-polymorphism with forall             |
| param_subs map threaded manually            | Union-find handles substitution          |
| Special case for every operator             | Constrained type vars (Elm-style)        |
| infer_type_args bolted on                   | Type args inferred via unification       |
| No occurs check                             | Proper occurs check                      |
| Compiler duplicates checker's type lookups  | Types available where codegen needs them |
| Struct/enum sync between checker + compiler | Single source of truth                   |

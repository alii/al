# AL Language - All Current Errors & Warnings

This file catalogs every error and warning the current checker (type checker) and
compiler (bytecode compiler) can emit. This serves as a regression reference for
the Hindley-Milner rewrite.

---

## Type Checker Errors (`src/types/checker.v`)

### Type Mismatches

- `Type mismatch {context}: expected '{expected}', got '{actual}'`
- `Conflicting types for type parameter '{name}': expected '{existing}', got '{actual}'`
- `Type mismatch in destructuring: expected '{expected}', got '{elem_type}'`
- `Pattern type '{expr_type}' does not match subject type '{subject_type}'`

### Unknown Identifiers / Types

- `Unknown identifier '{name}'`
- `Unknown identifier '{name}'. Did you mean '{suggestion}'?`
- `Unknown type '{name}'`
- `Unknown type '{name}' for field '{field_name}'`
- `Unknown type '{name}' in variant '{variant_name}'`
- `Unknown return type '{name}'`
- `Unknown error type '{name}'`
- `Unknown struct '{name}'`
- `'{name}' is not defined`
- `'{name}' is not defined. Did you mean '{suggestion}'?`

### Unconsumed Expressions

- `Expression of type '{type}' must be consumed. Assign it to a variable or use '{type} =' to discard`

### Binary Operator Errors

- `Cannot concatenate '{left}' with '{right}': use string interpolation instead`
- `Left operand of '{op}' must be numeric, got '{type}'`
- `Right operand of '{op}' must be numeric, got '{type}'`
- `Cannot apply '{op}' to '{left}' and '{right}': operands must have the same type`
- `Cannot compare '{left}' with '{right}': operator '{op}' requires numeric operands`
- `Cannot compare {left} with {right}`

### Unary Operator Errors

- `Operator '{op}' requires a numeric operand, got '{type}'`

### Function Errors

- `Named function declarations are only allowed at the top level. Use an anonymous function instead: callback = fn() { ... }`
- `Duplicate parameter '{name}'`
- `Function '{name}' expects {expected} arguments, got {actual}`

### Const Binding Errors

- `'const' declarations are only allowed at the top level, not inside functions`

### Array Errors

- `Cannot infer type of empty array. Provide a type annotation, e.g.: 'items []Int = []'`
- `Spread in array literal requires an expression`
- `Spread operator requires an array, got {type}`
- `Cannot slice non-array type {type}`
- `Cannot index non-array type {type}`

### Tuple Errors

- `Tuple destructuring requires a tuple type, got {type}`
- `Tuple destructuring pattern has {n} elements, but tuple has {m}`
- `Tuple index {index} out of bounds. Tuple has {n} elements.`
- `Cannot use numeric index on type {type}. Only tuples support .0 .1 etc.`

### Struct Errors

- `Struct definitions are only allowed at the top level`
- `Duplicate field '{name}' in struct '{struct_name}'`
- `Struct '{name}' expects {expected} type argument(s), got {actual}`
- `Could not infer type parameter '{param}' for struct '{name}'`
- `Duplicate field '{name}' in struct initializer`
- `Struct '{name}' has no field '{field_name}'. Available fields: {fields}`
- `Missing required fields in '{name}': {fields}`

### Enum Errors

- `Enum definitions are only allowed at the top level`
- `Duplicate variant '{name}' in enum '{enum_name}'`
- `Enum '{name}' has no variant '{variant_name}'`
- `Enum variant '{name}' expects {expected} argument(s), got {actual}`
- `Enum variant '{name}' expects no arguments, got {actual}`
- `Enum variant '{name}' takes no arguments`

### Property Access Errors

- `Expected identifier in property access`
- `Cannot access property '{name}' on type '{type}'`

### Match Errors

- `Match is not exhaustive, missing: {missing}`
- `Cannot match array pattern against non-array type {type}`
- `Spread pattern must be at the end of the array pattern`
- `Cannot match tuple pattern against non-tuple type {type}`
- `Tuple pattern has {n} elements, but tuple has {m}`

### Pattern Errors

- `Invalid pattern: unary expressions are only allowed for negative number literals`
- `Invalid pattern: only literals, identifiers, arrays, tuples, enum variants, ranges, and or-patterns are allowed`

### Or Expression Errors

- `'or' can only be used on Result or Option types, got '{type}'`

### Range Errors

- `Range start must be Int, got {type}`
- `Range end must be Int, got {type}`
- `Range pattern start must be Int, got {type}`
- `Range pattern end must be Int, got {type}`
- `Range pattern can only match Int, got {type}`

---

## Type Checker Warnings (`src/types/checker.v`)

- `Previous arms already match all cases, else branch is unreachable`
- `Unreachable pattern`

---

## Bytecode Compiler Errors (`src/bytecode/compiler.v`)

### Variable / Function Errors

- `Undefined variable: {name}`
- `Unknown function: {name}`

### Operator Errors

- `Unknown binary operator: {op}`
- `Unknown unary operator: {op}`

### Array Errors

- `Spread in array literal missing expression`

### Enum Errors

- `Unknown variant "{name}" in enum {enum_name}`
- `Variant "{name}" expects {n} payload argument(s)`
- `Variant "{name}" does not take a payload`
- `Variant "{name}" requires payload(s) of type ({types})`

### Method Call Errors

- `Cannot call '{name}' as a method. AL does not have methods - use '{name}(...)' as a regular function call instead.`

### Struct Errors

- `Unknown struct type: {name}`
- `Unknown field "{name}" in struct {struct_name}`
- `Duplicate field "{name}" in struct {struct_name}`
- `Missing field "{name}" in struct {struct_name}`

### Internal Errors

- `Internal error: unhandled expression type '{type}'. This is a compiler bug.`
- `Internal error: enum_type_id not set for {enum}.{variant}`

### Builtin Arity Errors

- `println expects 1 argument`
- `inspect expects 1 argument`
- `__stack_depth__ expects 0 arguments`
- `read_file expects 1 argument (path)`
- `write_file expects 2 arguments (path, content)`
- `tcp_listen expects 1 argument (port)`
- `tcp_accept expects 1 argument (listener)`
- `tcp_read expects 1 argument (socket)`
- `tcp_write expects 2 arguments (socket, data)`
- `tcp_close expects 1 argument (socket)`
- `str_split expects 2 arguments (string, delimiter)`

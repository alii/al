module bytecode

import flags { Flags }
import ast
import diagnostic
import span
import type_def {
	Type,
	TypeEnum,
	TypeFunction,
	TypeStruct,
	is_numeric,
	t_array,
	t_bool,
	t_float,
	t_int,
	t_none,
	t_string,
	t_tuple,
	t_var,
	type_to_string,
	types_equal,
}
import types { TypeEnv, TypePosition }

struct Scope {
	locals map[string]int
}

struct Compiler {
	flags Flags
mut:
	// Type checking state
	env                    TypeEnv
	diagnostics            []diagnostic.Diagnostic
	in_function            bool
	current_fn_return_type ?Type
	param_subs             map[string]Type
	type_positions         []TypePosition

	// Bytecode generation state
	program          Program
	locals           map[string]int
	outer_scopes     []Scope
	local_count      int
	current_func_idx int
	captures         map[string]int
	capture_names    []string
	current_binding  string
	in_tail_position bool
}

fn (mut c Compiler) register_builtins() {
	a := t_var('a')

	socket := TypeStruct{
		name:   'Socket'
		fields: map[string]Type{}
	}
	c.env.register_struct(socket)

	c.env.register_function('println', TypeFunction{
		params: [a]
		ret:    t_none()
	})

	c.env.register_function('__stack_depth__', TypeFunction{
		params: []
		ret:    t_int()
	})

	c.env.register_function('inspect', TypeFunction{
		params: [a]
		ret:    t_string()
	})

	c.env.register_function('read_file', TypeFunction{
		params: [t_string()]
		ret:    t_string()
	})

	c.env.register_function('write_file', TypeFunction{
		params: [t_string(), t_string()]
		ret:    t_none()
	})

	c.env.register_function('tcp_listen', TypeFunction{
		params: [t_int()]
		ret:    Type(socket)
	})

	c.env.register_function('tcp_accept', TypeFunction{
		params: [Type(socket)]
		ret:    Type(socket)
	})

	c.env.register_function('tcp_read', TypeFunction{
		params: [Type(socket)]
		ret:    t_string()
	})

	c.env.register_function('tcp_write', TypeFunction{
		params: [Type(socket), t_string()]
		ret:    t_none()
	})

	c.env.register_function('tcp_close', TypeFunction{
		params: [Type(socket)]
		ret:    t_none()
	})

	c.env.register_function('str_split', TypeFunction{
		params: [t_string(), t_string()]
		ret:    t_array(t_string())
	})
}

// Error helpers for type checking
fn (mut c Compiler) error_at_span(message string, s span.Span) {
	c.diagnostics << diagnostic.error_at(s.start_line, s.start_column, message)
}

fn (mut c Compiler) warning_at_span(message string, s span.Span) {
	c.diagnostics << diagnostic.warning_at(s.start_line, s.start_column, message)
}

fn (mut c Compiler) expect_type(actual Type, expected Type, s span.Span, context string) bool {
	if types_equal(actual, expected) {
		return true
	}
	// TypeVar matches any concrete type
	if expected is type_def.TypeVar {
		return true
	}
	if expected is type_def.TypeResult {
		if types_equal(actual, expected.success) {
			return true
		}
	}
	if expected is type_def.TypeOption {
		if types_equal(actual, expected.inner) {
			return true
		}
		if types_equal(actual, t_none()) {
			return true
		}
	}
	c.error_at_span("Type mismatch ${context}: expected '${type_to_string(expected)}', got '${type_to_string(actual)}'",
		s)
	return false
}

fn (mut c Compiler) record_type(name string, typ Type, s span.Span, doc ?string) {
	mut def_line := 0
	mut def_col := 0
	mut def_end := 0
	if def_loc := c.env.lookup_definition(name) {
		def_line = def_loc.line
		def_col = def_loc.column
		def_end = def_loc.end_col
	}

	c.type_positions << TypePosition{
		line:      s.start_line
		column:    s.start_column
		end_col:   s.end_column
		name:      name
		type_info: typ
		def_line:  def_line
		def_col:   def_col
		def_end:   def_end
		doc:       doc
	}
}

fn (mut c Compiler) infer_type_args(expected Type, actual Type, mut subs map[string]Type, s span.Span) {
	match expected {
		type_def.TypeVar {
			if existing := subs[expected.name] {
				if !types_equal(existing, actual) {
					c.error_at_span("Conflicting types for type parameter '${expected.name}': expected '${type_to_string(existing)}', got '${type_to_string(actual)}'",
						s)
				}
			} else {
				subs[expected.name] = actual
			}
		}
		type_def.TypeArray {
			if actual is type_def.TypeArray {
				c.infer_type_args(expected.element, actual.element, mut subs, s)
			}
		}
		type_def.TypeOption {
			if actual is type_def.TypeOption {
				c.infer_type_args(expected.inner, actual.inner, mut subs, s)
			}
		}
		type_def.TypeTuple {
			if actual is type_def.TypeTuple {
				if expected.elements.len == actual.elements.len {
					for i, exp_elem in expected.elements {
						c.infer_type_args(exp_elem, actual.elements[i], mut subs, s)
					}
				}
			}
		}
		type_def.TypeResult {
			if actual is type_def.TypeResult {
				c.infer_type_args(expected.success, actual.success, mut subs, s)
				c.infer_type_args(expected.error, actual.error, mut subs, s)
			}
		}
		TypeStruct {
			if actual is TypeStruct {
				for field_name, field_type in expected.fields {
					if actual_field := actual.fields[field_name] {
						c.infer_type_args(field_type, actual_field, mut subs, s)
					}
				}
			}
		}
		else {}
	}
}

fn (c Compiler) find_similar_name(name string) ?string {
	all_names := c.env.all_names()
	mut best_match := ''
	mut best_distance := 3 // max distance threshold

	for candidate in all_names {
		dist := levenshtein_distance(name, candidate)
		if dist < best_distance {
			best_distance = dist
			best_match = candidate
		}
	}

	if best_match.len > 0 {
		return best_match
	}
	return none
}

fn levenshtein_distance(a string, b string) int {
	if a.len == 0 {
		return b.len
	}
	if b.len == 0 {
		return a.len
	}

	mut prev := []int{len: b.len + 1, init: index}
	mut curr := []int{len: b.len + 1}

	for i := 1; i <= a.len; i++ {
		curr[0] = i
		for j := 1; j <= b.len; j++ {
			cost := if a[i - 1] == b[j - 1] { 0 } else { 1 }
			deletion := prev[j] + 1
			insertion := curr[j - 1] + 1
			substitution := prev[j - 1] + cost

			mut min_val := deletion
			if insertion < min_val {
				min_val = insertion
			}
			if substitution < min_val {
				min_val = substitution
			}
			curr[j] = min_val
		}

		prev = curr.clone()
		curr = []int{len: b.len + 1}
	}

	return prev[b.len]
}

fn (c Compiler) check_binary_operand_types(left Type, right Type) bool {
	// if either is a TypeVar, they're compatible (TypeVar will be resolved later)
	if left is type_def.TypeVar || right is type_def.TypeVar {
		return true
	}
	return types_equal(left, right)
}

fn (c Compiler) infer_binary_result_type(left Type, right Type) Type {
	// Prefer concrete type over TypeVar
	if left is type_def.TypeVar {
		return right
	}
	return left
}

fn span_key(s span.Span) string {
	return '${s.start_line}:${s.start_column}:${s.end_line}:${s.end_column}'
}

fn (c Compiler) get_resolved_type(s span.Span) ?Type {
	// TODO: Once type checking is fully merged, this will use computed types directly
	return none
}

fn (mut c Compiler) resolve_type_identifier(t ast.TypeIdentifier) ?Type {
	if t.is_array {
		elem := t.element_type or { return none }
		elem_type := c.resolve_type_identifier(*elem) or { return none }
		return t_array(elem_type)
	}

	name := t.identifier.name

	match name {
		'Int' { return t_int() }
		'Float' { return t_float() }
		'String' { return t_string() }
		'Bool' { return t_bool() }
		'None' { return t_none() }
		else {}
	}

	// Check for single-letter type variables
	is_type_var := name.len == 1 && name[0] >= `A` && name[0] <= `Z`
	if is_type_var {
		return t_var(name)
	}

	return c.env.lookup_type(name)
}

fn (mut c Compiler) compile_struct_decl(stmt ast.StructDeclaration) {
	mut type_params := []string{}
	for tp in stmt.type_params {
		type_params << tp.name
	}

	mut fields := map[string]Type{}
	for field in stmt.fields {
		if resolved := c.resolve_type_identifier(field.typ) {
			fields[field.identifier.name] = resolved
		}
	}

	struct_type := TypeStruct{
		name:        stmt.identifier.name
		type_params: type_params
		fields:      fields
	}
	c.env.register_struct(struct_type)
}

fn (mut c Compiler) compile_enum_decl(stmt ast.EnumDeclaration) {
	if c.in_function {
		c.error_at_span('Enum definitions are only allowed at the top level', stmt.span)
	}

	mut type_params := []string{}
	for tp in stmt.type_params {
		type_params << tp.name
	}

	mut variants := map[string][]Type{}
	for variant in stmt.variants {
		if variant.identifier.name in variants {
			c.error_at_span("Duplicate variant '${variant.identifier.name}' in enum '${stmt.identifier.name}'",
				variant.identifier.span)
			continue
		}

		mut payload_types := []Type{}
		for payload in variant.payload {
			if resolved := c.resolve_type_identifier(payload) {
				payload_types << resolved
			} else {
				c.error_at_span("Unknown type '${payload.identifier.name}' in variant '${variant.identifier.name}'",
					variant.identifier.span)
			}
		}

		if doc := variant.doc {
			c.env.store_doc('${stmt.identifier.name}.${variant.identifier.name}', doc)
		}

		variants[variant.identifier.name] = payload_types
	}

	enum_type := TypeEnum{
		name:        stmt.identifier.name
		type_params: type_params
		variants:    variants
	}

	loc := types.DefinitionLocation{
		line:    stmt.identifier.span.start_line
		column:  stmt.identifier.span.start_column
		end_col: stmt.identifier.span.end_column
	}
	registered_enum := c.env.register_enum_at(enum_type, loc)

	if doc := stmt.doc {
		c.env.store_doc(stmt.identifier.name, doc)
	}

	c.record_type(stmt.identifier.name, Type(registered_enum), stmt.identifier.span, stmt.doc)

	for variant in stmt.variants {
		qualified_name := '${stmt.identifier.name}.${variant.identifier.name}'
		variant_loc := types.DefinitionLocation{
			line:    variant.identifier.span.start_line
			column:  variant.identifier.span.start_column
			end_col: variant.identifier.span.end_column
		}
		c.env.store_definition(qualified_name, variant_loc)

		c.record_type(qualified_name, Type(registered_enum), variant.identifier.span,
			variant.doc)
	}
}

pub struct CompileResult {
pub:
	program        Program
	diagnostics    []diagnostic.Diagnostic
	success        bool
	env            TypeEnv
	program_type   Type
	type_positions []TypePosition
}

pub fn compile(expr ast.Expression, fl Flags) CompileResult {
	// Create a fresh compiler with its own type environment
	mut c := Compiler{
		flags:            fl
		env:              types.new_env()
		diagnostics:      []
		type_positions:   []
		program:          Program{
			constants: []
			functions: []
			code:      []
			entry:     0
		}
		locals:           {}
		outer_scopes:     []
		local_count:      0
		current_func_idx: -1
		captures:         {}
		capture_names:    []
	}

	// Register built-in functions and types
	c.register_builtins()

	main_start := c.program.code.len

	c.compile_expr(expr, none) or {
		c.diagnostics << diagnostic.error_at(0, 0, err.msg())
		return CompileResult{
			program:        c.program
			diagnostics:    c.diagnostics
			success:        false
			env:            c.env
			program_type:   Type(type_def.TypeNone{})
			type_positions: c.type_positions
		}
	}
	c.emit(.halt)

	c.program.functions << Function{
		name:          '__main__'
		arity:         0
		locals:        c.local_count
		capture_count: 0
		code_start:    main_start
		code_len:      c.program.code.len - main_start
	}
	c.program.entry = c.program.functions.len - 1

	return CompileResult{
		program:        c.program
		diagnostics:    c.diagnostics
		success:        !diagnostic.has_errors(c.diagnostics)
		env:            c.env
		program_type:   t_none() // TODO: compute from last expression
		type_positions: c.type_positions
	}
}

fn (mut c Compiler) emit(o Op) {
	c.program.code << op(o)
}

fn (mut c Compiler) emit_arg(o Op, operand int) {
	c.program.code << op_arg(o, operand)
}

fn (mut c Compiler) current_addr() int {
	return c.program.code.len
}

fn (mut c Compiler) add_constant(v Value) int {
	c.program.constants << v
	return c.program.constants.len - 1
}

fn (mut c Compiler) get_or_create_local(name string) int {
	if idx := c.locals[name] {
		return idx
	}
	idx := c.local_count
	c.locals[name] = idx
	c.local_count += 1
	return idx
}

struct VarAccess {
	is_local   bool
	is_capture bool
	is_self    bool
	index      int
}

fn (mut c Compiler) resolve_variable(name string) ?VarAccess {
	if idx := c.locals[name] {
		return VarAccess{
			is_local: true
			index:    idx
		}
	}

	if idx := c.captures[name] {
		return VarAccess{
			is_capture: true
			index:      idx
		}
	}

	for scope in c.outer_scopes {
		if name in scope.locals {
			if name == c.current_binding {
				return VarAccess{
					is_self: true
				}
			}

			capture_idx := c.capture_names.len
			c.captures[name] = capture_idx
			c.capture_names << name
			return VarAccess{
				is_capture: true
				index:      capture_idx
			}
		}
	}

	return none
}

fn (mut c Compiler) compile_node(node ast.Node) ! {
	match node {
		ast.Statement { c.compile_statement(node)! }
		ast.Expression { c.compile_expr(node, none)! }
	}
}

fn (mut c Compiler) compile_statement(stmt ast.Statement) ! {
	match stmt {
		ast.VariableBinding {
			idx := c.get_or_create_local(stmt.identifier.name)

			old_binding := c.current_binding
			c.current_binding = stmt.identifier.name
			type_hint := if t := stmt.typ { c.resolve_type_identifier(t) } else { none }
			expr_type := c.compile_expr(stmt.init, type_hint)!
			c.current_binding = old_binding

			// Validate type annotation matches expression type
			if th := type_hint {
				c.expect_type(expr_type, th, stmt.init.span, 'in variable binding')
			}

			// Register the variable type in the environment
			final_type := type_hint or { expr_type }
			c.env.define(stmt.identifier.name, final_type)

			c.emit_arg(.store_local, idx)
		}
		ast.ConstBinding {
			if c.in_function {
				c.error_at_span("'const' declarations are only allowed at the top level, not inside functions",
					stmt.span)
			}
			type_hint := if t := stmt.typ { c.resolve_type_identifier(t) } else { none }
			expr_type := c.compile_expr(stmt.init, type_hint)!
			idx := c.get_or_create_local(stmt.identifier.name)

			// Validate type annotation matches expression type
			if th := type_hint {
				c.expect_type(expr_type, th, stmt.init.span, 'in constant binding')
			}

			// Register the constant type in the environment
			final_type := type_hint or { expr_type }
			c.env.define(stmt.identifier.name, final_type)

			c.emit_arg(.store_local, idx)
		}
		ast.TypePatternBinding {
			c.compile_expr(stmt.init, none)!
			c.emit(.pop)
		}
		ast.TupleDestructuringBinding {
			c.compile_expr(stmt.init, none)!
			for i, pattern in stmt.patterns {
				if pattern is ast.Identifier {
					c.emit(.dup)
					c.emit_arg(.tuple_index, i)
					idx := c.get_or_create_local(pattern.name)
					c.emit_arg(.store_local, idx)
				}
			}
			c.emit(.pop)
		}
		ast.FunctionDeclaration {
			ret_hint := if rt := stmt.return_type {
				c.resolve_type_identifier(rt)
			} else {
				none
			}

			// Build and register the function type for type-aware compilation
			mut param_types := []Type{}
			for i, p in stmt.params {
				pt := if t := p.typ {
					c.resolve_type_identifier(t) or { t_var('P${i}') }
				} else {
					t_var('P${i}')
				}
				param_types << pt
			}
			ret_type := ret_hint or { t_var('R') }
			c.env.register_function(stmt.identifier.name, TypeFunction{
				params: param_types
				ret:    ret_type
			})

			c.compile_function_common(stmt.identifier.name, stmt.params, stmt.body, ret_hint)!
			idx := c.get_or_create_local(stmt.identifier.name)
			c.emit_arg(.store_local, idx)
		}
		ast.StructDeclaration {
			c.compile_struct_decl(stmt)
		}
		ast.EnumDeclaration {
			c.compile_enum_decl(stmt)
		}
		ast.ImportDeclaration {}
		ast.ExportDeclaration {
			c.compile_statement(stmt.declaration)!
		}
	}
}

fn (mut c Compiler) compile_expr(expr ast.Expression, hint ?Type) !Type {
	is_tail := c.in_tail_position
	c.in_tail_position = false

	match expr {
		ast.BlockExpression {
			mut last_type := t_none()
			for i, node in expr.body {
				is_last := i == expr.body.len - 1
				c.in_tail_position = is_tail && is_last
				if is_last {
					if node is ast.Expression {
						last_type = c.compile_expr(node, hint)!
					} else {
						c.compile_node(node)!
						c.emit(.push_none)
						last_type = t_none()
					}
				} else {
					c.compile_node(node)!
					if node is ast.Expression {
						c.emit(.pop)
					}
				}
				c.in_tail_position = false
			}
			if expr.body.len == 0 {
				c.emit(.push_none)
			}
			return last_type
		}
		ast.NumberLiteral {
			if expr.value.contains('.') {
				val := expr.value.f64()
				idx := c.add_constant(val)
				c.emit_arg(.push_const, idx)
				return t_float()
			} else {
				val := expr.value.int()
				idx := c.add_constant(val)
				c.emit_arg(.push_const, idx)
				return t_int()
			}
		}
		ast.StringLiteral {
			idx := c.add_constant(expr.value)
			c.emit_arg(.push_const, idx)
			return t_string()
		}
		ast.InterpolatedString {
			if expr.parts.len == 0 {
				idx := c.add_constant('')
				c.emit_arg(.push_const, idx)
			} else {
				c.compile_expr(expr.parts[0], none)!
				c.emit(.to_string)

				for i := 1; i < expr.parts.len; i++ {
					c.compile_expr(expr.parts[i], none)!
					c.emit(.to_string)
					c.emit(.str_concat)
				}
			}
			return t_string()
		}
		ast.BooleanLiteral {
			if expr.value {
				c.emit(.push_true)
			} else {
				c.emit(.push_false)
			}
			return t_bool()
		}
		ast.NoneExpression {
			c.emit(.push_none)
			return t_none()
		}
		ast.Identifier {
			// Check if this is a shorthand enum variant like None when hint is Option
			if h := hint {
				if h is TypeEnum {
					if expr.name in h.variants {
						c.emit_arg(.push_const, c.add_constant(h.id))
						c.emit_arg(.push_const, c.add_constant(h.name))
						c.emit_arg(.push_const, c.add_constant(expr.name))
						c.emit(.make_enum)
						return h
					}
				}
			}

			if access := c.resolve_variable(expr.name) {
				if access.is_local {
					c.emit_arg(.push_local, access.index)
				} else if access.is_capture {
					c.emit_arg(.push_capture, access.index)
				} else if access.is_self {
					c.emit(.push_self)
				}
				// Look up the type from the environment
				typ := c.env.lookup(expr.name) or { t_none() }
				c.record_type(expr.name, typ, expr.span, c.env.lookup_doc(expr.name))
				return typ
			} else {
				// Unknown identifier - emit error with "did you mean" suggestion
				if suggestion := c.find_similar_name(expr.name) {
					c.error_at_span("Unknown identifier '${expr.name}'. Did you mean '${suggestion}'?",
						expr.span)
				} else {
					c.error_at_span("Unknown identifier '${expr.name}'", expr.span)
				}
				return t_none()
			}
		}
		ast.BinaryExpression {
			if expr.op.kind == .logical_and {
				c.compile_expr(expr.left, none)!
				c.emit(.dup)

				end_jump := c.current_addr()
				c.emit_arg(.jump_if_false, 0)
				c.emit(.pop)
				c.compile_expr(expr.right, none)!
				c.program.code[end_jump] = op_arg(.jump_if_false, c.current_addr())
				return t_bool()
			}
			if expr.op.kind == .logical_or {
				c.compile_expr(expr.left, none)!
				c.emit(.dup)

				end_jump := c.current_addr()
				c.emit_arg(.jump_if_true, 0)
				c.emit(.pop)
				c.compile_expr(expr.right, none)!
				c.program.code[end_jump] = op_arg(.jump_if_true, c.current_addr())
				return t_bool()
			}

			left_type := c.compile_expr(expr.left, none)!
			right_type := c.compile_expr(expr.right, none)!
			op_str := expr.op.kind.str()

			match expr.op.kind {
				.punc_plus {
					c.emit(.add)
					// String concatenation
					if types_equal(left_type, t_string()) && types_equal(right_type, t_string()) {
						return t_string()
					}
					// String + TypeVar or TypeVar + String: infer as String
					if types_equal(left_type, t_string()) && right_type is type_def.TypeVar {
						return t_string()
					}
					if left_type is type_def.TypeVar && types_equal(right_type, t_string()) {
						return t_string()
					}
					// Mixed string + concrete non-string: suggest interpolation
					if types_equal(left_type, t_string()) || types_equal(right_type, t_string()) {
						c.error_at_span("Cannot concatenate '${type_to_string(left_type)}' with '${type_to_string(right_type)}': use string interpolation instead",
							expr.span)
						return t_string()
					}
					// Numeric addition (or TypeVar that will be inferred as numeric)
					if !is_numeric(left_type) && left_type !is type_def.TypeVar {
						c.error_at_span("Left operand of '${op_str}' must be numeric, got '${type_to_string(left_type)}'",
							expr.span)
						return t_int()
					}
					if !is_numeric(right_type) && right_type !is type_def.TypeVar {
						c.error_at_span("Right operand of '${op_str}' must be numeric, got '${type_to_string(right_type)}'",
							expr.span)
						return t_int()
					}
					if !c.check_binary_operand_types(left_type, right_type) {
						c.error_at_span("Cannot apply '${op_str}' to '${type_to_string(left_type)}' and '${type_to_string(right_type)}': operands must have the same type",
							expr.span)
					}
					return c.infer_binary_result_type(left_type, right_type)
				}
				.punc_minus, .punc_mul, .punc_div, .punc_mod {
					match expr.op.kind {
						.punc_minus { c.emit(.sub) }
						.punc_mul { c.emit(.mul) }
						.punc_div { c.emit(.div) }
						.punc_mod { c.emit(.mod) }
						else {}
					}
					// Allow TypeVar (will be inferred as numeric later)
					if !is_numeric(left_type) && left_type !is type_def.TypeVar {
						c.error_at_span("Left operand of '${op_str}' must be numeric, got '${type_to_string(left_type)}'",
							expr.span)
						return t_int()
					}
					if !is_numeric(right_type) && right_type !is type_def.TypeVar {
						c.error_at_span("Right operand of '${op_str}' must be numeric, got '${type_to_string(right_type)}'",
							expr.span)
						return t_int()
					}
					if !c.check_binary_operand_types(left_type, right_type) {
						c.error_at_span("Cannot apply '${op_str}' to '${type_to_string(left_type)}' and '${type_to_string(right_type)}': operands must have the same type",
							expr.span)
					}
					return c.infer_binary_result_type(left_type, right_type)
				}
				.punc_lt, .punc_gt, .punc_lte, .punc_gte {
					match expr.op.kind {
						.punc_lt { c.emit(.lt) }
						.punc_gt { c.emit(.gt) }
						.punc_lte { c.emit(.lte) }
						.punc_gte { c.emit(.gte) }
						else {}
					}
					// Allow TypeVar (will be inferred as numeric later)
					left_ok := is_numeric(left_type) || left_type is type_def.TypeVar
					right_ok := is_numeric(right_type) || right_type is type_def.TypeVar
					if !left_ok || !right_ok {
						c.error_at_span("Cannot compare '${type_to_string(left_type)}' with '${type_to_string(right_type)}': operator '${op_str}' requires numeric operands",
							expr.span)
					}
					return t_bool()
				}
				.punc_equals_comparator, .punc_not_equal {
					if expr.op.kind == .punc_equals_comparator {
						c.emit(.eq)
					} else {
						c.emit(.neq)
					}
					if !c.check_binary_operand_types(left_type, right_type) {
						c.error_at_span('Cannot compare ${type_to_string(left_type)} with ${type_to_string(right_type)}',
							expr.span)
					}
					return t_bool()
				}
				else {
					return error('Unknown binary operator: ${expr.op.kind}')
				}
			}
		}
		ast.UnaryExpression {
			operand_type := c.compile_expr(expr.expression, none)!
			op_str := expr.op.kind.str()

			match expr.op.kind {
				.punc_exclamation_mark {
					c.expect_type(operand_type, t_bool(), expr.expression.span, "for operator '${op_str}'")
					c.emit(.not)
					return t_bool()
				}
				.punc_minus {
					if !is_numeric(operand_type) {
						c.error_at_span("Operator '${op_str}' requires a numeric operand, got '${type_to_string(operand_type)}'",
							expr.expression.span)
					}
					c.emit(.neg)
					return operand_type
				}
				else {
					c.error_at_span('Unknown unary operator: ${expr.op.kind}', expr.span)
					return t_none()
				}
			}
		}
		ast.IfExpression {
			c.compile_expr(expr.condition, none)!

			else_jump := c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			c.in_tail_position = is_tail
			then_type := c.compile_expr(expr.body, hint)!
			c.in_tail_position = false

			end_jump := c.current_addr()
			c.emit_arg(.jump, 0)

			else_addr := c.current_addr()
			c.program.code[else_jump] = op_arg(.jump_if_false, else_addr)

			c.in_tail_position = is_tail
			if else_body := expr.else_body {
				c.compile_expr(else_body, hint)!
			} else {
				c.emit(.push_none)
			}
			c.in_tail_position = false

			end_addr := c.current_addr()
			c.program.code[end_jump] = op_arg(.jump, end_addr)
			// Return then branch type (checker already unified them)
			return then_type
		}
		ast.MatchExpression {
			return c.compile_match(expr, is_tail)!
		}
		ast.ArrayExpression {
			has_spread := expr.elements.any(it is ast.SpreadElement)

			// Determine element type from hint if available
			mut elem_type := if h := hint {
				if h is type_def.TypeArray {
					h.element
				} else {
					t_none()
				}
			} else {
				t_none()
			}

			if !has_spread {
				for elem in expr.elements {
					if elem is ast.Expression {
						// Use element hint for better type inference
						elem_type = c.compile_expr(elem, elem_type)!
					}
				}
				c.emit_arg(.make_array, expr.elements.len)
			} else {
				mut have_result := false

				mut i := 0
				for i < expr.elements.len {
					elem := expr.elements[i]

					if elem is ast.SpreadElement {
						inner := elem.expression or {
							return error('Spread in array literal missing expression')
						}

						arr_type := c.compile_expr(inner, none)!
						if arr_type is type_def.TypeArray {
							elem_type = arr_type.element
						}
						if have_result {
							c.emit(.array_concat)
						} else {
							have_result = true
						}
						i++
					} else {
						mut group_count := 0
						for j := i; j < expr.elements.len; j++ {
							if expr.elements[j] is ast.SpreadElement {
								break
							}
							arr_elem := expr.elements[j]
							if arr_elem is ast.Expression {
								elem_type = c.compile_expr(arr_elem, none)!
							}
							group_count++
						}
						c.emit_arg(.make_array, group_count)
						if have_result {
							c.emit(.array_concat)
						} else {
							have_result = true
						}
						i += group_count
					}
				}

				if !have_result {
					c.emit_arg(.make_array, 0)
				}
			}
			return t_array(elem_type)
		}
		ast.TupleExpression {
			mut elem_types := []Type{}
			for elem in expr.elements {
				elem_types << c.compile_expr(elem, none)!
			}
			c.emit_arg(.make_tuple, expr.elements.len)
			return t_tuple(elem_types)
		}
		ast.ArrayIndexExpression {
			arr_type := c.compile_expr(expr.expression, none)!
			if expr.index is ast.RangeExpression {
				range_idx := expr.index as ast.RangeExpression
				c.compile_expr(range_idx.start, none)!
				c.compile_expr(range_idx.end, none)!
				c.emit(.array_slice)
				return arr_type // slice returns same array type
			} else {
				c.compile_expr(expr.index, none)!
				c.emit(.index)
				// Return element type if array, otherwise the indexed type
				if arr_type is type_def.TypeArray {
					return arr_type.element
				}
				return t_none()
			}
		}
		ast.RangeExpression {
			c.compile_expr(expr.start, none)!
			c.compile_expr(expr.end, none)!
			c.emit(.make_range)
			return t_array(t_int()) // Range is essentially [Int]
		}
		ast.FunctionExpression {
			return c.compile_function_expression(expr)!
		}
		ast.FunctionCallExpression {
			// Check if this is a shorthand enum variant like Ok(value) when hint is an enum
			if h := hint {
				if h is TypeEnum {
					if expr.identifier.name in h.variants {
						// Validate enum variant argument count
						payload_types := h.variants[expr.identifier.name] or { []Type{} }
						if payload_types.len > 0 {
							if expr.arguments.len != payload_types.len {
								c.error_at_span("Enum variant '${expr.identifier.name}' expects ${payload_types.len} argument(s), got ${expr.arguments.len}",
									expr.span)
							}
						} else if expr.arguments.len != 0 {
							c.error_at_span("Enum variant '${expr.identifier.name}' expects no arguments, got ${expr.arguments.len}",
								expr.span)
						}

						c.emit_arg(.push_const, c.add_constant(h.id))
						c.emit_arg(.push_const, c.add_constant(h.name))
						c.emit_arg(.push_const, c.add_constant(expr.identifier.name))
						if expr.arguments.len > 0 {
							for i, arg in expr.arguments {
								arg_hint := if i < payload_types.len {
									payload_types[i]
								} else {
									none
								}
								arg_type := c.compile_expr(arg, arg_hint)!
								// Validate argument type matches expected payload type
								if i < payload_types.len {
									c.expect_type(arg_type, payload_types[i], arg.span,
										'in enum variant argument')
								}
							}
							c.emit_arg(.make_enum_payload, expr.arguments.len)
						} else {
							c.emit(.make_enum)
						}
						return h
					}
				}
			}

			func_type := c.env.lookup_function(expr.identifier.name)

			// Validate argument count
			if ft := func_type {
				if expr.arguments.len != ft.params.len {
					c.error_at_span("Function '${expr.identifier.name}' expects ${ft.params.len} argument(s), got ${expr.arguments.len}",
						expr.span)
				}
			}

			for i, arg in expr.arguments {
				param_hint := if ft := func_type {
					if i < ft.params.len { ft.params[i] } else { none }
				} else {
					none
				}
				arg_type := c.compile_expr(arg, param_hint)!

				// Validate argument type
				if ft := func_type {
					if i < ft.params.len {
						c.expect_type(arg_type, ft.params[i], arg.span, "in argument ${i + 1} of '${expr.identifier.name}'")
					}
				}
			}

			if access := c.resolve_variable(expr.identifier.name) {
				if access.is_local {
					c.emit_arg(.push_local, access.index)
				} else if access.is_capture {
					c.emit_arg(.push_capture, access.index)
				} else if access.is_self {
					c.emit(.push_self)
				}

				if is_tail {
					c.emit_arg(.tail_call, expr.arguments.len)
				} else {
					c.emit_arg(.call, expr.arguments.len)
				}
				// Return the function's return type
				if ft := func_type {
					return ft.ret
				}
				return t_none()
			} else {
				// Check if it's a builtin, otherwise report unknown function
				return c.compile_builtin_call(expr) or {
					if suggestion := c.find_similar_name(expr.identifier.name) {
						c.error_at_span("'${expr.identifier.name}' is not defined. Did you mean '${suggestion}'?",
							expr.span)
					} else {
						c.error_at_span("'${expr.identifier.name}' is not defined", expr.span)
					}
					return t_none()
				}
			}
		}
		ast.PropertyAccessExpression {
			if expr.left is ast.Identifier {
				left_id := expr.left as ast.Identifier
				if looked_up := c.env.lookup_type(left_id.name) {
					if looked_up is TypeEnum {
						enum_type := looked_up
						enum_name := left_id.name

						// Record type for enum name hover
						enum_doc := c.env.lookup_doc(enum_name)
						c.record_type(enum_name, Type(enum_type), left_id.span, enum_doc)

						variant_name, args, variant_span := if expr.right is ast.FunctionCallExpression {
							call := expr.right as ast.FunctionCallExpression
							call.identifier.name, call.arguments, call.span
						} else if expr.right is ast.Identifier {
							r := expr.right as ast.Identifier
							r.name, []ast.Expression{}, r.span
						} else {
							return c.compile_expr(expr.left, none)
						}

						if variant_name !in enum_type.variants {
							c.error_at_span("Enum '${enum_name}' has no variant '${variant_name}'",
								variant_span)
							return t_none()
						}

						// Record type for variant hover
						variant_doc := c.env.lookup_doc('${enum_name}.${variant_name}')
						c.record_type('${enum_name}.${variant_name}', Type(enum_type),
							variant_span, variant_doc)

						payload_types := enum_type.variants[variant_name] or { []Type{} }

						if payload_types.len > 0 {
							if args.len != payload_types.len {
								c.error_at_span("Enum variant '${variant_name}' expects ${payload_types.len} argument(s), got ${args.len}",
									variant_span)
							}

							c.emit_arg(.push_const, c.add_constant(enum_type.id))
							enum_idx := c.add_constant(enum_name)
							c.emit_arg(.push_const, enum_idx)
							variant_idx := c.add_constant(variant_name)
							c.emit_arg(.push_const, variant_idx)
							for i, arg in args {
								arg_hint := if i < payload_types.len {
									payload_types[i]
								} else {
									t_none()
								}
								arg_type := c.compile_expr(arg, arg_hint)!
								if i < payload_types.len {
									c.expect_type(arg_type, payload_types[i], arg.span,
										'in enum variant argument')
								}
							}
							c.emit_arg(.make_enum_payload, args.len)
						} else if args.len > 0 {
							c.error_at_span("Enum variant '${variant_name}' takes no arguments",
								variant_span)
							c.emit_arg(.push_const, c.add_constant(enum_type.id))
							enum_idx := c.add_constant(enum_name)
							c.emit_arg(.push_const, enum_idx)
							variant_idx := c.add_constant(variant_name)
							c.emit_arg(.push_const, variant_idx)
							c.emit(.make_enum)
						} else {
							c.emit_arg(.push_const, c.add_constant(enum_type.id))
							enum_idx := c.add_constant(enum_name)
							c.emit_arg(.push_const, enum_idx)
							variant_idx := c.add_constant(variant_name)
							c.emit_arg(.push_const, variant_idx)
							c.emit(.make_enum)
						}
						return enum_type
					}
				}
			}

			left_type := c.compile_expr(expr.left, none)!

			if expr.right is ast.FunctionCallExpression {
				call := expr.right as ast.FunctionCallExpression

				for arg in call.arguments {
					c.compile_expr(arg, none)!
				}

				c.error_at_span("Cannot call '${call.identifier.name}' as a method. AL does not have methods - use '${call.identifier.name}(...)' as a regular function call instead.",
					call.span)
				return t_none()
			} else if expr.right is ast.NumberLiteral {
				num := expr.right as ast.NumberLiteral
				index := num.value.int()

				if left_type is type_def.TypeTuple {
					if index < 0 || index >= left_type.elements.len {
						c.error_at_span('Tuple index ${index} out of bounds. Tuple has ${left_type.elements.len} elements.',
							num.span)
						return t_none()
					}
					c.emit_arg(.tuple_index, index)
					return left_type.elements[index]
				} else {
					c.error_at_span('Cannot use numeric index on type ${type_to_string(left_type)}. Only tuples support .0 .1 etc.',
						num.span)
					return t_none()
				}
			} else if expr.right is ast.Identifier {
				right := expr.right as ast.Identifier

				if left_type is TypeStruct {
					if field_type := left_type.fields[right.name] {
						// Record type for field hover
						qualified_name := '${left_type.name}.${right.name}'
						field_doc := c.env.lookup_doc(qualified_name)
						c.record_type(qualified_name, field_type, right.span, field_doc)

						idx := c.add_constant(right.name)
						c.emit_arg(.get_field, idx)
						return field_type
					} else {
						available := left_type.fields.keys().join(', ')
						c.error_at_span("Struct '${left_type.name}' has no field '${right.name}'. Available fields: ${available}",
							right.span)
						return t_none()
					}
				} else {
					c.error_at_span("Cannot access property '${right.name}' on type '${type_to_string(left_type)}'",
						right.span)
					return t_none()
				}
			} else {
				c.error_at_span('Expected identifier in property access', expr.right.span)
				return t_none()
			}
		}
		ast.StructInitExpression {
			struct_name := expr.identifier.name

			mut struct_type := if struct_def := c.env.lookup_struct(struct_name) {
				// Record type for struct name hover
				doc := c.env.lookup_doc(struct_name)
				c.record_type(struct_name, Type(struct_def), expr.identifier.span, doc)
				struct_def
			} else {
				c.error_at_span("Unknown struct '${struct_name}'", expr.identifier.span)
				TypeStruct{
					name:   struct_name
					fields: map[string]Type{}
				}
			}

			// Handle explicit type arguments (e.g., Pair[Int, String]{...})
			if expr.type_args.len > 0 {
				if struct_type.type_params.len != expr.type_args.len {
					c.error_at_span("Struct '${struct_name}' expects ${struct_type.type_params.len} type argument(s), got ${expr.type_args.len}",
						expr.identifier.span)
				} else {
					mut resolved_args := []Type{}
					for arg in expr.type_args {
						if resolved := c.resolve_type_identifier(arg) {
							resolved_args << resolved
						} else {
							c.error_at_span("Unknown type '${arg.identifier.name}'", arg.identifier.span)
							resolved_args << t_none()
						}
					}

					mut subs := map[string]Type{}
					for i, param in struct_type.type_params {
						subs[param] = resolved_args[i]
					}
					mut new_fields := map[string]Type{}
					for field_name, field_type in struct_type.fields {
						new_fields[field_name] = type_def.substitute(field_type, subs)
					}
					struct_type = TypeStruct{
						id:          struct_type.id
						name:        struct_type.name
						type_params: struct_type.type_params
						type_args:   resolved_args
						fields:      new_fields
					}
				}
			} else if struct_type.type_params.len > 0 {
				// Infer type parameters from field values
				mut subs := map[string]Type{}

				for field in expr.fields {
					if expected_type := struct_type.fields[field.identifier.name] {
						// Emit field name constant before the value
						name_idx := c.add_constant(field.identifier.name)
						c.emit_arg(.push_const, name_idx)
						actual_type := c.compile_expr(field.init, expected_type)!
						c.infer_type_args(expected_type, actual_type, mut subs, field.init.span)
					}
				}

				mut resolved_args := []Type{}
				for param in struct_type.type_params {
					if inferred := subs[param] {
						resolved_args << inferred
					} else {
						c.error_at_span("Could not infer type parameter '${param}' for struct '${struct_name}'",
							expr.identifier.span)
						resolved_args << t_none()
					}
				}

				mut new_fields := map[string]Type{}
				for field_name, field_type in struct_type.fields {
					new_fields[field_name] = type_def.substitute(field_type, subs)
				}
				struct_type = TypeStruct{
					id:          struct_type.id
					name:        struct_type.name
					type_params: struct_type.type_params
					type_args:   resolved_args
					fields:      new_fields
				}
			}

			mut provided_fields := map[string]bool{}

			for field in expr.fields {
				if field.identifier.name in provided_fields {
					c.error_at_span("Duplicate field '${field.identifier.name}' in struct initializer",
						field.identifier.span)
				}
				provided_fields[field.identifier.name] = true

				// For non-generic structs or with explicit type args, compile and check field values
				if struct_type.type_params.len == 0 || expr.type_args.len > 0 {
					// Emit field name constant before the value
					name_idx := c.add_constant(field.identifier.name)
					c.emit_arg(.push_const, name_idx)
					actual_type := c.compile_expr(field.init, struct_type.fields[field.identifier.name] or {
						t_none()
					})!
					if expected_type := struct_type.fields[field.identifier.name] {
						// Record type for field name hover in struct literals
						qualified_name := '${struct_name}.${field.identifier.name}'
						field_doc := c.env.lookup_doc(qualified_name)
						c.record_type(qualified_name, expected_type, field.identifier.span,
							field_doc)

						c.expect_type(actual_type, expected_type, field.init.span, "in field '${field.identifier.name}'")
					} else {
						available := struct_type.fields.keys().join(', ')
						c.error_at_span("Struct '${struct_name}' has no field '${field.identifier.name}'. Available fields: ${available}",
							field.identifier.span)
					}
				} else {
					// For inferred generics, check field existence (values already compiled during inference)
					if field.identifier.name !in struct_type.fields {
						available := struct_type.fields.keys().join(', ')
						c.error_at_span("Struct '${struct_name}' has no field '${field.identifier.name}'. Available fields: ${available}",
							field.identifier.span)
					} else {
						// Record type for hover
						if expected_type := struct_type.fields[field.identifier.name] {
							qualified_name := '${struct_name}.${field.identifier.name}'
							field_doc := c.env.lookup_doc(qualified_name)
							c.record_type(qualified_name, expected_type, field.identifier.span,
								field_doc)
						}
					}
				}
			}

			mut missing_fields := []string{}
			for field_name, _ in struct_type.fields {
				if field_name !in provided_fields {
					missing_fields << field_name
				}
			}
			if missing_fields.len > 0 {
				c.error_at_span("Missing required fields in '${struct_name}': ${missing_fields.join(', ')}",
					expr.identifier.span)
			}

			// Emit struct creation bytecode
			c.emit_arg(.push_const, c.add_constant(struct_type.id))
			type_idx := c.add_constant(struct_name)
			c.emit_arg(.push_const, type_idx)
			c.emit_arg(.make_struct, expr.fields.len)
			return struct_type
		}
		ast.ErrorExpression {
			err_type := c.compile_expr(expr.expression, none)!
			c.emit(.make_error)
			return type_def.TypeResult{
				success: t_none()
				error:   err_type
			}
		}
		ast.OrExpression {
			result_type := c.compile_expr(expr.expression, none)!
			c.emit(.dup)
			c.emit(.is_failure)

			not_failure_jump := c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			c.emit(.unwrap_failure)
			if receiver := expr.receiver {
				idx := c.get_or_create_local(receiver.name)
				c.emit_arg(.store_local, idx)
			} else {
				c.emit(.pop)
			}

			c.compile_expr(expr.body, none)!

			end_jump := c.current_addr()
			c.emit_arg(.jump, 0)

			c.program.code[not_failure_jump] = op_arg(.jump_if_false, c.current_addr())
			c.program.code[end_jump] = op_arg(.jump, c.current_addr())
			// Unwrap the success type from Result
			if result_type is type_def.TypeResult {
				return result_type.success
			}
			return result_type
		}
		else {
			return error("Internal error: unhandled expression type '${expr.type_name()}'. This is a compiler bug.")
		}
	}
}

fn (mut c Compiler) compile_function_expression(func ast.FunctionExpression) !Type {
	ret_hint := if rt := func.return_type {
		c.resolve_type_identifier(rt)
	} else {
		none
	}

	// Build parameter types
	mut param_types := []Type{}
	for i, p in func.params {
		pt := if t := p.typ {
			c.resolve_type_identifier(t) or { t_var('P${i}') }
		} else {
			t_var('P${i}')
		}
		param_types << pt
	}

	c.compile_function_common(none, func.params, func.body, ret_hint)!

	return TypeFunction{
		params: param_types
		ret:    ret_hint or { t_var('R') }
	}
}

fn (mut c Compiler) compile_function_common(name ?string, params []ast.FunctionParameter, body ast.Expression, return_type ?Type) ! {
	old_locals := c.locals.clone()
	old_local_count := c.local_count
	old_captures := c.captures.clone()
	old_capture_names := c.capture_names.clone()

	mut scope_locals := old_locals.clone()
	if n := name {
		scope_locals[n] = c.local_count
	}

	c.outer_scopes << Scope{
		locals: scope_locals
	}

	jump_over := c.current_addr()
	c.emit_arg(.jump, 0)

	c.locals = {}
	c.local_count = 0
	c.captures = {}
	c.capture_names = []

	// Build parameter types and register them in the type environment
	c.env.push_scope()
	mut seen_params := map[string]bool{}
	for i, param in params {
		if param.identifier.name in seen_params {
			c.error_at_span("Duplicate parameter '${param.identifier.name}'", param.identifier.span)
		}
		seen_params[param.identifier.name] = true

		c.get_or_create_local(param.identifier.name)
		// Resolve parameter type and register it in the environment
		pt := if t := param.typ {
			c.resolve_type_identifier(t) or { t_var('P${i}') }
		} else {
			t_var('P${i}')
		}
		c.env.define(param.identifier.name, pt)
	}

	func_start := c.current_addr()

	old_binding := c.current_binding
	if n := name {
		c.current_binding = n
	}

	old_tail := c.in_tail_position
	c.in_tail_position = true
	c.compile_expr(body, return_type)!
	c.in_tail_position = old_tail
	c.current_binding = old_binding
	c.emit(.ret)

	// Pop the function scope
	c.env.pop_scope()

	c.program.code[jump_over] = op_arg(.jump, c.current_addr())

	captured_names := c.capture_names.clone()
	capture_count := captured_names.len

	func_idx := c.program.functions.len
	c.program.functions << Function{
		name:          name or { '__anon__' }
		arity:         params.len
		locals:        c.local_count
		capture_count: capture_count
		code_start:    func_start
		code_len:      c.current_addr() - func_start - 1
	}

	c.outer_scopes.pop()

	c.locals = old_locals.clone()
	c.local_count = old_local_count
	c.captures = old_captures.clone()
	c.capture_names = old_capture_names.clone()

	for cap_name in captured_names {
		if access := c.resolve_variable(cap_name) {
			if access.is_local {
				c.emit_arg(.push_local, access.index)
			} else if access.is_capture {
				c.emit_arg(.push_capture, access.index)
			}
		}
	}

	c.emit_arg(.make_closure, func_idx)
}

fn (mut c Compiler) compile_pattern_element(pattern ast.Expression, mut fail_jumps []int) ! {
	match pattern {
		ast.NumberLiteral, ast.StringLiteral, ast.BooleanLiteral {
			c.compile_expr(pattern, none)!
			c.emit(.eq)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)
		}
		ast.Identifier {
			local_idx := c.get_or_create_local(pattern.name)
			c.emit_arg(.store_local, local_idx)
		}
		ast.WildcardPattern {
			c.emit(.pop)
		}
		ast.RangeExpression {
			temp_idx := c.local_count
			c.local_count++
			c.emit(.dup)
			c.emit_arg(.store_local, temp_idx)

			c.compile_expr(pattern.start, none)!
			c.emit(.gte)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			c.emit_arg(.push_local, temp_idx)
			c.compile_expr(pattern.end, none)!
			c.emit(.lt)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)
		}
		ast.TupleExpression {
			temp_idx := c.local_count
			c.local_count++
			c.emit_arg(.store_local, temp_idx)

			c.emit_arg(.push_local, temp_idx)
			c.emit(.array_len)
			c.emit_arg(.push_const, c.add_constant(pattern.elements.len))
			c.emit(.eq)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			for i, elem in pattern.elements {
				c.emit_arg(.push_local, temp_idx)
				c.emit_arg(.tuple_index, i)
				c.compile_pattern_element(elem, mut fail_jumps)!
			}
		}
		ast.ArrayExpression {
			has_spread := pattern.elements.len > 0 && pattern.elements.last() is ast.SpreadElement
			pre_count := if has_spread { pattern.elements.len - 1 } else { pattern.elements.len }

			temp_idx := c.local_count
			c.local_count++
			c.emit_arg(.store_local, temp_idx)

			c.emit_arg(.push_local, temp_idx)
			c.emit(.array_len)
			c.emit_arg(.push_const, c.add_constant(pre_count))
			if has_spread {
				c.emit(.gte)
			} else {
				c.emit(.eq)
			}
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			for i in 0 .. pre_count {
				elem := pattern.elements[i]
				c.emit_arg(.push_local, temp_idx)
				c.emit_arg(.push_const, c.add_constant(i))
				c.emit(.index)
				if elem is ast.Expression {
					c.compile_pattern_element(elem, mut fail_jumps)!
				}
			}

			if has_spread {
				spread_elem := pattern.elements.last()
				if spread_elem is ast.SpreadElement {
					if inner := spread_elem.expression {
						if inner is ast.Identifier {
							c.emit_arg(.push_local, temp_idx)
							c.emit_arg(.push_const, c.add_constant(pre_count))
							c.emit_arg(.push_local, temp_idx)
							c.emit(.array_len)
							c.emit(.array_slice)
							local_idx := c.get_or_create_local(inner.name)
							c.emit_arg(.store_local, local_idx)
						}
					}
				}
			}
		}
		else {
			c.compile_expr(pattern, none)!
			c.emit(.eq)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)
		}
	}
}

fn (mut c Compiler) compile_pattern(pattern ast.Expression, mut fail_jumps []int) ! {
	match pattern {
		ast.NumberLiteral, ast.StringLiteral, ast.BooleanLiteral {
			c.emit(.dup)
			c.compile_expr(pattern, none)!
			c.emit(.eq)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)
		}
		ast.Identifier {
			c.emit(.dup)
			local_idx := c.get_or_create_local(pattern.name)
			c.emit_arg(.store_local, local_idx)
		}
		ast.WildcardPattern {}
		ast.RangeExpression {
			c.emit(.dup)
			c.compile_expr(pattern.start, none)!
			c.emit(.gte)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			c.emit(.dup)
			c.compile_expr(pattern.end, none)!
			c.emit(.lt)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)
		}
		ast.TupleExpression {
			c.emit(.dup)
			c.emit(.array_len)
			c.emit_arg(.push_const, c.add_constant(pattern.elements.len))
			c.emit(.eq)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			for i, elem in pattern.elements {
				c.emit(.dup)
				c.emit_arg(.tuple_index, i)
				c.compile_pattern_element(elem, mut fail_jumps)!
			}
		}
		ast.ArrayExpression {
			has_spread := pattern.elements.len > 0 && pattern.elements.last() is ast.SpreadElement
			pre_count := if has_spread { pattern.elements.len - 1 } else { pattern.elements.len }

			c.emit(.dup)
			c.emit(.array_len)
			c.emit_arg(.push_const, c.add_constant(pre_count))
			if has_spread {
				c.emit(.gte)
			} else {
				c.emit(.eq)
			}
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)

			for i in 0 .. pre_count {
				elem := pattern.elements[i]
				c.emit(.dup)
				c.emit_arg(.push_const, c.add_constant(i))
				c.emit(.index)
				if elem is ast.Expression {
					c.compile_pattern_element(elem, mut fail_jumps)!
				}
			}

			if has_spread {
				spread_elem := pattern.elements.last()
				if spread_elem is ast.SpreadElement {
					if inner := spread_elem.expression {
						if inner is ast.Identifier {
							c.emit(.dup)
							c.emit(.array_len)
							c.emit_arg(.push_const, c.add_constant(pre_count))
							c.emit(.swap)
							c.emit(.array_slice)
							local_idx := c.get_or_create_local(inner.name)
							c.emit_arg(.store_local, local_idx)
						}
					}
				}
			}
		}
		else {
			c.emit(.dup)
			c.compile_expr(pattern, none)!
			c.emit(.eq)
			fail_jumps << c.current_addr()
			c.emit_arg(.jump_if_false, 0)
		}
	}
}

fn (mut c Compiler) compile_match(m ast.MatchExpression, is_tail bool) !Type {
	c.compile_expr(m.subject, none)!
	mut result_type := t_none()

	mut end_jumps := []int{}

	for arm in m.arms {
		c.emit(.dup)
		mut fail_jumps := []int{}

		mut is_enum_pattern := false
		mut binding_names := []string{}
		mut enum_payload_patterns := []ast.Expression{}
		mut enum_name := ?string(none)
		mut enum_type_id := ?int(none)
		mut variant_name := ?string(none)

		if arm.pattern is ast.PropertyAccessExpression {
			prop := arm.pattern as ast.PropertyAccessExpression
			if prop.left is ast.Identifier {
				left_id := prop.left as ast.Identifier
				if enum_type := c.env.lookup_type(left_id.name) {
					if enum_type is TypeEnum {
						is_enum_pattern = true
						enum_name = left_id.name
						enum_type_id = enum_type.id
						if prop.right is ast.FunctionCallExpression {
							call := prop.right as ast.FunctionCallExpression
							variant_name = call.identifier.name
							for arg in call.arguments {
								if arg is ast.Identifier {
									binding_names << arg.name
								} else {
									enum_payload_patterns << arg
								}
							}
						} else if prop.right is ast.Identifier {
							right_id := prop.right as ast.Identifier
							variant_name = right_id.name
						}
					}
				}
			}
		} else if arm.pattern is ast.FunctionCallExpression {
			call := arm.pattern as ast.FunctionCallExpression
			vname := call.identifier.name
			if en := c.env.lookup_enum_by_variant(vname) {
				is_enum_pattern = true
				enum_name = en.name
				enum_type_id = en.id
				variant_name = vname
				for arg in call.arguments {
					if arg is ast.Identifier {
						binding_names << arg.name
					} else {
						enum_payload_patterns << arg
					}
				}
			}
		} else if arm.pattern is ast.Identifier {
			vname := arm.pattern.name
			if en := c.env.lookup_enum_by_variant(vname) {
				is_enum_pattern = true
				enum_name = en.name
				enum_type_id = en.id
				variant_name = vname
			}
		}

		if is_enum_pattern {
			if ename := enum_name {
				if vname := variant_name {
					type_id := enum_type_id or {
						return error('Internal error: enum_type_id not set for ${ename}.${vname}')
					}

					c.emit_arg(.push_const, c.add_constant(type_id))
					c.emit_arg(.push_const, c.add_constant(ename))
					c.emit_arg(.push_const, c.add_constant(vname))
					c.emit(.match_enum)
					fail_jumps << c.current_addr()
					c.emit_arg(.jump_if_false, 0)

					if enum_payload_patterns.len > 0 {
						c.emit(.dup)
						c.emit(.unwrap_enum)
						for pat in enum_payload_patterns {
							c.compile_pattern(pat, mut fail_jumps)!
						}
						c.emit(.pop)
					} else if binding_names.len > 0 {
						c.emit(.dup)
						c.emit(.unwrap_enum)
						for i := binding_names.len - 1; i >= 0; i-- {
							local_idx := c.get_or_create_local(binding_names[i])
							c.emit_arg(.store_local, local_idx)
						}
					}

					c.emit(.pop)
					c.in_tail_position = is_tail
					result_type = c.compile_expr(arm.body, none)!
					c.in_tail_position = false

					end_jumps << c.current_addr()
					c.emit_arg(.jump, 0)

					next_arm_addr := c.current_addr()
					for jump_addr in fail_jumps {
						c.program.code[jump_addr] = op_arg(.jump_if_false, next_arm_addr)
					}
					continue
				}
			}
		}

		if arm.pattern is ast.OrPattern {
			mut body_jumps := []int{}

			for i, pattern in arm.pattern.patterns {
				if i > 0 {
					c.emit(.dup)
				}
				mut pattern_fail_jumps := []int{}
				c.compile_pattern(pattern, mut pattern_fail_jumps)!

				if i < arm.pattern.patterns.len - 1 {
					body_jumps << c.current_addr()
					c.emit_arg(.jump, 0)
					for jump_addr in pattern_fail_jumps {
						c.program.code[jump_addr] = op_arg(.jump_if_false, c.current_addr())
					}
				} else {
					fail_jumps << pattern_fail_jumps
				}
			}

			body_addr := c.current_addr()
			for jump_addr in body_jumps {
				c.program.code[jump_addr] = op_arg(.jump, body_addr)
			}

			c.emit(.pop)
			c.in_tail_position = is_tail
			result_type = c.compile_expr(arm.body, none)!
			c.in_tail_position = false

			end_jumps << c.current_addr()
			c.emit_arg(.jump, 0)

			next_arm_addr := c.current_addr()
			for jump_addr in fail_jumps {
				c.program.code[jump_addr] = op_arg(.jump_if_false, next_arm_addr)
			}
			continue
		}

		c.compile_pattern(arm.pattern, mut fail_jumps)!

		c.emit(.pop)
		c.in_tail_position = is_tail
		result_type = c.compile_expr(arm.body, none)!
		c.in_tail_position = false

		end_jumps << c.current_addr()
		c.emit_arg(.jump, 0)

		next_arm_addr := c.current_addr()
		for jump_addr in fail_jumps {
			c.program.code[jump_addr] = op_arg(.jump_if_false, next_arm_addr)
		}
	}

	c.emit(.pop)
	c.emit(.push_none)

	end_addr := c.current_addr()
	for jump_addr in end_jumps {
		c.program.code[jump_addr] = op_arg(.jump, end_addr)
	}
	return result_type
}

fn (mut c Compiler) compile_builtin_call(call ast.FunctionCallExpression) !Type {
	match call.identifier.name {
		'println' {
			if call.arguments.len != 1 {
				return error('println expects 1 argument')
			}
			c.compile_expr(call.arguments[0], none)!
			c.emit(.print)
			c.emit(.push_none)
			return t_none()
		}
		'inspect' {
			if call.arguments.len != 1 {
				return error('inspect expects 1 argument')
			}
			c.compile_expr(call.arguments[0], none)!
			c.emit(.to_string)
			return t_string()
		}
		'__stack_depth__' {
			if !c.flags.expose_debug_builtins {
				return error('Unknown function: ${call.identifier.name}')
			}
			if call.arguments.len != 0 {
				return error('__stack_depth__ expects 0 arguments')
			}
			c.emit(.stack_depth)
			return t_int()
		}
		'read_file' {
			if call.arguments.len != 1 {
				return error('read_file expects 1 argument (path)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.emit(.file_read)
			return t_string()
		}
		'write_file' {
			if call.arguments.len != 2 {
				return error('write_file expects 2 arguments (path, content)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.compile_expr(call.arguments[1], none)!
			c.emit(.file_write)
			return t_none()
		}
		'tcp_listen' {
			if call.arguments.len != 1 {
				return error('tcp_listen expects 1 argument (port)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.emit(.tcp_listen)
			// Socket type - look it up from the environment
			return c.env.lookup_type('Socket') or { t_none() }
		}
		'tcp_accept' {
			if call.arguments.len != 1 {
				return error('tcp_accept expects 1 argument (listener)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.emit(.tcp_accept)
			return c.env.lookup_type('Socket') or { t_none() }
		}
		'tcp_read' {
			if call.arguments.len != 1 {
				return error('tcp_read expects 1 argument (socket)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.emit(.tcp_read)
			return t_string()
		}
		'tcp_write' {
			if call.arguments.len != 2 {
				return error('tcp_write expects 2 arguments (socket, data)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.compile_expr(call.arguments[1], none)!
			c.emit(.tcp_write)
			return t_none()
		}
		'tcp_close' {
			if call.arguments.len != 1 {
				return error('tcp_close expects 1 argument (socket)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.emit(.tcp_close)
			return t_none()
		}
		'str_split' {
			if call.arguments.len != 2 {
				return error('str_split expects 2 arguments (string, delimiter)')
			}
			c.compile_expr(call.arguments[0], none)!
			c.compile_expr(call.arguments[1], none)!
			c.emit(.str_split)
			return t_array(t_string())
		}
		else {
			return error('Unknown function: ${call.identifier.name}')
		}
	}
}

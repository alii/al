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
	t_array,
	t_bool,
	t_float,
	t_int,
	t_none,
	t_string,
	t_tuple,
	t_var,
	type_to_string,
}
import types { TypeEnv, TypePosition, check }

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
	mut type_params := []string{}
	for tp in stmt.type_params {
		type_params << tp.name
	}

	mut variants := map[string][]Type{}
	for variant in stmt.variants {
		mut payload_types := []Type{}
		for payload in variant.payload {
			if resolved := c.resolve_type_identifier(payload) {
				payload_types << resolved
			}
		}
		variants[variant.identifier.name] = payload_types
	}

	enum_type := TypeEnum{
		name:        stmt.identifier.name
		type_params: type_params
		variants:    variants
	}
	c.env.register_enum(enum_type)
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
	// Run type checking first
	block_expr := if expr is ast.BlockExpression {
		expr
	} else {
		ast.BlockExpression{
			body: [ast.Node(expr)]
			span: span.point_span(0, 0)
		}
	}
	check_result := check(block_expr)

	// If type checking failed, return early with errors
	if !check_result.success {
		return CompileResult{
			program:        Program{
				constants: []
				functions: []
				code:      []
				entry:     0
			}
			diagnostics:    check_result.diagnostics
			success:        false
			env:            check_result.env
			program_type:   check_result.program_type
			type_positions: check_result.type_positions
		}
	}

	// Use the type-checked environment for bytecode compilation
	mut c := Compiler{
		flags:            fl
		env:              check_result.env
		diagnostics:      check_result.diagnostics
		type_positions:   check_result.type_positions
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
		program_type:   check_result.program_type
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
			c.compile_expr(stmt.init, type_hint)!
			c.current_binding = old_binding

			c.emit_arg(.store_local, idx)
		}
		ast.ConstBinding {
			type_hint := if t := stmt.typ { c.resolve_type_identifier(t) } else { none }
			c.compile_expr(stmt.init, type_hint)!
			idx := c.get_or_create_local(stmt.identifier.name)
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
				return c.env.lookup(expr.name) or { t_none() }
			} else {
				return error('Undefined variable: ${expr.name}')
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
			c.compile_expr(expr.right, none)!
			match expr.op.kind {
				.punc_plus {
					c.emit(.add)
					// String concatenation returns String, arithmetic returns the operand type
					if type_def.is_numeric(left_type) {
						return left_type
					}
					return t_string()
				}
				.punc_minus {
					c.emit(.sub)
					return left_type
				}
				.punc_mul {
					c.emit(.mul)
					return left_type
				}
				.punc_div {
					c.emit(.div)
					return left_type
				}
				.punc_mod {
					c.emit(.mod)
					return left_type
				}
				.punc_equals_comparator {
					c.emit(.eq)
					return t_bool()
				}
				.punc_not_equal {
					c.emit(.neq)
					return t_bool()
				}
				.punc_lt {
					c.emit(.lt)
					return t_bool()
				}
				.punc_gt {
					c.emit(.gt)
					return t_bool()
				}
				.punc_lte {
					c.emit(.lte)
					return t_bool()
				}
				.punc_gte {
					c.emit(.gte)
					return t_bool()
				}
				else {
					return error('Unknown binary operator: ${expr.op.kind}')
				}
			}
		}
		ast.UnaryExpression {
			operand_type := c.compile_expr(expr.expression, none)!
			match expr.op.kind {
				.punc_exclamation_mark {
					c.emit(.not)
					return t_bool()
				}
				.punc_minus {
					c.emit(.neg)
					return operand_type
				}
				else {
					return error('Unknown unary operator: ${expr.op.kind}')
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
			mut elem_type := t_none()

			if !has_spread {
				for elem in expr.elements {
					if elem is ast.Expression {
						elem_type = c.compile_expr(elem, none)!
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
						c.emit_arg(.push_const, c.add_constant(h.id))
						c.emit_arg(.push_const, c.add_constant(h.name))
						c.emit_arg(.push_const, c.add_constant(expr.identifier.name))
						if expr.arguments.len > 0 {
							for arg in expr.arguments {
								c.compile_expr(arg, none)!
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

			for i, arg in expr.arguments {
				param_hint := if ft := func_type {
					if i < ft.params.len { ft.params[i] } else { none }
				} else {
					none
				}
				c.compile_expr(arg, param_hint)!
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
				return c.compile_builtin_call(expr)!
			}
		}
		ast.PropertyAccessExpression {
			if expr.left is ast.Identifier {
				left_id := expr.left as ast.Identifier
				if enum_type := c.env.lookup_type(left_id.name) {
					if enum_type is TypeEnum {
						enum_name := left_id.name

						if expr.right is ast.FunctionCallExpression {
							call := expr.right as ast.FunctionCallExpression
							variant_name := call.identifier.name

							if variant_name !in enum_type.variants {
								return error('Unknown variant "${variant_name}" in enum ${enum_name}')
							}

							payload_types := enum_type.variants[variant_name] or { []Type{} }
							if payload_types.len > 0 {
								if call.arguments.len != payload_types.len {
									return error('Variant "${variant_name}" expects ${payload_types.len} payload argument(s)')
								}

								c.emit_arg(.push_const, c.add_constant(enum_type.id))
								enum_idx := c.add_constant(enum_name)
								c.emit_arg(.push_const, enum_idx)
								variant_idx := c.add_constant(variant_name)
								c.emit_arg(.push_const, variant_idx)
								for arg in call.arguments {
									c.compile_expr(arg, none)!
								}
								c.emit_arg(.make_enum_payload, call.arguments.len)
							} else {
								return error('Variant "${variant_name}" does not take a payload')
							}
						} else if expr.right is ast.Identifier {
							variant_id := expr.right as ast.Identifier
							variant_name := variant_id.name

							if variant_name !in enum_type.variants {
								return error('Unknown variant "${variant_name}" in enum ${enum_name}')
							}

							payload_types := enum_type.variants[variant_name] or { []Type{} }
							if payload_types.len > 0 {
								type_strs := payload_types.map(type_to_string)
								return error('Variant "${variant_name}" requires payload(s) of type (${type_strs.join(', ')})')
							}

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

				return error("Cannot call '${call.identifier.name}' as a method. AL does not have methods - use '${call.identifier.name}(...)' as a regular function call instead.")
			} else if expr.right is ast.NumberLiteral {
				num := expr.right as ast.NumberLiteral
				index := num.value.int()
				c.emit_arg(.tuple_index, index)
				// Return tuple element type if available
				if left_type is type_def.TypeTuple {
					if index < left_type.elements.len {
						return left_type.elements[index]
					}
				}
				return t_none()
			} else if expr.right is ast.Identifier {
				id := expr.right as ast.Identifier

				idx := c.add_constant(id.name)
				c.emit_arg(.get_field, idx)
				// Return struct field type if available
				if left_type is TypeStruct {
					if field_type := left_type.fields[id.name] {
						return field_type
					}
				}
				return t_none()
			}
			return t_none()
		}
		ast.StructInitExpression {
			struct_name := expr.identifier.name

			struct_type := c.env.lookup_struct(struct_name) or {
				return error('Unknown struct type: ${struct_name}')
			}

			mut provided := map[string]bool{}
			for field in expr.fields {
				field_name := field.identifier.name
				if field_name !in struct_type.fields {
					return error('Unknown field "${field_name}" in struct ${struct_name}')
				}
				if field_name in provided {
					return error('Duplicate field "${field_name}" in struct ${struct_name}')
				}
				provided[field_name] = true
			}

			for field_name, _ in struct_type.fields {
				if field_name !in provided {
					return error('Missing field "${field_name}" in struct ${struct_name}')
				}
			}

			for field in expr.fields {
				name_idx := c.add_constant(field.identifier.name)
				c.emit_arg(.push_const, name_idx)
				c.compile_expr(field.init, none)!
			}
			c.emit_arg(.push_const, c.add_constant(struct_type.id))
			type_idx := c.add_constant(expr.identifier.name)
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

	for param in params {
		c.get_or_create_local(param.identifier.name)
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

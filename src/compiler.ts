import type { DeclarationStatement, Expression, Statement } from "./ast/nodes";
import { JSGenerator } from "./generator/js";
import { ComptimeInterpreter } from "./interpreter/comptime";
import { Parser } from "./parser/parser";
import { Scanner } from "./scanner/scanner";

export function compile(source: string): string {
  const scanner = new Scanner(source);
  const tokens = scanner.scanAll();

  const parser = new Parser(tokens, source);
  const ast = parser.parseProgram();

  // First pass: collect all comptime functions and evaluate comptime declarations
  const interpreter = new ComptimeInterpreter();
  const transformedAst = evaluateComptime(ast, interpreter);

  const generator = new JSGenerator();
  return generator.generateRoot(transformedAst);
}

function evaluateComptime(
  statements: Statement[],
  interpreter: ComptimeInterpreter
): Statement[] {
  // First pass: register all functions that might be used in comptime
  for (const stmt of statements) {
    if (stmt.type === "FunctionStatement") {
      interpreter.registerFunction(stmt);
    }
  }

  // Second pass: evaluate comptime declarations and transform the AST
  return statements.map((stmt) => {
    if (stmt.type === "DeclarationStatement" && stmt.isComptime) {
      // Evaluate the comptime expression
      const value = interpreter.evaluate(stmt.init);

      // Transform the declaration to use the computed value
      const transformedInit: Expression = (() => {
        if (typeof value === "number") {
          return { type: "NumberLiteral", value: value.toString() };
        } else if (typeof value === "string") {
          return { type: "StringLiteral", value };
        } else if (typeof value === "boolean") {
          return { type: "BooleanLiteral", value };
        } else if (value === null) {
          return { type: "NoneExpression" };
        } else {
          // Fallback for other types - convert to string
          return { type: "StringLiteral", value: String(value) };
        }
      })();

      return {
        type: "DeclarationStatement",
        identifier: stmt.identifier,
        init: transformedInit,
        isComptime: false, // No longer needs comptime evaluation
      } as DeclarationStatement;
    }
    return stmt;
  });
}

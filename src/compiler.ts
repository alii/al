import {
  buildFunctionCallMap,
  findReachableFunctions,
} from "./analysis/reachability";
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

  // Build call graph & find reachable functions
  const { functionMap, callGraph } = buildFunctionCallMap(transformedAst);

  // Consider both "main" and any functions used in comptime declarations as entry points
  const entryPoints = ["main"];

  // Add any functions referenced in comptime declarations
  for (const stmt of transformedAst) {
    if (stmt.type === "DeclarationStatement" && stmt.isComptime) {
      // If this is a comptime declaration, its init expression might call functions
      // that need to be included in the output
      const initFunctionCalls = new Set<string>();
      walkExpressionForCalls(stmt.init, (name) => initFunctionCalls.add(name));
      entryPoints.push(...initFunctionCalls);
    }
  }

  const reachableFunctions = findReachableFunctions(callGraph, entryPoints);

  // Filter out any function statements not in reachableFunctions
  const prunedAst = transformedAst.filter((stmt) => {
    if (stmt.type === "FunctionStatement") {
      return reachableFunctions.has(stmt.identifier.name);
    }
    // Keep everything else
    return true;
  });

  const generator = new JSGenerator();
  return generator.generateRoot(prunedAst);
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

  // Second pass: recursively evaluate comptime declarations
  return statements.map((stmt) => transformStatement(stmt, interpreter));
}

function transformStatement(
  stmt: Statement,
  interpreter: ComptimeInterpreter
): Statement {
  switch (stmt.type) {
    case "FunctionStatement":
      return {
        ...stmt,
        body: stmt.body.map((s) => transformStatement(s, interpreter)),
      };
    case "DeclarationStatement":
      if (stmt.isComptime) {
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
    case "IfStatement":
      return {
        ...stmt,
        then: stmt.then.map((s) => transformStatement(s, interpreter)),
        else: stmt.else?.map((s) => transformStatement(s, interpreter)),
      };
    case "ForStatement":
      return {
        ...stmt,
        body: stmt.body.map((s) => transformStatement(s, interpreter)),
      };
    case "ForInStatement":
      return {
        ...stmt,
        body: stmt.body.map((s) => transformStatement(s, interpreter)),
      };
    default:
      return stmt;
  }
}

// Helper to collect function calls from an expression
function walkExpressionForCalls(
  expr: Expression,
  onCall: (name: string) => void
) {
  switch (expr.type) {
    case "FunctionCall":
      if (expr.callee.type === "Identifier") {
        onCall(expr.callee.name);
      }
      // Also check arguments
      for (const arg of expr.arguments) {
        walkExpressionForCalls(arg, onCall);
      }
      break;
    case "BinaryExpression":
      walkExpressionForCalls(expr.left, onCall);
      walkExpressionForCalls(expr.right, onCall);
      break;
    case "UnaryExpression":
      walkExpressionForCalls(expr.expression, onCall);
      break;
    // Add other cases as needed
  }
}

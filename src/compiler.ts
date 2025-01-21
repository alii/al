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

  const interpreter = new ComptimeInterpreter();
  const transformedAst = evaluateComptime(ast, interpreter);

  const callGraph = buildFunctionCallMap(transformedAst);

  const runtimeEntryPoints = new Set<string>();

  for (const stmt of transformedAst) {
    if (stmt.type === "ExpressionStatement") {
      walkExpressionForCalls(stmt.expression, (name) =>
        runtimeEntryPoints.add(name)
      );
    } else if (stmt.type === "FunctionStatement") {
      const hasComptimeDeclarations = stmt.body.some(
        (s) => s.type === "DeclarationStatement" && s.isComptime
      );
      if (hasComptimeDeclarations) {
        runtimeEntryPoints.add(stmt.identifier.name);
      }
    }
  }

  const reachableFunctions = findReachableFunctions(
    callGraph,
    Array.from(runtimeEntryPoints)
  );

  const prunedAst = transformedAst.filter((stmt) => {
    if (stmt.type === "FunctionStatement") {
      return reachableFunctions.has(stmt.identifier.name);
    }
    return true;
  });

  const generator = new JSGenerator();
  return generator.generateRoot(prunedAst);
}

function evaluateComptime(
  statements: Statement[],
  interpreter: ComptimeInterpreter
): Statement[] {
  for (const stmt of statements) {
    if (stmt.type === "FunctionStatement") {
      interpreter.registerFunction(stmt);
    }
  }

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
        const value = interpreter.evaluate(stmt.init);

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
            return { type: "StringLiteral", value: String(value) };
          }
        })();

        return {
          type: "DeclarationStatement",
          identifier: stmt.identifier,
          init: transformedInit,
          isComptime: false,
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

function walkExpressionForCalls(
  expr: Expression,
  onCall: (name: string) => void
) {
  switch (expr.type) {
    case "FunctionCall":
      if (expr.callee.type === "Identifier") {
        onCall(expr.callee.name);
      }
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
    case "PropertyAccess":
      walkExpressionForCalls(expr.left, onCall);
      break;
    case "ArrayExpression":
      for (const element of expr.elements) {
        walkExpressionForCalls(element, onCall);
      }
      break;
    case "ArrayIndexExpression":
      walkExpressionForCalls(expr.array, onCall);
      walkExpressionForCalls(expr.index, onCall);
      break;
    case "StructInitialization":
      for (const field of expr.fields) {
        walkExpressionForCalls(field.init, onCall);
      }
      break;
  }
}

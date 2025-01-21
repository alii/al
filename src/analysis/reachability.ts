import type { Expression, FunctionStatement, Statement } from "../ast/nodes";

/**
 * This function scans through an array of statements (the entire AST)
 * to build a map of functionName -> the FunctionStatement node,
 * plus a map of functionName -> a Set of function names it calls.
 */
export function buildFunctionCallMap(statements: Statement[]): {
  functionMap: Map<string, FunctionStatement>;
  callGraph: Map<string, Set<string>>;
} {
  const functionMap = new Map<string, FunctionStatement>();
  const callGraph = new Map<string, Set<string>>();

  // 1) Collect all functions
  for (const stmt of statements) {
    if (stmt.type === "FunctionStatement") {
      functionMap.set(stmt.identifier.name, stmt);
      callGraph.set(stmt.identifier.name, new Set());
    }
  }

  // 2) For each function, walk its body to find all calls
  for (const stmt of statements) {
    if (stmt.type === "FunctionStatement") {
      const callerName = stmt.identifier.name;
      const setOfCalls = callGraph.get(callerName) || new Set();
      walkStatementsForCalls(stmt.body, (calledFnName) => {
        setOfCalls.add(calledFnName);
      });
      callGraph.set(callerName, setOfCalls);
    }
  }

  return { functionMap, callGraph };
}

/**
 * Helper that traverses statements looking for FunctionCall expressions.
 * Whenever we see a call, we invoke onCall(calledFunctionName).
 */
function walkStatementsForCalls(
  statements: Statement[],
  onCall: (fnName: string) => void
) {
  for (const stmt of statements) {
    switch (stmt.type) {
      case "FunctionStatement":
        // Recurse deeper (handle nested function definitions, if any)
        walkStatementsForCalls(stmt.body, onCall);
        break;
      case "IfStatement":
        walkStatementsForCalls(stmt.then, onCall);
        if (stmt.else) {
          walkStatementsForCalls(stmt.else, onCall);
        }
        break;
      case "ForStatement":
      case "ForInStatement":
        walkStatementsForCalls(stmt.body, onCall);
        break;
      case "DeclarationStatement":
        // Potentially walk the init expression
        walkExpressionForCalls(stmt.init, onCall);
        break;
      case "ExpressionStatement":
        walkExpressionForCalls(stmt.expression, onCall);
        break;
      // ... Handle other statement types that can contain sub-expressions ...
      default:
        break;
    }
  }
}

/**
 * Recursively walk expressions to detect function calls.
 */
function walkExpressionForCalls(
  expr: Expression,
  onCall: (fnName: string) => void
) {
  switch (expr.type) {
    case "FunctionCall":
      // If the callee is an Identifier, we have a direct function call
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
    case "StructInitialization":
      // Each field init can contain expressions
      for (const field of expr.fields) {
        walkExpressionForCalls(field.init, onCall);
      }
      break;
    case "ArrayExpression":
      for (const e of expr.elements) {
        walkExpressionForCalls(e, onCall);
      }
      break;
    case "ArrayIndexExpression":
      walkExpressionForCalls(expr.array, onCall);
      walkExpressionForCalls(expr.index, onCall);
      break;
    case "RangeExpression":
      walkExpressionForCalls(expr.start, onCall);
      walkExpressionForCalls(expr.end, onCall);
      break;
    case "PropertyAccess":
      // property access might have a left expression
      walkExpressionForCalls(expr.left, onCall);
      break;
    case "OrExpression":
      // The "or" expression might have a handler body or fallback
      // This can be complicated if it's a function call, but let's omit details for brevity
      break;
    // ... handle other expression types as needed ...
    default:
      // StringLiteral, NumberLiteral, BooleanLiteral, Identifier, NoneExpression, etc.
      break;
  }
}

/**
 * Finds all reachable function names from a given set of entry points.
 */
export function findReachableFunctions(
  callGraph: Map<string, Set<string>>,
  entryPoints: string[]
): Set<string> {
  const visited = new Set<string>();
  const stack = [...entryPoints];

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (!visited.has(current)) {
      visited.add(current);
      const neighbors = callGraph.get(current);
      if (neighbors) {
        for (const callee of neighbors) {
          stack.push(callee);
        }
      }
    }
  }

  return visited;
}

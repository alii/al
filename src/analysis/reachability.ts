import type { Expression, Statement } from "../ast/nodes";

/**
 * This function scans through an array of statements (the entire AST)
 * and returns a map of functionName -> a Set of function names it calls.
 */
export function buildFunctionCallMap(
  statements: Statement[]
): Map<string, Set<string>> {
  const callGraph = new Map<string, Set<string>>();

  // 1) Collect all functions
  for (const stmt of statements) {
    if (stmt.type === "FunctionStatement") {
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

  return callGraph;
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
        // Check condition expression
        walkExpressionForCalls(stmt.condition, onCall);
        // Check both branches
        walkStatementsForCalls(stmt.then, onCall);
        if (stmt.else) {
          walkStatementsForCalls(stmt.else, onCall);
        }
        break;
      case "ForStatement":
        walkStatementsForCalls(stmt.body, onCall);
        break;
      case "ForInStatement":
        // Check the iterator expression
        walkExpressionForCalls(stmt.iterator, onCall);
        walkStatementsForCalls(stmt.body, onCall);
        break;
      case "DeclarationStatement":
        walkExpressionForCalls(stmt.init, onCall);
        break;
      case "ExpressionStatement":
        walkExpressionForCalls(stmt.expression, onCall);
        break;
      case "ReturnStatement":
        if (stmt.expression) {
          walkExpressionForCalls(stmt.expression, onCall);
        }
        break;
      case "ThrowStatement":
        walkExpressionForCalls(stmt.expression, onCall);
        break;
      case "AssertStatement":
        walkExpressionForCalls(stmt.expression, onCall);
        walkExpressionForCalls(stmt.message, onCall);
        break;
      case "ExportStatement":
        walkStatementsForCalls([stmt.declaration], onCall);
        break;
      case "ConstStatement":
        walkExpressionForCalls(stmt.init, onCall);
        break;
      case "StructDeclaration":
        // Check field initializers if any
        for (const field of stmt.fields) {
          if (field.init) {
            walkExpressionForCalls(field.init, onCall);
          }
        }
        break;
      case "BreakStatement":
      case "ContinueStatement":
        // These don't contain any expressions to check
        break;
      case "EnumDeclaration":
        // No expressions to check in enum declarations
        break;
      default:
        // If it's an expression used as a statement, check it
        if ((stmt as Expression).type) {
          walkExpressionForCalls(stmt as Expression, onCall);
        } else {
          console.warn(
            `Unhandled statement type in walkStatementsForCalls: ${
              (stmt as any).type
            }`
          );
        }
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
      // Direct function calls with identifier
      if (expr.callee.type === "Identifier") {
        onCall(expr.callee.name);
      } else {
        // Handle complex callee expressions (e.g., property access)
        walkExpressionForCalls(expr.callee, onCall);
      }
      // Check all arguments
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
      // Check field initializers
      for (const field of expr.fields) {
        walkExpressionForCalls(field.init, onCall);
      }
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
    case "RangeExpression":
      walkExpressionForCalls(expr.start, onCall);
      walkExpressionForCalls(expr.end, onCall);
      break;
    case "PropertyAccess":
      walkExpressionForCalls(expr.left, onCall);
      // The right side is always an identifier, no need to walk
      break;
    case "OrExpression":
      walkExpressionForCalls(expr.expression, onCall);
      // Walk the handler statements
      walkStatementsForCalls(expr.handler, onCall);
      break;
    case "OrExpressionFallback":
      walkExpressionForCalls(expr.expression, onCall);
      walkExpressionForCalls(expr.fallback, onCall);
      break;
    case "MatchExpression":
      walkExpressionForCalls(expr.expression, onCall);
      // Check all case bodies
      for (const matchCase of expr.cases) {
        walkExpressionForCalls(matchCase.body, onCall);
      }
      break;
    case "TypeIdentifier":
      // No function calls in type identifiers
      break;
    case "StringLiteral":
    case "NumberLiteral":
    case "BooleanLiteral":
    case "NoneExpression":
    case "Identifier":
      // These are leaf nodes with no function calls
      break;
    default:
      console.warn(
        `Unhandled expression type in walkExpressionForCalls: ${
          (expr as any).type
        }`
      );
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

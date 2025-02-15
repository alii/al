import type {
  BinaryExpression,
  Expression,
  FunctionCall,
  FunctionStatement,
  Identifier,
  MatchExpression,
  Statement,
  UnaryExpression,
} from "../ast/nodes";

/**
 * Context for comptime evaluation, storing variables and functions
 */
export interface ComptimeContext {
  variables: Map<string, any>;
  functions: Map<string, FunctionStatement>;
}

/**
 * Main class for evaluating comptime expressions
 */
export class ComptimeInterpreter {
  private context: ComptimeContext;

  constructor() {
    this.context = {
      variables: new Map(),
      functions: new Map(),
    };
  }

  /**
   * Evaluate a comptime expression in the current context
   */
  public evaluate(expr: Expression): any {
    switch (expr.type) {
      case "NumberLiteral":
        return Number(expr.value);
      case "StringLiteral":
        return expr.value;
      case "BooleanLiteral":
        return expr.value;
      case "NoneExpression":
        return null;
      case "Identifier":
        return this.evaluateIdentifier(expr);
      case "BinaryExpression":
        return this.evaluateBinaryExpression(expr);
      case "UnaryExpression":
        return this.evaluateUnaryExpression(expr);
      case "FunctionCall":
        return this.evaluateFunctionCall(expr);
      case "MatchExpression":
        return this.evaluateMatchExpression(expr);
      default:
        throw new Error(`Unsupported comptime expression type: ${expr.type}`);
    }
  }

  /**
   * Register a function in the context
   */
  public registerFunction(func: FunctionStatement): void {
    this.context.functions.set(func.identifier.name, func);
  }

  /**
   * Register a variable in the context
   */
  public registerVariable(name: string, value: any): void {
    this.context.variables.set(name, value);
  }

  private evaluateMatchExpression(expr: MatchExpression): any {
    /*
      match value {
        MyEnum.COOL => "cool",
        MyEnum.NOT_COOL => "not cool",
      }
    */

    throw new Error("evaluateMatchExpression() not implemented");

    // // `value` is the value of the variable we're matching on
    // const value = this.evaluate(expr.expression);

    // for (const c of expr.cases) {
    //   const pattern = c.pattern;

    //   return pattern.enum.type;
    // }
  }
  /**
   * Evaluate a binary expression
   */
  private evaluateBinaryExpression(expr: BinaryExpression): any {
    const left = this.evaluate(expr.left);
    const right = this.evaluate(expr.right);

    switch (expr.operator) {
      case "+":
        return left + right;
      case "-":
        return left - right;
      case "*":
        return left * right;
      case "/":
        return left / right;
      case "%":
        return left % right;
      case "===":
        return left === right;
      case "!==":
        return left !== right;
      case ">":
        return left > right;
      case ">=":
        return left >= right;
      case "<":
        return left < right;
      case "<=":
        return left <= right;
      case "&&":
        return left && right;
      case "||":
        return left || right;
      default:
        throw new Error(`Unsupported binary operator: ${expr.operator}`);
    }
  }

  /**
   * Evaluate a unary expression
   */
  private evaluateUnaryExpression(expr: UnaryExpression): any {
    const value = this.evaluate(expr.expression);

    switch (expr.operator) {
      case "!":
        return !value;
      case "-":
        return -value;
      default:
        throw new Error(`Unsupported unary operator: ${expr.operator}`);
    }
  }

  /**
   * Evaluate an identifier (variable lookup)
   */
  private evaluateIdentifier(expr: Identifier): any {
    const value = this.context.variables.get(expr.name);
    if (value === undefined) {
      throw new Error(`Undefined comptime variable: ${expr.name}`);
    }
    return value;
  }

  /**
   * Execute a block of statements and return the result of any return statement
   */
  private executeStatements(statements: Statement[]): {
    returned: boolean;
    value: any;
  } {
    for (const stmt of statements) {
      if (stmt.type === "ReturnStatement") {
        return {
          returned: true,
          value: stmt.expression ? this.evaluate(stmt.expression) : undefined,
        };
      } else if (stmt.type === "DeclarationStatement") {
        const value = this.evaluate(stmt.init);
        this.context.variables.set(stmt.identifier.name, value);
      } else if (stmt.type === "IfStatement") {
        const condition = this.evaluate(stmt.condition);
        if (condition) {
          const result = this.executeStatements(stmt.then);
          if (result.returned) {
            return result;
          }
        } else if (stmt.else) {
          const result = this.executeStatements(stmt.else);
          if (result.returned) {
            return result;
          }
        }
      }
      // Add support for other statement types as needed
    }
    return { returned: false, value: undefined };
  }

  /**
   * Evaluate a function call
   */
  private evaluateFunctionCall(expr: FunctionCall): any {
    if (expr.callee.type !== "Identifier") {
      throw new Error("Only direct function calls are supported in comptime");
    }

    const func = this.context.functions.get(expr.callee.name);
    if (!func) {
      throw new Error(`Undefined comptime function: ${expr.callee.name}`);
    }

    // Create a new scope for function variables
    const previousContext = { ...this.context };
    this.context.variables = new Map(this.context.variables);

    // Evaluate arguments and bind to parameters
    const args = expr.arguments.map((arg) => this.evaluate(arg));
    func.params.forEach((param, index) => {
      this.context.variables.set(param.identifier.name, args[index]);
    });

    // Execute function body
    const result = this.executeStatements(func.body);

    // Restore previous context
    this.context = previousContext;

    return result.value;
  }
}

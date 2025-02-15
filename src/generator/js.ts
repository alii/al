import type {
  ArrayExpression,
  ArrayIndexExpression,
  AssertStatement,
  BinaryExpression,
  BooleanLiteral,
  BreakStatement,
  ConstStatement,
  ContinueStatement,
  DeclarationStatement,
  EnumDeclaration,
  ExportStatement,
  Expression,
  ForInStatement,
  ForStatement,
  FunctionCall,
  FunctionStatement,
  Identifier,
  IfStatement,
  ImportDeclaration,
  MatchExpression,
  NoneExpression,
  NumberLiteral,
  OrExpression,
  PropertyAccess,
  RangeExpression,
  ReturnStatement,
  Statement,
  StringLiteral,
  StructDeclaration,
  StructInitialization,
  ThrowStatement,
  TypeIdentifier,
  UnaryExpression,
} from "../ast/nodes";
import { js } from "./util";

export class JSGenerator {
  generateRoot(statements: Statement[]): string {
    return js`
      const println = console.log;
      ${this.generateStatements(statements)}
    `;
  }

  private generateStatements(statements: Statement[]): string {
    return statements.map((stmt) => this.generateStatement(stmt)).join("\n");
  }

  private generateStatement(statement: Statement): string {
    switch (statement.type) {
      case "FunctionStatement":
        return this.generateFunctionStatement(statement);
      case "ReturnStatement":
        return this.generateReturnStatement(statement);
      case "ConstStatement":
        return this.generateConstStatement(statement);
      case "StructDeclaration":
        return this.generateStructDeclaration(statement);
      case "ImportDeclaration":
        return this.generateImportDeclaration(statement);
      case "ExportStatement":
        return this.generateExportStatement(statement);
      case "IfStatement":
        return this.generateIfStatement(statement);
      case "ForStatement":
        return this.generateForStatement(statement);
      case "ForInStatement":
        return this.generateForInStatement(statement);
      case "ThrowStatement":
        return this.generateThrowStatement(statement);
      case "AssertStatement":
        return this.generateAssertStatement(statement);
      case "DeclarationStatement":
        return this.generateDeclarationStatement(statement);
      case "BreakStatement":
        return this.generateBreakStatement(statement);
      case "ContinueStatement":
        return this.generateContinueStatement(statement);
      case "EnumDeclaration":
        return this.generateEnumDeclaration(statement);
      case "ExpressionStatement":
        return this.generateExpression(statement.expression) + ";";
      default:
        throw new Error("Unsupported statement type: " + statement.type);
    }
  }

  private generateFunctionStatement(statement: FunctionStatement): string {
    const { identifier, params, body } = statement;

    const functionBody = this.generateStatements(body);

    const paramsString = params.map((p) => p.identifier.name).join(", ");

    return js`
      function ${identifier.name}(${paramsString}) {
        ${functionBody}
      }
    `;
  }

  private generateReturnStatement(statement: ReturnStatement): string {
    const { expression } = statement;
    return `return${
      expression ? " " + this.generateExpression(expression) : ""
    };`;
  }

  private generateConstStatement(statement: ConstStatement): string {
    const { identifier, init } = statement;
    return `const ${identifier.name} = ${this.generateExpression(init)};`;
  }

  private generateStructDeclaration(statement: StructDeclaration): string {
    const { identifier, fields } = statement;

    const fieldInits = fields
      .map((field) => {
        const defaultValue = field.init
          ? ` = ${this.generateExpression(field.init)}`
          : "";
        return `${field.identifier.name}${defaultValue}`;
      })
      .join("\n");

    return js`
      class ${identifier.name} {
        ${fieldInits}

        constructor(init) {
          ${fields
            .map((f) => `this.${f.identifier.name} = init.${f.identifier.name}`)
            .join(";\n")};
        }
      }
    `;
  }

  private generateImportDeclaration(statement: ImportDeclaration): string {
    const { specifiers, path } = statement;
    return `import { ${specifiers
      .map((s) => s.identifier.name)
      .join(", ")} } from '${path}';`;
  }

  private generateExportStatement(statement: ExportStatement): string {
    return `export ${this.generateStatement(statement.declaration)}`;
  }

  private generateIfStatement(statement: IfStatement): string {
    const { condition, then, else: elseBody } = statement;
    let code = `if (${this.generateExpression(condition)}) {\n`;
    code += this.generateStatements(then) + "\n}";

    if (elseBody) {
      code += " else {\n";
      code += this.generateStatements(elseBody) + "\n}";
    }

    return code;
  }

  private generateForStatement(statement: ForStatement): string {
    return `for (;;) {\n${this.generateStatements(statement.body)}\n}`;
  }

  private generateForInStatement(statement: ForInStatement): string {
    const { identifier, iterator, body } = statement;
    return `for (const ${identifier.name} of ${this.generateExpression(
      iterator
    )}) {
${this.generateStatements(body)}
}`;
  }

  private generateThrowStatement(statement: ThrowStatement): string {
    return `throw ${this.generateExpression(statement.expression)};`;
  }

  private generateAssertStatement(statement: AssertStatement): string {
    const { expression, message } = statement;

    return js`
      if (!${this.generateExpression(expression)}) {
        throw new Error(${this.generateExpression(message)});
      }
    `;
  }

  private generateDeclarationStatement(
    statement: DeclarationStatement
  ): string {
    const { identifier, init } = statement;
    return `let ${identifier.name} = ${this.generateExpression(init)};`;
  }

  private generateBreakStatement(_: BreakStatement): string {
    return "break;";
  }

  private generateContinueStatement(_: ContinueStatement): string {
    return "continue;";
  }

  private generateEnumDeclaration(statement: EnumDeclaration): string {
    const { identifier, variants } = statement;
    const enumName = identifier.name;

    const variantDefs = variants
      .map((variant) => {
        const variantName = variant.name.name;

        if (variant.payload) {
          return js`
            static ${variantName}_class = class {
              constructor(value) {
                this.value = value;
              }
            };

            static ${variantName}(value) {
              return new ${enumName}.${variantName}_class(value);
            }
          `;
        } else {
          return js`
            static ${variantName}_class = class ${variantName} {};
            static ${variantName} = new ${enumName}.${variantName}_class();
          `;
        }
      })
      .join("\n");

    return js`
      class ${enumName} {
        ${variantDefs}
      }
    `;
  }

  private generateExpression(expression: Expression): string {
    switch (expression.type) {
      case "StringLiteral":
        return this.generateStringLiteral(expression);
      case "NumberLiteral":
        return this.generateNumberLiteral(expression);
      case "BooleanLiteral":
        return this.generateBooleanLiteral(expression);
      case "NoneExpression":
        return this.generateNoneExpression(expression);
      case "Identifier":
        return this.generateIdentifier(expression);
      case "BinaryExpression":
        return this.generateBinaryExpression(expression);
      case "UnaryExpression":
        return this.generateUnaryExpression(expression);
      case "FunctionCall":
        return this.generateFunctionCall(expression);
      case "PropertyAccess":
        return this.generatePropertyAccess(expression);
      case "StructInitialization":
        return this.generateStructInitialization(expression);
      case "ArrayExpression":
        return this.generateArrayExpression(expression);
      case "ArrayIndexExpression":
        return this.generateArrayIndexExpression(expression);
      case "RangeExpression":
        return this.generateRangeExpression(expression);
      case "TypeIdentifier":
        return this.generateTypeIdentifier(expression);
      case "MatchExpression":
        return this.generateMatchExpression(expression);
      case "OrExpression":
        return this.generateOrExpression(expression);
      default:
        throw new Error("Unsupported expression type: " + expression.type);
    }
  }

  private generateStringLiteral(literal: StringLiteral): string {
    return `'${literal.value.replace(/'/g, "\\'")}'`;
  }

  private generateNumberLiteral(literal: NumberLiteral): string {
    return literal.value;
  }

  private generateBooleanLiteral(literal: BooleanLiteral): string {
    return literal.value.toString();
  }

  private generateNoneExpression(_: NoneExpression): string {
    return "null";
  }

  private generateIdentifier(identifier: Identifier): string {
    return identifier.name;
  }

  private generateBinaryExpression(expression: BinaryExpression): string {
    return `(${this.generateExpression(expression.left)} ${
      expression.operator
    } ${this.generateExpression(expression.right)})`;
  }

  private generateUnaryExpression(expression: UnaryExpression): string {
    return `${expression.operator}${this.generateExpression(
      expression.expression
    )}`;
  }

  private generateFunctionCall(expression: FunctionCall): string {
    return `${this.generateExpression(expression.callee)}(${expression.arguments
      .map((arg) => this.generateExpression(arg))
      .join(", ")})`;
  }

  private generatePropertyAccess(expression: PropertyAccess): string {
    return `${this.generateExpression(
      expression.left
    )}.${this.generateIdentifier(expression.right)}`;
  }

  private generateStructInitialization(
    expression: StructInitialization
  ): string {
    const fields = expression.fields
      .map(
        (field) =>
          `${field.identifier.name}: ${this.generateExpression(field.init)}`
      )
      .join(",\n");

    return `new ${expression.identifier.name}({\n${fields}\n})`;
  }

  private generateArrayExpression(expression: ArrayExpression): string {
    return `[${expression.elements
      .map((e) => this.generateExpression(e))
      .join(", ")}]`;
  }

  private generateArrayIndexExpression(
    expression: ArrayIndexExpression
  ): string {
    return `${this.generateExpression(
      expression.array
    )}[${this.generateExpression(expression.index)}]`;
  }

  private generateRangeExpression(expression: RangeExpression): string {
    return `Array.from({length: ${this.generateExpression(
      expression.end
    )} - ${this.generateExpression(
      expression.start
    )}}, (_, i) => ${this.generateExpression(expression.start)} + i)`;
  }

  private generateTypeIdentifier(identifier: TypeIdentifier): string {
    let type = this.generateExpression(identifier.identifier);

    if (identifier.isArray) {
      type = `Array<${type}>`;
    }
    if (identifier.isOption) {
      type = `${type} | null`;
    }
    return type;
  }

  // static {
  //   const lol = new JSGenerator().generateExpression({
  //     type: "PropertyAccess",
  //     left: {
  //       type: "PropertyAccess",
  //       left: {
  //         type: "FunctionCall",
  //         callee: {
  //           type: "Identifier",
  //           name: "lego",
  //         },
  //         arguments: [
  //           {
  //             type: "MatchExpression",
  //             expression: {
  //               type: "Identifier",
  //               name: "x",
  //             },
  //             cases: [
  //               {
  //                 type: "MatchCase",
  //                 pattern: {
  //                   type: "MatchPattern",
  //                   enum: {
  //                     type: "Identifier",
  //                     name: "Wow",
  //                   },
  //                   variant: {
  //                     type: "Identifier",
  //                     name: "A",
  //                   },
  //                 },
  //                 body: {
  //                   type: "Identifier",
  //                   name: "x",
  //                 },
  //               },
  //             ],
  //           },
  //         ],
  //       },
  //       right: {
  //         type: "Identifier",
  //         name: "A",
  //       },
  //     },
  //     right: {
  //       type: "Identifier",
  //       name: "G",
  //     },
  //   });

  //   throw lol;
  // }

  private generateMatchExpression(expression: MatchExpression): string {
    const { expression: matchExpr, cases } = expression;
    const valueRef = this.generateExpression(matchExpr);

    const caseClauses = cases
      .map(({ pattern, body }) => {
        const fullPath = this.generatePropertyAccess({
          type: "PropertyAccess",
          left: pattern.enum,
          right: pattern.variant,
        });

        const className = `${fullPath}_class`;

        if (pattern.binding) {
          // Variant has a payload => use instanceof check,
          // then pull out the value from the variant's "this.value".
          const binding = `const ${pattern.binding.name} = ${valueRef}.value;`;

          return js`
            if (${valueRef} instanceof ${className}) {
              ${binding}
              return ${this.generateExpression(body)};
            }
          `;
        } else {
          // No payload => typically a single static instance => use direct equality
          return js`
            if (${valueRef} === ${fullPath}) {
              return ${this.generateExpression(body)};
            }
          `;
        }
      })
      .join(" else ");

    return js`
      (() => {
        ${caseClauses}
        throw new Error("No match case found");
      })()
    `;
  }

  private generateOrExpression(expression: OrExpression): string {
    const { expression: tryExpr, errorBinding, handler } = expression;
    const tryValue = this.generateExpression(tryExpr);
    const handlerBody = this.generateStatements(handler);

    if (errorBinding) {
      return js`
        (() => {
          try {
            return ${tryValue};
          } catch (${errorBinding.name}) {
            ${handlerBody}
          }
        })()
      `;
    } else {
      return js`
        (() => {
          try {
            return ${tryValue};
          } catch (e) {
            ${handlerBody}
          }
        })()
      `;
    }
  }
}

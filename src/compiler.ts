import { JSGenerator } from "./generator/js";
import { Parser } from "./parser/parser";
import { Scanner } from "./scanner/scanner";

export function compile(source: string): string {
  const scanner = new Scanner(source);
  const tokens = scanner.scanAll();

  const parser = new Parser(tokens, source);
  const ast = parser.parseProgram();

  const generator = new JSGenerator();
  return generator.generateRoot(ast);
}

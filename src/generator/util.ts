type TemplateValue = string | number | boolean;

function findBaseIndent(strings: TemplateStringsArray): number {
  let minIndent = Infinity;

  for (const str of strings) {
    const lines = str.split("\n");
    for (const line of lines) {
      if (line.trim().length === 0) continue;
      const indent = line.match(/^\s*/)?.[0].length ?? 0;
      minIndent = Math.min(minIndent, indent);
    }
  }

  return minIndent === Infinity ? 0 : minIndent;
}

function indentString(str: string, indentLevel: number): string {
  const indent = " ".repeat(indentLevel);
  return str
    .split("\n")
    .map((line) => (line.trim().length > 0 ? indent + line : line))
    .join("\n");
}

export function js(
  strings: TemplateStringsArray,
  ...values: TemplateValue[]
): string {
  const baseIndent = findBaseIndent(strings);
  let result = "";
  const lastIndex = strings.length - 1;

  for (let i = 0; i < strings.length; i++) {
    // Process the template string part
    const str = strings[i];
    const lines = str
      .split("\n")
      .map((line) => {
        if (line.trim().length === 0) return line;
        return line.slice(baseIndent);
      })
      .join("\n");

    result += lines;

    // Process interpolated value if it exists
    if (i < lastIndex) {
      const value = values[i];
      if (typeof value === "string" && value.includes("\n")) {
        // For multiline strings, maintain the indentation level
        const currentIndent =
          str.split("\n").pop()?.match(/^\s*/)?.[0].length ?? 0;
        result += indentString(value.toString(), currentIndent);
      } else {
        result += value;
      }
    }
  }

  // Remove leading/trailing whitespace while preserving internal formatting
  return result.trim();
}

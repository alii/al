<img width="96" src="images/icon.png" />

# Scarlet for Visual Studio Code

Editor support for the [Scarlet programming language](https://scarlet.industries).

## Features

- Syntax highlighting for `.scrl` files
- Diagnostics, completions, and other language features via the Scarlet language server (`scarlet lsp`)
- Document formatting via `scarlet fmt --stdin`

## Requirements

The `scarlet` binary must be installed and on your `PATH`. If it lives elsewhere, point the extension at it with the `scarlet.binaryPath` setting:

```json
{
  "scarlet.binaryPath": "/path/to/scarlet"
}
```

## Development

Use [Bun](https://bun.sh) for package management and scripts:

```sh
bun install
bun run build      # typecheck and bundle to out/extension.js
bun run package    # produce a .vsix
```

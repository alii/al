<img width="96" src="logo.png" />

# Scarlet for Zed

Editor support for the [Scarlet programming language](https://scarlet.industries).

## Features

- Registers the Scarlet language for `.scrl` files (comments, brackets, tab indentation)
- Diagnostics, completions, and formatting via the Scarlet language server (`scarlet lsp`)

Syntax highlighting requires a tree-sitter grammar, which Scarlet does not have yet; language server features work without one.

## Requirements

The `scarlet` binary must be installed and on your `PATH`. If it lives elsewhere, point Zed at it in your `settings.json`:

```json
{
  "lsp": {
    "scarlet": {
      "binary": {
        "path": "/path/to/scarlet"
      }
    }
  }
}
```

## Development

Install as a dev extension: in Zed, run `zed: install dev extension` and select this directory (`editors/zed`). Zed compiles the extension to WebAssembly itself; a Rust toolchain with the `wasm32-wasip2` target is required.

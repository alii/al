//! Scarlet's embedding of the language-agnostic VM (`scarlet_vm::vm`). The stdlib
//! constructor bindings ride inside the compiled `Program`
//! (`templates`/`abi`, bound by `scarlet_core`'s `bind_abi`), so nothing here
//! supplements them.

pub use scarlet_vm::vm::*;

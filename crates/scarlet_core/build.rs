//! `module/stdlib.rs` embeds `src/std/**` with `include_dir!`, which does not
//! register the files it embeds as build inputs: without this script, adding
//! a stdlib module (or editing one without touching any Rust) leaves the
//! stale tree embedded in the library, and everything downstream — the
//! driver's precompile included — keeps compiling against it. One
//! `rerun-if-changed` per file and directory is what makes the embedded tree
//! track the one on disk.

use std::path::PathBuf;

fn main() {
    let mut stack = vec![PathBuf::from("src/std")];
    while let Some(dir) = stack.pop() {
        println!("cargo:rerun-if-changed={}", dir.display());
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("build.rs: read_dir {dir:?}: {e}"));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("build.rs: walk {dir:?}: {e}"))
                .path();
            if path.is_dir() {
                stack.push(path);
            } else {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

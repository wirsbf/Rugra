fn main() {
    if cfg!(feature = "ffi-test") {
        // Automatically find the Ghidra cpp directory relative to this crate
        let current_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let path = std::path::Path::new(&current_dir)
            .parent()
            .unwrap()
            .join("ghidra")
            .join("Ghidra")
            .join("Features")
            .join("Decompiler")
            .join("src")
            .join("decompile")
            .join("cpp");

        println!("cargo:rustc-link-search=native={}", path.display());
        // Link against the rugra DLL compiled in that folder
        println!("cargo:rustc-link-lib=dylib=rugra");
    }
}

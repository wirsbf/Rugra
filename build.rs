use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(has_sleigh)");

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let cpp_dir = manifest
        .join("ghidra")
        .join("Ghidra")
        .join("Features")
        .join("Decompiler")
        .join("src")
        .join("decompile")
        .join("cpp");
    let shim_dir = manifest.join("sleigh_shim");

    println!("cargo:rerun-if-changed={}", shim_dir.display());
    println!("cargo:rerun-if-changed={}", cpp_dir.display());
    println!("cargo:rerun-if-env-changed=DEP_Z_INCLUDE");

    // Keep existing ffi-test logic
    if cfg!(feature = "ffi-test") {
        println!("cargo:rustc-link-search=native={}", cpp_dir.display());
    }

    // --- Compile SLEIGH C++ engine + shim for direct FFI ---
    if !cpp_dir.join("sleigh.cc").exists() {
        panic!(
            "locked Ghidra SLEIGH source tree is missing: {}",
            cpp_dir.display()
        );
    }

    // SLEIGH runtime source files (from Ghidra Makefile: CORE + SLEIGH)
    let sleigh_sources = [
        "xml",
        "marshal",
        "space",
        "float",
        "address",
        "pcoderaw",
        "translate",
        "opcodes",
        "globalcontext",
        "sleigh",
        "pcodeparse",
        "pcodecompile",
        "sleighbase",
        "slghsymbol",
        "slghpatexpress",
        "slghpattern",
        "semantics",
        "context",
        "slaformat",
        "compression",
        "filemanage",
    ];

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let mut cc = cc::Build::new();
    cc.cpp(true).include(&cpp_dir).warnings(false);

    if target_os == "windows" {
        // Ghidra's file-management layer selects its native Win32
        // implementation with this macro; no POSIX-header shims are needed.
        cc.define("_WINDOWS", None);
    }
    if target_env == "msvc" {
        // MSVC does not expose a C++11 language-mode switch.  C++14 is its
        // oldest supported explicit mode and accepts the locked C++11 code.
        cc.std("c++14").flag("/EHsc");
    } else {
        cc.std("c++11");
    }

    // libz-sys owns zlib discovery for this Cargo package.  Its `links = "z"`
    // metadata exposes the exact include directory selected by its build.
    if let Ok(include_dirs) = env::var("DEP_Z_INCLUDE") {
        for include_dir in include_dirs.split(',').filter(|s| !s.is_empty()) {
            cc.include(include_dir);
        }
    }

    // Add shim
    cc.file(shim_dir.join("rugra_sleigh.cpp"));

    // Add SLEIGH sources
    for src in &sleigh_sources {
        let f = cpp_dir.join(format!("{}.cc", src));
        if !f.exists() {
            panic!("required Ghidra SLEIGH source is missing: {}", f.display());
        }
        cc.file(f);
    }

    // A missing SLEIGH archive makes every real binary fail at final link.
    // Fail at the actual compile error instead of swallowing it and producing
    // a misleading green library-only build.
    cc.compile("rugra_sleigh");
    println!("cargo:rustc-cfg=has_sleigh");
}

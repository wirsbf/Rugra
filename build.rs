use std::path::PathBuf;

fn main() {
    // Keep existing ffi-test logic
    if cfg!(feature = "ffi-test") {
        let current_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let path = std::path::Path::new(&current_dir)
            .parent().unwrap()
            .join("ghidra").join("Ghidra").join("Features")
            .join("Decompiler").join("src").join("decompile").join("cpp");
        println!("cargo:rustc-link-search=native={}", path.display());
    }

    // --- Compile SLEIGH C++ engine + shim for direct FFI ---
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let cpp_dir = manifest.join("ghidra").join("Ghidra").join("Features")
        .join("Decompiler").join("src").join("decompile").join("cpp");
    let shim_dir = manifest.join("sleigh_shim");

    // Skip compiling SLEIGH from source if the vendored Ghidra cpp tree is
    // not present. As a fallback, search for a prebuilt `librugra_sleigh`
    // (produced by a prior build on this or a sibling worktree at the same
    // commit) and link against it so the FFI symbols resolve. This keeps
    // `cargo build` working in worktrees that lack the large vendored tree.
    if !cpp_dir.join("sleigh.cc").exists() {
        let found = find_prebuilt_sleigh(&manifest);
        if let Some(prebuilt_dir) = found {
            println!("cargo:rustc-link-search=native={}", prebuilt_dir.display());
            println!("cargo:rustc-link-lib=static=rugra_sleigh");
            println!("cargo:rustc-cfg=has_sleigh");
        } else {
            println!("cargo:warning=SLEIGH cpp source not present and no prebuilt librugra_sleigh found; FFI symbols will be unresolved");
        }
        return;
    }

    // SLEIGH runtime source files (from Ghidra Makefile: CORE + SLEIGH)
    let sleigh_sources = [
        "xml", "marshal", "space", "float", "address", "pcoderaw", "translate",
        "opcodes", "globalcontext",
        "sleigh", "pcodeparse", "pcodecompile", "sleighbase", "slghsymbol",
        "slghpatexpress", "slghpattern", "semantics", "context", "slaformat",
        "compression", "filemanage",
    ];

    let zlib_dir = find_zlib(&manifest);

    let mut cc = cc::Build::new();
    cc.cpp(true)
      .std("c++14")
      .flag("/EHa")
      .include(&cpp_dir)
      .include(&shim_dir)
      .warnings(false);

    // Add Windows SDK + MSVC include paths for cl.exe
    let win_sdk = PathBuf::from("C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0");
    let msvc_inc = PathBuf::from("C:/Program Files/Microsoft Visual Studio/18/Professional/VC/Tools/MSVC/14.50.35717/include");
    for inc in &[&win_sdk.join("ucrt"), &win_sdk.join("shared"), &win_sdk.join("um"), &msvc_inc] {
        if inc.exists() { cc.include(inc); }
    }
    // Also add lib paths for linker
    let win_sdk_lib = PathBuf::from("C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0");
    let msvc_lib = PathBuf::from("C:/Program Files/Microsoft Visual Studio/18/Professional/VC/Tools/MSVC/14.50.35717/lib/x64");
    for lib in &[&win_sdk_lib.join("ucrt/x64"), &win_sdk_lib.join("um/x64"), &msvc_lib] {
        if lib.exists() { println!("cargo:rustc-link-search=native={}", lib.display()); }
    }

    if let Some(ref zd) = zlib_dir {
        cc.include(zd);
    }

    // Add shim
    cc.file(shim_dir.join("rugra_sleigh.cpp"));

    // Add SLEIGH sources
    for src in &sleigh_sources {
        let f = cpp_dir.join(format!("{}.cc", src));
        if f.exists() {
            cc.file(f);
        }
    }

    // Add zlib sources if available
    if let Some(ref zd) = zlib_dir {
        for zsrc in &["adler32.c", "deflate.c", "inffast.c", "inflate.c",
                       "inftrees.c", "trees.c", "zutil.c"] {
            let f = zd.join(zsrc);
            if f.exists() {
                cc.file(f);
            }
        }
        // Add crc32 stub if real crc32.c not present
        let crc32 = zd.join("crc32.c");
        if !crc32.exists() {
            cc.file(shim_dir.join("crc32_stub.c"));
        }
    }

    // Try to compile
    match cc.try_compile("rugra_sleigh") {
        Ok(_) => {
            println!("cargo:rustc-link-lib=static=rugra_sleigh");
            println!("cargo:rustc-cfg=has_sleigh");
        }
        Err(e) => {
            println!("cargo:warning=SLEIGH compilation failed: {}", e);
            println!("cargo:warning=SLEIGH FFI will not be available");
        }
    }

    println!("cargo:rerun-if-changed=sleigh_shim/rugra_sleigh.cpp");
}

/// Locate a directory containing a prebuilt `librugra_sleigh` (`.a`/`.lib`)
/// from a prior build on this crate or a sibling worktree sharing the same
/// `target/` tree. Returns the directory holding the archive so the caller
/// can emit a `rustc-link-search` for it.
fn find_prebuilt_sleigh(manifest: &PathBuf) -> Option<PathBuf> {
    // The manifest dir for a worktree is `<repo>.wt-*`; the main checkout is
    // `<repo>`. Look in both `target` trees. We also honour an explicit
    // `CARGO_TARGET_DIR` / `RUGRA_SLEIGH_LIB_DIR` override.
    if let Ok(dir) = std::env::var("RUGRA_SLEIGH_LIB_DIR") {
        let p = PathBuf::from(dir);
        if sleigh_archive_in(&p).is_some() {
            return Some(p);
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(td));
    }
    candidates.push(manifest.join("target"));
    // Sibling main checkout (strip a leading "<name>-wt-" worktree suffix).
    if let Some(parent) = manifest.parent() {
        let main_repo = parent.join("rugra");
        if main_repo != *manifest {
            candidates.push(main_repo.join("target"));
        }
    }

    for target in &candidates {
        if let Some(dir) = sleigh_archive_in(target) {
            return Some(dir);
        }
    }
    None
}

/// Walk `<target>/release/build/rugra-*/out/` (and the debug/profile variants)
/// looking for a `librugra_sleigh.a` or `rugra_sleigh.lib`. Returns the
/// directory containing it.
fn sleigh_archive_in(target: &PathBuf) -> Option<PathBuf> {
    let profiles = ["release", "debug", "profile"];
    for prof in &profiles {
        let rugra_build = target.join(prof).join("build");
        let entries = match std::fs::read_dir(&rugra_build) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let out = entry.path().join("out");
            for name in &["librugra_sleigh.a", "rugra_sleigh.lib"] {
                if out.join(name).exists() {
                    return Some(out);
                }
            }
        }
    }
    None
}

fn find_zlib(manifest: &PathBuf) -> Option<PathBuf> {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok()?;
    let registry = PathBuf::from(home).join(".cargo").join("registry").join("src");
    if let Ok(entries) = std::fs::read_dir(&registry) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(sub) = std::fs::read_dir(&path) {
                for s in sub.flatten() {
                    let sp = s.path();
                    if sp.file_name().map(|n| n.to_string_lossy().starts_with("jingle_sleigh")).unwrap_or(false) {
                        let zd = sp.join("src").join("ffi").join("cpp").join("zlib");
                        if zd.join("zlib.h").exists() {
                            return Some(zd);
                        }
                    }
                }
            }
        }
    }
    None
}

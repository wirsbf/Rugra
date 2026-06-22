//! Integration test: 检查 src/ 下每个 .rs 文件是否都有对应 docs/api/ 文档。
//! 
//! 此测试在每次 `cargo test` 时自动运行，确保文档与代码永远同步。
//! 如果该测试失败，说明有 .rs 文件缺少对应的 .md 文档。

use std::path::{Path, PathBuf};

fn project_root() -> PathBuf {
    // tests/ 在项目根下, 所以 CARGO_MANIFEST_DIR 就是项目根
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                result.extend(collect_rs_files(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                result.push(path);
            }
        }
    }
    result
}

#[test]
fn every_rs_file_has_api_doc() {
    let root = project_root();
    let src_dir = root.join("src");
    let doc_dir = root.join("docs").join("api");

    let rs_files = collect_rs_files(&src_dir);
    assert!(!rs_files.is_empty(), "未找到任何 .rs 文件，路径可能有误");

    let mut missing: Vec<String> = Vec::new();

    for rs_path in &rs_files {
        // src/foo/bar.rs -> docs/api/foo/bar.md
        let rel = rs_path.strip_prefix(&src_dir).unwrap();
        let doc_path = doc_dir.join(rel).with_extension("md");

        if !doc_path.exists() {
            let rs_rel = rs_path.strip_prefix(&root).unwrap();
            let doc_rel = doc_path.strip_prefix(&root).unwrap();
            missing.push(format!(
                "  {} → {} (文档不存在)",
                rs_rel.display(),
                doc_rel.display()
            ));
        }
    }

    if !missing.is_empty() {
        panic!(
            "\n\n╔══════════════════════════════════════════════════╗\n\
             ║  ❌ docs/api/ 文档同步检查失败                    ║\n\
             ╠══════════════════════════════════════════════════╣\n\
             ║  以下 {} 个 .rs 文件缺少对应的 API 文档:         ║\n\
             ╚══════════════════════════════════════════════════╝\n\n{}\n\n\
             请为每个缺失的文件创建对应的 docs/api/*.md 文档。\n",
            missing.len(),
            missing.join("\n")
        );
    }
}

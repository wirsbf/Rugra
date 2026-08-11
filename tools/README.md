# 辅助脚本工具库 (Tools & Scripts)

此处归档所有用于项目测试辅助、Ghidra API 挂钩导出、一致性检测对拍的各种外部脚本（如 Python、Shell 脚本等）。不要将它们零散地扔在 Rust 项目根目录下。

目前主要脚本有：
- `ffi_test.py`: 涉及通过 C++ FFI 联调的一些绑定与驱动测试段。
- `ghidra_export.py`: 挂载在 Ghidra 原生环境中执行，用于将其内部的 P-code 数据导出为我们可以对比的形式。
- `pcode_compare_test.py`: 自动比较我们的 P-code 生成串与 Ghidra 原生串的微小差异脚本。

## 可复现快速构建

`rugra_build.py` 是 Cargo 的受控入口。它默认使用 `--locked --offline`、
固定 locale/timezone、记录工具链和输入指纹，并使用全部可用 CPU。若系统安装了
`sccache`，脚本同时缓存 Rust 与 C/C++；只有 `ccache` 时仅缓存 C/C++；两者都没有时
安全回退到直接编译。`cc` build dependency 的 `parallel` feature 会让 22 个 SLEIGH
翻译单元遵守 Cargo jobserver 并行构建。

```bash
# 日常快速语义检查（默认 fast-release）
python3 tools/rugra_build.py check --all-targets --report /tmp/rugra-build.json

# 快速可运行产物
python3 tools/rugra_build.py build --all-targets

# 最终发布构建仍使用原来的 fat-LTO release profile
python3 tools/rugra_build.py build --profile release

# 查看将执行的受控命令和环境，不启动编译
python3 tools/rugra_build.py check --dry-run
```

`fast-release` 只用于反馈速度；它不替代最终 `release` 门禁，也不改变锁定 oracle
或行为证据的判定标准。

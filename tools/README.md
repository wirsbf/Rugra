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

## Changed-function fixture 选择

`select_fixtures.py` 使用生成式 `FUNCTION_LEDGER.json` 的 Rust 函数 span 和稳定 ID，
把 git diff 映射到 `tests/oracle/fixture_registry.json`。删除、顶层改动或没有已登记
fixture 的 `src/*.rs` 改动会 fail-closed：选择全部 fixture，并在 `--strict` 下返回 2，
不会用“没选中测试”冒充无影响。

```bash
# 当前工作树，机器可读结果
python3 tools/select_fixtures.py --pretty

# 提交前只看暂存区；未覆盖源码改动直接失败
python3 tools/select_fixtures.py --staged --strict --pretty

# 显式函数或路径诊断
python3 tools/select_fixtures.py --function RG-F-9f9b178c52fe97265fbe --pretty
python3 tools/select_fixtures.py --path src/sleigh_ffi.rs --pretty
```

## 四级门禁

`rugra_gate.py` 把相同事实源组合成四个延迟层级，并为每条命令记录输入 hash、
工具输出 hash、耗时、timeout 和 exit 状态：

| 层级 | 目标 | 主要内容 |
|---|---|---|
| `edit` | 秒级反馈 | 门禁健康、changed annotation/ref、fast library check |
| `commit` | 原子提交 | 全静态门禁、生成账本、fast all-targets、受影响 fixture |
| `wave` | 集成 wave | commit + 全测试 + 全 fixture + curl/httpd/语法/诊断 golden |
| `nightly` | 冷闭包 | wave + fresh-target canonical release 全目标构建 |

```bash
python3 tools/rugra_gate.py edit --report /tmp/rugra-edit-gate.json
python3 tools/rugra_gate.py commit --staged --report /tmp/rugra-commit-gate.json
python3 tools/rugra_gate.py wave --report /tmp/rugra-wave-gate.json
python3 tools/rugra_gate.py nightly --report /tmp/rugra-nightly-gate.json

# 只查看命令和 fixture 选择，不执行
python3 tools/rugra_gate.py commit --staged --dry-run
```

`commit` 以上层级遇到 fixture coverage gap 会在运行前返回 2。`wave`/`nightly`
固定运行 registry 中的全部 fixture；旧 11.3.2 golden 只保留 diagnostic 身份。

# sleigh_ffi.rs

Sleigh p-code 引擎的进程内 FFI 边界。`build.rs` 从锁定的 Ghidra
Decompiler C++ 源码编译 CORE + SLEIGH 运行时和 `rugra_sleigh.cpp`，Rust
通过稳定的 C ABI 创建 `Sleigh`、加载 `.sla`、安装内存映像并取得 p-code。

Linux 构建使用系统 POSIX headers、Ghidra 的 C++11 模式以及 `libz-sys`
选定的 zlib。Windows 选择 Ghidra 的 `_WINDOWS` 实现并使用 MSVC
`/EHsc`；不再用自造 `unistd.h`/`dirent.h` 覆盖系统头。SLEIGH 编译错误是
硬失败，不能被吞掉后留到最终二进制链接时才暴露。

## RUGRA-GLUE 函数（无 1:1 Ghidra 对应）

这些函数是 Rust ↔ C++ SLEIGH 之间的 FFI/XML 胶水。Ghidra 内部用 C++
`xml.cc` 的 Document/Element 树处理 processor spec；Rugra 的轻量
`load_pspec` 当前只读取所需的 `<set ...>` 默认值。

- `fn cstr_to_string(buf: &[i8]) -> Option<String>` — C 字符串到 Rust String 的安全转换（无 Ghidra 对应，纯 Rust FFI 胶水）
- `fn simple_xml_find(xml: &str, tag: &str) -> Vec<String>` — 替代 Ghidra `xml.cc` 的 `Element::getChild(string)`：在 raw XML 字符串里扫描 `<tag ...>` 起标签，返回所有匹配的起标签字符串。
- `fn get_attr(tag_str: &str, attr: &str) -> Option<String>` — 替代 Ghidra `xml.cc` 的 `Element::getAttributeValue(name)`：在单个 tag 字符串里扫 `attr="..."` 取值。

## 对齐说明

`sleigh_ffi.rs` 整体是 Rugra 专属的 FFI 层（Ghidra 不需要 FFI，它直接用
C++ 类）。仅 `simple_xml_find` / `get_attr` 的**语义**有 Ghidra 对应物
（xml.cc 的 Element API），但**实现形态**不同（字符串扫描 vs 树查询），
故标 `// RUGRA-GLUE:`。

## 运行验证

```bash
cargo build --offline --bin rugra --example sleigh_test
target/debug/examples/sleigh_test
```

smoke 使用 `48 89 f8 c3`，加载 x86-64 pspec 后要求首指令长度为 3 并至少
产生一个 p-code op。它验证构建、链接、`.sla` 读取和上下文默认值，不代表
完整 Flow/SSA/C 输出已经与 Ghidra 等价。

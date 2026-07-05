# sleigh_ffi.rs

Sleigh p-code 引擎的 FFI 边界。Rugra 通过子进程方式调用 Ghidra 的 Sleigh
编译器，解析其 XML 输出，将指令译码为 p-code op 序列。

## RUGRA-GLUE 函数（无 1:1 Ghidra 对应）

这些函数是 Rust ↔ Sleigh 子进程之间的字符串/JSON 胶水，Ghidra 内部用
C++ xml.cc 的 Document/Element 树处理同样的数据；Rugra 在 FFI 边界只能拿到
raw 字符串/XML，需自己解析。

- `fn cstr_to_string(buf: &[i8]) -> Option<String>` — C 字符串到 Rust String 的安全转换（无 Ghidra 对应，纯 Rust FFI 胶水）
- `fn simple_xml_find(xml: &str, tag: &str) -> Vec<String>` — 替代 Ghidra `xml.cc` 的 `Element::getChild(string)`：在 raw XML 字符串里扫描 `<tag ...>` 起标签，返回所有匹配的起标签字符串。
- `fn get_attr(tag_str: &str, attr: &str) -> Option<String>` — 替代 Ghidra `xml.cc` 的 `Element::getAttributeValue(name)`：在单个 tag 字符串里扫 `attr="..."` 取值。

## 对齐说明

`sleigh_ffi.rs` 整体是 Rugra 专属的 FFI 层（Ghidra 不需要 FFI，它直接用
C++ 类）。仅 `simple_xml_find` / `get_attr` 的**语义**有 Ghidra 对应物
（xml.cc 的 Element API），但**实现形态**不同（字符串扫描 vs 树查询），
故标 `// RUGRA-GLUE:`。

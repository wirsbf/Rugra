# `constseq.rs` API Reference

**源代码路径**: `src/constseq.rs`
**Ghidra 对应**: `constseq.hh` / `constseq.cc` (1146行)
**状态**: 📋 L1→🔧 L2（WriteNode/ArraySequence/StringSequence/HeapSequence/RuleStringCopy/RuleStringStore 骨架）

## 模块说明

常量序列分析：将 COPY/STORE 操作序列合并为字符串拷贝。
对应 Ghidra 的 `constseq.hh`。

## 导出的公共 API

### `pub struct WriteNode`
数据流边 + 内存偏移。对应 `ArraySequence::WriteNode`。

### `pub struct ArraySequence`
收集最大连续 op 序列。对应 `ArraySequence`。

### `pub struct StringSequence`
收集 COPY op 序列写入栈/local 数组。对应 `StringSequence`。

### `pub struct HeapSequence`
收集 STORE op 序列通过堆指针写入。对应 `HeapSequence`。

### `pub struct RuleStringCopy` / `pub struct RuleStringStore`
触发 Rule。对应 Ghidra `RuleStringCopy`/`RuleStringStore`。
**当前限制**：完整分析需要 Symbol/SymbolEntry + 堆指针分析。

测试：constseq::tests 2 个。

## 2026-06-26（续）：constseq.rs 完善实现

新增 ArraySequence 分析方法：
- `new(root_op)` — 构造
- `sort_ops()` — 按操作序排序 move_ops（constseq.cc）
- `form_byte_array()` — 从常量 COPY 收集字节数组（constseq.cc formByteArray）
- `is_valid_string()` — 检查是否有效字符串（null 结尾 + 最小长度）
- `get_string()` — 获取字符串内容（截至首个 null）
- `select_string_copy_function()` — 根据 char 类型大小选择 strncpy/wcsncpy/memcpy（constseq.cc selectStringCopyFunction）

测试：新增 2 个（form_byte_array "Hello\0" + select_string_copy_function）。

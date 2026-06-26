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

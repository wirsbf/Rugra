# `constseq.rs` API Reference

**源代码路径**: `src/constseq.rs`
**Ghidra 对应**: `constseq.hh` / `constseq.cc` (1146行)
**状态**: 🔧 **L2 / `NO_ORACLE`（2026-08-11 锁定源码复核）**——现有 Rust 测试与源码锚点不能证明 L3；地址单位、space identity 和块内 predecessor 仍有确定性结构差异。

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

## 2026-08-11 ANN-J annotation bootstrap

The five newly anchored helpers were annotation-only changes. Their current
behavior must not be counted as oracle `MATCH`:

- `byte_to_address_int` / `address_to_byte_int` map to
  `space.hh:541/532`, where Ghidra divides/multiplies by `wordsize`. The current
  `constseq.rs` helpers ignore the supplied word size and return the input.
- `get_space_from_const` maps to `varnode.hh:426`. Ghidra recovers the encoded
  `AddrSpace*`; Rugra decodes a flat numeric `SpaceId` and adds a non-constant
  fallback absent from the oracle.
- `calc_ptradd_offset_inner` maps to
  `constseq.cc:604 HeapSequence::calcPtraddOffset`, but inherits the above
  address-unit and space-model gaps.
- `previous_op_in_block` maps to `op.cc:344 PcodeOp::previousOp`. Ghidra takes
  the immediately preceding list iterator in the same block; Rugra scans the
  global alive bank by mutable order. The current `best_order` comparison does
  not establish equivalent predecessor selection.

No behavior was changed in ANN-J. A locked 12.0.4 HeapSequence fixture is
still required, so this module remains L2/`NO_ORACLE`.

## 2026-06-26（续）：constseq.rs 完善实现

新增 ArraySequence 分析方法：
- `new(root_op)` — 构造
- `sort_ops()` — 按操作序排序 move_ops（constseq.cc）
- `form_byte_array()` — 从常量 COPY 收集字节数组（constseq.cc formByteArray）
- `is_valid_string()` — 检查是否有效字符串（null 结尾 + 最小长度）
- `get_string()` — 获取字符串内容（截至首个 null）
- `select_string_copy_function()` — 根据 char 类型大小选择 strncpy/wcsncpy/memcpy（constseq.cc selectStringCopyFunction）

测试：新增 2 个（form_byte_array "Hello\0" + select_string_copy_function）。

### 2026-06-27（会话3 L1）：constseq.cc 核心算法移植

移植 ArraySequence 的干扰检测和序列收集算法：

- **interfere_between(fd, start, end)** — interfereBetween(constseq.cc:42-58)：检查两个 op 之间是否有干扰 op（call/branch/STORE）
- **check_interference(fd, root_offset, element_size)** — checkInterference(constseq.cc:62-103)：从 root 开始收集同块 COPY 常量到连续偏移的 op，找无干扰的最大连续集
- **RuleStringCopy::apply_op** — RuleStringCopy::applyOp(constseq.cc:954-1002)：检测 COPY 常量字符序列，形成字节数组，验证字符串有效性。transform（替换为 strncpy CALLOTHER）需要 userop 基础设施。

### 2026-07-01（续）：StringCopy/StringStore CALLOTHER 替换（非 stub）
- userop.rs：BUILTIN 常量对齐 Ghidra（MEMCPY/STRNCPY/WCSNCPY），register_string_copy_op/register_string_store_op/register_builtin_by_id + builtin_map。
- constseq.rs：select_string_copy_function（constseq.cc:161）+ build_string_copy（347-372）+ transform（453-461）。RuleStringCopy/Store 现在真正创建 CPUI_CALLOTHER op + op_destroy_recursive。2 新测试。
<!-- annotation-pass: 2026-07-04 -->

# `opbehavior.rs` API Reference

**源代码路径**: `src/opbehavior.rs`
**Ghidra 对应**: `opbehavior.hh` / `opbehavior.cc` (1364行)
**状态**: 🔧 L2（evaluate_unary/evaluate_binary 核心实现，覆盖 25+ opcode）

## 模块说明

P-code 操作行为模拟。对应 Ghidra 的 `opbehavior.hh`。
每个 opcode 有对应的 evaluate 函数，用于常量折叠和跳转表模拟。

## 导出的公共 API

### `pub fn evaluate_unary(opc, size_out, size_in, in1) -> Option<u64>`
模拟一元 P-code 操作（COPY/ZEXT/SEXT/INT_NOT/INT_NEG/BOOL_NOT/SUBPIECE）。

### `pub fn evaluate_binary(opc, size_out, size_in, in1, in2) -> Option<u64>`
模拟二元 P-code 操作（ADD/SUB/MULT/DIV/SDIV/REM/SREM/AND/OR/XOR/
LEFT/RIGHT/SRIGHT/EQUAL/NOTEQUAL/LESS/SLESS/LESSEQUAL/SLESSEQUAL/
CARRY/SCARRY/SBORROW/BOOL_AND/BOOL_OR/BOOL_XOR）。

测试：opbehavior::tests 6 个（add/sub/and-or-xor/shifts/compare/unary）。

## 2026-06-26（续）：opbehavior.rs 完善实现

新增完整 opbehavior 功能：
- `evaluate_unary`: 新增 POPCOUNT/LZCOUNT
- `evaluate_binary`: 新增 PTRADD/PTRSUB/PIECE
- `evaluate_ternary`: PTRADD 三元求值（opbehavior.hh:71）
- `recover_input_unary`: 逆操作恢复（opbehavior.hh:77）
- `recover_input_binary`: 逆操作恢复（opbehavior.hh:74）

覆盖 Ghidra 的全部 evaluate/recoverInput 方法。

# `emulate.rs` API Reference

**源代码路径**: `src/emulate.rs`
**Ghidra 对应**: `emulate.hh` / `emulate.cc` (1013行)
**状态**: 📋 L1→🔧 L2（Emulate 骨架 + execute_op 使用 opbehavior evaluate）

## 模块说明

P-code 模拟执行引擎。对应 Ghidra 的 `emulate.hh`。
执行 P-code 操作于虚拟机状态，用于常量传播和跳转表分析。

## 导出的公共 API

### `pub enum EmulateOpBehavior`
执行结果（Continue/Branch/Return/Error）。

### `pub struct Emulate`
基础 P-code 模拟器。对应 Ghidra `Emulate`。
- `new()` — 构造
- `execute_op(op)` — 执行单个 PcodeOp，使用 opbehavior evaluate 进行常量折叠
- `terminated` — 是否已终止

**当前限制**：BreakCallBack/BreakTable、内存 LOAD/STORE 集成待补。

测试：emulate::tests 1 个。

## 2026-06-26（续）：emulate.rs 完善实现

新增完整模拟器功能：
- **Register file**：`(space_id, offset) → value` 映射，`set_register/get_register`
- **LOAD/STORE 集成**：execute_op 现在通过 MemState 执行 LOAD/STORE
- **CBRANCH 条件检查**：评估常量条件决定分支
- **Instruction limit**：`max_instructions` 限制模拟指令数（0=无限）
- **结果存储**：算术/逻辑操作结果存入寄存器文件

测试：新增 2 个（register_file + instruction_limit）。

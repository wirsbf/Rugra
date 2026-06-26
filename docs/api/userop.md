# `userop.rs` API Reference

**源代码路径**: `src/userop.rs`
**Ghidra 对应**: `userop.hh` / `userop.cc` (1009行)
**状态**: 📋 L1→🔧 L2（UserPcodeOp/UserOpType/UserOpManage 骨架已实现）

## 模块说明

用户自定义 P-code 操作（CALLOTHER）管理。对应 Ghidra 的 `userop.hh`。

## 导出的公共 API

### `pub enum UserOpType`
用户操作类型（Unspecialized/Injected/VolatileRead/VolatileWrite/Segment/JumpAssist/StringData/Datatype）。

### `pub struct UserPcodeOp`
用户定义 P-code 操作的基础定义。对应 Ghidra `UserPcodeOp`。
- `new(name, type, index)` / `get_name()` / `get_type()` / `get_index()` / `get_display()`

### `pub struct UserOpManage`
所有注册用户操作的管理器。对应 Ghidra `UserOpManage`。
- `register_op(name, type) -> i32` / `get_op(index)` / `get_index_by_name(name)` / `num_ops()`

### Built-in IDs
`BUILTIN_STRINGDATA/VOLATILE_READ/VOLATILE_WRITE/MEMCPY/STRNCPY/WCSNCPY`

测试：userop::tests 3 个。

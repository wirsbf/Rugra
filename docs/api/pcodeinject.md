# `pcodeinject.rs` API Reference

**源代码路径**: `src/pcodeinject.rs`
**Ghidra 对应**: `pcodeinject.hh` / `pcodeinject.cc` (638行)
**状态**: 📋 L1→🔧 L2（InjectParameter/InjectPayload/PcodeInjectLibrary 已实现）

## 模块说明

P-code 注入引擎。对应 Ghidra 的 `pcodeinject.hh`。
允许用用户定义的 p-code 模板替换特定操作（CALL fixup 等）。

## 导出的公共 API

### `pub struct InjectParameter`
注入 payload 的输入/输出参数。对应 `InjectParameter`。

### `pub enum InjectPayloadType`
注入类型（CallFixup/CallOtherFixup/CallMechanism/ExecutablePcode）。

### `pub struct InjectPayload`
可注入的 p-code 操作容器。对应 `InjectPayload`。

### `pub struct PcodeInjectLibrary`
所有注入 payload 的管理器。对应 `PcodeInjectLibrary`。
- `register_payload(payload) -> id` / `get_payload(name)` / `get_id(name)` / `num_payloads()`

测试：pcodeinject::tests 3 个。

## 2026-06-26（续）：pcodeinject.rs 完善实现

新增完整注入基础设施：
- `InjectPayload::add_input/add_output/get_input/get_output` — 参数管理
- `InjectContext` — 注入上下文（base_addr/next_addr/call_addr/input_list/output）（pcodeinject.hh:79）
- `PcodeEmit` trait — 注入操作发射回调
- `PcodeEmitArray` — 内存收集发射器（dump + ops 数组）

测试：新增 3 个（inject_context + pcode_emit_array + payload_add_params）。

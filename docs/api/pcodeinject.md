# `pcodeinject.rs` API Reference

**源代码路径**: `src/pcodeinject.rs`
**Ghidra 对应**: `pcodeinject.hh` / `pcodeinject.cc` (638行)
**状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——decoder、参数 index、script/id-vector/tempbase、dynamic payload 与 duplicate-error 契约不全；Architecture 无 inject library，Flow 不排队 CALLOTHER 也不调用 injection，直接 API 还从 HashMap 非确定取首项。生产闭包不可达，正式门禁 `NO_ORACLE`。

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
<!-- annotation-pass: 2026-07-04 -->

# 2026-08-16：Ghidra 结构重构 + decode 链（CSPEC-PCODEINJECT-CALLFIXUP-0001）

`PcodeInjectLibrary` 重构为 Ghidra 结构（pcodeinject.hh:187 +
inject_sleigh.hh:110）：id 索引 `injection: Vec<InjectPayload>`、四对
name→id map / id→name 向量（`call_fixups`/`call_fixup_names`、
`call_other_fixups`/`call_other_target`、`call_mechanisms`/`call_mech_target`、
`script_map`/`script_names`）、SLEIGH 库成员 `tempbase`（初始化自
`Translate::getUniqueStart(INJECT)`）与 sleigh 符号 lookup（`set_sleigh_lookup`）。

decode/注册链（错误逐字）：`register_call_fixup` 等（cc:220/236/252/268，
Duplicate 先抛后扩向量）、`allocate_inject`（inject_sleigh.cc:418，CALLFIXUP/
CALLOTHER 占位名 "unknown"）、`decode_inject`（cc:352 = allocate→decode→
register，失败留 orphan payload 非事务）、`InjectPayload::decode_callfixup`
（inject_sleigh.cc:171）/`decode_callother`（cc:201）/`decode_pcode`（cc:84）/
`decode_executable`（cc:256）/`decode_payload_attributes`（cc:83）/
`decode_payload_params`（cc:111）/`decode_body`（cc:72）/`decode_parameter`
（cc:46）/`order_parameters`（cc:67）、`register_inject`（cc:433：map 注册先于
编译）、`parse_inject`（cc:373：addOperand、setUniqueBase、parseStream、
`<src>: Unable to compile pcode: <msg>`、成功后 tpl 替换 parsestring）、
`manual_call_fixup`/`manual_call_other_fixup`（cc:493/504）。
`InjectPayload` 摊平 InjectPayloadSleigh/InjectPayloadCallfixup 子类字段
（source/parsestring/tpl/target_symbol_names）。`get_payload(name)` 保留为
FlowInfo 兼容视图（id 序首匹配）。旧 `register_payload`/`name_to_id`/
`num_payloads`/`get_id` 自创 API 删除。

对拍：runner 16 真实 callfixup 模板 XML 逐字节 MATCH + callother 编译失败
残留探针。残差：InjectPayloadDynamic addrMap/debug-decode（仅 ELEM_INJECTDEBUG
可达）UNTESTED。模块保持 L2。

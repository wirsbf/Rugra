# `subflow.rs` API Reference

**源代码路径**: `src/subflow.rs`
**Ghidra 对应**: `subflow.hh` / `subflow.cc` (4589行)
**状态**: 🟢 **L2.5（部分逐函数核对）**——SubvariableFlow 引擎 + subvar/split 族 Rule 已实现并注册；尚未完成模块全函数 oracle 对拍，不能宣称 L3。

## 模块说明

子字传播（subvariable propagation）：检测携带较小逻辑值的大 Varnode，将计算
下沉到窄类型，消除冗余的掩码/扩展操作。对应 Ghidra `SubvariableFlow`。

另含 `SplitDatatype`——结构体/数组的拆分 load/store/copy 分析（double.cc 共用）。

## 导出的公共 API

### `SubvariableFlow` (subflow.cc:1372)
子字传播引擎。Ghidra `SubvariableFlow` 类的 1:1 移植。
- `new(flow_size, aggressive, sext)` — 构造 (subflow.cc:1372-1404)
- `set_replacement(vn, mask)` / `has_replacement` / `get_replacement_index` — 子变量注册表 (66-151)
- `create_op` / `create_op_down` — 子图 op 创建 (159-197)
- `try_call_pull` / `try_return_pull` / `try_call_return_push` / `try_switch_pull` / `try_int2float_pull` — CALL/RETURN/SWITCH/INT2FLOAT 穿透 (208-367)
- `trace_forward` / `trace_backward` — 双向数据流追踪 (373-861)
- `trace_forward_sext` / `trace_backward_sext` — 符号扩展路径 (867-1009)
- `create_link` / `create_compare_bridge` — 跨 op 连接 (1022-1071)
- `add_constant` / `add_new_constant` / `create_new_out` / `add_push` — 常量/输出处理 (1080-1158)
- `add_terminal_patch` / `add_terminal_patch_same_op` / `add_boolean_patch` / `add_extension_patch` / `add_compare_patch` — 补丁 (1167-1250)
- `replace_input` / `use_same_address` / `get_replacement_address` / `get_replace_varnode` — 替换执行 (1258-1345)
- `process_next_work` / `do_trace` / `do_replacement` — 主流程 (1351-1545)

### 内部数据结构
- `ReplaceVarnode` — 小逻辑值占位 (对应 `SubvariableFlow::ReplaceVarnode`)
- `ReplaceOp` — 子图 op 占位
- `PatchRecord` + `PatchType`(CopyPatch/ComparePatch/ParameterPatch/ExtensionPatch/PushPatch/Int2FloatPatch)
- 静态 helper: `does_or_set(op, mask)` / `does_and_clear(op, mask)` (subflow.cc:26-53)

### oppool1 subvar 族 Rule (coreaction.cc:5621-5628)
- `RuleSubvarAnd` (1547) — INT_AND 截断触发
- `RuleSubvarSubpiece` (1584) — SUBPIECE 触发
- `RuleSubvarCompZero` (1621) — INT_EQUAL/NOTEQUAL 单 bit 测试
- `RuleSubvarShift` (1680) — INT_RIGHT 单 bit 右移
- `RuleSubvarZext` (1704) — INT_ZEXT
- `RuleSubvarSext` (1723) — INT_SEXT
- `RuleSplitFlow` (2039) — SUBPIECE 高半截取

### cleanup pool split 族 Rule (coreaction.cc:5706-5708)
- `RuleSplitCopy` / `RuleSplitLoad` / `RuleSplitStore` (2941/2964/2985) + `SplitDatatype`

### `RuleSubfloatConvert` (subflow.cc:3489, 5633)
浮点子精度转换——Rule struct 存在，TransformManager.apply 待补（依赖 transform.rs 基础设施）。

## 基础设施缺口（已标注 TODO，未绕过）
- `Varnode::isPtrFlow()` — 缺失，RuleSubvarSubpiece/Zext 保守 default false
- `Varnode::isZeroExtended(size)` — 缺失，INT_DIV/INT_REM 用 getNZMask 近似
- `Funcdata::opSetAllInput` — 缺失，extension_patch 用逐槽 op_set_input+op_remove_input 模拟
- `FuncCallSpecs` per-op 查询 — 缺失，CALL trim/push 推迟
- `RulePtrFlow`(5624, ruleaction.cc:9177) — 未移植（重：trialSetPtrFlow/propagateFlowToDef/Reads/truncatePointer + arch 构造）

## 测试
29 单元测试：SubvariableFlow 扫描+替换主流程、terminal/extension/boolean/compare patch、sext 路径、每条 Rule 的 pattern 触发 + guard（mask-too-big/consume-mismatch/no-constant/wrong-size/big-flag/zero-mask）。

### 2026-07-01（续）：TODO 替换 — 接入 Varnode flag 基础设施
- RuleSubvarSubpiece/Zext 的 `aggressive` 参数：从占位 default false 改为 `outvn.is_ptr_flow()`（subflow.cc:1601/1717）。
- RuleSplitFlow 新增 `is_precis_lo/hi` 守卫（subflow.cc:2054）。
- set_replacement 的 isAddrForce/isTypeLock 守卫：用 `is_addr_force()`/`is_type_lock()`+`get_type()` 实现 size 检查（subflow.cc:95/103-118）。
- 新增 `is_zero_extended(base_size)` 静态方法：完整复刻 varnode.cc:958-970（baseSize>=size / size>8 INT_ZEXT 链 / nzm 位移三段逻辑），替换 INT_DIV/REM 近似。
- 文件头部 gap 清单更新：5 项已补齐 + 7 项仍保留（逐条说明原因）。

### 2026-07-01（续 2）：RuleDumptyHumpLate（subflow.cc:3006-3064）
SUBPIECE(PIECE) 回溯：尝试低/高半分量，三路重写（size 不匹配/isAutoLive/完全替换）。

### 2026-07-01（续 3）：SplitFlow TransformManager 子类 + SplitCopy/Load/Store 真正变换
- SplitFlow（subflow.cc:1754-2037）：TransformManager 子类，set_replacement/add_op/trace_forward/trace_backward/do_trace。委托 TransformManager::apply。
- RuleSplitFlow::apply_op：从 eprintln+return 改为 SplitFlow::new→do_trace→apply→CHANGE。
- SplitCopy/SplitLoad/SplitStore：从 return false 改为真正变换（SUBPIECE→COPY/LOAD/STORE 拆分+PIECE 重组）。
4 新测试验证变换执行。

### 2026-07-01（续 4）：SubfloatConvert 常量折叠
FLOAT_FLOAT2FLOAT 常量输入→op_float2_float fold→COPY(constant)（subflow.cc:3394-3403）。3 新测试。

### 2026-07-01（续 5）：SubfloatConvert 非 const 精度追踪
非 const 路径：widening→root=outvn+insize，narrowing→root=invn+outsize。update_type 标记有效精度 float 类型。5 新测试。

### 2026-08-11：INT2FLOAT patch 宽度边界

`try_int2float_pull`（Ghidra `subflow.cc:341-367`）和 `do_replacement` 的
`int2float_patch` 分支（`subflow.cc:1531-1542`）现在共享
`TypeOpFloatInt2Float::preferred_zext_size`。旧的 `<=4 ? 4 : 8` 会在输入恰为
4 字节时返回 4、在 8 字节时返回 8；Ghidra 的严格 `<4`/`<8` 边界分别返回
8 和 9。直接编译锁定 Ghidra 12.0.4 `typeop.cc` 的 fixture 与 Rust 边界测试均
覆盖这些转折点。
<!-- annotation-pass: 2026-07-04 -->

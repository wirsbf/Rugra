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

### 2026-08-15：SUBFLOW-OUTVN-UNWRAP-0001 — outvn None 收敛 + 三处移植缺陷修复

E2E `my_get_token`(0x3720) 曾 panic 于 `trace_forward_sext` COPY/MULTIEQUAL/
INT_{NEGATE,XOR,OR,AND} 分支的 `outvn.unwrap()`。对照锁定 oracle 确认：
Ghidra 在 `traceForwardSext`(subflow.cc:883) 仅对 mark-skip 检查带
`(outvn!=0)` 守卫，随后把裸 `outvn` 指针直接传入 `createLink`(895)，
`setReplacement`(70) 无 null 检查——即该状态在 Ghidra 一致 IR 下不可达
（`opDestroy` funcdata_op.cc:213-217 会先擦除 descend 链接；天然无输出的
STORE/RETURN/BRANCH*/CBRANCH/无输出 CALL 走其它 case）。Rugra 上游仍可能
出现 alive 无输出 op（见 TODO SUBFLOW-OUTVN-UNWRAP-0001 的上游登记），故
所有消费 `op->getOut()` 的 case 现按"不可追踪即 abort"收敛：`None` →
`return false`（与每个 case 的失败路径一致，带 `[ACTION]` stderr 标记），
覆盖 `trace_forward`/`trace_forward_sext` 全部分支（COPY/MULTIEQUAL/
INT_NEGATE/XOR/OR/AND/ZEXT/SEXT/MULT/DIV/REM/ADD/LEFT/RIGHT/SRIGHT/
SUBPIECE/PIECE）。

同轮修复（fixture 对拍暴露）：
1. `do_replacement` CopyPatch/ExtensionPatch 的 `opRemoveInput` 循环——
   参数表达式中的读锁与 `op_remove_input` 的写锁同 op 死锁；guard 提升
   （Ghidra subflow.cc:1486-1487 无锁语义等价）。
2. `get_replace_varnode` 硬编码 `AddressSpace::Register`——Ghidra
   `fd->newVarnode(flowsize, addr)`(1338) 继承原 varnode 的地址空间
   （unique 输入现在正确产生 unique 替换）。
3. `get_replace_varnode` 内联 use_same 用 `flowsize*8 >= 8`（恒真）替代
   Ghidra `bitsize >= 8`(1281) 且漏掉 `aggressive`(1282)——改为方法化读取
   `self.bitsize`/`self.aggressive`，consume 位宽也改用 `1<<bitsize`。

oracle fixture `tests/oracle/subflow_outvn_1204.*`（runner
`tools/run_subflow_outvn_oracle.sh`，pinned base 07efbff + overlay）：15 case
= 6 sext Some + 6 sext None 状态投影（Ghidra 无法运行 doTrace——null 解引用，
NO_ORACLE 如实登记；Rust 侧断言 trace abort + IR 不变）+ 3 plain Some。
<!-- annotation-pass: 2026-07-04 -->

## get_replace_varnode / replace_input：setInputVarnode 移植（HELPF-NONFREE-NORMALIZE-0001，2026-08-17）

`SubvariableFlow::getReplaceVarnode`（Ghidra subflow.cc:1316）在
`useSameAddress` 判定后调用 `fd->setInputVarnode(rvn->replacement)`（cc:1343），
`replaceInput`（cc:1258）在 totalReplace 后调用 `fd->deleteVarnode(&oldvn)`
（cc:1264）。旧 Rugra 实现自述 "setInputVarnode is not ported" 而用原生
`set_flags(INPUT)`——产生 oracle 不可能态 **INPUT-without-INSERT**
（`VarnodeBank::setInput` varnode.cc:1358-1372 的 input⇒xref⇒INSERT 链），
被 `Heritage::collect` 的 read 分支收下后于 `normalizeReadSize`
（heritage.cc:383）→ `opSetOutput` 触发非自由 varnode fail-fast panic
（HELPF-NONFREE-NORMALIZE-0001 登记域，watchpoint 背栈直证）。

现改走 `fd.set_input_varnode`（`VarnodeBank::set_input_varnode` =
funcdata_varnode.cc:340-373 的三步链移植，canonical 返回值回写
`rvn.replacement`）；`replace_input` 在 totalReplace（先经 op_set_input
剥离全部读者，funcdata_varnode.cc:1474-1489）后补 `fd.delete_varnode`
（Ghidra 会传播 LowlevelError；`let _` 吞 Err 为登记残差——faithful 路径上
totalReplace 后无 def/descend，不可达）。

E2E：curl 74 decompiled/1 panic → **75 decompiled/0 panic**（helpf 0x3980
恢复复出体）；skeleton/defects/numbering 全持平。独立复核（机制 C 邻域）
全仓 grep 确认无共享 free varnode / raw `set_flags(INPUT)` 生产者残留。
<!-- annotation-pass: 2026-08-17 -->

## 测试区维护（2026-08-17）

`test_rule_dumpty_hump_late_*`×2 / `test_split_copy_performs_real_transform`
的 harness 修正（VARNODE-ADDDESCEND-THROW-0001 前置件）：同 ruleaction 侧
模式——被 totalReplace/preserve 分支（subflow.cc:3051）/buildInSubpieces
（subflow.cc:2734）重读的 free varnode 经 `set_input` 转 INPUT；断言零变化，
生产代码未动。
<!-- annotation-pass: 2026-08-17 -->

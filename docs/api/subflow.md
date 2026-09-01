# `subflow.rs` API Reference

## 2026-08-30：`test_split_datatype_constructs` 断言按 canonical-Architecture 不变式翻转

`Funcdata::new` 自 2026-08-30 起在构造尾绑定 canonical 默认 Architecture
（FUNCDATA-CANONICAL-ARCH-0001,恢复 `glb = scope->getArch()` 不变式,
funcdata.cc:48;详见 `docs/api/funcdata.md`）。本模块
`test_split_datatype_constructs` 原断言的 arch-less 前提
（`split_structures/split_arrays == false`）随之过时:canonical 默认
config 为 struct|array|pointer(architecture.cc:1430-1432),断言翻转为
`true/true`,`types` 仍为 `None`(canonical 实例无 TypeFactory,直到调用方
`set_arch` 接线)。`SplitDatatype::new` 本体(subflow.cc:2701-2709 移植)未变。

## 2026-08-25：SUBFLOW-ROOTPOINTER-PORT-0001 — RootPointer 家族 + 两段回溯移植

`SplitDatatype::RootPointer` 四方法 1:1 落地：`back_up_pointer`
（cc:2098-2134，PTRSUB/INT_ADD/PTRADD/COPY 单跳回溯 + impliedBase 门 +
`addressToByteInt` 字节换算）、`find`（cc:2144-2176，PARTIALSTRUCT/ARRAY
valueType 剥离 → implied 数组匹配 → `ptrTo != valueType` 双检 → 3 跳
addrTied/loneDescend 回溯环）、`duplicate_to_temp`（cc:2183-2189，
`build_copy_temp` + ptrType retype）、`free_pointer_chain`（cc:2195-2203，
逐级销毁无读者的指针计算 op，in(0) 先取后 destroy）。`build_pointers`
（cc:2616-2672）1:1：per-piece 从根指针按类型下降重建 PTRADD（元素步长
索引 + TYPE_INT retype）/PTRSUB 链，strip-array 指针经 canonical
`get_type_pointer` 构造；`build_in_constants`（cc:2474-2488）常量直建。
`split_load` 补 COPY-follow（cc:2761-2771：loneDescend 是 STORE 则让位
RuleSplitStore、是 COPY 则跟随其输出，piece LOAD 插到 COPY 前，双
destroy）；`split_store` 补 LOAD 值回溯（cc:2813-2832：单读者 LOAD 经
`get_value_datatype` 重导值类型，compat 失败时清 pieces 去掉 LOAD 重试）
+ addrTied 根 `duplicateToTemp`（cc:2874-2875）+ 双 `freePointerChain`
（cc:2892-2896）。双侧 fixture 扩到 31 记录（新增 flat_array_pointer/
progress8_twohop/addrtied_root/load_feed/load_feed_retry/copy_follow 六
例，全部 byte-identical；`flat_array_pointer_apply` UNTESTED 翻 MATCH）。
残留结构缺口收窄为 buildInSubpieces/buildOutVarnodes/buildOutConcats 的
原始 op-DAG 形状（地址放置输出、protoPartial PIECE 栈、
generateConstants 折叠；投影仍以有效语义对拍）。

## 2026-08-25（R15 返修）：M-1/M-2 — getComponent hole 语义重钉

R15 独立复核 REJECT 的两项阻断已修：`Datatype::get_hole_size` 基类 fallback
由 `size-off` 改为 oracle 的 **0**（type.hh:256；见
docs/api/type_system/datatype.md）——`get_component` 的 both-composite 标量
降取与标量字段内部偏移路径不再 false-accept。单测
`test_split_copy_mismatched_scalar_descent_rejected` 重钉 NO_CHANGE
（cc:2363-2364 + type.hh:256），新增合法 hole-filler 正向测试
（字段间隙 padding 中段，cc:2361/2368）。双侧 fixture 扩到 25 记录
（新增 mismatched_scalar_desc / initial_hole_window / two_piece_padding /
padding_filler_middle / gv scalar_field_interior 五例，全部双侧
byte-identical）。S-1（OptionSplitDatatypes pointer 位 toggle 缺口）、S-2
（legacy PTRREL side-table 回退）、S-4（per-op read-facing）已在 metadata
coverage 登记；S-3（clear 等价注释）与 S-5（categorize 冗余臂合并）已落码。

## 2026-08-25：SPLITDATATYPE-EXACTPIECE-0001 — RuleSplitLoad/Store 走 canonical get_exact_piece 门禁

`RuleSplitLoad::apply_op` / `RuleSplitStore::apply_op` 现按 oracle
（subflow.cc:2970-2983 / 2991-3004）先经
`SplitDatatype::get_value_datatype`（subflow.cc:2910-2938，新增）从指针
输入恢复值类型——TypePointerRel parent/offset 解析、超对齐标量
`getArray` 重释、STRUCT/ARRAY 指针走 **canonical**
`TypeFactory::get_exact_piece`（type.cc:4090-4117，与四个生产调用点同一
Architecture 工厂）——再过 STRUCT/ARRAY/PARTIALSTRUCT 元类型门。
分解走 `categorize_datatype` + `test_datatype_compatibility`
（subflow.cc:2237-2274 / 2285-2367，新增）:类别门（load/store 的
array/primitive 组合、整结构同 Arc 非常量拒绝）、hole 填充与
initial-hole/two-piece-padding 拒绝、numDepend>1 整结构门。构造器从
Architecture 读取 `split_datatype_config`（subflow.cc:2701-2709）。
`split_load`/`split_store` 的 piece 指针改为窗口相对（in(1) 即窗口起点,
镜像 buildPointers 的 baseOffset+offset 寻址）；移除旧
`collect_components`/`immediate_offset_after` 本地分解（其整结构分解 +
双计偏移是 my_fwrite 误拆根因）。双侧 fixture
`tests/oracle/splitdatatype_exactpiece_1204` 20 记录 byte-identical
（FILE\*+8 标量不拆、ProgressData 16B → PartialStruct/4 字段 piece、
二轮稳定）。残留结构缺口：RootPointer::find 多跳回溯/addrTied
duplicateToTemp、splitStore 的 LOAD 值回溯（cc:2817-2830）、splitLoad 的
COPY-follow（cc:2761-2769）、oracle buildPointers 的 PTRSUB/PTRADD op
形状（Rugra stand-in 用 INT_ADD,语义地址等价）。

## 2026-08-24：RuleSubvarSext reset 接入 pool virtual-reset seam + 名字对齐

`RuleSubvarSext` 的派生 reset（subflow.cc:1742-1746，从
`Architecture::aggressive_ext_trim` 刷新 `isaggressive`）此前是无法被池
调度的独立方法；现改为 `Rule::reset_for_function` 覆盖，经
`ActionPool::reset` 的 virtual 派发执行，并按 oracle 覆盖意图**不**调用
基类 `Rule::reset`（base warning-given 位跨 reset 存活）。新增
`fixture_is_aggressive()` 观察访问器供锁定 fixture 使用。
`RuleDumptyHumpLate::get_name` 对齐 oracle 精确名 `dumptyhumplate`
（subflow.hh ctor，原 `dumptyhump_late`）。


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
- `SplitDatatype::new` — 从 Architecture 读取 `split_datatype_config` 与工厂 (subflow.cc:2701-2709)
- `SplitDatatype::get_value_datatype(op, size, types)` — 指针→值类型恢复,canonical `get_exact_piece` (subflow.cc:2910-2938)
- `SplitDatatype::get_component` / `categorize_datatype` / `test_datatype_compatibility` — 组件/hole/类别门 (subflow.cc:2208-2234/2237-2274/2285-2367)
- `SplitDatatype::build_in_constants` / `build_pointers` — 常量直建 / 根指针 PTRADD·PTRSUB 链重建 (subflow.cc:2474-2488/2616-2672)
- `SplitDatatype::split_copy` / `split_load(op, in_type)` / `split_store(op, out_type)` — 拆分重写 (subflow.cc:2717/2756/2808)
- `RootPointer::find` / `duplicate_to_temp` / `free_pointer_chain`（+私有 `back_up_pointer`）— LOAD/STORE 根指针定位/复制/释放 (subflow.cc:2098-2203)
- `test_copy_constraints` — COPY 约束（函数输入/同地址 addrTied/LOAD 单读者）(subflow.cc:2370-2384)
- 自由函数 `is_arithmetic_opcode` / `is_arithmetic_input` / `is_arithmetic_output` / `load_store_space` — arithmetic sanity / LOAD·STORE 空间常量解码 (subflow.cc:2673-2696, typeop.hh:140, varnode.hh:426)

### `RuleSubfloatConvert` (subflow.cc:3489, 5633)
浮点子精度转换——完整 `SubfloatFlow`（subflow.cc:3070-3481）已移植：`maxPrecision`
（迭代 DFS + `maxPrecisionMap` 缓存 + op mark 环截断）、`exceedsPrecision`、
`setReplacement`（mark/constant 重编码/free/addrforce/typelock/input 守卫 +
newPiece/newPreexistingVarnode/worklist）、`traceForward`（算术 exceedsPrecision 门、
pass-through 替换、FLOAT2FLOAT/比较/TRUNC/NAN preexisting terminator、
`preexistingGuard` + `getRepeatSlot` 重复输入修正）、`traceBackward`（pass-through
def 复用、INT2FLOAT/FLOAT2FLOAT 源替换、常量 precision 重编码）、`doTrace`
（terminatorCount≥1 门）与 `apply`（委托 transform.rs `TransformManager::apply`）。
`preserveAddress` override（subflow.cc:3451 `vn->isInput()`）经
`set_preserve_address_override` 虚分发钩子接入。

## 基础设施缺口（已标注 TODO，未绕过）
- `Varnode::isPtrFlow()` — 缺失，RuleSubvarSubpiece/Zext 保守 default false
- `Varnode::isZeroExtended(size)` — 缺失，INT_DIV/INT_REM 用 getNZMask 近似
- `Funcdata::opSetAllInput` — 缺失，extension_patch 用逐槽 op_set_input+op_remove_input 模拟
- `FuncCallSpecs` per-op exact lookup — 已具备；CALL trim/push 的 active/locked/
  varargs guards 与 patch/addPush consumer 尚未接，`CALLSPEC-0001`/`UNTESTED`
- `RulePtrFlow`(5624, ruleaction.cc:9177) — 未移植（重：trialSetPtrFlow/propagateFlowToDef/Reads/truncatePointer + arch 构造）
- Split 族（2026-08-25 SUBFLOW-ROOTPOINTER-PORT-0001 起）：RootPointer 四方法与
  buildPointers/buildInConstants、splitStore LOAD 值回溯、splitLoad COPY-follow
  已 1:1 移植；残留：`buildInSubpieces`（地址放置输出 + generateConstants
  折叠，Rugra 用 SUBPIECE stand-in）、`buildOutVarnodes`/`buildOutConcats`
  （protoPartial PIECE 栈，Rugra 用 unique 输出 + PIECE 栈 stand-in，已带
  oracle 的 hasNoDescend 早退门）——投影以有效偏移+尺寸对拍

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

## `LaneDivide`（subflow.cc:3518-4128，LANEDIVIDE-INFRA-0001）

Ghidra `LaneDivide` 类 1:1 移植（LANEDIVIDE-INFRA-0001）：
- `set_replacement` (3518) / `build_unary_op` (3559) / `build_binary_op` (3578) /
  `build_piece` (3599) / `build_multiequal` (3654) / `build_indirect` (3681) /
  `build_store` (3704) / `build_load` (3753) / `build_right_shift` (3800) /
  `build_left_shift` (3837) / `build_zext` (3875) — lane 重建 op 族
- `trace_forward` (3916) / `trace_backward` (4012) — 双向 lane 追踪
- `process_next_work` (4085) — LIFO 工作队列（back/pop，先 backward 后 forward）
- `new` (4102) / `do_trace` (4112) / `apply`（TransformManager::apply, transform.cc:756）

对拍：`tools/run_lanedivide_infra_oracle.sh` MATCH（锁定 12.0.4 oracle 逐字节），
覆盖 PIECE（双 1-lane SUBPIECE → preexisting COPY 路径）、MULTIEQUAL（块首
逆序 + 常量 lane 拆分）成功投影与 INT_MULT 失败零突变投影；单测 47/47 绿。
残差 LANEDIVIDE-INFRA-RESIDUAL-0001（UNTESTED：terminator/store/load/shift/
zext/indirect/restricted-window/typelock 分支；NO_ORACLE：subflow.cc:3942
`rvn+(laneIndex-skipLanes)` 负索引为 oracle UB，Rugra 保守拒绝并注释），
登记见 tests/oracle/lanedivide_infra_1204.metadata.json。核心算法白名单
模块，合并需机制 C 独立复核。

### 2026-08-23：SplitFlow::add_op INDIRECT iop 占位符 + ConstantIop 空指针解码（SUBFLOW-SPLITFLOW-SIGABRT-0001）
- `SplitFlow::add_op` INDIRECT 臂（subflow.cc:1805-1811）：lo/hi 各自调用
  `new_iop`（两个独立 constant_iop 占位符），对齐 cc:1806-1807 的两次
  `newIop(op->getIn(1))` 调用 — createReplacement 为每个新 INDIRECT 物化
  独立 iop 注记 varnode。此前共享单个占位符会把同一 free varnode 接入
  两个 op（"Free varnode has multiple descendants"，varnode.cc:333-336），
  是 Ghidra per-call `emplace_back` 不可达的状态。
- `transform::get_op_from_const_offset` 改返回 `Option<PcodeOpRef>`：
  offset 0 → `None`（Ghidra `(PcodeOp*)(uintp)0 == NULL` 的非空 Arc 映射），
  消除 `Arc::from_raw(null)` UB（nightly `NonNull::new_unchecked` 前置检查
  触发 SIGABRT，`test_split_flow_full_transform_through_indirect` 干净基线
  即崩）；`create_replacement` constant_iop 臂 `None` 时按 `newVarnodeIop(NULL)`
  语义（funcdata_varnode.cc:176-184）直接物化 offset 0 的 iop 空间注记
  varnode。非零 offset 的解码路径逐字节不变。

## 2026-08-24：CALLSPEC-IDENTITY-D0 consumer residual

`Funcdata::get_call_specs_of_op` 已提供 typed annotation + exact PcodeOp identity
lookup，因此旧文案“per-op callspec lookup 不存在”不再成立。这个 D0 只交付
identity/lifecycle：`try_call_pull` 仍未执行 oracle 的 input-active/
input-locked/varargs guards 与 `ParameterPatch`，`try_call_return_push` 也仍未执行
output-locked/output-active guards 与 `addPush`。两者继续保守返回 false；源码审计
确认它们尚未等价，但没有同输入双侧 fixture，证据状态为 `UNTESTED`，统一绑定
已登记的 `CALLSPEC-0001`，不计入 D0 的 identity `MATCH` 投影。

## 2026-08-29：SUBFLOAT-TRANSFORM-NOT-PORTED-0001 — RuleSubfloatConvert 非常量路径改为 defer

`RuleSubfloatConvert::applyOp`（subflow.cc:3489-3507）在 oracle 中构造完整
`SubfloatFlow` 追踪并**重写数据流**至较小精度（`setReplacement` 的
`newPiece` + `TransformManager::apply`，subflow.cc:3194-3237）——它从不给
原较宽 Varnode 重新定类型。Rugra 未移植 transform 层，此前的"pragmatic
minimum"把较小精度 float 类型直接 `update_type` 到较宽 root 上：一方面
Datatype 尺寸错配，另一方面与 `ActionInferTypes::writeBack`（每轮重推导
尺寸正确的 interned 类型）永久振荡，把 float 密集函数（myprogress）的
`localcount` 推到 7 上限发出「Type propagation algorithm not settling」。
现非常量、非等宽输入一律 `NO_CHANGE` defer（等宽早退、常量折叠路径保持），
两个旧断言盖章行为的单测改为断言 defer 且不出现小尺寸 float 盖章。
遗留：完整 `SubfloatFlow` trace/transform 移植登记于
SUBFLOAT-TRANSFORM-NOT-PORTED-0001。
（2026-09-01 更新：该遗留已由 SUBFLOAT-TRANSFORM-RESIDUAL-0001 关闭，见下方
2026-09-01 节——三处 defer 全部替换为真实 trace+apply，双侧 oracle fixture
`subflow_transform_subfloat_1204` MATCH。）

## 2026-09-01：SUBFLOAT-TRANSFORM-RESIDUAL-0001 — SubfloatFlow 完整移植

`TransformManager`（transform.rs）已具备全部簿记原语（SplitFlow/LaneDivide 已用），
缺口是 `SubfloatFlow` 本体未接线。本次按 subflow.cc:3070-3481 逐函数移植：

- `max_precision`（cc:3079-3175）：`State{op,slot,maxPrecision}` 显式栈 DFS；
  MULTIEQUAL/COPY/一元 float def 穿透，ADD/SUB/MULT/DIV 贡献 0，
  FLOAT2FLOAT/INT2FLOAT 贡献 `min(in(0) size, vn size)`，default 贡献 vn size；
  op mark 截环、完成后入 `max_precision_map`（key=`Arc::as_ptr` 身份），
  命中缓存直接吸收。
- `exceeds_precision`（cc:3186-3193）：两输入 maxPrecision 的 min > precision。
- `set_replacement`（cc:3200-3240）：mark 复查→`getPiece(vn, precision*8, 0)`；
  常量 `convertEncoding` 重编码（格式缺失→abort）；free/addrforce(尺寸≠precision)/
  typelock(非 PARTIALSTRUCT 且尺寸≠precision)/input(尺寸≠precision) 守卫；
  `newPreexistingVarnode`（size==precision）或 `newPiece`+worklist。
- `trace_forward`（cc:3249-3330）：descend 快照遍历；outvn 已 mark 跳过；
  二元算术先 `exceedsPrecision`；pass-through 族 `newOpReplace(numInput)` +
  输出 `setReplacement`；FLOAT2FLOAT 下游按 outsize==precision 折 COPY 作
  preexisting terminator；比较族重复输入走 `getRepeatSlot`（count=descend
  中当前 op 之前的出现次数+1，对齐 op.cc:93-111 迭代器语义）+ `preexistingGuard`；
  TRUNC/NAN 一元 terminator；default abort。
- `trace_backward`（cc:3339-3419）：def 为 input→true；pass-through 复用
  `rvn->getDef()` placeholder 或 new；INT2FLOAT 源替换（free 非常量拒绝）；
  FLOAT2FLOAT 源常量按 size==precision 直取 offset / 否则 setReplacement
  重编码，非常量 `getPreexistingVarnode`，COPY/FLOAT2FLOAT 二选一。
- `do_trace`（cc:3462-3481）：format 缺失 false；drain worklist；清 mark；
  `terminatorCount==0` 拒绝。
- `apply_op`（cc:3489-3507）改回 oracle 结构：widening root=outvn/prec=insize，
  narrowing root=invn/prec=outsize，`doTrace` 过→`apply`，**无常量特判**。

行为修复（对齐 oracle，非回归）：常量 widening 现在要求下游 terminator 才折叠
（`doTrace` 的 terminatorCount 门，cc:3479）；常量 narrowing root 是常量、不进
worklist，永不折叠（此前无条件折叠为 COPY，偏离 oracle）。widening/narrowing
非常量路径从 defer 变为真实数据流重写：原 op 销毁（op_replacement）、新建
Varnode/ops、terminator 原地 retarget（op_preexisting），**不 retype 原 Varnode**
（myprogress「Type propagation not settling」的根因家族 F2 就此关闭）。

### 2026-09-01（续）：getRepeatSlot 迭代器语义内联 + 双侧 oracle fixture

双侧 fixture `tests/oracle/subflow_transform_subfloat_1204.{cc,rs}`（runner
`tools/run_subflow_transform_subfloat_oracle.sh`，registry 条目
`subflow_transform_subfloat_1204`）以 9 个 IR 场景对拍锁定 oracle：非 const
widen/narrow 重写、常量 narrow / 无 terminator 常量 widen 拒绝、常量 widen
折叠、exceedsPrecision 阻断（COPY 链 maxPrecision=8）、精度 4 算术穿透、
比较 preexistingGuard slot-0/slot-1、重复输入 getRepeatSlot count 1/2。
观察为全 IR GraphProjection（op 顺序/opcode/addr/seqnum/dead/parent/in-out
边 + varnode create-index/size/space/free/input/written/def/descends + bank
计数）before/after，双侧 stdout 逐字节一致 = MATCH（sha256 钉在 metadata）。

fixture 引出 `src/op.rs PcodeOp::get_repeat_slot` 缺 op.cc:101 的
`count==1 → firstSlot` 早退（登记 `OPS-GETREPEATSLOT-COUNT1-0001`，op.rs 属
他人 write-set 未越界修复）。subflow 调用点改为内联完整迭代器重载语义的
`subfloat_get_repeat_slot`（op.cc:93-111），同时修正 count 前缀为
[0..current)（不含当前 descend 条目，对齐 `--ourIter` 后的 Ghidra 区间）。

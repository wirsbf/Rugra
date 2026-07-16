# `fspec.rs` API Reference

**状态**: ✅ **L3（2026-06-28 完整对齐）**——全部 FuncProto/FuncCallSpecs/ParamTrial/ParamActive 方法覆盖（含 is_input_locked/set_input_lock/copy_from/clear_unlocked_input/is_varargs）。7 单元测试。
**源代码路径**: `src/fspec.rs`

## 模块说明 (Module Doc)

Function prototypes and call specifications

Corresponds to Ghidra's `fspec.hh`. This module manages how functions
are defined (prototypes) and how call sites are handled (call specs).

## 导出的公共 API (Public API)

### `pub const HIDDEN_RETURN: u32 = 1 << 0`

*暂无代码注释*

### `pub const INDIRECT_STORAGE: u32 = 1 << 1`

*暂无代码注释*

### `pub const THIS_POINTER: u32 = 1 << 2`

*暂无代码注释*

### `pub const NAME_LOCKED: u32 = 1 << 3`

*暂无代码注释*

### `pub const TYPE_LOCKED: u32 = 1 << 4`

*暂无代码注释*

### `pub struct ProtoParameter`

A single parameter in a function signature

Corresponds to Ghidra's `ProtoParameter` class.

### `pub fn new(name: String, data_type: Arc<Datatype>, address: Address) -> Self`

Create a new function parameter

### `pub fn is_this_pointer(&self) -> bool`

Returns true if this parameter is a "this" pointer

### `pub fn is_type_locked(&self) -> bool`

Returns true if the type is locked (user-defined)

### `pub struct FuncProto`

A formal function prototype

Corresponds to Ghidra's `FuncProto` class. It defines the return type,
parameters, and calling convention of a function.

### `pub fn new(name: String, return_type: Arc<Datatype>) -> Self`

Create a new function prototype

### `pub fn add_parameter(&mut self, param: ProtoParameter)`

Add a parameter to the prototype

### `pub fn num_params(&self) -> usize`

Get the number of parameters

### `pub fn get_param(&self, index: usize) -> Option<&ProtoParameter>`

Get a parameter by index

### `pub struct FuncCallSpecs`

Specification for a specific function call site

Corresponds to Ghidra's `FuncCallSpecs` class.

### `pub fn new(op_addr: Address, prototype: FuncProto) -> Self`

Create a new call specification


### 2026-06-27（会话3 G5 续）：ParamTrial + ParamActive 基础设施移植

完整移植 Ghidra `ParamTrial`（fspec.hh:210-273）+ `ParamActive`（fspec.hh:285-380）——参数恢复基础设施，是 FuncCallSpecs Action（ActionFuncLink/ActionParamDouble/ActionActiveParam 等）的依赖。

**ParamTrial**（30+ 方法）：参数候选存储位置的试验，含 checked/used/active/unref/killedbycall 等标志位 + splitHi/splitLo 分割。
**ParamActive**（15+ 方法）：试验容器，registerTrial/whichTrial/splitTrial/getNumUsed 等。

**关键状态**：ParamTrial/ParamActive 数据结构 + 核心方法完整移植，4 单元测试验证（标志位、split、register/split、num_used）。但 FuncCallSpecs 尚未持有 `active_input`/`active_output` 字段——这是下一个接入点，接入后即可移植 ActionFuncLink 等 Action 的 apply()。

### 2026-06-27（会话3 G5 接入）：FuncCallSpecs active_input/active_output 字段 + 访问器

- `FuncCallSpecs.active_input: Option<ParamActive>` / `active_output: Option<ParamActive>` — 忠实于 Ghidra `activeinput`/`activeoutput`（fspec.hh）。
- `is_input_locked()` / `is_output_locked()` — FuncCallSpecs::isInputLocked/isOutputLocked
- `is_dotdotdot()` — isDotdotdot
- `init_active_input()` / `init_active_output()` — initActiveInput/initActiveOutput
- `get_active_input()` / `get_active_output()` — getActiveInput/getActiveOutput

### 2026-06-27（会话3 G5 接入续）：ActionFuncLink apply() + funcLinkInput/funcLinkOutput

完整移植 ActionFuncLink（coreaction.cc:1575-1586）+ funcLinkInput(1474-1513)/funcLinkOutput(1521-1572)：

- `func_link_input(fc)`：unlocked/varargs → init_active_input；locked → 注册每个参数为 trial 并 mark_active（Ghidra 的 opStackLoad/opInsertInput pcode 注入需 Funcdata op-edit，暂缓）
- `func_link_output(fc_idx, op)`（2026-06-30 完整移植 coreaction.cc:1521-1572）：① 若 CALL 已有 output，op_unset_output 移除（让返回值重新决定）；② 若 `is_output_locked()`：return-type 为 Void → **不产生 output**（exit/free/__stack_chk_fail 等 void 函数永不产生返回 varnode）；非 void → `new_varnode_out(sz, RAX_addr)`；③ 若 unlocked → `init_active_output()`（不立即建 output，留给 ActionActiveReturn 试验恢复）。locked-stack-output 与 assumedOutputExtension 路径需更多 Funcdata op-edit，暂缓。
- `ActionFuncLink::apply`：遍历 callspecs 调用 func_link_input + func_link_output
- `ActionFuncLinkOutOnly::apply`：只调用 func_link_output

### 2026-06-30：FuncProto.output_type_locked + known_return_type 表

- `FuncProto.output_type_locked: bool` — 忠实于 Ghidra `FuncProto::isOutputLocked`（fspec.cc:3906-3914）。`set_output_lock(val)` 现真正置位（此前是空桩）。`FuncCallSpecs::is_output_locked()` 委托给 `prototype.is_output_locked()`（此前误用 `is_input_locked()` 启发式）。
- `ensure_callspecs` 现按 `known_return_type(name)`（KnownReturn::{Void,Pointer,Int(sz)}）为已知库/curl/httpd 函数设置锁定的 return-type：Void → locked-void（无 output），Pointer → `void *` locked，Int(sz) → `int`/`long` locked，未知 → unlocked。
- 效果：curl gcc 审计 17→19（match_url/__libc_csu_init 的 void-赋值 bug 消除）。


3 单元测试：空 Funcdata、unlocked callspec 初始化 active_input/output、is_input_locked。712/712 测试。

### 2026-06-27（会话3 G5续）：FuncCallSpecs 参数恢复支撑方法 + ParamActive pass控制

- FuncCallSpecs: is_input_active/is_output_active/clear_active_input/clear_active_output/check_input_trial_use（简化版，核心版需 AncestorRealistic）
- ParamActive: finish_pass/is_fully_checked/mark_fully_checked/mark_needs_final_check

### 2026-06-27（会话3 G5接入）：ProtoModel 接入 FuncCallSpecs + checkInputTrialUse 升级

FuncCallSpecs 新增 `proto_model: Option<ProtoModel>` 字段 + 方法：
- `has_model()` / `set_model(model)` — hasModel/setModel
- `resolve_model()` — resolveModel（non-merged 模型为 no-op）
- `derive_input_map()` — 调用 ProtoModel.fillin_input_map（完整版，替代简化版）
- `derive_output_map()` — 调用 ProtoModel.derive_output_map

**checkInputTrialUse 升级**：当 proto_model 存在时，用 ProtoModel.possible_input_param 判断每个试验是否匹配参数存储位置（Register/Stack），匹配→mark_active，不匹配→mark_no_use。无 model 时回退到简化版（全标记 active）。

**ActionActiveParam 升级**：finalize 路径现调用 resolve_model + derive_input_map（ProtoModel.fillinMap 驱动），不再是纯简化版。

### 2026-06-27（会话3 G5闭环）：buildInputFromTrials

- `build_input_from_trials() -> Vec<(Address, i32)>` — `FuncCallSpecs::buildInputFromTrials`（fspec.cc:5685-5741）忠实适配：遍历 active-input 试验，收集 USED 试验的 (address, size) 作为最终参数列表，删除未用试验。关闭参数恢复闭环：checkInputTrialUse → deriveInputMap → buildInputFromTrials。

### 2026-06-29：FuncCallSpecs::stackoffset + get_spacebase_offset
- 新增 `stackoffset: i64` 字段 + `OFFSET_UNKNOWN` 常量（fspec.hh:1641/1651）。
- `get_spacebase_offset() -> i64` — 忠实移植 `FuncCallSpecs::getSpacebaseOffset`（fspec.hh:1689）。
- `set_spacebase_offset(offset)` / `has_spacebase_offset()` — 设置/查询。
- 解锁 ActionRestrictLocal 的完整版（Loop 1: 遍历 locked stack params → markNotMapped）。

### 2026-06-29（续）：EffectRecord + FuncProto::effects
- 新增 `EffectRecord` 结构 + `EffectType` 枚举（unaffected/killedbycall/return_address/unknown_effect）。忠实移植 Ghidra `EffectRecord`（fspec.hh:391-416）。
- `FuncProto` 新增 `effects: Vec<EffectRecord>` 字段 + `effect_iter()` / `add_effect()` 方法。对应 Ghidra `FuncProto::effectlist` + `effectBegin/effectEnd`。
- 解锁 ActionRestrictLocal Loop 2（遍历 effect records 找 saved registers → COPY to stack → markNotMapped）。

### 2026-07-01：bytes_consumed tracking
FuncProto: +return_bytes_consumed 字段 + get/set（fspec.hh:1367/1429）。
FuncCallSpecs: +input_consume Vec + get/set_input_bytes_consumed（fspec.cc:5870）。

### 2026-07-04：AncestorRealistic + finalInputCheck + checkInputTrialUse 1:1 对齐

**AncestorRealistic**（funcdata.rs，移植自 funcdata.hh:655-724 + funcdata_varnode.cc:1997-2237）：
- `AncestorRealistic` 结构 + `ArState`（op/slot/flags/offset）+ `state_flags`/`ar_command` 模块
- `execute(op, slot, trial, allow_fail) -> bool` — 深度优先祖先遍历，检测 varnode 是否有 realistic 祖先
- `enter_node` — 处理 INDIRECT/SUBPIECE/COPY/MULTIEQUAL/PIECE 5 个 case（全部分支）
- `upon_pop` — MULTIEQUAL 回溯逻辑（seen_solid/seen_kill + checkConditionalExe）
- `check_conditional_exe` — 条件执行路径验证（BlockBasic.size_in/get_in/size_out）
- Rust 所有权适配：trial_killed_by_call/trial_size 快照 + 延迟 pending 标志（避免 &mut ParamTrial 别名）

**finalInputCheck**（fspec.rs，移植自 fspec.cc:5564-5576）：
- `final_input_check(op_ref)` — 对 hasCondExeEffect 的活跃试验重新运行 AncestorRealistic，失败→markNoUse

**checkInputTrialUse 重写**（fspec.rs，移植自 fspec.cc:5585-5653）：
- 签名改为 `check_input_trial_use(op_ref, has_active_output, aliascheck, maxancestor) -> Vec<(slot, vn_size)>`
- Stack 空间试验：aliascheck.hasLocalAlias → markNoUse；否则 AncestorRealistic + ancestorOpUse
- Register 空间试验：AncestorRealistic(allowFail=true) + ancestorOpUse + condexe 标记
- 返回 definitelyNotUsed 试验的 (slot, size) 供调用者执行 opSetInput(newConstant)

**ancestorOpUse + onlyOpUse**（funcdata.rs，移植自 funcdata_varnode.cc:1805-1994）：
- `ancestor_op_use(has_active_output, maxlevel, vn, op, trial_slot, offset, flags) -> bool`
- 递归跟随 def 链（INDIRECT/MULTIEQUAL/COPY/PIECE/SUBPIECE），调用 only_op_use
- `only_op_use` — 前向遍历 descend，检测 BRANCH/LOAD/STORE/CALL/RETURN 等"非参数使用"
- TraverseNode flags（ACTIONALT/INDIRECT/INDIRECTALT/LSB_TRUNCATED/CONCAT_HIGH）

**ActionActiveParam::apply 1:1 重写**（coreaction.rs，移植自 coreaction.cc:1725-1771）：
- AliasChecker gather → 每个活跃 callspec：trimmable 检查 → checkInputTrialUse → finishPass → maxPass 检查 → trimmable+fullyChecked 时 finalInputCheck → resolveModel → deriveInputMap → buildInputFromTrials → clearActiveInput

**Varnode/PcodeOp 访问器补齐**：
- Varnode: is_return_address/is_indirect_zero/is_incidental_copy/overlap（varnode.hh:257/271/277 + varnode.cc:178）
- PcodeOp: is_indirect_creation/is_indirect_store/is_incidental_copy/is_store_unmarked/is_mark/set_mark/clear_mark（op.hh:179/180/209/225/190/234/235）

**验证**：cargo test --lib 952/952 通过；curl 24/24 反编译；compare_ghidra defects=0（0/24 函数）。
<!-- annotation-pass: 2026-07-04 -->
<!-- activeparam-port: 1783158350.9591746 -->
 
 

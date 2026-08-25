# `fspec.rs` API Reference

`FuncProto` now represents Ghidra's resolved `ProtoModel *` with a shared
`Arc<ProtoModelFull>`. `copy_from` preserves exact model identity while
value-copying the local effect vector. `set_model` applies Ghidra's guarded
extra-pop update and sticky `hasThis` / constructor / auto-killed flags; a
null model resets extra-pop to `0x8000` without clearing those flags.
The legacy `calling_convention == "unknown"` string remains a compatibility
sentinel for existing pipeline consumers; pointer-presence observables such
as `has_model` and `print_raw` consult the resolved `Arc`, not that sentinel.

Call-effect lookup also follows the locked oracle: a non-empty local effect
list is a complete override, while an empty list delegates to the shared
model. Records are ordered by address-space index and offset (not Rust enum
declaration order), unique-space storage is always unaffected, size-zero
records cover their whole space, only fully contained ranges inherit an
effect, and constant-space addresses do not overlap ordinary records.

`ProtoModelFull::output` now owns a concrete output parameter-list variant
through `ParamListOutput`: the standard strategy dispatches to
`ParamListStandardOut`, while the register strategy dispatches to
`ParamListRegisterOut`. Output decode, assignment, recovery, possibility
queries, entry iteration, containment queries, and killed-by-call state all
flow through that one owned variant. `ParamTrial` also carries its complete
address space. `ParamActive::register_trial(Address, ...)` now requires the
address's architecture-owned space tag, projects its type/index without using
the space name, and fails closed without mutation when the address is
spaceless or unrepresentable. Known-space transitional callers use the
explicit `register_trial_in_space` bridge. Both paths preserve Ghidra's
1-based slot sequence and mark non-spacebase trials killed-by-call.

The locked differential fixture
`tools/run_funcproto_effect_model_oracle.sh` compares these observations
against Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`. Its Rust side is built from a
recorded Rugra HEAD archive with only `src/fspec.rs` overlaid, so concurrent
workspace source changes cannot enter the comparand. The covered slice is
`MATCH`; the module remains L2 because compiler-spec/loader attachment,
`ProtoStore` parity, likely-trash/injection copy state, and downstream
Funcdata parameter recovery are outside this atom. In particular this model
primitive alone does not claim to resolve the `GetStr` parameter-name/output
differences.

`FuncProto` also represents Ghidra's `voidinputlock` explicitly. An empty
parameter vector is therefore unlocked until `set_input_lock(true)` is called;
a known `f(void)` remains locked through analysis, while an empty stripped
prototype is still eligible for active recovery. `clearInput` clears the void
lock, `clearUnlockedInput` preserves an authoritative prototype as a whole,
and `copy` preserves the flag.

As in `FuncProto::setInputLock` / `setOutputLock` (`fspec.cc:3921-3948`),
setting either lock also locks the prototype model. Clearing an individual
input/output lock does not implicitly unlock the model.

**状态**: 🔧 **L2（2026-08-23 锁定审计）**——结构化 DOM 中的
`ParamEntry` / `ParamListStandard` / `ProtoModelFull` 解码切片已有锁定
12.0.4 行为对拍，生产 `.cspec` loader 已进入 output fixture；但
`ModelRule` 构造与若干未覆盖分支仍为 `MISMATCH` / `UNTESTED`，因此不升 L3。
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

### `pub fn set_model(&mut self, model: Option<Arc<ProtoModelFull>>)`

Install or clear the shared prototype model and update model-derived state.

### `pub fn has_model(&self) -> bool`

Test the stored model pointer/`Arc`, independently of its printable name.

### `pub fn has_effect(&self, space: AddressSpace, offset: u64, size: i32) -> EffectType`

Look up a full address-space/range call effect through the local override or
the shared model fallback.

### `pub fn effect_iter(&self) -> &[EffectRecord]`

Iterate the effective local-override or shared-model effect list.

### `pub fn get_extra_pop(&self) -> i32`

Return the prototype-local extra stack-pop value.

### `pub fn is_auto_killed_by_call(&self) -> bool`

Return the sticky model property, with output locking as an independent true
condition.

### `pub struct FuncCallSpecs`

Specification for a specific function call site

Corresponds to Ghidra's `FuncCallSpecs` class.

### `pub fn new(op_addr: Address, prototype: FuncProto) -> Self`

Create a new call specification

### `pub fn set_funcdata(&mut self, display_name: &str, entry: Address)`

(`CALLSPEC-DRIVER-0001`) Associate the callee with this call site — the
faithful observable port of `FuncCallSpecs::setFuncdata` (fspec.cc:4949-4960):
the entry address is taken from the callee and a non-empty display name
replaces `prototype.name`. Ghidra additionally keeps the callee `Funcdata*`
(and throws `LowlevelError` on a double set); Rugra has no per-callee Funcdata
objects, so the front-end boundary (`FlowInfo::queryCall`, flow.cc:660-669 —
driven by the driver's symbol/signature tables) hands the observable
(name, entry) pair directly, and re-association overwrites instead of
throwing. The previous `Option<&Funcdata>` form had no callers and was
consolidated into this signature.


### 2026-06-27（会话3 G5 续）：ParamTrial + ParamActive 基础设施移植

完整移植 Ghidra `ParamTrial`（fspec.hh:210-273）+ `ParamActive`（fspec.hh:285-380）——参数恢复基础设施，是 FuncCallSpecs Action（ActionFuncLink/ActionParamDouble/ActionActiveParam 等）的依赖。

**ParamTrial**（30+ 方法）：参数候选存储位置的试验，含 checked/used/active/unref/killedbycall 等标志位 + splitHi/splitLo 分割。
**ParamActive**（15+ 方法）：试验容器，registerTrial/whichTrial/splitTrial/getNumUsed 等。

**关键状态**：ParamTrial/ParamActive 数据结构 + 核心方法完整移植，4 单元测试验证（标志位、split、register/split、num_used）。但 FuncCallSpecs 尚未持有 `active_input`/`active_output` 字段——这是下一个接入点，接入后即可移植 ActionFuncLink 等 Action 的 apply()。

当前实现已由 2026-08-23 的 output fixture 补齐 `AddressSpace`、1-based
`slotbase`、非 spacebase `killedbycall` 标记及空 entry 的 offset=0 状态；
本段保留为历史接入记录。

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
 
 
**2026-07-22**: +10 FuncProto methods (clearInput/copyFlowEffects/paramShift/resolveExtraPop/setInjectId/cancelInjectId/clearUnlockedOutput/setInternal/updateThisPointer)

### 2026-07-22：ParamEntry + ParamListStandard 算法主体

完整移植 Ghidra `ParamEntry`（fspec.hh:84-155 / fspec.cc:60-595）+ `ParamListStandard`（fspec.hh:589-646 / fspec.cc:597-1517）——参数存储资源建模 + 资源分配算法。

**ParamEntry**（参数存储资源条目：寄存器集合 / 栈槽范围 / join）—— 30+ 方法：
- 资源查询：`get_group`/`get_all_groups`/`get_size`/`get_min_size`/`get_align`/`get_type`/`get_space`/`get_base`/`get_join_pieces`（fspec.hh:126-148）
- 状态谓词：`is_exclusion`/`is_reverse_stack`/`is_grouped`/`is_overlap`/`is_first_in_class`/`is_param_check_high`/`is_param_check_low`（fspec.hh:134-153）
- 包含/相交：`contained_by`(cc:199)/`intersects`(cc:214)/`justified_contain`(cc:248)/`justified_contain_in_space`(cc:248 带查询空间的完整空间守卫形态)/`get_container`(cc:295)/`contains`(cc:335)/`subsumes_definition`(cc:184)/`group_overlap`(cc:157)
- 解析：`find_entry_by_storage`(cc:60)/`resolve_first`(cc:76)/`resolve_join`(cc:94)/`resolve_overlap`(cc:122)/`order_within_group`(cc:583)
- 地址分配：`get_slot`(cc:407)/`get_addr_by_slot` 3-arg(cc:434)/`get_addr_by_slot_just` 4-arg(cc:450)
- 扩展：`assumed_extension`(cc:366) 返回 CPUI_COPY/INT_ZEXT/INT_SEXT/PIECE
- 标志模块 `param_entry_flags`（FORCE_LEFT_JUSTIFY..FIRST_STORAGE，fspec.hh:88-97）+ `containment` 模块（NO_CONTAINMENT..CONTAINED_BY）

**ParamListStandard**（标准参数列表模型：ParamEntry 数组 + 资源分配）—— 35+ 方法：
- 资源分配核心：`assign_address_fallback`(cc:735)/`assign_address`(cc:772)/`assign_map`(cc:785) —— 给定数据类型列表，映射到存储位置
- 试验映射：`build_trial_map`(cc:849) —— 将 ParamActive 试验关联到 ParamEntry；`fillin_map`(cc:1285) —— 决定正式参数列表（buildTrialMap → forceExclusionGroup → separateSections → forceNoUse → forceInactiveChain）
- 排除/链规则：`force_exclusion_group`(cc:1032)/`force_no_use`(cc:1069)/`force_inactive_chain`(cc:1111)/`mark_group_no_use`(cc:974)/`mark_best_inactive`(cc:997)/`select_unreference_entry`(cc:820)/`separate_sections`(cc:946)
- 查询：`find_entry`(cc:661)/`characterize_as_param`(cc:682)/`possible_param`(cc:1354)/`possible_param_with_slot`(cc:1360)/`get_biggest_contained_param`(cc:1375)/`unjustified_container`(cc:1411)/`assumed_extension`(cc:1426)/`check_join`(cc:1315)/`check_split`(cc:1342)
- 解析/finalize：`parse_pentry`(cc:1226)/`parse_group`(cc:1262)/`finalize_after_decode`(cc:1451)/`calc_delay`(cc:1153)/`populate_resolver`(cc:1191)/`add_resolver_range`(cc:1174)
- 辅助：`extract_tiles`(cc:626)/`get_stack_entry`(cc:642)/`get_range_list`(cc:1439)/`clone_model`(hh:645)

**辅助类型**（fspec 模块局部副本，与 modelrules 模块的同名类型互不冲突）：
- `TypeClass` 枚举（General/Float/Pointer/HiddenReturn/Vector/Class1-4，fspec.hh:421-431）
- `VarnodeData`（space+offset+size，varnode.hh）+ `ParamEntryJoin`（fspec.hh:99）
- `ParamListKind`（Standard/StandardOut/Register/RegisterOut/Merged，fspec.hh:427-433）
- `AssignActionResponse`（Success/Fail/NoAssignment，modelrules.hh:264-271）
- `ParameterPieces`（addr+ty+flags，fspec.hh:451-460）+ `HIDDEN_RET_PARM`/`INDIRECT_STORAGE_PIECE` 常量
- `PrototypePieces`（out_type+in_types+first_var_arg_slot，fspec.hh:445-450）
- 自由函数：`string_to_type_class`/`metatype_to_type_class`/`justified_contain_range`/`is_contiguous`

**ParamTrial 扩展**：+`entry_index: Option<usize>` 字段（替代 Ghidra `const ParamEntry*` 指针，fspec.hh:230）+ `set_entry(entry_index, off)`/`clear_entry`/`get_entry_index` 访问器 + `op_less(entries, a, b)`（`operator<` 1:1 移植，cc:1893-1914）。`ParamActive::sort_trials`（hh:316）按 `op_less` 模型槽序（group → entry 序 → exclusion offset / reverseStack 地址 → size）排序试验，见 2026-08-23 节。

**ALIGNMENT_ROADMAP 记录的未移植依赖**（每个 TODO 均有记录）：
- `ParamEntryResolver` rangemap 数据结构本体（fspec.hh:597）—— `find_entry`/
  `characterize_as_param`/`get_biggest_contained_param` 以 `registered_extents`
  窗口化线性扫描等价复刻（见 2026-08-25 节；`add_resolver_range` 仍是
  API-parity no-op stub）
- `AddrSpaceManager::findJoin`（space.cc）—— `resolve_join`/`set_join_pieces` 由调用方提供 pieces
- 生产 `.cspec` 文本到 `Element` DOM 的解析器尚缺；本模块现可通过既有
  `TreeDecoder` 消费结构化 DOM，真实文本 ingestion 仍在本模块之外
- `ModelRule`（modelrules.hh）—— `assign_address` 直接走 fallback
- `Datatype::getAlignSize`/`getAlignment` —— 用 size/alignment=1 近似

### 2026-08-14：compiler-spec 参数模型结构化 DOM 解码

- `ParamEntry::decode` 从 `<pentry>` 读取 `minsize`、`maxsize`、对齐、存储类、
  extension 与地址子元素；命名寄存器通过调用方提供的 Translate 等价解析器
  查询，不嵌入 SysV/Windows ABI 寄存器表。
- `ParamListStandard::decode` 按文档顺序处理 `<pentry>` / `<group>`，保留共享
  group counter、split-float resource 起点、重叠检查、正向/反向栈边界，并由
  `get_range_list` 从实际 stack pentry 推导区间。
- `ProtoModelFull::decode_with_register_resolver` 解码 input/output、effects、trash、
  internal storage，并优先从实际 input stack entries 派生 parameter range；
  `decode` 保留为无命名寄存器目录时的兼容入口。
- `ProtoModelFull` 的 declaration-print flag 使用对象内部的原子可变状态：所有
  指向同一模型的 `Arc` 观察同一次 `setPrintInDecl` 原位突变；复制 alias 时则
  新建独立 flag，匹配 Ghidra 新 `ProtoModel` 对象而非共享 flag。
- 锁定 fixture `tools/run_cspec_param_model_oracle.sh` 用完整
  `x86-64-gcc.cspec`：Ghidra 端走生产 `DocumentStorage`，Rust 端把同一锁定文本
  转为结构化 `Element` 后调用现有 `TreeDecoder` 和上述生产函数。默认模型、
  MSABI 分组、栈区间、正向栈与错误路径的已声明观测逐字节一致。
- 整体状态仍是 `MISMATCH`：Rust 生产路径尚不能直接 ingest `.cspec` 文本；
  `<rule>` 当前仅被消费，尚未构造 `ModelRule`。`resolveprototype`、join-space
  pentry 与 default-return 注入仍为 `UNTESTED`。fixture 不把这些残差归为匹配。

**验证**：cargo check --lib 0 错误；cargo test --lib fspec:: 12/12 通过（6 原有 + 6 新增：ParamEntry exclusion/aligned/justified_contain + ParamListStandard new/possible_param）。repo 中 6 个预存失败（pcodeparse/unionresolve）与本移植无关。

### 2026-08-23：fspec Phase-0 对齐修复（FSPEC-SPACEFILTER-0002 + FSPEC-TRIALCMP-0003）

审计依据 `docs/alignment_audit/FSPEC_GAPS_2026-08-23.md` §3.B/§3.C/§3.D。两处修复均以锁定
oracle `fspec_phase0_1204` fixture（`tools/run_fspec_phase0_oracle.sh`，pin-base schema2）
双侧投影逐字节 MATCH 验证。

- `ParamListStandard::find_entry`（cc:661-680）：删除自创的 `!= AddressSpace::Ram` 过滤，
  改为查询空间 vs entry 空间比较（`e.get_space() != space`），对齐 Ghidra 每空间
  `resolverMap` 的语义（`populateResolver` 只把 entry 注册进它自己空间的 resolver，
  cc:1191-1216）。签名增补 `space: Option<AddressSpace>`：`Some(s)` 精确对齐（寄存器/栈
  entry 正常命中，const/unique 查询不会在别的空间 offset 上假命中）；`None` 只保留给
  遗留 spaceless 兼容调用。`build_trial_map`/output fill-in 两个 trial 驱动调用点现从
  `ParamTrial` 读取完整空间并传入 `Some(space)`。
  下游 `possible_param`/`possible_param_with_slot`/`check_join`/`check_split` 签名随之增补
  显式 `space: AddressSpace`（同 `characterize_as_param`/`get_biggest_contained_param`
  的既有模式）。
- `unjustified_container`（cc:1411-1424）/`assumed_extension`（cc:1426-1437）：删除
  Ram-only 过滤，无空间过滤地遍历全部 entry（Ghidra 依赖逐 entry `justifiedContain` 的
  空间拒绝）。残差：Rust 逐 entry 谓词是 offset-only（遗留无空间 Address），来自异空间
  的查询理论上可假命中 —— 登记为 ADDRESS-0001 的下游缺口。
- `ParamTrial::op_less`（cc:1893-1914 新增移植）：排序键逐分支对齐 —— null entry 恒后、
  group id、entry 指针序（Rust 用 `entry_index`：`std::list` 只在 decode 期 push_back，
  节点分配序 == 声明序 == 索引序）、exclusion entry 的 justified offset、非 exclusion 的
  reverseStack 地址序、size。`sort_trials` 签名改为 `(entries: &[ParamEntry])`，四处调用
  点（`build_trial_map`、`Out::fillin_map`/`fillin_map_fallback`×2）传入所属 entry 表。
  残差：Rust `sort_by` 稳定 vs `std::sort` introsort 不稳定 —— 比较器等价元素（同 entry/
  地址/size）的相对次序可能不同；生产 trial 集不会产生比较器等价重复。
- `ParamTrial::split_hi`/`split_lo`（cc:1845/1856）：`split_lo` 低片地址改
  `addr + (size - sz)`（原 `+sz` 错误，仅 size==2*sz 时巧合相等；12 字节切 4 时
  0x104→0x108），两函数补 `res.flags = flags` 复制（used/checked/active 跨切分保留）。
- `ParamActive::split_trial`（cc:2033-2057 全量移植）：补 stackplaceholder>=0 panic 守卫、
  分裂点以上 trial 的 slot 重编号、`splitLo(getSize()-sz)` 调用形、`slotbase += 1`。
- 单测：`test_param_trial_split_12_at_4_flags_and_address`、
  `test_param_active_split_trial_12_at_4_renumbers_slots`、
  `test_param_active_sort_trials_uses_model_order`、扩展
  `test_param_list_standard_possible_param`（空间负例）。
- fixture `fspec_phase0_1204`：跨空间 entry 查找（register 命中 / const/unique/ram 交叉
  miss / minsize 门）、无空间过滤的容器/扩展判定（register INT_ZEXT、ram PIECE、COPY 门）、
  comparator 阶梯排序（group/entry/offset/reverseStack/null-entry）、12/4 切分的边界地址与
  flags 继承、split_trial slot 重编号。该 fixture 的 Rust 侧现在还会断言每个
  tagged-address 注册成功；它仍只打印 split 前后的 slot delta，而绝对 1-based slot
  与 register-trial flags 由 `fspec_paramlist_output_1204` 直接观察。

**验证**：cargo check --lib 0 错误；cargo test --lib fspec:: 19/19；全库 1473 通过、
2 失败均为 base 即存的 funcdata 推断测试（`test_infer_params_and_return_type`/
`test_type_propagation`，与本改动无关，已 stash 复核）。
`tools/run_fspec_phase0_oracle.sh`：covered_projection=6/6 MATCH。

### 2026-08-23：output ParamList 多态分派（FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001）

- `ParamListOutput::{Standard,Register}` 是 Ghidra `ProtoModel::output`
  虚函数所有权在 Rust 中的封闭表示；`build_param_list("")` /
  `build_param_list("standard")` 建立 `ParamListStandardOut`，而
  `build_param_list("register")` 建立 `ParamListRegisterOut`。所有 output
  decode/assign/fillin/possible/containment/entry 查询均由该枚举按具体类分派，
  不再把 output 存成 input 型 `ParamListStandard`。
- `ParamListStandardOut::decode` 现在完整委托 `ParamListStandard::decode` 后执行
  `initialize`；`ProtoModelFull::decode_with_defaults` 因而把生产 cspec 的 output
  pentry 写入 output 自有列表。`derive_output_map` 与
  `possible_output_param(space,offset,size)` 直接消费同一列表。
- `ParamTrial` 增加 address-space 分量；tagged `register_trial` 不再把缺失空间
  猜作 Register，无法证明空间时零突变返回 `false`。显式
  `register_trial_in_space` 使用 1-based slotbase，并对非 Stack/spacebase trial
  设置 `KILLEDBYCALL`。output fallback
  以 trial space 查 entry，`setEntry(nullptr,0)` 的 Rust 表示同时清 entry index
  和 offset；before/after 序列化因此覆盖 slot、entry group/offset 和全部 flags。
- 锁定 fixture：`tools/run_fspec_paramlist_output_oracle.sh` 使用真实
  `BfdArchitecture` + `examples/curl` + `x86-64-gcc.cspec` 运行 Ghidra，Rust 侧
  使用生产 `DocumentStorage` / SLA / `Architecture::parse_compiler_config`。
  `float_only`、`general_only`、`general_beats_float`、`invalid_output` 四个
  subprojection 的 model/possible 查询及全部 trial 容器突变逐字节一致。
  fixture 另外逐侧序列化 output 的 `autoKilledByCall` 以及只给
  `XMM1_Qa`/`RDX` 的 second-resource case：Ghidra 的生产 `join_dual_class`
  令 `useFillinFallback=false`、`autoKilledByCall=false` 并拒绝缺少首资源的
  second trial；Rust 尚未拥有/执行 decoded `ModelRule`，仍强制 fallback/auto-kill
  为 true 并接受该 trial。因此双侧输出分别 pin，overall/covered projection
  明确为 `MISMATCH`，runner 只有在该差异被完整复现时才成功。

保守残差：`ModelRule` 状态/second-resource 行为已是有真实 oracle 的
`MISMATCH`；成功合成 dual join 与 hidden-return 的分支仍为 `UNTESTED`。input 侧
`ParamListRegister` 所有权、register-output assignment、void/oversize hidden
return、双寄存器 join、错误路径与 endian 边界也不在本 fixture 的 MATCH 投影内。
这些残差使 fspec 保持 L2；本批不声称 output 参数模型整体 L3。

### 2026-08-11：ANN-C 函数来源注释审计

以锁定 oracle `Ghidra 12.0.4`（commit `e40ed13014025f82488b1f8f7bca566894ac376b`）复核 `fspec.cc/.hh` 后，为注释扫描器报告的 18 个函数补齐来源分类。本轮只增加来源注释，不改变任何运行时行为，也不提升模块的 L2 状态。

- 真实 Ghidra 映射（3 个）：`set_input_parameter` → `ProtoStoreInternal::setInput`、`set_output_parameter` → `ProtoStoreInternal::setOutput`、`is_left_justified` → `ParamEntry::isLeftJustified`。
- Rust 数据表示胶水（3 个）：`VarnodeData::default`、`ParameterPieces::default`、`parse_u64`；C++ 侧使用无 `default()` 成员的 aggregate 或 typed `Decoder`。
- Rust trait/继承胶水（6 个）：`ParamListStandard::default`、`ParamListStandardOut::default`、`ParamListRegisterOut::default`、`get_num_group`、`entry_mut`、`is_alias_of`。
- 分阶段 loader 胶水（6 个）：`set_base`、`set_sizes`、`set_alignment`、`set_type_class`、`set_auto_killed_by_call`、`set_num_group`；Ghidra 在 `ParamEntry::decode`、`ParamListStandard::decode` 或派生类中直接写字段，没有这些独立 setter。

这些注释只声明函数来源或 Rust 结构适配原因；尤其不证明扁平 `FuncProto` 存储、默认值、alias identity 或分阶段 loader 与 Ghidra 行为等价。

### 2026-08-15：FuncCallSpecs effect/characterize 委托 FuncProto（HERITAGE-CALLGUARD-0001）

- `FuncCallSpecs::has_effect(space, offset, size) -> EffectType`：对齐
  `FuncCallSpecs : public FuncProto`（fspec.hh:1645）的继承解析——非空本地
  effect 列表完整覆盖，空列表委托 `FuncProto::has_effect`（fspec.cc:4234，
  即 PROTO-EFFECT-MODEL-0001 的 ProtoModelFull 查询）。modelless 的
  FuncProto 在 Ghidra 是无效状态（解引用即错）；Rugra 生产侧在
  FUNCPROTO-MODEL-BIND-0001 落地前保守返回 `unknown_effect`（guardCalls
  因此建 INDIRECT，不会欠保护）。
- `characterize_as_output`/`characterize_as_input_param` 改为委托
  `FuncProto::characterize_as_{output,input_param}`（fspec.cc:4336/4289 新增
  端口）——修复 HERITAGE-DRIVER 审计指出的 output 塌缩到 input
  characterization 的问题。locked-param/output 分支因 Rugra
  `ProtoParameter.address` 无空间身份降级到 model 分支（ADDRESS-0001 移除）。
- `is_auto_killed_by_call` 委托 `FuncProto::is_auto_killed_by_call`
  （fspec.cc:4609：model output 的 autoKilledByCall 粘滞位或 locked output），
  替代写死的 `true`。
- `ParamListStandard::characterize_as_param(space, offset, size)`：修复原
  `space != Ram` 过滤（x86-64 的参数 entry 在 Register 空间，被全部滤掉），
  按 per-entry space 匹配（Ghidra 的 per-space resolverMap 语义）。
- `ParamListStandard::get_biggest_contained_param(space, offset, size)`：
  忠实端口（cc:1375-1409：环绕检查、intersect 窗口、containedBy、取最大、
  `isExclusion` 要求），替代被删除的 Ram-only 旧版。
- `FuncProto::get_biggest_contained_input_param/output`（cc:4459/4492）、
  `justified_contain_range` 转公开（heritage 的 call-guard helper 复用同一
  `Address::justifiedContain` 数学）、`ParamEntry::from_storage`（fixture
  构造 glue）、`FuncCallSpecs::has_effect_translate` 签名更新。
- 证据：`tests/oracle/heritage_callguard_1204.*`（model_state/effect 探针 +
  trials case 双侧逐字节 MATCH）。


# 2026-08-16：defaultReturnAddr 注入点（CSPEC-DEFAULT-RETURN-0001）

`ProtoModelFull::decode_with_defaults`：`decode_with_register_resolver` 的
超集（追加 `default_return_addr: Option<&VarnodeData>` 参数）。模型无自带
`<returnaddress>`（!saw_retaddr）且 Architecture defaultReturnAddr 已设置时，
在 effectlist 排序前追加 `EffectRecord(default, return_address)`——逐字对齐
fspec.cc:2689-2691。旧入口委托 None（等价 defaultReturnAddr.space==null 的
Ghidra 行为），`Architecture::decode_proto_spec`/`decode_default_proto_spec`
为 parse_compiler_config 路径传真值。另新增
`get_alias_parent_marker`/`set_alias_parent_marker`（Ghidra
`getAliasParent()`/copy-ctor `compatModel` 的 Some/None 可观测面）。

### 2026-08-17：setInternal 签名对齐（FUNCPROTO-MODEL-BIND-0001）

- `set_internal(&mut self, model: Option<Arc<ProtoModelFull>>, vt)`——参数从
  简化 `type_system::protomodel::ProtoModel` 改为完整 `ProtoModelFull`，并
  逐字对齐 fspec.cc:3891-3898：`return_type = vt`（内部 store 的 void 输出
  可观测面，store 本体属 PROTOSTORE-SYMBOL-0001）+ `if (model == None)
  set_model(model)` 守卫——已绑定 model（如 set_arch 链安装的 defaultfp）
  不被后续 internal setup 覆盖。零调用者受签名影响（此前无生产调用点）。

### 2026-08-17（续）：print_model_in_decl 修复为模型自有 flag（FUNCPROTO-MODEL-BIND-0001）

- `print_model_in_decl()` 原实现 `!is_model_unknown()` 是字符串哨兵简化——
  model 绑定后会把 `__stdcall` 打进所有声明（golden 为 0 处）。修复为
  fspec.hh:1395 的 `model->printInDecl()` 委托：`setDefaultModel` 将旧默认
  置 true、新默认置 false（architecture.cc:326-329，Rugra `set_default_model`
  已实现同一翻转），别名 clone（copy-ctor `isPrinted=true` 不继承，
  fspec.cc:2360-2366）保持打印。modelless（PLT 锁定路径）保持 false，
  `is_model_unknown` 哨兵语义（"Unknown calling convention" golden warning）
  不受影响。

### 2026-08-17（r2 返工）：has_matching_model（FUNCPROTO-MODEL-BIND-0001）

- `FuncProto::has_matching_model(&Arc<ProtoModelFull>)`——逐字移植
  fspec.hh:1391 内联 `(model == op2)` 指针相等，供 ActionPrototypeTypes
  绑定守卫（coreaction.cc:4617）与 ActionDefaultParams（cc:2325）消费。

### 2026-08-24：CALLSPEC-IDENTITY-D0 exact call-op identity

- `FuncCallSpecs` 现在保存 `op: Weak<RwLock<PcodeOp>>`，精确对应 Ghidra 的
  非拥有 `PcodeOp *`；类型不再派生 `Clone`，避免通过普通值复制悄悄复制一个
  身份对象。`find_call_op` 只升级该 `Weak`，不再按 `op_addr` 扫描 alive op。
- `new_for_op(&PcodeOpRef, FuncProto)` 绑定 exact op。直接 CALL 在 setup 用 FSPEC
  annotation 替换 input(0) 之前捕获目标；若克隆的 input(0) 已携带 typed FSPEC
  handle，则从原 callspec 恢复 entry。裸 Iop constant 即使 offset 相同也不被
  当作 callspec。CALLIND 初建时不臆造 entry。
- `clone_for_op(&PcodeOpRef)` 显式创建新的 callspec 身份并绑定新 op，复制当前已
  建模的 prototype/entry/stack offset；`active_input` 与 `active_output` 由新构造器
  重置。这个专用 clone 是 truncated-flow 生命周期操作，不等同于 `Clone` trait。
- callspec → op 和 CALL input annotation → callspec 均为 `Weak`；
  `Funcdata::callspecs: Vec<Arc<RwLock<FuncCallSpecs>>>` 是权威的持久强 owner。
  短生命周期的局部/返回 `Arc` handle 不会成为反向边，因此没有强引用环。
- D0 的行为门禁是 `callspec_identity_lifecycle_1204`，但总体判定保持
  `MISMATCH`：专用 `IPTR_FSPEC` 尚未实现，当前仍用 `AddressSpace::Iop`
  （`TYPEOP-FSPEC-SPACE-0001`）；本阶段不接 TypeOp getter、PrintC、
  StringManager，也不消除其它既有 FuncCallSpecs 字段残差。
- 旧 `deindirect` helper 没有生产调用者，且 hook 仍只接收裸
  `&mut FuncCallSpecs`，无法把 `new_varnode_call_specs` 所需的 stable `Arc` owner
  传给 typed annotation。owner/rebind seam、override flag 与 callee prototype
  分支均为 `CALLSPEC-0001` 的 `UNTESTED` consumer residual；D0 只更正“annotation
  API 未实现”的过时前提，不宣称该 helper 行为已接通。

### 2026-08-24：noreturn 位生命周期补齐（CALLSPEC-NORETURN-WIRE-0001 段a）

以锁定 oracle `Ghidra 12.0.4`（commit `e40ed13014025f82488b1f8f7bca566894ac376b`）
复核 `fspec.hh:1343-1459/1645` 与 `fspec.cc:3778-3812/5443-5472/4625-4840` 后落地：

- **`FuncProto::copy_flow_effects` 修正为 Ghidra 语义**（fspec.cc:3806-3812）：
  只单向覆盖 `is_inline|no_return` 位子集（Ghidra 先 `flags &= ~(...)` 再
  `flags |= op2.flags & (...)`，源位为 0 时清空目标位），不再拷贝 effects
  列表——effectlist 的整体拷贝属于 `FuncProto::copy`（fspec.cc:3801），旧
  实现是自创语义。这是 `FlowInfo::queryCall`（flow.cc:664）把 callee 的
  noreturn 状态传播到 call-site FuncCallSpecs 的主通道（`__stack_chk_fail`
  路径）。`injectid = op2.injectid` 拷贝暂缺：FuncProto 无 injection id
  存储（`set_inject_id` 为 INJECT-0001 stub），登记于 INJECT-0001。
- **`FuncCallSpecs` 补继承面委托访问器** `is_no_return`/`set_no_return`/
  `is_inline`/`set_inline`/`copy_flow_effects`：Ghidra 的
  `class FuncCallSpecs : public FuncProto`（fspec.hh:1645）经继承直接暴露
  fspec.hh:1434/1439/1411/1417 与 fspec.cc:3806；Rugra 组合持有 prototype，
  以委托等价暴露。flow.rs 的消费侧接线（`FuncCallSpecsExt` stub 退役、
  `query_call` 补 `copy_flow_effects` 调用、`truncate_indirect_jump` 的
  `set_no_return(true)`）为段(b)（flow 租约释放后）。
- **`FuncCallSpecs::deindirect` 的 noreturn/inline 门直接接线**：删除
  `callee_is_no_return_or_inline` closure 参数，改为直接读
  `newfd.get_func_proto()` 的 `is_no_return()/is_inline()`（fspec.cc:5460-5461
  `FuncProto &newproto(newfd->getFuncProto())`）。该方法无生产调用方。
- FuncProto 侧 noreturn 的既有生命周期维持不变：默认构造 `flags=0`
  （fspec.cc:3783 → `no_return:false`）、`set_no_return`/`is_no_return`
  （fspec.hh:1439/1434）、`copy_from`/`clone` 整位拷贝（fspec.cc:3794）、
  decode 的 `noreturn` 属性（fspec.cc:4720-4722）、encode 的
  `ATTRIB_NORETURN`（fspec.cc:4642-4643）、`is_compatible` 的位子集比较
  （fspec.cc:4567）。Ghidra fspec 层**没有** void 返回 → noreturn 的推断
  通道（`setNoReturn` 的全部调用点仅 flow.cc:747、options.cc:358 与 decode
  直接置位），noreturn 只能来自数据库 prototype XML、`OptionNoReturn`、
  call-site 直置或 `copyFlowEffects` 传播。
- 双侧 fixture：`tests/oracle/callspec_noreturn_1204.{cc,rs,metadata.json}` +
  `tools/run_callspec_noreturn_oracle.sh`（六 case 投影：default_ctor、
  explicit_set_idempotent、copy_flow_effects、full_copy_and_clone、
  void_no_inference、decode_encode_channel）。

### 2026-08-24：justified_contain_range 极性修复（FSPEC-JUSTIFIED-CONTAIN-0001）

- **`justified_contain_range(base, sz2, addr, sz, force_left)`** 谓词重写为
  `Address::justifiedContain`（address.cc:131-141）的逐字语义：**任一侧独立
  越界即 -1**——`if addr < base { return -1 }`（cc:133 `op2.offset < offset`）
  与 `if end_addr > this_end { return -1 }`（cc:137 `off2 > off1`），两个
  检查相互独立。旧实现的成对条件（`addr < base && end_addr < this_end` /
  `addr > base && end_addr > this_end`）漏判三类几何：等始越顶
  （`view=start` 返回 0 = 假 justified）、低侧重叠止于 entry 尾（`view=end`
  返回 0）、双端溢出（落入 u64 回绕减法，dev 构建直接 panic 于
  `this_end - end_addr`）。
- **投影后果**：`characterize_as_param`（fspec.cc:682-719）对 range⊃entry 的
  query 曾错判 `contains_justified`（off=0），修复后走 `containedBy` →
  `contained_by`（fspec.cc:707），`guardReturnsOverlapping` 的触发前提在
  Rust 侧可达。
- **分支算术维持**：`force_left=true` → `op2.offset - offset`（start 距离），
  `force_left=false` → `off1 - off2`（end 距离 = Ghidra BE+!forceleft）。
  已知未对齐面：小端空间 + forceleft=false 时 Ghidra 返回 start 距离，而
  spaceless helper 取 flag 直接选分支——LE 调用方传 `false` 会得到 end 距离
  （heritage truncate_amount 与 LE 无 flag entry 的 `==0` 判定受影响）。修
  复需把空间端序穿进 helper 签名（含 heritage.rs 调用点），超出本租约，
  待登记 TODO 后另行处理。
  （当日后续：已由 FSPEC-JUSTIFIED-ENDIAN-0002 修复，见下方条目。）
- 双侧 fixture：`tests/oracle/justified_contain_1204.{cc,rs,metadata.json}` +
  `tools/run_justified_contain_oracle.sh`（三 case 投影：LE/BE×forceleft 的
  17 几何极性+分支算术矩阵（含 1/4/8/cross-4 尺寸边界）、ParamEntry
  alignment==0 包装、characterizeAsParam 三分类；63 行双侧逐字节 MATCH）。

### 2026-08-24：空间端序穿签名 + characterizeAsParam resolver 门控（FSPEC-JUSTIFIED-ENDIAN-0002 / FSPEC-CHARACTERIZE-RESOLVER-GATE-0003）

- **`justified_contain_range(base, sz2, addr, sz, force_left, space_is_big_endian)`**
  增加第 6 参空间端序，分支条件重写为 Ghidra 原文的
  `base->isBigEndian() && !forceleft`（address.cc:138）：仅
  **BE 空间 + forceleft=false** 返回 end 距离 `off1 - off2`，其余组合（含
  **LE 空间任意 forceleft**）返回 start 距离 `op2.offset - offset`
  （address.cc:141）。旧实现把 `!force_left` 直接当 BE 路由，LE 调用方
  （heritage truncate_amount、无 flag LE entry 的 `==0` 判定）拿到错误的
  end 距离。
- **调用点端序来源**（Ghidra 均为 `base->isBigEndian()`，即地址所在空间）：
  - `ParamEntry::justified_contain` alignment==0 路径传
    `self.space.is_big_endian()`（cc:266-267 构造 `Address entry(spaceid,…)`）；
    join-piece walk 传各 piece 自己的 `vdata.space.is_big_endian()`（cc:255）。
    过渡期 enum `AddressSpace::is_big_endian` 恒 LE（space.rs 默认），即生产
    闭包全部走 start 距离；BE ParamEntry 空间在 enum 模型下不可表达
    （ADDRESS-0001 残差）。
  - `transfer_locked_output_param` 四处（cc:5073/5075/5082/5084）只观察
    `>= 0`（containment），距离不可观测，传 LE 默认并注释声明。
  - `heritage.rs guard_call_overlapping_input` 的 truncate_amount（cc:1221）
    传 heritage 空间 `space.is_big_endian()` —— LE 下 SUBPIECE 常量 =
    `truncAddr - addr`（start 距离），不再是 end 距离。
- **`characterize_as_param` 重构为 Ghidra 的 resolver 门控两段扫描**
  （fspec.cc:682-719）：phase-1 只访问**注册 extent 包含 query 起点**的 entry
  （`resolver->find(loc.getOffset())`，rangemap.hh:332；populateResolver
  fspec.cc:1191-1216 按 entry 自身 extent / join 逐 piece extent 注册），
  phase-2 仅当 phase-1 块不是 resolver 最后一块（cc:708
  `iterpair.first != resolver->end()`，等价于该空间存在**起点高于 query
  起点**的注册 extent——细化区间在每个注册起点处分裂，上方存在区间 iff
  存在更高起点）时扫描**注册起点落在 `(offset, offset+size-1]`** 的 entry
  （cc:709-716 `find_end(loc.getOffset()+size-1)`）。query 起点在所有同空间
  extent 之上时门控关闭、containedBy 扫描整体跳过、直返
  `no_containment`。join entry 的 `containedBy` 因 spaceid=join 空间恒 false
  （cc:202），Rust 以 `e.space == space` 守卫复刻。线性扫描被窗口化扫描
  取代；窗口辅助 `registered_extents`（RUGRA-GLUE）。
- 单元测试：`test_justified_contain_range_one_sided_violations` /
  `test_param_entry_justified_contain` 改钉 LE 端序语义（无 flag Register
  entry 的 0x202/2 → start 距离 2，非 end 距离 4）。
- 双侧 fixture：`tests/oracle/fspec_endian_resolver_1204.{cc,rs,metadata.json}`
  + `tools/run_fspec_endian_resolver_oracle.sh`（三 case：helper 级
  LE/BE×forceleft 四组合距离判别、LE 无 flag entry 的 wrapper 投影、
  heritage truncate 的 SUBPIECE 常量形态 + characterizeAsParam 的
  extent-out 门控 query 集）。`justified_contain_1204` 因 src 行为变更
  同 commit 重钉（Rust 侧 view=start 行改走 `force_left=false`+LE 的真实
  缺陷路由，be=1 行改 helper 显式端序直调——enum 空间无法 staging BE
  ParamEntry，ADDRESS-0001 过渡声明）。

### 2026-08-25：findEntry 的 resolver find-窗口门控 + join piece 访问（FSPEC-FINDENTRY-GATE-0005）

- **`ParamListStandard::find_entry(space, loc, size, just)`**（cc:661-680）：
  无限定的逐 entry 线性扫描 + `e.get_space() != space` 平面过滤被
  `characterize_as_param` 同款 **resolver find-窗口**取代——只访问
  `registered_extents(e, space)`（populateResolver fspec.cc:1191-1216 的
  per-space 注册：普通 entry 自身 extent / join 逐 piece extent）数值上
  包含 query 起点的 entry。find 窗口 = 起点所在的唯一细化子区间
  （rangemap.hh:332 `find(point)`），窗口内 record 共享同一 `last` 键、按
  `position` 子序排列（AddrRange::operator<），而 position 按 entry 列表
  注册序递增——**有序列表扫描 = 恰好按 Ghidra 顺序访问恰好的窗口集**。
  可观测后果（fixture 钉住）：`just=false` 下 extent-out query（低于/介于/
  高于该空间全部 extent）返回 `None`（旧实现会返回首个同空间 entry）；
  窗口内 minSize 门控不再被窗口外的更早 entry 抢先。
- **join entry 可达**：旧实现的 `get_space() != space` 过滤把 join entry
  （spaceid=join 空间）结构性排除；新窗口按 piece 空间注册访问，findEntry
  可以返回 join entry（cc:1201-1207 逐 piece `addResolverRange`）。
- **`ParamEntry::justified_contain_in_space(addr, sz, query_space)`**
  （cc:248-283 的完整空间守卫形态，resolver 窗口调用方
  `find_entry`/`characterize_as_param` 使用；R13 复核发现 B 的修复）：
  - join walk（cc:253-261，从最低有效 piece 起）：异空间 piece 走
    address.cc:133 `base != op2.base` → -1，仅向跳过累加器贡献自身 size
    ——跨空间 join 的数值巧合不再误报 ≥0；
  - alignment==0（cc:264-267）：entry 空间 Address 的 cc:133 守卫；
  - alignment!=0（cc:269）：显式 `spaceid != addr.getSpace()` 守卫。
  无查询空间的过渡调用方保留 spaceless `justified_contain`
  （ADDRESS-0001）。
- `characterize_as_param` phase-1 的 `justifiedContain` 调用切换到
  space-aware 形态（`loc` 在 Ghidra 原文携带空间）；7 个 `find_entry`
  调用点（build_trial_map/check_join×2/check_split×2/possible_param/
  possible_param_with_slot/fillin_map）签名去 `Option`（Ghidra 的
  `loc.getSpace()` 恒存在，与 characterize 的显式空间形态一致）。
- 双侧 fixture：`tests/oracle/fspec_findentry_1204.{cc,rs,metadata.json}` +
  `tools/run_fspec_findentry_oracle.sh`（四 case 29 行：窗口内外几何、
  just=false 的 NULL 形态、join piece 访问与位置序、跨空间 join 的
  per-piece 空间守卫、find/characterize 对照）。`fspec_phase0_1204` 的
  12 行 findEntry 投影在新窗口语义下逐行不变（已复核），无需重钉。

### 2026-08-24：possible_param join 可达 + assumed_extension 空间守卫（FSPEC-POSSIBLEPARAM-JOIN-0006，A46 残差 3）

- `ParamListStandardOut::possible_param`（cc:1765-1774）：删除调用方级
  `get_space() != space` 过滤（Ghidra 原文遍历**全部** entry，无空间过滤、
  无 resolver 窗口、无 minSize 门），逐 entry 改走
  `justified_contain_in_space(loc, size, space)`：
  - **join entry 可达**（旧过滤把 spaceid=join 空间的 entry 结构性排除）：
    join walk 逐 piece 空间守卫（address.cc:133），`0x104/4` 返回 offset
    4，`>= 0` 即 true（对比 `find_entry(just=true)` 的 `== 0` 门——
    possibleParam 接受未对齐包含）；
  - 普通 entry 的空间拒绝只发生在 `justifiedContain` 内部
    （cc:269 对齐路由 / address.cc:133 exclusion 路由），
    异空间数值巧合 offset 不再假命中；
  - 无 minSize 门：小于 entry minsize 但数值包含的查询仍 true。
- `ParamEntry::assumed_extension`（cc:366-394）签名增补
  `query_space: AddressSpace`（`addr` 在 Ghidra 原文携带空间）：
  cc:377 的 `justifiedContain(addr,sz)!=0` 调用改走 space-aware 形态——
  异空间查询在数值上 justified 的 offset 也返回 `CPUI_COPY`
  （旧 spaceless 形态会误报 ZEXT/SEXT/PIECE 并写入 res）。join entry 在
  cc:376 已提前返回 COPY，不达该调用。容器回写两种形态不变
  （alignment!=0 整对齐 cc:383-388 / exclusion 整 entry cc:378-382），
  flag 优先级 zext→inttype→sext（cc:389-393）。
- `ParamListStandard::assumed_extension`（cc:1426-1437）签名随之增补
  `space: AddressSpace` 透传（list 级 minSize 跳过 cc:1431 不变）。
- 单测 4 个：`test_param_list_standard_out_possible_param_join_and_space`、
  `test_param_list_standard_out_possible_param_aligned_foreign_space`、
  `test_assumed_extension_space_join_and_minsize_gates`、
  `test_assumed_extension_exclusion_container_and_flags`。
- 双侧 fixture：`tests/oracle/fspec_possibleparam_1204.{cc,rs,metadata.json}` +
  `tools/run_fspec_possibleparam_oracle.sh`（四 case 34 观察行：普通 entry
  的 `>=0` 接受与双空间守卫路由、join 可达性与 poke-out、跨空间 join 的
  offset-4 接受、assumed_extension 的异空间 COPY/join 守卫/sz 门/
  minSize 跳过/双容器/flag 优先级）。
- 残差：BE 空间行仍 UNTESTED（ADDRESS-0001 过渡 enum 小端限定）；
  spaceless `justified_contain` 的其余调用方（`unjustified_container`
  cc:1411、`ParamListStandard::fillin_map` cc:1382-1410 两处 trial 查询）
  不在本租约内，保持过渡形态。

### 2026-08-25：unjustified_container/fillin_map_fallback 空间线程化（FSPEC-SPACELESS-REMAINDER）

最后两处 spaceless `justified_contain` 调用方收口（A46 残差 4，由
FSPEC-POSSIBLEPARAM-JOIN-0006 的 metadata residual 登记）：

- **`ParamListStandard::unjustified_container`（cc:1411-1424）** 签名增补
  `space: AddressSpace`（Ghidra 从 `const Address &loc` 携带；过渡
  spaceless `Address` 需旁路传入——同 `find_entry`/`assumed_extension` 形态）。
  cc:1417 的 `justifiedContain(loc,size)` 改走
  `justified_contain_in_space(loc, size, space)`：异空间查询在数值上
  unjustified 的 offset 也返回 hit=0（旧 spaceless 形态会把 stack 查询
  数值巧合地匹配进 register/ram entry 并回写容器）；join entry 经逐
  piece walk 可达，cc:295-302 `getContainer` 回写**包含该 range 的
  piece**（register:0x100/4），而非整个 join。调用方级无空间过滤
  （Ghidra 没有）；minSize 门（cc:1415）在 justifiedContain 之前跳过
  entry；just==0 提前返回 false（cc:1420）。
- **`ParamListStandardOut::fillin_map_fallback`（cc:1638-1719）** 两处
  trial 查询（cc:1656 逐 entry 评估 + cc:1702 best entry 复评）均改走
  `justified_contain_in_space(t_addr, t_size, t_space)`，并**删除自创的
  调用方级 `curentry.get_space() == t_space` 守卫**——该守卫使 join
  entry 永不可达（join space != register），Ghidra 中 join 经逐 piece
  空间匹配可达：register trial 命中 join 后被 mark_used/set_entry，
  而旧代码 bestentry 为 null、全部 trial markNoUse。异空间 rejection
  只发生在 walk 内部（逐 piece address.cc:133 / fspec.cc:269 +
  address.cc:133），与 plain entry 行为等价。
- 单测 2 个：`test_unjustified_container_space_guards_and_join`、
  `test_fillin_map_fallback_join_reachable`（含 bestentry null 分支）。
- 双侧 fixture：`tests/oracle/fspec_spaceless_rem_1204.{cc,rs,metadata.json}` +
  `tools/run_fspec_spaceless_rem_oracle.sh`（7 case 31 行：uc 普通 entry
  的跨空间拒绝/对齐路由/minSize 门/just==0 早退、uc join 可达性与
  piece 容器、fb plain best-cover 与 tie 拒绝、fb join 可达性（核心
  分歧行）、fb 跨空间 join piece、fb firstOnly 跳过与放行）真实双侧
  执行 byte-identical。
- 关联重钉：`fspec_phase0_1204`（unjustified_container 唯一存量调用方）
  更新调用签名并重钉 comparand；possibleparam/findentry/endian_resolver
  runner 的 fspec_rs pin 因本次 src 变更滞后，登记 TODO
  `FSPEC-PIN-STALE-0002` 待重钉。
- 残差：BE 空间行仍 UNTESTED（ADDRESS-0001 过渡 enum 小端限定）；
  fspec 内 spaceless `justified_contain` 生产调用方清零（仅
  `justified_contain_in_space` 内部委托与测试保留）。

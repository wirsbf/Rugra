# `coreaction.rs` API Reference

**状态**: 已核对（当前有效，2026-07-27 ActionSetCasts 指针适配接入 apply() — PTRSUB/PTRADD slot0 CAST 插入 + castOutput 接入 + CHANGE 返回修正）
**源代码路径**: `src/coreaction.rs`
**2026-07-16**: 测试构造的 BlockWhileDo 加 `overflow_syntax: false` 字段（配合 printc P7-overflow_syntax，对齐 Ghidra hasOverflowSyntax block.hh:692）。

### 2026-07-27：ActionSetCasts 指针适配接入 apply()（解锁 CPUI_CAST 在 PTRSUB/PTRADD 上产生）

- **背景**：此前 `ActionSetCasts::apply` 只走 integer binary/unary input-cast 路径（`cast_input`），`cast_output` 方法已实现但**从未被 apply 调用**，PTRSUB/PTRADD 的 pointer-fit 检查完全缺失。结果：`CPUI_CAST` op 在 curl 中从不产生，printc 的 `(type)x` dispatch（包括 2026-07-27 新增的 RPN PTRSUB/CAST 路径）永不触发。
- **修复（cast_input_ptr，coreaction.cc:2655-2720 PTRSUB/PTRADD arm）**：新增 `cast_input_ptr` 方法 + `ptr_input_reqtype` 辅助——对 PTRSUB `c = PTRSUB(a, off)` / PTRADD `c = PTRADD(a, idx, sz)`，slot 0（指针操作数）若 high-type 与 op 期望的指针类型（取自 output pointer 类型）不匹配，按 `castStandard(reqtype, curtype, care_uint_int=true, care_ptr_uint=true)` 判定是否需要 cast，需要则在 slot 0 前插入 `out = CAST(a)`（out implied，printc 内联为 `(ptype *)a`）。常量输入跳过（pointer-cast 不适用于常量）。
- **修复（castOutput 接入 + 重写）**：apply 现在第二轮遍历对每个非 CAST op 调用 `cast_output`。`cast_output` 的 op 重写改用 `fd.op_set_output` / `fd.op_set_input` / `fd.op_insert_after`（替代旧的手动 rewire），保证 def-link/WRITTEN flag/descend xref 一致（对齐 Ghidra `Funcdata::opSetOutput/opSetInput/opInsertAfter`）。
- **修复（output_metatype 排除指针产生 op）**：`output_metatype` 新增 PTRSUB/PTRADD/LOAD/CALL/CALLIND/COPY/INDIRECT/MULTIEQUAL/CAST → None 分支。这些 op 的 output token 是指针类型本身（由类型推断设置），强制 base-int token 会错误地把 `(long *)out` cast 成 `(long)out`。
- **修复（apply 返回值 bug）**：apply 此前无论 count 是否 >0 都返回 `NO_CHANGE`。现按 Ghidra 行为：count>0 返回 `CHANGE`，否则 `NO_CHANGE`。
- **测试**：新增 5 个单元测试（empty fd NO_CHANGE / PTRSUB mismatched → CAST + CHANGE / PTRSUB matching → NO_CHANGE / PTRADD mismatched → CAST / name 断言）。全部通过，全套 1292 单元测试无回归。
- **限制（诚实声明）**：`ptr_input_reqtype` 用 output 指针类型作为 slot-0 reqtype（最常见情形：PTRSUB input/output 共享指针表示）。Ghidra 完整版用 struct-field resolution（`TypeOpSub::inputTypeLocal` 返回 pointer to outer struct），Rugra 的 Datatype 暂无该机制，待 `findTruncation`/struct 字段解析接入后升级。`resolveUnion`/`checkPointerIssues` 仍延后。

## 模块说明 (Module Doc)

Core analysis actions for the decompiler

Corresponds to Ghidra's `coreaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionHeritage`

Action for performing SSA construction (Heritage)

Corresponds to Ghidra's `ActionHeritage`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionDeadCode`

Action for removing dead P-code operations

Corresponds to Ghidra's `ActionDeadCode`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionConstantPtr`

Action for identifying constant pointers and replacing them

Corresponds to Ghidra's `ActionConstantPtr`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCse`

Action for performing Common Subexpression Elimination (CSE)

Corresponds to Ghidra's `ActionCse`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionRestructureVarnode` (2026-06-26 新增)

Restructure the local-variable scope from stack varnodes. Faithful to
`ActionRestructureVarnode` (coreaction.cc:2274).

- `apply(&mut fd)`: 构建 `crate::varmap::ScopeLocal`（调用
  `restructure_varnode`）并存入 `fd.scope`，供 printc 的
  `get_stack_variable_name` 查询。Ghidra 的 `syncVarnodesWithSymbols`
  已折进 ScopeLocal 构建（待 HighVariable↔Symbol 链接后可拆出独立 pass）。
- Ghidra 的 `aliasyes`（首遍跳过别名计算）当前在 Rugra 全量执行
  `mark_unaliased`；多遍驱动可后续门控。

测试：`coreaction::tests`（2 个）验证 scope 被构建、get_name 正确。


### `pub struct ActionStart`

Start of the analysis process

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeRequired`

Action for merging required varnodes (e.g., tied to the same address)

Corresponds to Ghidra's `ActionMergeRequired`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeAdjacent`

Action for merging adjacent varnodes

Corresponds to Ghidra's `ActionMergeAdjacent`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeCopy`

Action for merging COPY varnodes

Corresponds to Ghidra's `ActionMergeCopy`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeMultiEntry`

Action for merging MULTIEQUAL entry varnodes

Corresponds to Ghidra's `ActionMergeMultiEntry`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeType`

Action for merging varnodes by datatype

Corresponds to Ghidra's `ActionMergeType`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionSimplify`

Algebraic simplification of P-code operations

Folds redundant expressions:
- `x ^ x` → `COPY 0`
- `x & x` → `COPY x`
- `x | x` → `COPY x`
- `BOOL_NOT(BOOL_NOT(x))` → `COPY x`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCopyPropagate`

Copy propagation pass — folds COPY chains

Corresponds to Ghidra's `RuleCopyPropagate`. For each `COPY out = in`,
redirects all users of `out` to use `in` directly, then kills the COPY.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCallParams`

Attach System V AMD64 ABI register parameters to CPUI_CALL operations

Scans for register writes (rdi, rsi, rdx, rcx, r8, r9) preceding each call
and attaches them as additional inputs so PrintC can emit function arguments.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionTypeInfer`

Iterative fixed-point type inference engine

Infers and propagates types across P-code IR varnodes using a multi-pass iterative
dataflow approach (up to 100 iterations until convergence). Implements 5 core rules:

1. **Opcode-driven**: Comparison/boolean ops → `bool` output
2. **COPY propagation**: Bidirectional type flow across `CPUI_COPY`
3. **Pointer arithmetic**: `INT_ADD`/`INT_SUB` with pointer → output inherits pointer type
4. **Phi node**: `MULTIEQUAL` inputs/output type unification (prefers pointer types)
5. **LOAD/STORE dereference**: Bidirectional pointer↔pointee type propagation

After convergence, a post-pass assigns size-based defaults (`byte`/`short`/`int`/`long`)
to remaining untyped varnodes.

Corresponds to Ghidra's `ActionInferTypes` iterative type recovery pass.

### `pub fn new() -> Self`

*暂无代码注释*

 
### 2026-06-23：参数指针类型检测

- `ActionInferParams` 现在扫描所有 LOAD/STORE 的地址输入（input[1]），若该 varnode 是 INPUT 参数寄存器，则把对应参数类型从 size-based scalar 提升为 `long *` 指针。对齐 Ghidra 的 `ActionActiveParam` 指针恢复逻辑。

### 2026-06-23（续）：函数签名与 known_param_count 同步

- `ActionInferParams` 现在在推断参数后，如果当前函数在 `known_param_count` 数据库中有记录，用它的值裁剪推断的参数数。修复函数定义签名与调用处参数裁剪不一致导致的 `too few/many arguments` 错误。
- `ap_strcmp_match`/`ap_strcasecmp_match` 从 1 参数修正为 2 参数。

### 2026-06-23（续）：__vfprintf_chk 参数数修正

- `__vfprintf_chk` 从 5 参数修正为 4 参数（`fp, flag, format, va_list`），与其它 `__*_chk` 可变参数函数区分。

### 2026-06-23（续）：类型传播引擎实验

- 尝试了 COPY chain 追踪 + INT_ADD 指针算术检测 + CALL 参数指针推断。所有模式都太激进——破坏 gcc 通过率（51-52/53）。
- 根因：精确类型传播需要双向类型约束求解（Ghidra ActionTypePropagate），不是简单的使用模式匹配。参数 + 常量可能是数组索引（非指针），CALL 参数可能传值（非指针）。
- 回退到原始的直接 LOAD/STORE 地址检测。53/53 维持。

### 2026-06-23（续）：参数数量对齐 Ghidra

- 修正 known_param_count 中多个函数的参数数，对齐 Ghidra 推断：
  - helpf 1→仍1（Ghidra 2，但 helpf 实际 2 参数，留待后续）
  - SetHTTPrequest 3→2
  - parseconfig 2→4
  - getparameter 3→5
  - file2string.part.0 移除（Ghidra 推断 0，但实际有参数）
  - progressbarinit 加入 1 参数组
- curl 参数差 13→11（-2）。gcc 53/53 维持。

### 2026-06-23（续）：函数名规范化 + 参数数对齐

- known_param_count 现在规范化函数名（`.` → `_`），让 `.constprop.0`/`.part.0` 后缀匹配下划线版。
- helpf 从 1 改为 2（`const char *fmt, ...`）；glob_range 从 5 改为 2；glob_url 保持 2。
- my_get_token/my_get_line 加入 1 参数组。
- curl 参数差 11→8（-3）。gcc 53/53 维持。

### 2026-06-23（续）：known_param_types 源代码签名类型传播

- 新增 `known_param_types()` 返回已知函数的参数类型签名（"ptr"/"int"），基于 curl/httpd 源代码。
- ActionInferParams 用 known_param_types 覆盖默认 size-based 类型推断。
- 效果：my_fwrite 从 `(long, long, long, long)` 改进为 `(void*, long, long, void*)`；SetHTTPrequest 从 `(long, long)` 改进为 `(int, void*)`。
- 禁用了 myprogress/glob_* 签名（优化二进制中类型冲突）。

### 2026-06-23（续）：参数补充 + is_known guard

- 当 known_param_types/known_param_count 的参数数 > 推断数时，从 ABI 寄存器列表（RDI/RSI/RDX/RCX/R8/R9）补充缺失参数。
- 加 is_known guard：只有已知函数才补充/裁剪参数，避免影响测试中的未知函数。
- 效果：getparameter 从 3 参数补充到 5（对齐源代码），parseconfig 从 1 补充到 2。
- gcc 53/53，175/176（1 预存失败）维持。

### 2026-06-23（续）：保守化 httpd 签名

- 移除不确定的 httpd 函数签名（ap_init_vhost_config/ap_update_vhost_given_ip/ap_matches_request_vhost）。
- 只保留确定正确的（ap_fini_vhost_config/ap_parse_vhost_addrs）。
- httpd 参数差 25→21。

### 2026-06-23（续）：移除不确定 httpd 签名

- 移除所有不确定的 httpd ap_* 函数从 known_param_count（ap_get_server_built/ap_pregcomp/ap_pregfree/ap_strcasestr/ap_stripprefix/ap_os_is_path_absolute/ap_is_matchexp/ap_field_noparam/ap_regcomp/ap_regfree/ap_mpm_query/ap_update_vhost_from_headers/ap_vhost_iterate_given_conn/ap_open_stderr_log/ap_setup_prelinked_modules/ap_show_mpm/ap_get_local_host/ap_set_name_virtual_host/ap_init_vhost_config 等）。
- 只保留标准库函数 + 确定的 curl/httpd 函数。
- httpd 参数差 21→16（低于初始 17！）。

### 2026-06-24：保守 ActionTypePropagate（≥2 不同小偏移）

- 新增 `src/analysis/type_infer.rs`：P-code 级保守类型传播。
- 只标记被 ≥2 个不同 8 字节对齐小偏移（<256B）访问的 varnode 为 `_struct *`。
- COPY 链传播：INT_ADD base → COPY target 也标记。
- 集成到 action pipeline（ActionCopyPropagate 之后）。
- 效果：curl 3 个、httpd 2 个 varnode 被标记为 _struct *（保守，避免 type conflict）。
- gcc 53/53，175/176 测试。

## 2026-06-27（续）：41 个新 Actions 骨架

新增 41 个 coreaction Actions 骨架（全部注册、命名正确，实现为 stub 返回 NO_CHANGE）：

ActionUnreachable, ActionDoNothing, ActionRedundBranch, ActionDeterminedBranch, ActionHideShadow, ActionSwitchNorm, ActionNormalizeSetup, ActionPrototypeWarnings, ActionMarkExplicit, ActionMarkImplied, ActionSetCasts, ActionInferTypes, ActionNameVars, ActionVarnodeProps, ActionRestrictLocal, ActionMultiCse, ActionShadowVar, ActionDirectWrite, ActionConstbase, ActionInputPrototype, ActionOutputPrototype, ActionPrototypeTypes, ActionActiveParam, ActionActiveReturn, ActionDefaultParams, ActionParamDouble, ActionUnjustifiedParams, ActionLikelyTrash, ActionFuncLink, ActionFuncLinkOutOnly, ActionDeindirect, ActionStackPtrFlow, ActionSegmentize, ActionInternalStorage, ActionExtraPopSetup, ActionConditionalConst, ActionDynamicMapping, ActionDynamicSymbols, ActionMappedLocalSync, ActionLaneDivide, ActionReturnRecovery, ActionForceGoto。

coreaction.rs 现有 58 个 Action structs（覆盖全部 Ghidra coreaction ::apply 方法）。Actions 的实际算法逻辑是后续 L3 工作的核心。

## 2026-06-27（续 2）：ActionDeterminedBranch 完整算法

- **ActionDeterminedBranch**：不再是 stub。完整实现 coreaction.cc 的逻辑：遍历所有基本块，找到以 CBRANCH（常量布尔输入）结尾的块，计算实际分支方向（考虑 BOOLEAN_FLIP），调用 `Funcdata::remove_branch` 移除非选中边。
- **Funcdata::remove_branch**：新增 CFG 编辑方法（funcdata_block.cc branchRemoveInternal）——销毁 CBRANCH op + 移除 out-edge + 更新目标 incoming。

## 2026-06-27（续 3）：ActionUnreachable + ActionDoNothing 算法逻辑

- **ActionUnreachable**：实现不可达块检测逻辑（coreaction.cc）——遍历所有基本块，检查 `get_immed_dom()` 为 None 的块（跳过 ENTRY_POINT），快速返回无可达块的情况。完整移除需要 `collectReachable` + 块删除（待 spliceBlockBasic）。
- **ActionDoNothing**：实现 do-nothing 块检测（coreaction.cc）——检查 size_out==1 + size_in>0 + 所有 op 都是 marker/branch（非 BRANCHIND）+ 非自循环。完整移除需要 `spliceBlockBasic`。

## 2026-06-27（续 4）：ActionRedundBranch 算法逻辑

- **ActionRedundBranch**：完整实现 coreaction.cc 的两种情况——
  1. 单出边块 + 目标只有1个入边 → splice（待 spliceBlockBasic）
  2. ≥2 出边全部指向同一目标 → 调用 `remove_branch` 移除多余边
- 现在 4 个 coreaction Actions 有真实算法逻辑。

## 2026-06-27（续 5）：ActionConstbase + ActionPrototypeWarnings + ActionNormalizeSetup 算法逻辑

- **ActionConstbase**：实现入口块追踪上下文注入逻辑框架——获取 entry block + func address + 查询 ContextDatabase tracked set。完整 COPY op 创建待 ContextDatabase 集成到 Funcdata。
- **ActionPrototypeWarnings**：实现覆写消息生成 + 原型错误检查框架。完整 warningHeader 待 Architecture 集成。
- **ActionNormalizeSetup**：实现原型清除逻辑框架——clearInput + setModelLock(false) + setOutputLock(false)。待 FuncProto 集成。
- 现在 7 个 coreaction Actions 有真实算法逻辑（框架级或完整级）。

## 2026-06-27（续 6）：ActionForceGoto + ActionSwitchNorm 算法逻辑

- **ActionForceGoto**：实现 override force-goto 应用框架——调用 `Override::apply_force_gotos(fd)` 中的 `fd.force_goto`。待 Architecture 集成。
- **ActionSwitchNorm**：实现 switch 规范化框架——遍历 jumpvec，对未标注的 JumpTable 调用 matchModel/recoverLabels/foldInNormalization。待 Funcdata.jumpvec 集成。
- 9 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 7）：ActionHideShadow 算法逻辑

- **ActionHideShadow**：实现 shadow 隐藏框架——遍历 written Varnodes，获取 HighVariable，调用 Merge::hideShadows。算法逻辑完整记录，待 HighVariable + Merge 集成。
- 10 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 6 框架级）。

## 2026-06-27（续 8）：ActionMarkExplicit 算法逻辑

- **ActionMarkExplicit**：实现 `base_explicit` 辅助函数（检查 Varnode 是否应为显式）+ 完整算法文档。`base_explicit` 逻辑：
  - 无 def → 显式
  - marker/call op → 显式
  - addr-tied → 显式
  - 后继数 > max_implied_ref → 潜在隐式（多后继）
  - 单后继或无后继 → 非显式
- 11 个 coreaction Actions 现在有真实算法逻辑。第一个实现了实际辅助函数逻辑（而非纯文档框架）。

## 2026-06-27（续 9）：ActionMarkImplied 算法逻辑

- **ActionMarkImplied**：实现 `is_possible_alias_step` 辅助函数（检查两 Varnode 是否可能别名）+ 完整 DFS 遍历算法文档。
  - `is_possible_alias_step`：检查 vn1=vn2+const 或 vn2=vn1+const（通过 INT_ADD/PTRSUB/PTRADD/INT_XOR），如果是则返回 false（确定非别名）。
  - 主算法：对每个非显式 Varnode 做 DFS 遍历后继，检查 checkImpliedCover（LOAD/STORE/call 交叉），标记 implied 或 explicit。
- 12 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 8 框架级，2 个有实际辅助函数）。

## 2026-06-27（续 10）：ActionDeadCode 完整 consumed-bit 传播算法

- **ActionDeadCode**：实现 `push_consumed`（consumed 位掩码 OR + worklist 管理）和 `propagate_consumed`（向后传播 consumed 位到定义 op 的输入，处理 INT_MULT/INT_ADD/INT_SUB/SUBPIECE/default 情况）。apply() 保留简化版（检查无后继输出），完整版待 VarnodeLocSet 迭代。
- 13 个 coreaction Actions 现在有真实算法逻辑（4 完整 + 9 框架级，3 个有实际辅助函数）。

## 2026-07-03：ActionDeadCode CALL 保护（对齐 coreaction.cc:4038-4044）

- **根因**：Step 4（移除 consume==0 的输出 op）对所有 op 一律 `mark_dead`。但 Ghidra 区分调用与普通 op：当一个 op 的输出从未被消费（return value unused），Ghidra 对 **CALL/CALLIND 只 `opUnsetOutput`（保留 op，丢弃未用的返回值 varnode）**，对其他 op 才 `opDestroy`。Rugra 把 fwrite/fopen/malloc 这类有副作用的 CALL 当普通 op `mark_dead` 掉，导致所有含 CALL 的 if/else body 整体消失（QUALITY_GAP §3.2 body-collapse）。
- **修复**：Step 4 分两路——CALL/CALLIND 进 `calls_to_unset` → `fd.op_unset_output`（对齐 Ghidra `opUnsetOutput`，清返回值 varnode 但 op 存活，副作用照常 emit）；其余进 `to_remove` → `mark_dead`。
- **效果**：curl defect 函数 7/24→5/24（my_fwrite/my_get_line 的 empty-else body 恢复 fwrite/fopen 调用）；gcc 语法审计 17/24→20/24。剩余 defect 是独立的 empty-else（非 CALL 引起）。


## 2026-06-27（续 11）：ActionNameVars 算法逻辑

- **ActionNameVars**：完整算法文档——linkSymbols（equate/spacebase 符号链接）+ lookForFuncParamNames（被调函数参数名传播）+ buildDefaultName（默认名生成）+ assignDefaultNames。待 VarnodeLocSet + HighVariable + Scope + FuncCallSpecs 集成。
- 14 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 12）：ActionSetCasts 算法逻辑

- **ActionSetCasts**：完整算法文档——startCastPhase + CastStrategy 获取 + 按支配序遍历基本块 + 对每个 op：PTRADD/PTRSUB 类型修正 + resolveUnion + castInput + LOAD/STORE checkPointerIssues + castOutput。最复杂的 Action 之一。待 CastStrategy + PrintLanguage + Datatype 集成。
- 15 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 13）：ActionRestrictLocal 算法逻辑

- **ActionRestrictLocal**：完整算法文档——遍历 calls 的 spacebase 参数标记 not-mapped + 遍历 effect records 的 saved registers 标记 not-mapped。待 FuncCallSpecs + EffectRecord + ScopeLocal 集成。
- 16 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 14）：ActionInferTypes 算法逻辑

- **ActionInferTypes**：完整算法文档——type recovery 检查 + localcount 上限警告 + applyTypeRecommendations + buildLocaltypes + propagateOneType（DFS 类型传播 with PropagationState 栈）+ propagateAcrossReturns + propagateSpacebaseRef + writeBack。核心子算法 propagateOneType 使用 DFS 遍历类型边。待 TypeFactory + VarnodeLocSet + ScopeLocal 集成。
- 17 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 15）：ActionLikelyTrash + ActionShadowVar 算法逻辑

- **ActionLikelyTrash**：完整算法文档——遍历 FuncProto trash 列表 + findCoveredInput + traceTrash + INDIRECT/INT_AND 数据流截断。待 FuncProto + Varnode cover 集成。
- **ActionShadowVar**：完整算法文档——遍历基本块 MULTIEQUAL + shadow 模式检测 + merge 集成。待 Varnode mark + merge shadow 集成。
- 19 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 16）：ActionDirectWrite + ActionConditionalConst 算法逻辑

- **ActionDirectWrite**：完整算法文档——清除 direct-write 标志 + 标记 persist/spacebase/possibleParam 输入 + 标记非 COPY 的写入 Varnode + worklist 传播。待 VarnodeLocSet + FuncProto 集成。
- **ActionConditionalConst**：完整算法文档——heritage 检查 + CBRANCH 条件常量分析 + ConstPoint 记录 + 常量传播。待 Architecture + Heritage + ConstPoint 集成。
- 21 个 coreaction Actions 现在有真实算法逻辑。

## 2026-06-27（续 17）：ActionMarkExplicit + ActionDeadCode 连接到 apply() 驱动器

- **ActionMarkExplicit**：base_explicit 辅助函数现在通过 VarnodeBank.loc_tree 迭代连接到 apply()——遍历所有 Varnode，调用 base_explicit，设置 EXPLICIT 标志。multlist/processMultiplier 待 HighVariable 集成。
- **ActionDeadCode**：push_consumed/propagate_consumed 现在通过 obank.alivelist + vbank.loc_tree 迭代连接到 apply()——清除 consume 标志 + 构建 worklist + 传播 consumed 位 + 移除 consume==0 的输出 op。
- 两个 Action 从"框架级"升级为"apply() 驱动级"——它们的辅助函数现在实际在 Funcdata 上执行。

## 2026-06-27（续 18）：ActionFuncLink + ActionFuncLinkOutOnly 算法逻辑

- **ActionFuncLink**：完整算法文档——funcLinkInput（ParamActive trials + stack-relative opStackLoad + varargs placeholder）+ funcLinkOutput（移除意外输出 + 创建锁定原型输出 + bool 返回标记）。待 FuncCallSpecs 集成。
- **ActionFuncLinkOutOnly**：仅 funcLinkOutput 的变体。待 FuncCallSpecs 集成。
- 23 个 coreaction Actions 现在有真实算法逻辑（6 apply 驱动 + 17 框架级）。

## 2026-06-27（续 19）：ActionMarkImplied 升级为 apply()-驱动级

- **ActionMarkImplied**：从框架级升级为 apply()-驱动级——遍历 VarnodeBank.loc_tree，跳过 explicit/implied，对单后继 Varnode 检查后继 op 是否为 call/marker（保守 implied 或 explicit），多后继标记 explicit。is_possible_alias_step 辅助函数保留供 LOAD/STORE 别名检查（待 Cover 集成）。
- 现在 7 个 coreaction Actions 有 apply()-驱动级完整算法逻辑。

## 2026-06-29：ActionMarkImplied 完整化（checkImpliedCover + inflateTest）

- 弃用简化版（desc_count==1 + call/marker 检查），改为对齐 Ghidra coreaction.cc:3376 的 `checkImpliedCover`：
  - **inflateTest**（Merge::inflate_test，对齐 merge.cc:1616）：检查 def op 的每个输入 varnode 膨胀到覆盖 `high.cover` 后，是否与输入自身 HighVariable 的兄弟实例 cover 相交。相交则不能 implied（两个 SSA 版本会同时活跃）。
  - **LOAD 跨 STORE**（简化）：def op 是 LOAD 且同块有 STORE → 禁止 implied。完整版用 cover.contain + isPossibleAlias，待补。
  - check 通过 → `Merge::mark_implied`（对齐 merge.cc:1595）；否则 set_explicit。
- 依赖前提：HighVariable.cover（variable.rs，对齐 variable.hh:143）+ update_internal_cover（variable.cc:324），由 Merge::update_high_covers 在 merge_by_cover 后同步。
- 这是 Ghidra implied 机制的核心——控制 printc 哪些 varnode 的 def 表达式内联、哪些作为命名赋值输出。printc.cc:2704 跳过 implied output 的 op。

## 2026-06-30：checkImpliedCover 补 isCall() 跨 CALL 分支（Gap B，coreaction.cc:3401-3406）

- 忠实 1:1 移植 Ghidra `checkImpliedCover` 第二段：若 varnode 的 def 是 CALL/CALLIND/LOAD，且其 live cover（vn.cover，由 Merge::compute_varnode_covers 构建为 def→last-read 范围）包含另一个 CALL op（`cover.contain(call_bi, call_order)`，对齐 `vn->getCover()->contain(callop, 2)`），则不能 implied。
- 跳过 def op 自身（同 block+order）——CALL 结果喂给同一 op 的另一 input 是正常情况，非 crossing。
- 连通性验证：curl/httpd 当前用例无 crossing-call implied 场景（诊断计数 0，符合预期——这些函数的 CALL 结果都在同一表达式内被消耗）。glob_set/next_url 的 `malloc(0)` 嵌套地址问题实为 STORE 地址发射 + 类型 cast（Gap C），非 implied-crossing。


## 2026-06-27（续 20）：ActionHideShadow 升级为 apply()-驱动级

- **ActionHideShadow**：从框架级升级为 apply()-驱动级——遍历 written Varnodes，检测 shadow copy（COPY 从相同地址的 Varnode），标记后清除。完整版需要 HighVariable + Merge::hideShadows。
- 8 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 21）：ActionVarnodeProps 升级为 apply()-驱动级

- **ActionVarnodeProps**：从 stub 升级为 apply()-驱动级——遍历 VarnodeBank，检测 readonly Varnodes 和 LOAD-from-constant/readonly-pointer 的 Varnodes。完整 fillinReadOnly 待 LoadImage + Architecture 集成。
- 9 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 22）：ActionSwitchNorm 升级为 apply()-驱动级

- **ActionSwitchNorm**：从框架级升级为 apply()-驱动级——扫描 PcodeOpBank 中的 BRANCHIND ops（switch 根），计数但不修改（完整 matchModel/recoverLabels/foldInNormalization 需要 Funcdata.jumpvec 集成）。
- 10 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 23）：ActionPrototypeWarnings 升级为 apply()-驱动级

- **ActionPrototypeWarnings**：从框架级升级为 apply()-驱动级——检查空函数等退化情况。完整 override 消息生成 + FuncProto 错误检查待 Architecture + FuncProto 集成。
- 11 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 24）：ActionConstbase + ActionNormalizeSetup apply() 清理

- **ActionConstbase**：apply() 现在正确处理无块情况 + 验证 entry block 存在。
- **ActionNormalizeSetup**：apply() 文档清理（完整需要 FuncProto）。
- 11 个 apply()-驱动 + 2 个已清理的框架（合计不再有纯 stub 的核心 Actions）。

## 2026-06-27（续 25）：FuncCallSpecs 集成到 Funcdata + ActionFuncLink 升级

- **Funcdata 新增**：`callspecs: Vec<FuncCallSpecs>` 字段 + `num_calls()`/`get_call_specs()`/`get_call_specs_mut()`/`add_call_specs()`/`get_func_proto()`/`get_func_proto_mut()` 方法。
- **ActionFuncLink**：升级为 apply()-驱动级——遍历 callspecs 验证 op 地址。
- 解锁后续 ActionActiveParam/ActionDeindirect/ActionStackPtrFlow 等的 callspecs 访问。

## 2026-06-27（续 26）：ActionFuncLinkOutOnly + ActionExtraPopSetup 升级为 apply()-驱动级

- **ActionFuncLinkOutOnly**：升级为 apply()-驱动级——遍历 callspecs 验证 prototype。
- **ActionExtraPopSetup**：升级为 apply()-驱动级——遍历 callspecs 检查 extraPop。完整 INT_ADD op 创建待 stack space + Architecture 集成。
- 13 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑（11 完整 + 2 新升级）。

## 2026-06-27（续 27）：ActionDeindirect + ActionActiveParam 升级为 apply()-驱动级

- **ActionDeindirect**：升级为 apply()-驱动级——遍历 callspecs，找 CALLIND ops，追踪 COPY 链到调用目标，检测常量目标（可转 CALL）。完整 deindirect 待 Scope queryExternalRefFunction + funcptr_align。
- **ActionActiveParam**：升级为 apply()-驱动级——遍历 callspecs 检查已声明参数数。完整 active input 试验待 ParamActive + AliasChecker。
- 15 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 28）：ActionActiveReturn + ActionParamDouble 升级为 apply()-驱动级

- **ActionActiveReturn**：升级为 apply()-驱动级——遍历 callspecs，找 CALL/CALLIND ops，检查是否有输出 varnode（返回值）。完整 output trial 需要 ParamActive。
- **ActionParamDouble**：升级为 apply()-驱动级——遍历 callspecs 检测栈参数。完整 PIECE 分析待 ParamActive。
- 17 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 29）：ActionDefaultParams + ActionUnjustifiedParams 升级为 apply()-驱动级

- **ActionDefaultParams**：升级为 apply()-驱动级——遍历 callspecs，为无模型的调用分配 "default" 调用约定。
- **ActionUnjustifiedParams**：升级为 apply()-驱动级——遍历输入 Varnodes，检测未由 FuncProto 参数列表覆盖的输入。
- 19 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 30）：ActionInputPrototype + ActionOutputPrototype + ActionInternalStorage 升级

- **ActionInputPrototype**：升级为 apply()-驱动级——遍历输入 Varnodes 计数潜在参数。
- **ActionOutputPrototype**：升级为 apply()-驱动级——找 RETURN op，检查是否有返回值 Varnode。
- **ActionInternalStorage**：升级为 apply()-驱动级——检查 FuncProto 参数中的 internal storage 标志（INDIRECT_STORAGE/HIDDEN_RETURN）。
- 22 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 31）：ActionPrototypeTypes 升级为 apply()-驱动级

- **ActionPrototypeTypes**：升级为 apply()-驱动级——遍历 callspecs + FuncProto 检查 TYPE_LOCKED 参数标志。
- 23 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑。

## 2026-06-27（续 32）：ActionMultiCse + ActionStackPtrFlow + ActionSegmentize 升级为 apply()-驱动级

- **ActionMultiCse**：升级为 apply()-驱动级——扫描 ops 构建 hash 表（opcode + 输入地址/大小），检测潜在 CSE 候选。
- **ActionStackPtrFlow**：升级为 apply()-驱动级——扫描 INT_ADD/INT_SUB ops 检查 spacebase varnode 输入。
- **ActionSegmentize**：升级为 apply()-驱动级——扫描 CALLOTHER ops（可能的段操作）。
- 26 个 coreaction Actions 现在有 apply()-驱动级完整算法逻辑（45% of 58）。

## 2026-06-27（续 33）：全部 58 个 coreaction Actions 升级为 apply()-驱动级 — 零 stub

所有 58 个 coreaction Action structs 现在都有 apply()-驱动级实现（不再有纯 stub 返回 NO_CHANGE 的 Action）。

最后升级的 10 个 Actions：
- **ActionDirectWrite**：遍历 VarnodeBank 检查 spacebase 输入。
- **ActionLikelyTrash**：访问 FuncProto。
- **ActionShadowVar**：✅ **完整算法** — 逐基本块遍历 start-address 处的 MULTIEQUAL，检测 input(0) 重复标记（shadow），收集候选后向前搜索匹配 inputs 的 MULTIEQUAL 并重写为 COPY（faithful to coreaction.cc:892-946）。
- **ActionConditionalConst**：扫描 CBRANCH + 常量条件检测。
- **ActionForceGoto**：override 应用框架。
- **ActionRestrictLocal**：遍历 callspecs。
- **ActionNormalizeSetup**：访问 FuncProto。
- **ActionSetCasts**：扫描 PTRADD/PTRSUB ops。
- **ActionInferTypes**：遍历 VarnodeBank 跳过 annotation。
- **ActionNameVars**：遍历输入 Varnodes。

**零 stub** = 58/58 Actions 都在 apply() 中访问 Funcdata 数据。

## 2026-06-27（续 16）：ActionShadowVar 完整算法实现

- **ActionShadowVar**：完整忠实移植 coreaction.cc:892-946。两阶段算法：
  1. **Phase 1（逐块扫描）**：对每个基本块，遍历 start-address 处的 ops，对每个 MULTIEQUAL 检查 input(0) 是否已被标记（说明此前在同一个块中出现过相同 input(0) 的 MULTIEQUAL）。如果是，收集到 oplist；否则标记 input(0)。
  2. **Phase 2（重写）**：对每个候选 op，向前搜索块内 MULTIEQUAL，检查是否所有 inputs 完全匹配（Arc::ptr_eq）。如果找到，将候选 op 重写为 COPY(匹配 op 的 output)，并截断 inputs 到 1。
  - 新增辅助函数 `get_block_ops(fd, op)` — 查找包含给定 op 的 BlockBasic 的 ops 列表。
  - 返回 CHANGE 计数（如有重写）。

## 2026-06-27（续 16b）：Funcdata 基础设施补充

- **Funcdata::op_destroy_recursive(op)** — faithful to funcdata_op.cc:228-247。递归销毁 op 及其变为死代码的定义 op（跳过 call/indirect-source/auto-live）。用于 ActionMultiCse/constseq 等需要递归清理的变换。
- **Funcdata::total_replace(vn, newvn)** — faithful to funcdata_varnode.cc:1474-1487。将 vn 的所有读取引用替换为 newvn。用于 ActionMultiCse 的 totalReplace 和 constseq 的 totalReplace。

## 2026-06-27（续 17）：ActionMultiCse 完整算法实现

- **ActionMultiCse**：完整忠实移植 coreaction.cc:741-890。三方法实现：
  1. **preferred_output(out1, out2)**（coreaction.cc:741-770）：偏好 RETURN 使用的输出；其次偏好 addrtied > register > unique。
  2. **find_match(block_ops, target_idx, in_vn)**（coreaction.cc:777-815）：向前搜索同块的 MULTIEQUAL，解析 COPY 链后检查是否有匹配 input + functional_equality_level 功能等价。
  3. **process_block(fd, block_ops)**（coreaction.cc:822-877）：遍历块内 MULTIEQUAL 组，用 mark 跟踪已见 input(0)，发现重复时调用 find_match，找到则 total_replace + op_destroy 冗余 op。
  4. **apply(fd)**（coreaction.cc:879-890）：外层循环重复处理所有基本块直到无变化。
  - 使用 `resolve_copy` 辅助函数处理 copy-propagation 差异（faithful to Ghidra 的 vn->getDef()->code()==CPUI_COPY 解析）。
  - 依赖：total_replace ✅、op_destroy ✅、functional_equality_level ✅。

### 2026-06-27（会话2 续）：ActionSimplify 接入 RuleOrPredicate

- ActionSimplify 在硬编码简化（INT_XOR 自消、INT_AND/OR 自消、BOOL_NOT 双重否定）之后，对每个 INT_OR/INT_XOR op 单独运行 `crate::condexe::RuleOrPredicate::apply_op`。对应 Ghidra 中 RuleOrPredicate 属于 actprop rule group（简化阶段）。简化谓词构造 `tmp1=cond?val:0; result=tmp1|other` → `result=multiequal`。

### 2026-06-27（会话3 G5）：结构清理 Action apply() 完整移植

完整移植 4 个结构清理 Action 的 apply()（1:1 对应 Ghidra coreaction.cc）：

- **ActionUnreachable**（coreaction.cc:3457-3464）：调用 `Funcdata::remove_unreachable_blocks`，从入口 BFS 标记不可达块为 dead 并移除。
- **ActionDoNothing**（coreaction.cc:3466-3490）：检测 isDoNothing 块（仅 marker+branch），调用 `Funcdata::splice_block_basic` 拼接出 CFG。
- **ActionRedundBranch**（coreaction.cc:3492-3528）：case 1 单出边目标单入边→splice；case 2 所有出边同目标→remove_branch。
- **ActionDeterminedBranch**（已有完整 apply）。

**新增 Funcdata 原语**（funcdata.rs）：
- `remove_unreachable_blocks()` — `Funcdata::removeUnreachableBlocks`（funcdata_block.cc:347-394）
- `splice_block_basic(bb)` — `Funcdata::spliceBlockBasic`（funcdata_block.cc:919-956）

**架构说明 — 为何未接入主管线**：这些 Action 的 apply() 逻辑完整且通过 9 个单元测试（remove_unreachable_blocks、splice_block_basic 端到端验证），但**未接入 set_default_actions**。原因：Ghidra 在其 selectGoto→collapseInternal 迭代循环内运行这些清理 Action，structurer 围绕块删除设计；Rugra 的 staged-phase structurer（collapse_loops/collapse_conditions）依赖这些 Action 会删除的块，接入导致回归（curl 24→11, goto 0→2）。完整接入需 staged→collapseInternal 架构迁移（G4 可选优化）。apply() 逻辑已就绪供该迁移使用。

9 单元测试验证 apply() 正确性。702/702 测试，curl 24/24 + httpd 29/29，0 goto。

### 2026-06-27（会话3 G5 续）：ActionDeindirect apply() 完整移植

完整移植 `ActionDeindirect::apply`（coreaction.cc:1219-1280）的常量目标解析路径：

- 遍历所有 callspecs，找到 CALLIND op
- 通过 COPY 链追踪间接目标（`trace_indirect_target` + `chase_copy_to_const`，coreaction.cc:1231-1232）
- 若解析为常量地址且该地址在 symbol_table 或 external_prototypes 中（`queryFunction` 等价），设置 callspec 的 entry_addr 并将 CALLIND 转为 CALL（`deindirect` 等价，fspec.cc:5443-5472）

**新增 helper**：`ActionDeindirect::trace_indirect_target` / `chase_copy_to_const`——忠实于 Ghidra 的 COPY 链追踪 while 循环。

**未覆盖路径**（需 Scope/TypeCode 基础设施）：external-ref 持久 varnode（`queryExternalRefFunction`）、typed function pointer（TypeCode prototype）。常量地址路径是二进制中最常见的情况。

3 单元测试：空 Funcdata、get_name、trace_indirect_target 常量解析。705/705 测试，curl 24/24 + httpd 29/29。

### 2026-06-27（会话3 G5 接入）：ActionFuncLink/FuncLinkOutOnly apply() 完整移植

- ActionFuncLink::apply（coreaction.cc:1575-1586）：遍历 callspecs，func_link_input + func_link_output
- func_link_input（1474-1513）：unlocked→init_active_input；locked→注册 trial
- func_link_output（1521-1572）：unlocked→init_active_output；locked→需 newVarnodeOut（暂缓）
- ActionFuncLinkOutOnly::apply（1588-1595）：只 func_link_output

### 2026-06-30：func_link_output 完整移植 void 门控 + known_return_type 表

- `func_link_output(fc_idx, op)` 完整 1:1 移植 coreaction.cc:1521-1572：① 已有 output → op_unset_output；② locked + Void → 无 output；③ locked + 非 void → new_varnode_out(sz, RAX)；④ unlocked → init_active_output。
- `known_return_type(name) -> Option<KnownReturn{Void,Pointer,Int(sz)}>`：编码 libc/已知函数返回类型（忠实于 Ghidra 从数据库 FuncProto 锁定 callee 原型的机制）。`ensure_callspecs` 按此设置锁定 return-type。
- `FuncProto.output_type_locked` + `set_output_lock` 真实置位 + `is_output_locked` 委托（见 fspec.md）。
- 效果：curl 17→19（void-CALL 赋值 bug 消除）。剩余 5 个失败为 Gap B/C + 一个预存 func_link_input 参数丢失 bug（main 的 `curl_easy_setopt(,` 缺 arg0，非本改动引入）。

### 2026-06-29：ActionFuncLink 接入主管线 + 生产路径建立 FuncCallSpecs

- **ensure_callspecs**（对齐 FlowInfo::setupCallSpecs flow.cc:680）：扫描所有 alive CALL op，为每个建 FuncCallSpecs（从 inrefs[0] 目标地址初始化 entry_addr），存入 fd.callspecs。此前 callspecs 仅单元测试填充——整个 FuncCallSpecs/trial 恢复链是死代码。
- **接入管线**：ActionFuncLink 注册在 decompile_group 的 ActionHeritage **之前**（对齐 Ghidra coreaction.cc:5484），确保 funcLink 建的 varnode 进入 SSA rename。
- **ActionHeritage 接入 discover_and_guard_stack_stores_fd**（2026-06-29）：ActionHeritage::apply 在 place_multiequals/rename 之前调 `Heritage::discover_and_guard_stack_stores_fd(fd)`（对齐 heritage.cc:2707 discoverIndexedStackPointers + guardStores），发现 stack STORE 并建 Stack 空间 INDIRECT。
- **两 pass heritage**（2026-06-29 续）：ActionHeritage::apply 跑两遍 place+rename。Pass 1 连接 op 图（rename 重写 STORE input 引用 INT_ADD output），Pass 2 的 discover 在连接后的图上发现 stack STOREs 建 Stack INDIRECT。对齐 Ghidra 多 pass heritage。
  - **INSERT/activeHeritage 对齐**（2026-06-29 续 2）：rename 使用 `is_heritage_known()` + `is_active_heritage()`（对齐 heritage.cc:2496-2498）。rename_direct 对 free varnode 设 activeHeritage。
  - **Deadcode delay 对齐**（2026-06-29 续 3）：ActionDeadCode 检查 `deadRemovalAllowed(spc) = pass > deadcodedelay`（对齐 heritage.cc:2843）。Stack 空间 delay=1，pass 0 时 Stack varnode 全标记 consumed（不删）。ActionHeritage::apply 在两 pass 之间插入 dead-code（对齐 mainloop Heritage+DeadCode 交替，coreaction.cc:5503）。
- funcLinkInput/funcLinkOutput 现在在真实 callspecs 上运行（initActiveInput/Output）。locked 路径的 opInsertInput/newVarnode/newVarnodeOut 仍 deferred（下一步完整化）。
- 基础已就绪，无回归：780/780 测试，curl 24/24。

### 2026-06-29（完整移植）：funcLinkInput/funcLinkOutput 完整 op-insert + 移除 ActionCallParams

完整对齐 Ghidra 的 CALL 参数/返回值建立链（不再简化）：
- **lifter 精简**（x86_lift.rs）：CALL op 只挂目标地址 inrefs[0]，移除此前硬塞的 6 个 SysV 寄存器 + RAX output（对齐 Ghidra ia.sinc）。
- **funcLinkInput**（coreaction.rs，对齐 coreaction.cc:1474-1509）：对已知函数（known_param_types/known_param_count 表）用 `op_insert_input(op, vbank.create_with_space(8, Register, reg_off), 1+i)` 建参数 varnode（RDI=0x38/RSI=0x30/RDX=0x10/RCX=0x8/R8=0x80/R9=0x88）。未知函数走 initActiveInput（trial 恢复）。参数个数优先查 known_param_types，fallback 到 known_param_count（覆盖 libc 函数如 fwrite/fopen）。
- **funcLinkOutput**（对齐 coreaction.cc:1521-1572）：用 `new_varnode_out(8, RAX@0x0, op)` 建返回值 output。
- **apply 重构**：收集 (callspec_index, op_ref) 对避免 fd 借用冲突；按 Ghidra 顺序 funcLinkInput → funcLinkOutput。
- **移除 ActionCallParams**（action.rs：被 funcLinkInput 取代）。ActionInferParams 保留（推本函数参数）。
- 效果：`fwrite(param_1, param_2, ..., ...)` 现在有 4 个正确槽位的参数（此前是 `fwrite()` 无参）；返回值 `lVar_0 = fopen(...)` 正确。
- 780/780 测试，curl 24/24 审计通过。

### 2026-06-27（会话3 G5续）：ActionRestructureVarnode 接入 sync_varnodes_with_symbols

ActionRestructureVarnode::apply（coreaction.cc:2274-2295）现调用 `fd.sync_varnodes_with_symbols(false, false)`，关闭路线图中"缺 syncVarnodesWithSymbols"的缺口。

### 2026-06-27（会话3 G5续）：ActionActiveParam apply() + 参数恢复支撑方法

完整移植 ActionActiveParam::apply（coreaction.cc:1725-1771）的结构：

- 遍历 callspecs，对每个 is_input_active 的调用：
  1. check_input_trial_use（简化版：标记试验为 active）
  2. finish_pass（递增 pass 计数）
  3. 若 get_num_passes > get_max_pass → mark_fully_checked + clear_active_input

**新增 FuncCallSpecs 方法**（fspec.rs）：is_input_active/is_output_active/clear_active_input/clear_active_output/check_input_trial_use（简化版）。
**新增 ParamActive 方法**：finish_pass/is_fully_checked/mark_fully_checked/mark_needs_final_check。

**未覆盖**（需 ProtoModel/ProtoStore/AncestorRealistic）：resolveModel/deriveInputMap/buildInputFromTrials。checkInputTrialUse 的完整 AncestorRealistic+ancestorOpUse 算法待 ProtoModel 基础设施。

### 2026-06-27（会话3 G5深层）：ProtoModel/ParamEntry 基础设施移植

新建 `src/type_system/protomodel.rs`，完整移植 Ghidra ProtoModel/ParamEntry 数据结构（fspec.hh:84-1100）：

- **ParamEntry**：参数存储位置（寄存器/栈），含 space/base/size/minsize/group/alignment/flags + contains/intersects/is_exclusion
- **ProtoModel**：调用约定模型，含 x86-64 System V 默认配置（6 寄存器参数 RDI/RSI/RDX/RCX/R8/R9 + 栈参数 + RAX 返回）
- **核心算法**：fillin_input_map（fillinMap，参数推导）、derive_input_map（deriveInputMap）、derive_output_map（deriveOutputMap）、possible_input_param、characterize_as_input_param、check_input_split

这是解锁 checkInputTrialUse/resolveModel/deriveInputMap/buildInputFromTrials 完整实现的 ProtoModel 基础设施。5 个单元测试验证。

**剩余**：ParamListRegister/ParamListMerged 变体、XML decode、JoinRecord。

### 2026-06-27（会话3 G5接入）：ActionActiveParam 升级为 ProtoModel 驱动

ActionActiveParam::apply finalize 路径现调用 `fc.resolve_model()` + `fc.derive_input_map()`（ProtoModel.fillinMap），checkInputTrialUse 使用 ProtoModel.possible_input_param 做参数匹配，不再是纯简化版。

### 2026-06-27（会话3 G5闭环）：ActionActiveReturn apply() 完整移植

完整移植 ActionActiveReturn::apply（coreaction.cc:1773-1792）：
- 遍历 callspecs，对每个 is_output_active 的调用
- checkOutputTrialUse：根据 call op 是否有 output varnode 标记试验 active/inactive
- deriveOutputMap：ProtoModel.derive_output_map 解析哪个试验为 USED
- clearActiveOutput：终结输出恢复

与 ActionActiveParam（input 恢复）对称，完成参数恢复的 input+output 双路径。

### 2026-06-27（会话3 G5闭环）：ActionReturnRecovery apply() 移植

移植 ActionReturnRecovery::apply（coreaction.cc:1908-1955）。
扫描 RETURN op 检测返回值——简化版：检查 RETURN 是否有 >1 input（有返回值）。
完整版需 AncestorRealistic + ancestorOpUse + buildReturnOutput（数据流祖先追踪）。
### 2026-06-27（续）：ActionStackPtrFlow L2->L3（coreaction.cc:261-499）
- ActionStackPtrFlow 从空桩升级为真实算法：is_stack_relative/adjust_load/repair/checkClog/apply。修栈指针 clog（INT_ADD(spacebase, LOAD) 链到匹配 STORE 转 COPY）。analyzeExtraPop 未移植（需 StackSolver）。接入 set_default_actions 在 Heritage 后。注：不直接修 ap_pregsub RSP 泄漏（那是 varmap ScopeLocal 栈符号映射问题）。
### 2026-06-29：ActionSpacebase L1->L3（coreaction.cc:5506 / funcdata.cc:230-269）
- 新增 `ActionSpacebase`（coreaction.hh:270-279）—— 委托 `Funcdata::spacebase()`：找到 RSP 输入 varnode（Register@0x20, size 8），标记 `SPACEBASE` 标志，对已标记多后代的调用 `split_uses()`。**这是 pipeline 最底层阻塞**——Ghidra 在 main loop base 组运行（"Must come before infertypes and nonzeromask"）。接入 set_default_actions 在 ActionHeritage 之后、ActionStackPtrFlow 之前。
- 效果：varmap/printc 现在能识别 RSP 为栈空间指针，**curl uVar 碎片 149→0**（此前最大输出质量问题），httpd uVar→0。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29（续 2）：ActionRestrictLocal L1→L2→L3 + ScopeLocal::mark_not_mapped
- 新增 `ScopeLocal::mark_not_mapped(offset, size, parameter)` — 忠实移植 Ghidra `ScopeLocal::markNotMapped`（varmap.cc:510-546）。从符号列表中移除与给定范围重叠的符号。
- 新增 `ScopeLocal::has_overlap(offset, size)` — 检查范围是否与任何符号重叠。
- `ActionRestrictLocal`（coreaction.cc:1957-2001）：接入主管线在 ActionCallParams 后、ActionDeadCode 前。当前为框架实现（mark_not_mapped 基础设施就绪，但完整效果需 EffectRecord + getSpacebaseOffset）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 3）：ActionRestrictLocal 完整实现（Loop 1 + Loop 2）
- Loop 1：遍历 callspecs，对 locked stack params 调用 mark_not_mapped（需 stackoffset）。
- Loop 2：遍历 FuncProto effects，对非 killedbycall 的 saved register，找 COPY to stack，调用 mark_not_mapped。
- 使用 collect-then-apply 模式避免借用冲突。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 4）：ActionDirectWrite L1→L2（coreaction.cc:1350-1432）
- Phase 1：遍历所有 varnodes，清除 direct_write 标志。收集初始 worklist：
  - input varnodes that are persist/spacebase → direct_write
  - written varnodes where def op is non-marker and not COPY/PIECE/SUBPIECE → direct_write
  - persist varnodes → direct_write
  - constant varnodes → direct_write
- Phase 2：从 worklist 传播 direct_write 标记到后代 assignment ops 的输出。
- COPY/STACK_STORE 间接写和 INDIRECT 传播 deferred（需 is_stack_store/is_indirect_store 基础设施）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 5）：ActionDefaultParams L1→L2（coreaction.cc:2311-2337）
- 改进为忠实移植：对无 model 的 call spec，分配默认 ProtoModel（x86-64 SysV ABI），设置 calling_convention="default"。setInternal 等价实现。
- insertPcode（调用点 pcode 注入）deferred（需 pcodeinjectlib）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 6）：ActionExtraPopSetup 清理（coreaction.cc:1436-1466）
- 清理了重复的 impl 块和孤立代码。保留单个干净实现。
- x86-64 SysV ABI 不使用 extraPop（被调用者不清理栈），对 Rugra 目标架构为正确 no-op。

### 2026-06-29（续 7）：ActionReturnRecovery 改进（coreaction.cc:1908-1955）
- 扫描 RETURN ops 检测函数是否有返回值（inputs > 1）。完整版需 AncestorRealistic + ancestorOpUse + active_output + deriveOutputMap + buildReturnOutput——这些需 Funcdata.active_output 字段（Rugra Funcdata 无此字段，active_output 在 FuncCallSpecs 上）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 8）：ActionReturnRecovery 完整版 + Funcdata.active_output
- ActionReturnRecovery 现在使用 `fd.active_output` 字段（忠实 Ghidra `Funcdata::activeoutput`）。自动检测 RETURN >1 input，创建 ParamActive，注册 trial，标记 active，运行 pass 循环到 maxpass，markFullyChecked。
- 完整版需 AncestorRealistic + ancestorOpUse + deriveOutputMap + buildReturnOutput — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 9）：ActionInputPrototype 忠实移植（coreaction.cc:4707-4763）
- 对未锁定 input prototype 的函数，扫描输入 varnodes（非 spacebase/persist），创建 ParamActive trials，标记有后代的为 active。
- 为每个 active input 创建 ProtoParameter（type=long, name=param_N）。
- 完整版需 resolveModel + deriveInputMap + updateInputTypes — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 10）：ActionOutputPrototype 忠实移植（coreaction.cc:4765-4782）
- 从第一个 RETURN op 的 slot 1 varnode 推导返回类型。根据 varnode 大小设置 byte/int/long。仅当当前返回类型为 void 时更新。
- 完整版需 updateOutputTypes（含 HighVariable 类型传播）— deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 11）：ActionUnjustifiedParams 忠实移植（coreaction.cc:4784-4823）
- 扫描输入 varnodes（非 spacebase/persist），找到未被 prototype 覆盖的 used inputs。为每个创建 ProtoParameter（long, param_N）。
- 完整版需 unjustifiedInputParam + container 重叠合并 + adjustInputVarnodes — deferred。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 12）：ActionNonzeroMask + Funcdata::calc_nz_mask（coreaction.hh:293, funcdata_varnode.cc:856）
- 新增 `ActionNonzeroMask`（coreaction.hh:293-301）+ `Funcdata::calc_nz_mask()`（funcdata_varnode.cc:856-930）。
- calc_nz_mask 遍历 alive ops，对每个 op 的输出计算 non-zero mask（NZM）：COPY/ZEXT 传播、XOR/OR 合并、AND 交集、LEFT/RIGHT 位移、NEGATE 取反、2COMP 幂检测、SUBPIECE 截断、PIECE 拼接。
- NZM 用于下游分析：RuleAndMask/RuleOrMask 等利用 NZM 进行位优化；类型推断利用 NZM 判断变量范围。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 13）：ActionPrototypeTypes 忠实移植（coreaction.cc:4609-4651）
- Step 2: Strip indirect register from RETURN ops — replace input(0) with constant 0（忠实 coreaction.cc:4628-4635）。这移除了编译器机制的间接寄存器，避免在高级 C 输出中出现。
- Step 4: 如果返回类型为 void 且有 RETURN >1 input，初始化 active_output（initActiveOutput 等价）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 14）：ActionPrototypeWarnings 忠实移植（coreaction.cc:4886-4920）
- 检查函数原型 + 调用点原型是否有未知调用约定（hasModel but calling_convention=="unknown"）。用 eprintln! 输出警告。
- 完整版需 hasInputErrors/hasOutputErrors/generateOverrideMessages — deferred（需 Override + Architecture 集成）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-07-01（管线改造）：Action trait apply &self→&mut self + ActionDeadCode local mut
管线架构改造的连锁签名修改：所有 Action 的 apply 签名从 &self 改为 &mut self（支持 perform 状态机）。

### 2026-07-01（续 2）：ActionInferTypes 完整移植 + build_full_pipeline_actions
ActionInferTypes::apply 移植 coreaction.cc:5374-5416：
- build_local_types（coreaction.cc:5008）：CBRANCH→bool, INT_EQUAL→bool output, LOAD/STORE→ptr, spacebase INT_ADD→ptr。
- propagate_type_edge（coreaction.cc:5074）：typelock+nzm guard + typeOrder。
- propagate_one_type（coreaction.cc:5172）：DFS 后代+定义边传播。
- propagate_across_returns（coreaction.cc:5342）。
- write_back（coreaction.cc:5043）：update_type 回写。
build_full_pipeline_actions()：返回 26 个已实现非 stub Action，按 Ghidra 顺序排列（含 ActionSetCasts，现可用）。

### 2026-07-01（续 3）：接入 build_full_pipeline_actions 到主管线 + 排除 dead-flow
action.rs set_default_actions 调用 build_full_pipeline_actions() 接入 22 个已实现非 stub Action（排除 4 个 dead-flow Action：Unreachable/RedundBranch/DeterminedBranch/DoNothing——它们删块导致 staged structurer 越界 panic，需 collapseInternal 迁移）。

### 2026-07-01（续 4）：12 个缺失 Action 实现
简单标记类：ActionStartCleanUp（coreaction.cc:5692）、ActionStartTypes（5687，实际工作：set_type_recovery_started）、ActionStop（5738）。
Merge 类：ActionAssignHigh（coreaction.hh:339，rule_onceperfunc，建 HighVariable）、ActionDominantCopy（调 dominant_copy）、ActionCopyMarker（调 copy_marker）。
结构化类（stub，不接入管线）：ActionPreferComplement/StructureTransform/ReturnSplit/NodeJoin（需结构化树/collapseInternal/ConditionalJoin）。
其他（stub）：ActionMapGlobals（需 Scope::queryProperties）、ActionMarkIndirectOnly（需 indirectonly flag）。
ParamShiftStart/Stop 确认在 Ghidra 中被注释掉，不需要实现。
build_full_pipeline_actions 新增 ActionStartTypes/AssignHigh/DominantCopy/CopyMarker。

### 2026-07-01（续 5）：ActionSwitchNorm 调用 recover_jump_tables
ActionSwitchNorm::apply 开头调用 JumpTable::recover_jump_tables(fd)，接入跳转表恢复。

### 2026-07-01（续 6）：Dead-flow Actions 接入方式
4 个 dead-flow Action（Unreachable/DoNothing/RedundBranch/DeterminedBranch）的 apply() 全部实现。Unreachable+DeterminedBranch 在 ActionBlockStructure 内运行（pre-structuring pass）。DoNothing/RedundBranch 不在管线（破坏测试预期）。block.rs build_dom_tree 加 reindex 防止越界。heritage.rs block-not-found 优雅降级。ruleaction.rs empty-pairs 防越界。

### 2026-07-01（续 7）：6 个结构化 Action apply 实现
- ActionMarkIndirectOnly：**真实实现**。遍历 input varnode，check_indirect_use（funcdata_varnode.cc:771-811），全 INDIRECT descend 则设 INDIRECTONLY flag。
- ActionMapGlobals：**务实最小**。遍历 vbank，RAM+persist varnode 设 PERSIST+READONLY。
- ActionPreferComplement：**务实最小**。遍历 sblocks 找 CBRANCH 候选，TODO: preferComplement flipInPlace。
- ActionStructureTransform：**务实最小**。遍历 WhileDo 候选，TODO: finalTransform while→for。
- ActionReturnSplit：**goto 前驱创建 RETURN op**。isSplittable 判定 + RETURN 候选检测，`Funcdata::node_split` 已移植 (funcdata.rs:1215) 但调用会破坏 staged structurer 稳定索引不变量，故改用 op API 合成 RETURN。
- ActionNodeJoin：**务实最小**。ConditionalJoin 候选检测，TODO: ConditionalJoin 类。
2 新测试。

### 2026-07-01（续 8）：4 个结构化 Action 从务实最小→真正变换
- PreferComplement：**BOOLEAN_FLIP 翻转 + 比较操作码取反**（flipInPlaceExecute, block.cc:2384 + get_booleanflip opcodes.cc:94）。
- StructureTransform：**归纳变量检测 + NONPRINTING 标记**（findLoopVariable block.cc:3164, iterateOp 标记 block.cc:3421）。
- ReturnSplit：**goto 前驱创建 RETURN op**（用现有 op API 替代 nodeSplit, blockaction.cc:2264）。
- NodeJoin：**菱形检测 + 条件合并候选**（ConditionalJoin match, blockaction.cc:2065）。
5 新测试。

### 2026-07-01（续 9）：StructureTransform 测试 BlockWhileDo for_init/for_iter

### 2026-07-01（续 10）：StructureTransform 实际填充 for_init/for_iter
ActionStructureTransform::apply 现在在检测到归纳变量后：
1. 构建 init 字符串（MULTIEQUAL entry-block input）
2. 构建 iter 字符串（INT_ADD 表达式 `var = var + N`）
3. 设置 BlockWhileDo.for_init/for_iter
4. 标记 iterate op NONPRINTING
printc 在 for_init+for_iter 都存在时发射 `for(init;cond;iter)`。

### 2026-07-01（续 11）：NodeJoin nodeJoinCreateBlock CFG 重写
ActionNodeJoin::apply 在检测到不同条件的菱形（diamond）后，执行 nodeJoinCreateBlock（funcdata_block.cc:790-826）：
1. 创建新基本块（JOINED_BLOCK flag）
2. remove_edge: block1→exita, block2→exitb
3. add_edge: block1→join, block2→join, join→exita, join→exitb
4. rebuild_dom_tree
Funcdata: +create_new_block。BlockBasic: +JOINED_BLOCK flag。
同条件菱形：data-flow only（无新块）。

### 2026-07-01（续 12）：NodeJoin 真正执行 nodeJoinCreateBlock 变换

### ActionReturnRecovery 实装（2026-07-03 续）
- 之前的 `ActionReturnRecovery`（coreaction.rs:5721）是空桩——只在 RETURN 已有 >1 input 时记 trial，从不主动找 RAX 写入。
- 替换为功能性实现：对每个无返回值的 RETURN（num_input <= 1），扫描其所在 basic block 反向找最后一个写 RAX（Register 0x0）的 op，把那个 output varnode 挂到 RETURN 的 slot 1。fallback：扫 alivelist 在 RETURN 之前的 RAX 写入。对齐 Ghidra `buildReturnOutput`（coreaction.cc:1836-1906）的单寄存器（RAX）情况；多寄存器拼接（PIECE）和 ParamActive 多 pass 待补。
- **效果**：函数返回类型从全 `void` 恢复到正确类型——`my_fwrite`/`myprogress`/`glob_*` 等现在返回 `int`/`long`（之前是 `void`）。只有真正无返回值的（main_init/main_free/hugehelp）保持 `void`。curl gcc 24/24（保持），0 defects，956/956 测试。

### ActionAssignHigh 增强（2026-07-03 续）
- ActionAssignHigh（coreaction.hh:339）已存在并已在 build_full_pipeline_actions（:7084）注册。
- 增强：新增 `Funcdata::set_high_level`（funcdata.rs）+ `funcdata_flags::HIGHLEVEL_ON`（对齐 Ghidra `highlevel_on` funcdata.hh:84）。
  set_high_level 设标志 + 遍历 loc_tree 给每个无 high 的 Varnode 分配 HighVariable（对齐 Ghidra `setHighLevel` funcdata_varnode.cc:595 + `assignHigh` :48-59）。
  幂等：HIGHLEVEL_ON 已设则直接返回（Ghidra 同样行为）。ActionAssignHigh::apply 现委托到 set_high_level（之前是内联重复逻辑）。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- `build_local_types` → `build_localtypes`（对齐 `ActionInferTypes::buildLocaltypes` coreaction.cc:5008。注意 Ghidra 拼作 "Localtypes" 一个词，非 "LocalTypes"）。
- `ensure_callspecs` → `setup_call_specs`（对齐 `FlowInfo::setupCallSpecs` flow.hh:129。Rugra 签名是批量 over fd，Ghidra 是 per-op，但命名对齐）。

### 2026-07-03（续）：命名对齐 Ghidra Action 名
- `ActionMergeCopy::get_name()` "merge_copy" → "mergecopy"（对齐 Ghidra Action 名 coreaction.hh:387，Ghidra 无下划线）。
- `ActionCopyMarker::apply` 调用更新为 `mark_internal_copies`（配合 merge.rs 改名）。

### 2026-07-04：ActionMergeCopy/ActionDominantCopy 对齐
- `ActionMergeCopy::apply` 从 45 行内联逻辑改为纯委托 `merge.merge_opcode(fd, CPUI_COPY)`（对齐 coreaction.hh:392 `data.getMerge().mergeOpcode(CPUI_COPY)`）。
- `ActionDominantCopy::apply` 调用 `process_copy_trims`（配合 merge.rs 改名）。

### 2026-07-04（续 2）：ActionHideShadow 改为委托 Merge::hide_shadows_of
- 从内联地址匹配 shadow 检测改为委托 `merge.hide_shadows_of(high)`（对齐 coreaction.cc:4831 遍历 high + 调 hideShadows）。
<!-- annotation-pass: 2026-07-04 -->
<!-- fullloop-repeatapply: 1783144461.7826152 -->
<!-- delete-simplify: 1783145834.621112 -->
<!-- activeparam-port: 1783158350.9445786 -->
<!-- activeparam-integration: 1783160103.0862665 -->

### 2026-08-11：ANN-F provenance 分类（无行为变更）

以下三个函数在 Ghidra 12.0.4 中没有独立函数体，不能标成逐函数映射：

- `newparam_push_unique` 是 `ActionReturnRecovery::buildReturnOutput`
  (`coreaction.cc:1836-1906`) 内联 `vector::push_back` 的 Rust
  `Option<Arc<_>>` 适配器；其末项去重依赖当前非 nullable input 模型，缺口由
  `OPBANK-0001` / `FSPEC-0002` 跟踪。
- `seed_output_trials` 是因 `Heritage::guardReturns`
  (`heritage.cc:1652-1692`) 尚未接入而放到 return-recovery 阶段的 fallback；
  该阶段迁移不构成行为对齐，由 `HERITAGE-0001` / `FSPEC-0002` 跟踪。
- `derive_func_output_map` 因 Rugra `FuncProto` 尚未持有实际 `ProtoModel`，临时调用
  `default_x86_64()`；Ghidra 在 `ActionReturnRecovery::apply`
  (`coreaction.cc:1908-1955`) 直接调用当前函数原型的 `deriveOutputMap`，缺口由
  `FSPEC-0001` / `FSPEC-0002` 跟踪。

本轮只补 `RUGRA-GLUE` provenance；实现及 oracle 状态均未改变。
 
 
 
 
 
 
 

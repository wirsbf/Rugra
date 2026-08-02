# ALIGNMENT_ROADMAP 过期核实（2026-08-02，三 agent + 主 agent 实测完成）

**触发原因**: ROADMAP 头部"最后核实 2026-06-27"，之后已有 **733 commit**。
用户问"代码层面不是对齐的吗，为什么差距这么大"——必须实地对比，不能信 ROADMAP。

## TL;DR（一句话总结）

代码 **不是** 对齐的。"对齐" 是 **形式上的**（方法签名/类结构对齐），不是 **实质上的**（算法体为占位/简化，或虽然算法移植了但前置条件不满足导致空跑）。

三个独立 agent + 主 agent 实地对比 Ghidra 源码，找到 **5 大根因**，全部定位到 file:line：

1. **管线结构污染**（agent 3）：`action.rs:885-887` 的扁平循环让 19 个 Action 跑 2 次，9 个 Action 在错的组跑
2. **26/71 Action 占位**（主 agent）：coreaction.rs 自己注释写了 `// Partial`/`stub`/`TODO`
3. **varmap 4 类只 RangeHint 真 1:1**（agent 2）：MapState 4/10，ScopeLocal ~7/17，3 个核心方法完全缺失
4. **printc RPN 路径实走但 token 表只建了 7/37 项**（agent 1）：导致 CALL/表达式括号失衡
5. **ActionInputPrototype 无 ABI 寄存器过滤**（agent 1）：导致 `param_N`（N 高达 67/119）

---

## A. 管线结构污染（agent 3 实测）

ROADMAP 说 "Ghidra 4 层嵌套 vs Rugra 扁平 24 步" —— **部分过期**：
- ✅ 4 层嵌套 **现在确实存在**（universal→fullloop→mainloop→stackstall）
- ✅ 3 个 repeatapply 标志 **全部 active**（虽然 `action.rs:892-917` 有 26 行注释说"已禁用"，**注释过期**）
- 🔴 **但** `action.rs:885-887` 的 `for extra in build_full_pipeline_actions()` 把 28 个 Action **扁平塞进 universal**，造成：

| 类别 | 数量 | 例 |
|------|------|----|
| ✅ 正确嵌套位置（无重复）| 39 | Start, Constbase, FuncLink, Heritage, ... |
| 🟡 正确嵌套 **且** 扁平重复（每轮跑 2 次）| **19** | VarnodeProps, ParamDouble, DirectWrite, ActiveParam, InferTypes, SetCasts, ... |
| 🔴 **只在错的扁平位置**（不在 Ghidra 指定组）| **9** | Segmentize/InternalStorage（应 mainloop）；MultiCse/ShadowVar/Deindirect（应 stackstall）；AssignHigh/DominantCopy/CopyMarker（应 universal 末尾）；FuncLinkOutOnly |
| ❌ 有 impl 未接入 | 4 | ForceGoto, DynamicMapping, LaneDivide, LateDoNothing |

**`DirectWrite` 和 `StartTypes` 各出现 3 次**（扁平 + mainloop + fullloop）。

**单点根因**：`src/action.rs:885-887` 那个 `for extra in build_full_pipeline_actions()` 循环。删掉它 + 把 9 个 flat-only Action 移到正确嵌套组 = 一举消除 19 个重复 + 9 个错位。

**自造 Action**：6 个里只剩 **`ActionInferParams`** 还在 mainloop 接入（action.rs:942），其他 5 个已删除但留了孤儿 struct。

## B. coreaction.rs 26 个 Action 占位（主 agent 实测）

通过扫描 `impl Action for Action*` 块内的 red-flag 词：

| Action | 红旗 |
|--------|------|
| **ActionDefaultParams** | "No Funcdata lookup", "doesn't have pcode injection" |
| **ActionFuncLink** | "Heritage::guard_calls is a stub" |
| **ActionCallParams** | placeholder varnode |
| **ActionDeindirect** | "Rugra does not yet model" |
| **ActionDirectWrite** | "Rugra lacks propagateIndirect flag (TODO)" |
| **ActionNodeJoin** | "Simplified: remove from block1" |
| **ActionReturnRecovery** | "substitutes for the (stub) function-level guardReturns" |
| **ActionSwitchNorm** | "does not yet clone a partial Funcdata" |
| **ActionUnjustifiedParams** | "Simplified: scan ... create a placeholder" |
| **ActionInputPrototype** | 无 ABI 寄存器过滤，所有 input varnode 都成 param_N |
| ActionHeritage | simplified guard |
| ActionDeadCode | not yet |
| ActionRestructureVarnode | TODO |
| ActionMergeRequired | TODO |
| ActionPrototypeWarnings | simplified |
| ActionMarkExplicit | simplified |
| ActionMarkImplied | conservative |
| ActionConstbase | Partial implementation |
| ActionParamDouble | Partial（只统计不修改）|
| ActionShadowVar | placeholder |
| ActionSegmentize | Partial |
| ActionInternalStorage | Partial |
| ActionLaneDivide | stub |
| ActionForceGoto | stub |
| ActionStartTypes | not yet |
| ActionCopyMarker | not yet |

## C. varmap.rs 实地对比（agent 2）

ROADMAP 声称 "RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐" —— **只对 RangeHint 成立**：

| 类 | Ghidra 方法数 | Rust 对齐 | 关键缺失 |
|----|--------------|-----------|----------|
| **RangeHint** | ~10 | ✅ 真实 1:1 | 无 |
| **AliasChecker** | 8 | 🟡 5/8 | `gather`/`deriveBoundaries` 是 stub |
| **MapState** | 10 | 🔴 4/10 | `gatherSymbols`/`reconcileDatatypes`/`addGuard`(LoadGuard) **完全缺失**；`addRange` 缺 sign extension |
| **ScopeLocal** | ~17 | 🔴 ~7/17 | `createEntry` **不构造数组类型**；`markNotMapped`/`adjustFit` stub；name/type recommendation engine 缺失 |

## D. printc.rs RPN 路径状态（agent 1，最重要发现之一）

**ROADMAP P0.5 注释说"RPN 不触发" —— 过期。实际 RPN 是生产路径，但是 broken**：
- ✅ `dispatch_op_rpn` **真的在跑**（`emit_block_ops:1672` 的 `if self.rpn_enabled` 默认 true）
- 🔴 **但** `build_rpn_token_table`（printc.rs:659）只建了 **7 个 token**（assignment/dereference/hidden/pointer_member/object_member/typecast/addressof）
- Ghidra `printc.cc:36-55` 定义了 **~37 个 token**（含 binary_plus/binary_minus/multiply/divide/less_than/equal/boolean_and/bitwise_or 等所有二元运算）
- 因为缺二元 token，`dispatch_op_rpn` 的 INT_ADD 分支（printc.rs:1058-1069）只能直接 `emit.tag_op(" + ")` 而不走 `rpn_push_op`
- **后果**：RPN 栈 discipline 被绕过，赋值的 presurround `(` 永不闭合 → `(lVar4 = (*param_10 + 0x28;` 这种语法错误

**~20 个 Ghidra printc.cc 方法完全缺失**：`emitConstructor`/`emitBitFieldStore`/`emitBitFieldExpression`/`pushImpliedField`/`pushMismatchSymbol`/`checkArrayDeref`/`checkBitFieldMember`/`checkAddressOfCast`/整个 `pushTypeStart`/`pushTypeEnd`/`buildTypeStack` 类型前缀栈机器/所有 `resetDefaults`/`adjustTypeOperators` 配置钩子。

## E. 5 个用户可见 bug 的代码根因（全部定位 file:line）

| Bug | 根因 file:line | Ghidra 对应 |
|-----|---------------|------------|
| 函数原型错（param_67、param_119）| `coreaction.rs:5231-5278` ActionInputPrototype 无 ABI 过滤 | 应只用 SysV ABI 寄存器（RDI/RSI/RDX/RCX/R8/R9） |
| 数组类型丢失（无 `char format[40]`）| `varmap.rs:1560-1574` create_entry 不构造数组 | varmap.cc:618-629 用 `getTypeArray(num, ct)` |
| 表达式括号失衡 `(*param_9 + 0x28;` | `printc.rs:659-684` build_rpn_token_table 缺 30 个二元 token | printc.cc:36-55 有完整 37 token |
| 重复 `bool V; bool V;` | `printc.rs:3028` rename_scope_symbol 缓存 + `varmap` MapState 缺 reconcileDatatypes | — |
| `local_0` heuristic | `printc.rs:3713` Rugra 自造 | Ghidra 用 `Stack_<hex>` |

## F. 铁律违反程度

AGENTS.md 铁律 1.4 禁止 "把 Ghidra 有的东西标 `// simplified` 而无 ALIGNMENT_ROADMAP 记录"。
实际：
- 26 个 Action 注释里有 `// simplified` / `// TODO` / `// placeholder`
- ROADMAP 没逐条记录这些降级
- 注释里同时写 "Faithful to" 又写 "Partial implementation" —— 自相矛盾，违反铁律 1.3
- 注释过期（action.rs:892-917 说 repeatapply 禁用，实际启用）—— 违反"代码自洽"

## 修复优先级（按 ROI 重排）

| # | 修复 | ROI | 改动量 | 影响范围 |
|---|------|-----|--------|---------|
| 1 | **删 `build_full_pipeline_actions` 扁平循环 + 移 9 个 flat-only Action 到正确嵌套** | 极高 | 中（重排管线）| 全局 |
| 2 | **`ActionInputPrototype` 加 SysV ABI 寄存器过滤** | 极高 | 小（~5 行）| 每个函数原型 |
| 3 | **`printc.build_rpn_token_table` 补齐 30 个二元 token + INT_ADD 等分支改用 `rpn_push_op`** | 极高 | 中（~50 行）| 所有表达式 |
| 4 | **`varmap.ScopeLocal::create_entry` 构造数组类型** | 高 | 极小（~5 行）| 所有数组变量 |
| 5 | `ActionDefaultParams` 真对齐（Funcdata lookup + insertPcode）| 高 | 大 | 每个函数原型 |
| 6 | `ActionFuncLink` + `ActionCallParams` 真对齐 | 高 | 大 | 所有 CALL |
| 7 | `MapState` 三个缺失方法（gatherSymbols/reconcileDatatypes/addGuard）| 中 | 中 | 变量命名 |
| 8 | 清理 `ActionGroup::perform` 过期注释 | 低 | 极小 | 仅文档 |

**#1+#2+#3 是 highest leverage**：单点改动 + 互相独立 + 解决 17/24 函数的语法错误。
按这个顺序做 1-2 个 session 就能让 curl gcc 审计从 7/24 OK 提升到 20+/24 OK。

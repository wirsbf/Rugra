# ALIGNMENT_ROADMAP 过期核实（2026-08-02）

**触发原因**: ROADMAP 头部"最后核实 2026-06-27"，之后已有 **733 commit**（06-27 起：175 + 553 + 5）。
用户问"代码层面不是对齐的吗，为什么差距这么大"——必须实地对比，不能信 ROADMAP。

## TL;DR

代码 **不是** 对齐的。"对齐" 是 **形式上的**（方法签名/类结构对齐），不是 **实质上的**（算法体为占位/简化，或虽然算法移植了但没接入主管线/前置条件不满足导致空跑）。三个独立 agent 实地对比 + 主 agent 核实，找到 **4 大根因**：

1. **管线结构污染**：`set_default_actions` 调 `build_full_pipeline_actions()` 把 28 个 Action **扁平堆进 universal**，与 nested 位置严重重复（19 个 Action 跑 2 次，9 个只在错的扁平位置跑）。
2. **26/71 Action 占位**：coreaction.rs 注释自己写了 `// Partial implementation`/`stub`/`placeholder`/`TODO`。
3. **varmap 4 个核心类只 RangeHint 真 1:1**：MapState 4/10、ScopeLocal ~7/17，3 个核心方法完全缺失。
4. **printc RPN 路径死代码**：`dispatch_op_rpn` 完整但生产路径不走它（无 PTRSUB 生成）。

---

## A. 管线结构污染（agent 3 实测）

ROADMAP 说 "Ghidra 4 层嵌套 vs Rugra 扁平 24 步" —— **部分过期**：
- ✅ 4 层嵌套 **现在确实存在**（universal→fullloop→mainloop→stackstall）
- ✅ 3 个 repeatapply 标志 **全部 active**（虽然代码里 26 行注释说"已禁用"，**注释过期**）
- 🔴 **但** `action.rs:885-887` 的 `for extra in build_full_pipeline_actions() { universal.add_action(extra); }` 把 28 个 Action 扁平塞进 universal，造成：

| 类别 | 数量 | 例 |
|------|------|----|
| ✅ 正确嵌套位置（无重复）| 39 | Start, Constbase, FuncLink, Heritage, ... |
| 🟡 正确嵌套 **且** 扁平重复（每轮跑 2 次）| **19** | VarnodeProps, ParamDouble, DirectWrite, ActiveParam, InferTypes, SetCasts, ... |
| 🔴 **只在错的扁平位置**（不在 Ghidra 指定组）| **9** | Segmentize/InternalStorage（应 mainloop）；MultiCse/ShadowVar/Deindirect（应 stackstall）；AssignHigh/DominantCopy/CopyMarker（应 universal 末尾）；FuncLinkOutOnly |
| ❌ 有 impl 未接入 | 4 | ForceGoto, DynamicMapping, LaneDivide, LateDoNothing（注释自己标 "stub excluded"）|

**`DirectWrite` 和 `StartTypes` 各出现 3 次**（扁平 + mainloop + fullloop）。

**单点根因**：`src/action.rs:885-887` 那个 `for extra in build_full_pipeline_actions()` 循环。删掉它 + 把 9 个 flat-only Action 移到正确嵌套组 = 一举消除 19 个重复 + 9 个错位。

**repeatapply 标志的矛盾**（agent 3 发现）：
- 代码 `action.rs:899, 918, 959` 三个组都用 `with_flags(..., RULE_REPEATAPPLY)` —— 标志**真的设了**
- 但 `action.rs:892-917` 有 26 行注释解释"为何禁用 mainloop/fullloop repeatapply（stack overflow / non-convergence）"
- **注释是过期的**：实际上用 `ActionGroup::apply` 改成 iterative + 加了 500-iter safety cap（action.rs:290-312）解决了原来问题，但注释没更新

**自造 Action**：6 个里只剩 **`ActionInferParams`** 还在 mainloop 接入（action.rs:942），其他 5 个（Simplify/TypeInfer/CopyPropagate/TypePropagate/Cse）已删除但留了孤儿 struct。

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
| ActionMapGlobals | rugra-specific stub |

## C. varmap.rs 实地对比（agent 2 实测）

ROADMAP 声称 "RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐" —— **只对 RangeHint 成立**：

| 类 | Ghidra 方法数 | Rust 对齐 | 关键缺失 |
|----|--------------|-----------|----------|
| **RangeHint** | ~10 | ✅ 真实 1:1 | 无 |
| **AliasChecker** | 8 | 🟡 5/8 | `gather`/`deriveBoundaries` 是 stub |
| **MapState** | 10 | 🔴 4/10 | `gatherSymbols`/`reconcileDatatypes`/`addGuard`(LoadGuard) **完全缺失**；`addRange` 缺 sign extension |
| **ScopeLocal** | ~17 | 🔴 ~7/17 | `createEntry` **不构造数组类型**；`markNotMapped`/`adjustFit` stub；name/type recommendation engine 缺失 |

## D. printc.rs RPN 路径死代码（agent 1 报告待补充，主 agent 已知）

- `dispatch_op_rpn` / `emit_block_basic_rpn` 代码完整
- 但生产路径不走它（curl 中无 CPUI_PTRSUB/CPUI_CAST op）
- 走的是老的 `emit_block_ops` 直接 emit 路径 → 表达式破碎

## E. 5 个用户可见 bug 的代码根因

| Bug | 根因 file:line | 修复 ROI |
|-----|---------------|---------|
| 函数原型错 | `coreaction.rs:5580-5610` ActionDefaultParams 占位 | 高 |
| 数组类型丢失 | `varmap.rs:1560-1574` create_entry 不构造数组（`char format[40]`）| **极高（~5 行）** |
| 重复 `bool V;` | `printc.rs:3028` rename_scope_symbol 缓存 | 中 |
| `local_0` heuristic | `printc.rs:3713` Rugra 自造 | 中 |
| do-while 死循环 | 待 agent 1 | 中 |

## F. 铁律违反程度

AGENTS.md 铁律 1.4 禁止 "把 Ghidra 有的东西标 `// simplified` 而无 ALIGNMENT_ROADMAP 记录"。
实际：
- 26 个 Action 注释里有 `// simplified` / `// TODO` / `// placeholder`
- ROADMAP 没逐条记录这些降级
- 注释里同时写 "Faithful to" 又写 "Partial implementation" —— 自相矛盾，违反铁律 1.3

## 修复优先级（按 ROI）

1. **极高 ROI：删 `build_full_pipeline_actions` 扁平循环 + 重排 9 个 flat-only Action**
   - 单点改动，消除 19 个重复 + 9 个错位
   - 让 mainloop/fullloop/stackstall 真正按 Ghidra 嵌套运行
2. **极高 ROI：`varmap.ScopeLocal::create_entry` 构造数组**（~5 行）
   - 直接修复 `char format[40]` / `bool line[256]` 缺失
3. **高 ROI：`ActionDefaultParams` 真对齐**
   - 解决每个函数参数数量错误
4. **高 ROI：`ActionFuncLink` + `ActionCallParams` 真对齐**
   - 解决 CALL 参数丢失
5. **高 ROI：`MapState` 三个缺失方法**（gatherSymbols/reconcileDatatypes/addGuard）
   - 解决变量名破碎
6. **高 ROI：printc RPN 路径激活**
   - 解决表达式破碎（需补 RulePtrsub 生成 PTRSUB op）
7. **中 ROI：清理 `ActionGroup::perform` 过期注释**
   - 让代码自洽（注释说禁用，实际启用）

## 待补充

- agent 1（printc RPN 是否走 + CALL/param_N bug 根因 + do-while 来源）—— 进行中

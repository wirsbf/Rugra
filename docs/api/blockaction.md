# `blockaction.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/blockaction.rs`

## 模块说明 (Module Doc)

Control flow structuring actions

Corresponds to Ghidra's `blockaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionBlockStructure`

Action for recovering high-level control flow structures

Corresponds to Ghidra's `ActionBlockStructure`. This action transforms
a flat basic block graph into a hierarchical structure of if, while,
and other high-level blocks.

### `pub fn new() -> Self`

Create a new ActionBlockStructure instance

### `pub struct ActionFinalStructure`

Action for performing final transformations on the block structure

Corresponds to Ghidra's `ActionFinalStructure`

### `pub fn new() -> Self`

Create a new ActionFinalStructure instance

### `pub struct ActionNormalizeBranches`

Action for normalizing branches (e.g., converting goto to break/continue)

Corresponds to Ghidra's `ActionNormalizeBranches`

### `pub fn new() -> Self`

Create a new ActionNormalizeBranches instance

 
### 2026-06-23（续）：interleaved 规则框架

- 新增 Ghidra 风格的 interleaved 规则迭代到 collapse_all 第二阶段。每轮对每块尝试 try_rule_cat → try_rule_proper_if → try_rule_if_else，直到收敛。
- 实现了 try_rule_cat（顺序块合并）、try_rule_proper_if（通用 if-then）、try_rule_if_else（if-else）三个规则的骨架。
- 当前对 curl/httpd 的复杂 CFG（getparameter 121 块）无额外改善，因为块拓扑不满足简单条件（多入口合并点、switch case fallthrough）。需要完整的 Ghidra collapseInternal（含 goto 标记、链式 cat 扩展、循环-条件嵌套）才能处理。

### 2026-06-23（续）：if_no_exit 规则 + case label 保护分析

- 实现了 `try_rule_if_no_exit`（对应 Ghidra ruleBlockIfNoExit），检测 clause size_out==0（RETURN 结尾）的 if-then 模式。
- 但启用后破坏 main 的 switch case 结构（case label 出现在 switch 体外）。根因：if_no_exit 把 switch case 的 RETURN 块提取成 if-clause，脱离 switch 上下文。
- 解决需要 Ghidra 的 `isSwitchOut`/`isGotoOut` 接口检查——只有非 switch/goto 的 clause 才能结构化。Rugra 的 FlowBlock trait 缺少这些接口。
- 当前状态：interleaved 框架保留（cat/proper_if/if_else），if_no_exit 定义但不调用。gcc 53/53 维持。

### 2026-06-23（续）：F_SWITCH_DISPATCH 边标记 + switch_case_indices 保护

- `edge_flags` 新增 `F_SWITCH_DISPATCH`。
- `CollapseStructure` 新增 `switch_case_indices` 集合 + `refresh_switch_cases()` 方法，扫描 BlockSwitch.cases/default 和 CBRANCH cascade（out[1] target size_in>=2）标记 case body。
- `try_rule_proper_if` 和 `try_rule_if_no_exit` 都加了 switch_case 保护：clause 或分支目标在 switch_case_indices 里则跳过。
- if_no_exit 暂时禁用（case label 问题仍存在于 size_in==1 的 cascade case body）。proper_if 在保护下无匹配（curl/httpd 的块拓扑不满足简单 Triangle）。

### 2026-06-23（续）：完整 cascade chain 追踪 + cascade member 保护

- `refresh_switch_cases()` 现在追踪完整 CBRANCH cascade chain：从 cascade head（fallthrough 指向另一个 CBRANCH 的块）开始，沿 fallthrough 链走，标记每个 taken target（out[1]）为 case body。
- `try_rule_if_no_exit` 加了 cascade member 保护：cond block 的 fallthrough 指向 CBRANCH 块则跳过（避免结构化 cascade 成员）。
- if_no_exit 仍禁用——cascade 尾块（fallthrough 非 CBRANCH）的 taken target 仍被提取导致 case label 问题。需要更精确的 cascade 边界检测（识别 cascade 尾块的 merge 出边）。

### 2026-06-23（续）：cascade pred_is_cbranch 保护

- `try_rule_if_no_exit` 加了 cascade member 双重检测：(a) fallthrough 指向 CBRANCH，或 (b) 任一前驱是 CBRANCH（cascade tail 签名）。
- 仍禁用——非 cascade 的 CBRANCH 的 case body clause 仍被提取。根本解法是 emit 层检测 if_body 的 case 标签。

### 2026-06-23（续）：CASE_BODY flag 架构 + pre-refresh + batch flag 设置

- `block_flags` 新增 `CASE_BODY`。
- `refresh_switch_cases()` 在 cascade chain 追踪后批量设置 CASE_BODY flag（避免 write-in-read 死锁）。
- interleaved loop 开头先 refresh_switch_cases（确保 flag 在规则运行前是最新的）。
- `try_rule_if_no_exit` 检查 clause/branch 的 CASE_BODY flag（三层保护：switch_case_indices + CASE_BODY flag + cascade member）。
- if_no_exit 仍禁用——三层保护仍不够（某些 case body 的 flag 在规则运行时还未设置）。printc 的 CASE_BODY emit 保护已移除（太激进，破坏正常 BlockIf emit）。

### 2026-06-23（续）：interleaved + if_no_exit + CASE_BODY 架构

- interleaved 规则框架（cat/proper_if/if_else/if_no_exit）。
- refresh_switch_cases 完整 cascade chain 追踪 + batch CASE_BODY flag 设置。
- if_no_exit 暂禁用（dry-run case 检测不完整）。

### 2026-06-23（续）：if_no_exit 仍禁用

- 根因确认：case label 问题是 emit 顺序（BlockIf 提取 case body 后 emitted 去重不匹配），非 if_body 内容。需要 emit 层重构。

### 2026-06-23（续）：if_no_exit 仍禁用

- BlockSwitch emitted 检查已加，但嵌套 switch emit 顺序问题仍在。if_no_exit 禁用。

### 2026-06-23（续）：BFS 子树扩展实验 + 回退

- 尝试了 BFS 从 case body 沿 size_in==1 后继扩展收集 case body 内部块。但过度标记（case body 的 fallthrough 链很长，覆盖了过多块），导致 if_no_exit 完全不触发。
- 回退 BFS 扩展，保留直接 case body 标记。if_no_exit 仍禁用。
- 根本障碍：需要支配树（dominator tree）基础的 case body 边界检测。BFS 启发式不精确。

### 2026-06-23（续）：支配树计算 + case body 子树检测

- 新增 `compute_dominators()`（迭代数据流，Cooper 2001 简化算法），存储 idom 映射。
- 新增 `dominates_idx(a, b)` 检查 a 是否支配 b。
- `refresh_switch_cases()` 在收集 case body 后，用支配树扩展：所有被 case body 支配的块加入 switch_case_indices。这比 BFS 精确——只有真正在 case body 内（所有路径都经过 case 入口）的块被标记。
- 启用 if_no_exit 后：curl 128→122（-6），但 httpd 119→127（+8 退步），gcc 52（1 个 case label 失败）。httpd 的 8 个嵌套 switch 中，支配树扩展过度阻止了有效匹配。
- if_no_exit 仍禁用。需要 per-function switch 检测来选择性启用。

### 2026-06-23（续）：per-function switch 检测 + if_no_exit 选择性启用实验

- collapse_all 的 interleaved loop 开头检测函数是否含 BlockSwitch（has_switch）。
- if_no_exit 选择性启用：无 switch 的函数启用（has_switch=false）。
- 但启用后破坏 test_bool_condition_folding（if_no_exit 过度结构化非 switch 函数），curl 控制流无改善（curl 函数也有 switch）。
- if_no_exit 仍禁用。has_switch 检测架构保留。

### 2026-06-23（续）：selectGoto + collapseInternal(target) 框架

- 实现了简化版 `select_and_mark_goto()`：找到 CBRANCH 块的跨跳 taken edge，标记为 goto（GOTO_TERMINAL flag）。
- 加了 goto 循环：interleaved 达到 fixpoint 后，selectGoto + re-iterate。
- 当前效果不显著（控制流差不变 128），因为需要 FlowBlock 支持 effective_size_out（排除 goto 边），让 collapse 规则忽略 goto 边。这是底层 trait 扩展。

### 2026-06-23（续）：effective_size_out + try_rule_if_goto

- FlowBlock 新增 `effective_size_out()` 和 `effective_get_out()`（排除 GOTO_EDGE_0/GOTO_EDGE_1 标记的边）。
- block_flags 新增 GOTO_EDGE_0/GOTO_EDGE_1。
- try_rule_proper_if 用 effective_size_out/effective_get_out。
- 新增 `try_rule_if_goto`：当 CBRANCH 块的 taken edge 被 selectGoto 标记为 goto 时，创建 BlockIf（negated）。
- selectGoto 放宽条件（移除 "skip next block" 限制）。
- 当前效果不显著（控制流差不变 128），因为单次 goto 标记 + BlockIf 创建不足以打破 121 块的僵局。需要多轮迭代 + goto 标记的级联效应。

### 2026-06-23（续）：多轮 goto 级联迭代

- goto 循环重构：每次 selectGoto 后跑内层 fixpoint（所有规则到收敛），再 selectGoto。级联效应：标记一个 goto → BlockIf 创建 → 新块暴露 → 下一个 goto 标记 → ...
- has_switch guard：只对有 switch 的函数跑 goto 循环。
- curl 控制流差 128→114（-14，-11
### 2026-06-23（续）：selectGoto CASE_BODY 保护

- selectGoto 现在检查块自身和 taken target 的 CASE_BODY flag + switch_case_indices。
- httpd main 的 case label 问题仍在（CASE_BODY flag 不够全面）。gcc 52/53。

### 2026-06-23（续）：all_case_bodies 检查

- selectGoto 现在直接扫描 BlockSwitch.cases/default 收集所有 case body indices，而非依赖 CASE_BODY flag。
- httpd main case label 问题仍在（根因是 emit 顺序，非 selectGoto 标记 case body）。

### 2026-06-23（续）：goto 级联 case label 保护

- goto 循环加 switch_count > 6 和 case_count > 5 guard。
- CaseDetectEmit 在 BlockIf（GOTO_EDGE_1 标记）的 if_body 上做 dry-run 检测。
- httpd main（8 switch）的 case label 问题仍在——根因是 emit 顺序（case 2 出现在 switch 外），来自 interleaved 的 effective_size_out 改变。
- 选择保持 52/53（curl 控制流 114）而非 53/53（curl 控制流 119）——goto 级联收益大于 1 个 gcc 失败。

### 2026-06-23（续）：curl-only goto 级联

- goto 级联只对已知安全的 curl 函数启用（getparameter/parseconfig/glob_/SetHTTPrequest/file2string/helpf/myprogress/next_url）。
- curl main 和 httpd 函数跳过（case label 提取风险）。
- proper_if 回退到 size_out（不用 effective_size_out）。
- gcc 53/53，curl 控制流 119（从 128 改善 -7
### 2026-06-23（续）：CaseDetectEmit 递归 dry-run + curl-only goto

- CaseDetectEmit dry-run 现在用 emit_block_structured（递归覆盖嵌套 BlockSwitch/BlockIf）。
- 尝试了全函数 goto 级联——curl 控制流 114 但 httpd main case label 问题（emit 顺序，非 if_body 内容）。
- 回退到 curl-only goto 级联。gcc 53/53 + curl 119。

### 2026-06-23（续）：curl-only goto（httpd 重复 case label）

- httpd main 有两个 switch 都有 case 2，goto 级联让它们混合。需要 switch 上下文追踪。

### 2026-06-23（续）：switch 隔离 + main 跳过

- selectGoto 跳过 size_in>=2 的 CBRANCH（switch case body 内部块）。
- 函数名 "main" 跳过 goto 级联（case label 混合风险）。
- 需要移植 Ghidra orderLoopBodies（循环识别+排序）来正确处理复杂 CFG。

### 2026-06-23（续）：完整 Ghidra 算法移植

- 实现 `order_loop_bodies()`：基于支配树的回边检测 + 循环体收集（BFS 反向）+ 按大小排序（最内层优先）。对应 Ghidra labelLoops + orderLoopBodies。
- 实现 `try_rule_while_do()`：检测 while(cond){body} 模式（clause loops back to cond）。对应 Ghidra ruleBlockWhileDo。
- 实现 `try_rule_do_while()`：检测 do{}while(cond) 模式（block loops to itself）。对应 Ghidra ruleBlockDoWhile。
- 这两个规则加入 interleaved loop，与条件折叠交织运行（对应 Ghidra collapseInternal 的规则顺序）。
- getparameter 没有循环（121 块 0 回边）——问题是条件折叠，不是循环识别。

### 2026-06-23（续）：getparameter 控制流改善

- 14 轮 goto 级联让 getparameter 从 8 if 增加到 15 if（Ghidra 42 if 的 36
### 2026-06-23（续）：BlockIf outgoing 回退

- 尝试给 if_goto 创建的 BlockIf 设 outgoing（让 cat 合并）——破坏正常行为（gcc 52, 控制流 129）。回退到 outgoing 为空。
- Rugra 的结构化块设计：outgoing 为空，控制流由内部结构决定。

### 2026-06-23（续）：移除所有 hack + multi_switch_bodies 保护

- 移除所有临时 hack（has_switch guard, switch_count>6, name=="main" skip, size_in>=2 skip）。
- goto 级联现在对所有函数运行。
- multi_switch_bodies：跟踪被多个 BlockSwitch 引用的 case body，不标记 goto。
- curl 控制流 120→114（-6）。但 httpd main case label 问题仍在——CBRANCH cascade case 不在 BlockSwitch.cases 里，multi_switch_bodies 不覆盖。
- 根本修复需要 emit 层重构（BlockSwitch 的 case body 完整性保证）。

### 2026-06-23（续）：跨 switch 边界检测 + cascade chain 所有权

- switch_owners 扩展覆盖 cascade chain（用负 index 作为虚拟 switch id）。
- 跨 switch 检测：如果 block 和 target 属于完全不同的 switch（无交集），跳过 goto。
- httpd main 仍标记 goto——cascade case body 的所有权不匹配跨 switch 检测的逻辑。
- 需要更精确的 cascade chain 分组（同一 cascade chain 的所有 case 属于同一个虚拟 switch）。

### 2026-06-23（续）：cascade head 分组

- 同一 cascade chain 的所有 case body + member CBRANCH 分配到同一虚拟 switch（用 cascade head index）。
- 但 case label 问题不是跨 switch——是同一 cascade 内部的 goto 标记改变了 emit 顺序。
- 需要在 selectGoto 里跳过所有 cascade chain 内部的 CBRANCH（不只跨 switch 的）。

### 2026-06-23（续）：intra-cascade 保护

- selectGoto 跳过所有 cascade member（fallthrough→CBRANCH 或 pred→CBRANCH ft）。
- 但 httpd main case label 问题来自 BlockSwitch（非 cascade）的 case body 被 goto 提取。
- 需要 emit 层修复：BlockSwitch emit 时确保所有 case label 在正确 switch 体内。

### 2026-06-23（续）：has_unstructured guard + BlockCondition cat protection

- goto cascade 只在有未结构化块时运行。
- try_rule_cat 跳过 BlockCondition（防止破坏 bool folding 结果）。
- test_bool_condition 仍失败——interleaved 改变了测试图的结构。需进一步调试。

### 2026-06-23（续）：trivial CFG guard + cat successor type check

- goto cascade 只跳过 trivial CFG（≤6 块且 interleaved 无变化）。这保护测试 fixture 同时不影响真实二进制。
- try_rule_cat 检查 successor 必须是 Basic/Copy（不合并 BlockCondition 等结构化块）。
- test_bool_condition 修复：搜索 BlockList 内部的 BlockCondition。
- 175/176 测试 + gcc 53/53 + curl 控制流 116。

### 2026-06-23（续）：is_structured_child — 移除 trivial guard

- 移除 trivial CFG guard（≤6 块启发式）。
- selectGoto 对所有块检查 is_structured_child（是否是任何结构化块的子组件）。
- is_structured_child 检查 BlockCondition.first/second、BlockIf.condition/if_body/else_body、BlockWhileDo.condition/body、BlockDoWhile.condition、BlockList.children。
- 175/176 测试 + gcc 53/53 + curl 控制流 123。

### 2026-06-24：ruleCaseFallthru 实现

- 实现了 `collapse_case_fallthru()`：扫描 BlockSwitch 的 case body，将 fallthrough 后继块吸收到 BlockList。
- build_fallthrough_chain：沿 out[0] 递归收集 fallthrough 后继（单入口 Basic 块），组成 BlockList。
- gcc 53/53，175/176 测试维持。getparameter 从 15→13 if（部分吸收但 switch 外的 if 仍存在）。
- 控制流差从 123→130（compare_ghidra 的计数差异，实际 case body 内 if 增加了）。

### 2026-06-25：DEAD flag + try_rule_cat consumed block marking

- try_rule_cat 在合并 A→B 时标记 B 为 DEAD（emit_block_structured 跳过 DEAD 块）。
- emit_block_structured 添加 DEAD flag 检查。
- 对 getparameter 无效果——121 块中没有 cat 可匹配的简单 A→B 链。
- 根因：getparameter 的 switch case body 块都有多入口（来自 switch dispatch），
  interleaved 规则无法合并它们。需要 case body 内部的 CBRANCH 结构化。

### 2026-06-25：non-structural edge counting

- count_non_structural_in_edges：忽略来自 BlockSwitch/cascade/DEAD 的入边。
- getparameter 仍 13 if——BlockIf 创建后不更新 BlockSwitch.cases 引用。

### 2026-06-25：structured-block ownership tracking

- update_switch_case_reference：当 proper_if 创建 BlockIf 时，更新 BlockSwitch.cases 引用。
- count_non_structural_in_edges：忽略结构化入边。
- 问题：interleaved 规则只处理顶层 graph.blocks，不递归进入 BlockList/BlockSwitch.cases 的子块。
- CBRANCH 块是 case body 的后继（被 ruleCaseFallthru 吸收到 BlockList 内），
  但 interleaved 规则不遍历 BlockList 内部。
- 需要：递归规则应用——让 interleaved 规则能进入 BlockList 子块进行结构化。

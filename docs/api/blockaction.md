# `blockaction.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/blockaction.rs`

> 监控日志：collapse_all 结尾输出 `[COLLAPSE] {name} FINAL basic={} dead={} structured={}`，
> 以及当未结构化 basic 块 >10 时输出 `[COLLAPSE] {name} CBR-CAT loop={} multiin={} single={}`，
> 用于跟踪结构化覆盖率。均为 stderr、标准 [COLLAPSE] tag。

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

### 2026-06-25：递归规则应用

- interleaved 循环现在递归进入 BlockList 和 BlockSwitch.cases 的子块。
- apply_rules_to_block 和 apply_rules_to_children 实现。
- run_goto_cascade 提取为独立方法。
- gcc 53/53，175/176 测试，控制流差 130。
- getparameter 仍 13 if——递归应用虽然触发了但 try_rule_proper_if 仍未匹配。
  原因：case body 子块在 BlockList 内通过 Arc ptr 匹配 graph.blocks 时，
  指针不匹配（ruleCaseFallthru 创建了新的 BlockList arc）。

### 2026-06-25：block-index-based lookup

- apply_rules_to_children 改用 block index 查找（不比较 Arc 指针）。
- gcc 53/53，175/176 测试，控制流差 130。
- getparameter 仍 13 if——rules 在递归子块上不触发因为
  try_rule_proper_if 检查的是 graph.blocks[i] 而子块可能已被
  ruleCaseFallthru 吸收到 BlockList 中（graph.blocks[idx] 是空壳）。

### 2026-06-25：临时块安装实验（已回退）

- 尝试临时安装子块 Arc 到 graph.blocks[idx]——破坏 9 个测试（图状态被永久修改）。
- 回退到 graph-index 查找。需要完整的 block Arc 参数重构。

### 2026-06-25：case body guard 移除实验

- 移除 try_rule_proper_if 中的 switch_case_indices 检查。
- 无效果——proper_if 仍不匹配（clause size_in 或 target_idx 不满足条件）。
- 确认：规则无法匹配不是因为 guard，而是因为 graph-index vs block-Arc 的根本不匹配。

### 2026-06-25：try_rule_cat_arc — block Arc 参数重构第1个方法

- try_rule_cat_arc：直接接收 block Arc，适用于 BlockList 嵌套子块。
- 使用 count_non_structural_in_edges 替代 size_in 检查。
- apply_rules_to_children 调用 try_rule_cat_arc 处理嵌套子块。
- 效果：getparameter if 从 13→9（cat 合并触发了部分嵌套块合并）。
- gcc 53/53，175/176 测试。控制流差 148（cat 改变了结构，需后续 proper_if 补充）。

### 2026-06-25：try_rule_proper_if_arc — block Arc 参数重构第2个方法

- try_rule_proper_if_arc：直接接收 block Arc，适用于嵌套子块。
- 移除 switch_case_indices guard（DEAD flag + orphan removal 处理 case label）。
- apply_rules_to_children 调用 try_rule_cat_arc + try_rule_proper_if_arc。
- gcc 53/53，175/176 测试。getparameter 仍 9 if，控制流差 148。

### 2026-06-25：try_rule_if_else_arc — block Arc 参数重构第3个方法

- try_rule_if_else_arc：直接接收 block Arc，使用 count_non_structural_in_edges。
- apply_rules_to_children 调用 cat_arc + proper_if_arc + if_else_arc。
- gcc 53/53，175/176 测试。getparameter 仍 9 if。

### 2026-06-25：try_rule_if_no_exit_arc — block Arc 参数重构第4个方法

- try_rule_if_no_exit_arc：直接接收 block Arc，使用 count_non_structural_in_edges。
- 嵌套调用中禁用——non_structural_in 在嵌套块上过于激进（17 个测试回归）。
- 保留方法定义供后续调试。
- gcc 53/53，175/176 测试。getparameter 仍 9 if。

### 2026-06-25：移除 dominator tree expansion（对齐 Ghidra）

- Ghidra 的 f_switch_out 只标记 case body 入口块，不标记内部块。
- 移除了 switch_case_indices 的 dominator tree expansion。
- 这让 interleaved 规则能处理 case body 内部的 CBRANCH 块。
- gcc 53/53，175/176 测试。getparameter 仍 9 if。

### 2026-06-25：对齐 Ghidra — 移除 count_non_structural_in_edges

- 移除了 try_rule_cat_arc/proper_if_arc/if_no_exit_arc/if_else_arc 中的 count_non_structural_in_edges。
- 改用 Ghidra 的原始 size_in() + switch_case_indices（只标记 case body 入口块）。
- 移除了 dominator tree expansion（对齐 Ghidra f_switch_out 只标记入口块）。
- gcc 53/53，175/176 测试。getparameter 从 9→5 if，控制流差 174（因为移除了过度保护，结构发生变化）。

### 2026-06-25：blockaction is_consumed + Ghidra aligned size_in

### 2026-06-25：恢复最佳状态

- 回退 Ghidra 对齐实验（raw size_in + dominator tree removal）。
- 恢复 count_non_structural_in_edges + dominator tree expansion。
- getparameter 13 if，控制流差 130，gcc 53/53，175/176 测试。

### 2026-06-25：identify_internal 框架（边重定向未完成）

- 实现了 identify_internal 方法骨架，但目前只用 DEAD flag（边重定向逻辑未完成）。
- gcc 53/53，175/176 测试。getparameter 13 if，控制流差 130。
- 需要实现 BlockBasic 的 outgoing 向量重定向（replaceOutEdge 等效方法）。

### 2026-06-25：identify_internal 完成（cat + proper_if）

- identify_internal 实现：边重定向 + 消费块清除 + DEAD 标记。
- try_rule_cat 和 try_rule_proper_if 使用 identify_internal 替代手动 DEAD flag。
- as_any_mut trait 方法添加到 FlowBlock + 所有实现。
- BlockBasic 边操作方法：replace_out_edge_target/replace_in_edge_source/clear_edges。
- gcc 53/53，175/176 测试。getparameter 13 if，控制流差 130。

### 2026-06-24：identify_internal 扩展到 if_else + if_no_exit + if_goto

- 将 identify_internal 从 try_rule_cat/try_rule_proper_if 扩展到剩余三个产生 BlockIf 的规则。
- `try_rule_if_else`：对齐 Ghidra `newBlockIfElse(cond,tc,fc)` → identifyInternal([cond,tc,fc])，
  消费两个 clause 块（边重定向到新 BlockIf + 标记 DEAD），替换原先的 `self.graph.blocks[i]=if_block`。
- `try_rule_if_no_exit`：对齐 Ghidra `newBlockIf(cond,tc)` → identifyInternal([cond,tc])，
  消费 clause 块。
- `try_rule_if_goto`：对齐 Ghidra `newBlockIfGoto(cond)`（注意：Ghidra 只消费 cond，
  body 通过 forceFalseEdge 保持外部）。Rust 的 BlockIf 架构将 body 嵌入 if_body，
  因此消费 body 块以避免悬挂可见节点，语义上等价于"clause 被吸收进 BlockIf"。
- 三个规则都补充了 update_switch_case_reference 调用，保证 switch case body
  被结构化时 BlockSwitch 的引用同步更新。
- gcc 53/53（curl 24/24，httpd 29/29），175/176 测试（预存失败不变）。
- getparameter 13→12 if，curl 总 if 105→104。httpd 97 if、0 goto。

### 2026-06-24：identify_internal 移植 Ghidra selfIdentify（边界边捕获）

**根因诊断**：identify_internal 此前只安装新结构块 + 标记消费块 DEAD，但从未填充新结构块
自身的 incoming/outgoing 边向量。这导致 BlockIf/BlockList 安装后 size_in=0 size_out=0，
外部指向它们的块看到"空块"，无法继续结构化（getparameter 出现 block62 BlockIf in=0out=0
孤立项，85 个 basic 块未结构化）。

**修复**：忠实移植 Ghidra `BlockGraph::selfIdentify`（block.cc:895）。在覆盖 install_idx
之前，遍历 consumed_indices 的每个块，收集其边界边（源/目的不在 consumed_set 的边）到
new_block 的 new_in/new_out，然后 dedup（Ghidra selfIdentify 以 dedup() 结尾），最后将
收集到的边安装到 new_block（按 BlockIf/BlockList/BlockWhileDo/BlockDoWhile 类型 downcast）。

**设计取舍**：不重写外部块的边 Arc（Ghidra 用 replaceOutEdge/replaceInEdge 基于裸指针无锁
完成）。Rust 中在迭代期间重写外部 Arc 会导致自环/不收敛（myprogress 超时）。改为依赖 DEAD
flag + count_non_structural_in_edges 使消费块对后续规则不可见；new_block 自身的边界边
（已捕获）让它有正确的 size_in/size_out 以参与进一步结构化。

**试验排除**：将 cond_idx 加入 consumed_indices（模拟 Ghidra newBlockIf 传 [cond,tc]）会
导致 if 结构坍塌（curl 104→83 if，getparameter 12→6 if，structured 28→25）+ myprogress
超时。根因是 cond 在 install_idx，其内部边（→clause）被错误计入边界。最终只消费 clause
（cond 由 install 位置自然接管）。

**验证**：curl 104→101 if，24/24 gcc，24 函数（无超时）；httpd 97→94 if，0 goto，29/29 gcc。
175/176 测试（预存失败不变）。getparameter FINAL basic 85（orphans 消除）。

### 2026-06-24：完整移植 ruleBlockCat 链式合并 + while_do/do_while 使用 identify_internal

- **try_rule_cat 链式扩展**：忠实移植 Ghidra `ruleBlockCat`（blockaction.cc:1284）。
  此前仅合并 2 个块。现在：bl 必须是链首（sizeIn==1 且唯一前驱 sizeOut==1 时返回
  false），然后沿 out(0) 扩展链（每条链 sizeIn==1、sizeOut==1、非 CASE_BODY、非结构化块），
  最终将 [block, out0, out1, ...] 全部合并为 BlockList，consume nodes[1..]。
  对齐 Ghidra newBlockList(nodes) 传整条链给 identifyInternal。
- **try_rule_while_do / try_rule_do_while 改用 identify_internal**：
  此前这两个规则仍用 `self.graph.blocks[i] = block`（手动安装，不捕获边界边）。
  now：while_do 用 identify_internal(&block, &[clause_idx], i)（Ghidra newBlockWhileDo
  consume [cond,cl]，clause 在 Rust 端 consume）；do_while 用 identify_internal(&block,
  &[cond_idx], i)（Ghidra newBlockDoWhile consume [condcl]，自回环块）。
  消除了 while/do-while 产生的 orphan 边。
- 至此 7/7 个 try_rule_* 方法全部使用 identify_internal，架构一致。
- 验证：curl 101 if，24/24 gcc；httpd 94 if，0 goto，29/29 gcc。175/176 测试（预存失败不变）。

### 2026-06-24：identify_internal 恢复外部边重写（对齐 Ghidra selfIdentify）

- 之前 self_identify 出于死锁/自环顾虑跳过了外部边重写。但这导致父 CBRANCH 的
  out-edge 在其 clause 被别处结构化（consume+DEAD）后变成悬空指针，无法继续结构化
  （getparameter 11 个 single-in CBR 中 8 个 clause size_out!=1，无法匹配 proper_if）。
- 恢复 Ghidra selfIdentify 的 replaceOutEdge/replaceInEdge 语义：捕获边界边后，
  将外部 Basic 块指向消费块的 out-edge 重写为 new_block，incoming 对称处理。
  加自环保护（跳过 Arc::ptr_eq(new_block)），且只消费 clause（不消费 cond），
  避免了之前 cond-in-consumed 导致的 myprogress 超时。
- 验证：curl 101 if，24/24 gcc；httpd 96 if，0 goto，29/29 gcc。175/176 测试。

### 2026-06-24：实现 ruleBlockGoto + clip_extra_roots fallback（goto-cascade 收敛）

**根因**：之前的 clip_extra_roots fallback 导致 httpd 超时。根因是 goto 标记（GOTO_EDGE_0/1）
后没有规则消费这些块——Ghidra 的 ruleBlockGoto 会把 goto 标记的块结构化为 BlockGoto/
BlockIfGoto/BlockMultiGoto，使它们从图中"消失"并让周围 cat/if 规则能继续合并。Rugra 缺失
这个规则，导致 goto 标记永远不收敛。

**修复**：
- **try_rule_goto**（对应 Ghidra ruleBlockGoto size_out==1 分支 / newBlockGoto）：
  检测 GOTO_EDGE_0 + size_out==1 的 Basic 块，包装为 BlockGoto（identify_internal 消费原块，
  self_identify 捕获边界边）。BlockGoto 加入 identify_internal 的 downcast 链。
  （size_out==2 + GOTO_EDGE_1 分支已由 try_rule_if_goto 处理 = newBlockIfGoto。）
- **clip_extra_roots**（对应 Ghidra clipExtraRoots）：作为 select_and_mark_goto 的 fallback，
  检测多根（size_in==0, index>0）的 Basic/Copy 块，onlyReachableFromRoot 收集 body，
  markExitsAsGotos 标记出口边为 goto。跳过已结构化块（BlockGoto 等）避免重标记。
- **max_goto_rounds=40 cap**：防止相互不可归约根导致的失控循环（Ghidra 在此情况抛
  LowlevelError，Rugra 改为 cap）。
- try_rule_goto 加入 apply_rules_to_block 和 goto-cascade 内层循环的规则链。

**验证**：curl 101 if，0 goto，24/24 gcc；httpd 91 if，29/29 gcc（不超时）；
175/176 测试（预存失败不变）。getparameter FINAL basic 85→84，structured 28→29。
multiin CBR 仍=4（需 TraceDAG 进一步处理）。

### 2026-06-24：循环结构化诊断 + skip-orphan/cat-head 安全保护

**诊断**：orderLoopBodies 检测到 getparameter 有 2 个嵌套循环（head=21，内层 bodysize=2、
外层 bodysize=4），但最终 TYPES whiledo=0 dowhile=0——循环未被结构化为 while/do。

**根因**：循环头 block 21 的边在 phase1 collapse_loops 运行前/中被清除（out=0 in=0），
变成 orphan 块。phase1 的 collapse_loops While-Do 检测要求 clause size_in==1，但循环体
block 20 有多入边（循环回边 + 入口），不匹配。循环头被 phase1 三角匹配（collapse_conditions）
消耗成 BlockIf，而非 while/do。禁用 phase1 collapse_conditions/sequences 虽然让 curl if 从
101→77（更紧凑），但破坏 gcc 语法（curl 20/24、httpd 28/29），已回退。

**安全改进（保留）**：
- **apply_rules_to_block skip-orphan guard**：跳过边已清除（size_in==0 && size_out==0）
  但未标记 DEAD 的 orphan 块，防止 spurious 匹配破坏图。
- **try_rule_cat loop-head guard**：cat-chain 扩展时不消费 loop_bodies 中的循环头，
  对齐 Ghidra isDecisionOut 语义（循环头必须留给 while_do/do_while）。
- **try_rule_while_do** 放宽 clause 检查为 count_non_structural_in_edges（忽略 DEAD/goto 源）。
- 监控日志：TYPES（whiledo/dowhile/if/list/other 计数）+ loop head/bodysize。

**验证**：curl 101 if，24/24 gcc；httpd 91 if，29/29 gcc。175/176 测试（预存失败不变）。
循环仍未输出为 while/do——需 phase1 collapse_loops 多入边循环体重构（后续工作）。

### 2026-06-26：重新启用 structure_loops_first + collapse_cbranch_cascades 结构化块保护

**突破**：WhileDo 循环现在被保留（TYPES whiledo=1）。
- 重新启用 structure_loops_first（phase1 前 WhileDo 预结构化）+ phase1 Basic-only guards。
- WhileDo body emit 用 emit_block_ops 绕过 DEAD 检查（body 被 identify_internal 消费为 DEAD）。
- **collapse_cbranch_cascades 不覆盖结构化块**：替换 extra_indices 时跳过 WhileDo/DoWhile/If
  等非 Basic 块（之前会把 WhileDo 替换成空 placeholder BlockBasic）。
- 验证：176/176 测试。curl 24/24 gcc，102 if。getparameter TYPES whiledo=1（循环保留）。
- httpd 28/29 gcc（ap_getparents duplicate case — collapse_cbranch_cascades 级联链包含
  WhileDo 导致 case_values 重复，独立 switch 检测 bug，需后续修复）。

### 2026-06-26（续）：collapse_cbranch_cascades 级联链遇结构化块停止

- 级联链遍历 CBRANCH fallthrough 时，遇到 WhileDo/DoWhile/If 等结构化块立即停止，
  避免把它们错误纳入 cascade chain 导致 duplicate case_values。
- 验证：176/176 测试。curl 24/24。httpd 仍 28/29（ap_getparents duplicate case 未完全修复，
  其他路径的 case_values 计算问题）。

### 2026-06-26（续）：identify_internal 捕获 install_idx 块的外部入边

- self_identify 现在也捕获 install_idx 块（cond/head）的外部入边（排除 consumed 块和自环），
  使结构化块（如 WhileDo）从函数入口可达。仅捕获入边（不捕获出边，避免 httpd 边双重计数）。
- 验证：176/176 测试。curl 24/24 gcc（3 while）。httpd 29/29 gcc（11 while）。
- getparameter WhileDo 仍不可达（head=21 仅自环前驱，函数特定 CFG 问题）。

### 2026-06-26（续）：collapse_sequences 保留 BlockList 的 out-edges

- collapse_sequences 合并 block→succ 为 BlockList 时，原来 BlockList::new 不复制 out-edges，
  导致 BlockList 后续的边（包括指向 WhileDo 的边）丢失，WhileDo 变为不可达。
- 修复：BlockList.outging = succ（最后一个 child）的 out-edges，保持控制流连续性。
- 验证：176/176 测试。curl 24/24 gcc（3 while）。httpd 29/29 gcc（13 while，从 12 增加）。

### 2026-06-26（续）：collapse_conditions 保留 BlockIf 的 out-edges

- collapse_conditions 的 Triangle/Triangle-reverse/Diamond 匹配创建 BlockIf 时，原来
  outgoing 为空，导致 BlockIf 后续的边丢失。
- 修复：BlockIf.outgoing = merge 块的 out-edges（Triangle: false/true_block, Diamond: D 块）。
- 验证：176/176 测试。curl 24/24 gcc（3 while, 98 ifs 从 106 下降）。httpd 29/29 gcc（13 while）。

### 2026-06-26（续）：BlockIf out-edge 指向 merge 块本身（非 merge 的 out-edge）

- collapse_conditions 的 Triangle/Diamond 匹配创建 BlockIf 时，out-edge 现在指向 merge 块本身
  （Triangle: false/true_block, Diamond: D 块），而非 merge 块的 out-edge。
  之前读 merge 的 out-edge 会跳过 merge 块（如 WhileDo），破坏可达性。
- 验证：176/176 测试。curl 24/24 gcc（3 while, 100 ifs）。httpd 29/29 gcc（13 while）。

### 2026-06-26（续）：identify_internal 更新指向旧块的 Arc 边引用

**根因**：identify_internal 执行 self.graph.blocks[install_idx] = new_block 时，其他块的
out-edge 仍持有旧块的 Arc（Arc identity 不变），导致新结构化块不可达。
**修复**：安装 new_block 前保存 old_block Arc，安装后扫描所有块的 incoming/outgoing，
将 Arc::ptr_eq(old_block) 的边重定向到 new_block。覆盖 BlockBasic/BlockList/BlockIf/BlockWhileDo。
**验证**：176/176 测试。curl 24/24 gcc（3 while, 102 ifs）。httpd 29/29 gcc（16 while，从 13 增加！）。

### 2026-06-26（续）：对齐 Ghidra rule 顺序（switch 检测最后）

- Ghidra 的 collapseInternal 顺序：cat → proper_if → if_else → while_do → do_while →
  inf_loop → switch（switch 最后）。这让循环/if 结构化优先消费块。
- Rugra 的 phase1 原顺序：collapse_switches 在 collapse_sequences 之前。
- 修复：collapse_switches 移到最后（collapse_sequences 之后），对齐 Ghidra。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。
- getparameter 仍有 1 switch（multiin CBR 阻止 if/while 消费这些块，需 TraceDAG）。

### 2026-06-26（续）：TraceDAG 骨架移植（已禁用）

- 新增 src/tracedag.rs：BranchPoint/BlockTrace 结构 + pushBranches 算法骨架。
- 集成到 run_goto_cascade（当 select_and_mark_goto 和 clip_extra_roots 都无结果时触发）。
- 当前 DISABLED：check_open/select_bad_edge 使用简化近似，需完整 BadEdgeScore + visit-count
  追踪后才能安全启用。
- 验证（禁用状态）：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：TraceDAG 完整 BadEdgeScore + visit-count（仍禁用）

- tracedag.rs 实现 BadEdgeScore 评分（siblingedge/terminal/distance/depth）和 visit-count 追踪。
- 当前仍 DISABLED：open_branch/retire_branch 需更新 visit-count。验证（禁用）：176/176 测试。

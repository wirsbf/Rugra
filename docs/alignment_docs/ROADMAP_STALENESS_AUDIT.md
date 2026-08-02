# ALIGNMENT_ROADMAP 过期核实（2026-08-02）

**触发原因**: ROADMAP 头部"最后核实 2026-06-27"，之后已有 **733 commit**（06-27 起：175 + 553 + 5）。
用户问"代码层面不是对齐的吗，为什么差距这么大"——必须实地对比，不能信 ROADMAP。

## 实测发现总览

### A. coreaction.rs 71 个 Action 中 **26 个有占位/简化标记**

通过扫描 `impl Action for Action*` 块内的 red-flag 词（partial/simplified/doesn't/stub/placeholder/todo/not yet/conservative）：

| Action | 红旗（来自代码注释）|
|--------|------|
| **ActionDefaultParams** | "No Funcdata lookup available", "doesn't have pcode injection for calls yet" |
| **ActionFuncLink** | "Heritage::guard_calls is a stub" |
| **ActionCallParams** | 用 placeholder varnode 凑数 |
| **ActionDeindirect** | "Rugra does not yet model" |
| **ActionDirectWrite** | "Rugra lacks propagateIndirect flag (TODO)" |
| **ActionNodeJoin** | "Simplified: remove from block1" |
| **ActionReturnRecovery** | "substitutes for the (stub) function-level guardReturns" |
| **ActionSwitchNorm** | "does not yet clone a partial Funcdata" |
| **ActionUnjustifiedParams** | "Simplified: scan ... create a placeholder" |
| ActionHeritage | guard "simplified" |
| ActionDeadCode | "not yet"（部分语义） |
| ActionRestructureVarnode | TODO |
| ActionMergeRequired | TODO |
| ActionPrototypeWarnings | simplified |
| ActionMarkExplicit | simplified |
| ActionMarkImplied | "conservative for rare chained" |
| ActionConstbase | Partial implementation |
| ActionParamDouble | Partial implementation（只统计不修改）|
| ActionShadowVar | placeholder |
| ActionSegmentize | Partial implementation |
| ActionInternalStorage | Partial implementation |
| ActionLaneDivide | stub |
| ActionForceGoto | stub |
| ActionStartTypes | not yet |
| ActionCopyMarker | not yet |

**真实 L3（完整对齐 + 接入 + 验证）的 Action 远少于 71 个**。但其中很多是底层
数据维护 Action（Start/Constbase/NormalizeSetup）—— 即便简化也不影响输出质量。

### B. varmap.rs 实地对比（agent 报告，class 级别）

ROADMAP 声称 "RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐" —— **过度自信**：

| 类 | Ghidra 方法数 | Rust 对齐 | 缺失/占位 |
|----|--------------|-----------|----------|
| **RangeHint** | ~10 | ✅ 真实 1:1 | 无 |
| **AliasChecker** | 8 | 🟡 5/8 | `gather`/`deriveBoundaries` 是 stub，prototype-driven boundaries 缺失 |
| **MapState** | 10 | 🔴 4/10 | `gatherSymbols`/`reconcileDatatypes`/`addGuard`(LoadGuard) **完全缺失**；`addRange` 缺 sign extension |
| **ScopeLocal** | ~17 | 🔴 ~7/17 | `createEntry` **不构造数组类型**（`char format[40]` bug 根因）；`markNotMapped`/`adjustFit` 是 stub；整个 name/type recommendation engine 缺失 |

### C. 5 个用户可见 bug 的代码根因（已定位到 file:line）

| Bug | 根因 file:line | Ghidra 对应 |
|-----|---------------|------------|
| 函数原型错（参数数量）| coreaction.rs:5580-5610 ActionDefaultParams::apply 占位 | coreaction.cc:2418-2442（`fc->copy(otherfunc->getFuncProto())` + `fc->insertPcode(data)` 完全缺失）|
| 重复 `bool V; bool V; bool V;` | printc.rs:3028-3046 rename_scope_symbol cache（待 agent 1 复核）| — |
| 数组类型丢失（无 `char format[40]`）| varmap.rs:1560-1574 ScopeLocal::create_entry 不构造数组 | varmap.cc:618-629 用 `getTypeArray(num, ct)` |
| `local_0` 出现在循环条件 | printc.rs:3713,3732 Rugra 自造 heuristic（不是 Ghidra fallback）| Ghidra 用 `Stack_<hex>` / `StackX_<hex>` |
| do-while(!(local_0)) 死循环 | 待核实（ruleBlockDoWhile 规则位置/触发条件）| blockaction.cc:1555-1577 要求 bl->getOut(i)==bl（块必须自回环）|

### D. flow.cc / funcdata 的架构级替代（ROADMAP 已承认）

- `flow.cc` 完全缺失（📋 L1），用 `inject_raw_ops` + `build_blocks_from_ops` 线性扫描替代
- 注释 `// RUGRA-GLUE: 从全部 alive ops 构建 CFG（FlowInfo 流追踪后调用）` 自己承认是 GLUE 不是 port
- 影响：跳转表流内展开、子函数内联、truncatedFlow 都没有 —— 对 curl 这种简单函数能跑，但复杂函数会漏代码

### E. ROADMAP 的 L3 声明过度自信（ROADMAP 头部自己承认）

ROADMAP 头部原话：
> **新 L3 标准**：只有当 Ghidra 源文件中**所有 public 算法**都在 Rust 侧有 1:1 对应实现、且通过测试或反编译输出验证，方可标 L3。
>
> 此前路线图存在**过度自信声明**：许多模块被标"✅ L3 完整实现"但实际仅有数据结构骨架

按这个标准，**printc.rs 标的 "✅ L3 完整对齐" 是有问题的**：
- doc_function / emit_block_ops 等方法存在
- 但 RPN 表达式重建路径 `dispatch_op_rpn` 是空跑的（前置 Rule 不生成 PTRSUB/CAST op）
- 所以 printc 的"对齐"是**形式上的方法覆盖**，不是**实际算法生效**

## 铁律违反程度

AGENTS.md 铁律 1.4 明确禁止：
> ❌ 把 Ghidra 有的东西标 `// TODO` / `// simplified` 而无 `ALIGNMENT_ROADMAP.md` 记录

实际代码：
- coreaction.rs 26 个 Action 有 `// simplified` / `// TODO` / `// placeholder` 等标记
- ROADMAP 没有逐条记录这些降级
- 注释里同时写 "Faithful to" 又写 "Partial implementation" —— 自相矛盾，违反铁律 1.3（每个函数必须有准确的 `// Ghidra:` 注释）

## 与 curl 输出差距的对应关系

| 输出问题 | 主要责任模块 | 实际状态 | 修复 ROI |
|---------|------------|---------|---------|
| 函数原型错（参数数量/类型）| ActionDefaultParams + ActionFuncLink | 🔴 占位 | 高（影响每个函数）|
| 调用参数丢失 | ActionFuncLink + ActionCallParams | 🔴 占位 | 高 |
| 数组类型丢失 | varmap.ScopeLocal::create_entry | 🔴 单点 bug | **极高（5 行修复）** |
| 重复 `bool V;` | printc rename_scope_symbol | 🟡 缓存逻辑（待 agent 1）| 中 |
| `local_0` heuristic | printc.get_stack_variable_name | 🟡 Rugra 自造 | 中（需先修 varmap 让 find_symbol 命中）|
| 表达式破碎 | printc RPN 路径 + RulePtrsub | 🔴 RPN 不触发 | 高（需补 PTRSUB 生成）|
| CALL 渲染坏 | printc.op_call | 🔴 待 agent 1 | 高 |
| do-while 死循环 | ActionBlockStructure | 🟡 待核实 | 中 |

## 修复优先级建议（按 ROI）

1. **极高 ROI：varmap.ScopeLocal::create_entry 构造数组**（~5 行修复）
   - 直接解决 `char format[40]` / `bool line[256]` 缺失
   - 对齐 Ghidra varmap.cc:618-629 的 `getTypeArray(num, ct)`

2. **高 ROI：ActionDefaultParams 真对齐**
   - 解决每个函数参数数量错误
   - 需要 Funcdata lookup（calltarget → Funcdata）+ insertPcode

3. **高 ROI：ActionFuncLink + ActionCallParams 真对齐**
   - 解决 CALL 渲染参数丢失
   - 依赖 Heritage::guard_calls（目前是 stub）

4. **高 ROI：printc RPN 路径激活**
   - 解决表达式破碎
   - 依赖 RulePtrsub / RulePtrArith 生成 PTRSUB op（plan-sess_24510194 已设计）

5. **中 ROI：MapState 三个缺失方法**（gatherSymbols/reconcileDatatypes/addGuard）
   - 解决变量名破碎、local_0 heuristic

## 待补充（agent 报告完成后更新）

- agent 1（printc RPN 是否走 + CALL/param_N bug 根因）—— 进行中
- agent 3（管线结构是否还扁平 + repeatapply）—— 进行中

# IR 层逐步差异分析（2026-08-02，IR agent 报告）

**方法**: 用 `dump_ir --seed`（与 curl_decompile 同样的 DWARF 全局指针 seeding）dump
5 个函数的 PRE/POST pipeline P-code IR，对照 Ghidra 黄金 IR（main 可用）。

## 关键发现：4 类关键 op 全为 0

| op | Ghidra main | Rugra main | Ghidra 期望 | 影响 |
|----|-------------|------------|-------------|------|
| MULTIEQUAL (phi) | 1628 | **0** | SSA 合并节点 | 无跨分支值追踪 |
| INDIRECT | 5339 | **0** | call/store 副本 | 无副作用 SSA |
| CAST | 43 | **0** | 类型转换 | 无显式类型转换 |
| PTRSUB | 20 | **0** | 结构字段访问 | 无 ->field 渲染（IR 层）|
| PTRADD | 18 | **0** | 指针算术 | 同上 |

**所有 5 个采样函数都是 0**（myprogress/glob_url/my_fwrite/GetStr/main）。

## Gap 1: Heritage 不放 phi（最大缺陷）

**根因**: `src/coreaction.rs:163` `ActionHeritage::apply` 调 `place_multiequals_direct`
**之前没调** `fd.bblocks.build_dom_tree()`。

`place_multiequals_direct` 读 `bblocks[i].get_dom_frontier()`（heritage.rs:3412），
该字段由 `build_dom_tree` → `calc_dom_frontier`（block.rs:1858）填充。没调 build_dom_tree
→ dom_frontier 全空 → 零 phi 节点放置。

**Ghidra 对照**: `heritage.cc:2674` `if (maxdepth == -1) buildADT();` —— buildADT 在
Heritage::heritage() 内部构建 dominator tree。

**历史**: build_dom_tree 曾在 ActionHeritage 里，commit fb6d912/683fca0 因"性能"移除。
但性能问题后来被定位为 rename_direct 死锁（commit 84bf42f 已修），不是 build_dom_tree 本身。

**修复尝试（2026-08-02）**: 在 ActionHeritage::apply 加 `fd.bblocks.build_dom_tree()`
→ **整个管线挂**（所有函数超时）。说明 phi 生成暴露了下游 rename_direct / DeadCode /
其他 Actions 的未测 bug。需要专门的多 session 工作来逐步修复下游。

## Gap 2: RulePtrArith 不触发

**根因**: `src/ruleaction.rs:15188` RulePtrArith 要求 INT_ADD 输入的 type 是 Pointer。
但 `ActionInferTypes`（coreaction.rs:4101）从不给**输入参数** varnode 标 Pointer 类型
（argv、stack pointer 都是 Int）。Pointer 类型确实在全局地址常量上 seed，但那些 COPY
链被 DeadCode 移除了。

**修复方向**: (a) 依赖 Gap 1 修好（SSA 正确才能做基于用法的指针推断）。(b) 在
ActionInferTypes/ActionInferParams 加输入参数指针推断（如果 input 流入 LOAD/STORE
指针槽，标 Pointer）。(c) 别在 RulePtrArith 之前 DeadCode 掉全局 seed COPY 链。

## Gap 3: CAST 下游缺陷（依赖 Gap 1+2）

`ActionSetCasts`（coreaction.rs:3274）实现完整正确，但没有 PTRSUB 可工作 + 所有
varnode 都是 Int → 无 CAST 插入。Gap 1+2 修好后会自动开始产生 CAST。

## printc 的 mapentry workaround

12 个 `->field` 访问**不来自** PTRSUB ops。printc.rs STORE handler（行 1173-1219）
直接从 ActionHeritage stamp 的 mapentry（SymbolEntry）合成 `gname->fieldname`，绕过
了缺失的 PTRSUB。所以打印机**掩盖**了 PTRSUB 缺陷（仅对 2 个 seeded 全局变量）；
所有其他指针算术渲染错误。

## Follow-up 计划

修复 Gap 1（phi 生成）需要**多 session 渐进工作**：

### Phase 1: 单函数验证（小函数先）
1. 加 `build_dom_tree` 到 ActionHeritage
2. 用最小函数（my_fwrite, 103 ops）测试，看 phi 是否生成 + rename 是否完成
3. 逐步定位下游挂点（DeadCode? MergeTypes? printc?）

### Phase 2: rename_direct 容量
- main 函数 1628 phi × rename DFS 可能爆栈或循环
- 检查 visit_rename_direct 的 dom-tree walk 在大函数下的复杂度

### Phase 3: 下游 Action 适配
- DeadCode: phi 节点的 consumed-bit 传播
- MergeType: HighVariable 合并含 phi
- printc: phi output 的命名/渲染

### Phase 4: 全量验证
- 24/24 函数完成
- defects=0
- gcc audit 提升

## 当前状态（Gap 1 修复尝试已 revert）

- gcc audit: **17/24 OK**（+10 自 baseline 7/24）
- skeleton diff: 2845
- defects: 0, numbering: 1
- 24/24 函数反编译，0 超时（baseline 稳定）

## 本 session 累积成果

| commit | 改动 | gcc delta |
|--------|------|-----------|
| 84bf42f | heritage deadlock fix | 7→24 timeouts resolved |
| 705e7a0 | ActionInputPrototype/UnjustifiedParams ABI filter | 函数原型正确 |
| 303795f | ScopeLocal::create_entry 数组类型 | 数组类型出现 |
| efab97a | build_rpn_token_table 21 个二元 token | (infra) |
| f77f9bf | 删 flat build_full_pipeline_actions 循环 | -124 skeleton diff |
| e7c2d34 | merge.rs in_N 命名 + audit_syntax typedef | 7→12 OK |
| e29f2cb | rpn_push_op open_group vs open_paren | 12→**17 OK** |

总 gcc audit: **7/24 → 17/24 OK**（+10 函数编译通过）。

# P0 "变量声明却从未赋值" 根因诊断

**日期**: 2026-06-29
**方法**: systematic-debugging（Phase 1 根因调查 → Phase 3 受控实验 → 证据确认）
**症状**: curl `my_fwrite` 输出中 `piVar2/lVar1/lVar2/lVar5/iVar1/bVar1` 等"声明了却在赋值前被读"
**结论**: **推翻两个流传的错误假设；定位真正根因到 printc 层**

---

## 一、被推翻的两个错误假设（重要）

### ❌ 假设 1："heritage SSA rename 跨块断裂"

**来源**: `QUALITY_GAP_ANALYSIS_2026-06-29.md` 差距 1，用词"**可能**在跨块场景断裂"（未验证猜测）。

**证据（推翻）**:
- 逐行对比 Ghidra `renameRecurse`（heritage.cc:2480）与 Rugra `visit_rename_impl`（heritage.rs:431）：算法结构一致（Cytron 式）
- `debug_my_fwrite` 打印 heritage 后 P-code（39 ops）**def 链完整**：
  - `[14] CALL 0x2500`（fwrite）前 `[12] RSI=...` `[13] RDI=...` 参数正确设置
  - `[24] CALL 0x24b0`（fopen）前 `[22] INT_ADD RSP+8` `[23] STORE val=RDX` 参数完整
  - `[32] STORE val=RAX`（fopen 返回值存栈）+ `[33] RCX=COPY RAX` def 完整
- funcdata.rs 有 4 个跨块 SSA 测试（diamond/phi/single/multi block）全过

**SSA 层不是根因。** 唯一存在的次要差异：Ghidra 在 input 重写时 stack 空会 `newUnique+setInputVarnode` 兜底（heritage.cc:2500-2504），Rugra 没有——但这不造成"声明却未赋值"。

### ❌ 假设 2："ActionCopyPropagate 未完整传播 / 双重 copy 消除"

**来源**: 同上差距 1/3/4，反复点名 `ActionCopyPropagate`。

**证据（推翻）**:
- **Ghidra 根本没有 `ActionCopyPropagate` 这个类**。核对 `coreaction.cc` 全部 70+ 个 `new Action*` 列表，无此项。Ghidra 的 copy 传播真名是 **`RulePropagateCopy`**（ruleaction.cc:3944），跑在 `actprop` Rule 池（coreaction.cc:5566）。差距分析连对象名字都错了。
- **受控实验（Phase 3）**：用 env 门控临时禁用 Rugra 的 `ActionCopyPropagate`（action.rs:422），只留对齐 Ghidra 的 `RulePropagateCopy`，重跑 `debug_my_fwrite`：

  ```text
  # baseline（ActionCopyPropagate 开）           # 实验B（ActionCopyPropagate 关）
  lVar4 = RSP + 0xff0;                            lVar2 = RSP + 0xff0;
  piVar1 = param_4 + 8;                            piVar2 = param_4 + 8;
  lVar3 = *(long *)piVar1;                         lVar3 = *(long *)piVar2;
  if (lVar3 == 0) {                                if (lVar3 == 0) {
    *(long *)(RSP+0x8) = param_3;                    *(long *)(RSP+0x8) = param_3;
    fopen(*((long *)piVar2), ...);   ← 未赋值       fopen(*((long *)piVar1), ...);   ← 仍未赋值
    *(long *)(lVar5 + 0x8) = lVar2;  ← 未赋值       *(long *)(lVar4 + 0x8) = lVar1;  ← 仍未赋值
    if (lVar1 != 0) return;          ← 未赋值       if (lVar5 != 0) return;          ← 仍未赋值
  ```

  **症状本质完全不变**，仅变量编号错位。→ 双重 copy 消除不是主因。

**实验价值**: 一个干净对照实验推翻了静态分析假设——这正是 systematic-debugging Phase 3 的意义。

---

## 二、真正的根因（基于证据）

### 根因：printc 用自造的 map 子系统代替了 SSA def-inline，且声明来源是"被读取过的名字"

**证据链**:

1. **heritage 后 P-code def 完整**（见上），但**管线运行后 loc_tree 中每个 Unique offset 都有成对同名 varnode**：一个 `def=op@...`、一个 `def=INPUT`：
   ```
   Unique off=0x1038 size=8 def=op@34a2/22 high='uVar29' type=long   ← 有 def
   Unique off=0x1038 size=8 def=INPUT      high='uVar29' type=long   ← 无 def，同名
   ```
   这是 **HighVariable 合并（merge）的产物**：同一 HighVariable 聚合多个 SSA 实例，有的有 def、有的是 INPUT。

2. **声明来源 = "body 中被读取过的 varnode 名"**（printc.rs:1199-1215 `doc_variable_decls_from_funcdata`）：遍历 `used_varnode_types`，凡被引用的名字就声明。**不检查该名字是否有 def**。

3. **读取产生点 = `push_varnode`（printc.rs:4084）**：遇到 varnode 只查 HighVariable 名字并打印变量名（printc.rs:4152-4173），**不去 inline 其 def 表达式**。`resolve_varnode`（printc.rs:1541）只做 `copy_map` 查表，不沿 SSA def 递归 inline。

4. **自造子系统**：printc 维护 `copy_map`/`def_map`/`value_def_map`/`comparison_def_map` 四套 map（printc.rs:2715-2840），用"地址/指针键"手工重建 Ghidra 的 HighVariable 关系。这是**绕过 Rugra 缺真正 merge pass 的补丁**，但在 def 查找上不完整——找不到时就回退打印变量名 → "声明却未赋值"。

### Ghidra 的正确机制（ground truth，待移植）

Ghidra 不在 printc 里重建 def 关系。它有权威的 **HighVariable merge pass**（`merge.cc`，已在 ALIGNMENT_ROADMAP 标 L2 算法不完整）：
- `Merge` 把同地址的多个 SSA varnode 合并成 HighVariable，保证每个 HighVariable 至少一个有 def 的实例
- printc 遍历 HighVariable 的 `instances`，选**有 def 的那个** emit 表达式（不会输出"无 def 实例"）
- 根本不存在 printc 自己查 def 的逻辑

---

## 三、修复路径（按对齐铁律 #5：移植 Ghidra 机制，不绕过）

### ✅ 正确路径（移植 Ghidra 机制）

**P0-Fix-1（推荐，治本）**：完善 `merge.cc` → merge pass，让 printc 依赖权威的 HighVariable。具体：
- merge 把同 offset 的 SSA 实例聚合，标记"代表实例"（有 def 的那个）
- printc 的 `push_varnode` 改为：沿 HighVariable 找代表实例，inline 其 def（而非打印变量名）
- 移除 printc 的 4 套自造 map（`copy_map`/`def_map`/`value_def_map`/`comparison_def_map`），它们是 merge 缺失的补丁

**P0-Fix-2（治标，先止血）**：printc 的 `push_varnode` 增加 def 检查——若 varnode 无 def（`def=None` 或 def op 已死），沿 HighVariable 找有 def 的兄弟实例 emit；全无 def 才退化打印变量名。这能消除"读未赋值变量"，但保留自造 map（技术债）。

### ❌ 禁止的"修复"（违反铁律 #5）

- 禁止在 printc 里加"如果变量没赋值就不声明"——那是症状掩盖，变量会被读到却不存在 = 编译错误
- 禁止禁用/移除某个 Action/Rule 来"减少未赋值变量"——实验已证明 copy-prop 不是主因

---

## 四、实验产物处置

- `src/action.rs:422` 的 env 门控代码已**还原**（实验完成，不留 throwaway 代码）
- 工作树干净，git status 无变更
- 本文档是本轮产出（铁律 #2 不空轮）

## 五、证据可复现命令

```bash
# 复现 baseline 症状
cargo run --release --example debug_my_fwrite 2>/dev/null | tail -45

# 查看 heritage 后 P-code（证明 def 链完整）
cargo run --release --example debug_my_fwrite 2>&1 >/dev/null | sed -n '/=== P-code after heritage/,/=== After full pipeline/p'

# 查看管线后 varnode def（证明同名 varnode 一有一无 def）
cargo run --release --example debug_my_fwrite 2>&1 >/dev/null | sed -n '/=== After full pipeline/,/=== Output/p' | grep Unique
```

---

## 六、治本进展（2026-06-29 续：merge 权威化 + implied 移植调查）

### 已完成并提交（4 commit，已验证）

| commit | 内容 | 效果 |
|---|---|---|
| f61bd18 | merge: is_live_varnode 过滤 | merge 跳过死 varnode（后被 live_set 取代） |
| efb02ba | core: move ActionMergeType 到 dead-code 之后 | 对齐 Ghidra coreaction.cc:5682→5718 顺序 |
| f5f5653 | merge: live_set 权威存活集 | 修正 is_live_varnode 的错误判定（def-dead 不可靠，改用"被 alive op 引用"） |
| 0e1cd48 | printc: push_varnode Priority 1.4 | 沿 high.get_type_representative() inline def |

**判据 1（HighVariable.instances 权威）已达成**：merge 在 dead-code 后运行 + live_set 过滤，instances 只含被 alive op 引用的 varnode。780/780 测试通过，curl 审计 24/24。

### 关键修正：is_live_varnode → live_set

`is_live_varnode` 初版用 "vn.def 的 op 是否 dead" 判存活——**错误**。诊断证据（debug_my_fwrite）：loc_tree=108 varnode，is_live_varnode 只通过 10 个（29 个 written-with-dead-def 被误杀）。根因：copy-prop 重定向 `user.inrefs[slot]` 后**不更新**旧 varnode 的 vn.def（仍指向已 mark_dead 的 COPY）和 vn.descend（清空）。所以 def/descend 在 copy-prop 后不可靠。正确判定：**varnode 是否被某 alive op 的 inrefs/output 引用**（live_set）。

### implied 机制移植调查（判据 3"删 map"的正确路径）

按铁律 #6 读 Ghidra printc.cc 发现：**Ghidra printc 没有任何自建 map**（copy_map/def_map/value_def_map/comparison_def_map 全不存在）。Ghidra 控制内联的唯一权威机制是 **`isImplied()` 标志 + `ActionMarkImplied` pass**：
- `ActionMarkImplied`（coreaction.cc:3416）DFS 遍历 varnode，用 `checkImpliedCover`（cover 相交检测）判定哪些 varnode 可 implied
- `printc.cc:2704` `if (vn->isImplied()) continue` — implied output 的 op 不作为独立语句输出
- implied varnode 的 def 表达式通过 `recurse()`（表达式 emit 时递归输入）在消费者处 inline

**Rugra 现状**：
- `ActionMarkImplied` struct 已定义（coreaction.rs:2373）但**未接入管线**（action.rs 零命中），且是**简化版**（注释明说"no full Cover-based checkImpliedCover"，desc_count==1 就标 implied）
- `is_implied`/`is_explicit` 访问器 + `varnode_flags::IMPLIED/EXPLICIT` 标志位**已定义**
- `cover.rs` + `Varnode.cover` 字段**已存在**，`compute_varnode_covers` 已实现
- printc **完全不查 is_implied**（零命中），用 4 套自造 map 模拟内联

**架构差异（implied 移植的真正阻塞）**：Rugra printc 是 **op-遍历 + 自造 map** 架构（emit_block_ops 遍历 op 输出语句，push_varnode 是叶子）；Ghidra 是 **op-push + recurse** 架构（opcode 自己决定输出，recurse 递归展开输入）。

**验证证据**：尝试接入简化版 MarkImplied + printc 跳过 implied op → **输出变空**（commit 前撤回）。根因：简化版 MarkImplied 把单后代 varnode 都标 implied，printc 跳过这些 op，但 Rugra 的 push_varnode 不会在消费者处递归 inline（没有 recurse 等价物），所以这些 op 既不作为语句输出、也没在别处 inline，消失。

### implied 移植的正确路径（下一步）

完整移植 implied 机制需要：
1. **补全 ActionMarkImplied 的 cover 检查**（checkImpliedCover + inflateTest，依赖 cover 相交）
2. **重构 printc 表达式 emit 为 op-push + recurse 模型**（或在 push_varnode 遇 implied 时沿 def 递归 inline——已尝试的 Priority 1.4 是雏形，但需配合完整的 implied 标记）
3. 接入后 4 套 map 自然冗余（implied 接管内联决策）

这是独立的、比"删 map"更大的任务。当前已验证的 merge 权威化（4 commit）是其必要前提。

### my_fwrite 残留（判据 4）的独立阻塞

merge 权威化后 my_fwrite 未赋值变量 5→3，残留 3 个（`lVar_18`/`uVar_1050`/`uVar_1061`）的根因是 **CALL 返回值 def 缺失**：CALL op 无 output，RAX 返回值的 def 不建立。诊断证据：RAX varnode 只有 `def=INPUT`，无 `def=op`。这是 ActionReturnRecovery 需 active_output 的已知缺口（CURRENT_STATUS.md 记录），与 merge/implied 无关。

---

## 七、implied 机制完整移植（2026-06-29 完成，3 commit）

### 成果

完整移植 Ghidra 的 implied 控制机制（替代 printc 自造 map 做内联决策）：

| commit | 内容 |
|---|---|
| 3b4c34b | HighVariable.cover + update_internal_cover + update_high_covers（variable.hh:143 / variable.cc:324） |
| 89622e2 | checkImpliedCover + inflateTest + mark_implied（coreaction.cc:3376 / merge.cc:1616/1595） |
| e128161 | 接入管线（MarkExplicit+MarkImplied 在 MergeType 后）+ printc 跳过 implied op（printc.cc:2704）+ push_varnode 递归 inline（recurse 等价） |

### 验证

- **implied 工作**：my_fwrite 中间变量 `piVar1 = param_4 + 8` / `lVar3 = *(piVar1)` 被内联成 `if (*(long *)(param_4 + 0x8) == 0)`，消除冗余临时变量。
- **780/780 测试通过**，curl 审计 24/24，0 goto，0 uVar。
- **关键修复**：禁用 `propagate_cover_through_cfg`（merge.rs）——Ghidra Cover 是精确 def→use 范围，不是 CFG 前向可达性近似。传播到所有后继 `[0,MAX]` 让 cover 覆盖全图，破坏 inflateTest（每个输入都相交 → 0 implied）。精确范围后 implied 决策正确。
- **时序修复**：MarkExplicit+MarkImplied 放在 MergeType **之后**（Ghidra 的 MergeRequired 在 MarkImplied 前建 high，Rugra 的 merge_all 合并了 MergeRequired+MergeType，故 MarkImplied 跟在 merge_all 后）。

### 4 套 map 的现状

implied 机制现在控制内联决策（Ghidra 方式）。printc 的 4 套自造 map（copy_map/def_map/value_def_map/comparison_def_map）成为 implied 的**冗余回退**——Priority 1.5/1.7 仍在，但 implied（push_varnode 开头 + Priority 1.4）优先。物理删除是后续清理任务（78 处引用，风险高，建议独立 commit）。

### 已知非阻塞问题

- **重复声明（curl 17 个）**：A/B 实验证明是**预先存在的 bug**（禁用 implied 跳过后仍有 17 个），非 implied 引入。根因是 doc_variable_decls 的声明收集与 switch 块结构交互，独立于 implied。

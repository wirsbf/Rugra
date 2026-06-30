# Stack 空间架构对齐 — 待办与诊断方向

**日期**: 2026-06-30
**状态**: 阶段 5c 回归修复中

## 已完成（全部对齐 Ghidra，10 commit）

| commit | 内容 |
|---|---|
| a84a581 | loc_tree 排序含 address_space + iter_space |
| 7a2fc5d | Architecture/Funcdata stack space/spacebase 配置字段 |
| a64f75a | op.rs spacebase_ptr 访问器 + Funcdata::new_indirect_op |
| 2b3d69f | varnode free/input 去重 + discover_and_guard 框架 |
| 22afd75 | find_or_create_input_space（free/input-only 去重） |
| 991b773 | rename isHeritageKnown 检查 + 两 pass heritage |
| 9be2094 | loc_tree VarnodeCompareLocDef 排序对齐 |
| 56d809d | INSERT/activeHeritage flag 模型 + AGENTS.md 铁律 5.5 |
| 379bece | deadcode delay（Stack 空间 pass 0 保护）+ 两 pass 间插入 dead-code |
| 2d50b77 | printc 删除硬编码 RSP/RBP 名（RSP 137→0, RBP 18→0） |

## 当前回归

**引入点**: commit 991b773（rename isHeritageKnown + 两 pass heritage）
**症状**: curl gcc 审计 24/24 → 9/24（15 个 FAIL，全是 "lvalue required as left operand of assignment"）
**根因链**:
1. 991b773 改变了 rename 行为（isHeritageKnown 检查 + activeHeritage 标记）
2. 这改变了 SSA def-use 连接 → Merge 的 `live_set` 变小（某些 written varnode 不再被 alive op 引用）
3. ActionMarkImplied 发现这些 varnode `high=false`（Merge 没给它们建 HighVariable）
4. check_implied_cover 返回 false（无 HighVariable → return false）
5. 这些 varnode 被标记 explicit 而非 implied
6. emit_block_ops 输出它们为 `lhs = expr` 语句 → 产生 `(param_4 + 8) = param_4 + 8` self-assignment

## 诊断方向（下一步）

### 方向 1：对比 991b773 前后 Merge live_set 差异
- 在 991b773~1（即 22afd75）跑 curl，诊断 Merge `ensure_all_have_high` 的 filtered 数
- 在 991b773 跑同样诊断，对比差异
- 找出哪些 varnode 从 live 变成 dead（不在 live_set 里了）

### 方向 2：检查 inter-pass dead-code 是否误删
- ActionHeritage::apply 在 pass 1 和 pass 2 之间插入 ActionDeadCode
- 此时 heritage.pass=1，stack_deadcode_allowed = (1 > 1) = false → Stack 保护
- 但 Register/Unique varnode 正常 dead-code
- **可能问题**：pass 1 rename 后，某些 varnode 的 descend 链不完整（因为 isHeritageKnown 检查改变了 rename 的替换行为），导致 dead-code 误删它们

### 方向 3：检查 rename 的 isHeritageKnown 是否过于宽松
- Ghidra isHeritageKnown = `flags & (insert | constant | annotation)` — 检查 INSERT flag
- Rugra 的 `create` 不设 INSERT（对齐 Ghidra varnode.cc:1250）
- `set_def`/`set_input` 设 INSERT（对齐 createDef/makeInput→xref）
- **可能问题**：inject_raw_ops 的 output 创建（`create_with_space` + 手动设 def）可能没走 `set_def`，而是手动设 WRITTEN + def。如果没设 INSERT，这些 output 的 `isHeritageKnown` = false → rename 处理它们 → 但它们已经有 def（written），rename 应该跳过

**关键验证**：检查 inject_raw_ops 创建的 output varnode 是否有 INSERT flag。inject_raw_ops line 1620-1627:
```rust
let out_vn = self.vbank.create_with_space(out_raw.size, out_raw.space, out_raw.offset);
self.vbank.set_def(out_vn.clone(), Arc::downgrade(&op_ref.0));
```
`create_with_space` → `create`（不设 INSERT）→ `set_def`（设 INSERT）。所以 output **应该有** INSERT。✓

**但**: `find_or_create_input_space` 返回的 varnode（复用的 free/input）如果碰巧被后一个 op 的 `create_with_space` 复用了呢？由于排序键包含 input/written/free 分类，free 和 written 不会碰撞。✓

### 方向 4（最可能）：rename_direct 的 activeHeritage 标记范围
- `rename_direct` 遍历 loc_tree，对 `!is_heritage_known()` 的 varnode 设 `active_heritage`
- 这**包括** written varnode 如果它们没有 INSERT
- 但 written varnode 通过 `set_def` 有 INSERT → `is_heritage_known` = true → 不被标记 activeHeritage → rename 跳过
- **然而**：rename 的 input 替换逻辑是 `should_skip = is_heritage_known || !is_active_heritage`
- written varnode（INSERT=true）→ is_heritage_known=true → skip ✓
- free varnode（INSERT=false）→ is_heritage_known=false → check activeHeritage → 标记了 → 不 skip → rename 替换 ✓

逻辑看起来正确。问题可能在**两 pass 重复标记**：pass 2 的 rename_direct 对 pass 1 已 rename 过的 varnode 再次标记 activeHeritage。pass 1 rename 替换了 free varnode 的 input → 原 free varnode 被废弃（替换成 written version）。但它们仍在 loc_tree → pass 2 仍标记它们 → pass 2 rename 尝试替换它们（但已经没人用了）→ descend 链混乱。

### 方向 5（检查清单）
- [ ] inject_raw_ops output 是否通过 set_def 走（确认有 INSERT）
- [ ] 两 pass rename 的 pass 2 是否对 pass 1 已处理的 varnode 重复处理
- [ ] inter-pass dead-code 是否删了 INT_ADD output（descend 链断裂导致）
- [ ] Merge 的 live_set 对比 991b773 前后差异
- [ ] check_implied_cover 的 inflate_test 是否对新 HighVariable cover 产生误判

## 已验证正确的部分（不需重查）
- loc_tree VarnodeCompareLocDef 排序（input/written/free 分类）
- Stack INDIRECT 产生（curl 发现 STOREs：main=2, helpf=6 等）
- Stack varnode 存活（deadcode delay 保护，main=6 Stack varnodes）
- gather_varnodes 对 same-addr INDIRECT 跳过（对齐 varmap.cc:1145）
- RSP/RBP 寄存器名消除（137→0, 18→0）
- 780/780 测试通过

## 不做的事
- 不回退已提交的对齐工作（铁律 #8）
- 不用 stack_frame_size 绕过（铁律 #5.5）
- 不改 isHeritageKnown 语义回到 is_free（违反铁律 #5.5）

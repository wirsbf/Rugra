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
**根因链（已确认，非原假设）**:
1. 991b773 改变了 SSA，部分 Unique 输出 varnode 不再有 HighVariable（Merge 未覆盖）
2. 这些 varnode 落到 printc `push_varnode` 的 Priority 2 Unique-space fallback
3. **真根因（与 MarkImplied 无关）**：Priority 2 Unique 分支缺少 `!is_lhs` 守卫 → 在赋值左值处仍调用 `emit_inline_expr` 内联自身 def → `(a + 8) = a + 8;` 自赋值
4. Register-space 的 Priority 2 分支**有**该守卫，Unique 分支遗漏 → 不一致

**修复**: commit e32cc9a — Priority 2 Unique 分支加 `!self.is_lhs` 守卫（对齐 Ghidra `pushSymbolDetail`/`pushUnnamedLocation`：左值永远解析为命名位置，`recurse()` 内联只发生在读取侧）
**效果**: curl gcc 审计 **9/24 → 17/24**（15→6 FAIL）。780/780 测试通过。httpd 4/11。

## 剩余独立输出 bug（非 lhs-inlining，2026-06-30 核实）

curl 剩余 6 个 FAIL（1 个 `getparameter_constprop_0` 仅 stub conflicting-types，审计记为 FAIL 但实质可忽略）：

| 函数 | 行 | 错误 | 根因类别 |
|---|---|---|---|
| main | L103 | `maprintf(..., __stack_chk_fail();` | CALL 参数含嵌套 void-CALL，内联产生裸 `;` |
| myprogress | L69 | `piVar1 \| param_5` invalid operands (`int *` \| `long`) | 类型推断：指针被推为 `int *` 用于位运算 |
| glob_set | L62 | `piVar1 + malloc(0) * *(long *)(8 + 0x50) = 1;` lvalue | STORE 地址含嵌套 CALL（malloc），地址表达式无 `*()` 解引用包裹 |
| next_url | L57 | `strcpy(..., *((long **(long *)()piVar3 ...))` expected `)` | CALL 解析为类型转换 `long **(long *)()`，嵌套表达式括号错配 |
| match_url | L46 | `lVar1 = exit(3);` void value not ignored | void 返回函数被赋值（CALL 输出误生成） |
| __libc_csu_init | L44 | `lVar2 = (*(void(*)())0)();` void value not ignored | void 函数指针调用被赋值 |

**共性**: 全部归因于 **CALL 输出处理** 与 **类型推断/cast** 两个 Ghidra 机制未移植。详见下节。

## 剩余 bug 的 Ghidra 机制 vs Rugra 缺口（2026-06-30 核实）

### 缺口 A：CALL 输出无条件生成（影响：match_url / __libc_csu_init / main）

**Ghidra** `funcLinkOutput` (coreaction.cc:1521-1572)：
- 若 CALL 已有 output，先 `opUnsetOutput`（移除），让返回值恢复重新决定
- 若 callee 原型 **锁定**：仅当 `outtype != TYPE_VOID` 才 `newVarnodeOut`；void 函数（exit/__stack_chk_fail）**永不产生 output**
- 若原型 **未锁定**：调 `initActiveOutput()`（开 trial），**不立即建 output**；由 `ActionReturnRecovery`/`ActionActiveReturn` 后续决定

**Rugra** `func_link_output` (coreaction.rs:3976-3982)：
```rust
if has_output { return; }
fd.new_varnode_out(8, Address::new(0x0), op);  // 无条件建 RAX output
```
→ 每个 CALL 都有 8 字节 RAX output，包括 void 函数 → `lVar1 = exit(3);`

**修复方向**：移植 Ghidra 的 `isOutputLocked()/outtype==TYPE_VOID` 门控 + `initActiveOutput` trial 机制（需 FuncCallSpecs 的 output prototype 字段 + ActionActiveReturn）。

### 缺口 B：CALL-def 不被 implied 门控（影响：glob_set / next_url）

**Ghidra** `checkImpliedCover` (coreaction.cc:3401-3406)：
```cpp
if (op->isCall() || (op->code() == CPUI_LOAD)) { // loads crossing calls
  for(i=0;i<data.numCalls();++i) {
    callop = data.getCallSpecs(i)->getOp();
    if (vn->getCover()->contain(callop,2)) return false;  // 不 implied
  }
}
```
CALL 输出 varnode 的 cover 若包含另一个 CALL，**不能 implied** → `setExplicit()` → printc 用命名变量，不内联进表达式。

**Rugra** `check_implied_cover` (coreaction.rs:2496-2519)：
- 只有 LOAD-crossing-STORE 检查（且是简化版：同基本块即禁止，非真正的 cover.contain）
- **完全缺失** `op->isCall()` 分支 → CALL 输出可被 implied → 内联进 STORE 地址 / CALL 参数 → `malloc(0)` 裸出现在 `piVar1 + malloc(0) * ...` 中

**修复方向**：补 `isCall()` 分支 + 真正的 cover（Cover 类，op 序号区间）基础设施。这是个大工程（Cover 未移植），但对 printc 输出质量影响最大。

### 缺口 C：ActionSetCasts 类型对齐（影响：myprogress / next_url / glob_set 的 `int *` 误用）

**Ghidra** `ActionSetCasts` (coreaction.cc:2526-2700+)：op 的 `outputtype_token` 与 varnode 的 high-type 不一致时插入 cast（`castInput`/`castOutput`/`castStandard`）。`piVar` 被 LOAD 赋了 `int *`，用于 `INT_OR` 时 token 是 `long`，castStrategy 判定需 cast → 插入 `(long)piVar` 或 `(uint)`。

**Rugra**：`ActionSetCasts` 是空桩（L2.5），无 castStrategy、无 `outputtype_token`、无类型 flow 解析。类型推断是 merge 阶段的简化版（vn.v_type 沿 def 传播），不与 op token 对齐。

**修复方向**：移植 `ActionSetCasts` + `CastStrategyC` + `outputtype_token`（依赖 type system 完整度，type.cc L2）。

### 优先级排序（ROI）
1. **缺口 A**（void CALL）：实现量小（FuncCallSpecs 加 output prototype + 一个 if），解锁 2 个 curl 函数 + httpd 多个。**最高 ROI**。
2. **缺口 B**（CALL implied 门控）：需 Cover 基础设施，但能让所有嵌套 CALL 退化为命名变量，printc 质量大幅提升。中 ROI。
3. **缺口 C**（ActionSetCasts）：大工程，依赖 type system。低 ROI（短期）。




## 诊断方向（已解决 — 2026-06-30）

原 5 个方向（live_set 差异 / inter-pass deadcode / isHeritageKnown 宽松 / activeHeritage 重复标记 / 检查清单）**全部排查**，结论：**真根因不在 heritage/merge 层**，而在 printc 的 lhs-inlining。

排查过程：
1. 在 `emit_inline_expr` 入口加 `if self.is_lhs` 断言诊断 → **0 次命中**。证明 lhs 表达式不是 `emit_inline_expr` 在 lhs 路径产生的。
2. 在 `push_varnode` 入口加 `is_lhs + inline_candidates/value_def_map` 命中诊断 → 大量命中，但所有内联分支**都有** `!is_lhs` 守卫。
3. 逐分支核对 `push_varnode`：Priority 1.4/1.5/1.7（high 名）✓ 有守卫；Priority 2 Register ✓ 有守卫；**Priority 2 Unique ✗ 无守卫**。
4. Priority 2 Unique 分支（line ~4444）在 lhs 时仍从 `inline_candidates` 取 def 并调 `emit_inline_expr` → 这是唯一漏洞。
5. 加守卫 → curl 9→17。验证 780/780 测试通过。

**教训**：回归根因假设（MarkImplied high=false）方向错误。实际是 printc 自身的 lhs-inlining 不一致（Register 有守卫、Unique 没有）。应在 printc 层用 `emit_inline_expr` lhs 断言快速定位，而非沿 heritage/merge 链深挖。


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

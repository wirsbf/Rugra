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

**共性**: 大多是 CALL/void 返回值处理 + 嵌套表达式括号。这些是 printc 的 CALL-emission 与类型推断层面的独立缺陷，**不属于** Stack space 对齐范围，留待后续 printc 对齐迭代。


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

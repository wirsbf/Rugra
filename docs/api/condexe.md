# `condexe.rs` API Reference

**源代码路径**: `src/condexe.rs`
**Ghidra 对应**: `condexe.hh` / `condexe.cc` (712 行)
**状态**: 🔧 L2（2026-06-27 完整移植核心图重写算法，尚未在真实二进制触发到候选——curl/httpd 无匹配模式）

## 模块说明

条件执行简化。对应 Ghidra 的 `ConditionalExecution` 类与 `ActionConditionalExe`
（condexe.hh:91, condexe.cc:478-503）。

当两个 CBRANCH 测试相同（或互补）的布尔值时，第二个路径合并是冗余的，可被消除：

```text
   if (a) {           if (a) {
      BODY1              BODY1
   }          ==>        BODY2
   if (a) {           }
      BODY2
   }
```

iblock 是两条流不必要汇合的块；initblock 是最初计算布尔值的块。两条路径从
initblock 到 iblock（prea / preb），两条路径离开 iblock（posta / postb）。
若 iblock 的 CBRANCH 冗余，则移除 iblock，将 prea 重连到 posta（条件互补时连到
postb），并通过把读推入正确路径来保留 MULTIEQUAL 数据流。

## 2026-06-27：完整 1:1 移植

此前实现仅检测候选并 `eprintln!` 标记，**核心图重写完全缺失**。本次完整移植：

### ConditionalExecution（condexe.hh:91, 712 行算法全部移植）

| 方法 | Ghidra 行号 | 说明 |
|---|---|---|
| `new` | 432 | 构造 + buildHeritageArray |
| `test_iblock` | 43 | iblock 必须有 2 入/2 出 + 末尾 CBRANCH |
| `find_init_pre` | 55 | 沿 prea/preb 链回溯找 initblock + 设 init2a_true |
| `verify_same_condition` | 80 | BooleanExpressionMatch 验证同/互补条件 |
| `test_multi_read` | 101 | MULTIEQUAL 的读是否可移动 |
| `test_op_read` | 120 | 非 MULTIEQUAL op 的读是否可移动 |
| `test_removability` | 361 | iblock 内 op 是否可移除 |
| `verify` | 402 | 完整配置验证 + 所有 op 可移除性检查 |
| `find_pullback` | 146 | 查找已构造的 pull-back |
| `pullback_op` | 160 | 将 iblock 内 op 复制到前驱块（MULTIEQUAL slot 选择） |
| `get_new_multi` | 198 | 在给定块创建 MULTIEQUAL 持有数据流 |
| `resolve_read` | 224 | 计算通过任意块的读的替换 Varnode |
| `resolve_iblock_read` | 242 | 计算通过 iblock 的读的替换 |
| `get_multiequal_read` | 270 | MULTIEQUAL 读的替换 |
| `get_replacement_read` | 291 | 块的替换 Varnode（缓存 + 支配者回溯） |
| `do_replacement` | 320 | 重写给定 iblock op 的数据流 |
| `trial` | 448 | 测试给定块是否为可修改的 iblock |
| `execute` | 457 | 消除 iblock 的不必要路径汇合（op_destroy + remove_from_flow_split） |

### BooleanMatch / BooleanExpressionMatch（expression.cc:57-232）

- `boolean_match_evaluate` — `BooleanMatch::evaluate`（SAME/COMPLEMENTARY/UNCORRELATED）
- `same_op_complement` — `sameOpComplement`（INT_LESS/INT_SLESS 常量互补）
- `varnode_same` — `varnodeSame`
- `boolean_match_verify_condition` — `BooleanExpressionMatch::verifyCondition`

### 底层原语（为支撑 condexe 新增）

**`block.rs`**：
- `BlockBasic::get_out_rev_index` / `get_in_rev_index`（block.cc）
- `BlockBasic::half_delete_in_edge` / `half_delete_out_edge`（block.cc:140/149）
- `BlockBasic::replace_edges_thru`（block.cc:198-216）—— 核心边重定向
- `BlockGraph::remove_block_arc` / `remove_edge_blocks`（block.cc:1517）

**`funcdata.rs`**：
- `Funcdata::remove_from_flow_split`（funcdata_block.cc:892 + block.cc:1575）
- `Funcdata::structure_reset`（funcdata_block.cc:705）

**`op.rs`**：
- `PcodeOp::is_boolean_flip`（op.hh:210）

### 主管线接入

`ActionConditionalExe` 注册在 `decompile` group 的 `ActionDeadCode` 之后、
`ActionBlockStructure` 之前（对应 Ghidra coreaction.cc:5675 mainloop 顺序）。

## 已知限制

1. **边顺序适配**：Rugra CBRANCH 出边为 `[branch_target, fallthru]`，Ghidra 为
   `[falseOut, trueOut]`。`is_true_out_to` 通过 `BOOLEAN_FLIP` 标志适配，但若
   lift 阶段边顺序未来改变需同步调整。
2. **heritageyes 近似**：Rugra 全局跑一次 heritage，buildHeritageArray 近似为
   所有空间已 heritage（匹配 Ghidra post-heritage 行为）。
3. **RuleOrPredicate**（condexe.cc:509+）尚未移植（MULTIEQUAL + zero 谓词模式）。
4. **真实二进制未触发**：curl/httpd 的函数恰好无 `if(a){}if(a){}` 模式，故
   apply 返回 NO_CHANGE（正确行为）。算法正确性由单元测试守护。

## 测试

`condexe::tests`（6 个）：action_name、correlation_constants、
varnode_same_identity、apply_on_empty_fd、boolean_match_same_condition、
trial_rejects_unrelated_conditions。

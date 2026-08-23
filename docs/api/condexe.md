# `condexe.rs` API Reference

**源代码路径**: `src/condexe.rs`
**Ghidra 对应**: `condexe.hh` / `condexe.cc` (712 行)
**状态**: 🔧 **L2（2026-08-23 更新）**——trueout 极性（CONDEXE-TRUEOUT-0002，2026-08-23 集成）与
pullbackOp storage/插入位置（CONDEXE-PULLBACK-0005，2026-08-23，`condexe_pullback_1204`
5/5 MATCH）已对齐；`remove_from_flow_split` 映射相反且一支可越界（CFG-0001）、
Action guard/count/stage 与异常路径仍未对齐，故保持 L2。

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

- `boolean_match_evaluate` — `BooleanMatch::evaluate`（SAME/COMPLEMENTARY/UNCORRELATED）。**2026-07-05 修正**：expression.cc:154-164 的 commutative re-pairing 之前是死代码（`match (a,d,c,b) { _ => {} }` 从未真正递归），导致 swapped-operand AND/OR 被误判 UNCORRELATED，condexe 折叠失效。现按 Ghidra 行 154-164 完整移植：`pair1==uncorrelated` 时尝试 `(in1[0],in2[1])`，仍 uncorrelated 才返回；否则计算 `(in1[1],in2[0])` 作为 pair2。
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

1. ~~**边顺序适配**~~ **已修复（2026-08-23，CONDEXE-TRUEOUT-0002）**：Rugra CBRANCH
   出边实际为 `[fallthru, branch_target]`（flow.rs:920-928，同 flow.cc:960-967），
   与 Ghidra `[falseOut, trueOut]` 布局相同，无需任何 flip 适配。
   `is_true_out_to` 已删除（其 flip 重映射是多余翻转，`find_init_pre` 现内联
   condexe.cc:72 的纯位置比较）；`discover_path_is_true` 改纯位置
   getTrueOut/getFalseOut（condexe.cc:575-582）。BOOLEAN_FLIP 的合法消费点只剩
   `discover_conditional_zero`（condexe.cc:612-613）与 `verify_same_condition`
   的 matchflip 合成（expression.cc:227-230），各恰好一次。
2. **heritageyes 近似**：Rugra 全局跑一次 heritage，buildHeritageArray 近似为
   所有空间已 heritage（匹配 Ghidra post-heritage 行为）。
3. **真实二进制未触发**：curl/httpd 的函数恰好无 `if(a){}if(a){}` 或
   `cond ? val : 0` 谓词模式，故 apply 返回 NO_CHANGE（正确行为）。算法正确性由
   单元测试守护。

**fixture 可观测胶水（RUGRA-GLUE，2026-08-23）**：`ConditionalExecution::fixture_find_init_pre`
/ `fixture_verify`、`RuleOrPredicate::fixture_discover_path_is_true` —
供 locked oracle fixture（tests/oracle/condexe_trueout_1204）在隔离状态下驱动
私有阶段并观察 init2a_true / camethruposta_slot / zero_path_is_true；Ghidra 侧经
`#define private public` 读取同一批私有成员。

## 2026-08-23（CONDEXE-PULLBACK-0005）：pullbackOp storage/插入位置对齐

审计（docs/alignment_audit/CONDEXE_GAPS_2026-08-22.md §1 #8）定位的两处缺陷修复：

1. **storage（cc:182）**：`pullback_op` 的复制输出原为 `new_unique_out`（匿名
   unique 地址）；Ghidra 是 `fd->newVarnodeOut(origOutVn->getSize(),
   origOutVn->getAddr(), newOp)` — 保留原输出地址**与其地址空间**。新增私有
   `pullback_new_varnode_out`（funcdata_varnode.cc:104 newVarnodeOut 的逐语句复制：
   createDef → setOutput → assignHigh → laned → queryProperties），因 Rugra
   `Funcdata::new_varnode_out` 在 split Address 模型下硬编码 Register 空间，
   无法表达 unique 空间原地址（P2 投影即钉死该差异）。
2. **插入位置（cc:187）**：`op_insert_begin` → `op_insert_end`（funcdata_op.cc:435-446，
   落在块尾、trailing flow-break 之前，而非 MULTIEQUAL 组之后）。
3. **defOp slot 语义（cc:172）**：`defOp->getIn(inbranch)` 缺槽时不再回退原
   varnode，而是按 Ghidra 的不可达语义向上传播 `None`。

**fixture**：`tests/oracle/condexe_pullback_1204`（.cc/.rs/.metadata.json）+
`tools/run_condexe_pullback_oracle.sh`（pin-base schema2，base 0d9f8a1 + 单
src/condexe.rs overlay）。三投影（块位 idx/nops、SeqNum pc:time、storage
space:offset/size）覆盖：P1/P1b SUBPIECE 经 iblock MULTIEQUAL 的 inbranch 0/1
pullback（目标块 = iblock->In(inbranch)，input 0 = MULTIEQUAL slot）、P3
findPullback 缓存命中（同指针、零新 op）、P2 跨块 immedDom pullback（unique
空间原地址保留）、P5 常量 input 0 直传 immedDom、G1-G8 testOpRead 准入矩阵
（INT_ADD/PTRSUB 非常量 input 1 拒绝 cc:126-128、非 MULTIEQUAL in-ib 定义者拒绝
cc:131-133、free/常量 input 0 拒绝 cc:135-136）。14/14 记录双侧字节一致
（`covered_projection=5/5 projection_status=MATCH`）。负向对照已验证：回退到
`new_unique_out`+`op_insert_begin` 后 P1-P5 全部 MISMATCH（`out=unique:<counter>`、
`idx=0`）。

新增 fixture 胶水：`ConditionalExecution::fixture_pullback_op` /
`fixture_test_op_read`（同上 trueout 胶水模式）。

**残差（CFG-0001）**：execute/doReplacement/removeFromFlowSplit 与 pullback 输出的
交互未投影（fixture metadata `residual_union`）；doReplacement RETURN 腿的
newVarnodeOut 地址保留（condexe.cc:340-349）留待同一后续任务。

## 2026-06-27（续）：RuleOrPredicate 完整移植（condexe.cc:509-712）

condexe.cc 的第二部分，一个独立的 Rule，处理谓词构造：
```text
    tmp1 = cond ? val1 : 0;
    tmp2 = cond ?  0 : val2;
    result = tmp1 | tmp2;   ==>   newtmp = val1 ? val2;  result = newtmp;
```

**MultiPredicate**（condexe.hh:174）全部 4 个方法移植：
- `discover_zero_slot` — `discoverZeroSlot`（509）：检测 2 输入 MULTIEQUAL，一端为 COPY(#0)
- `discover_cbranch` — `discoverCbranch`（539）：找控制 MULTIEQUAL 两入路径的单一 CBRANCH
- `discover_path_is_true` — `discoverPathIsTrue`（572）：判定 condBlock 真出边是否流向 zero set
- `discover_conditional_zero` — `discoverConditionalZero`（590）：验证 CBRANCH 布尔是 (vn==0)/(vn!=0)

**RuleOrPredicate**（condexe.hh:172）：
- `get_opcodes` — `getOpList`（617）：INT_OR + INT_XOR
- `check_single` — `checkSingle`（638）：交替形式 `tmp1=(val2==0)?val1:0; result=tmp1|other`
- `apply_op` — `applyOp`（654）：双 branch 模式 + 共享/独立条件 + finalBlock MULTIEQUAL 重写

**支撑原语新增**：
- `block.rs`: `BlockGraph::find_common_block`（block.cc:736 支配者树 LCA）
- `op.rs`: `PcodeOp::compare_order`（op.cc:778 控制流顺序比较）
- `condexe.rs`: `verify_condition_with_flip`（暴露 BooleanExpressionMatch::getFlip）

**接入**：在 ActionSimplify 的硬编码简化之后，对 INT_OR/INT_XOR op 单独跑 RuleOrPredicate
（Ghidra 里它在 actprop rule group，即简化阶段）。

## 测试

`condexe::tests`（9 个）：action_name、correlation_constants、varnode_same_identity、
apply_on_empty_fd、boolean_match_same_condition、trial_rejects_unrelated_conditions、
rule_or_predicate_rejects_plain_input、rule_or_predicate_opcodes、compare_order_basic。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-07-01（管线改造）：ActionConditionalExe apply &self→&mut self

### 2026-07-01：RuleOrPredicate impl Rule trait
包装现有 apply_op 为 Rule trait（INT_OR/INT_XOR dispatch）。注册 oppool1:5631。
<!-- annotation-pass: 2026-07-04 -->

 

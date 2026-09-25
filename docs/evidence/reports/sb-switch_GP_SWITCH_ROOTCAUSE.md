# GP_SWITCH_ROOTCAUSE — getparameter.constprop.0 的 40-case switch 结构丢失根因

- 日期: 2026-09-22 | Lane X(只读分析,零 repo 改动;产物全部在 /dev/shm/rugra-tests/sb-switch/)
- 对象: `getparameter.constprop.0 @0x3f00`(curl,2653 bytes)vs oracle `getparameter @0x103f00`(Ghidra 12.0.4, e40ed130)
- 输入: baseline = /dev/shm/rugra-tests/sb-baseline/curl_new.c(HEAD@0acde30 构建);复核 = 本 lane 在 HEAD@6afe6eb 重建 fast-release 后重跑(gp 输出与 baseline 逐行几乎一致,gp 内 switch 数恒为 0,行为已复现)
- 分诊前置: /dev/shm/rugra-tests/sb-triage/TRIAGE_MAIN_GETPARAM.md §2 C12

---

## 0. 根因层判定(一句话)

**丢失发生在 (b) blockaction 结构化层,但根因是其上游两个使能机制缺失:①`ActionSwitchNorm` 是空壳(coreaction.rs:3611-3636,matchModel/recoverLabels/foldInNormalization/foldInGuards 全被注释),守卫 CBRANCH@0x3fc5 永不折叠、default 边永不标注;②`newBlockMultiGoto` 未移植(ruleBlockGoto 的 isSwitchOut arm,blockaction.cc:1456-1458 无对应物),switch 出边无法被 goto 机制摘除 —— 二者叠加使 `ruleBlockSwitch`(blockaction.cc:1649)的守卫在 gp 拓扑下永远不可满足,111 次尝试全部 reject。**
jumptable 恢复层(a)完全正常;SwitchNorm(c)是空壳既没建也没拆,不背锅。

## 1. 现象固化

### 1.1 Rugra 侧(gp_rugra.c = curl_new.c:2144-2628,484 行)

- **零 `switch` 关键字、零 `case` 标签**(整个 curl 输出仅 glob_set 有 1 个畸形 switch,curl_new.c:2811)。
- switch 头残骸:gp_rugra.c:165-166
  ```c
  (0x57 < (int *)(int)config_00 - 0x23);
  ;
  ```
  即守卫条件 `x-0x23 > 0x34`(default 路径判定)成了悬空表达式语句 + 空语句 —— 守卫 CBRANCH 的分支结构被吃掉,布尔计算残留。0x23/0x57 正是 oracle switch 的 case 值域。
- 顺序化范围:oracle switch 的 348 行(47 个 case 体 + default)在 Rugra 里全部直落为顺序代码;仅 6 处 goto/code_r 残余标签(gp_rugra.c:105,111,351,390-391,399-400,474-476)。
- 结构化层信号(stderr,curl_new.err gp action 窗口):
  - `[BLOCKSTRUCT] ... selectGoto exhausted (LowlevelError site, blockaction.cc:1275)`(Ghidra 此处抛 LowlevelError,Rugra 降级为日志)
  - `[BLOCKSTRUCT] ... finalize_structure: 138 -> 52 (removed 86 consumed)`
  - `ruleBlockGoto: wrapped block {22,9,7,82,70,110,99,89,60,102,25,127,111,131,12}`(case 体出边逐个被 goto 包裹,但致命拓扑从未改变)

### 1.2 Oracle 侧(gp_ghidra.c = ghidra_curl_1204.c:1649-2125,476 行)

- `switch((int)pCVar10 - 0x23U & 0xff)`(ghidra_curl_1204.c:1765)。
- **47 个 distinct case 标签**(值域 0..0x57,稀疏;分诊报告写 "40-case",实测 47)+ `default:`。
- case 打印顺序 = 表顺序:case 0 → default → case 0xf → ...(default 第二个 ⇒ default 目标是表边 out[1],与 §3 拓扑吻合)。
- 每个 case 体以 `break` 结束;default 体是 if/else(`pCVar10=='\0'` 二分 helpf)且以 **`goto LAB_0010404b`** 结束(= default 体的出边在 Ghidra 结构里也是非结构化 goto —— 与 Rugra 把 blk131/127/126 goto 包裹是同型动作)。
- **oracle 里守卫 if 完全消失**(switch 表达式直接是归一化的 `(x-0x23)&0xff`)⇒ Ghidra 把守卫折叠进了 switch(foldInGuards)。

## 2. 分层排查证据

### 层 (a) jumptable 恢复 —— ✅ 正常,排除

| 证据 | 值 | 判读 |
|---|---|---|
| stderr:6198 `[JUMPTABLE] recovered 88 entries from indirect jump at 0x3fd5` | 88 条 | 恢复成功 |
| stderr:6199 `[STEP] gp flow done ... raw_ops=1866 bblocks=138` | 138 块 | 表已展开进 CFG(36→138,与看板 JUMPTABLE-PIPELINE-0001 验收记录逐字一致)|
| oracle case 值域 | 0..0x57 = 88 个索引 | **88 精确匹配 oracle 索引空间**(47 个去重目标 + 直达出口的 skip 条目)|
| 最终 bblocks | bb29(BRANCHIND@0x3fd5)49 条出边 | 多目标分支块在 BBGraph 中存在,结构化输入齐全 |

⇒ CBRANCH/BRANCHIND 目标**已**展开,(a) 不成立。表基址/表项宽/范围与 Ghidra 无失配(88=0x57-0x23+1 的掩码索引空间;看板 JUMPTABLE-TABLEAPI-0001 关心的表 API 缺失是下游消费者问题,不是恢复问题)。

### 层 (b) blockaction 结构化 —— ❌ 失败发生地(可观测、可复现)

观测方法(零代码改动,全部为既有 env 钩子):`RUGRA_IRRED_DBG=1` + `RUGRA_BS_TRACE=1` + `RUGRA_DUMP_FUNC=getparameter.constprop.0` + `RUGRA_BS_DUMP=1`(blockaction.rs:5545/1977/2743/1475)。

**B1. try_rule_switch 被 111 次调用、111 次全部同一守卫拒绝**(gp_action_trace.err):

```
[IRRED-SW] try blk29 fn=getparameter.constprop.0 ty=Copy fl=0x200010 sizeout=49
           out=[130@0x41c1(L10),127@0x41a0(L10),126@0x41cd(L10),...,131@0x4030(L20),...]
[IRRED-SW] blk29 obvious exit=127
[IRRED-SW] reject blk29 cc:1705 case blk130 out=Some(131) != exit 127
```
blk29 = BRANCHIND 块的 Copy 节点,is_switch_out ✓(try_rule_switch 第一守卫通过,blockaction.rs:5553);49 条出边与 bblocks 一致;拒绝点 = Ghidra blockaction.cc:1701/1705"case 的唯一出边必须指向 exitblock"。

**B2. 拓扑真相**(RUGRA_DUMP_FUNC 最终 bblocks,gp_ranges.txt):

```
bb28 守卫CBRANCH@0x3fc5  in=[26,27,24]  out=[29(switch), 125(default体)]   ← 守卫未折叠!
bb29 BRANCHIND@0x3fd5    in=[28]        out=[128@0x41c1, 125@0x41a0, 124, ..., 129@0x4030, ...] (49条)
bb125 default体@0x41a0   in=[28,29]     out=[127,126]   ← sizeIn=2:守卫边+表default边 双入!
bb128 case0体@0x41c1     in=[29]        out=[129]
bb129 switch出口merge@0x4030 in=[29,35,...55个前驱] out=[130,131]   ← 真正的 switch exit
bb127/bb126(default 的 helpf 二分) → bb132@0x404b(= LAB_0010404b)
```

**B3. Ghidra 为何能成而 Rugra 不能(逐步模拟,引文级对照)**:

| 步 | Ghidra(oracle 路径) | Rugra(实测) |
|---|---|---|
| 1 | `ActionSwitchNorm::apply`(coreaction.cc:4548-4563):`matchModel`+`recoverLabels`+`foldInNormalization`,再 `foldInGuards` | **空壳**:coreaction.rs:3624-3632 循环体里三行调用全注释,`fold_in_guards` 调用注释,自注 "The fold stages remain L3 gaps" |
| 2 | `JumpBasic::foldInGuards`→`foldInOneGuard`(jumptable.cc:1555/1358-1410):guardtarget(=bb125)**已是 switch 出边** → `jump->setDefaultBlock(pos)`(cc:1404)+ `opSetInput(cbranch,const)` 中和守卫 → 守卫边 bb28→bb125 变死边被移除 → oracle 输出无守卫 if ✓ | `fold_in_one_guard` **已移植**(jumptable.rs:2648,含 setDefaultBlock 语义)但是**死代码**——无任何调用方;守卫存活 ⇒ ① bb125 永远 sizeIn=2;② 守卫布尔残骸打印成悬空 `(0x57 < config_00 - 0x23);` ✓(与 gp_rugra.c:165 吻合)|
| 3 | `installSwitchDefaults`(funcdata_block.cc:687)在 buildCopy 前给 default 边挂 `f_defaultswitch_edge` | 同名函数已移植且在 blockaction.rs:58 于 build_copy 前调用,但 `get_default_block()==-1`(步骤 2 没跑)→ no-op;IRRED 边旗只见 L10/L20(=F_TREE/FORWARD,DFS 分类),无 0x04 default 标 ✓ 实测佐证 |
| 4 | TraceDAG/selectGoto 把 default 边标记 goto 后,`ruleBlockGoto`(blockaction.cc:1450-1472)的 **isSwitchOut arm**:`graph.newBlockMultiGoto(bl,i)`(block.cc:1716-1755)→ **把该出边从 switch 块上摘除**(removeEdge cc:1734)+ setDefaultGoto | **newBlockMultiGoto 无对应物**;try_rule_goto 显式跳过 switch-out 块(blockaction.rs:4993-4995,注释自认 `BLOCKSTRUCT-MULTIGOTO-0001 ... has no Rugra counterpart yet`)⇒ switch 的坏边永远摘不掉 |
| 5 | 边摘除后 obvious-exit 扫描落到 **bb129@0x4030(sizeIn=55)** = 真 exit;全部 case 满足 sizeIn==1 ∧ out==bb129;`checkSwitchSkips`(cc:1626-1642)把直达出口的表条目 setGotoBranch;`newBlockSwitch` 成立 → 47 case + default + break/goto 形态 = oracle 逐项吻合 | obvious-exit 扫描先撞 **bb125@0x41a0**(out[1],sizeIn=2 或 sizeOut=2 都触发 cc:1659-1666)→ exit 误选;随后第一个 case bb128 的 out=bb129≠bb125 → cc:1705 reject,**循环 111 次**直到 selectGoto 耗尽 |

注意:两个缺失**缺一不可**——只补守卫折叠,bb125 仍以 sizeOut=2 赢得 obvious-exit → 仍在 cc:1705 拒;只补 MultiGoto,守卫 CBRANCH 残留输出(oracle 证明守卫必须被折叠掉)。Ghidra 两者都有。

### 层 (c) SwitchNorm 拆 switch —— ❌ 不成立

ActionSwitchNorm 在 Rugra 是空壳(什么都不做),既不可能建也不可能拆。glob_set 的畸形 switch 表达式(curl_new.c:2811,`switch((int *)(int *)(__spacebase_1_0 *)0x0 + 0x149d4 + ...)`)恰是同一空壳的另一症状:无 `foldInNormalization`/`recoverLabels`,switch 表达式以未归一化原始 IR 形态直出。

## 3. Ghidra/Rugra 行号对照账(修复面清单)

| # | Ghidra 锚点 | 机制 | Rugra 锚点 | 状态 |
|---|---|---|---|---|
| 1 | coreaction.cc:4548-4563 `ActionSwitchNorm::apply` | 标签恢复+守卫折叠入口 | coreaction.rs:3611-3636 | **STUB**(调用全注释)|
| 2 | jumptable.cc:1555 `JumpBasic::foldInGuards`;cc:1358-1410 `foldInOneGuard`;cc:1404 `setDefaultBlock` | 折守卫/定 default | jumptable.rs:1652(traits)/2648/3095;funcdata.rs:2907 `install_switch_defaults`;jumptable.rs:4249 `get_default_block` | 移植但**死代码**(无调用方链)|
| 3 | jumptable.hh:594 `matchModel`;`recoverLabels` | 模型匹配/case 标签 | — | **未移植**(=JUMPTABLE-TABLEAPI-0001 的 13 方法范围)|
| 4 | jumptable.cc `foldInNormalization` | switch 表达式归一化 | jumptable.rs:1643/1782/3053/3627/3833/4044(6 个模型 impl) | 移植但**死代码** |
| 5 | blockaction.cc:1450-1472 `ruleBlockGoto`(isSwitchOut arm cc:1456-1458) | switch 块的 goto 包裹 | blockaction.rs:4968 `try_rule_goto`;4993-4995 **显式 return false 跳过** | **MISSING arm** |
| 6 | block.cc:1716-1755 `newBlockMultiGoto`(removeEdge cc:1734, setDefaultGoto) | 从 switch 摘除 goto 边 | — | **未移植**(代码注释引用 `BLOCKSTRUCT-MULTIGOTO-0001`,**该 ID 未上看板**)|
| 7 | blockaction.cc:1649-1726 `ruleBlockSwitch` | switch 结构化本体 | blockaction.rs:5544 `try_rule_switch` | 忠实移植(含 cc:1705 拒绝日志),被上游卡死 |
| 8 | blockaction.cc:1626-1647 `checkSwitchSkips` | 直达出口边→goto | blockaction.rs:5475 `check_switch_skips` | 移植,对 gp 不可达 |
| 9 | blockaction.cc:2176-2177 `installSwitchDefaults` → `buildCopy` 顺序 | default 边标注先于快照 | blockaction.rs:58 → 61 | 移植 ✓(顺序正确)|
| 10 | blockaction.cc:1264-1278 `selectGoto` 耗尽→LowlevelError(cc:1275) | — | blockaction.rs:1500-1521(降级为日志) | 已知降级,stderr 可见 |

## 4. 修复方向建议(不改代码)

1. **P0-A|接线 ActionSwitchNorm**(JUMPTABLE-TABLEAPI-0001 消费者链):
   - 实现表级 `match_model` + `recover_labels`(该 TODO 登记的 13 方法之二);
   - 激活既有死代码:`fold_in_normalization`(按 unlabelled 分支)、`fold_in_guards`(每次调用,成功则清结构重跑,Ghidra cc:4559-4561)。
   - 预期直接收益:gp 守卫折叠+default 边标注+glob_set switch 表达式归一化(畸形 cast 链消除)。
2. **P0-B|补 `new_block_multigoto` + ruleBlockGoto 的 isSwitchOut arm**:
   - 按 block.cc:1716-1755:identifyInternal 包裹、`addEdge(targetbl)`、自环保护(forceOutputNum)、`removeEdge(ret,targetbl)`、`setDefaultGoto`(当且仅当 isDefaultBranch);
   - printc 侧需能发射 BlockMultiGoto(与 checkSwitchSkips 的 setGotoBranch 配合)。
   - 没有它,P0-A 之后 gp 仍会在 cc:1705 拒(bb125 以 sizeOut=2 抢占 obvious-exit)。
3. **P1|B2 fixture**:`gp_switch_struct_1204` 双侧函数 fixture(oracle 侧输入=锁定 curl 二进制+12.0.4 选项;观察:flow 恢复条目数、switchnorm 后 CBRANCH@0x3fc5 存活状态、default 边旗标、BlockSwitch 出现与否、case 标签集合)。修复验收 = `compare_ghidra.py --func getparameter.constprop.0` skeleton 大降 + defects/numbering=0 + httpd main(8 个 switch,blockaction.rs:1749)回归不降。
4. 顺序建议:P0-A 与 P0-B 可并行(写集不重叠:coreaction/jumptable vs blockaction/block/printc),集成须同 wave 验收,因为 gp 需要两者同时在场。

## 5. 看板登记建议

- **并入 JUMPTABLE-TABLEAPI-0001**(不新开):ActionSwitchNorm 空壳接线(matchModel/recoverLabels 实现 + fold_in_normalization/fold_in_guards 激活)正是该登记项"表级 13 方法的消费者链"的本体;本报告把它从"switch 渲染"残差升级为"gp switch 结构丢失的根因 #1",并补上证据链(stderr 111×reject + bblocks 拓扑)。
- **新开 ID(建议名 BLOCKSTRUCT-MULTIGOTO-0001,从代码注释正式上看板)**:newBlockMultiGoto(block.cc:1716-1755)+ ruleBlockGoto isSwitchOut arm(blockaction.cc:1456-1458)。当前该缺口只在 blockaction.rs:4991 注释里引用、TODO_BOARD 无登记(违反铁律 3"代码引用的 TODO ID 必须登记"),write-set=src/blockaction.rs + src/block.rs + src/printc.rs(MultiGoto 发射)+ docs/api 三件。
- **依赖关系**:JUMPTABLE-TABLEAPI-0001(先行)→ BLOCKSTRUCT-MULTIGOTO-0001(并行)→ gp_switch fixture(验收)。
- 已知关联登记:JUMPTABLE-PIPELINE-0001(其"残差→JUMPTABLE-TABLEAPI-0001(switch 渲染)"的归因经本调查**确认且加重**:不止渲染,结构本身没成)。

## 6. 工件清单(本目录)

| 文件 | 内容 |
|---|---|
| gp_rugra.c / gp_ghidra.c | 两侧函数体提取(固化对照)|
| gp_irred.c / gp_irred.err | HEAD@6afe6eb 重建后全量重跑(RUGRA_IRRED_DBG=1 RUGRA_BS_TRACE=1)|
| gp_action_trace.err | gp 的 action 阶段 stderr 切片(111×try/reject 全轨迹)|
| gp_dump.c / gp_dump.err | RUGRA_DUMP_FUNC 块级转储(含每块 op 地址范围/终止分支)|
| gp_ranges.txt | 每基本块 in/out/地址范围/终止 op 的结构化表 |
| gp_bbmap.txt | 块邻接原始行 |
| GP_SWITCH_ROOTCAUSE.md | 本报告 |

### 环境坑位记录

- `target/fast-release/examples/curl_decompile` 曾是 **8月17 日的陈旧产物**(早于 563264a jumptable pipeline 合入):首跑显示 `raw_ops=677 bblocks=36` 且零 `[JUMPTABLE]` 日志,险些误判为 (a) 层回退。重建后 `raw_ops=1866 bblocks=138`。后续 lane 用 fast-release 前先核对二进制 mtime vs 最近 src commit。
- baseline(0acde30)与 HEAD(6afe6eb)的 gp 输出仅有 2 行局部语句换位差异,本结论对两个 commit 均成立。

# coreaction.cc 全量 Action 差距审计（COREACTION-GAPS-2026-08-22）

> 审计 Agent: `coreaction_gaps_audit`（只读）。日期 2026-08-22/23。
> Oracle: Ghidra 12.0.4, commit `e40ed13014025f82488b1f8f7bca566894ac376b`,
> `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.{hh,cc}`（.hh 1085 行 / .cc 5741 行）。
> Rugra: master `296c128`, `src/coreaction.rs`（11824 行）+ `src/action.rs`（1421 行）。
> 结论基于对两侧源码的逐个 `apply()` 体核读；每个 claim 附 file:line。
> 阶段树参考 `docs/alignment_docs/PIPELINE_STAGES_1204.md`（universal 树 :5477-:5738）。

## 0. 摘要

- Ghidra `coreaction.hh` 声明 **62 个 Action 类**（coreaction.hh:34-1058，其中 16 个 apply 内联在 .hh，
  46 个 `::apply` 在 coreaction.cc）。
- Rugra `src/coreaction.rs` 有 **71 个 `impl Action for`**：62 个 oracle 对应物全部有 struct
  （无一 MISSING），另有 9 个 Rust 侧自创/历史 Action（ActionCse/ActionCopyPropagate/ActionCallParams/
  ActionInferParams/ActionTypeInfer/ActionPreferComplement/ActionStructureTransform/ActionReturnSplit/
  ActionNodeJoin — 后 4 个实为 blockaction.hh 的类，前 5 个为 Rugra 自创替代层）。
- **材料性缺口 = 30/62**：18 个 PARTIAL（有实体但缺 Ghidra 关键腿）+ 12 个 STUB/near-stub
  （其中 2 个同时未注册：ActionDynamicMapping、ActionForceGoto）。
- 另有 3 处"实体完整但注册/顺序与 oracle 不一致"（FuncLinkOutOnly 保留、Unreachable :5490 丢弃、
  ConstantPtr 槽位错误），以及 mainloop 内 6 处顺序重排（见 §3）。
- 依赖 DAG 根节点（§4）：**FuncCallSpecs/ProtoModel 语义缺口**（resolve_model no-op、trashset、
  extraPop、internal-storage、数据库 FuncProto 查询被硬编码 libc 表替代、Heritage::guardReturns 缺失）、
  **持久 Merge/HighVariable 语义缺口**（fd.getMerge() 缺失、copyTrims/snip、multipleInteraction、
  后代 DFS）、**Symbol/Scope 层**（queryProperties 建符号、SLEIGH 寄存器表）。

---

## 1. (a) 全量对照表

状态图例：
- ✅ **OK** = 实体移植完整 + 已在主管线注册（允许有已登记的次级残留）
- 🟡 **PARTIAL** = 已注册，但 apply 缺 Ghidra 关键算法腿或带启发式替代
- 🔴 **STUB** = no-op / 仅计数；已注册为惰性节点
- ⛔ **STUB+UNWIRED** = no-op 且未注册（oracle 的 decompile root 里有该节点）
- ➖ **OK-UNWIRED** = 未注册且 oracle 的 decompile grouplist 也排除它（正确）

universal 树槽位 = coreaction.cc `universalAction`（:5462-5738）中的注册序号；
组名 = 构造函数第二参。`decompile` grouplist 见 coreaction.cc:5424-5431（不含
`noproto`/`protorecovery_b`/`normalanalysis` — 故 FuncLinkOutOnly、DirectWrite_b、NormalizeSetup
三个实例在 Ghidra derive 出的 decompile root 中被过滤）。

### 1.1 头部 8 槽（coreaction.cc:5477-5485）

| # | Ghidra Action | .hh/.cc | 树槽/组 | Rust impl | 注册(action.rs) | 状态 | 证据 |
|---|---|---|---|---|---|---|---|
| 1 | ActionStart | hh:34 / hh:41 内联 | :5477 base | rs:842/851 | :915 | ✅ | 委托 `fd.start_processing()`（rs:855 ↔ hh:42） |
| 2 | ActionConstbase | hh:259 / cc:678 | :5478 base | rs:5470/5475 | :916 | ✅ | 真移植（tracked-set COPY 注入 rs:5523-5542 ↔ cc:692-705）；INJECT-0001 残留（rs:5499）已登记 |
| 3 | ActionNormalizeSetup | hh:628 / cc:4567 | :5479 normalanalysis | rs:2600/2605 | 未注册 | ➖ | `normalanalysis` 不在 decompile grouplist（cc:5424-5431），oracle derive 时丢弃；action.rs:917-921 有论证 |
| 4 | ActionDefaultParams | hh:659 / cc:2311 | :5480 base | rs:5953/5958 | :922 | ✅ | FUNCPROTO-MODEL-BIND-0001 r2 完成（TODO_BOARD.md:175），evalfp/内部存储路径齐 |
| 5 | ActionExtraPopSetup | hh:676 / cc:1436 | :5482 base | rs:7551/7556 | :923 | 🔴 STUB | rs:7563-7566 "Rugra doesn't track extraPop per-callspec yet, so this is a no-op"；Ghidra cc:1436-1466 建 INT_ADD/INDIRECT 调整 SP |
| 6 | ActionPrototypeTypes | hh:643 / cc:4609 | :5483 protorecovery | rs:5709/5714 | :924 | 🟡 PARTIAL | 自注 "Partial"（rs:5717）；step1 model 绑定✅（rs:5730-5743 ↔ cc:4615-4619）；RETURN strip✅（rs:5749-5770 ↔ cc:4628-4635）；**缺**：locked-output 插入返回 varnode 腿（cc:4637-4649）与 `prepareThisPointer`（cc:4623-4624） |
| 7 | ActionFuncLink | hh:692 / cc:1575 | :5484 protorecovery | rs:6362/6553 | :925 | 🟡 PARTIAL | `setup_call_specs`（rs:6373）+ `func_link_input/output` 有实体，但: ① 返回类型/参数来自**硬编码 libc ABI 表** `known_return_type/known_param_types/known_param_count`（rs:1170-1334, 6414, 6475-6482）而 Ghidra 读 callspec 锁定的 FuncProto（cc:1491-1511 `fc->getParam(i)`）；② `func_link_input` 用硬编码 SysV 偏移表（rs:6488）；③ Ghidra 的 opStackLoad/createPlaceholder 栈参路径缺（rs:6463-6465 自述）；④ guardCalls trial 注册被集中到此处替代 heritage（rs:6594-6598） |
| 8 | ActionFuncLinkOutOnly | hh:713 / cc:1588 | :5485 noproto | rs:6649/6654 | :939 | ✅(体)/⚠注册 | apply 体为 funcLinkOutput 委托（rs:6675-6677 ↔ cc:1588-1595）；oracle 因 `noproto`∉decompile grouplist **丢弃该实例**（cc:5424-5431），Rugra 保留注册（action.rs:926-938 论证其惰性） |

### 1.2 mainloop 18 槽（coreaction.cc:5490-5656，PIPELINE_STAGES §2）

| # | Ghidra Action | .hh/.cc | 树槽/组 | Rust impl | 注册(action.rs) | 状态 | 证据 |
|---|---|---|---|---|---|---|---|
| 9 | ActionUnreachable(base) | hh:491 / cc:3457 | :5490 base | rs:2237/2242 | 仅 :5673 槽(rs:1077) | ✅(体)/⚠注册 | apply 真移植；**:5490 首实例被丢弃**（action.rs:983-985、coreaction.rs:10303-10306 自述，理由=bblocks 不完整时误删） |
| 10 | ActionVarnodeProps | hh:222 / cc:1282 | :5491 base | rs:4824/4829 | :986 | ✅ | consume/nzmask 折叠常量（rs:4985-5025 ↔ cc:1282-1347） |
| 11 | ActionHeritage | hh:282 / hh:289 内联 | :5492 base | rs:15/24 | :987 | ✅ | 委托 `fd.op_heritage()`（HERITAGE-DRIVER-SWITCH-0001 r2） |
| 12 | ActionParamDouble | hh:730 / cc:1597 | :5493 protorecovery | rs:6047/6052 | :988 | 🔴 near-STUB | 自注 "Partial implementation... Full algorithm requires ParamActive + PIECE analysis"（rs:6055-6058）；实际只数 stack-param（rs:6063-6073），无 trial/double 分析（Ghidra cc:1597-1723） |
| 13 | ActionSegmentize | hh:128 / cc:624 | :5494 base | rs:7485/7490 | :995 | 🔴 near-STUB | 只数 CALLOTHER（rs:7493-7506 自述需 UserOpManage+SegmentOp+Architecture）；Ghidra cc:624-649 走 userops.evaluate |
| 14 | ActionInternalStorage | hh:1058 / cc:4938 | :5495 base | rs:7515/7520 | :996 | 🔴 near-STUB | 只数 INDIRECT_STORAGE/HIDDEN_RETURN 参数（rs:7523-7538）；Ghidra cc:4938-4975 重建 CALL/CALLIND 输入 |
| 15 | ActionForceGoto | hh:141 / cc:671 | :5496 blockrecovery | rs:8935/8940 | **未注册** | ⛔ STUB+UNWIRED | rs:8947-8953 自述 Architecture/Override 未接入 Funcdata；`blockrecovery` **在** decompile grouplist（cc:5426）→ oracle root 有此节点，Rugra 缺注册 |
| 16 | ActionDirectWrite(a) | hh:243 / cc:1350 | :5497 protorecovery_a | rs:5375/5380 | :997 | 🟡 PARTIAL(轻) | 两阶段 direct_write 传播✅（rs:5388-5456 ↔ cc:1350-1432）；缺 `propagateIndirect` 位（rs:5445-5448 用保守 true 替代，TODO 自述）；:5498 protorecovery_b 实例按 oracle 过滤丢弃✅（cc:5424-5431） |
| 17 | ActionDirectWrite(b) | 同上 | :5498 protorecovery_b | — | 未注册 | ➖ | `protorecovery_b` ∉ decompile grouplist（cc:5424-5431），oracle 同样丢弃 |
| 18 | ActionActiveParam | hh:748 / cc:1725 | :5499 protorecovery | rs:5793/5798 | :998 | ✅ | 状态机完整: aliascheck gather/trimmable/checkInputTrialUse/finishPass/maxPass/needsFinalCheck/resolve+derive+build+clear（rs:5804-5875 ↔ cc:1725-1771） |
| 19 | ActionReturnRecovery | hh:796 / cc:1908 | :5500 protorecovery | rs:8578/8693 | :999 | 🟡 PARTIAL | buildReturnOutput 完整（0/1/2/>2 trial PIECE 重组, rs:8589-8691 ↔ cc:1836-1906）；**缺**: 函数级 Heritage::guardReturns（rs:8571-8577 自述以 ProtoModel output_entries 播种替代）；constructJoinAddress 缺（rs:8623-8628 用 min-offset 替代） |
| 20 | ActionRestrictLocal | hh:811 / cc:1957 | :5502 localrecovery | rs:5046/5051 | :1057 | 🟡 PARTIAL | 两条循环都在（rs:5061-5099 ↔ cc:1967-2000），但栈参判定用 `p.address.as_u64() > 0x7FFF_FFFF` 启发式（rs:5068）替代 Ghidra 的 space 维度（Address 无 space）；`fd.scope` 由 RestructureVarnode 每轮 new（rs:789-818），mark_not_mapped 依赖该 scope 存在 |
| 21 | ActionDeadCode | hh:552 / cc:3925 | :5503 deadcode | rs:56/454 | :1058 | ✅ | ~160 行分析器（rs:454-615）；另注册 fullloop :5682 槽（rs:1092） |
| 22 | ActionDynamicMapping | hh:1023 / cc:4852 | :5504 dynamic | rs:8464/8469 | **未注册** | ⛔ STUB+UNWIRED | 纯 no-op（rs:8471-8473）；`dynamic` 在 decompile grouplist（cc:5429）→ oracle root 有此节点；coreaction.rs:10300-10302 自述故意不注册 |
| 23 | ActionRestructureVarnode | hh:848 / cc:2274 | :5505 localrecovery | rs:768/783 | :1059 | 🟡 PARTIAL | numpass/syncVarnodesWithSymbols✅（rs:786-825 ↔ cc:2279-2282）；缺: ① aliasyes 未穿透进 restructure（rs:814-816 TODO）；② 寄存器名表**硬编码 x86-64**（rs:795-812）替代 SLEIGH register index；③ protectSwitchPaths 缺（rs:823-824 TODO，需 jumptable 状态） |
| 24 | ActionSpacebase | hh:270 / hh:277 内联 | :5506 base | rs:7468/7473 | :1000 | ✅ | 委托 `fd.spacebase()`（rs:7476 ↔ hh:278） |
| 25 | ActionNonzeroMask | hh:293 / hh:300 内联 | :5507 analysis | rs:8912/8917 | :1001 | ✅ | 委托 `fd.calc_nz_mask()`（rs:8923 ↔ hh:301） |
| 26 | ActionInferTypes | hh:960 / cc:5374 | :5508 typerecovery | rs:3531/4204 | :1064 | ✅ | ~600 行类型传播（含 IntTypes 辅助 rs:4184-4203；seed_global_struct_pointers rs:4324）；自限 7 pass（rs:1063 注） |

### 1.3 stackstall 5 尾槽（coreaction.cc:5652-5656；oppool1 见 rule 审计，不在本文范围）

| # | Ghidra Action | .hh/.cc | 树槽/组 | Rust impl | 注册(action.rs) | 状态 | 证据 |
|---|---|---|---|---|---|---|---|
| 27 | ActionLaneDivide | hh:113 / cc:585 | :5652 base | rs:8539/8544 | :1034 | 🔴 STUB | no-op（rs:8546-8548）；已有 TODO `LANEDIVIDE-INFRA-0001`（IN_PROGRESS, TODO_BOARD.md:65）+ `ACTION-LANEDIVIDE-0001`（BLOCKED, :68），明确"完成前不得在默认树以 no-op 注册"——当前 rs:1034 仍注册为惰性节点，与 TODO 验收语冲突，需 PIPE-HEAD-FLAT-ACTIONS-0001 收口 |
| 28 | ActionMultiCse | hh:163 / cc:879 | :5653 analysis | rs:5122/5320 | :1035 | ✅ | preferredOutput/findMatch/processBlock 全套（roadmap #22 line 143 确认 coreaction.cc:741-890 全移植） |
| 29 | ActionShadowVar | hh:177 / cc:892 | :5654 analysis | rs:6188/6196 | :1036 | ✅ | 逐块 MULTIEQUAL shadow 检测+重写（rs:6198-6336 ↔ cc:892-946） |
| 30 | ActionDeindirect | hh:206 / cc:1219 | :5655 deindirect | rs:6688/6693 | :1037 | 🟡 PARTIAL | 常量/COPY 链路径✅（rs:6723-6808）；缺 GOT/external-ref thunk 与 TypeCode 函数指针路径（rs:6702-6705 自述需 queryExternalRefFunction/TypeCode） |
| 31 | ActionStackPtrFlow | hh:89 / cc:481 | :5656 stackptrflow | rs:7250/7376 | :1038 | 🟡 PARTIAL | checkClog+repair✅（rs:7401-7448）；**缺 phase-1**: `analysis_finished` 守卫与 `analyzeExtraPop` callspec 回写（cc:483-496）；`analyze_extra_pop`（rs:7218）是死代码、apply 不调用（grep 仅定义处） |

### 1.4 mainloop 后段（coreaction.cc:5658-5676）

| # | Ghidra Action | 树槽/组 | Rust impl | 注册 | 状态 | 证据 |
|---|---|---|---|---|---|---|
| 32 | ActionRedundBranch | hh:513 / cc:3492；:5658 deadcontrolflow | rs:2350/2355 | :1072 | ✅ | 死分支剪除（rs:2355-2420） |
| 33 | ActionBlockStructure | blockaction.hh:311；:5659 | blockaction.rs（另行审计） | :1073 | — | 不属 coreaction.cc |
| 34 | ActionConstantPtr | hh:188 / cc:1167；:5660 typerecovery | rs:616/625 | :1008（**在 stackstall 之前**） | ✅(体)/⚠槽位 | apply 真移植；oracle 槽 = BlockStructure 之后、oppool2 之前（cc:5660），Rugra 放在 NonzeroMask 后、stackstall 前（action.rs:1008）——结构化未定即跑，顺序偏差 |
| 35 | ActionDeterminedBranch | hh:524 / cc:3530；:5678 unreachable | rs:2431/2436 | :1076 | ✅ | rs:2436-2492 |
| 36 | ActionUnreachable(unreachable) | :5679 | （同 #9） | :1077 | ✅ | 见 #9 的 :5490 丢弃偏差 |
| 37 | ActionNodeJoin | blockaction.hh:350；:5680 nodejoin | rs:10076/10087 | :1078 | ✅ | diamond join（rs:10087-10268）；`condjoin.match` 简化路径 rs:10249（"Simplified: remove from block1"）自述偏差 |
| 38 | ActionConditionalExe | condexe.hh:133；:5681 | condexe.rs | :1065（**在 RedundBranch 之前**） | ⚠槽位 | oracle 在 NodeJoin 后（cc:5681），Rugra 在 mainloop 中段（action.rs:1065）；另行审计 |
| 39 | ActionConditionalConst | hh:569 / cc:4514；:5682 analysis | rs:7588/8264 | :1079 | ✅ | ~680 行（ConstPoint 机制 rs:7594-7635 ↔ hh:571-582） |

### 1.5 fullloop 尾 10 槽（coreaction.cc:5679-5688）

| # | Ghidra Action | .hh/.cc | 树槽/组 | Rust impl | 注册 | 状态 | 证据 |
|---|---|---|---|---|---|---|---|
| 40 | ActionLikelyTrash | hh:833 / cc:2140 | :5679 protorecovery | rs:6157/6162 | :1084 | 🔴 STUB | 体= `let proto = fd.get_func_proto(); let _ = proto;`（rs:6174-6176）；Ghidra cc:2140-2174 走 trashBegin/trashEnd + traceTrash + INDIRECT/INT_AND 截断；Rugra 的 FuncProto 无 trashset |
| 41/42 | ActionDirectWrite ×2 | :5680-5681 | （同 #16） | :1085（仅 a） | 🟡 PARTIAL(轻) | 同 #16；b 实例 oracle 亦滤除 |
| 43 | ActionDeadCode | :5682 | （同 #21） | :1092 | ✅ | |
| 44 | ActionDoNothing | hh:502 / cc:3466；:5683 | rs:2261/2266 | :1086 | ✅ | rs:2266-2349 |
| 45 | ActionSwitchNorm | hh:607 / cc:4548；:5684 switchnorm | rs:2544/2549 | :1087 | ✅ | rs:2549-2598；残余绑定 `JUMPTABLE-PIPELINE-0001`（TODO_BOARD.md:48） |
| 46 | ActionReturnSplit | blockaction.hh:337；:5685 returnsplit | rs:9872/9919 | :1088 | ✅ | rs:9919-10075 |
| 47 | ActionUnjustifiedParams | hh:918 / cc:4784；:5686 | rs:6084/6089 | :1089 | 🟡 PARTIAL | 自注 "Simplified"（rs:6097-6099）：造 `param_N`/long 占位参数（rs:6123-6141）；Ghidra cc:4784-4823 是 input varnode 与 proto 的 justifies 容器归并算法 |
| 48 | ActionStartTypes | hh:74 / hh:82 内联；:5687 | rs:9014/9026 | :1090 | ✅ | reset/apply 双钩（rs:9028-9042 ↔ hh:77-85） |
| 49 | ActionActiveReturn | hh:761 / cc:1773；:5688 | rs:5884/5889 | :1091 | 🟡 PARTIAL | `checkOutputTrialUse` 被简化为"call op 有 output 即 markActive"（rs:5905-5934）；**不调** `buildOutputFromTrials`（注释列了 step3 但代码直跳 clear，rs:5939-5942）；Ghidra cc:1773-1792 四步全做；count 累加丢弃（rs:5943 `change` 未用） |

### 1.6 fullloop 后顶层（coreaction.cc:5691-5738）

| # | Ghidra Action | .hh/.cc | 树槽/组 | Rust impl | 注册 | 状态 | 证据 |
|---|---|---|---|---|---|---|---|
| 50 | ActionMappedLocalSync | hh:867 / cc:2297 | :5691 localrecovery | rs:8503/8512 | :1097 | ✅ | sync_varnodes_with_symbols(true,true) + overlap 告警（rs:8514-8526 ↔ cc:2297-2309） |
| 51 | ActionStartCleanUp | hh:58 / hh:65 内联 | :5692 cleanup | rs:8986/8995 | :1098 | 🔴 STUB(标记) | no-op（rs:8997-8999）；Ghidra `data.startCleanUp()` 记录 clean_up_index（hh:66）；rs:8984-8985 自述 Funcdata 无该字段 |
| 52 | ActionPreferComplement | blockaction.hh:300；:5714 | rs:9412/9465 | :1112 | ✅ | 另行审计（blockaction 域） |
| 53 | ActionStructureTransform | blockaction.hh:270；:5715 | rs:9588/9602 | :1113 | ✅ | 同上 |
| 54 | ActionNormalizeBranches | blockaction.hh:284；:5716 | blockaction.rs | :1114 | — | 不属 coreaction.cc |
| 55 | ActionAssignHigh | hh:339 / hh:346 内联；:5717 merge | rs:9092/9101 | :1115 | ✅ | 委托 `fd.set_high_level()`（rs:9109 ↔ hh:347） |
| 56 | ActionMergeRequired | hh:362 / hh:369 内联；:5718 | rs:868/877 | :1117 | 🟡 PARTIAL | 三委托齐（rs:888-890 ↔ hh:370-371）但: `group_partials` 是 no-op（rs:889 自注 "CONCAT infra TODO"; merge.rs:1496）；且 `Merge::new()` 每次**新建**，Ghidra 用 `data.getMerge()` 持久对象（hh:370） |
| 57 | ActionMarkExplicit | hh:427 / cc:3237；:5719 | rs:2775/2835 | :1118 | 🟡 PARTIAL | baseExplicit✅（rs:2862-2868）；缺 multlist/multipleInteraction/processMultiplier（rs:2869-2870 自注 "require HighVariable integration (L3 gap)"；Ghidra cc:3007-3090+3237-3415） |
| 58 | ActionMarkImplied | hh:449 / cc:3416；:5720 | rs:2895/3056 | :1119 | 🟡 PARTIAL | 逻辑同构但**遍历序不同**: Ghidra 用后代 DFS 栈（内层先标记, cc:3426-3452），Rugra 平铺 loc_tree 顺序（rs:3077-3096），且 cover 用静态 high.cover 近似（rs:3070-3074 自述） |
| 59 | ActionMergeMultiEntry | hh:396 / hh:403；:5721 | rs:969/978 | :1120 | ✅ | 委托 merge_multi_entry（merge.rs:1578） |
| 60 | ActionMergeCopy | hh:385 / hh:392；:5722 | rs:937/946 | :1121 | ✅ | 委托 merge_opcode(COPY)（merge.rs:1740） |
| 61 | ActionDominantCopy | hh:1001 / hh:1008；:5723 | rs:9135/9144 | :1122 | 🔴 STUB(等价) | `process_copy_trims` 是"faithful no-op"——copyTrims 永不填充（Rugra 无 snip/trim 子系统, rs:9133-9134, merge.rs:2840） |
| 62 | ActionDynamicSymbols | hh:1034 / cc:4869；:5724+:5733 dynamic | rs:8480/8485 | :1123+:1136 | 🔴 STUB | 双实例 no-op（rs:8492-8494）；Ghidra cc:4869-4884 走 Scope::buildDynamicSymbols 建符号 |
| 63 | ActionMarkIndirectOnly | hh:350 / hh:357；:5725 | rs:9208/9265 | :1124 | ✅ | checkIndirectUse 数据流闭包 + markIndirectOnly（rs:9222-9263） |
| 64 | ActionMergeAdjacent | hh:374 / hh:381；:5726 | rs:903/912 | :1125 | ✅ | 委托 merge_adjacent（merge.rs:2887） |
| 65 | ActionMergeType | hh:407 / hh:414；:5727 | rs:1000/1009 | :1126 | 🟡 PARTIAL | 名义只做 mergeByDatatype（hh:415-416），Rugra 委托 `merge_all`（rs:1018）**折叠了 :5718-5729 全序列**（action.rs:1126 注）；持久 Merge 缺失同 #56 |
| 66 | ActionHideShadow | hh:990 / cc:4831；:5728 | rs:2494/2499 | :1127 | ✅ | 高变量去重 + hide_shadows_of（rs:2510-2530 ↔ cc:4831-4845; merge.rs:3307） |
| 67 | ActionCopyMarker | hh:1012 / hh:1019；:5729 | rs:9171/9180 | :1128 | ✅ | 委托 mark_internal_copies（merge.rs:3622） |
| 68 | ActionOutputPrototype | hh:903 / cc:4765；:5730 | rs:5635/5640 | :1133 | 🟡 PARTIAL | 从首个 RETURN 推返回类型（rs:5655-5670）；缺 `isHighOn→updateOutputTypes / updateOutputNoTypes` 分派（cc:4778-4781），Rugra 无 High 层输出类型归并 |
| 69 | ActionInputPrototype | hh:892 / cc:4707；:5731 | rs:5553/5558 | :1134 | 🟡 PARTIAL | 缺 `clearCategory(fake_input)`/`clearUnlockedInput`/`possibleInputParam`/`deriveInputMap`/`updateInputTypes`（cc:4707-4763）；Rugra 直接造 `param_N` long 参数（rs:5606-5626），markActive 也没真正生效（rs:5594-5598 自述 trial 不可变） |
| 70 | ActionMapGlobals | hh:878 / hh:885；:5732 | rs:9315/9324 | :1135 | 🟡 PARTIAL | 只设 PERSIST/READONLY flag（rs:9343-9360）；Ghidra `data.mapGlobals()`（funcdata_varnode.cc:1653-1719）做 queryProperties/discoverScope **建符号**；rs:9331 自述 "cannot create Symbols yet" |
| 71 | ActionNameVars | hh:470 / cc:2978；:5734 | rs:4417/4579 | :1137 | ✅ | ~245 行命名（rs:4579-4823） |
| 72 | ActionSetCasts | hh:320 / cc:2722；:5735 | rs:3118/3434 | :1143 | ✅ | ~310 行（castInput/castOutput 体系 rs:3119-3433）；roadmap #514 项已标 L3 |
| 73 | ActionPrototypeWarnings | hh:1045 / cc:4886；:5737 | rs:2632/2675 | :1145 | 🟡 PARTIAL | 走 callspecs 判 warning（rs:2675-2774），但 `proto_has_input_errors`/`proto_has_output_errors`/`proto_has_custom_storage` 恒 false（rs:2648/2654/2662）→ 三个 warning 类永不触发 |
| 74 | ActionStop | hh:46 / hh:53 内联；:5738 | rs:9060/9069 | :1146 | ✅ | 委托 `fd.stop_processing()`（rs:9073 ↔ hh:54） |

### 1.7 Rust 侧非 oracle Action（coreaction.rs）

| Rust Action | rs 行 | Ghidra 对应 | 注册 | 判定 |
|---|---|---|---|---|
| ActionCse | 669/678 | coreaction.cc:708（**源码中被注释掉**，已核 cc:708-715） | 未注册 | 保留 inert 可接受；注释引用正确 |
| ActionCopyPropagate | 1037/1046 | 无（Ghidra=RulePropagateCopy, oppool1） | 未注册 | 自创层，已从管线删除（action.rs:1049-1051） |
| ActionCallParams | 1152/1342 | 无（自创 SysV ABI 表 rs:1170-1334） | 未注册 | 死代码；硬编码表违反铁律 1.4（机制 D red flag），应随 FUNCLINK 修复一并删除 |
| ActionInferParams | 1585/1594 | 无 | **mainloop 注册**（action.rs:1007） | Rugra 替代层，自述待 ActionActiveParam/DefaultParams 覆盖后替换（action.rs:1004-1006） |
| ActionTypeInfer | 1921/1930 | 无 | 未注册 | 已删除（action.rs:1045-1048） |

---

## 2. 计数汇总

| 类别 | 数量 | Action |
|---|---|---|
| ✅ 实体完整+已注册 | 29 | Start, Constbase, DefaultParams, VarnodeProps, Heritage, DirectWrite*(轻缺), ActiveParam, Spacebase, NonzeroMask, InferTypes, MultiCse, ShadowVar, RedundBranch, DeterminedBranch, Unreachable*(槽位注), DeadCode, ConditionalConst, DoNothing, SwitchNorm, MappedLocalSync, AssignHigh, MergeAdjacent, MergeCopy, MergeMultiEntry, MarkIndirectOnly, HideShadow, CopyMarker, NameVars, SetCasts, Stop（30，其中 DirectWrite 记轻 PARTIAL → 29 严格 FULL） |
| 🟡 PARTIAL（已注册缺腿） | 18 | PrototypeTypes, FuncLink, RestrictLocal, ReturnRecovery, RestructureVarnode, Deindirect, StackPtrFlow, ActiveReturn, UnjustifiedParams, OutputPrototype, InputPrototype, MarkExplicit, MarkImplied, MergeRequired, MergeType, MapGlobals, PrototypeWarnings, DirectWrite |
| 🔴 STUB/near-STUB 已注册 | 10 | ExtraPopSetup, ParamDouble, Segmentize, InternalStorage, LaneDivide, LikelyTrash, StartCleanUp, DominantCopy, DynamicSymbols, ParamDouble |
| ⛔ STUB 且未注册（oracle 有） | 2 | **ActionDynamicMapping（:5504）, ActionForceGoto（:5496）** |
| ➖ 未注册且 oracle 亦滤除 | 3 | NormalizeSetup(normalanalysis), DirectWrite_b(protorecovery_b), FuncLinkOutOnly*(oracle 滤除但 Rust 保留注册=惰性) |

**材料性缺口合计 = 18 PARTIAL + 12 STUB（含 2 个未注册）= 30/62。**
与任务假设的 "~20 个 FuncCallSpecs/HighVariable 依赖型" 对应子集：
FuncCallSpecs 家族缺腿 11 个（FuncLink, PrototypeTypes, ExtraPopSetup, ParamDouble, ActiveReturn,
ReturnRecovery, RestrictLocal, LikelyTrash, UnjustifiedParams, InputPrototype, OutputPrototype）+
HighVariable/符号家族缺腿 7 个（MarkExplicit, MarkImplied, DominantCopy, MapGlobals, MergeRequired/
MergeType 的持久 Merge, RestructureVarnode 的 scope 层）+ 其余（Deindirect, StackPtrFlow, Segmentize,
InternalStorage, DynamicMapping, DynamicSymbols, ForceGoto, StartCleanUp, PrototypeWarnings）。

---

## 3. 管线注册/顺序偏差（oracle=PIPELINE_STAGES_1204.md §2）

Rugra mainloop 实际序（action.rs:986-1079）:
`VarnodeProps→Heritage→ParamDouble→Segmentize→InternalStorage→DirectWrite_a→ActiveParam→
ReturnRecovery→Spacebase→NonzeroMask→[InferParams*R]→ConstantPtr→stackstall(oppool1+LaneDivide/
MultiCse/ShadowVar/Deindirect/StackPtrFlow)→oppool2→RestrictLocal→DeadCode→RestructureVarnode→
InferTypes→ConditionalExe→RedundBranch→BlockStructure→DeterminedBranch→Unreachable→NodeJoin→ConditionalConst`

oracle 序（coreaction.cc:5490-5508, 5652-5658, 5660-5682）:
`Unreachable→VarnodeProps→Heritage→ParamDouble→Segmentize→InternalStorage→ForceGoto→DirectWrite_a→
DirectWrite_b→ActiveParam→ReturnRecovery→RestrictLocal→DeadCode→DynamicMapping→RestructureVarnode→
Spacebase→NonzeroMask→InferTypes→stackstall→RedundBranch→BlockStructure→ConstantPtr→oppool2→
DeterminedBranch→Unreachable→NodeJoin→ConditionalExe→ConditionalConst`

偏差清单（均已写进 action.rs 注释，属可解释但未闭环）：
1. **Unreachable :5490 首实例丢弃**（action.rs:983-985；Rugra 只留 :5673 槽）。
2. **ForceGoto/DynamicMapping 缺注册**（action.rs:993-994, coreaction.rs:10300-10302 自述"故意不注册"）。
3. **RestrictLocal/DeadCode/RestructureVarnode/Spacebase/NonzeroMask/InferTypes 六槽移到 oppool2 之后**
   （oracle 在 stackstall 之前, cc:5502-5508 vs action.rs:1057-1064）。
4. **ConstantPtr 移到 stackstall 之前**（oracle :5660 = BlockStructure 后, action.rs:1008）。
5. **ConditionalExe 移到 RedundBranch/BlockStructure 之前**（oracle :5681 = NodeJoin 后, action.rs:1065）。
6. **FuncLinkOutOnly 保留注册**（oracle 因 noproto 滤除; action.rs:926-938 论证惰性）。
7. Rugra 自创 `ActionInferParams` 插在 mainloop（action.rs:1007），oracle 无此节点。
8. mainloop/fullloop 的 RULE_REPEATAPPLY：代码已置位（action.rs:962,981）但 action.rs:954-980 大段
   注释仍称"not enabled"——注释与代码不一致，且 PIPE-STACKSTALL-COUNT-0001（TODO_BOARD.md:64）
   要求的逐 pass count 反馈尚未验收。

以上 1-7 与 `PIPE-HEAD-FLAT-ACTIONS-0001`（REWORK, TODO_BOARD.md:62）/`PIPE-DERIVED-TREE-0001`
（TODO_BOARD.md:20）的验收范围重叠，本审计不重复开 TODO，只补缺口。

---

## 4. (b) 依赖 DAG 与移植路线（wave 建议）

### 4.1 地基层缺口（DAG 根，按依赖方向）

```
R1 FuncCallSpecs/ProtoModel/FuncProto 语义
   R1.1 FuncProto trashset(trashBegin/trashEnd) 缺 ────────────→ LikelyTrash(cc:2142-2146)
   R1.2 per-callspec extraPop 缺 ─────────────────────────────→ ExtraPopSetup(cc:1436-1466)
   │                                                              └→ StackPtrFlow phase-1(cc:483-496)
   R1.3 FuncProto internal-storage 区间(internalBegin/End) 缺 ─→ InternalStorage(cc:4938-4975)
   R1.4 数据库/符号 FuncProto 查询（现=硬编码 libc 表 rs:1170-1334）→ FuncLink(cc:1474-1572)
   │                                                              └→ ParamDouble(cc:1597-1723)
   R1.5 checkOutputTrialUse 真实遍历 + buildOutputFromTrials ──→ ActiveReturn(cc:1783-1788)
   R1.6 Heritage::guardReturns 缺（heritage.rs:1725 未接，登记于 PARAM-BIND 族）→ ReturnRecovery
   R1.7 deriveInputMap/updateInputTypes/possibleInputParam ────→ InputPrototype(cc:4707-4763)
   │    updateOutputTypes(isHighOn 分派) ─────────────────────→ OutputPrototype(cc:4778-4781)
   R1.8 locked-output RETURN 插腿 + prepareThisPointer ────────→ PrototypeTypes(cc:4623-4649)
   R1.9 justifies 容器归并算法 ────────────────────────────────→ UnjustifiedParams(cc:4784-4823)
   R1.10 queryExternalRefFunction/TypeCode ────────────────────→ Deindirect 外部引用路径(cc:1219-1280)
   （已闭环: FUNCPROTO-MODEL-BIND-0001 DONE→DefaultParams✓; resolve_model 仍 no-op, fspec.rs:1905-1909,
     ProtoModelMerged::selectModel 未支持——影响所有 model 决策点，建议并入 R1 主干）

R2 HighVariable / 持久 Merge
   R2.1 Funcdata 持久 getMerge()（现每 Action Merge::new(): rs:886,920,955,986,1017,9149,9184,2509）
        ─→ MergeRequired/MergeType/MergeAdjacent/MergeCopy/MergeMultiEntry/DominantCopy/CopyMarker/HideShadow
   R2.2 snip/copyTrims 子系统 ────────────────────────────────→ DominantCopy(真体)
   R2.3 CONCAT/groupPartials 基础设施 ────────────────────────→ MergeRequired 的 group_partials(merge.rs:1496)
   R2.4 HighVariable 多后代聚合 multipleInteraction/processMultiplier → MarkExplicit(cc:3007-3090)
   R2.5 后代 DFS 遍历序（DescTreeElement 栈）────────────────→ MarkImplied(cc:3426-3452)

R3 Symbol/Scope 层
   R3.1 queryProperties/discoverScope 建符号（funcdata_varnode.cc:1653-1719）→ MapGlobals
   R3.2 ScopeLocal clearCategory(fake_input) ─────────────────→ InputPrototype
   R3.3 SLEIGH register index（现硬编码 x86 表 rs:795-812）────→ RestructureVarnode
   R3.4 Scope::buildDynamicSymbols ───────────────────────────→ DynamicSymbols(cc:4869-4884)
   R3.5 dynamic 映射（database 层）───────────────────────────→ DynamicMapping(cc:4852-4867)
   （上游: FUNCDATA-LOCALSCOPE-OWNERSHIP-0001 BLOCKED, TODO_BOARD.md:178 — R3 系多数被它压着）

R4 Architecture/Override 接线 ───────────────────────────────→ ForceGoto(cc:671-676)

R5 专项地基（已有 TODO 在跑）
   R5.1 LanedRegister/LaneDivide 全类 ── LANEDIVIDE-INFRA-0001(IN_PROGRESS)+ACTION-LANEDIVIDE-0001(BLOCKED)
   R5.2 UserOpManage/SegmentOp ─────────→ Segmentize(cc:624-649)
   R5.3 jumptable 状态 ─────────────────→ RestructureVarnode.protectSwitchPaths; SwitchNorm 归 JUMPTABLE-PIPELINE-0001
   R5.4 doLiveInject ───────────────────→ Constbase INJECT-0001 残留
```

### 4.2 Wave 建议（高扇出地基优先，write-set 无重叠可并行）

**Wave CA-1（R1/R4 小地基，解锁 6 个 Action，风险最小）**
- FuncProto trashset + per-callspec extraPop + internal-storage 区间（fspec.rs 单文件）
- Heritage::guard_returns（heritage.rs，复用 PARAM-BIND 族既登记缺口）
- Override→Architecture 接线 + ForceGoto 注册（arch.rs/override_rs.rs/action.rs）
- 交付: LikelyTrash, ExtraPopSetup, StackPtrFlow(phase-1), InternalStorage, ReturnRecovery(去播种替代), ForceGoto

**Wave CA-2（R1 主体：protorecovery 家族收口）**
- 依赖 CA-1 + FUNCDATA-LOCALSCOPE-OWNERSHIP-0001（符号 FuncProto 查询）
- FuncLink 去硬编码 ABI 表（删 rs:1170-1334 与 ActionCallParams 死代码）+ ParamDouble 真算法
- ActiveReturn(checkOutputTrialUse+buildOutputFromTrials) + PrototypeTypes locked 腿
- Input/OutputPrototype(deriveInputMap/updateInputTypes) + UnjustifiedParams 容器归并
- Deindirect 外部引用/函数指针路径 + RestrictLocal space 维度（配合 Address space 化）

**Wave CA-3（R2/R3：HighVariable 与符号）**
- Funcdata 持久 Merge 对象（8 处 Merge::new() 收敛）+ copyTrims/snip + groupPartials
- MarkExplicit multiplier 族 + MarkImplied DFS 序
- MapGlobals 建符号 + DynamicSymbols + DynamicMapping(+注册 :5504) + RestructureVarnode SLEIGH 表
- 交付后可拆 Rugra 替代层 ActionInferParams（action.rs:1007）

**Wave CA-4（顺序/注册收口，归 PIPE 系列不改名）**
- mainloop 顺序对齐（§3 偏差 1-7）：由 PIPE-HEAD-FLAT-ACTIONS-0001 + PIPE-DERIVED-TREE-0001 +
  PIPE-STACKSTALL-COUNT-0001 统一验收；LaneDivide 注册策略按 ACTION-LANEDIVIDE-0001 验收语收口。

---

## 5. (c) 拟登记 TODO 清单

格式: ID | 依赖 | write-set | 验收（均要求锁定 oracle fixture `tests/oracle/<id>_1204.{cc,rs,metadata.json}`
+ 权威 runner；核心算法模块 commit 需 `## Cross-Review: APPROVE`）

| ID | 依赖 | write-set | 验收要点 |
|---|---|---|---|
| COREACTION-PORT-LIKELYTRASH-0001 | R1.1 trashset | src/{fspec,coreaction}.rs, docs/api/{fspec,coreaction}.md, fixture+runner | trashset 遍历/traceTrash/INDIRECT+INT_AND 截断/count（cc:2140-2272 全观察） |
| COREACTION-PORT-EXTRAPOP-0001 | R1.2 | 同上 | INT_ADD/INDIRECT SP 调整 + resolveExtraPop 联动（cc:1436-1466） |
| COREACTION-PORT-STACKPTRFLOW-0001 | R1.2（与上同地基，串行同 writer） | src/{fspec,coreaction}.rs, docs | analysis_finished 守卫 + analyzeExtraPop callspec 回写（cc:481-496; rs:7218 死代码激活） |
| COREACTION-PORT-INTERNALSTORAGE-0001 | R1.3 | src/{fspec,coreaction}.rs, docs | internalBegin/End + CALL/CALLIND 输入重建（cc:4938-4975） |
| COREACTION-PORT-FORCEGOTO-0001 | R4 | src/{arch,override_rs,coreaction,action}.rs, docs | Override 接线 + :5496 注册 + applyForceGoto 观察（cc:671-676; override.cc） |
| HERITAGE-GUARDRETURNS-0001（挂 PARAM-BIND 族） | R1.6 | src/{heritage,funcdata,fspec}.rs, docs | guardReturns(cc:1194) 注册 RETURN trials; ReturnRecovery 撤销 model-seeded 替代（rs:8571-8577） |
| COREACTION-PORT-FUNCLINK-0001 | CA-1 + FUNCDATA-LOCALSCOPE-OWNERSHIP-0001 | src/{fspec,coreaction}.rs, docs | 删硬编码 ABI 表（rs:1170-1334）与 ActionCallParams；locked/unlocked/varargs/栈参 opStackLoad+createPlaceholder（cc:1474-1586） |
| COREACTION-PORT-PARAMDOUBLE-0001 | R1.4 | src/{fspec,coreaction}.rs, docs | trial+PIECE 分析（cc:1597-1723） |
| COREACTION-PORT-PROTOTYPES-TYPES-0001 | — | src/coreaction.rs, docs | locked-output RETURN 插腿 + prepareThisPointer（cc:4623-4649） |
| COREACTION-PORT-ACTIVERETURN-0001 | R1.5 | src/{fspec,coreaction}.rs, docs | checkOutputTrialUse 真遍历 + buildOutputFromTrials 接回（cc:1773-1792; rs:5939-5942） |
| COREACTION-PORT-INPUTPROTOTYPE-0001 | R1.7+R3.2 | src/{fspec,varmap,coreaction}.rs, docs | clearCategory/clearUnlockedInput/possibleInputParam/deriveInputMap/updateInputTypes（cc:4707-4763） |
| COREACTION-PORT-OUTPUTPROTOTYPE-0001 | R1.7 | src/{fspec,coreaction}.rs, docs | isHighOn 分派 updateOutputTypes/NoTypes（cc:4765-4782） |
| COREACTION-PORT-UNJUSTIFIEDPARAMS-0001 | R1.9 | src/{fspec,coreaction}.rs, docs | 容器归并（cc:4784-4823），删 param_N/long 占位（rs:6123-6141） |
| COREACTION-PORT-DEINDIRECT-0001 | R1.10 | src/{coreaction,database}.rs, docs | 外部引用 thunk + TypeCode 函数指针路径（cc:1219-1280） |
| COREACTION-PORT-RESTRICTLOCAL-0001 | Address space 维度 | src/{address,fspec,coreaction}.rs, docs | space 感知栈参判定替代 0x7FFF_FFFF 启发式（rs:5068） |
| COREACTION-STATEFUL-MERGE-0001 | — | src/{funcdata,merge,coreaction}.rs, docs | fd.getMerge() 持久对象；8 处 Merge::new() 收敛；MergeType 恢复单职责（hh:414-416） |
| COREACTION-PORT-DOMINANTCOPY-0001 | R2.2 snip/copyTrims | src/{merge,coreaction}.rs, docs | processCopyTrims 真体（merge.cc 对应段） |
| COREACTION-PORT-GROUPPARTIALS-0001 | R2.3 CONCAT 基础设施 | src/{merge,coreaction}.rs, docs | groupPartials 真体（merge.rs:1496 去 no-op） |
| COREACTION-PORT-MARKEXPLICIT-0001 | R2.4 | src/{coreaction,variable}.rs, docs | multipleInteraction/processMultiplier/checkNewToConstructor（cc:3007-3090, 3237-3415） |
| COREACTION-PORT-MARKIMPLIED-0001 | R2.5 | src/coreaction.rs, docs | 后代 DFS 栈遍历序（cc:3426-3452）+ 动态 cover |
| COREACTION-PORT-MAPGLOBALS-0001 | R3.1 | src/{coreaction,database,varmap}.rs, docs | queryProperties/discoverScope 建符号（funcdata_varnode.cc:1653-1719） |
| COREACTION-PORT-DYNAMICSYMBOLS-0001 | R3.4 | src/{coreaction,database}.rs, docs | buildDynamicSymbols（cc:4869-4884） |
| COREACTION-PORT-DYNAMICMAPPING-0001 | R3.5 | src/{coreaction,database,action}.rs, docs | 真体 + **注册 :5504**（cc:4852-4867; action.rs 缺） |
| COREACTION-PORT-RESTRUCTUREVARNODE-0001 | R3.3+R5.3 | src/{coreaction,varmap}.rs, docs | aliasyes 穿透 + SLEIGH register index 替代硬编码表（rs:795-812）+ protectSwitchPaths |
| COREACTION-PORT-SEGMENTIZE-0001 | R5.2 | src/{arch,coreaction}.rs, docs | UserOpManage/SegmentOp（cc:624-649） |
| COREACTION-PORT-STARTCLEANUP-0001 | Funcdata clean_up_index | src/{funcdata,coreaction}.rs, docs | startCleanUp 记录索引（hh:66; rs:8984） |
| COREACTION-PORT-PROTOTYPEWARNINGS-0001 | — | src/{fspec,coreaction}.rs, docs | 三个恒 false 谓词真化（rs:2648/2654/2662; cc:4886-4936） |
| COREACTION-DEINFUNCPARAMS-0001 | CA-2 完成后 | src/{coreaction,action}.rs, docs | 撤 Rugra 替代层 ActionInferParams（action.rs:1007）与死代码 ActionCallParams（rs:1152） |

已存在、直接复用（不重开）: `ACTION-LANEDIVIDE-0001`（TODO_BOARD.md:68）、`LANEDIVIDE-INFRA-0001`（:65）、
`PIPE-HEAD-FLAT-ACTIONS-0001`（:62）、`PIPE-STACKSTALL-COUNT-0001`（:64）、`PIPE-DERIVED-TREE-0001`（:20）、
`JUMPTABLE-PIPELINE-0001`（:48，SwitchNorm）、`FUNCDATA-LOCALSCOPE-OWNERSHIP-0001`（:178）、
`FUNCPROTO-MODEL-BIND-0001`（:175，已 DONE）、`INJECT-0001`（Constbase 残留）、
`HERITAGE-DRIVER-SWITCH-0001`（:158）、`ORACLE-0002`（:122，12.0.4 golden 已就位——上述验收可用真 12.0.4 oracle）。

---

## 6. 审计方法与限制

- 逐个核读 62 个 oracle 类声明（coreaction.hh:34-1058）+ 46 个 cc 内 apply 全文抽样 + Rust 71 个 impl 体；
  树注册对照 action.rs:905-1148 与 coreaction.cc:5462-5738。
- 未做: 逐 Action 的 oracle 行为差分（本 agent 只读且禁 build/test）；表中 ✅ 判定基于"结构完整 + 关键腿在位"，
  按机制 B2 仍属 `NO_ORACLE`/`UNTESTED`，升 L3 需逐 fixture 验证。
- `resolve_model` no-op（fspec.rs:1905-1909）影响所有走 model 决策的路径（ProtoModelMerged 缺失），
  建议作为 R1 主干单独登记（本报告归入 R1 说明，未单列 TODO，避免与 FUNCPROTO 系重叠）。

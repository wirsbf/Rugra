# PIPE-TREE-0001：Ghidra 12.0.4 Action 有序树与执行语义审计

日期：2026-08-13
结论：**REJECT / MISMATCH**。本报告只证明源码级结构与执行语义差异；没有锁定 oracle 的同输入运行结果，不能作为 `MATCH`、L3 或全流水线门禁通过证据。

## 1. 锁定范围与证据快照

- 唯一 oracle：Ghidra tag `Ghidra_12.0.4_build`，commit `e40ed13014025f82488b1f8f7bca566894ac376b`。
- 完整重读：
  - `action.hh:1-327`；核心定义 `ActionGroupList:31-40`、`Action:52-135`、`ActionGroup:143-165`、`ActionRestartGroup:173-182`、`ActionPool:262-285`。
  - `action.cc:1-1160`；核心函数 `Action::Action:27`、`reset:100`、`resetStats:108`、`perform:298-362`、`ActionGroup::addAction:376`、`clone:391`、`reset:408`、`apply:506`、`ActionRestartGroup::clone:529`、`reset:546`、`apply:553`、`ActionPool::addRule:740`、`processOp:822`、`apply:877`、`clone:899`、`reset/resetStats:916-934`、`ActionDatabase::setGroup:1059-1069`。
  - `coreaction.hh:1-1085`，包括每个 Action 的构造 flags、base-group、reset 与 count 约定。
  - `coreaction.cc:5374-5739`；`ActionInferTypes::apply:5374-5416`、`buildDefaultGroups:5419-5458`、`universalAction:5462-5739`。
  - restart 状态清除闭包：`architecture.cc:335-341 Architecture::clearAnalysis`、`funcdata.cc:84-112 Funcdata::clear`。
  - 实际主管线：`architecture.cc:582-591 Architecture::buildAction`、`ghidra_process.hh:149-164 DecompileAt`、`ghidra_process.cc:284-335 DecompileAt::loadParameters/rawAction`。
- Rugra 审计对象：`src/action.rs`、`src/coreaction.rs`、直接生产消费者及 `src/funcdata.rs` 的状态清除/HighVariable 路径。
- Rugra 是共享工作树，writer 冻结前的采样哈希为：
  - `src/action.rs` 冻结 SHA-256：`e1b191fe10daae003931405850beeb11c0d807945985f0a7ea2aa845715f9bfb`
  - `src/coreaction.rs` 冻结 SHA-256：`79364848c7c134da6ba97e594ab0be2d486be35776d4abd657c23d568befdfe7`
  - 以下 Rust 行号已按这组冻结内容重扫。

审计方法不是比较动作名字集合。比较键是结构路径、同层 ordinal、节点种类、运行时名字、base-group、flags、构造参数和 pool 内 rule ordinal；重复节点不去重，group-set 的书写顺序也不冒充执行顺序。

## 2. 四类决定性语义

### 2.1 引用、输出与共享状态

- `Action::perform(Funcdata &data)`、每个 `apply(Funcdata &data)` 和 `reset(Funcdata &data)` 操作同一个 `Funcdata` 引用；Action 的 `count/status/lcount` 是对象成员，不是一次调用的局部返回值，见 `action.hh:79-88,122-130`、`action.cc:298-362`。
- `ActionGroup` 持有并按序复用同一组 child Action 指针；partial return 后保存 iterator，下一次从同一个 child 继续，见 `action.hh:145-148`、`action.cc:506-527`。
- `ActionGroup::reset` 先调用自己的 `Action::reset`，再按 vector 顺序 reset 每个 child；不会重建或替换 child identity，见 `action.cc:408-416`。
- `ActionRestartGroup` restart 时不是只重置 executor。它先通过 `Architecture::clearAnalysis(&data)` 清空该 `Funcdata` 的分析产物，再只 reset children；该调用最终清 IR/CFG/SSA/High/calls/jumptables 和 analysis flags，见 `action.cc:574-580`、`architecture.cc:335-341`、`funcdata.cc:84-112`。
- `ActionPool` 中 `allrules` 与 per-op vectors 保存相同 Rule 对象指针；per-op 表只改变查找入口，不复制或重排 Rule 身份，见 `action.hh:263-268`、`action.cc:740-751`。
- `ActionPool::clone` 按 `allrules` 原序调用每个 `Rule::clone(group-set)`，首次 surviving Rule 才建立同名同 flags pool；全空返回 `NULL`，见 `action.cc:899-914`。

### 2.2 循环边界与遍历顺序

- `ActionGroup::addAction` 是 `push_back`；apply 从 `actlist.begin()` 到 `end()`，严格保持 universal tree 的构造顺序，见 `action.cc:376-380,506-527`。
- `ActionGroup::clone` 递归过滤但保持原顺序；首次 surviving child 才创建 wrapper，全空返回 `NULL`，见 `action.cc:391-406`。
- `ActionPool::processOp` 每条 Rule 后立即检查 opcode。opcode 一变，马上切到新 opcode 的 Rule vector 且 `rule_index=0`；不会把旧 opcode 的剩余 rules 跑完，见 `action.cc:836-869`。
- `ActionPool::apply` 使用 `PcodeOpTree::beginOpAll/endOpAll` 的确定顺序且支持中断续跑，见 `action.cc:877-888`。这不是 `alivelist` 的偶然插入顺序。
- 固定点嵌套顺序是 `oppool1 → stackstall → mainloop → fullloop` 逐层向外传播；`oppool2`、`cleanup` 各有自己的固定点。任何 flatten 都会改变可观察 phase boundary。

### 2.3 计数器、初值、增量和 reset

- `Action::perform` 在 `status_start` 才把 `count=0`；start breakpoint 在 `count_tests++` 之前。`status_breakstarthit/status_repeat` 才设置 `lcount=count`；`status_mid` 续跑不重置 `lcount`，见 `action.cc:303-327`。
- derived `apply` 的正常完成返回 `0`，partial 返回 `-1`；发生的变化由 derived Action 增加继承的 `count`。若本 pass 有 `lcount<count`，base `perform` 只把 `count_apply` 加一次，而不是每个 rewrite 加一次，见 `action.cc:328-353`。
- `rule_repeatapply` 只在本 pass 的 `count` 增长时重跑。`rule_onceperfunc` 完成后无条件进入 `status_end`；`rule_oneactperfunc` 仅当总 count 大于零才结束，见 `action.cc:345-361`。
- `Action::reset` 只恢复 `status_start` 并清 `rule_warnings_given`；不清 `count_tests/count_apply`。统计只由 `resetStats` 清，见 `action.cc:100-115`。
- `ActionGroup::apply` 只在 child 完整完成后把 child 的正 count 累加到 group；partial 不提前推进 iterator，见 `action.cc:514-524`。
- `ActionRestartGroup::reset` 才初始化 `curstart=0`。apply 中先执行整组；正常 pending 时 `++curstart` 后以 `>` 比 max，因此 `max=1` 允许初跑后恰好一次 clean restart，见 `action.cc:546-580`。
- 没有 restart pending 时 `curstart=-1`，后续 apply 直接返回 0；jumptable recovery pending 时直接返回 0 且不把 `curstart` 置为 `-1`，见 `action.cc:558-567`。

### 2.4 排序与比较键

- `ActionGroupList` 内部是 `set<string>`；`setGroup` 去重并以集合自身比较器保存，默认组数组的书写次序不决定 action 执行次序，见 `action.hh:31-40`、`action.cc:1059-1069`。
- Action/Rule 是否存活的比较键是 `basegroup ∈ selected group-set`。复合 wrapper 没有可独立选择的 base-group；只要有 descendant 存活，wrapper 就按原位置存活。
- Action tree 的比较键必须是 `(parent structural path, ordinal, kind, name, basegroup, flags, constructor args)`。名字并不唯一：oracle 有两处 `Unreachable`、四处 raw `DirectWrite`、两处 `DeadCode`、两处 `DynamicSymbols`。
- pool 的比较键是 opcode 对应 Rule vector 中的 registration ordinal；没有 name-sort 或 HashMap iteration 语义。

## 3. 默认组选择语义

`buildDefaultGroups` 的原始数组及定义行为如下；数组末尾空串只是终止符：

- `decompile`，31 个 group，`coreaction.cc:5424-5432`：`base, protorecovery, protorecovery_a, deindirect, localrecovery, deadcode, typerecovery, stackptrflow, blockrecovery, stackvars, deadcontrolflow, switchnorm, cleanup, splitcopy, splitpointer, merge, dynamic, casts, analysis, fixateglobals, fixateproto, constsequence, segment, returnsplit, nodejoin, doubleload, doubleprecis, unreachable, subvar, floatprecision, conditionalexe`。
- `jumptable`，11 个，`coreaction.cc:5434-5436`：`base, noproto, localrecovery, deadcode, stackptrflow, stackvars, analysis, segment, subvar, normalizebranches, conditionalexe`。
- `normalize`，18 个，`coreaction.cc:5438-5443`：`base, protorecovery, protorecovery_b, deindirect, localrecovery, deadcode, stackptrflow, normalanalysis, stackvars, deadcontrolflow, analysis, fixateproto, nodejoin, unreachable, subvar, floatprecision, normalizebranches, conditionalexe`。
- `paramid`，17 个，`coreaction.cc:5445-5450`：`base, protorecovery, protorecovery_b, deindirect, localrecovery, deadcode, typerecovery, stackptrflow, siganalysis, stackvars, deadcontrolflow, analysis, fixateproto, unreachable, subvar, floatprecision, conditionalexe`。
- `register`：`base, analysis, subvar`，`coreaction.cc:5452-5453`；`firstpass`：`base`，`coreaction.cc:5455-5456`。

`siganalysis` 在静态 universal tree 中没有成员，可能只为架构扩展保留。有效 `decompile` root 是从唯一 universal tree clone/filter 得到的：注册 key 是 `decompile`，但 root Action 的 identity/name 仍是 `universal`。

## 4. Oracle 的完整有序 Action tree

记法：`Class("runtime-name")[base-group; flags; args] @ coreaction.cc:line`。`×` 表示 raw universal 中存在、但被默认 `decompile` group-set 过滤；不是漏项。

```text
ActionRestartGroup("universal")[wrapper; onceperfunc; maxrestarts=1] @5474
├─ 01 ActionStart("start")[base] @5477
├─ 02 ActionConstbase("constbase")[base] @5478
├─ 03 × ActionNormalizeSetup("normalizesetup")[normalanalysis; onceperfunc] @5479
├─ 04 ActionDefaultParams("defaultparams")[base; onceperfunc] @5480
├─ 05 ActionExtraPopSetup("extrapopsetup")[base; onceperfunc; stackspace] @5482
├─ 06 ActionPrototypeTypes("prototypetypes")[protorecovery; onceperfunc] @5483
├─ 07 ActionFuncLink("funclink")[protorecovery; onceperfunc] @5484
├─ 08 × ActionFuncLinkOutOnly("funclink_outonly")[noproto; onceperfunc] @5485
├─ 09 ActionGroup("fullloop")[wrapper; repeatapply] @5487
│  ├─ 09.01 ActionGroup("mainloop")[wrapper; repeatapply] @5489
│  │  ├─ 01 ActionUnreachable("unreachable")[base] @5490
│  │  ├─ 02 ActionVarnodeProps("varnodeprops")[base] @5491
│  │  ├─ 03 ActionHeritage("heritage")[base] @5492
│  │  ├─ 04 ActionParamDouble("paramdouble")[protorecovery] @5493
│  │  ├─ 05 ActionSegmentize("segmentize")[base] @5494
│  │  ├─ 06 ActionInternalStorage("internalstorage")[base; onceperfunc] @5495
│  │  ├─ 07 ActionForceGoto("forcegoto")[blockrecovery] @5496
│  │  ├─ 08 ActionDirectWrite("directwrite")[protorecovery_a; propagate_indirect=true] @5497
│  │  ├─ 09 × ActionDirectWrite("directwrite")[protorecovery_b; propagate_indirect=false] @5498
│  │  ├─ 10 ActionActiveParam("activeparam")[protorecovery] @5499
│  │  ├─ 11 ActionReturnRecovery("returnrecovery")[protorecovery] @5500
│  │  ├─ 12 ActionRestrictLocal("restrictlocal")[localrecovery] @5502
│  │  ├─ 13 ActionDeadCode("deadcode")[deadcode] @5503
│  │  ├─ 14 ActionDynamicMapping("dynamicmapping")[dynamic] @5504
│  │  ├─ 15 ActionRestructureVarnode("restructure_varnode")[localrecovery] @5505
│  │  ├─ 16 ActionSpacebase("spacebase")[base] @5506
│  │  ├─ 17 ActionNonzeroMask("nonzeromask")[analysis] @5507
│  │  ├─ 18 ActionInferTypes("infertypes")[typerecovery] @5508
│  │  ├─ 19 ActionGroup("stackstall")[wrapper; repeatapply] @5509
│  │  │  ├─ a ActionPool("oppool1")[wrapper; repeatapply] @5511
│  │  │  ├─ b ActionLaneDivide("lanedivide")[base; onceperfunc] @5652
│  │  │  ├─ c ActionMultiCse("multicse")[analysis] @5653
│  │  │  ├─ d ActionShadowVar("shadowvar")[analysis] @5654
│  │  │  ├─ e ActionDeindirect("deindirect")[deindirect] @5655
│  │  │  └─ f ActionStackPtrFlow("stackptrflow")[stackptrflow; stackspace] @5656
│  │  ├─ 20 ActionRedundBranch("redundbranch")[deadcontrolflow] @5658
│  │  ├─ 21 ActionBlockStructure("blockstructure")[blockrecovery] @5659
│  │  ├─ 22 ActionConstantPtr("constantptr")[typerecovery] @5660
│  │  ├─ 23 ActionPool("oppool2")[wrapper; repeatapply] @5662
│  │  ├─ 24 ActionDeterminedBranch("determinedbranch")[unreachable] @5672
│  │  ├─ 25 ActionUnreachable("unreachable")[unreachable] @5673
│  │  ├─ 26 ActionNodeJoin("nodejoin")[nodejoin] @5674
│  │  ├─ 27 ActionConditionalExe("conditionalexe")[conditionalexe] @5675
│  │  └─ 28 ActionConditionalConst("condconst")[analysis] @5676
│  ├─ 09.02 ActionLikelyTrash("likelytrash")[protorecovery] @5679
│  ├─ 09.03 ActionDirectWrite("directwrite")[protorecovery_a; propagate_indirect=true] @5680
│  ├─ 09.04 × ActionDirectWrite("directwrite")[protorecovery_b; propagate_indirect=false] @5681
│  ├─ 09.05 ActionDeadCode("deadcode")[deadcode] @5682
│  ├─ 09.06 ActionDoNothing("donothing")[deadcontrolflow; repeatapply] @5683
│  ├─ 09.07 ActionSwitchNorm("switchnorm")[switchnorm] @5684
│  ├─ 09.08 ActionReturnSplit("returnsplit")[returnsplit] @5685
│  ├─ 09.09 ActionUnjustifiedParams("unjustparams")[protorecovery] @5686
│  ├─ 09.10 ActionStartTypes("starttypes")[typerecovery] @5687
│  └─ 09.11 ActionActiveReturn("activereturn")[protorecovery] @5688
├─ 10 ActionMappedLocalSync("mapped_local_sync")[localrecovery] @5691
├─ 11 ActionStartCleanUp("startcleanup")[cleanup] @5692
├─ 12 ActionPool("cleanup")[wrapper; repeatapply] @5694
├─ 13 ActionPreferComplement("prefercomplement")[blockrecovery] @5714
├─ 14 ActionStructureTransform("structuretransform")[blockrecovery] @5715
├─ 15 × ActionNormalizeBranches("normalizebranches")[normalizebranches] @5716
├─ 16 ActionAssignHigh("assignhigh")[merge; onceperfunc] @5717
├─ 17 ActionMergeRequired("mergerequired")[merge; onceperfunc] @5718
├─ 18 ActionMarkExplicit("markexplicit")[merge; onceperfunc] @5719
├─ 19 ActionMarkImplied("markimplied")[merge; onceperfunc] @5720
├─ 20 ActionMergeMultiEntry("mergemultientry")[merge; onceperfunc] @5721
├─ 21 ActionMergeCopy("mergecopy")[merge; onceperfunc] @5722
├─ 22 ActionDominantCopy("dominantcopy")[merge; onceperfunc] @5723
├─ 23 ActionDynamicSymbols("dynamicsymbols")[dynamic; onceperfunc] @5724
├─ 24 ActionMarkIndirectOnly("markindirectonly")[merge; onceperfunc] @5725
├─ 25 ActionMergeAdjacent("mergeadjacent")[merge; onceperfunc] @5726
├─ 26 ActionMergeType("mergetype")[merge; onceperfunc] @5727
├─ 27 ActionHideShadow("hideshadow")[merge; onceperfunc] @5728
├─ 28 ActionCopyMarker("copymarker")[merge; onceperfunc] @5729
├─ 29 ActionOutputPrototype("outputprototype")[localrecovery; onceperfunc] @5730
├─ 30 ActionInputPrototype("inputprototype")[fixateproto; onceperfunc] @5731
├─ 31 ActionMapGlobals("mapglobals")[fixateglobals; onceperfunc] @5732
├─ 32 ActionDynamicSymbols("dynamicsymbols")[dynamic; onceperfunc] @5733
├─ 33 ActionNameVars("namevars")[merge; onceperfunc] @5734
├─ 34 ActionSetCasts("setcasts")[casts; onceperfunc] @5735
├─ 35 ActionFinalStructure("finalstructure")[blockrecovery] @5736
├─ 36 ActionPrototypeWarnings("prototypewarnings")[protorecovery; onceperfunc] @5737
└─ 37 ActionStop("stop")[base] @5738
```

Raw universal 有 83 个 Action nodes：root 1、nested groups 3、pools 3、leaf Actions 76。默认 `decompile` 精确过滤 5 个 leaf：`NormalizeSetup`、`FuncLinkOutOnly`、两处 `DirectWrite(protorecovery_b,false)`、`NormalizeBranches`；所以有效树是 **78 Action nodes = root 1 + groups 3 + pools 3 + leaves 71**。不能把这五项记为 Rugra 的必需 leaf，但 Rugra 必须具有 universal→group-filter 的同构机制。

注释掉的 `ActionParamShiftStart/Stop`（`5481/5501`）和 `RuleIndirectConcat`（`5667`）不属于树，禁止把注释行算作漏项。

### 4.1 `oppool1` 的 134 条静态 Rule

以下就是 registration order；末尾才追加 `conf->extra_pool_rules` 的原 vector 顺序，并在转移所有权后 clear，见 `coreaction.cc:5511-5649`：

```text
001 EarlyRemoval; 002 TermOrder; 003 SelectCse; 004 CollectTerms;
005 PullsubMulti; 006 PullsubIndirect; 007 PushMulti; 008 Sborrow;
009 Scarry; 010 IntLessEqual; 011 TrivialArith; 012 TrivialBool;
013 TrivialShift; 014 SignShift; 015 TestSign; 016 IdentityEl;
017 OrMask; 018 AndMask; 019 OrConsume; 020 OrCollapse;
021 AndOrLump; 022 ShiftBitops; 023 RightShiftAnd; 024 NotDistribute;
025 HighOrderAnd; 026 AndDistribute; 027 AndCommute; 028 AndPiece;
029 AndZext; 030 AndCompare; 031 DoubleSub; 032 DoubleShift;
033 DoubleArithShift; 034 ConcatShift; 035 LeftRight; 036 ShiftCompare;
037 Shift2Mult; 038 ShiftPiece; 039 MultiCollapse; 040 IndirectCollapse;
041 2Comp2Mult; 042 Sub2Add; 043 CarryElim; 044 Bxor2NotEqual;
045 Less2Zero; 046 LessEqual2Zero; 047 SLess2Zero; 048 Equal2Zero;
049 Equal2Constant; 050 ThreeWayCompare; 051 XorCollapse; 052 AddMultCollapse;
053 CollapseConstants; 054 TransformCpool; 055 PropagateCopy; 056 ZextEliminate;
057 SlessToLess; 058 ZextSless; 059 BitUndistribute; 060 BooleanUndistribute;
061 BooleanDedup; 062 BoolZext; 063 BooleanNegate; 064 Logic2Bool;
065 SubExtComm; 066 SubCommute; 067 ConcatCommute; 068 ConcatZext;
069 ZextCommute; 070 ZextShiftZext; 071 ShiftAnd; 072 ConcatZero;
073 ConcatLeftShift; 074 SubZext; 075 SubCancel; 076 ShiftSub;
077 HumptyDumpty; 078 DumptyHump; 079 HumptyOr; 080 NegateIdentity;
081 SubNormal; 082 PositiveDiv; 083 DivTermAdd; 084 DivTermAdd2;
085 DivOpt; 086 SignForm; 087 SignForm2; 088 SignDiv2;
089 DivChain; 090 SignNearMult; 091 ModOpt; 092 SignMod2nOpt;
093 SignMod2nOpt2; 094 SignMod2Opt; 095 SwitchSingle; 096 CondNegate;
097 BoolNegate; 098 LessEqual; 099 LessNotEqual; 100 LessOne;
101 RangeMeld; 102 FloatRange; 103 Piece2Zext; 104 Piece2Sext;
105 PopcountBoolXor; 106 XorSwap; 107 LzcountShiftBool; 108 FloatSign;
109 OrCompare; 110 SubvarAnd; 111 SubvarSubpiece; 112 SplitFlow;
113 PtrFlow; 114 SubvarCompZero; 115 SubvarShift; 116 SubvarZext;
117 SubvarSext; 118 NegateNegate; 119 ConditionalMove; 120 OrPredicate;
121 FuncPtrEncoding; 122 SubfloatConvert; 123 FloatCast; 124 IgnoreNan;
125 Unsigned2Float; 126 Int2FloatCollapse; 127 PtraddUndo; 128 PtrsubUndo;
129 Segment; 130 PiecePathology; 131 DoubleLoad; 132 DoubleStore;
133 DoubleIn; 134 DoubleOut;
then: architecture extra_pool_rules[0..N] in vector order
```

静态 group 分布为：`analysis=111, deadcode=1, nodejoin=1, subvar=8, conditionalexe=2, floatprecision=3, typerecovery=2, segment=1, protorecovery=1, doubleload=1, doubleprecis=3`。这些 group 全在 `decompile` 中，故 134 条静态 Rule 全部存活。

### 4.2 `oppool2` 与 `cleanup`

- `oppool2`，`coreaction.cc:5662-5669`，严格五条：`PushPtr, StructOffset0, PtrArith, LoadVarnode, StoreVarnode`。
- `cleanup`，`coreaction.cc:5694-5710`，严格十五条：`MultNegOne, AddUnsigned, 2Comp2Sub, DumptyHumpLate, SubRight, FloatSignCleanup, ExpandLoad, PtrsubCharConstant, ExtensionPush, PieceStructure, SplitCopy, SplitLoad, SplitStore, StringCopy, StringStore`。

## 5. Rugra 的实际有序树

`ActionDatabase::set_default_actions` 位于 `src/action.rs:834-1021`；`build_full_pipeline_actions` 位于 `src/coreaction.rs:9510-9569`。后者不是 group-preserving subtree builder，而是 27 个 leaf 的平铺 Vec；前者把整段 Vec 插到 `FuncLink` 后、`ExtraPopSetup` 前。

```text
ActionRestartGroup("decompile")[onceperfunc; maxrestarts=1] @action.rs:836
├─ 01 Start @843
├─ 02 Constbase @844
├─ 03 DefaultParams @849
├─ 04 FuncLink @850
├─ 05..31 build_full_pipeline_actions[0..26] @854-856
│  ├─ DefaultParams; PrototypeTypes; FuncLinkOutOnly;
│  ├─ VarnodeProps; ParamDouble; Segmentize; InternalStorage;
│  ├─ DirectWrite; ActiveParam; ReturnRecovery; NonzeroMask; InferTypes;
│  ├─ MultiCse; ShadowVar; Deindirect;
│  ├─ UnjustifiedParams; StartTypes; ActiveReturn; SwitchNorm;
│  └─ AssignHigh; HideShadow; DominantCopy; CopyMarker;
│     OutputPrototype; InputPrototype; SetCasts; PrototypeWarnings
├─ 32 ExtraPopSetup @857
├─ 33 PrototypeTypes @858
├─ 34 ActionGroup("fullloop")[repeatapply] @868
│  ├─ 34.01 ActionGroup("mainloop")[repeatapply] @887
│  │  ├─ VarnodeProps @892
│  │  ├─ Heritage @893
│  │  ├─ ParamDouble @894
│  │  ├─ DirectWrite @895
│  │  ├─ ActiveParam @896
│  │  ├─ ReturnRecovery @897
│  │  ├─ Spacebase @898
│  │  ├─ NonzeroMask @899
│  │  ├─ StackPtrFlow @900
│  │  ├─ Rugra-only InferParams @906
│  │  ├─ ConstantPtr @907
│  │  ├─ ActionGroup("stackstall")[repeatapply] @918
│  │  │  └─ ActionPool("simplifypool")[repeatapply] @920
│  │  ├─ ActionPool("oppool2")[repeatapply] @925
│  │  ├─ RestrictLocal @939
│  │  ├─ DeadCode @940
│  │  ├─ RestructureVarnode @941
│  │  ├─ InferTypes @946
│  │  ├─ ConditionalExe @947
│  │  ├─ RedundBranch @954
│  │  ├─ BlockStructure @955
│  │  ├─ DeterminedBranch @958
│  │  ├─ Unreachable @959
│  │  ├─ NodeJoin @960
│  │  └─ ConditionalConst @961
│  ├─ LikelyTrash @966
│  ├─ DirectWrite @967
│  ├─ DoNothing @968
│  ├─ SwitchNorm @969
│  ├─ ReturnSplit @970
│  ├─ UnjustifiedParams @971
│  ├─ StartTypes @972
│  ├─ ActiveReturn @973
│  └─ DeadCode @974
├─ MappedLocalSync @979
├─ StartCleanUp @980
├─ ActionPool("cleanup")[repeatapply] @982
├─ MergeType                         # extra/premature @987
├─ NormalizeBranches                 # default decompile 应过滤 @988
├─ PreferComplement @990
├─ StructureTransform @991
├─ MergeRequired @993
├─ MarkExplicit @994
├─ MarkImplied @995
├─ MergeMultiEntry @996
├─ MergeCopy @997
├─ MarkIndirectOnly @998
├─ MergeAdjacent @999
├─ MergeType @1000
├─ HideShadow @1001
├─ OutputPrototype @1006
├─ InputPrototype @1007
├─ MapGlobals @1008
├─ DynamicSymbols @1009
├─ NameVars @1010
├─ SetCasts @1016
├─ PrototypeWarnings @1017
├─ FinalStructure @1018
└─ Stop @1019
```

该快照共 **95 Action nodes = root 1 + nested groups 3 + pools 3 + leaves 88**。`simplifypool` 有 136 条 Rule（oracle 134 条后追加 Rugra-only `RuleSextEliminate`、`RuleEquality`）；`oppool2` 为 5；`cleanup` 为 16（oracle 15 条后追加 Rugra-only `RuleTrivialArith`），总计 157。数目只作一致性校验，不能替代 ordered structural diff。

## 6. 首差异与完整结构差异矩阵

### 6.1 首差异

有两个层次的首差异，均在 Heritage 前且生产路径可达：

1. identity 首差异：oracle derived root 的注册 key 是 `decompile`，但 Action name 仍是 `universal`（`coreaction.cc:5474` + `action.cc:391-406`）；Rugra root node name 直接是 `decompile`（`src/action.rs:836-840`）。
2. 同层顺序首差异：有效 decompile 的前 3 个 leaf 都是 `Start, Constbase, DefaultParams`；ordinal 4 oracle 是 `ExtraPopSetup`（raw `:5482`），Rugra 是 `FuncLink`（`src/action.rs:850`）。Rugra 随后在 ordinal 5 插入 flatten helper，而 oracle ordinal 5/6 是 `PrototypeTypes/FuncLink`。

### 6.2 平铺、重复、错阶段、漏项

| 类别 | 确定差异 | 可观察后果 |
|---|---|---|
| 平铺 | 27 个 helper leaf 在 root 的 `FuncLink` 后、`ExtraPopSetup` 前执行；oracle 中大多数属于 mainloop、stackstall、fullloop tail 或 merge/final 阶段 | 绕过 4 层 fixed-point 边界；多数提前到 Heritage 前 |
| group/filter 缺失 | Rugra 没有 universal clone、base-group、derived roots、`current_group` 的执行语义 | `FuncLinkOutOnly[noproto]` 与 `NormalizeBranches[normalizebranches]` 错进 decompile；无法构造 jumptable/normalize/paramid/register/firstpass 等根 |
| 重复 | DefaultParams、PrototypeTypes、VarnodeProps、ParamDouble、DirectWrite、ActiveParam、ReturnRecovery、NonzeroMask、InferTypes、UnjustifiedParams、StartTypes、ActiveReturn、SwitchNorm、HideShadow、Output/InputPrototype、SetCasts、PrototypeWarnings 等由 flatten 与原树双跑；`MergeType` 又在 post-cleanup 双跑 | once flags 大量缺失时不是无害重复；前一次突变改变后一次 guard/输入 |
| 正确的 oracle 重复被破坏 | 缺 mainloop 首部 `Unreachable[base]`；缺 second `DynamicSymbols`；`DeadCode` 第二次被移到 ActiveReturn 后；只有 A 风格 DirectWrite，没有 B 参数化实例 | 不同 base-group/phase/constructor arg 的节点被误 dedup 或错位 |
| stackstall 被拆平 | `LaneDivide` 缺失；`MultiCse/ShadowVar/Deindirect` 只在 root flatten；`StackPtrFlow` 在 stackstall 外；stackstall 只含 pool | pool 变化不再触发同轮 Lane/MultiCse/Shadow/Deindirect/stack flow，并向外反馈 |
| mainloop 缺/错位 | 缺 `ForceGoto`、`DynamicMapping`、`Segmentize/InternalStorage` 的正确位置；`oppool2` 提前；`RestrictLocal/DeadCode/Restructure/InferTypes` 在 oppool2 后；`ConditionalExe` 过早 | CFG、local-map、type-recovery、conditional-execution 输入状态不同 |
| merge/final 阶段 | 正确位置的 `AssignHigh`、`DominantCopy`、`CopyMarker` 和第一处 `DynamicSymbols` 缺；`NormalizeBranches` 错入；`MergeType` 提前一次；`PrototypeWarnings` 与 `FinalStructure` 逆序 | High identity 不完整、merge trim/marker 无输入、默认 root 行为与 oracle 不同、诊断次序改变 |
| pool 内容 | `simplifypool` 多 2 条 local Rule；`cleanup` 多 1 条；architecture `extra_pool_rules` 接口缺失 | registration ordinal、opcode transition 轨迹及最终 IR 可变 |
| local action | `ActionInferParams` 插在 Heritage 后、ConstantPtr 前，oracle universal 没有此 leaf | 主管线存在无 oracle 对应的 phase mutation |

### 6.3 token/name identity 差异

这些不是 cosmetic：Action path lookup、debug trace、fixture node identity 和重复名歧义都观察 name。

- root：`decompile` vs oracle `universal`。
- `funclinkoutonly` vs `funclink_outonly`。
- `unjustifiedparams` vs `unjustparams`。
- `restructureVarnode` vs `restructure_varnode`。
- `conditionalconst` vs `condconst`。
- `mappedlocalsync` vs `mapped_local_sync`。
- merge-family 中还要逐构造器核 `merge_required/merge_adjacent/merge_multientry/merge_type` 与 oracle 的 `mergerequired/mergeadjacent/mergemultientry/mergetype`，禁止 fixture 先做字符串归一化来掩盖差异。

oracle 的重复名本身也必须保留：`Unreachable` 两次、raw `DirectWrite` 四次（default decompile 保留 A 两次）、`DeadCode` 两次、`DynamicSymbols` 两次。`ActionGroup` 的 name lookup 对重复名会返回歧义/NULL（`action.cc:456-478`），但执行次数和顺序不受影响。

## 7. 27 个 Heritage 前 flatten leaf 的决定性分类

这里的“死运行”指当前新建 Funcdata/当前前置状态下，apply 确定返回零且无目标突变；“条件提前”表示 guard 或 IR 形状满足时会在错误阶段突变。不能把当前样本没命中当成安全。

| helper ordinal | Rust leaf（builder line） | 分类 | 完整函数体核对后的决定性结果 |
|---:|---|---|---|
| 1 | DefaultParams (`coreaction.rs:9516`) | 正确前期 leaf 的重复；当前通常死 | root 已先跑一次；随后 FuncLink 已给 call model，第二次一般无剩余 no-model call |
| 2 | PrototypeTypes (`:9517`) | 确定错序且双跑 | 应在 ExtraPop 后、FuncLink 前；可改 RETURN input，并建立 function active output |
| 3 | FuncLinkOutOnly (`:9518`) | 禁止 group；条件提前 | `noproto` 不在 decompile；有 CALL 时可 unset/rebuild output 与 active output |
| 4 | VarnodeProps (`:9525`) | 重复；条件提前 | pass=0 会挡住部分 live/NZ 分支，但 readonly/volatile 属性仍可在 Heritage 前写入 |
| 5 | ParamDouble (`:9526`) | 当前实现确定死 | 只扫描/改局部计数后丢弃，没有持久突变 |
| 6 | Segmentize (`:9527`) | 当前实现确定死 | 只扫描/局部计数，未执行 oracle segment transform |
| 7 | InternalStorage (`:9528`) | 当前实现确定死 | 只扫描/局部计数，未写 fd |
| 8 | DirectWrite (`:9529`) | 条件提前，生产常可达 | SSA 前清/重算 `DIRECT_WRITE` 并传播；constructor 的 bool identity 也丢失 |
| 9 | ActiveParam (`:9530`) | 条件提前 | FuncLink 可先建立 active-input trials；此处可置零 call 输入、derive/finish/clear trials |
| 10 | ReturnRecovery (`:9531`) | 条件提前 | 未锁 output 且有 RETURN 时，可建/seed active output、合成 Varnode 和 RETURN input、提前 finalize |
| 11 | NonzeroMask (`:9532`) | 提前突变 | 在 SSA/Spacebase 前对整图写 nz-mask 状态 |
| 12 | InferTypes (`:9533`) | fresh Funcdata 确定死；外部预置时条件提前 | `TYPE_RECOVERY_START` 尚未由后面的 StartTypes 设置，`coreaction.rs:3805-3807` 立即返回 |
| 13 | MultiCse (`:9536`) | 条件提前 | 若已有等价表达式，会 total-replace 并 destroy op；位置应在 stackstall 内、Heritage 后 |
| 14 | ShadowVar (`:9537`) | fresh 通常死；条件提前 | 需要 block 首已有重复 MULTIEQUAL；满足时把后一个 MULTIEQUAL 改成 COPY、缩减输入并重接到前一个 output，不删除 op |
| 15 | Deindirect (`:9538`) | 条件提前 | 已有 callspec/CALLIND 且 COPY 链解析到 symbol/external 时，会改 entry/opcode |
| 16 | UnjustifiedParams (`:9545`) | 条件提前，生产常可达 | unlocked input + used INPUT 会加参数；生产 inject 路径已可预标 INPUT |
| 17 | StartTypes (`:9546`) | fresh 状态确定突变 | 提前置 type-recovery-start，破坏 oracle“首轮类型关闭，fullloop 尾触发下一轮”的边界 |
| 18 | ActiveReturn (`:9547`) | 条件提前 | 有 call active output 时会 derive/clear，早于 Heritage/return-use analysis |
| 19 | SwitchNorm (`:9551`) | 条件提前 | 有 BRANCHIND/jumptable 时原地 recovery；oracle 位于 fullloop 尾 |
| 20 | AssignHigh (`:9558`) | **确定且致命的提前相变** | 无条件置一次性 `HIGHLEVEL_ON`；当时已有 Varnode 才获得 singleton High。以后新 Varnode 不 attach High，后续正确 `set_high_level` 永久 early-return，见 `funcdata.rs:513-536` |
| 21 | HideShadow (`:9559`) | fresh 通常死；条件提前 | 刚 AssignHigh 后每个 High 是 singleton；只有已有共享 High 时才可突变 |
| 22 | DominantCopy (`:9560`) | 当前实现确定死 | fresh `Merge::new` 的 `copy_trims` 为空，没有先前 merge state |
| 23 | CopyMarker (`:9561`) | fresh 通常死；条件提前 | 需要 COPY 两端已有共享 High；singleton AssignHigh 后通常不成立 |
| 24 | OutputPrototype (`:9562`) | 条件提前且 lock 语义缺失 | void + RETURN slot 时提前固定返回；当前 Rust 未检查 `output_type_locked`，可覆盖 locked-void |
| 25 | InputPrototype (`:9563`) | 条件提前，生产常可达 | unlocked + used INPUT 会提前填 parameters；后面正确阶段因 non-empty 不再修正 |
| 26 | SetCasts (`:9564`) | 条件提前 | 在 singleton/undefined High 上按不稳定类型插 CAST；随后正确位置又跑 |
| 27 | PrototypeWarnings (`:9565`) | 条件提前的可见输出 | 不改 Funcdata，但会提前向 stderr 发诊断；输出顺序是可观察语义 |

至少四项是当前实现的确定 no-op（ParamDouble、Segmentize、InternalStorage、DominantCopy）；另有 fresh-state 通常被 guard/形状挡住的 `InferTypes/ShadowVar/HideShadow/CopyMarker`。其余不能称作“无害预热”：多项会提前改 IR、flags、prototype 或 stderr。最危险的是 `StartTypes` 与 `AssignHigh`，前者遮蔽固定点计数缺陷，后者产生永久不完整的 High 集。

## 8. 生产可达性

锁定 oracle 的主管线不是测试 helper：`Architecture::buildAction` 先 `parseExtraRules`，再 `universalAction(this) → resetDefaults()`（`architecture.cc:582-591`）；`DecompileAt::rawAction` 在 `!fd->isProcStarted()` 时对 current root 严格调用 `reset(*fd) → perform(*fd)`，完成后只有 current name 为 `decompile` 才调用 C printer，见 `ghidra_process.cc:293-331`。同一已开始的 `Funcdata` 会跳过第二次 action 执行。

当前直接消费者已统一走 root executor：

- `src/bin/rugra.rs:257-261`。
- `examples/decompile_demo.rs:84-88,167-171`、`httpd_decompile.rs:268-272`、`curl_decompile.rs:486-490`、`debug_cfg.rs:97-101`、`debug_my_fwrite.rs:226-230`、`rugra_decompile_func.rs:244-248`、`getstr_stage_snapshot.rs:529-535`。
- 共同模式是 `ActionDatabase::new → set_default_actions → perform_action("decompile", fd)`。
- 只有 `src/funcdata.rs:10931-10935` 的测试路径调用 `apply_all`；未发现生产调用 `get_action/register/current_group`。

因此 flatten、错序和 nested repeat 都在真实主管线可达，不是 dormant builder。另一方面，缺失的 group clone/current-root API 没有消费者覆盖，现有单一 `decompile` 路径不能证明 alternate root 等价。

## 9. PIPE-0000 executor 独立 cross-review

这一节只审当前容器执行器，不要求 PIPE-0000 同时建完整 tree。当前可接受的进展是：`perform_action` 确实执行 `reset → fresh ActionState → perform`（`src/action.rs:786-802`）；Group 已有 per-child state、partial cursor 和 pending count。本次冻结版还修复了 Group reset/internal restart 的 cursor 时机：`ActionGroup::reset` 不再移动 iterator，restart 重置 children 后以 `STATUS_START` 显式准备下一次 apply。该局部项不再是 REJECT；仍有以下 **REJECT** 项，故整体只能记 `PARTIAL_MATCH`。

### 9.1 `Action::perform` 状态机

- `src/action.rs:95-149` 已在 `STATUS_ACTIONBREAK` 令 `apply_now=false`，这点符合 oracle “resume 时不重新 apply”。但没有实现 start/action/tmp breakpoints、warning-given 和 debug trace 的状态转移；不能声称完整 `action.cc:298-362`。
- Rust 把 positive `apply()` return 适配进 `state.count`（`src/action.rs:117-129`），同时又提供 `take_count_delta`。oracle 的 contract 是 apply 返回控制码而 derived object 增继承 count；双通道要求每个 leaf 精确选择，否则会漏计或双计。
- `ActionState.flags != 0` 时优先使用 add 时快照，等于 0 才动态读 `get_flags`（`src/action.rs:133-140`）。当前只有少数 leaf override flags，因此大部分 oracle once/repeat 语义根本没有进入 state。
- Rugra `perform_action` 每次无条件 reset/perform（`src/action.rs:786-802`），没有 oracle `DecompileAt::rawAction` 的 `!isProcStarted()` supervisor guard（`ghidra_process.cc:305-311`）。对同一 fd 再调用时，冻结版 `ActionStart` 会进入下述 `PROCESSING_STARTED` panic，而 oracle supervisor 跳过第二次执行。

### 9.2 leaf count contract：确定断裂

`Action::take_count_delta` 默认返回 0（`src/action.rs:82-85`），`src/coreaction.rs` 当前只有容器而非下列 leaves 提供 count bridge。典型确定差异：

- `ActionStartTypes` 在 `coreaction.rs:8246-8249` 增加自己的 `self.count`、返回 0，但 executor 永远看不到 delta。oracle `coreaction.hh:82-84` 依靠该 count 强迫 fullloop 再跑。
- `ActionDoNothing` 每次最多 splice 一个普通空块（`coreaction.rs:1988-2055`）却返回 0，且没有 `repeatapply` flag override；oracle leaf 自身 repeat 直到耗尽。
- `VarnodeProps`、`ConstantPtr`、`MultiCse`、`ShadowVar`、`Deindirect`、`ActiveReturn`、`UnjustifiedParams`、`SwitchNorm`、`HideShadow` 等均存在“突变但返回 0/无 delta”路径，会使 enclosing fixed point 提前停止。
- `SetCasts`、`ReturnRecovery` 等把 N 次内部 mutation 压成一个 positive return；可能足以触发收敛，但精确 count、stats 与 breakpoint 时机不等价。

这不是未来风险：`fullloop` 和 `mainloop` 实际都以 `RULE_REPEATAPPLY` 构造（`action.rs:868,887`），尽管相邻旧注释仍声称未启用。任何漏报或常报 count 都会立即改变生产执行次数。

### 9.3 leaf flags 与 reset

`coreaction.hh` 中精确有 28 个 nonzero-flag leaves：27 个 `onceperfunc` 加 `ActionDoNothing(repeatapply)`。Rust 当前只有五个 `get_flags` override（`AssignHigh`、`DominantCopy`、`CopyMarker`、`MarkIndirectOnly`、`MapGlobals`，位于 `coreaction.rs:8322,8359,8394,8497,8570`）。其余 23 个缺口是：

```text
LaneDivide(once), SetCasts(once),
MergeRequired(once), MergeAdjacent(once), MergeCopy(once),
MergeMultiEntry(once), MergeType(once), MarkExplicit(once), MarkImplied(once),
NameVars(once), DoNothing(repeat), NormalizeSetup(once), PrototypeTypes(once),
DefaultParams(once), ExtraPopSetup(once), FuncLink(once), FuncLinkOutOnly(once),
InputPrototype(once), OutputPrototype(once), HideShadow(once),
DynamicSymbols(once), PrototypeWarnings(once),
InternalStorage(once)
```

此外 oracle `ActionInferTypes::reset` 必须把 per-function `localcount=0`（`coreaction.hh:974-976`）；Rust `coreaction.rs:3800-3904` 没有 reset override。CLI 每函数 new DB 只能偶然遮蔽，DB 重用、restart 或 `apply_all` 会泄漏 7-pass 上限。

### 9.4 Group、Pool 与 Restart

- Group：`src/action.rs:263-304` 的完成 child 累加、partial 不推进、reset 全 children 已接近 oracle。冻结版 `reset` 保留 protected iterator，与 `action.cc:408-416` 一致；下一次 `perform` 通过 `prepare_apply(STATUS_START)` 在 apply 入口把 iterator 置回起点，对应 `action.cc:511-512`。原先的 reset/cursor 差异已闭合；但 child leaf 的 count/flags 缺失仍使容器无法在真实树上闭合。
- Group breakpoint：Rust container 没有 oracle `checkActionBreak()` 字段/调用，因此 `action.cc:517-520` 的“产生变化的 child 完成后先推进 iterator，再以 partial 返回”当前并未实现；这不是仅缺测试。
- Pool ordered iterator：Rust 对 `fd.obank.alivelist.clone()` 快照（`src/action.rs:463`），oracle 使用 `PcodeOpTree`。新 op、dead op 删除及 seq order 不等价。
- Pool opcode transition：Rust 在旧 opcode 的整张 `rule_idxs` 全跑完后才检查 opcode（`src/action.rs:475-497`）；oracle 每条 Rule 后立即检查并把新 opcode 的 `rule_index=0`。旧规则可错误作用在已变 opcode 的 op；变化后再变回原 opcode还会被完全藏掉。
- Pool reset：oracle reset 每个 Rule 的 per-function state但保留 stats，stats 只由 resetStats 清；Rust Rule trait没有 reset/disable/tests/applies/breakpoint，`ActionPool::reset` 反而清 `total/rule_hits`（`src/action.rs:518-521`）。
- Restart：Rust `ActionRestartGroup::apply` 在 pending 时以 `group.reset(fd)` 重置 children，然后显式 `prepare_apply(STATUS_START)`（`src/action.rs:348-381`）；后者已修复 internal restart 后嵌入 Group iterator 留在 end 的旧差异，对应 oracle `action.cc:576-580`。但它仍明写 `clearAnalysis` 未建模，而 oracle 在 children reset 前必定调用 `Architecture::clearAnalysis(&data)`（`action.cc:574`）。`Funcdata::clear` 本身也只清部分 banks（`funcdata.rs:4494-4506`），没有完整 oracle flags/calls/jumptable/proto 清理。冻结版 `ActionStart` 已真实调用 `start_processing`，下一轮会因 `PROCESSING_STARTED` 仍置位而 panic（`funcdata.rs:5718-5724`）。

### 9.5 收敛/不收敛矩阵

| 缺陷 | 方向 | 确定触发 |
|---|---|---|
| mutation 不进 count | 提前停止 | pool/stackstall/mainloop/fullloop 看不到 child 变化 |
| StartTypes delta 丢失 | phase 少一轮 | 修掉 flatten 后，首轮 InferTypes 因 type recovery 未开始而跳过；StartTypes 不触发第二轮 |
| DoNothing 无 leaf repeat/count | 剩余空块 | 一次只删一个 block，N>1 时无法耗尽 |
| non-idempotent action 常报 positive | 过度重复或无限循环 | 两层真实 repeat group 会持续重跑；旧注释已承认此类症状但未锁定责任 action |
| InferTypes localcount 不 reset | 跨函数提前停止 | 同一 DB 分析第 2 个函数或 restart |
| restart 不 clearAnalysis | panic/旧 IR 上重复 | 任意正常 restart_pending，第二轮 Start 发现 PROCESSING_STARTED |
| pool 延迟 opcode dispatch | 错规则、漏新规则 | 任一 Rule 改 opcode；新 opcode rules 不立即执行 |
| pool 快照 + mutation 返回 0 | 新 op 永不见 | 当前 pass 新建 op，而外层 count 没增长 |

## 10. 最小原子修复 DAG

```text
T0 locked tree/trace fixture + read-only snapshot API
 │
 ├── T1 Action identity/state foundation
 │    ├─ basegroup + exact runtime name + constructor args
 │    ├─ one authoritative count carrier shared by base/derived apply
 │    ├─ exact leaf flags + reset/resetStats split
 │    └─ break/warning/status transitions
 │
 ├── T2 Rule/Pool foundation
 │    ├─ Rule reset/disabled/tests/applies/breakpoint state
 │    ├─ PcodeOpTree-equivalent ordered/resumable iterator
 │    └─ after-each-rule opcode dispatch + dead-op removal
 │
 └── T3 clean restart foundation
      └─ Funcdata/Architecture clearAnalysis observable-state parity

T1 + T2 + T3
   ↓
T4 build one raw universal tree exactly once
   ├─ preserve all deliberate duplicate nodes and DirectWrite(bool) args
   ├─ exact stackstall/mainloop/fullloop/pool nesting
   └─ architecture extra_pool_rules at exact suffix
   ↓
T5 buildDefaultGroups + clone/filter derived roots
   └─ registration key separate from root Action name
   ↓
T6 delete flat helper insertion and Rugra-only pool/action nodes from oracle root
   ↓
T7 locked per-function phase fixtures + alternate-root fixtures
   ↓
T8 end-to-end 12.0.4 oracle text/IR comparison
```

原子边界：

1. 先加只读 snapshot/fixture，不改运行行为。
2. count/flags/reset 是一个可闭合 executor 单元；在它完成前不要只搬树，因为新 nested fixed points 会放大错误。
3. Pool 是独立单元，必须同时修 iterator、每-rule opcode check 与 Rule reset；只改其中一项会产生新的顺序假阳性。
4. restart 必须以完整 clearAnalysis observable fingerprint 为一个单元；仅清几个 flags 会在旧 IR 上继续跑。
5. tree 单元必须是“构造 raw universal + group filter + exact identity/order”整体。不能只删除 flatten helper，否则会直接丢功能；也不能把 27 leaf 简单移入某个 group 而不恢复参数和重复实例。
6. Rugra-only `InferParams`、pool extra rules 若业务上仍需保留，应进入显式非-oracle mode；默认 `decompile` fixture 必须拒绝它们。

## 11. Locked executable fixture schema

### 11.1 静态 tree fixture：`rugra.pipeline-tree.v1`

两侧都必须从真实构造对象产生 JSON，不允许由名字表手写 expected，也不允许 sort/dedup：

```json
{
  "schema": "rugra.pipeline-tree.v1",
  "oracle": {
    "tag": "Ghidra_12.0.4_build",
    "commit": "e40ed13014025f82488b1f8f7bca566894ac376b"
  },
  "fixture": {
    "architecture_id": "x86:LE:64:default",
    "compiler_spec": "gcc",
    "analysis_options_sha256": "...",
    "input_sha256": "...",
    "root_key": "decompile"
  },
  "root": {
    "node_id": "derived:0:restart_group",
    "derived_path": "0",
    "derived_ordinal": 0,
    "universal_path": "0",
    "universal_ordinal": 0,
    "kind": "restart_group",
    "name": "universal",
    "base_group": null,
    "flags": ["onceperfunc"],
    "args": {"max_restarts": 1},
    "children": []
  },
  "pools": {
    "root/fullloop/mainloop/stackstall/oppool1": {
      "rules": [
        {
          "ordinal": 0,
          "name": "earlyremoval",
          "base_group": "deadcode",
          "opcodes": ["..."],
          "args": {},
          "source": "static"
        }
      ]
    }
  }
}
```

要求：

- 所有 ordinal 都是 **0-based sibling ordinal**。`node_id` 使用 clone 后逐级 sibling ordinal 与 kind（例如 decompile clone 中 stackstall 是 `derived:0/6/0/17:action_group`）作为主 identity；名字重复合法且不可归一化。每个 node 同时记录 `derived_path/derived_ordinal` 和来源 `universal_path/universal_ordinal`，既区分同父重复节点，又能回链 raw universal；该 stackstall 的 raw 路径是 `0/8/0/18`。
- 每个 node 必须记录 kind、name、base-group、完整 flags、constructor args。`DirectWrite(true/false)`、stackspace/conf 等不可只留类名。
- 每个 pool 的 rules 必须放在同一个连续 `rules[]` registration stream；静态 Rule 后直接接 architecture extras。每条保留连续 ordinal、opcode vector 顺序、constructor `args`（例如 `RulePtrFlow(..., conf)`）和 `source: static|architecture_extra`，禁止把 extras 拆成旁路数组。
- Ghidra producer 的可执行调用链是 `universalAction(conf) → resetDefaults() → getCurrent()`；`resetDefaults()` 内部已经调用 private `buildDefaultGroups()` 和 `setCurrent("decompile")`，不得重复调用。Rust producer 应调用真实 `set_default_actions`。两侧 test-only `snapshot()` 比解析 debug 字符串可靠，因为 `Action::print` 不包含完整 group/args。
- comparator 先报第一个结构差异，再输出完整 edit script；数组逐项比较，不做集合比较。

### 11.2 runtime trace fixture：`rugra.action-trace.v1`

```json
{
  "schema": "rugra.action-trace.v1",
  "oracle": {
    "tag": "Ghidra_12.0.4_build",
    "commit": "e40ed13014025f82488b1f8f7bca566894ac376b"
  },
  "case_id": "repeat-leaf-1-1-0",
  "fixture": {
    "architecture_id": "x86:LE:64:default",
    "compiler_spec": "gcc",
    "analysis_options_sha256": "...",
    "input_sha256": "..."
  },
  "input": {"initial_state": "..."},
  "events": [
    {
      "seq": 0,
      "node_id": "derived:0/6/0/17:action_group",
      "derived_path": "0/6/0/17",
      "universal_path": "0/8/0/18",
      "event": "reset|perform_enter|apply_enter|apply_exit|perform_exit|restart_clear",
      "status_before": 1,
      "status_after": 4,
      "lcount_before": 0,
      "lcount_after": 0,
      "count_before": 0,
      "count_after": 1,
      "count_tests": 1,
      "count_apply": 1,
      "return": 0,
      "ir_sha256": "...",
      "restart_pending": false,
      "op_seqnum": null,
      "opcode": null,
      "rule_index": null
    }
  ],
  "final": {
    "ir_sha256": "...",
    "cfg_sha256": "...",
    "flags_sha256": "...",
    "high_identity_sha256": "...",
    "prototype_sha256": "...",
    "stderr_sha256": "..."
  }
}
```

最小 case 集：

1. repeat leaf 的变化序列 `[1,1,0]`，核 count/tests/applies。
2. once-per-func 完成后第二次 perform 返回 0；reset 后可重新执行。
3. Group child partial `-1` 后从同 child/iterator 继续，且 count 只在完整完成后向 parent 累加。
4. action-break resume 不重新调用 apply，并预增正确 child iterator。
5. restart pending、`max=1`：初跑 + 一次 clearAnalysis 后重跑；第二次 pending 超限；核完整清除 fingerprint。
6. pool Rule A 把 opcode X 改 Y：同一 op 立刻从 Y 的 rule ordinal 0 开始；X 的剩余 Rule 不执行。
7. pool dead-op、新建 op、PcodeOpTree seq order 与 partial resume。
8. Rule reset 清 per-function state但保留 stats；resetStats 单独清 stats。
9. phase fixture：首轮 InferTypes 观察 `started=false`；StartTypes 增 count；外层 fullloop 第二轮 InferTypes 观察 `true`。
10. DoNothing 有 N>1 个可删 block，leaf 自身 repeat 恰好耗尽。
11. derived-root tree：同一个 raw universal 分别 clone decompile/normalize/jumptable，核过滤不改 surviving ordinal 相对顺序。

完整 event arrays 的数组顺序和每个标量必须 exact match。若做 byte-for-byte 文件比较，两侧必须用 RFC 8785 JSON Canonicalization Scheme；否则 comparator 应 parse JSON 后逐字段比较，不能让 object key 顺序或空白制造假差异。只允许规范化已证明无语义的临时地址，禁止删除 node identity/path/order/count/status/rule index/constructor identity。

## 12. 最终判定

- 树结构：`MISMATCH`。首差异在 root identity 与第 4 个有效 child；flatten、错序、漏项、错误重复、extra nodes、group filtering 和 pool contents 均已确定。
- 主管线：差异可达。生产消费者已执行 `perform_action("decompile")`。
- executor：`PARTIAL_MATCH`。Group 的基本 cursor/count 适配、reset 保留 iterator、internal restart 的 `STATUS_START` 准备与 root reset→perform 已接入，但 leaf count/flags/reset、Pool、restart clearAnalysis、break/warning 状态未闭合。
- 运行 oracle：`UNTESTED/NO_ORACLE`。本报告没有把 Rust 自测、11.3.2 golden 或源码形似当作 Ghidra 12.0.4 行为 MATCH。
- 路线图：本报告不修改路线图；依据这些差异，该模块不得升 L3。

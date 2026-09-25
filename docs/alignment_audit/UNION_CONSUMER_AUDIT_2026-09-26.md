# UNIONRESOLVE-CONSUMER-SCOPE-0001 只读审计终报（2026-09-26, ora-5 UNIONSCOPE 车道）

> oracle = Ghidra 12.0.4 (e40ed130)。审计人：独立 oracle 车道（机制 C 同款读法，不采信转述）。
> 消费点总数 116：35 aligned / 77 divergent / 4 other。派单序（活语料影响）：A > B > C > D/E > F > G > H。

**审计口径**：oracle `varnode.cc:626-672` 四个 facing 方法（`getTypeDefFacing`/`getTypeReadFacing`/`getHighTypeDefFacing`/`getHighTypeReadFacing` = `needsResolution() ? findResolve(op,slot) : this`）+ `resolveInFlow/findResolve/findCompatibleResolve/resolveTruncation` 虚分派（type.cc）。Rugra 侧三形态：①fd-aware 孪生（unionresolve.rs:1898-1970，consult `fd.union_map`）②退化方法（varnode.rs:1538-1627，consult 恒取 map-miss 臂 `return this`）③裸 `v_type/get_type()`。**判定标准**：①+slot 正确=aligned；②③在 resolution-needing 型可达处=divergent（map-hit 臂缺失；Array/Struct 单字段/PartialUnion 连 map-miss 臂都不同——miss 返回 element/field[0]/stripped 而非 this）。needsResolution=true 的型：union、ptr-to-union（type.cc:1051）、size-1 数组（cc:1342）、单字段满幅 struct（cc:1571/1877）、partial-union（cc:2427）。

**语料活性**：curl golden 含活 union（`anon_union_16_3_e2f18bb4_for_content` ×8，glob 初始化）——分歧**非潜伏**，print/setcasts 层已在活语料上运行。

## 一、消费面审计表

### printc.rs（33 处：29 divergent / 3 aligned-in-practice / 1 glue）

| 文件:行 | 判定 | oracle 对应 | 差异语义 | 修法 |
|---|---|---|---|---|
| printc.rs:1867 | divergent | printlanguage.cc:227 `pushVnExplicit→getHighTypeReadFacing(op)`（pushConstant 入口） | 常量 high 型 needsResolution 时 oracle 取 resolved field 的 metatype 选打印臂；退化形取 raw union → 落 default cast 臂 | 换 snapshot-backed 孪生（见修法包 C） |
| printc.rs:2814+2815 | divergent | printc.cc:789 `isZextCast(outDefFacing,inRead)` | map-hit 时 oracle in/out 均为 resolved field 型→cast 判定变；退化形恒 raw | 同上 |
| printc.rs:2852+2853 | divergent | printc.cc:802 `isSextCast` | 同上（SEXT 族） | 同上 |
| printc.rs:2899 | divergent | printc.cc:848 `vn->getHighTypeReadFacing(op)`（opSubpiece 特印臂） | oracle 先 consult 再 `isPieceStructured()`；退化形对 union 恒 raw（union 本身 piece-structured，行为偶合，但 resolved-field-非复合型时 oracle 不进特印臂、Rugra 进） | 同上 |
| printc.rs:2992+2993 | divergent | printc.cc:872-873 `isSubpieceCast(outDef,inRead,off)` | 同 789 族 | 同上 |
| printc.rs:3095 | divergent | printc.cc:942 `in0->getHighTypeReadFacing(op)`（opPtrsub） | union 臂有 snapshot 补偿（3138 slot -1 ↔ cc:983），但 942 的 slot-0 map-hit 臂缺失：resolveUnion "cast still needed" 分支（coreaction.cc:2504-2506 return 0 不插 PTRSUB、map 条目残留）下 oracle 打印 resolved field 访问、Rugra 打印 `field_0x0` | 换 snapshot-backed 孪生；顺带核对 cc:981/985 throw 臂的 fail-closed 语义（现 `field_0x` 兜底=已登记的 printer 无 throw 通道让步，参照 MIRROR3-PRETTYFLUSH-FAILCLOSED-0001 类） |
| printc.rs:3538+3551 | divergent | printc.cc:451 `opTypeCast out getHighTypeDefFacing`（+379/381/403 checkAddressOfCast **整体未移植**，3540 注释自认） | cast 目标型为 resolved field 时 oracle 打印 field 型；退化形打印整个 union。checkAddressOfCast 缺失是伴生缺口（`&` 数组衰减形） | 换孪生 + 单独登记 checkAddressOfCast 移植票 |
| printc.rs:3641 | divergent | printc.cc:835 `opFloatInt2Float out getHighTypeDefFacing` | 同 451 族 | 同上 |
| printc.rs:8822 | divergent | printc.cc:451（emit_inline_expr CAST 内联孪生） | 同上（legacy 运输层） | 同上 |
| printc.rs:8878+8879 | divergent | printc.cc:872-873（内联孪生） | 同上 | 同上 |
| printc.rs:13185 | divergent | printc.cc:726 `opConstructor outvn->getTypeDefFacing()` | 构造器名取 resolved field 显示名 vs raw union 名 | 同上 |
| printc.rs:13492 | divergent | printc.cc:1246 `opNewOp outvn->getTypeDefFacing()` | `new T(...)` 的 T 同上 | 同上 |
| printc.rs:13583 | divergent | printc.cc:942（legacy op_ptrsub） | 与 3095 同构（snapshot 补偿在 13655） | 同上 |
| printc.rs:13925+13938 | divergent | printc.cc:451（legacy op_type_cast） | 与 3538 同构 | 同上 |
| printc.rs:17417+17418 | divergent | printc.cc:789（legacy op_int_zext） | 与 2814 同构 | 同上 |
| printc.rs:17455+17456 | divergent | printc.cc:802（legacy op_int_sext） | 与 2852 同构 | 同上 |
| printc.rs:17564 | divergent | printc.cc:848（legacy op_subpiece 特印臂） | 与 2899 同构（snapshot 补偿在 17634） | 同上 |
| printc.rs:17662+17663 | divergent | printc.cc:872-873（legacy） | 与 2992 同构 | 同上 |
| printc.rs:17926 | divergent | cast.cc:259 `isExtensionCastImplied outVn->getHighTypeReadFacing(readOp)` | out 与 other 的 metatype 匹配测试：oracle 比 resolved field 型（可异型→不隐藏 cast）、Rugra 比 raw（同 union→恒等→隐藏 cast） | 换 snapshot-backed 孪生（经 Package F 的 fd 化 local_extension_type） |
| printc.rs:17971 | divergent | cast.cc:289 `otherVn->getHighTypeReadFacing(readOp)` | 同上 | 同上 |
| printc.rs:1518 | aligned-in-practice | （Rugra 运输层门，oracle 对应=coreaction.cc castInput 插 CAST，已 fd-aware@5612/5750） | CALLIND slot-0 型被 TypeOpCallind::getInputLocal（typeop.cc:752-755）typeprop 钉死 `code *`→needsResolution 恒 false→退化形≡oracle。仅 locked-union-symbol 直喂 CALLIND 的构造输入可破 | 保持现状；若做 Package C 顺手换孪生零成本 |
| printc.rs:8746 | aligned-in-practice | （同上，inline_expr 门） | 同上 | 同上 |
| printc.rs:12988 | aligned-in-practice | （同上，op_callind 门） | 同上 | 同上 |
| printc.rs:12431 | glue | 无 oracle 对应（PRINTC-UNLINKED-REF-FAMILY 的 Rugra 兜底名发射） | v_type 优先+退化 high 兜底；oracle 无此路径 | 无需对齐；若 union 型未链接引用到达，命名行为无 oracle 可比 |

### coreaction.rs（41 处：29 aligned / 13 divergent——含 grep 漏计的零参形态）

**aligned 29 处**（fd-aware 孪生，slot 逐一核对通过）：5230/5239（Load getInputCast ↔ typeop.cc:444/446，slot -1 语义经 def-facing +1 slot）、5304/5306（Store ↔ cc:525/527，slot 1/2 ✓）、5372/5382（Copy ↔ cc:400/401，slot 0 ✓）、5439（TypeOp::getInputCast ↔ cc:301，slot ✓）、5612（castInput testStructOffset0 ↔ cc:2692，slot ✓）、5750（generic ↔ cc:301）、5840（Sless/Less ↔ cc:1029/1055/1081/1105，slot ✓）、5878（Zext/Sext ↔ cc:1137/1163）、5927（Right/Sright ↔ cc:1549/1591 slot 0 门 ✓）、5965（Div/Rem 族 ↔ cc:1644/1664/1684/1704）、6293/6304（tryResolutionAdjustment ↔ cc:2436/2441/2443 findCompatibleResolve，实参序 receiver-first 核对=一致）、6408/6419（resolveUnion ↔ cc:2499/2504，slot ✓，insertPtrsubZero+setUnionField(dt,ptrsub,-1) attach ✓、implied writeRes 比较 ✓）、6844/6847（castOutput ↔ cc:2556/2557 resolveInFlow(op,-1)+findResolve(op,-1)）、6825-6831（cc:2545-2548 force-parent setUnionField ✓）、6989（cc:2571/2579 refresh）、7348/7398（apply PTRADD/PTRSUB 巡检 ↔ cc:2742/2748，slot 0 ✓）、7889（typeprop ↔ cc:5083，inslot ✓，backtrack 前置副作用保序 ✓）、5772/5795/5808（castInput inherit/force ↔ cc:2695-2696/2713-2717）、6968/6971（castOutput force/inherit ↔ cc:2610-2613）。funcdata.rs get/set_union_field（↔ funcdata.cc:917-965，含 MULTIEQUAL 同 vn 复制臂+lock 语义）与 force_facing_type/inherit_resolution（↔ cc:974-1005）本体忠实。

| 文件:行 | 判定 | oracle 对应 | 差异语义 | 修法 |
|---|---|---|---|---|
| coreaction.rs:989 | divergent | coreaction.cc:1077 `isPointer vn->getTypeReadFacing(op)` | 常量指针推断头门：union-with-ptr-field resolved 后 oracle 视 TYPE_PTR→needexacthit=false；退化形视 union→走启发式门 | 换 `vn_type_read_facing`（fd 在域内） |
| coreaction.rs:1070 | divergent | coreaction.cc:1120 `outvn->getTypeDefFacing()` | INT_ADD 臂同上族 | 同上 |
| coreaction.rs:1081 | divergent | coreaction.cc:1122 `getIn(1-slot)->getTypeReadFacing(op)` | 对侧指针判定：resolved-ptr-field 时 oracle 判"另一基指针"→常量当偏移；退化形漏判 | 同上 |
| coreaction.rs:6079 | divergent | cast.cc:47 `markExplicitUnsigned vn->getHighTypeReadFacing(op)` | 常量 high 型 resolved 为 uint 族时 oracle 强制 unsigned 打印；退化形 union metatype→不强制 | 换 `vn_high_type_read_facing` |
| coreaction.rs:6097 | divergent | cast.cc:55 `firstvn->getHighTypeReadFacing(op)` | 对侧同上 | 同上 |
| coreaction.rs:6478 | divergent | typeop.cc:2147 `Subpiece getOutputToken in0 readFacing` | oracle 先 consult（slot 0 键）→对 **resolved field 型** findTruncation；Rugra 恒 raw union→对 union 以**人工 slot 1** find_truncation（键不同：typeprop 建的是 slot-1 条目）。两键命中集不同→field 为 struct 时 oracle 可下钻子字段、Rugra 落 def-facing | 换 fd-aware 孪生（fd 已入参） |
| coreaction.rs:6517 | divergent | typeop.cc:2155 `outvn->getHighTypeDefFacing()` | def-facing slot -1 map-hit 臂缺失 | 换 `vn_high_type_def_facing` |
| coreaction.rs:6643+6650 | divergent | typeop.cc:475/484 `TypeOpLoad::getOutputToken` | LOAD token 的地址 read-facing/输出 def-facing consult 缺失 | 同上两孪生 |
| coreaction.rs:6729 | divergent | typeop.cc:1521/1561/1611 `Int{Left,Right,Sright}::getOutputToken` | 移位族 token=in0 read-facing；map-hit 臂缺失 | 换 `vn_high_type_read_facing` |
| coreaction.rs:6772 | divergent | typeop.cc:2067 `TypeOpPiece::getOutputToken out getHighTypeDefFacing` | PIECE token 同族 | 换 `vn_high_type_def_facing` |
| coreaction.rs:7142 | divergent | typeop.cc:2325 `Ptrsub::getInputCast reqtype=getTypeReadFacing(op)` | **裸 v_type**（连 needsResolution 检查都无）；7124-7127 注释自认 residual（ACTION-INFERTYPES-DISPATCH-0001） | 换 `vn_type_read_facing`；注释随修更新 |
| coreaction.rs:7146 | divergent | typeop.cc:2326 `curtype=getHighTypeReadFacing(op)` | union-ptr 基座 map-hit→oracle curtype=field 指针→same_type/下钻一层判定变 | 换 `vn_high_type_read_facing` |

### ruleaction.rs（20 处：6 aligned / 14 divergent）

**aligned 6 处**：14200（RulePieceStructure ↔ cc:7678 `resolveInFlow(copyOp,-1)` ✓，伴 19348 inheritResolution ↔ cc:7673-7675 ✓）、15239（RulePtraddUndo ↔ cc:6915 slot 0 ✓）、15842（RulePtrsubUndo ↔ cc:7138 slot 0 ✓——该 consult 正是防 AddTree↔PtrsubUndo 重写乒乓的关键，注释链完整）、18186（AddTreeState ctor ↔ cc:6025 slot 透传 ✓）、19169（assignPropagatedType ↔ cc:6346 slot 0 ✓）、19354（RuleStructOffset0 ↔ cc:6691 slot 1 ✓）。

| 文件:行 | 判定 | oracle 对应 | 差异语义 | 修法 |
|---|---|---|---|---|
| ruleaction.rs:18995 | divergent | ruleaction.cc:6430 `buildDegenerate ptr`（cc 侧读 `ct` 缓存字段，其来源=cc:6025 consult） | 零参退化形 | 换 `vn_type_read_facing`（AddTreeState 持 self.data） |
| ruleaction.rs:~19000 (build_degenerate out) | divergent | ruleaction.cc:6430 `baseOp->getOut()->getTypeDefFacing()->getMetatype()!=TYPE_PTR` | **裸 v_type**；resolved-ptr-field 输出时 oracle 过门、Rugra 拒绝退化变换 | 换 `vn_type_def_facing` |
| ruleaction.rs:17952+17961 | divergent | ruleaction.cc:6548/6550 `verifyPreferredPointer` | preslot 探测双读零参退化 | 换孪生 |
| ruleaction.rs:17998+18027 | divergent | ruleaction.cc:6576/6588 `evaluatePointerExpression` | 对侧/后代指针探测同族 | 换孪生 |
| ruleaction.rs:18092 | divergent | ruleaction.cc:6645 `RulePtrArith::applyOp op->getIn(slot)->getTypeReadFacing(op)` | 指针算术转换门同族 | 换孪生 |
| ruleaction.rs:17811 | divergent | ruleaction.cc:6854 `RulePushPtr vni->getTypeReadFacing(op)` | push 变换的指针输入探测同族 | 换孪生 |
| ruleaction.rs:12763 | divergent | ruleaction.cc:7188 `RuleAddUnsigned constvn->getTypeReadFacing(op)` | 12760-63 注释称"returns the varnode's resolved base type"——**陈述错误**（零参形返回 raw）；resolved-uint 常量时 oracle 触发、Rugra 不触发 | 换孪生+修注释 |
| ruleaction.rs:12840 | divergent | ruleaction.cc:7256 `RuleSubRight op->getIn(0)->getTypeReadFacing(op)->isPieceStructured()` | 特印标记门：resolved field 为复合型时 oracle 标 SPECIAL_PRINT、Rugra 漏标→SUBPIECE 打印形变 | 换孪生 |
| ruleaction.rs:13159 | divergent | ruleaction.cc:7358 `RulePtrsubCharConstant sb->getTypeReadFacing(op)` | **裸 get_type** | 换孪生 |
| ruleaction.rs:13172 | divergent | ruleaction.cc:7366 `outvn->getTypeDefFacing()` | **裸 get_type** | 换 `vn_type_def_facing` |
| ruleaction.rs:13550/13558/13566 | divergent | ruleaction.cc:10937/10940/10943 `RuleExpandLoad rootPtr->getTypeReadFacing(defOp/op)` | **裸 get_type ×3**（含 defOp/op 双键分派语义丢失） | 换孪生（注意 10937 用 defOp、10940/43 用 op 两键） |
| ruleaction.rs:13598 | divergent | ruleaction.cc:10964 `outVn->getTypeDefFacing()->getMetatype()` | **裸 get_type** | 换 `vn_type_def_facing` |

### typeop.rs（8 处：全 divergent；3 活跃 / 4 仅测试 / 1 未接线）

| 文件:行 | 判定 | oracle 对应 | 差异语义 | 修法 |
|---|---|---|---|---|
| typeop.rs:113 | divergent（**活跃**，coreaction.rs:5518 调用） | typeop.cc:935/936/941 `TypeOpEqual::getInputCast`（==/!= 族） | 相等比较 cast：required/other/current 三读全退化；Less 族已 fd-aware（5840）而 Equal 族未——同构 oracle 行不对齐 | comparison_input_cast 加 fd 参+换孪生+改 5518 调用点 |
| typeop.rs:2509 | divergent（**活跃**，coreaction.rs:6590） | typeop.cc:2352 `Ptrsub::getOutputToken` | union-ptr 基座 map-hit→oracle downChain 走 field 指针、Rugra 走 union-ptr（downChain 穿 union 语义不同键） | get_output_token 加 fd 参+换孪生+改 6590 |
| typeop.rs:2357 | divergent（**活跃**，coreaction.rs:6605） | typeop.cc:2247 `Ptradd::getOutputToken` | token=in0 read-facing；同族 | 同上 |
| typeop.rs:747 | divergent（**未接线**：生产 token 分发对 COPY 落 default base 臂，oracle=TypeOpCopy::getOutputToken 覆盖） | typeop.cc:408 | **双重**：裸 v_type（非 high）+ 生产路径根本不路由此实现 | 修读为 high read-facing 孪生 + cast_output 分发加 COPY 臂路由 |
| typeop.rs:2367+2372 | divergent（仅测试调用） | typeop.cc:2255/2256 `Ptradd::getInputCast` | 生产走 coreaction.rs:7142/7146（同 divergent，见上）；此副本退化 | 与 7142/7146 修复合并：单一实现两处引用，或标 RUGRA-GLUE test-only |
| typeop.rs:2472+2477 | divergent（仅测试调用） | typeop.cc:2325/2326 `Ptrsub::getInputCast` | 同上 | 同上 |

### subflow.rs（10 处：全 divergent）

| 文件:行 | 判定 | oracle 对应 | 差异语义 | 修法 |
|---|---|---|---|---|
| subflow.rs:4803 | divergent | subflow.cc:2118 `backUpPointer tmpPointer->getTypeReadFacing(addOp)` | 分裂规则指针回溯门：resolved-ptr-field 时 oracle 过门回溯、Rugra 拒 | 换 `vn_type_read_facing`（SplitDatatype 持 data） |
| subflow.rs:4883 | divergent | subflow.cc:2157 `RootPointer::find pointer->getTypeReadFacing(op)` | 根指针定位同族 | 同上 |
| subflow.rs:5024 | divergent | subflow.cc:2914 `getValueDatatype loadStore->getIn(1)->getTypeReadFacing(loadStore)` | 同族 | 同上 |
| subflow.rs:5385+5386 | divergent | subflow.cc:2950/2951 `RuleSplitCopy::applyOp in/out facing`（oracle 在调用方读取后**作参数**传入 splitCopy；Rugra 结构上内联重读） | 双退化+参数传递结构差；resolved-struct-field 时 oracle 过 metatype 门分裂、Rugra 拒 | 换孪生（结构差可后置：语义等价时保留内联） |
| subflow.rs:5929 | divergent | subflow.cc:2772 `splitLoad outVn->getTypeDefFacing()` | def-facing 同族 | 换 `vn_type_def_facing` |
| subflow.rs:6053+6072 | divergent | subflow.cc:2822/2828 `splitStore inVn->getTypeReadFacing(storeOp)`（含去 LOAD 重试臂） | slot 2 双读同族 | 换 `vn_type_read_facing` |
| subflow.rs:6390+6391 | divergent | subflow.cc:2950/2951（applyOp metatype 门） | 零参双退化；union→resolved-struct-field 过门差 | 换孪生 |

### type_system/cast.rs（3 处：全 divergent）

| 文件:行 | 判定 | oracle 对应 | 差异语义 | 修法 |
|---|---|---|---|---|
| cast.rs:35 | divergent | cast.cc:397 `arithmeticOutputStandard in0 getHighTypeReadFacing(op)` | 算术族输出 token 的 typeOrder 排序键输入退化：resolved field 参与排序时 oracle 选 field 型、Rugra 选 raw union（typeOrder 不同→token 选择变） | 加 fd 参+换孪生；调用点 coreaction.rs:6630（fd 在域）与 printc.rs:17898（需 Package C 的 snapshot 通道） |
| cast.rs:50 | divergent | cast.cc:403（后续输入循环） | 同上（**排序键**类决定性语义） | 同上 |
| cast.rs:155 | divergent | cast.cc:143 `localExtensionType vn->getHighTypeReadFacing(op)` | oracle metatype 分派表含 PARTIALSTRUCT/PARTIALUNION——partial-union 是**预期输入**；resolved 为 INT 时 oracle=SIGNED、Rugra raw partial-union=UNSIGNED→isExtensionCastImplied 走向变 | 同上 |

### 邻接域（票外同类别，5 处，登记备查）

constseq.rs:1414/1702、varmap.rs:1897、datatype.rs:3011（TypeStruct::scoreSingleComponent 的 LOAD/STORE 指针臂 ↔ type.cc consult——**此一处直接污染 resolve_in_flow 的 Array/Struct 臂的 field 选择**，优先级高于其字面位置）、funcdata.rs:4585（opUndoPtradd 偏移改型）。全部退化形，同修法。

## 二、unionresolve.rs 本体 + 头注时效

| 项 | 判定 | 说明 |
|---|---|---|
| 头注（:20-27）"wiring gap…no pipeline producer invokes this scorer yet" | **过时（票注证实）** | 已有 4 个生产者：coreaction.rs:6408（resolveUnion）/6844（castOutput）/7889（typeprop）、ruleaction.rs:14200（RulePieceStructure），均经 `resolve_in_flow`→`ScoreUnionFields::new`。头注与本文件 ：1523+ "Pipeline wiring" 节自相矛盾。**修法**：改写为列 4 生产者+标注 varnode.rs 退化形与 fd-aware 孪生的分工现状 |
| `ResolvedUnion::with_field`（:82-114） | **divergent（本体）** | `let _ = typegrp;`——工厂被忽略，cc:51-55 的 `typegrp.getTypePointer` **interning 未做**，指针臂 `Arc::new(Datatype::Pointer(...))` 造非规范 Arc。:76-81 注释称"Canonical interning lands with the pipeline wiring"——wiring 已落地而 interning 未随之修，**注释掩盖未修分歧**。后果：resolve 型非规范→`castStandard` 的指针恒等短路（cast.cc:303）失效→多余 cast；`Arc::ptr_eq` 恒等比较族失配。**修法**：with_field 改收 `&mut TypeFactory`（或经 RwLock write guard），指针臂走 `get_type_pointer`；force_facing_type（funcdata.rs:8207，现持读 guard）需重构为取写 guard |
| 评分器主体（score_trial_down/up 表、compute_best_index、new_for_subpiece/implied_trunc、run_passes） | aligned | 抽验 INT_ADD downChain（cc:429-438 常量偏移 drill/array elSize/非数组 +5）、STORE slot-1/2、LOAD-up 指针包裹（wordsize 1）、CBRANCH/BRANCHIND/CALL 族、computeBestIndex 严格 `>` 首胜 tie-break（cc:950-956）、subpiece swap+`>1` 门（cc:1069-1070）——逐一吻合 |
| `resolve_in_flow`/`find_resolve`/`find_compatible_resolve`/`union_resolve_truncation` | aligned | 各虚分派臂（含 PartialUnion 容器走、`newType==curType→null`、findCompatibleResolve 实参序 receiver-first、subpiece 人工 slot newoff=0）核对一致 |
| `setImpliedField`（coreaction.rs resolve_union 内 cc:2519 臂） | **divergent（登记在案的功能缺口）** | 注释自认"varnode.rs 无 has_implied_field…no current Rugra print path reads it"——implied-union-field 打印路径（printlanguage.cc:527 pushImpliedField）端到端缺失。**单独立票**（Package H） |
| datatype.rs:5157/5195 方法形 `resolve_in_flow`/`find_resolve` | 死码孪生（仅测试引用） | 退化语义（无 fd 缓存）；与 unionresolve.rs 自由函数重名易误用。**修法**：标 deprecated 或删除 |

## 三、统计与修复包

**判定计数（Rugra 侧 oracle 映射消费点共 116）**：

| 文件 | aligned | divergent | 其他 |
|---|---|---|---|
| printc.rs | 0 | **29** | 3 aligned-in-practice（CALLIND code\* 钉死）+ 1 glue |
| coreaction.rs | **29** | **13** | — |
| ruleaction.rs | **6** | **14** | — |
| typeop.rs | 0 | **8**（3 活跃/4 仅测试/1 未接线） | — |
| subflow.rs | 0 | **10** | — |
| type_system/cast.rs | 0 | **3** | — |
| **合计** | **35** | **77** | 4 |

票据 "~70 处" 与实测 77 基本吻合（票据 grep 口径漏计零参/裸读形态：coreaction 989/1081、ruleaction 裸读族、subflow 5385/6390）；票据分布 printc 33/coreaction 12/ruleaction 11/typeop 7/subflow 5/cast 3 中 coreaction 12 与实测 13 仅差 989，printc 33=29+4，其余为口径差。**以本表为准**。

**divergent 按文件聚合修复包（预估）**：

| 包 | 域 | 内容 | 预估 | 门禁 |
|---|---|---|---|---|
| A | coreaction.rs | 13 处换既有 fd-aware 孪生（fd 全在域内，机械替换；7142 裸读+注释同步） | 0.5 天 | 机制 B 差分（coreaction 白名单）：curl/httpd 镜 + canon 不回退 |
| B | typeop.rs | 3 活跃处加 fd 参（113/2357/2509）+调用点（5518/6590/6605）；747 修裸读+**接线 COPY token 臂**（独立保真缺口）；4 测试处合并到单一实现 | 0.5-1 天 | 同上 |
| C | printc.rs | 新增 4 个 snapshot-backed facing helper（consult `self.union_resolutions`，doc_function 起点快照=打印期冻结的同一 map，语义等价 fd.union_map）+29 处替换（RPN/legacy 双运输层每 oracle 行两处） | 1-1.5 天 | 机制 B 差分（printc 白名单）三口径 |
| D | ruleaction.rs | 14 处换 `vn_type_read_facing`/`vn_type_def_facing`（规则持 fd）；12763 错误注释修正 | 0.5 天 | 差分（ruleaction 白名单） |
| E | subflow.rs | 10 处换孪生（SplitDatatype 持 data）；规则期 map 仅 typeprop 填充，行为变化面小 | 0.5 天 | 差分 |
| F | cast.rs | 3 处加 fd 参；调用点 6630（fd 在域）+printc.rs:17898（依赖包 C 通道） | 0.5 天 | 差分 |
| G | unionresolve.rs+funcdata.rs | with_field interning（&mut TypeFactory 线程+force_facing_type 写 guard 重构）+头注改写+datatype.rs 死码孪生处置 | 0.25 天 | 单元+差分 |
| H | varnode.rs+printlanguage.rs+printc.rs | setImpliedField 标志位+pushImpliedField 移植+rpn_recurse 消费——implied union field 打印端到端（**独立立票**，varnode.rs 写域另租） | 1-2 天 | 差分三口径 |

**总计 A-G ≈ 4-5 agent-days**（H 另计）。**派单顺序按活语料影响**：A（管线活跃，curl union 在跑）> B（活跃 token 位）> C（打印层，可观测面最大）> D/E（规则期 map 稀疏，形式分歧为主）> F > G > H。

**关键风险提示**：①包 C 的 snapshot 通道与 fd-aware 孪生的 live-consult 在打印期等价（map 冻结），但**必须**保持快照时点=doc_function 入口不提前；②包 G 的 interning 修复会改变 `Arc::ptr_eq` 恒等比较的命中集，可能翻转 castStandard 恒等短路——需全量差分盯 `(type)` 前缀 cast 增减；③coreaction.rs:6534-6535 "union needsResolution arms remain registered residuals" 注释已过时（6844/6847/6968/6971 已落地），包 A 顺手清理；④邻接域 datatype.rs:3011（scoreSingleComponent）建议并入包 A 优先修——它直接污染 resolve_in_flow Array/Struct 臂的 field 选择正确性。

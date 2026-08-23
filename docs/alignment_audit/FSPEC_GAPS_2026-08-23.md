# FSPEC 深度对齐审计 — fspec.cc/fspec.hh vs src/fspec.rs

- **日期**: 2026-08-23
- **审计 Agent**: fspec_gaps_audit(只读)
- **Oracle**: Ghidra 12.0.4,commit `e40ed13014025f82488b1f8f7bca566894ac376b`(已核实 `ghidra/` HEAD)
- **Rugra 基线**: master `b19a16a`
- **对照物**: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/fspec.hh`(1785 行)/ `fspec.cc`(5976 行)↔ `src/fspec.rs`(7039 行)+ `src/type_system/protomodel.rs`(315 行)+ `src/coreaction.rs`(consumer)+ `src/database.rs`(symbol 通道)+ `src/funcdata.rs`(owner)
- **性质**: 只读审计。所有 claim 附 file:line。禁 git/cargo(未执行)。

---

## 0. 执行摘要

| 维度 | 数字 |
|---|---|
| Ghidra 侧类(含抽象基类) | 26 |
| Rust 侧有对应物的类 | 16(其中 4 个为扁平/合并替代) |
| **完全缺失的类** | **10**(ParamEntryRange/ParamListRegister/ParamListMerged/ProtoModelMerged/ScoreProtoModel/UnknownProtoModel/ProtoParameter 虚接口/ParameterBasic/ParameterSymbol/ProtoStore 三件套) |
| 函数级:MISSING(无对应物) | **约 88** |
| 函数级:MISMATCH(存在但语义不同) | **11**(其中 4 个是主动行为差异,非降级) |
| 函数级:STUB/no-op | **6**(fspec.rs 内)+ 3 个 coreaction Action 空转 |
| 函数级:PARTIAL(带 hook/近似) | **约 22** |
| 已核对且行为等价(MATCH 形) | **约 150**(多为 ParamEntry/ParamActive/EffectRecord/ParamListStandard 核心算法;oracle 双侧 fixture 覆盖度 = UNTESTED 居多) |
| COREACTION_GAPS_2026-08-22 六条线索 | 6/6 证实,其中 2 条比原报告更严重(见 §2) |
| 本审计新发现(线索外) | 7 项(见 §3),含 1 个架构级双模型栈分裂 |

> 状态口径:MATCH=读双侧代码逐语义等价;PARTIAL=主路径在但有 hook/近似/缺分支;MISSING=无对应物;MISMATCH=存在但可观察行为不同;一切未跑 locked-oracle 双侧 fixture 的均为 UNTESTED(机制 B2 口径,本审计只做代码级核对)。

---

## 1. 类级总览

| # | Ghidra 类 (hh:line) | Rust 对应物 (rs:line) | 类级状态 | 一句话差异 |
|---|---|---|---|---|
| 1 | ParamEntry (hh:84) | fspec::ParamEntry (rs:3515) | PARTIAL | 核心几何算法齐;decode 缺 `isReverseJustified` 腿(cc:565-571);join 依赖未移植的 findJoin(rs:3774 自述) |
| 2 | ParamEntryRange (hh:158) + ParamEntryResolver (hh:194) | 无(rangemap 未移植) | **MISSING** | findEntry 用线性扫描替代(rs:4480 自述 TODO),无 position subsort |
| 3 | ParamTrial (hh:210) | fspec::ParamTrial (rs:3028) | **MISMATCH** | `operator<` 排序键不同(rs:3317 vs cc:1893);splitLo 地址算错(rs:3138 vs cc:1859);split 丢 flags(rs:3131 vs cc:1847) |
| 4 | ParamActive (hh:285) | fspec::ParamActive (rs:3198) | PARTIAL | 缺 `setPlaceholderSlot`(hh:310)、`getTrialForInputVarnode`(hh:1749) |
| 5 | FspecSpace (hh:349) | 3 个自由函数 (rs:2920/2944/2967) | PARTIAL | `FspecSpace::decode`(cc:2166)缺;AddressSpace 是 enum 无法建子类 |
| 6 | ParameterPieces (hh:360) | fspec::ParameterPieces (rs:4218) | PARTIAL | swapMarkup 在;`assignAddressFromPieces`(cc:2191)**MISSING** |
| 7 | PrototypePieces (hh:377) | fspec::PrototypePieces(rs:4268)+ grammar::PrototypePieces 双轨 | PARTIAL | fspec 版缺 model/innames;FuncProto 用 grammar 版(rs:684/992) |
| 8 | EffectRecord (hh:391) | fspec::EffectRecord (rs:30) | MATCH(形) | encode/decode/compare 逐行对齐(rs:92/126/144) |
| 9 | ParamList 抽象 (hh:425) | 无 trait,由各 struct 固有方法承担 | PARTIAL | 无多态;getType 用 enum ParamListKind(rs:4198) |
| 10 | ParamListStandard (hh:589) | fspec::ParamListStandard (rs:4277) | **MISMATCH** | findEntry/unjustifiedContainer/assumedExtension 硬编码 Ram 空间过滤(rs:4484/5018/5034,Ghidra 无此过滤) |
| 11 | ParamListStandardOut (hh:656) | fspec::ParamListStandardOut (rs:5238) | PARTIAL | initialize() 无 ModelRule 扫描,无条件走 fallback(rs:5278);fillinMap 无规则腿(rs:5529) |
| 12 | ParamListRegisterOut (hh:679) | fspec::ParamListRegisterOut (rs:5587) | MATCH(形) | assignMap 对齐(rs:5621 vs cc:1519) |
| 13 | ParamListRegister (hh:695) | 无 | **MISSING** | `buildParamList("register")` 静默降级为 Standard(rs:5875-5882),fillinMap 的"允许空洞"变体(cc:1542-1560)不存在 |
| 14 | ParamListMerged (hh:712) | 无 | **MISSING** | foldIn(cc:1794)未移植 |
| 15 | ProtoModel (hh:748) | fspec::ProtoModelFull (rs:5696) | PARTIAL | decode/lookup/assignParameterStorage 齐;isMerged/isUnknown 虚函数无;`<resolveprototype>` 不解析(arch.rs:1855 CSPEC-PARAMMODEL-0001) |
| 16 | UnknownProtoModel (hh:1025) | 无(字符串 "unknown" 哨兵,rs:859) | **MISSING** | getPlaceholderModel/克隆行为无 |
| 17 | ScoreProtoModel (hh:1040) | 无 | **MISSING** | addParameter/doScore(cc:2717/2738)全缺 |
| 18 | ProtoModelMerged (hh:1077) | 无(仅两个静态孤儿 helper rs:6130/6162) | **MISSING** | foldIn/selectModel/decode(cc:2834/2877/2904)缺;intersectEffects/intersectRegisters 被抬成 ProtoModelFull 静态方法 |
| 19 | ProtoParameter 抽象 (hh:1100) | fspec::ProtoParameter 扁平 struct (rs:165) | PARTIAL | 无 Basic/Symbol 二分;overrideSizeLockType/resetSizeLockType(hh:1124/1130)缺 |
| 20 | ParameterBasic (hh:1163) | 并入 ProtoParameter | **MISSING**(作为类型) | setTypeLock/overrideSizeLockType 等 7 个 cc 实现(cc:2924-2979)无独立对应 |
| 21 | ParameterSymbol (hh:1256) | 无 | **MISSING** | 16 个方法(cc:2981-3101)全缺;锁标志不镜像 Varnode flag |
| 22 | ProtoStore 抽象 (hh:1198) | 无(FuncProto 内嵌 set_input_parameter/set_output_parameter,rs:1241/1261) | PARTIAL | 仅 Internal 语义的扁平版 |
| 23 | ProtoStoreSymbol (hh:1286) | 无 | **MISSING** | setInput 不建 category-0 符号(§2.7) |
| 24 | ProtoStoreInternal (hh:1312) | 扁平内嵌 | PARTIAL | encode/decode(cc:3421/3464)缺 |
| 25 | FuncProto (hh:1343) | fspec::FuncProto (rs:224) | **MISMATCH** | 无 likelytrash/errorflags/custom_storage;resolveExtraPop/paramShift/setInjectId 是 no-op;encode/decode 失真(§3.E) |
| 26 | FuncCallSpecs (hh:1645) | fspec::FuncCallSpecs (rs:1683) | **MISMATCH** | 无 effective_extrapop/paramshift/matchCallCount/isbadjumptable/is_override;proto_model 绑的是**简化 stub**(§3.A);12 个方法 MISSING |

---

## 2. 六条线索逐条核实(全部成立;2 条比原报告更严重)

### 2.1 线索"FuncProto trashset 缺失" — 证实,且 decode 语义被污染

- Ghidra:`FuncProto::likelytrash` 字段(hh:1365),`trashBegin/trashEnd`(hh:1549-1550 → cc:4260/4269),decode 读 `<likelytrash>` 到独立列表(cc:4807-4812),`decodeLikelyTrash`(cc:3684)与模型表合并,`encodeLikelyTrash`(cc:3631)。消费方 `ActionLikelyTrash`(coreaction.cc:2140-2272)遍历 trashBegin/trashEnd 做 traceTrash/INDIRECT/INT_AND 截断。
- Rust:`FuncProto` 无 likelytrash 字段(rs:224-291 字段清单);`FuncProto::decode` 把 `<likelytrash>` 子元素**折叠进 effects 并标 KilledByCall**(rs:1195-1206,注释自述"fold into effects")。这不仅是缺失:
  - `has_effect`(rs:355-373)优先用非空本地 effects——trash 记录会被当作 killedbycall 返回,污染 guardCalls/RestrictLocal 的效果判定;
  - `is_compatible`(rs:1344-1358)对比 effects 列表时,折叠的 trash 记录参与逐项比较,而 Ghidra 比较的是独立 likelytrash 列表(cc:4572-4576)。
- `ProtoModelFull.likelytrash` 与 `trash_iter` 存在且 `<likelytrash>` 正确解码(rs:5711/6118/6417-6427),`encode_likely_trash`/`decode_likely_trash` 也已移植(rs:1462/1553)——即 **model 侧地基已在,FuncProto 侧缺字段+错误折叠**。
- 消费方 `ActionLikelyTrash` 为空转:`let proto = fd.get_func_proto(); let _ = proto;`(coreaction.rs:6174-6176)。

### 2.2 线索"per-callspec extraPop 缺失" — 证实

- Ghidra:`FuncCallSpecs::effective_extrapop`(hh:1650),ctor 初始化为 `extrapop_unknown`(cc:4929),`setEffectiveExtraPop/getEffectiveExtraPop`(hh:1687-1688);`FuncProto::resolveExtraPop`(cc:3971-3992)是真算法(varargs→4;否则从 spacebase 参数偏移推 4 对齐最大值);`ActionExtraPopSetup`(coreaction.cc:1436-1466)按 per-callspec extrapop 建 INT_ADD/INDIRECT 调 SP;`ActionStackPtrFlow` phase-1 回写 analyzeExtraPop(coreaction.cc:483-496)。
- Rust:`FuncCallSpecs` 结构体无 effective_extrapop 字段(rs:1683-1720);无 setter/getter(grep `set_effective_extrapop` 零命中);`FuncProto::resolve_extra_pop` 是注释 no-op(rs:774-778);`FuncProto::set_inject_id`/`param_shift` 同为 stub(rs:768-772/780-788)。`ActionExtraPopSetup::apply` 整体 no-op(coreaction.rs:7561-7566,注释 "Rugra doesn't track extraPop per-callspec yet")。funcdata.rs:7160/7195/7933 自述 RUGRA-GAP(FuncProto 无 extrapop 字段——实际 rs:249 有 `extra_pop`,但 resolve 不写它)。

### 2.3 线索"internal-storage 区间缺失" — 证实(半成品:模型侧在,消费链断)

- Ghidra:`ProtoModel::internalstorage`(hh:758)+ `internalBegin/internalEnd`(hh:844-845);`FuncProto::internalBegin/End` 委托模型(hh:1551-1552);`ActionInternalStorage`(coreaction.cc:4938-4975)遍历区间,对命中 CALL/CALLIND 输入做重建+markNotMapped。
- Rust:`ProtoModelFull.internalstorage` 存在且 `<internal_storage>` 正确解码排序(rs:5714/6428-6438/6493);但 **FuncProto 无 internal_begin/end 访问器**(grep 零命中);`ActionInternalStorage::apply` 改为遍历 `proto.parameters` 的 INDIRECT_STORAGE/HIDDEN_RETURN flag 计数然后丢弃(coreaction.rs:7519-7542,`let _ = change_count` + 恒 NO_CHANGE)——与 Ghidra 的"模型寄存器区间→CALL 输入重建"完全是两件事。

### 2.4 线索"checkOutputTrialUse/buildOutputFromTrials 未接" — 证实

- Ghidra:`FuncCallSpecs::collectOutputTrialVarnodes`(cc:5536-5563,走 INDIRECT 链收集 trial varnode)→ `checkOutputTrialUse`(cc:5661-5677,null varnode 判 inactive,**非 null 即 markActive**,不 markNoUse)→ `ActionActiveReturn`(coreaction.cc:1773-1792)四步:checkOutputTrialUse → deriveOutputMap → buildOutputFromTrials(cc:5770-5860)→ clearActiveOutput。
- Rust:`build_output_from_trials` 在 fspec.rs:2598-2673 已相当忠实(单 trial 移交/双 trial join+SUBPIECE/deleteUnusedTrials;findPreexistingWhole 缺,rs:2661 自述);`collectOutputTrialVarnodes` **MISSING**(grep 零命中);`checkOutputTrialUse` **MISSING**(作为方法);`ActionActiveReturn::apply` 内联了一个"call op 有 output 即全部 markActive"的启发式(coreaction.rs:5903-5933,逐 trial 但判定源是 op.output.is_some() 而非 collectOutputTrialVarnodes 的 per-trial varnode 存在性),随后 **rs:5939-5942 注释列了 step3 却直接 clear_active_output,从不调用 fspec.rs:2598 的 build_output_from_trials**;`change += 1` 后返回恒 `NO_CHANGE`(rs:5943-5945)。

### 2.5 线索"deriveInputMap/updateInputTypes 未用" — 证实,且注释性陈述已过时

- Ghidra:`ActionInputPrototype`(coreaction.cc:4707-4763):clearCategory(0)+clearUnlockedInput→收集 possibleInputParam 输入→registerTrial+markActive(按 descend 计)→resolveModel→deriveInputMap→updateInputTypes(cc:4052)/必要时 updateInputNoTypes(cc:4097)。
- Rust:`FuncProto::update_input_types` 已移植且带 find_disjoint_cover hook(rs:891-943);`update_input_no_types`/`update_output_no_types` **MISSING**(grep 零命中;Ghidra cc:4097-4134/4172-4192)。`ActionInputPrototype::apply`(coreaction.rs:5558-5626)自建 ParamActive 后**不设 trial 状态、不调 derive_input_map、不调 update_input_types**,直接手搓 `param_N` + `long` 类型参数(rs:5606-5626);rs:5594-5598 注释"Rugra doesn't expose trial mutably"已过时——`ParamActive::get_trial_mut` 存在(rs:3241),这是**陈旧注释掩盖的未接线**,不是能力缺口。
- 另:`ActionActiveParam`(coreaction.rs:5827-5876)确实调了 check_input_trial_use/resolve_model/derive_input_map/build_input_from_trials(rs:5830/5868-5870),但 derive_input_map 走的是**简化 stub 模型**(见 §3.A),且 build_input_from_trials 是抽取版(见 §3.D)。

### 2.6 线索"resolve_model no-op (fspec.rs:1905)" — 证实;根因是整个 merged-model 族不存在

- Ghidra:`FuncProto::resolveModel`(cc:3767-3776)仅对 `isMerged()` 模型做事:委托 `ProtoModelMerged::selectModel`(cc:2877-2903,ScoreProtoModel 逐模型打分,<500 起评,0 分即短路)。
- Rust:`FuncCallSpecs::resolve_model` 空 body(rs:1905-1909),调用点 coreaction.rs:5868。**判定:no-op 对"当前只有具体模型"是对的,但 Rugra 无法表达 merged 模型**:`ProtoModelMerged`/`ScoreProtoModel`/`ParamListMerged` 三类全缺(grep 仅注释命中:arch.rs:1699/1855,fspec.rs:1903);`<resolveprototype>` 元素不解析(arch.rs:1855 明示 CSPEC-PARAMMODEL-0001);`intersect_effects/intersect_registers` 被错误安放在 ProtoModelFull 上当静态孤儿(rs:6130-6184,注释自述"ProtoModelMerged itself is not yet modelled")。任何带多模型 resolvesprototype 的 cspec(Windows __stdcall/__fastcall 合并、MIPS o32/n32/64)在 Rugra 不可表示。

### 2.7 线索"无 ProtoStoreSymbol 等价" — 证实(最深的结构缺口)

- Ghidra:`Funcdata` ctor 即 `funcp.setScope(localmap,baseaddr-1)`(funcdata.cc:69)→ `FuncProto::setScope`(cc:3879-3884)换装 **ProtoStoreSymbol**;此后 `FuncProto::setInput` 走 `ProtoStoreSymbol::setInput`(cc:3147-3214):查 category-0 符号、地址/大小不符则 removeSymbol 重建、`scope->addSymbol + setCategory(function_parameter,i)`(cc:3169-3170)、把 indirectstorage/hiddenretparm/typelock/namelock **镜像到 Varnode flag 属性**(cc:3171-3182)、rename/retype(cc:3209-3212)。`clearAllInputs`(cc:3233)清 category。
- Rust:`FuncProto::set_input_parameter`(rs:1241-1255)只写扁平 parameters 向量(占位符类型还是 `return_type`,rs:1245);`Funcdata` 构造链只做了 setScope 的 **model-binding 尾巴**(funcdata.rs:962-969 注释自述);`setScope` 本身 MISSING(grep 零命中);database.rs 有完整的 category-0 API(`set_category`/`get_category_symbol`/`clear_category`,rs:2108/2920 等,单测 rs:4319-4326)但**没有任何调用方把 FuncProto 参数写入 category 0**。后果:varmap/ScopeLocal 的参数符号恢复、UnjustifiedParams 的容器归并、locked 参数的 name/type 锁镜像全部失去数据源。

---

## 3. 线索之外的新发现(7 项)

### A.(架构级)FuncCallSpecs 挂的是简化 stub 模型,不是解码出的 ProtoModelFull —— 双模型栈分裂

- `FuncCallSpecs::proto_model: Option<crate::type_system::protomodel::ProtoModel>`(fspec.rs:1701)。该类型是 315 行的**硬编码 x86-64 SysV stub**(protomodel.rs:109-131,RDI/RSI/RDX/RCX/R8/R9+栈+RAX,`RUGRA-GLUE: default_x86_64 (no Ghidra counterpart found)`),自带另一套 ParamEntry(protomodel.rs:31)和**另一个 fillinMap**(protomodel.rs:185-218,自述 "simplified for Rugra's model")。
- 全管线只有三处 set:coreaction.rs:6029-6030、6451 —— 全部 `ProtoModel::default_x86_64()`。**从不绑定 Architecture 的 `proto_models: BTreeMap<String, Arc<ProtoModelFull>>`(arch.rs:425/476)里由 cspec 解码出的模型**。
- 因此 `FuncCallSpecs::derive_input_map`(fspec.rs:1914-1918)→ stub 的 `fillin_input_map`(protomodel.rs:185),而**同文件里忠实移植的 `ParamListStandard::fillin_map`(fspec.rs:4932,对齐 cc:1285-1313)在主管线上是死代码**。characterizeAsParam 同理分裂:fspec.rs:402 走 ProtoModelFull(对),FuncCallSpecs::possible_input_param(fspec.rs:1809)走 stub。
- 这是 R1 根缺口:**所有 callspec 级模型决策的行为都由 stub 决定**,cspec 的 `<pentry>`/group/float 分区全部失效。

### B. ParamListStandard 的 Ram-only 空间过滤(Rugra 自创,非 Ghidra 语义)

- `find_entry`(fspec.rs:4479-4488):`if e.get_space() != AddressSpace::Ram { continue; }`(rs:4484)。
- `unjustified_container`(rs:5015-5026)rs:5018、`assumed_extension`(rs:5031-5039)rs:5034 同样硬编码 Ram。
- Ghidra:`findEntry`(cc:661-680)用查询地址**自身空间**的 resolverMap(register/stack 空间照常命中);`unjustifiedContainer`(cc:1411-1424)/`assumedExtension`(cc:1426-1437)遍历**全部 entries 无空间过滤**。
- 后果:①寄存器空间的参数 entries 在这三条路径上永远不命中(possibleParam/checkJoin/checkSplit 全废);②当查询在 register 空间时,Ram entries 仍按裸 offset 比较 → 跨空间假命中可能。

### C. ParamActive::sort_trials 排序键错误

- Rust:`sort_by(|a,b| a.addr.cmp(&b.addr).then(a.size.cmp(&b.size)))`(fspec.rs:3317-3321)。
- Ghidra:`ParamTrial::operator<`(cc:1893-1918)按 (entry group → entry 指针序 → exclusion 时 offset → reverseStack 感知的 addr → size) 排。
- 该排序是 `buildTrialMap` 末尾、`separateSections`/`forceNoUse`/`forceInactiveChain` 的前提(cc:935/849);用地址序替代模型槽序会让段边界与 no-use 链判定错位。**注意**:由于主管线走 stub 模型(§3.A),此 bug 目前潜伏;模型统一后立即显形。

### D. ParamTrial::split_lo 地址算错 + split 丢 flags

- `split_lo`:`Address::new(self.addr.as_u64() + sz as u64)`(fspec.rs:3138)vs Ghidra `addr + (size-sz)`(cc:1859)。仅当 size==2*sz 时相等;12 字节 trial 切 4 时 Rust 得 0x104,Ghidra 得 0x108。单测 rs:6789-6798 恰好用 8 切 4,掩盖了该错。
- `split_hi/split_lo` 均不复制 flags(rs:3131-3139 用 `ParamTrial::new`,flags=0)vs Ghidra `res.flags = flags`(cc:1847/1860)。used/checked/active 状态在 split 后丢失。
- `split_trial`(rs:3299)依赖这两个函数,`ActionParamDouble` 的 trial 切分将来会踩。

### E. FuncProto encode/decode 失真

- encode:`extrapop` 恒写 `"unknown"`(rs:1625,注释自述),voidlock 从不写(Ghidra cc:4640-4649 按 flags 写);inject 元素跳过(rs:1671-1672)。
- decode:extrapop 读入后丢弃(rs:1136-1140),voidlock 读入后丢弃(rs:1126),`<internallist>` 整体跳过(rs:1214-1219 vs Ghidra store->decode cc:4820-4823),`<inject>` 只吞字符串(rs:1207-1213),decodeEffect/decodeLikelyTrash/reconcile-modellock 尾巴未执行(rs:1229 注释列出但只调了 update_this_pointer)。
- likelytrash 折叠污染(§2.1)同属 decode 失真。

### F. is_stack_output_lock 恒 false

- `FuncCallSpecs::is_stack_output_lock` 直接 `return false`(fspec.rs:1849-1852),Ghidra 由 `ActionPrototypeTypes` 设置(hh:1703-1704)用于 funcLinkOutput 的栈上返回值特殊处理(coreaction.cc:1489-1511 附近)。

### G. commitNewInputs 近似

- 参数 size 恒 0(rs:2290-2293 `psize = 0i32`),trial 注册硬编码 size 8(rs:2305 `register_trial(paddr, 8)`),首个参数无条件当 placeholder 候选(rs:2310-2316);Ghidra cc:5150-5190 用 param 实际 size、按 stack 空间判 placeholder。getSpacebaseRelative 未接线(rs:2253-2255 自述)。

---

## 4. 全量函数对照表

> 状态列:M=MATCH(代码级等价)/ P=PARTIAL/ X=MISSING/ MM=MISMATCH/ (U)=oracle 双侧 fixture 未跑。Ghidra 行=定义起始行;fspec.cc 行号基于 e40ed130。

### 4.1 ParamEntry (hh:84)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:60 findEntryByStorage | rs:3746 find_entry_by_storage | M(U) | 反向线性扫描一致 |
| cc:76 resolveFirst | rs:3758 resolve_first | M(U) | |
| cc:94 resolveJoin | rs:3773 resolve_join | P | 依赖未移植 findJoin,pieces 由 set_join_pieces 注入(rs:3803-3809) |
| cc:122 resolveOverlap | rs:3815 resolve_overlap | M(U) | 空间不等 continue 保留(rs:3822 注释) |
| cc:157 groupOverlap | rs:3855 group_overlap | M(U) | |
| cc:184 subsumesDefinition | rs:3878 subsumes_definition | M(U) | |
| cc:199 containedBy | rs:3894 contained_by | M(U) | |
| cc:214 intersects | rs:3905 intersects | M(U) | join 分支在 |
| cc:248 justifiedContain | rs:3925 justified_contain | M(U) | join/alignment 双分支在 |
| cc:295 getContainer | rs:3959 get_container | M(U) | |
| cc:335 contains | rs:3994 contains | M(U) | |
| cc:366 assumedExtension | rs:4013 assumed_extension | M(U) | SMALLSIZE_FLOATEXT 的 constructFloatExtensionAddress 缺(rs:4089-4095 TODO) |
| cc:407 getSlot | rs:4051 get_slot | M(U) | |
| cc:434 getAddrBySlot(3) | rs:4070 get_addr_by_slot | M(U) | |
| cc:450 getAddrBySlot(4) | rs:4078 get_addr_by_slot_just | M(U) | float-ext 缺(同上) |
| cc:501 decode | rs:3585 decode | P | 缺 `isReverseJustified→force_left_justify` 腿(cc:565-571);register 解析走 resolver hook(合理) |
| cc:583 orderWithinGroup | rs:4126 order_within_group | M(U) | |
| hh:123 isLeftJustified 等 inline | rs:3532 等 | M(U) | |

### 4.2 ParamEntryRange / ParamEntryResolver (hh:158/194) — 全 X

rangemap subsort(position)基础设施无;`addResolverRange`(cc:1174)/`populateResolver`(cc:1191)在 Rust 是 no-op/缓存刷新(rs:5088-5090/5072-5079)。**所有依赖 resolver 的查询改为线性扫描**:findEntry(rs:4479)、characterizeAsParam(rs:4504)、getBiggestContainedParam(rs:4532)。characterize/getBiggest 的语义近似等价(同空间 entry 集合一致),findEntry 的 Ram 过滤是行为差异(§3.B)。

### 4.3 ParamTrial (hh:210)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:1845 splitHi | rs:3131 split_hi | MM | flags 不复制(cc:1847) |
| cc:1856 splitLo | rs:3137 split_lo | **MM** | 地址 `+sz` 应为 `+(size-sz)`(cc:1859);flags 不复制 |
| cc:1871 testShrink | rs:3153 test_shrink | M(U) | endian 由调用者传(hook) |
| cc:1893 operator< | (无;sort_trials 内联) | **MM** | 排序键 addr/size vs group/entry/reverseStack(rs:3317) |
| cc:1920 fixedPositionCompare | rs:3177 fixed_position_compare | P | op_less 由闭包传入(等价);但 sortFixedPosition 全缺(见 4.4) |
| hh:235 ctor + 30 个 inline | rs:3045-3126 | M(U) | flags 位值逐一一致(rs:3011-3023) |

### 4.4 ParamActive (hh:285)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:1936 ctor | rs:3213 | M(U) | |
| cc:1949 clear | rs:3228 | M(U) | |
| cc:1963 registerTrial | rs:3278 | M(U) | slot=trial.len() |
| cc:1982 whichTrial | rs:3286 | M(U) | |
| cc:1995 freePlaceholderSlot | rs:3349 | M(U) | -2/slotbase/maxpass=0 语义在 |
| cc:2013 deleteUnusedTrials | rs:3330 | M(U) | 1-based renumber 在 |
| cc:2033 splitTrial | rs:3299 | P | 依赖 §3.D 的 split_lo 错误 |
| cc:2063 joinTrial | rs:3366 | M(U) | panic 对应 LowlevelError |
| cc:2087 sortTrials | rs:3317 | MM | 排序键(§3.C) |
| cc:2097 getNumUsed | rs:3308 | M(U) | |
| hh:310 setPlaceholderSlot | — | **X** | stackplaceholder/slotbase 联动缺 |
| hh:317 sortFixedPosition | — | **X** | varargs 固定参数前置(buildInputFromTrials cc:5700 依赖) |
| hh:1749 getTrialForInputVarnode | — | **X** | checkInputJoin(cc:5349)依赖 |

### 4.5 FspecSpace (hh:349)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:2116 ctor | —(enum 空间) | X | 语言结构差异,可接受降级需记录 |
| cc:2124 encodeAttributes(2) | rs:2920 | M(U) | space 名占位 "ram"(rs:2984) |
| cc:2138 encodeAttributes(3) | rs:2944 | M(U) | 同上 |
| cc:2153 printRaw | rs:2967 | M(U) | |
| cc:2166 decode | — | X | |

### 4.6 ParameterPieces / PrototypePieces / EffectRecord

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:2175 swapMarkup | rs:4242 swap_markup | M(U) | MARKUP_MASK 六位一致 |
| cc:2191 assignAddressFromPieces | — | **X** | join 地址重建(多 piece 参数)无 |
| hh:377 PrototypePieces | rs:4268(fspec 版)+ grammar 版双轨 | P | fspec 版缺 model/innames/name |
| cc:2212/2223/2234 EffectRecord ctors | rs:44/69/81 | M(U) | |
| cc:2243 encode | rs:92 | M(U) | parent 元素由调用者传(等价) |
| cc:2256 decode | rs:126 | M(U) | |
| hh:1761 compareByAddress | rs:144 | M(U) | space_id 序 |

### 4.7 ParamListStandard (hh:589)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:597 copy-ctor | derive Clone | M(U) | |
| cc:626 extractTiles | rs:4453 | M(U) | |
| cc:642 getStackEntry | rs:4466 | M(U) | |
| cc:661 findEntry | rs:4479 | **MM** | Ram-only 过滤(§3.B);resolver→线性 |
| cc:682 characterizeAsParam | rs:4504 | P | 线性扫描+同空间过滤,语义近似;Ghidra 第二遍 find_end 起点扫描(cc:719-729)未显式做(contained_by 由同遍历覆盖) |
| cc:735 assignAddressFallback | rs:4573 | P | getAlignSize/getAlignment 未移植,用 size/1 近似(rs:4584-4587 TODO) |
| cc:772 assignAddress | rs:4607 | P | ModelRule 腿缺,直落 fallback(rs:4611-4615) |
| cc:785 assignMap | rs:4621 | P | hiddenret 二段逻辑在;res.len()==2 前提是调用方先放 output(耦合) |
| cc:820 selectUnreferenceEntry | rs:4660 | M(U) | |
| cc:849 buildTrialMap | rs:4675 | P | 主体在;entry 指针→index 等价;sort_trials 排序键错误传导(§3.C) |
| cc:946 separateSections | rs:4751 | M(U) | |
| cc:974 markGroupNoUse | rs:4780 | M(U) | |
| cc:997 markBestInactive | rs:4800 | M(U) | |
| cc:1032 forceExclusionGroup | rs:4828 | M(U) | |
| cc:1069 forceNoUse | rs:4860 | M(U) | |
| cc:1111 forceInactiveChain | rs:4883 | M(U) | unref+stack 判定近似(rs:4895-4896) |
| cc:1153 calcDelay | rs:5058 | M(U) | |
| cc:1174 addResolverRange | rs:5088 | X(空) | rangemap 缺 |
| cc:1191 populateResolver | rs:5072 | P | 仅刷新 stack_entry_index 缓存 |
| cc:1226 parsePentry | rs:5100 | M(U) | decode 后置状态迁移对齐;resource_start/space_base/num_group 语义在 |
| cc:1262 parseGroup | rs:5147 | M(U) | |
| cc:1285 fillinMap | rs:4932 | P | 主体对齐;entry.empty() 静默 return vs Ghidra throw(cc:1290-1291);**主管线未用**(§3.A) |
| cc:1315 checkJoin | rs:4959 | M(U) | isContiguous 近似(rs:6703,忽略 lo_size 端序) |
| cc:1342 checkSplit | rs:4982 | M(U) | |
| cc:1354 possibleParam | rs:4991 | MM(传导) | 经 find_entry 的 Ram 过滤 |
| cc:1360 possibleParamWithSlot | rs:4998 | M(U) | |
| cc:1375 getBiggestContainedParam | rs:4532 | M(U) | wrapping 检查在 |
| cc:1411 unjustifiedContainer | rs:5015 | **MM** | Ram-only 过滤(§3.B) |
| cc:1426 assumedExtension | rs:5031 | **MM** | 同上 |
| cc:1439 getRangeList | rs:5044 | M(U) | |
| cc:1451 decode | rs:4318 | P | pointermax/separatefloat/两阶段 rule 拒后 pentry 在;`<rule>` 元素吞掉不建 ModelRule(rs:4415-4419) |

### 4.8 ParamListStandardOut / RegisterOut (hh:656/679)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:1569 assignMap | rs:5299 | P | hiddenret 升级在;getTypePointer 无,复用 out_type 当指针类型(rs:5347);AssignAction hiddenret_* 三码坍缩为本地枚举(rs:5326-5331) |
| cc:1614 initialize | rs:5278 | P | 无 ModelRule 扫描,无条件 fallback+auto_killedby_call |
| cc:1638 fillinMapFallback | rs:5387 | M(U) | best_class=PTR 初值、extracheck 高低、rem/indcreate 拒绝、minsize 全在 |
| cc:1721 fillinMap | rs:5498 | P | 规则腿缺,非 fallback 路径落 fallback(true)(rs:5529-5534) |
| cc:1765 possibleParam | rs:5543 | M(U) | 与 Standard 版差异被注释正确保留 |
| cc:1776 decode | rs:5556 | P | 结构性 stub:只跑 initialize |
| cc:1783 clone | rs:5572 | M(U) | |
| cc:1519 ParamListRegisterOut::assignMap | rs:5621 | M(U) | |
| cc:1535 clone | rs:5655 | M(U) | |

### 4.9 ParamListRegister / ParamListMerged (hh:695/712) — 全 X

- `ParamListRegister::fillinMap`(cc:1542-1560,允许空洞:markNoUse 仅当无 entry,active→used):**X**。`build_param_list("register")` 静默给 ParamListStandard(rs:5875-5882)→ 空洞禁令错误生效。
- `ParamListMerged::foldIn`(cc:1794-1833,subsumesDefinition 三态合并)/clone(cc:1835):**X**。

### 4.10 ProtoModel (hh:748) → ProtoModelFull (rs:5696)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:2263 defaultLocalRange | rs:5800 | P | `spc->getHighest()` 用 u64::MAX 近似(rs:5805) |
| cc:2292 defaultParamRange | rs:5836 | P | 同上 |
| cc:2323 buildParamList | rs:5871 | P | "register" 降级(§4.9) |
| cc:2339 ctor | rs:5770 | M(U) | |
| cc:2360 copy-ctor(alias) | rs:5744 Clone | P | is_printed 拷贝固定 true(注释声明);compat_model 是 usize 标记非指针(rs:5737) |
| cc:2406 isCompatible | rs:5909 | P | `this==op2` 用 ptr::eq;alias 链用 name/numgroup 近似(rs:5930-5935),Ghidra 是指针等价 |
| cc:2429 assignParameterStorage | rs:5946 | M(U) | hiddenret+isthis 交换/索引逻辑在(swap_markup split_at_mut) |
| cc:2472 lookupEffect | rs:5996 | M(U) | upper_bound/size==0 全空间 unaffected/IPTR_INTERNAL 在(rs:6003) |
| cc:2510 lookupRecord | rs:6058 | M(U) | -1/-2 语义映射 Ok(None)/Err |
| cc:2541 hasEffect | rs:6047 | M(U) | |
| cc:2549 decode | rs:6190/6223/6255 | M(U) | 全属性+全子元素+默认 returnaddress(cc:2689-2691 对应 rs:6472-6483)+三列表排序在 |
| hh:781-1003 inline 访问器 | rs:6507-6540 | M(U) | getAliasParent→marker(rs:5892) |
| hh:1008 isMerged / hh:1013 isUnknown | — | **X** | 无虚函数分层 |
| injectUponEntry/Return 访问器 | 字段 rs:5717/5720 | M(U) | 无 getter,直接 pub 字段 |
| **ScoreProtoModel**(hh:1040;cc:2705/2717/2738) | — | **X** | 整类缺 |
| **ProtoModelMerged**(hh:1077;cc:2780/2809/2834/2877/2904) | 仅静态孤儿 rs:6130/6162 | **X** | foldIn/selectModel/decode 全缺;intersect* 被安放到 ProtoModelFull 上(归属错误) |
| **UnknownProtoModel**(hh:1025) | 字符串哨兵 rs:859 | **X** | getPlaceholderModel 无 |

### 4.11 ProtoParameter 家族 (hh:1100-1330)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| ProtoParameter 抽象 16 虚方法 | rs:165 扁平 struct | P | isNameLocked/isSizeTypeLocked/isNameUndefined/setNameLock 缺方法(字段 flags 在) |
| hh:1124 overrideSizeLockType | — | **X** | ParameterBasic(cc:2954)与 ParameterSymbol(cc:3077)两实现全缺 |
| hh:1130 resetSizeLockType | — | **X** | 同上(cc:2966/3083) |
| ParameterBasic 7 个 cc 实现(cc:2924-2979) | 并入扁平 struct | P(语义) | setTypeLock 等由 flag 位承担 |
| **ParameterSymbol** 16 个方法(cc:2981-3101) | — | **X** | 全部;Symbol 代理读取无 |
| **ProtoStore** 抽象(hh:1198) | — | X | 无接口 |
| **ProtoStoreSymbol**(hh:1286;cc:3103/3132/3147/3216/3233/3239/3245/3256/3265/3274/3280/3293/3299) | — | **X** | 13 方法全缺(§2.7) |
| **ProtoStoreInternal**(hh:1312;cc:3306/3329/3340/3356/3366/3372/3380/3389/3397/3403/3421/3464) | 扁平内嵌 rs:1241/1261 | P | set/clear 语义近似;encode(cc:3421 `<internallist>`)/decode(cc:3464)缺 |

### 4.12 FuncProto (hh:1343)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:3572 updateThisPointer | rs:819 | M(U) | hiddenret 跳过逻辑在 |
| cc:3589 encodeEffect | rs:1406 | M(U) | 模型过滤+三分区在 |
| cc:3631 encodeLikelyTrash | rs:1462 | M(U) | 但 FuncProto 无本地 trash 列表存它 |
| cc:3652 decodeEffect | rs:1501 | M(U) | |
| cc:3684 decodeLikelyTrash | rs:1553 | M(U) | 静态方法,无字段挂靠 |
| cc:3706 paramShift | rs:768 | **STUB** | 空 body;Ghidra 重建 ProtoStoreInternal+assignParameterStorage 全流程 |
| cc:3767 resolveModel | rs:1905(在 FuncCallSpecs 上) | STUB | 见 §2.6 |
| cc:3778 ctor | rs:296 | P | model=Some 由绑定链补;store 概念无 |
| cc:3789 copy | rs:723 copy_from | P | 不拷 return_bytes_consumed(rs:290 字段在,copy 漏);store clone 无 |
| cc:3806 copyFlowEffects | rs:762 | **MM** | Ghidra 只拷 is_inline|no_return + injectid(rs 拷整个 effects 列表,语义错对象) |
| cc:3818 setModel | rs:473 | M(U) | extrapop 粘滞/has_this/is_construct/auto_killed 粘滞全在 |
| cc:3843 setPieces | rs:684 | P | 无 ProtoModel 指针,按名记录;assignParameterStorage 不跑(update_all_types 地址全 0,rs:977) |
| cc:3857 getPieces | rs:992 | M(U) | model 以名代指针 |
| cc:3879 setScope | — | **X** | funcdata.rs:962 只做 model 尾巴 |
| cc:3891 setInternal | rs:807 | P | guard `model.is_none()` 在;store 切换无 |
| cc:3906 isInputLocked | rs:540 | M(U) | void_input_locked 语义对 |
| cc:3921 setInputLock | rs:554 | P | Ghidra 空表锁 voidinputlock 且**不**设 modellock(cc:3921-3939 无 flags|=modellock);Rugra rs:556-557 顺带置 model_locked —— 需复核(疑 MM) |
| cc:3942 setOutputLock | rs:572 | P | 同上,Ghidra cc:3942-3948 无 modellock 置位 |
| cc:3954 setReturnBytesConsumed | rs:709 | M(U) | 最小值获胜 |
| cc:3971 resolveExtraPop | rs:776 | **STUB** | §2.2 |
| cc:3994 clearUnlockedInput | rs:746 | M(U) | |
| cc:4001 clearUnlockedOutput | rs:792 | P | Ghidra store->clearOutput 重建 void 参数;Rugra 只清 flag |
| cc:4016 clearInput | rs:755 | M(U) | |
| cc:4025 setInjectId | rs:782 | **STUB** | |
| cc:4036 cancelInjectId | rs:788 | **STUB** | |
| cc:4052 updateInputTypes | rs:891 | P | 忠实+find_disjoint_cover hook;**无调用方**(§2.5) |
| cc:4097 updateInputNoTypes | — | **X** | |
| cc:4136 updateOutputTypes | rs:1019 | P | size-lock 分支用 output_type_locked 兼职(rs:1030-1031 自述);set_output 不存地址 |
| cc:4172 updateOutputNoTypes | — | **X** | |
| cc:4194 updateAllTypes | rs:955 | P | assignParameterStorage 缺→地址 0;typelock 置位额外加(rs:980,Ghidra 由 setPieces 锁) |
| cc:4234 hasEffect | rs:355 | M(U) | 本地优先/模型委托在 |
| cc:4243/4251 effectBegin/End | rs:341 effect_iter | M(U) | |
| cc:4260/4269 trashBegin/End | — | **X** | §2.1 |
| cc:4289 characterizeAsInputParam | rs:384 | P | locked 参数扫描分支整体降级到 model 分支(rs:381-383,ADDRESS-0001) |
| cc:4336 characterizeAsOutput | rs:412 | P | 同上 |
| cc:4366 possibleInputParam | (FuncCallSpecs rs:1809 走 stub) | MM(传导) | §3.A |
| cc:4398 possibleOutputParam | — | **X** | |
| cc:4426 unjustifiedInputParam | — | **X** | ParamList 版在(rs:5015)但 FuncProto 门面缺+Ram 过滤 |
| cc:4459 getBiggestContainedInputParam | rs:433 | P | locked 扫描降级 |
| cc:4492 getBiggestContainedOutput | rs:455 | P | 同上 |
| cc:4516 getThisPointerStorage | — | **X** | |
| cc:4542 isCompatible | rs:1300 | P | 模型按名、输出按 Arc 指针、extrapop 折叠进模型名、injectid 假定相等(rs:1302-1336 逐条注释)、likelytrash 比较缺 |
| cc:4583 printRaw | rs:1367 | P | extrapop 恒 "0"(rs:1395) |
| cc:4609 isAutoKilledByCall | rs:506 | M(U) | output lock 独立强制在 |
| cc:4625 encode | rs:1589 | P | §3.E |
| cc:4675 decode | rs:1082 | P | §3.E |
| hh:1444-1474 flag inline | rs:604-675 | M(U) | error_inputparam/error_outputparam/custom_storage 三 flag 无(对应 coreaction.rs:2648-2666 恒 false 谓词,已登记理由) |
| hh:1551 internalBegin/End | — | **X** | §2.3 |

### 4.13 FuncCallSpecs (hh:1645)

| Ghidra | Rust | 状态 | 差异 |
|---|---|---|---|
| cc:4924 ctor | rs:1729 | P | 无 effective_extrapop/paramshift/matchCallCount/isbadjumptable/isstackoutputlock 字段;CALL 入参地址不提取(cc:4936-4944) |
| cc:4949 setFuncdata | rs:2219 | P | 重复 set 不抛(注释声明);fd* 不保留 |
| cc:4964 clone | rs:2849 | P | effective_extrapop/paramshift/isbadjumptable 不拷 |
| cc:4982 getSpacebaseRelative | — | **X** | commitNewInputs/transferLockedInput 的 stackref 依赖 |
| cc:5005 buildParam | hook 参数(coreaction 侧) | P | |
| cc:5038 transferLockedInputParam | rs:2421 | P | IPTR_SPACEBASE 分支恒 (false,0)(rs:2440-2447,ProtoParameter 无空间) |
| cc:5068 transferLockedOutputParam | rs:2457 | M(U) | INDIRECT 链收集在 |
| cc:5100 transferLockedInput | rs:2520 | P | stackref 恒缺席→Err(rs:2543-2549) |
| cc:5130 transferLockedOutput | rs:2563 | M(U) | |
| cc:5150 commitNewInputs | rs:2239 | P | §3.G |
| cc:5201 commitNewOutputs | rs:2345 | P | exact-match 按 size 不按地址(rs:2369-2374);extend 分支空(rs:2399-2403) |
| cc:5331 initActiveInput | rs:1880 | P | maxdelay→3 clamp 缺(cc:5334-5336) |
| cc:5349 checkInputJoin | — | **X** | |
| cc:5376 doInputJoin | — | **X** | constructJoinAddress 依赖 |
| cc:5408 lateRestriction | hook only(deindirect 参数) | **X**(实体) | |
| cc:5443 deindirect | rs:2695 | P | 忠实控制流+3 hook;isOverride 无(rs:2726-2728 TODO) |
| cc:5485 forceSet | — | **X** | |
| cc:5517 insertPcode | — | **X** | |
| cc:5536 collectOutputTrialVarnodes | — | **X** | §2.4 |
| cc:5564 finalInputCheck | rs:2039 | M(U) | |
| cc:5585 checkInputTrialUse | rs:2076 | M(U) | stack/register 双路径+ancestor_op_use+needs_final_check 在 |
| cc:5661 checkOutputTrialUse | —(coreaction.rs:5903 启发式) | **X** | §2.4 |
| cc:5685 buildInputFromTrials | rs:1939 | **P(重)** | 缺:varargs sortFixedPosition(cc:5700)、spacebase 偏移换算 cc:5713、unref→newVarnode cc:5716、SUBPIECE 截断 cc:5720-5732、markNotMapped cc:5737、opSetAllInput(cc:5739);仅返回 (addr,size) 列表 |
| cc:5750 findPreexistingWhole | — | **X** | buildOutputFromTrials 双 trial 路径依赖 |
| cc:5770 buildOutputFromTrials | rs:2598 | P | 单/双 trial 主干在;findPreexistingWhole 缺;precisLo/Hi TODO(rs:2650-2652);**无主管线调用方**(§2.4) |
| cc:5870 getInputBytesConsumed | rs:1990 | M(U) | |
| cc:5887 setInputBytesConsumed | rs:2004 | M(U) | |
| cc:5901 paramshiftModifyStart | rs:2865 | P | paramshift 由参数传入而非字段 |
| cc:5911 paramshiftModifyStop | rs:2879 | P | paramshift_applied flag 无(rs:2885 注释) |
| cc:5934 hasEffectTranslate | rs:2755 | M(U) | wrapOffset 用 rem_euclid 近似(rs:2771) |
| cc:5950 countMatchingCalls | rs:2787 | P | 返回 Vec 而非写 matchCallCount 字段(字段无) |
| hh:1687 setEffectiveExtraPop 等 inline | — | **X** | §2.2 |

### 4.14 coreaction 侧消费者(证据交叉)

| Action | Ghidra cc | Rugra rs | 状态 |
|---|---|---|---|
| ActionExtraPopSetup | cc:1436-1466 | coreaction.rs:7561-7566 | STUB(no-op) |
| ActionLikelyTrash | cc:2140-2272 | coreaction.rs:6162-6177 | STUB(`let _ = proto`) |
| ActionInternalStorage | cc:4938-4975 | coreaction.rs:7519-7542 | STUB(数 flag 后丢弃) |
| ActionActiveReturn | cc:1773-1792 | coreaction.rs:5891-5946 | PARTIAL(§2.4;恒 NO_CHANGE) |
| ActionInputPrototype | cc:4707-4763 | coreaction.rs:5558-5626 | PARTIAL(§2.5;param_N/long 手搓) |
| ActionActiveParam | cc:1794-1839 附近 | coreaction.rs:5827-5876 | PARTIAL(调 stub 模型链) |
| ActionFuncLink | cc:1474-1586 | coreaction.rs:6373-6600 | PARTIAL(硬编码 libc 表 coreaction.rs:1171-1334/6414/6475-6482;stack 参路径缺 rs:6463-6465 自述) |

---

## 5. 分阶段移植路线(按解锁的 coreaction Action 排序)

> 原则(AGENTS.md 铁律 1.5/1.6):从底向上补基础设施,禁止上层绕过。每阶段 = 一个可独立验收的最小闭包;验收一律 = locked 12.0.4 双侧 fixture(同输入同输出,机制 B2)。

### Phase 0 — 模型统一与静默 MISMATCH 修复(解锁:所有后续阶段;本身修复主管线语义)

1. **FSPEC-MODEL-UNIFY-0001**:`FuncCallSpecs::proto_model` 从 `type_system::protomodel::ProtoModel`(stub)切换为 `Arc<ProtoModelFull>`,由 Architecture `proto_models`/`defaultfp` 绑定(coreaction.rs:6029-6030/6451/6617 三处 set 点改造);`derive_input_map/derive_output_map/possible_input_param/characterize_*` 全部改走 ProtoModelFull.input/output 的忠实方法(fspec.rs:4932/5498/4991)。stub 文件保留为测试夹具或删除。**这一步让 fspec.rs:4932 的忠实 fillinMap 第一次接入主管线**。
2. **FSPEC-SPACEFILTER-0002**:删除 find_entry/unjustified_container/assumed_extension 的 `!= AddressSpace::Ram` 过滤(fspec.rs:4484/5018/5034),改为比较查询空间与 entry 空间(find_entry)/无过滤(另两个,对齐 cc:661-680/1411-1424/1426-1437)。
3. **FSPEC-TRIALCMP-0003**:`ParamActive::sort_trials` 改为 Ghidra comparator(entry group→entry 序→exclusion offset→reverseStack addr→size,cc:1893-1918);`split_lo` 地址改 `addr+(size-sz)`(cc:1859);split_hi/split_lo 复制 flags(cc:1847/1860);补单测覆盖 12/4 切分。
4. **FSPEC-INPUTVAR-0004**:补 `ParamActive::set_placeholder_slot`(hh:310)、`get_trial_for_input_varnode`(hh:1749)、`sort_fixed_position`(hh:317)。

验收:x86-64 + 一个非 x86(如 MIPS)cspec 下,callspec 参数恢复路径双侧同输出;paramdouble/activeparam fixture。

### Phase 1 — CA-1 最小闭包(trashset + extraPop + internalstorage;fspec.rs 单文件为主)

5. **FSPEC-TRASH-0005**:`FuncProto` 增加 `likelytrash: Vec<VarnodeData>` + trash_begin/trash_end;decode 停止折叠进 effects(fspec.rs:1195-1206 改为独立列表+decodeLikelyTrash 合并);has_effect/is_compatible 恢复独立语义;接通 `ActionLikelyTrash`(coreaction.cc:2140-2272 traceTrash 全观察)。解锁:ActionLikelyTrash、PrototypeWarnings trash 腿。
6. **FSPEC-EXTRAPOP-0006**:`FuncCallSpecs.effective_extrapop` 字段+访问器;`FuncProto::resolve_extra_pop` 实算法(cc:3971-3992);`FuncProto::param_shift` 实装(cc:3706-3760);接通 ActionExtraPopSetup(cc:1436-1466)与 StackPtrFlow phase-1(coreaction.cc:483-496;激活 rs:7218 死代码 analyze_extra_pop)。解锁:ActionExtraPopSetup、StackPtrFlow 完整、ActionParamshift。
7. **FSPEC-INTERNAL-0007**:`FuncProto::internal_iter`(委托 model,hh:1551);`ActionInternalStorage` 重写为模型区间→CALL/CALLIND 输入重建+markNotMapped(cc:4938-4975)。解锁:ActionInternalStorage。

### Phase 2 — ProtoStore 符号通道(依赖 FUNCDATA-LOCALSCOPE-OWNERSHIP-0001;解锁 FuncLink/UnjustifiedParams/参数命名)

8. **FSPEC-PROTOSTORE-0008**:在 FuncProto 上引入 store 二态(enum{Symbol(ScopeRef),Internal});`set_scope`(cc:3879)由 Funcdata 构造链调用(funcdata.rs:962 补全);`set_input_parameter` 走 ProtoStoreSymbol 语义:category-0 查询/重建/属性镜像/rename/retype(cc:3147-3214,复用 database.rs:2108/2920 已有 API);clearAllInputs 清 category。encode/decode `<internallist>`(cc:3421/3464)。
9. **FSPEC-FUNCLINK-0009**:删硬编码 libc 表(coreaction.rs:1171-1334、6414、6475-6482),FuncLink 改读 callspec 锁定 FuncProto(cc:1474-1586):opStackLoad/createPlaceholder 栈参路径、getSpacebaseRelative、commitNew* 真实化。解锁:ActionFuncLink 完整、ActionPrototypeTypes locked 腿。

### Phase 3 — 输出/输入 trial 闭环(依赖 Phase 0/2)

10. **FSPEC-OUTTRIAL-0010**:实现 `collect_output_trial_varnodes`(cc:5536)+ `FuncCallSpecs::check_output_trial_use`(cc:5661);ActionActiveReturn 四步接全,`build_output_from_trials`(rs:2598)接入并补 findPreexistingWhole(cc:5750)与 precisLo/Hi。返回真实 change 计数。解锁:ActionActiveReturn、ReturnRecovery 撤播种的前提之一。
11. **FSPEC-INBUILD-0011**:`build_input_from_trials` 补全(cc:5685-5741 五缺失项);`create_placeholder`/`resolve_spacebase_relative`(cc:4849/4870);`check_input_join`/`do_input_join`(cc:5349/5376)。解锁:ActionParamDouble、ActionJoinParam 系列。

### Phase 4 — merged 模型族(独立,可与 Phase 2/3 并行,write-set 无重叠)

12. **FSPEC-MERGED-0012**:ScoreProtoModel(cc:2705-2778)、ProtoModelMerged(foldIn/selectModel/decode,cc:2780-2922)、ParamListMerged::foldIn(cc:1794)、UnknownProtoModel(hh:1025);intersect_effects/intersect_registers 从 ProtoModelFull 迁回;`<resolveprototype>` decode(arch.rs:1855 CSPEC-PARAMMODEL-0001 关闭);`resolve_model` 实装。解锁:多 ABI cspec 支持。
13. **FSPEC-REGISTERLIST-0013**:ParamListRegister::fillinMap(cc:1542)+ buildParamList 真分派;ParamEntryRange rangemap(可后置,线性扫描已语义等价,但 position subsort 影响同偏移多 entry 查询序)。

### Phase 5 — 编解码与收尾

14. **FSPEC-ENCDEC-0014**:FuncProto encode/decode 失真项(§3.E 全清单)。
15. **FSPEC-RECOVER-0015**:lateRestriction/forceSet/insertPcode 实体化(hook 转 fn);isOverride/isStackOutputLock/matchCallCount/paramshift 字段;copyFlowEffects 语义修正;updateInputNoTypes/updateOutputNoTypes/getThisPointerStorage。

---

## 6. TODO 登记清单(拟)

| ID | 主题 | write-set | 依赖 | 验收(locked 12.0.4 双侧 fixture) |
|---|---|---|---|---|
| FSPEC-MODEL-UNIFY-0001 | callspec 绑定 ProtoModelFull | src/{fspec,coreaction,arch}.rs, docs/api/*.md | — | 同一 cspec+fixture,Ghidra oracle 与 Rugra 的 fillinMap trial 终态(used/defnouse/slot)零差异 |
| FSPEC-SPACEFILTER-0002 | 删 Ram-only 过滤 | src/fspec.rs, docs | 0001 | register/stack 空间 possibleParam/characterize 双侧枚举一致 |
| FSPEC-TRIALCMP-0003 | sort comparator+split_lo+flags | src/fspec.rs | — | trial 排序序列与 split 后 (addr,size,flags) 双侧一致 |
| FSPEC-INPUTVAR-0004 | placeholder/fixedPosition/getTrialForInputVarnode | src/fspec.rs | — | cc:1920/5700 行为 fixture |
| FSPEC-TRASH-0005 | FuncProto.likelytrash+ActionLikelyTrash | src/{fspec,coreaction}.rs, docs | — | trash 寄存器 fixture:INDIRECT/INT_AND 截断+count 全观察 |
| FSPEC-EXTRAPOP-0006 | effective_extrapop+resolveExtraPop+paramShift | src/{fspec,coreaction,funcdata}.rs, docs | — | extrapop≠0 ABI(如 __stdcall)i386 fixture:SP 调整 op 序列双侧一致 |
| FSPEC-INTERNAL-0007 | FuncProto::internal_iter+ActionInternalStorage | src/{fspec,coreaction}.rs, docs | — | 带 internal_storage cspec fixture:CALL 输入重建双侧一致 |
| FSPEC-PROTOSTORE-0008 | ProtoStoreSymbol 通道 | src/{fspec,funcdata,database}.rs, docs | FUNCDATA-LOCALSCOPE-OWNERSHIP-0001 | setInput 后 category-0 符号表内容(名/型/地址/锁)双侧一致 |
| FSPEC-FUNCLINK-0009 | 删 libc 表,FuncLink 真实化 | src/{fspec,coreaction}.rs, docs | 0008 | curl/httpd 差分:defects=0 且无新增 numbering |
| FSPEC-OUTTRIAL-0010 | checkOutputTrialUse+buildOutputFromTrials 接通 | src/{fspec,coreaction}.rs, docs | 0001 | 双 trial join 返回值 fixture:op 图+precis 双侧一致 |
| FSPEC-INBUILD-0011 | buildInputFromTrials 全量+placeholder/join | src/{fspec,coreaction}.rs, docs | 0001,0004 | 栈参+unref 参 fixture:opSetAllInput 终态双侧一致 |
| FSPEC-MERGED-0012 | ScoreProtoModel/ProtoModelMerged/resolveprototype | src/{fspec,arch}.rs, docs | 0001 | 多模型 cspec:selectModel 评分与选中模型双侧一致 |
| FSPEC-REGISTERLIST-0013 | ParamListRegister::fillinMap | src/fspec.rs, docs | 0001 | register 策略 cspec 空洞 fixture |
| FSPEC-ENCDEC-0014 | FuncProto encode/decode 保真 | src/fspec.rs, docs | 0005 | decode(encode(x))==x 双侧;voidlock/extrapop/internallist round-trip |
| FSPEC-RECOVER-0015 | lateRestriction/forceSet/insertPcode/杂项 | src/{fspec,coreaction}.rs, docs | 0008 | deindirect 全路径 fixture |

并发注意(铁律 6):0005/0006/0007 同在 src/fspec.rs+coreaction.rs,须串行同 writer;0012 只碰 fspec.rs 的 merged 区+arch.rs,与 Phase 2/3 的 write-set 无重叠可并行。

---

## 7. 附录:双模型栈数据流(现状)

```
Architecture (arch.rs:476 proto_models: BTreeMap<String, Arc<ProtoModelFull>>)   ← cspec <prototype> 解码(忠实)
   │ defaultfp / evalfp_called
   ▼
FuncProto.model: Arc<ProtoModelFull> (fspec.rs:246)   ✅ 忠实
   │ characterize/has_effect/get_pieces...
   ▼ (主管线 Funcdata 级查询正确)

FuncCallSpecs.proto_model: type_system::protomodel::ProtoModel (fspec.rs:1701)  ❌ stub
   ▲ 唯一写入点: coreaction.rs:6030 / 6451 = ProtoModel::default_x86_64() (硬编码 SysV)
   │ derive_input_map → stub.fillin_input_map (protomodel.rs:185, 自述 simplified)
   │ 而 fspec.rs:4932 ParamListStandard::fillin_map (忠实, 对齐 cc:1285) 无调用方
   ▼
ActionActiveParam/FuncLink 的 callspec 参数恢复全部由 stub 决定
```

修复方向即 FSPEC-MODEL-UNIFY-0001:右列消灭,箭头改指 `Arc<ProtoModelFull>`。

---

## 8. 结论

- 六条线索全部证实;其中 trashset(§2.1,decode 折叠污染 effects)与 resolve_model(§2.6,根因是 merged 族整类缺失+双模型栈)比 COREACTION_GAPS_2026-08-22 的描述更深。
- 新发现 7 项,最重要的是 **双模型栈分裂(§3.A)** —— 它使 fspec.rs 内已忠实移植的 ~150 行 ParamListStandard 算法在主管线上是死代码,所有 callspec 级模型决策由 315 行硬编码 SysV stub 决定。
- **最先该做的最小闭包 = Phase 0(FSPEC-MODEL-UNIFY-0001 + FSPEC-SPACEFILTER-0002 + FSPEC-TRIALCMP-0003)**:不新增 Ghidra 机制,只消灭 Rugra 自创的简化路径与三个静默 MISMATCH,即可让既有忠实代码接入主管线,并为 CA-1(trash/extrapop/internalstorage)提供正确地基。
- 函数账本建议:fspec 族当前整体状态 **L2 以下**(核心算法大量存在但主管线走 stub; ProtoStore 符号通道/merged 族/trashset 缺失),不得标 L3。

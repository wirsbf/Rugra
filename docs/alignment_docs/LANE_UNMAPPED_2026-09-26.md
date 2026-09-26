# LANE UNMAPPED 终报 — 真缺失 2645 结构化分诊与工作包打包（2026-09-26）

> **归档注记（2026-09-26,Lane REBASE0/WORKPKG-UNMAP-REBASE-0000）**: 本报告归档自内存盘
> `/dev/shm/rugra-reports/LANE_UNMAPPED_2026-09-26.md`（来源车道 UNMAPPED,2026-09-26
> 交付,纯分析零 src 改动;内存盘易失,本件为 docs/alignment_docs/ 持久化归档,
> 除本注记外与源文件逐字节一致）。本归档件即 UNMAPPED 工作包的**权威包表与全部数字
> 唯一来源**（§1 时效勘误/§1.1 recall-gap/§4 十八工作包/§5 波次/§6 交叉核对）;
> TODO_BOARD「UNMAPPED 工作包池」为其登记形态。

> **车道**: UNMAPPED（纯分析，零 src 改动，零 commit；直接读主仓 /home/ls/Rugra @ master 377385fe）。
> **任务**: 把 DECOMP 车道四类分解中的**真缺失 2645** 转化为可派发工作包（分诊维度=可观测面冲击/域归属/依赖序/工作量级），P0=能解释现有残差的缺失项排最前。
> **数据源**: `docs/alignment_audit/UNMAPPED_DECOMPOSITION_2026-09-26.md` + `/dev/shm/rugra-reports/decomp/classified_final.json`（checkpoint `80ffb7d1`，REGEN 账本 9494=映射 4538+未映射 4956）+ `FUNCTION_MAP.md` + 6 份 GAPS 审计 + `TODO_BOARD.md`（3207 行全量通读）+ 三份残差归因审计（CURL_CANON / HTTPD_MAIN / MIRROR_RESIDUAL / SQFACE）。
> **残差基线锚**（派单口径 = MERGEBATCH17 集成态 `14ca6d19`，亲核 TODO:3199）: canon curl **200/0/0**、canon httpd **229/0/0**（main 13）、镜面 curl 58/65 · httpd 156/156 · vsh 15/16 · **sq 4481**/7500（记账态）· sqlite 26833/1385/1385。
> **只读合规**: 本车道未改任何 repo 文件、未跑构建；全部结论基于账本+审计既有数据+grep 存在性抽查。

---

## §1 快照时效勘误（最重要发现）——2645 是过期分母，当前真缺失 ≈ 2290

`classified_final.json` 生成于 REGEN checkpoint `80ffb7d1`（2026-09-26 早晨）。**同日下午以下车道已落地并集成**，消耗了快照中的部分真缺失项：

| 已落地车道 | 消耗簇 | 消耗 defs（估） | 证据 |
|---|---|---:|---|
| MIGW-FSPEC | fspec 136 | 136 | TODO:77-102（136 条全部处置） |
| MIGW-TYPEOP | typeop 52 push + PTRADD push | 53 | TODO:684（三层承载落地） |
| MIGW-FUNCDATA | funcdata 77/80 | 80 | TODO:3166（含 7 依赖阻塞转 FUNCDATA-ENCODE-DEP-0001） |
| MIGW-DATABASE | database 63（phase1+2） | 63 | TODO:24（残余 ~13 已列名） |
| F8FOR | block.cc WhileDo 六函数族 | ~8 | TODO:2950 |
| F7NAME | varmap.hh NameRecommend 族 + coreaction lookForFuncParamNames/makeRec | ~8 | TODO:2959 |
| RESIDE | merge.hh StackAffectingOps + cover.hh PcodeOpSet 族 | ~4 | TODO:2935 |
| PKGG/SUBCOMMUTE/DATATYPEPR/PRINTCS 等 | 行为修复，defs 消耗 0-2 | ~2 | 各 lane 行 |

**净消耗 ≈ 354 → 主管线真缺失 1799 → ~1445；全层 2645 → ≈2290**（±20，个别 lane 记账粒度差异）。
**推论**: 每个工作包的 **step 0 必须是 ledger 再基线**（`python3 tools/generate_function_ledger.py` 在当前 master 重跑 + 与 80ffb7d1 快照 diff），避免对着过期清单移植已存在物。

### §1.1 Recall-gap 校准（"missing"≠"不存在"）

对快照中 12 个关键缺失名做 Rust 侧 grep 存在性抽查：

| 快照缺失项 | Rust 侧实测 | 判定 |
|---|---|---|
| block.cc:3164 findLoopVariable | `while_do_find_loop_variable` 已在（F8FOR） | **已消耗**（快照过期） |
| type.cc resolveInFlow/findResolve 族 | `resolve_in_flow` 在 datatype/coreaction/unionresolve（PKGG 删死孪生） | **部分存在**——虚分派族残项需逐臂核验 |
| coreaction.cc:2858 lookForFuncParamNames | F7NAME 证"此前已移植"（改名族） | **未链接候选**（应转 REGEN 边） |
| varmap.hh NameRecommend 族 | `name_recommend` 存储在 varmap.rs:2535（F7NAME） | **已消耗** |
| printc emitSwitchCase | `emit_switch_case` 在 printc.rs | **部分存在/形态核验** |
| stringmanage getStringData | `get_string_data` 在（STRNCPY 只接 hash 通道） | **部分存在**（惰性读载缺） |
| coreaction.cc:2206 protectSwitchPathIndirects | 无对应物 | **真缺失** ✅ |
| printc.cc:3357 genericFunctionName | 无对应物 | **真缺失** ✅ |
| printc.cc:233 emitSymbolScope | 无对应物 | **真缺失** ✅ |
| printc.cc:2067 pushMismatchSymbol | 无对应物 | **真缺失** ✅ |
| varmap.cc:1457 remapSymbol/remapSymbolDynamic | 无对应物 | **真缺失** ✅ |
| blockaction.cc:1378 ruleBlockProperIf | `try_rule_proper_if` 在（F5 审计亲证） | **未链接候选** |

**结论**: 真缺失口袋内混有两类——①**真待移植/补全**（上表 ✅ 形态）；②**改名/形态偏移的未链接**（应走 REGEN 注解边而非移植）。这与 DECOMP 报告 §5"召回下界声明"一致（funcdata 迭代器族已按此处理）。分诊按"先核验后移植"原则执行，包内逐项标注预估核验/移植比。

---

## §2 方法

1. **簇聚合**: classified_final.json 按 Ghidra 文件簇（去 .cc/.hh 后缀）聚合 1799 条主管线真缺失 → 63 簇（top18 覆盖 ~92%）。
2. **可观测面归因交叉**: 逐簇对照四份残差族审计（curl 267 族表 21 族 / httpd main 499→13 族链 / 镜面 132/265/41→58/156/15 的 12+ 族 / sq 4481 的 11 族），能解释现有残差行的缺失项 → P0。
3. **域归属**: 簇 → src 模块（`docs/api/` 1:1 镜像惯例）+ 现有租约/持有状态（TODO 通读）。
4. **依赖序**: 按 AGENTS 铁律 6 构建 DAG（地基=type/typeop/cast → setcasts/unionresolve → printc 发射；funcdata/database → varmap；marshal/xml → 各 encode/decode）。
5. **工作量**: Ghidra span 合计（快照字段）× 1.6 系数 + B2 fixture 数；S<50 行 / M 50-300 / L>300（Rust 口径）。
6. **防重复**: 与 TODO_BOARD 现有票（含 MIGW1 票池、MIRATTR/CURLCANON/HTTPDMAIN/GEN4/SQ 票族、MERGEBATCH 台账）逐条交叉。

---

## §3 维度统计

### 3a. 可观测面冲击（@ 残差基线 curl 200 / httpd 229 / sq 4481 / 镜面 58·156·15）

| 冲击层 | 定义 | 项数（快照口径，簇级估） | 代表簇 |
|---|---|---:|---|
| **P0-直接解释残差** | 缺失函数本体/直接臂在现有残差族根因链上 | **~282**（MIGW 后残量） | typeop getInputCast/getOutputToken 族（curl A 族 45 行 + CASTFUSE-B）、type.cc union resolve/truncation 族（curl D 族 46 行）、coreaction setcasts 辅助族（A/CASTFUSE）、printc 单例 15（F-STRFOLD/F-PLTNAME/curl O 族/F-DECL）、varmap remap 族（sq STACKSLOT 域）、constseq（F-STRFOLD） |
| **P1-主管线完整性** | 无现行残差行但属主管线闭包/未来观测杠杆 | ~620 | block/blockaction 结构面残项、modelrules fillinOutputMap、action debug/print 面、transform、jumptable JT 族、funcdata encode（依赖阻塞）、ruleaction 算法残项 15 |
| **P2-休眠路径** | 错误注入/冷门架构/持久化协议/未接线分析器面 | ~543（main）+228（periphery） | XML encode/decode 家族 84、sleigh_arch 48、architecture XML 面、grammar/pcodeparse bison 骨架 39、periphery 228 |
| **豁免** | UI-控制台桥（AGENTS 明文豁免；decomp 协议对拍票未开） | 618 | ifacedecomp/codedata/*_ghidra 族 |

### 3b. 域归属（簇 → src 域 → 当前持有状态）

| Ghidra 簇 | 快照缺失 | 消耗后 | src 域 | 持有/租约状态 |
|---|---:|---:|---|---|
| ruleaction | 239 | ~239 | src/ruleaction.rs | 空闲（binsweepfix/subcommute 已并） |
| typeop | 160 | ~107 | src/typeop.rs | migtypeop 已收，释放 |
| block+blockaction | 145 | ~137 | src/block.rs+blockaction.rs | blockfinal/f8for 已收，机制 C 白名单 |
| coreaction | 101 | ~99 | src/coreaction.rs | f4webtype 已并（MB17），空闲 |
| type | 88 | ~88 | src/type_system/datatype.rs+typefactory.rs | datatypepr/tfsingle 已收 |
| printc | 68 | ~15 | src/printc.rs | **阻塞**: fspecdein/curlfam 在飞（grep 亲核）+ HERMETICITY-TYPEDEF-LATCH P2 |
| database | 76 | ~13 | src/database.rs | migdatabase 已收，残余已列名 |
| architecture+sleigh_arch+userop+modelrules+globalcontext+options | 41+48+27+17+13+4=150 | ~150 | src/arch.rs 等 | tfsingle/cspecglobal 已并 arch.rs，sleigh_arch 无既有 Rust 主体 |
| marshal+xml | 84 | ~84 | src/marshal.rs | 空闲 |
| action | 30 | ~30 | src/action.rs | piperestart 已收 |
| jumptable | 28 | ~28 | src/jumptable.rs | 机制 C 白名单，空闲 |
| funcdata(+_block/_op) | 80 | ~2+2+1 | src/funcdata.rs | migfuncdata 已收；encode 族=FUNCDATA-ENCODE-DEP-0001 |
| varmap | 25 | ~19 | src/varmap.rs | genwire 已并；VARMPOISON 在飞（写域 varmap.rs!） |
| grammar+pcodeparse | 39 | ~39 | src/grammar.rs+pcodeparse.rs | 空闲（裁决非移植） |
| constseq/stringmanage/cast | 13+3+6 | 同 | src/constseq.rs/stringmanage.rs/type_system/cast.rs | printc 邻接；cast 空闲 |
| 其余工具簇（address/space/translate/transform/op/varnode/partmap/rangemap/unify/comment/cover/…） | ~120 | ~120 | 各对应 .rs | 空闲 |
| periphery 228 / ui-console 618 | — | — | （emulate.rs/printjava 等无主体） | 豁免/未接线 |

### 3c. 依赖 DAG（地基→上层）

```
L0 地基: type.cc resolve/truncation 族 ── typeop getInputCast/getOutputToken ── cast.cc 残项
            │                                    │
L1 仲裁:    └──> unionresolve (ScoreUnionFields 评分/采纳门槛) ──> coreaction setcasts 辅助族
                                                     │
L2 命名:   varmap remap/MapState 残项 <── database 残余 13 <── funcdata (已收)
            │
L3 发射:   printc 单例 15（pushMismatchSymbol/emitSymbolScope/push_float/…）<── stringmanage getStringData
            │                                                <── constseq StringSequence
L4 结构:   block/blockaction 残项（encode/decode+verify 面；算法面已由 F5/F8/SWGOTO/BLOCKFINAL 收）
L5 持久化: marshal/xml <── funcdata/jumptable/block encode（FUNCDATA-ENCODE-DEP-0001 语义）
L6 装载:   sleigh_arch/architecture XML 面 <── userop/modelrules decode <── globalcontext/options
L7 外围:   rulecompile <── expression/multiprecision；emulate <── jumptable EmulateFunction 残项；paramid（F7NAME 邻接）
```

### 3d. 工作量分布（消耗后 ~2290 项）

| 量级 | 包数 | 项数（估） | 说明 |
|---|---:|---:|---|
| S（<50 行 Rust） | 5 | ~60 | 单点函数/访问器族/裁决票 |
| M（50-300） | 7 | ~480 | 簇内算法残项+fixture |
| L（>300） | 4 | ~1290 | 含两个 XL（ruleaction 裁决 235、XML 持久化 84+encode 闭包） |
| 豁免/暂缓 | — | 846 | ui-console 618 + periphery 主体 |

---

## §4 工作包全表

> ID 格式 WORKPKG-UNMAP-\<域\>-NNNN。**全部为建议，root 裁决后入 TODO_BOARD。**
> 每包共通验收骨架：step0 ledger 再基线 diff → 逐项"核验（已存在→REGEN 链接）/移植/裁决"三态记账 → 每个实移植 def 一份 B2 双侧 fixture（锁定 oracle e40ed130，同输入/同输出）→ `// Ghidra:` 注解 + annotations/refs 三门禁 → canon 双语料 + 镜面五面 + bank 391/391 零回退 → docs/api 同 commit。

---

### P0 包（能解释现有残差——对齐收敛直接杠杆）

#### `WORKPKG-UNMAP-TYPEOP-0001` — typeop getInputCast/getOutputToken 虚分派残项（P0）
- **包内项**: typeop.cc 残 ~107 中的 cast 仲裁族——`TypeOpPtradd::getInputCast`(2250,17行)/`FloatInt2Float`(1847)/`IntRight`(1543)/`NotEqual`(996)/`IntSdiv/Rem/Srem`(1659/1679/1699)/`IntSless(+Equal)`(1023/1049)/`IntLessEqual`(1099)/`IntSext`(1157)/`absorbZext`(1872)/`getInputLocal`(Indirect 1992/Cbranch 609/Callother 855)/`getOutputToken` 族(Piece 2063/IntLeft 1518/IntRight 1558 等)/`propagateAcrossCompare`(963,24行)/`registerInstructions`(24,85行=表核验)。**排除** selectJavaOperators(114,34行)=Java 专用休眠 → 归 P2-13。
- **域**: src/typeop.rs（+ type_system/cast.rs 联动臂）。
- **oracle 锚**: typeop.cc:{24,609,855,963,996,1023,1049,1099,1148,1157,1518,1543,1558,1659,1679,1699,1847,1872,1992,2037,2063,2116,2250}; typeop.hh 对应声明行。
- **可观测面**: **curl A 族 45 行**（PROTOCAST——castInput 逐臂仲裁正是此虚分派族；CURLCANON-A 修复规格"先 fixture 钉 castStandard 返回 None vs Some 的臂"即本包）；sq CASTFUSE-B 残量；F-TYPE/SEXT48 收敛后残余 cast 形。
- **验收**: B2=每 getInputCast/getOutputToken 臂一组双侧构造 fixture（参照 typeop_push_dispatch_1204 先例可按 op 家族合并）；语料面=curl getparameter/my_get_line `--func` defects=numbering=0 且 A 族行数下降或归因转移。
- **依赖**: 无（地基）；与 `WORKPKG-UNMAP-COREACT-0002` 并行但 fixture 互引（setcasts 消费 getInputCast）。
- **量级**: **M**（~30 实臂 ×10-17 行 + 核验 registerInstructions 表）；机制 B 白名单（printc 差分门禁）。
- **优先级**: **P0**（单包理论收益 −45 curl 行，最大直接杠杆）。

#### `WORKPKG-UNMAP-COREACT-0002` — coreaction 真缺失算法残项（P0）
- **包内项**: 39 实移植项头部——`ActionRestructureVarnode::protectSwitchPathIndirects`(2206,**53行**,亲证真缺失)/`protectSwitchPaths`(2262)/`ActionLikelyTrash::traceTrash`(2047,**92行**)+`countMarks`(2007)/`ActionSetCasts::checkPointerIssues`(2349)/`ActionInferTypes::canonicalReturnOp`(5311)+`propagationDebug`(4980)+`PropagationState::step/ctor`(5139/5115)/`ActionConditionalConst::flowTogether`(4174)/`ActionPrototypeTypes::extendInput`(4590)/`isDelayedConstant`(2187)/`isCopyConstant`(2174)+62 clone-family 裁决。**排除**: lookForFuncParamNames/makeRec（已移植→REGEN 边）。
- **域**: src/coreaction.rs。
- **oracle 锚**: coreaction.cc:{2007,2047,2174,2187,2206,2262,2349,2815,2858,4174,4590,4980,5115,5139,5311}。
- **可观测面**: checkPointerIssues→curl A 族值侧 cast；protectSwitchPathIndirects→switch/goto 残余族（SWITCH-GOTO sq 记账 4481 内残留 + BLOCKSTRUCT 域）；traceTrash→fspec trashset（COREACTION_GAPS 列为 DAG 根：trash 参数面，疑与 UNAFF-EXTRAOUT 555 行族部分相关——**需深挖**，不可宣称）；ACTION-COUNTHARVEST-FAMILY-0001（P3 排队票）同域可搭车。
- **验收**: B2=protectSwitchPathIndirects/traceTrash 各一组双侧 fixture（switch 间接路径 + trash 标记传播构造）；语料面=curl/httpd canon + sq `--one` 405/680 抽查。
- **依赖**: TYPEOP-0001 的 getInputCast（setcasts 消费序）。
- **量级**: **M-L**（39 defs/~450 Ghidra LOC，traceTrash 92 行最重）。
- **优先级**: **P0**（A 族次级杠杆 + switch 域完整性）。

#### `WORKPKG-UNMAP-TYPEUNION-0003` — type.cc union/struct 解析仲裁残项（P0）
- **包内项**: `TypeStruct::nearestArrayedComponentForward/Backward`(1698/1669,43+28行)/`TypeUnion::findTruncation`(2185)/`TypeStruct::findTruncation`(1624)/`resolveInFlow` 虚分派族（TypePartialUnion 2498/TypeArray 1283/TypeStruct 1929/TypeUnion 2125——**先核验** PKGG 后哪些臂缺）/`findCompatibleResolve`(1954/1308)/`TypeFactory` 残项（recalcPointerSubmeta 3724/setName 3445/removeWarning 3761/getTypePointerWithSpace 4055/destroyType 4122）/`setFields`(1563)/`decodeFields`(2014)/`string2typeclass`(371,41行)+`metatype2typeclass`(420)/encode 面（TypeChar 822 等，P2-12 候选）。15 clone 裁决。
- **域**: src/type_system/datatype.rs + typefactory.rs。
- **oracle 锚**: type.cc:{371,420,822,869,920,1283,1308,1563,1624,1669,1698,1929,1954,2014,2125,2185,2498,2517,3445,3724,3761,4055,4122}。
- **可观测面**: **curl D 族 46 行**（UNIONSTORE 仲裁——CURLCANON-D 根因方向③"downChain 对 union 下降语义/ScoreUnionFields 采纳门槛/逐站点解析仲裁"正是 nearestArrayedComponent+findTruncation+resolveInFlow 族）；F-TYPE 数组元素型派生。
- **验收**: B2=union store 8+1 站点形态双侧 fixture（配合 CURLCANON-UNIONSTORE-ARBITRATION-0001 票的 oracle resolveInFlow drill；**注意该票要求先等 wt/printcs 合并重测——已并，可启动**）；语料面=curl main `--func` D 族行收敛。
- **依赖**: 无（地基）；消费方=unionresolve/coreaction。
- **量级**: **M-L**（73 defs/~680 LOC，但 ~30% 预估为核验/已存在）。
- **优先级**: **P0**（单函数 main 最大池 −46）。

#### `WORKPKG-UNMAP-PRINTC-0004` — printc 单例发射族残项（P0，租约受限）
- **包内项**: cc 侧 ~15 实缺——`push_float`(1380,45行)/`checkAddressOfCast`(376,43行)/`pushImpliedField`(2085,32行;绑定既有票 UNIONRESOLVE-PKG-H-0001)/`emitSwitchCase`(3129,30行,**先核验**部分在)/`emitSymbolScope`(233,27行)/`pushMismatchSymbol`(2067,17行)/`genericFunctionName`(3359,9行)/`setCommentStyle`(2350)/`initializeFromArchitecture`(2332)/`adjustTypeOperators`(2342)/`resetDefaults`(2325)/`pushTypePointerRel`(hh:365)/`doEmitWideCharPrefix`(1504)/`PendingBrace::callback`(2872;**已被 PENDINGBRACE 车道处理？核验**)/PrintCCapability(108,115)。hh 53 条 opXxx 已由 MIGW-TYPEOP 承载（排除）。
- **域**: src/printc.rs。
- **oracle 锚**: printc.cc:{108,115,233,376,1380,1504,2067,2085,2325,2332,2342,2350,2872,3129,3359}; printc.hh:365。
- **可观测面**: 镜面 F-STRFOLD（httpd ≥5 处字面量折叠，受 stringmanage 读载联动）/F-PLTNAME（genericFunctionName 2 行）/curl O 族 `_DAT` mismatch 3 行/F-DECL 声明序 ~23 行（emitSymbolScope 两序源）/F-WRAP（部分）。
- **验收**: B2=每单例一组双侧 fixture；语料面=镜面三面 + curl canon O 族。
- **依赖**: stringmanage（F-STRFOLD 联动）；**阻塞链=fspedein/curlfam 在飞 + HERMETICITY-TYPEDEF-LATCH-0002（P2 printc.rs）**——解封后首派。
- **量级**: **M**（15 defs/~315 LOC）。
- **优先级**: **P0**（解释镜面 4 族 + curl O 族）。

#### `WORKPKG-UNMAP-VARMAP-0005` — varmap remap/MapState 残项（P0，受 VARMPOISON 排队约束）
- **包内项**: `ScopeLocal::remapSymbol`(1457,19行)/`remapSymbolDynamic`(1485,15行)/encode(462)/decode(472)/`decodeWrappingAttributes`(479)/`MapState` dtor/next/turnOnDebug 族/RangeHint::compareRanges(hh:126)——NameRecommend 族已消耗（排除）。
- **域**: src/varmap.rs。
- **oracle 锚**: varmap.cc:{462,472,479,881,1457,1485}; varmap.hh:{126,190,191,201}。
- **可观测面**: **sq STACKSLOT-MATERIALIZE 2203 行族**（varmap ScopeLocal 晋升域主杠杆之一——remap 族是多 entry 符号重映射机制）；F-DECL multi-entry 首整映射；curl I 族声明漂移 8 行。
- **验收**: B2=remap 双侧 fixture（multi-entry 符号+范围分裂构造）；语料面=sq `--one` read_inode_2/GetOptimum 栈槽物化计数 + curl canon I 族。
- **依赖**: **排队于 VARMPOISON（在飞持 varmap.rs 写域）之后**；database 残余（P1-09）弱依赖。
- **量级**: **S-M**（~19 defs/~86 LOC 但 remap 语义敏感）。
- **优先级**: **P0**（sq 面最大族 2203 行的地基之一；机制 C 白名单）。

#### `WORKPKG-UNMAP-STRFOLD-0006` — constseq + stringmanage 字符串折叠残项（P0-小）
- **包内项**: `StringSequence::constructTypedPointer`(273,**67行**)/`collectCopyOps`(227)/`removeCopyOps`(415)/ctor(188)/`removeForward`(383)/`buildStringCopy`(347)/`transform`(453)+RuleStringCopy/Store clone（constseq.rs **先核验**——UNIONRESOLVE-ADJACENT 已证部分在+两退化形）; `StringManagerUnicode::getStringData`(427,49行,惰性读载臂——hash 通道已在，读载缺)。
- **域**: src/constseq.rs + src/stringmanage.rs。
- **oracle 锚**: constseq.cc:{188,227,273,347,383,415,453}; stringmanage.cc:427。
- **可观测面**: 镜面 F-STRFOLD（httpd 3/curl 1 行字面量折叠）+ httpd F6 数据模型伴族 + STRNCPY-PRINT-CALLOTHER 域邻接。
- **验收**: B2=getStringData 惰性读载（同 `.rodata` 串双侧逐字节）+ constructTypedPointer 形态；语料面=镜面 `= "` 折叠计数 ≥5 对齐 golden。
- **依赖**: 无（与 PRINTC-0004 的 F-STRFOLD 消费端并行开发、串行集成）。
- **量级**: **S-M**（16 defs/~300 LOC）。
- **优先级**: **P0-尾**（行数小但独立便宜）。

---

### P1 包（主管线完整性，DAG 层序）

#### `WORKPKG-UNMAP-BLOCK-0007` — block/blockaction 结构面残项（P1；= MIGW1-BLOCK-0003 重定义收窄）
- **包内项**: 消耗后 ~137——`BlockGraph::selfIdentify`(895,37)/`isConsistent`(2218,34)/`checkEdges`(545,28)/`spliceBlock`(1597)/`removeFromFlow(+Split)`(1545/1575)/工厂族 newBlockIfGoto/newBlockList/newBlockSwitch(1799/1758/1904)/`BlockMap::find/resolveBlock`(3685/3665)/`BlockSwitch::nextFlowAfter`(3639,23)/printRaw 族(1300/2672/2688)/encode/decodeBody 族(1373/1401+2938/3137→**转 P2-12 持久化**)/blockaction TraceDAG/LoopBody/ConditionalJoin 残项（**高核验比**——F5/BO/SWGOTO 审计证大部分在：ruleBlockProperIf/ruleBlockCat/ruleBlockIfNoExit/ruleBlockDoWhile/labelLoops/onlyReachableFromRoot 等均为未链接候选）+7 clone。
- **域**: src/block.rs + src/blockaction.rs（机制 C 白名单）。
- **oracle 锚**: block.cc:{545,895,1300,1373,1401,1545,1575,1597,1758,1799,1904,2218,2672,2688,3639,3665,3685}; blockaction.cc:{473,489,499,541,555,565,576,586,603,635,940,951,958,1021,1052,1083,1126,1284,1378,1481,1555,1898,2065,2094}。
- **可观测面**: 当前无直接残差行（F5/F8/SWGOTO/ORDERBLOCKS/LABELBUMPUP/BO 已收）；价值=**结构完整性防回归面**（isConsistent/checkEdges=selfIdentify 校验器，是后续所有 blockaction 修复的 B2 夹具地基）+ deadregion/goto_cascade 两 MISMATCH fixture 的残余（IDENTIFY-BOUNDARY/DEADREGION-COLLAPSE 票域邻接）。
- **验收**: B2=校验器族（selfIdentify/isConsistent/checkEdges）双侧 fixture 一次覆盖 + 工厂族构造等价；核验转 REGEN 的比率 ≥40% 预期。
- **依赖**: 无；机制 C 强制。
- **量级**: **L**（~80 实处置，~700 LOC；encode/decode 拆出后）。
- **优先级**: **P1**。

#### `WORKPKG-UNMAP-MODELRULES-0008` — modelrules 装载/分配动作残项（P1）
- **包内项**: `MultiSlotDualAssign::fillinOutputMap`(1242,57)/`MultiSlotAssign`(902,51)/`MultiMemberAssign`(1019,29)/`ConsumeAs`(1345,20)/`AssignAction::decodeAction/decodeSideeffect/decodePrecondition`(592/653/630)/`DatatypeFilter::decodeFilter`(252)/`QualifierFilter::decodeFilter`(451)/ModelRule dtor 族。
- **域**: src/modelrules.rs（fspec.rs 邻接）。
- **oracle 锚**: modelrules.cc:{252,451,476,539,592,630,653,902,1019,1242,1345,1623}。
- **可观测面**: 无直接现行残差行；=fspec 参数绑定模型的 **spec 驱动半边**（MIGW-FSPEC 已收手写半边，本包补 XML 规则装载+分配动作）——未来 cspec 差异语料的防御面；DECOMP 抽样已证 fillinOutputMap 真缺失（MultiSlotDualAssign）。
- **验收**: B2=fillinOutputMap 三动作双侧 fixture（构造 ModelRule 树同输入）；decode 族与 MARSHAL-0012 同一 XML 语料。
- **依赖**: MARSHAL-0012（decode 原语）弱依赖，可先行手写 decode。
- **量级**: **M**（17 defs/~290 LOC）。
- **优先级**: **P1**。

#### `WORKPKG-UNMAP-DATABASE-0009` — database 残余聚合面（P1-小；MIGW-DATABASE 续派）
- **包内项**: MIGW-DATABASE 已列名残余 ~13——`addDynamicMapInternal` whole-count/categorySanity/multi_entry_symbols/`resolveExternalRefFunction`/`decodeWrappingAttributes`（与 VARMAP-0005 共票面分流）/children 迭代器/`printEntries` 聚合面+快照残余 `resolveScope`(1315,31)/`Database::resolveScopeFromSymbolName`(3113)/`findCreateScopeFromSymbolName`(3151)/`findDistinguishingScope`(1481)/`hashScopeName`(880)。
- **域**: src/database.rs。
- **oracle 锚**: database.cc:{880,1315,1481,1874,1992,3113,3151}。
- **可观测面**: F-RAM 伴族（PIRAM 在跑勿撞——集成后再派）；GENDRIVER-SYMTAB-DB-0001 的 query_container 通道健全性。
- **验收**: B2=database_scope_tree_1204 fixture 扩 case（scope 解析路径）；语料面=curl/httpd canon 恒等（预期中性）。
- **依赖**: PIRAM 集成（funcdata 写域）；VARMAP-0005 串行。
- **量级**: **S-M**。
- **优先级**: **P1-尾**。

#### `WORKPKG-UNMAP-ACTIONDBG-0010` — action 注册/debug/打印面残项（P1-小）
- **包内项**: `ActionPool::print`(753,23)/`printState`(777)/`turnOnDebug/turnOffDebug`(937/950)/`printStatistics`(964)/`Action::printState`(148)/`print`(132)/`ActionGroup` 族(428/444/585/597/610)/`Rule::turnOnDebug/OffDebug`(669/682)/`ActionDatabase::cloneGroup`(1077)/`Action::Action`(27)。
- **域**: src/action.rs。
- **oracle 锚**: action.cc:{27,67,80,93,132,148,364,428,444,585,597,610,622,669,682,697,728,753,777,937,950,964,976,1077}。
- **可观测面**: 无 canon 行；=**观测基础设施**——OPACTION_DEBUG 面（MIGWFUNCDATA 已开 14 观察函数）的 print/printState 是未来所有 Action 域 fixture 的调试对照面；与 ACTION-COUNTHARVEST-FAMILY-0001（P3 排队）同 write-set 搭车。
- **验收**: B2=print 树形态双侧 fixture（同 action 树逐字）。
- **依赖**: 无。
- **量级**: **S-M**（30 defs/~256 LOC，多为机械）。
- **优先级**: **P1**。

#### `WORKPKG-UNMAP-FLOWUTIL-0011` — 通用工具/基础设施残件（P1；transform 优先）
- **包内项**: **transform**（`TransformOp::createReplacement` 225,26行=live!RuleSplit*/subvar 变换管理器地基;LanedRegister 族）/varnode（`VarnodeBank::verifyIntegrity` 1971,36/endLoc 重载族/printCover/setDef）/op（PcodeOp ctor 71/clear 族 hh 单行→裁决）/address（`AddrSpace::read` space.cc:255,44/get_offset_size/byte_swap/popcount/bit_transitions/zero_extend）/translate（AddrSpaceManager 族 17）/variable（verifyCover 920,19/VariablePiece 族）/merge 残（groupPartialRoot 1374,34——**机制 C**）/heritage 残（verify_dfs 2013,29=debug 断言）/cover/comment/rangemap/partmap/unify/pcoderaw/pcodeinject/inject_sleigh/memstate/loadimage/options/compression/double/float/cpool/override/prefersplit/opcodes/signature/pcodecompile 尾簇。
- **域**: 对应各 src/*.rs（分散，按文件释放逐片并入）。
- **oracle 锚**: transform.cc:225/284; varnode.cc:1971/1762/1693/394/269; space.cc:255/224; merge.cc:1374; heritage.cc:2013;（余略，包内清单逐项带锚）。
- **可观测面**: transform::createReplacement=split 规则族行为地基（subvar/splitcopy/splitload/splitstore——sq BYTELANE-STRUCT 票域邻接）；AddrSpace::read=spec 读值原语；余=debug/断言/访问器（中性）。
- **验收**: B2=transform createReplacement + merge groupPartialRoot（机制 C）两组；余类级 RUGRA-GLUE 文档化（胶水先例）。
- **依赖**: 无；**按文件租约串行**（merge.rs 与 DETERM/MERGEBATCH 冲突面注意）。
- **量级**: **M**（~120 defs，但 ≥60% 预估为单行裁决/文档化）。
- **优先级**: **P1**。

#### `WORKPKG-UNMAP-RULEADJ-0013` — ruleaction 算法残项 + 工厂等价裁决（P1；双半票）
- **包内项**: **实移植 ~15**——`RuleSignMod2nOpt2::checkMultiequalForm`(8941,45)/`RuleSubCommute::cancelExtensions`(4483,30;**核验**——SUBCOMMUTE 车道已触 cancel_extensions!)/`RuleBooleanDedup::isMatch`(2817,14)/余 stragglers；**裁决 235**（136 clone + 99 Rule ctor 注册族）= TODO 既记"结构吸收裁决票（未开）"正式化。
- **域**: src/ruleaction.rs。
- **oracle 锚**: ruleaction.cc:{2817,4483,8941}; ruleaction.hh ctor 全表。
- **可观测面**: sq CMP-ORIENT 128 行域邻接（rule 取向）；实移植三项当前语料休眠（核验后定）。
- **验收**: B2=三函数双侧 fixture；裁决半=类级 RUGRA-GLUE 登记表（clone→Rust 注册表映射文档）+ REGEN 边，**不冒充移植完成**。
- **依赖**: 无。
- **量级**: **M 实 + M 裁决**（可拆两车道）。
- **优先级**: **P1**（裁决半便宜且解锁账本 235 条去向）。

---

### P2 包（休眠路径补齐，DAG 尾部）

#### `WORKPKG-UNMAP-PERSIST-0012` — XML/packed encode-decode 持久化家族（P2）
- **包内项**: marshal 44（PackedDecode/XmlEncode/XmlDecode 全族）+ xml 40（TreeHandler/SAX/yy* 骨架→**裁决** bison 生成件归"生成器吸收"子类，参照 SLEIGH 替代层口径）+ funcdata encode 族 ~40（FUNCDATA-ENCODE-DEP-0001 解锁：encodeTree/encode/encodeHigh/decode 72行/doLiveInject/encodeJumpTable）+ jumptable encode/decode 族 ~12（JumpTable::encode/decode/JumpBasicOverride encode/decode/LoadTable）+ block encode/decodeBody 族 ~8 + IopSpace/architecture encode 残项。
- **域**: src/marshal.rs 主体 + 各模块 encode 臂。
- **oracle 锚**: marshal.cc:{231,269,326,340,429,440,458,583,620,641,661,676,695,704,808,887,912,1042,1051}; xml.cc:{1202,1070,2492}; funcdata.cc:{661,689,737,767,848,613,628}; jumptable.cc:{2764,2796,2032,2061,37,48}; block.cc:{1373,1401}。
- **可观测面**: **休眠**（Rugra 无 XML 协议消费面）；价值=①未来 decomp 协议对拍（ui-console 桥启用前置）②B2 fixture 的状态序列化通道③encodeRecursive 是 FUNCDATA-ENCODE-DEP 的 7 阻塞 defs 的解锁面。
- **验收**: B2=marshal round-trip fixture（encode→decode 恒等）双侧。
- **依赖**: 无硬依赖；建议在 P0/P1 收口后。
- **量级**: **L**（~144 defs/~1600 LOC，机械占比高）。
- **优先级**: **P2**。

#### `WORKPKG-UNMAP-ARCHSPEC-0014` — spec 装载/XML 配置面（P2）
- **包内项**: sleigh_arch 48（LanguageDescription/buildSpecFile/buildSymbols/scanForSleighDirectories/normalize 族——Rugra 用预编译 .sla+驱动构建，**整簇休眠**，kuna-sleigh 时代语义再评估）+ architecture XML 面 ~30（parseProcessorConfig 1172/restoreXml 491/decodeDynamicRule/decodeVolatile/decodeReadOnly/decodeDeadcodeDelay/decodeInferPtrBounds/decodeSpacebase/initializeSegments——**部分非休眠**: cacheAddrSpaceProperties 已被 F4WEBTYPE 证承重；decode* 是 spec 语义正确性防御面）+ userop decode 族（SegmentOp::decode 225,66/JumpAssistOp::decode 302,52/VolatileOp 族）+ SegmentedResolver::resolve(1447,31)+ globalcontext 13 + options 4。
- **域**: src/arch.rs + 新 src/sleigh_arch.rs（若无主体则裁决豁免形态）+ userop.rs。
- **oracle 锚**: architecture.cc:{491,624,665,705,882,914,1019,1033,1071,1172,1355,1371,1447}; sleigh_arch.cc:{35,55,121,265,323,354,451,529,572}; userop.cc:{85,105,128,159,189,225,302}。
- **可观测面**: 当前零（驱动硬编码装载）；防御面=F4WEBTYPE 型 spec 语义差（寄存器空间过滤已修，decode 族其余臂同型风险）；SegmentedResolver=非 x86-64 分段架构（休眠）。
- **验收**: B2=decode 臂逐族双侧 fixture（同 XML 输入→同 Architecture 状态投影）；sleigh_arch 整簇先出**豁免/移植裁决文档**再定。
- **依赖**: MARSHAL-0012 decode 原语。
- **量级**: **L**（150 defs/~1330 LOC）。
- **优先级**: **P2**。

#### `WORKPKG-UNMAP-PARSEADJ-0015` — grammar/pcodeparse bison 骨架裁决（P2；非移植）
- **包内项**: grammar.cc 25（yyparse 753行!/moveState 231/yysyntax_error 132/yy 骨架）+ pcodeparse.cc 14（yyparse 933行!/yydestruct/…）+ 真实残项 PointerModifier/ArrayModifier modType（2403/2412）+ FunctionModifier ctor。
- **处置**: yyparse/yy* = bison 生成 C 代码，Rugra 手写递归下降（grammar.rs 33 mapped/pcodeparse.rs 33 mapped）已替代——**建议 reclassify 为"生成器吸收"新子类**（对齐 SLEIGH 替代层先例，写入账本口径），等价证明单位=解析器整面 fixture（同 C 类型串/DWARF 声明串双侧 parse 树恒等），**不逐函数移植**。真实残项仅 modType 族 2-3 项 S 级。
- **oracle 锚**: grammar.cc:{2403,2412,2419}; pcodeparse.cc:{3174,3195}。
- **量级**: **S 实 + S 裁决**（LOC 账面 2574 但生成件不移植）。
- **优先级**: **P2**（账本卫生票：一次消 ~39 defs + 2574 假 LOC）。

#### `WORKPKG-UNMAP-PERIPH-0016` — 分析外围 228（P2；切片）
- **包内项与切片**: ①**paramid 7**（F7NAME IMPORTSIG 通道邻接——`ParamIdAnalyzer` 面，Iface 分析器，Rugra 现由驱动台账替代；裁决文档+可移植半）②**emulate 47+emulateutil 33**（EmulateFunction 残项在 jumptable 簇；Rugra jumptable 用简化仿真——JUMPTABLE_GAPS 已记 LOAD/MULTIEQUAL 语义缺；**与 JT 域联动**）③rulecompile 80+expression 12+multiprecision 15（动态规则编译链，architecture.cc decodeDynamicRule 消费面；休眠）④printjava 17（PrintJava 语言面；休眠——selectJavaOperators 归此）⑤callgraph 8/capability 4（CRATESPLIT-R7 已登记 capability 裁决票勿重复）/error 3（Rust anyhow 吸收裁决）。
- **可观测面**: 零（全部未接线）；paramid 半有 F7NAME 数据通道先例。
- **量级**: **L 总量、按切片 S-M 派发**。
- **优先级**: **P2**（paramid 切片 P2-头部，余 P3）。

#### `WORKPKG-UNMAP-UICONSOLE-0017` — UI-控制台桥 618（豁免维持；不开移植）
- 按 AGENTS/DECOMP §7 维持豁免；唯一动作=若未来启动 decomp 协议对拍，先开 **PERSIST-0012 的 marshal 半**作前置（已登记"宿主协议后端另票"口径不变）。本包仅为账本记账行，无派发内容。

#### `WORKPKG-UNMAP-REBASE-0000` — 再基线与账本卫生（P0-前置，meta）
- **包内项**: ①当前 master 重跑 `tools/generate_function_ledger.py` + 与 80ffb7d1 快照 diff → 产出"真缺失现状清单 v2"（预期 ~2290）；②REGEN 边补挂：本报告 §1.1 核验出的未链接候选（lookForFuncParamNames/makeRec/ruleBlockProperIf 族等）移交 REGEN 车道批量链接（排除清单沿用 typeop push 52 禁链 + 本报告新增 selectJavaOperators 归属调整）；③grammar/pcodeparse"生成器吸收"子类口径进账本（与 PARSEADJ-0015 联动）。
- **量级**: **S**；**优先级 P0-最前**（所有包的 step0，也可独立先行）。

---

## §5 排序输出（依赖 + 收敛杠杆）

```
Wave-A（P0，立即可派——写域空闲核验完毕）:
  1. REBASE-0000   (meta, S, 解锁全包的准确分母)
  2. TYPEOP-0001   (M,  curl A 族 −45 杠杆, typeop.rs 空闲)
  3. TYPEUNION-0003(M-L, curl D 族 −46 杠杆, datatype.rs 空闲; 先与 CURLCANON-UNIONSTORE 票合一)
  4. COREACT-0002  (M-L, A 族次级+switch 域, coreaction.rs 空闲@MB17)
  5. STRFOLD-0006  (S-M, constseq/stringmanage 空闲)
  （串行约束: VARMAP-0005 排队 VARMPOISON; PRINTC-0004 排队 fspedein/curlfam+TYPEDEF-LATCH）
Wave-B（P0-解锁后）:
  6. VARMAP-0005   (S-M, VARMPOISON 集成后; sq STACKSLOT 2203 地基)
  7. PRINTC-0004   (M, printc.rs 解封后)
Wave-C（P1, 与 Wave-A/B 并行可派, 写域不冲突）:
  8. BLOCK-0007    (L, 机制 C; block/blockaction 空闲)
  9. ACTIONDBG-0010(S-M, action.rs 空闲)
  10. MODELRRULES-0008 / FLOWUTIL-0011 / RULEADJ-0013 / DATABASE-0009 (按租约)
Wave-D（P2, P0/P1 收口后）:
  11. PARSEADJ-0015(账本卫生, 可提前与 REBASE 同拍)
  12. PERSIST-0012 → 13. ARCHSPEC-0014 → 14. PERIPH-0016 切片 → 17. UICONSOLE 维持豁免
```

**排序依据**: P0 六包直接对应现行残差族账面 ~166 行（curl A45+D46+O3+I8 + 镜面 F-STRFOLD~4/F-DECL~23/F-PLTNAME~2 + sq CASTFUSE-B/STACKSLOT 域地基）+ sq 2203 行族地基；纯完整性包按 DAG 层序居后；休眠面最后。

---

## §6 与既有票交叉核对（防重复，root 复核清单）

| 本报告包 | 既有票关系 |
|---|---|
| TYPEOP-0001 | 承接 MIGW1-TYPEOP-0002 残量（53 push 已收，本包=残 107）；TYPEOP-PUSH-PTRADD-0001（P4）并入；TYPEOP-INTADD-PROPTEST-0001（P3）并入 |
| COREACT-0002 | ACTION-COUNTHARVEST-FAMILY-0001（P3 排队）同域搭车；不覆盖 F7NAME（已 DONE） |
| TYPEUNION-0003 | 与 CURLCANON-UNIONSTORE-ARBITRATION-0001（P1 未认领）**合一派发**（机制/仲裁同体）；UNIONRESOLVE-PKG-H-0001（P3）归 PRINTC-0004 |
| PRINTC-0004 | 吸收 MIRATTR-F-STRFOLD/F-DECL/F-WRAP 消费半+curl O 族；HERMETICITY-TYPEDEF-LATCH-0002（P2）串行约束；不重复 F-ARRCAST/F3-DOUBLECAST（已 DONE） |
| VARMAP-0005 | VARMPOISON（在飞）后串行；不覆盖 F-TYPE-FEED（VARMPOISON 域） |
| BLOCK-0007 | = MIGW1-BLOCK-0003（未派发）**收窄重定义**（encode 拆 PERSIST、F8/F5 已收项剔除）；F8FOR-REJECT-RESIDUAL/BLOCKFINAL 残项邻接不并入 |
| DATABASE-0009 | = MIGW-DATABASE 残余清单正式化；与 PIRAM（在飞）/GENDRIVER-SYMTAB-DB 串行 |
| RULEADJ-0013 | = TODO"结构吸收裁决票 ~411"中 ruleaction 半（235）+ 3 实残项正式化 |
| PERSIST-0012 | 解锁 FUNCDATA-ENCODE-DEP-0001（7 defs） |
| PERIPH-0016 | capability 部分勿撞 CRATESPLIT-R7-CAPABILITY-0019 |
| 所有 | 不重复 HELPF-VARARGS 复活（condexe/fspec 域，非真缺失范畴——Rust 函数面已有，是行为缺口非账目缺失） |

## §7 残余风险与诚实声明

1. **"需深挖"清单**: ①traceTrash↔UNAFF-EXTRAOUT 555 行族的因果未证（仅 DAG 根假设，COREACTION_GAPS 旧审计+FSPEC_GAPS trashset 记载，派发前须 IR 钉死）；②emitSwitchCase/printc 部分单例的"部分存在"边界未经逐行核验；③blockaction 簇核验比（预估 ≥40% 未链接）未逐一证实；④sleigh_arch 整簇在 kuna-sleigh 时代的豁免/移植归属需 root 裁决。
2. 行数收益为**理论上限**（族间耦合去重后打折，CURLCANON 先例：A+F 互斥区 −33 而非 −69）。
3. 本报告全部工作包为**建议**；分母/去向裁决权在 root（REGEN/账本口径变更尤其如此）。
4. 快照消耗量 ~354 为 lane 记账口径推算，精确值以 REBASE-0000 再基线 diff 为准。

## §8 复现

```bash
python3 - <<'EOF'   # 簇聚合重放（本报告 §3 数字源）
import json; from collections import Counter
d=[x for x in json.load(open('/dev/shm/rugra-reports/decomp/classified_final.json')) if x['cat']=='missing']
print(Counter(x['layer'] for x in d))
print(Counter(x['file'].rsplit('.',1)[0] for x in d if x['layer']=='main').most_common(20))
EOF
```
（/dev/shm 易失：classified_final.json 若丢，按 UNMAPPED_DECOMPOSITION 附录用 classify2.py 重生成。）

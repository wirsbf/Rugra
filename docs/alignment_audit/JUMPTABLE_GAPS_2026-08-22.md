# Jumptable 深度差距审计报告(2026-08-22)

- **审计 Agent**: jumptable_gaps_audit(只读;唯一 write-set = 本报告)
- **Oracle**: Ghidra 12.0.4 tag `Ghidra_12.0.4_build`,commit `e40ed13014025f82488b1f8f7bca566894ac376b`(本 session 已核实 `ghidra/` HEAD 等于该 commit)
- **Oracle 文件**: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.cc`(2861 行)/ `jumptable.hh`(645 行);关联 `emulate.cc`、`funcdata_block.cc`、`flow.cc`、`coreaction.cc`
- **Rugra 文件**: `src/jumptable.rs`(4685 行)、`src/emulate.rs`(516 行)、`src/funcdata.rs`、`src/flow.rs`、`src/coreaction.rs`
- **对照方法**: 逐行读完 jumptable.cc/hh 全部 2861+645 行与 jumptable.rs 全部 4685 行、emulate.rs 全部 516 行;交叉核实 flow/funcdata/coreaction/userop/pcodeinject/memstate/loadimage/dynamic 的调用闭包。每个 claim 带 file:line。
- **验收口径**: 所有拟登记 TODO 的验收 = locked 12.0.4 双侧 jumptable 恢复 fixture(oracle 侧用 ORACLE-0002 已建成的 12.0.4 headless dist 重放,`tests/golden/ghidra_curl_1204.*` 作回归信号)。

---

## 0. 执行摘要

| 指标 | 数值 |
|---|---|
| jumptable.cc 被对照函数/方法总数 | 128 |
| MATCH(逐行为等价,仍需 oracle fixture 定级) | 43 |
| PARTIAL(结构在,≥1 决定性语义缺失) | 29 |
| MISMATCH(存在即错,行为分歧) | 21 |
| MISSING(oracle 有、Rust 无) | 33 |
| DEAD(实现存在但主管线/调用方为零) | 2 |
| INVENTED(12.0.4 oracle 无对应物) | 1 |
| 已知 5 缺口复核结论 | 全部属实,其中 2 个比 ROADMAP #21 记载更严重 |
| 新发现(ROADMAP #21 未登记)缺口 | 14 项 |
| 最重依赖地基 | **Funcdata 部分克隆 + "jumptable" action 策略链(truncatedFlow + allacts)完全缺失** —— 其次为 EmulateFunction 的 LOAD/MULTIEQUAL 语义 + loader 桥 |

当前 jumptable.rs 模块实际能力:对**无守卫、直线路径、无 LOAD、无 MULTIEQUAL、非 readonly** 的最简 switch 可产出地址表;守卫范围约束被整体丢弃(`calc_range`,见 §3.1),因此**任何带范围守卫的真实 switch 在 JumpBasic 下 range 尺寸巨大 → 超 maxtablesize → 恢复失败**。主管线入口 `ActionSwitchNorm`(coreaction.rs:2550)只做计数 stub,`matchModel/recoverLabels/foldInNormalization/foldInGuards` 闭包全部未接。

---

## 1. 逐类逐函数账本

状态图例: ✅MATCH / 🟡PARTIAL / ❌MISMATCH / ⛔MISSING / 💀DEAD / 🄯INVENTED。Ghidra 行号 = oracle jumptable.cc(除非另注);Rust 行号 = src/jumptable.rs(除非另注)。

### 1.1 LoadTable(jumptable.hh:50-63)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `LoadTable::encode` | cc:37 | 无 | — | ⛔MISSING | marshal 层缺失(阻塞 JumpTable::encode) |
| `LoadTable::decode` | cc:48 | 无 | — | ⛔MISSING | 同上 |
| `LoadTable::collapseTable` | cc:60 | `LoadTable::collapse_table` | rs:73 | ✅MATCH | 已排序连续检测、sort、折叠循环、resize 语义逐条对应 |

### 1.2 EmulateFunction(jumptable.hh:109-127;依赖 emulate.cc 的 EmulatePcodeOp)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `executeLoad` | cc:113 | `execute_op` 内 LOAD 分支 | rs:3970-4027 | ❌MISMATCH | ① Ghidra 先记录 loadpoint(`getSpaceFromConst` 取 space、`addressToByte(off,wordSize)`)再调 `EmulatePcodeOp::executeLoad` 从 **LoadImage 读内存**;Rust 无 loader,LOAD 走 `evaluate_binary`(rs:4001)不是内存读,loadpoint 记录 `Address::new(in_vals[1])`(rs:4021)无 byte 换算/space。② Rust 仅在求值 `Some` 时记录;Ghidra 无条件先记录 |
| `executeBranch` | cc:126 | 无 | — | ⛔MISSING | Ghidra 抛 `LowlevelError("Branch encountered…")`;Rust 无该守卫 |
| `executeBranchind` | cc:132 | 无 | — | ⛔MISSING | 同上(indirect branch 守卫) |
| `executeCall` / `executeCallind` / `executeCallother` | cc:138/145/152 | 无 | — | ⛔MISSING | Ghidra **忽略调用并 fallthru**;Rust 会把 CALLOTHER 当算术求值 → `None` → emulate_path 失败 |
| 构造器 `EmulateFunction(Funcdata*)` | cc:160 | `EmulateFunction::new()` | rs:3928 | 🟡PARTIAL | 无 `fd`、无 `glb->loader` 桥;jumptable.rs:2363 `EmulateFunction::new()` 未传 fd |
| `setExecuteAddress` | cc:167 | 无 | — | ⛔MISSING | 依赖 `fd->target(addr)`;Rugra 以 pathMeld 索引驱动,结构性缺此件(影响低) |
| `getVarnodeValue` | cc:179 | `get_varnode_value` | rs:3944 | 🟡PARTIAL | 常量/map 命中两路 ✓;**fallback 不是 `getLoadImageValue` 而是 0**(rs:3953-3954)——readonly 表/内存常量全部读 0 |
| `setVarnodeValue` | cc:194 | `set_varnode_value` | rs:3960 | ✅MATCH | Arc 指针为 key 等价 `map<Varnode*,uintb>` |
| `fallthruOp`(lastOp 跟踪) | cc:200 | 无 | — | ⛔MISSING | MULTIEQUAL 执行选择依赖 lastOp,缺此件 → MULTIEQUAL 不可执行 |
| `emulatePath` | cc:216 | `emulate_path` | rs:4038 | 🟡PARTIAL | 循环结构、MULTIEQUAL 起始处理(cc:222-234 ↔ rs:4064-4091)、终点取 `getOp(0)->getIn(0)` ✓;但失败语义:Ghidra 抛 LowlevelError/DataUnavailError → **整个 recoverAddresses 失败**;Rust 返回 None → `buildAddresses` 推入 `Address::new(0)`(rs:2417)继续跑 |

**MULTIEQUAL 执行语义**(oracle emulate.cc:185 分派 → `EmulateMemory::executeMultiequal` emulate.cc:298,按 lastOp 所在父块选输入):Rust `execute_op` 按 `num_input` 1/2/3 分派到 evaluate_unary/binary/ternary(rs:3997-4012),MULTIEQUAL 落入 evaluate_binary —— 非选择语义,求值必然 `None` → 路径含 MULTIEQUAL 即失败。**已知缺口 #3 属实**。

### 1.3 JumpValuesRange / JumpValuesRangeDefault(jumptable.hh:187-230)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `JumpValuesRange::truncate` | cc:260 | `truncate` | rs:955 | ✅MATCH | mask→rangeSize、left/step/right、setRange 逐条对应 |
| `getSize`/`contains`/`initializeForReading`/`next`/`getValue`/`getStartVarnode`/`getStartOp`/`isReversible`/`clone` | cc:271-323 | trait impl | rs:965-1027 | ✅MATCH | `mutable curval` 用 AtomicU64 等价(rs:901 注释) |
| `JumpValuesRangeDefault::getSize`/`contains`/`initializeForReading`/`next`/`getStartVarnode`/`getStartOp`/`isReversible`/`clone` | cc:325-387 | trait impl | rs:1117-1198 | ✅MATCH | lastvalue/extra 迭代顺序(额外值最后)、`isReversible = !lastvalue` ✓ |

### 1.4 JumpModelTrivial(jumptable.hh:349-365)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `recoverModel` | cc:389 | `recover_model` | rs:1347 | ✅MATCH | sizeOut 计数 + `size!=0 && size<=matchsize` ✓ |
| `buildAddresses` | cc:396 | `build_addresses` | rs:1375 | ✅MATCH | 逐 out-edge push `getStart` ✓ |
| `buildLabels` | cc:407 | `build_labels` | rs:1402 | ✅MATCH | 地址本身作 label ✓ |
| `clone` | cc:414 | `clone_model` | rs:1446 | ✅MATCH | — |
| no-op 虚方法(findUnnormalized/foldInNormalization/foldInGuards/sanityCheck) | hh:358-363 | trait impl | rs:1399-1443 | ✅MATCH | — |

### 1.5 JumpBasic 静态与工具(jumptable.hh:381-386)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `isprune` | cc:424 | `is_prune` | rs:1516 | ✅MATCH | call/marker/零输入 ✓ |
| `ispoint` | cc:436 | `is_point` | rs:1535 | ✅MATCH | const/annotation/readonly ✓ |
| `getStride` | cc:449 | `get_stride` | rs:1552 | ✅MATCH | 0x3f 上限/32 ✓ |
| `backup2Switch` | cc:472 | `backup2_switch` | rs:1636 | 🟡PARTIAL | ① Ghidra 用 `getEvalType()` 判 binary/unary;Rust 用"其他 slot 是否常量"启发式(rs:1667-1683),双非常量输入时 Ghidra 走 **MemoryImage 读另一输入地址**(cc:489-491),Rust 误走 unary → None → NO_LABEL。② `recoverInputBinary/Unary` 已接 opbehavior ✓ |
| `getMaxValue` | cc:512 | `get_max_value` | rs:1571 | ✅MATCH | INT_AND 常量 + MULTIEQUAL 跨块 AND 重复(含 max 取大、break 条件)逐条对应 |
| `matching_constants`(static) | cc:598 | `matching_constants` | rs:722 | ✅MATCH | — |
| `duplicateVarnodes` | cc:1289 | `duplicate_varnodes` | rs:1728 | ✅MATCH | 空数组语义差异良性(Ghidra arr[0] UB) |

### 1.6 GuardRecord(jumptable.hh:137-157)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| 构造器(quasiCopy 初始化 baseVn/bitsPreserved) | cc:613 | `GuardRecord::new` | rs:475 | ✅MATCH | — |
| `valueMatch` | cc:637 | `value_match` | rs:540 | ❌MISMATCH | 同 vn / 同 bits+同 baseVn 两早退 ✓;**缺 `oneOffMatch(loadOp,loadOp2)==1 → 1` 分支与 LOAD 等价 → 2 分支**(cc:654-674),Rust rs:559-562 直接 return 0。`one_off_match` 已实现(rs:683)但未接线 |
| `oneOffMatch` | cc:684 | `one_off_match` | rs:683 | 💀DEAD | 实现忠实(9 op + matching_constants),但无任何调用方 |
| `quasiCopy` | cc:719 | `quasi_copy` | rs:575 | ✅MATCH | mask=2^bits−1、COPY/AND/OR/SEXT/ZEXT/PIECE/SUBPIECE 各守卫逐条对应 |

### 1.7 PathMeld(jumptable.hh:72-102)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `internalIntersect` | cc:794 | 内联于 `meld` | rs:316-339 | ✅MATCH | mark 检测/parentMap/-1 回填(逆序)逐条对应 |
| `meldOps` | cc:832 | `meld_ops` | rs:380 | ❌MISMATCH | Ghidra 归并键 = **父块身份 + lastBlock 推进 + `SeqNum::getOrder()` 比较**(cc:859-877),且不可排序时返回 **newCutoff** 触发截断(cc:864-871);Rust 无 parent/SeqNum 排序、旧 op 无条件先于新 op 出队(rs:400-403)、永不返回 cut point。**已知缺口 #2 属实** |
| `truncatePaths` | cc:901 | 无 | — | ⛔MISSING | `meld` rs:372-374 注释自认"conservative ordered merge",截断永不发生 → split-未-rejoin 的 op 残留、commonVn 不收缩 |
| `set(const PathMeld&)` | cc:913 | `set_from` | rs:233 | ✅MATCH | — |
| `set(vector<PcodeOpNode>&)` | cc:922 | `set_path` | rs:242 | 🟡PARTIAL | Rust 多一次 clear()(Ghidra 不清,复用语义不同;当前调用点无害) |
| `set(PcodeOp*,Varnode*)` | cc:935 | `set_single` | rs:262 | ✅MATCH | — |
| `append` | cc:947 | `append` | rs:272 | ✅MATCH | 前插 + 仅旧 op rootVn 偏移 renumber 逐条对应 |
| `clear` | cc:957 | `clear` | rs:292 | ✅MATCH | — |
| `meld` | cc:968 | `meld` | rs:305 | 🟡PARTIAL | mark/intersect/cutoff 计算 ✓(rs:307-355);meldOps 简化 + 无 truncatePaths 调用 |
| `markPaths` | cc:1000 | `mark_paths` | rs:418 | ✅MATCH | 自尾找 rootVn==startVarnode、0..=startOp 置/清 mark ✓ |
| `getEarliestOp` | cc:1023 | `get_earliest_op` | rs:202 | ✅MATCH | — |
| (无对应物) | — | `is_load_in_path` | rs:214 | 🄯INVENTED | 12.0.4 oracle **不存在** `PathMeld::isLoadInPath`(grep 全 oracle 0 命中;注释引用的 cc:1038 实为 doc-comment 行)。且被 `find_smallest_normal`(rs:2085)用于改写 findSmallestNormal 的接受条件,属版本漂移污染(来自未锁定的新版 Ghidra) |

### 1.8 JumpBasic 主体(jumptable.hh:373-426)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `findDeterminingVarnodes` | cc:554 | `find_determining_varnodes` | rs:1927 | ✅MATCH | DFS/回溯 slot 推进/firstpoint set-vs-meld/empty 回退 set(op,in) 逐条对应 |
| `analyzeGuards` | cc:1046 | `analyze_guards` | rs:2710 | ❌MISMATCH | ① **pathout≥0 首轮即 break**(rs:2729-2735 返回 placeholder `(None,ip)` → rs:2789-2791 break)——JumpBasic2 传入 pathout 时守卫分析全空;② `sizeIn>1` 时 **不调 checkUnrolledGuard**(rs:2743-2746 只 break;Ghidra cc:1069-1070);③ `indpathstore` 缺 `getFlipPath() ? 1-indpath` 调整(rs:2804 直接 `= indpath`;Ghidra cc:1100);④ 缺 `i!=0` 的 other-switch 保护(cc:1083-1091);⑤ pullback 循环 ✓(rs:2819-2837)。**已知缺口 #4 属实且重于 ROADMAP 记载** |
| `calcRange` | cc:1120 | `calc_range` | rs:2011 | ❌MISMATCH | **守卫交集结果被丢弃**:rs:2038-2040 `let mut gr = guard.range.clone(); let _ = gr.intersect(rng);` 算完即扔,`rng` 从不被 guard 限制(Ghidra cc:1143-1145 `rng.intersect(guard.getRange())` 就地修改);另缺 `isBoolOutput → CircleRange(0,2,1,1)`(cc:1127-1128)。**守卫永远不约束 → 正常 switch 的 range 巨大 → JumpBasic 必败。本审计最重新发现** |
| `findSmallestNormal` | cc:1165 | `find_smallest_normal` | rs:2057 | 🟡PARTIAL | 主循环/matchsize 早退/1-byte-256 守卫 ✓;但接受条件多出 `is_load_in_path(i)`(rs:2085,INVENTED,见 1.7) |
| `findNormalized` | cc:1204 | `find_normalized` | rs:2102 | 🟡PARTIAL | analyzeGuards+findSmallestNormal ✓;**readonly 单入口救援为空壳**(rs:2117-2128,Ghidra cc:1223-1231 用 `MemoryImage(vn->getSpace(),4,16,glb->loader)` 读值建 CircleRange;Rust 注释自认 TODO: wire LoadImage) |
| `markFoldableGuards` | cc:1239 | `mark_foldable_guards` | rs:2134 | ✅MATCH | valueMatch==0 或 unrolled → clear ✓(受 value_match 缺陷传导) |
| `markModel` | cc:1254 | `mark_model` | rs:2150 | ✅MATCH | pathMeld.markPaths + readOp mark ✓ |
| `flowsOnlyToModel` | cc:1274 | `flows_only_to_model` | rs:2169 | ✅MATCH | descend 迭代 + trailOp 跳过 + isMark ✓ |
| `checkCommonCbranch` | cc:1305 | `check_common_cbranch` | rs:1741 | ✅MATCH | 首 in-block CBRANCH/flip/revIndex/逐 in-block 校验 ✓ |
| `checkUnrolledGuard` | cc:1338 | `check_unrolled_guard` | rs:1829 | 💀DEAD+❌ | **无任何调用方**(analyze_guards 应调而未调);且 GuardRecord 以字面量构造,`base_vn:None, bits_preserved:0`(rs:1870-1894)未走 `quasiCopy`(Ghidra 构造器语义),valueMatch 必然 0 |
| `foldInOneGuard` | cc:1373 | `fold_in_one_guard` | rs:2195 | 🟡PARTIAL | 缺:① `hasFoldedDefault && defaultBlock != pos` 早退(cc:1391);② `noInterveningStatement()`(cc:1394);③ 常量 val **未考虑 isBooleanFlip**(Ghidra cc:1402 `((indpath==0)!=isBooleanFlip()) ? 0 : 1`;Rust rs:2269-2274 只看 indpath);④ `getFlipPath()` 用 GOTO_EDGE_1 flag 近似(rs:2218-2221)。push_branch/addBlockToSwitch/setLastAsDefault/setFoldedDefault 结构在 |
| `recoverModel` | cc:1418 | `recover_model` | rs:2316 | 🟡PARTIAL | Ghidra 走 `findNormalized(fd,parent,-1,…)`;Rust 直接 analyze_guards+find_smallest_normal(rs:2333-2335),**绕过 find_normalized 的 readonly 救援**;jrange 新建/size 判定/markFoldableGuards ✓ |
| `buildAddresses` | cc:1434 | `build_addresses` | rs:2350 | 🟡PARTIAL | funcptr_align mask ✓(rs:2380-2385,曾修 bug);addressToByte 以 word_size=1 恒等(单 space 模型,rs:2394 注释);loadcounts 累计 ✓ 近似;**emulate 失败 → Address::new(0) 入表**(rs:2417,Ghidra 异常终止全表);EmulateFunction 无 fd |
| `findUnnormalized` | cc:1462 | `find_unnormalized` | rs:2451 | ✅MATCH | ADD/SUB/ZEXT/SEXT 计数、常量约束、flowsOnlyToModel/normop 尾迹、markModel 包裹逐条对应(maxleftright 双方都未用,与 oracle 一致) |
| `buildLabels` | cc:1506 | `build_labels` | rs:2523 | ❌MISMATCH | Ghidra 迭代 **orig 模型**的 `origrange`(cc:1510-1512)并检查 `jrange->contains(val)` 产生 needswarning=1/2 + `fd->warning`;Rust 忽略 `_orig` 参数、迭代自身 jrange、无 contains 检查、无任何 warning(rs:2525-2571)。sanity 截断后 label 数与顺序均会错 |
| `foldInNormalization` | cc:1546 | `fold_in_normalization` | rs:2574 | ❌MISMATCH | Ghidra `fd->opSetInput(indop,switchvn,0)`(维护 descend/insert 顺序);Rust **裸写 `op.inrefs[0]`**(rs:2582-2588),旧输入 descend 残留、新 switchvn descend 未登记 → 破坏后续 Heritage/分析 |
| `foldInGuards` | cc:1555 | `fold_in_guards` | rs:2595 | ✅MATCH | isDead→clear、逐 guard fold ✓ |
| `sanityCheck` | cc:1572 | `sanity_check` | rs:2625 | 🟡PARTIAL | 首 0 址/0xffff diff/截断+jrange.truncate+loadpoints 截断 ✓;**diff>0xffff 时 Ghidra 用 `loader->loadFill` 验证数据可用则继续**(cc:1589-1597),Rust 无 loader 恒 break(rs:2650-2654) |
| `clone` | cc:1613 | `clone_model` | rs:2679 | ❌MISMATCH | Ghidra **只克隆 jrange**("We only need to clone the JumpValues");Rust 克隆 path_meld/selectguards/normalvn/switchvn/varnode_index 全套(rs:2683-2687)——部分克隆管线中这些指向旧 Funcdata 的 op/vn,是悬空指针式错误 |
| `clear` | cc:1621 | `clear` | rs:2692 | ✅MATCH | — |

### 1.9 JumpBasic2(jumptable.hh:440-452)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `foldInOneGuard` | cc:1634 | `fold_in_guards`(Basic2 impl) | rs:3091 | ❌MISMATCH | Ghidra 只 `setLastAsDefault + guard.clear(); return true`;Rust **清空全部 selectguards**(rs:3097)且不清单个 guard。**已知缺口 #5a 属实** |
| `initializeStart` | cc:1651 | `initialize_start` | rs:2875 | ✅MATCH | empty→extravn=null + 尾 varnode + origPathMeld.set ✓ |
| `recoverModel` | cc:1663 | `recover_model` | rs:2974 | 🟡PARTIAL | joinvn/MULTIEQUAL-2 路/常量 COPY 搜索/rootbl=path(1-path)/pathout=revIndex/jdef 三 set/findDeterminingVarnodes(multiop,1-path)/append/varnodeIndex += ✓;**被 analyze_guards(pathout≥0 即 break)废掉守卫分析**;jrange->getSize>maxtablesize 早退 ✓ |
| `checkNormalDominance` | cc:1718 | `check_normal_dominance` | rs:2887 | ✅MATCH | isInput 早退 + immedDom 链 ✓ |
| `findUnnormalized` | cc:1733 | `find_unnormalized_inner` | rs:2936 | 🟡PARTIAL | 支配时走 JumpBasic ✓;**backward 分支 Ghidra 抛 `LowlevelError("Backward normalization not implemented")`**(cc:1750),Rust 只 eprintln WARN(rs:2962)且 normalvn 保持未定义态;MULTIEQUAL 直连判定 ✓ |
| `clone` | cc:1753 | `clone_model` | rs:3114 | ✅MATCH | 仅 jrange ✓(new Basic2 其余置空) |
| `clear` | cc:1761 | `clear` | rs:3122 | ✅MATCH | — |

### 1.10 JumpBasicOverride(jumptable.hh:460-493)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| 构造器 | cc:1770 | `new` | rs:3148 | ✅MATCH | — |
| `setAddresses` | cc:1779 | `set_addresses` | rs:3162 | ❌MISMATCH | Ghidra **只去重入 adset**;Rust 额外按输入序填 addrtable(rs:3164-3168),未去重、顺序错误 |
| `findStartOp` | cc:1791 | 无 | — | ⛔MISSING | **已知缺口 #1a 属实**:descend 置 mark → 找 pathMeld 中首个命中 op → 清 mark |
| `trialNorm` | cc:1823 | `trial_norm` | rs:3194 | ❌MISMATCH(stub) | **恒 -1**(rs:3198)。注释归因 "DynamicHash missing" **已过时**——`DynamicHash::find_varnode` 存在于 src/dynamic.rs:803;真正缺的是 findStartOp + `EmulateFunction(fd)` 迭代(adset 命中/tolerance/alreadyseen/values+addrtable 累积,cc:1843-1876) |
| `setupTrivial` | cc:1882 | `setup_trivial` | rs:3183 | ❌MISMATCH | Ghidra:addrtable 空时从**排序 adset** 填充;`values[i] = addrtable[i].getOffset()`(地址偏移即值);`normalvn = pathMeld.getVarnode(0)`;Rust:values = starting_value 递增(rs:3186-3189)、不填 addrtable、不设 normalvn |
| `findLikelyNorm` | cc:1906 | 无 | — | ⛔MISSING | LOAD→ADD→MULT 三段回溯找 norm 候选 |
| `clearCopySpecific` | cc:1943 | `clear_copy_specific` | rs:3202 | ❌MISMATCH | **语义反转**:Ghidra 清 selectguards/pathMeld/normalvn/switchvn,**保留 adset**(cc:2023 注释 "permanent");Rust 清 adset/values/addrtable/is_trivial,不清 pathMeld/guards |
| `recoverModel` | cc:1952 | `recover_model` | rs:3217 | ❌MISMATCH | 缺:clearCopySpecific 正确字段、`findDeterminingVarnodes(indop,0)`(rs 全无)、hash!=0 时 `DynamicHash::findVarnode(fd,normaddress,hash)`(Rust 用 `indop->getIn(0)` 顶替,rs:3225)、`findLikelyNorm` 回退、`istrivial` 短路、tolerance=10(Rust 传 0)、opi 成功后 varnodeIndex/normalvn 设置 |
| `buildAddresses` | cc:1980 | `build_addresses` | rs:3239 | 🟡PARTIAL | 拷贝 addrtable ✓;上游 addrtable 内容错误(见 setAddresses/setupTrivial) |
| `buildLabels` | cc:1986 | `build_labels` | rs:3260 | ❌MISMATCH | Ghidra 逐 `values[i]` 走 `backup2Switch`(EvaluationError→NO_LABEL)+ warning;Rust trivial→starting_value 递增、非 trivial→按地址查 values(机制全错) |
| `clone` | cc:2007 | `clone_model` | rs:3321 | 🟡PARTIAL | 六字段 ✓;多拷 istrivial(Ghidra 新对象恒 false) |
| `clear` | cc:2020 | `clear` | rs:3335 | ❌MISMATCH | 经 clear_copy_specific 反转传导(adset 被误清) |
| `encode` / `decode` | cc:2032/2061 | 无 | — | ⛔MISSING | BASICOVERRIDE/DEST/NORMADDR/NORMHASH/STARTVAL 元素;decode 空集抛错 |

### 1.11 JumpAssisted(jumptable.hh:509-530)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `getTableSize` | hh:518 | `get_table_size` | rs:3378 | ❌MISMATCH | Ghidra `sizeIndices+1`(含 default);Rust 无 +1 |
| `recoverModel` | cc:2091 | `recover_model` | rs:3381 | ❌MISMATCH(stub) | Ghidra:in(0) def **直接**须 CALLOTHER(Rust 额外走 COPY 链 rs:3391-3407)、`userops.getOp(index)` 类型判定、`getCalcSize()==-1` 时取 in(2) 否则 **ExecutablePcode evaluate**、matchsize-1==sizeIndices、maxtablesize 校验;Rust 找到 CALLOTHER 即 WARN+false,JumpAssistOp(userop.rs:338 已有结构)与注入脚本求值(pcodeinject.rs 无 `evaluate`)未接 |
| `buildAddresses` | cc:2131 | `build_addresses` | rs:3412 | ❌MISMATCH(stub) | 空 + WARN;Ghidra 用 index2addr/default 脚本逐 index 求值 + funcptr_align mask |
| `buildLabels` | cc:2166 | `build_labels` | rs:3429 | ❌MISMATCH(stub) | Ghidra:index2case==-1→index 为 label,否则脚本求值;size 变化抛错;**尾补 NO_LABEL**;Rust push 0..size_indices(而 size_indices 恒 0) |
| `foldInNormalization` | cc:2193 | `fold_in_normalization` | rs:3443 | ❌MISMATCH | Ghidra 替换 assistOp 输出的**全部** descend + `opDestroy(assistOp)`;Rust 返回 indop->getIn(0) |
| `foldInGuards` | cc:2208 | `fold_in_guards` | rs:3452 | ❌MISMATCH | Ghidra `setLastAsDefault` 后返回 `origVal != defaultBlock`(变化检测);Rust 恒 true |
| `clone` | cc:2216 | `clone_model` | rs:3473 | 🟡PARTIAL | sizeIndices ✓;无 userop 字段可拷(Ghidra 拷 userop) |
| `clear` | hh:529 | `clear` | rs:3485 | ✅MATCH | — |

**已知缺口 #5b(JumpAssisted)属实**;同时它阻塞 JumpTable::recoverModel 的模型选择顺序(Ghidra 在 CALLOTHER 定义时**先**尝试 Assisted,cc:2264-2273)。

### 1.12 JumpTable(jumptable.hh:540-624)

| Ghidra 函数 | Ghidra 行 | Rust 对应物 | Rust 行 | 状态 | 差异明细 |
|---|---|---|---|---|---|
| `IndexPair::operator<` / `compareByPosition` | hh:628/638 | `less_than`/`compare_by_position` | rs:3515/3524 | ✅MATCH | — |
| `saveModel` / `restoreSavedModel` / `clearSavedModel` | cc:2225/2234/2243 | 同名 | rs:3740/3747/3753 | ✅MATCH | — |
| `recoverModel`(模型选择) | cc:2254 | `recover_model` | rs:3792 | ❌MISMATCH | Ghidra 顺序:override → CALLOTHER→JumpAssisted → JumpBasic → **JumpBasic2(initializeStart 接 Basic 的 pathMeld)** → NULL;Rust:override → JumpBasic → **JumpModelTrivial(Ghidra 在此从不用 trivial)** → NULL;**无 Assisted/Basic2 尝试**;maxtablesize 用硬编码 `MAX_JUMPTABLE_SIZE=1024`(rs:3904)而非 `glb->max_jumptable_size`;rs:3815 dummy `Arc<RwLock<JumpTable>>` 父引用 hack。**已知缺口 #5c(model selection)属实** |
| `sanityCheck`(表级) | cc:2295 | 无 | — | ⛔MISSING | override 跳过、`isReachable→partialTable`、单入口 thunk 判定(0 址或 diff>0xffff → **JumptableThunkError**)、模型 sanity false → LowlevelError、截断 warning |
| `block2Position` | cc:2337 | 无 | — | ⛔MISSING | — |
| `isReachable` | cc:2354 | 无 | — | ⛔MISSING | 两级 guard-collapsed-to-false 检测 |
| 构造器(Architecture*) | cc:2380 | `new(opaddress)` | rs:3584 | 🟡PARTIAL | 无 glb(max_jumptable_size 来源断) |
| 拷贝构造器(部分克隆) | cc:2401 | 无 | — | ⛔MISSING | `Funcdata::recoverJumpTable` cc:668 `new JumpTable(&trialjt)` 依赖;Rust funcdata.rs:7507 直接 push trial 表(深拷贝语义缺失) |
| `numIndicesByBlock` | cc:2438 | 无 | — | ⛔MISSING | equal_range by position |
| `isOverride` | cc:2447 | `is_override` | rs:3618 | ✅MATCH | — |
| `setOverride` | cc:2466 | 无 | — | ⛔MISSING | 手工 override 唯一入口(new JumpBasicOverride + setAddresses/setNorm/setStartingValue) |
| `getIndexByBlock` | cc:2485 | 无 | — | ⛔MISSING | lower_bound 遍历 |
| `setLastAsDefault` | cc:2502 | `set_last_as_default` | rs:3690 | ✅MATCH | — |
| `addBlockToSwitch` | cc:2513 | `add_block_to_switch` | rs:3726 | ❌MISMATCH | Ghidra `lastBlock = indirect->getParent()->sizeOut()`(块**将**成为的 out-edge 序号);Rust 用 `addresstable.len()-1`(rs:3730)——block2addr 的 blockPosition 语义错误 |
| `switchOver` | cc:2528 | 无 | — | ⛔MISSING | flow.target 解析、out-edge 映射、lastBlock、sort、maxcount→defaultBlock;funcdata.rs `switch_over_jump_tables` 是 no-op stub(funcdata.rs:7525 区域 RUGRA-GAP 注释) |
| `foldInNormalization`(表级,switchVarConsume) | cc:2574 | 无 | — | ⛔MISSING | `minimalmask(nzmask)` + 全覆盖时 SEXT 下传优化 |
| `trivialSwitchOver` | cc:2594 | 无 | — | ⛔MISSING | — |
| `recoverAddresses` | cc:2623 | `recover_addresses` | rs:3845 | 🟡PARTIAL | collectloads 双路(loadcounts+collapseTable)结构 ✓;**bool 返回替代异常语义**:jmodel==NULL/size==0/sanity false 三处 Ghidra 抛 LowlevelError,Rust 静默 false;模型 sanity 结果被丢弃(rs:3876/3892 `let _ =`) |
| `recoverMultistage` | cc:2653 | 无 | — | ⛔MISSING | saveModel/恢复/双异常回滚/partialTable=false |
| `matchModel` | cc:2683 | 无 | — | ⛔MISSING | saveModel(非 override)、recoverModel 重跑、尺寸不匹配→`insertMultistageJump + setRestartPending` 或 warning |
| `recoverLabels` | cc:2714 | 无 | — | ⛔MISSING | origmodel 分支、trivial 回退实例化、clearSavedModel |
| `clear` | cc:2739 | `clear` | rs:3760 | ✅MATCH | override→m.clear / else drop + 字段清空 ✓ |
| `encode` / `decode` | cc:2764/2796 | 无 | — | ⛔MISSING | JUMPTABLE/DEST/ATTRIB_LABEL/LOADTABLE/BASICOVERRIDE + label 连续性校验 |
| `checkForMultistage` | cc:2847 | 无 | — | ⛔MISSING | `queryMultistageJumptable` → partialTable |

### 1.13 管线闭包(jumptable.cc 之外,审计范围内核实)

| 环节 | Oracle | Rust | 状态 | 差异明细 |
|---|---|---|---|---|
| `Funcdata::stageJumpTable` | funcdata_block.cc:492 | `stage_jump_table` funcdata.rs:7270 | ❌MISMATCH | **核心缺失**:partial 克隆 + `partial.flags |= jumptablerecovery_on` + `truncatedFlow(this,flow)` + `allacts.setCurrent("jumptable")` 全套 simplification;Rust 只设 flag 并注释 "Callers must simplify partial themselves"(funcdata.rs:7271-7273)。**恢复跑在未简化的原始数据流上,findDeterminingVarnodes 看到的是未规整 IR —— 一切上层对齐的前置条件** |
| `Funcdata::recoverJumpTable` | funcdata_block.cc:640 | `recover_jump_table` funcdata.rs:7468 | 🟡PARTIAL | link/override-partial 早退/JUMPTABLERECOVERY_DONT/earlyJumpTableFail/trial 持久化 ✓;`new JumpTable(&trialjt)` 部分克隆缺失;`jt->setLoadCollect(flow->doesJumpRecord())` 未见对应(flow.rs 无 doesJumpRecord) |
| `FlowInfo::recoverJumpTables` | flow.cc:1427 | flow.rs:654 | 🟡PARTIAL | notreached/partialTable 推迟、truncate_indirect_jump 映射在;实际恢复走 `try_recover`(in-place,无 partial 克隆) |
| `Funcdata::switchOverJumpTables` | funcdata_block.cc:678 | funcdata.rs `switch_over_jump_tables` | ⛔MISSING(stub) | no-op 循环 |
| `ActionSwitchNorm::apply` | coreaction.cc:4548-4560 | coreaction.rs:2550 | ❌MISMATCH(stub) | Ghidra:每未 label 表 `matchModel → recoverLabels → foldInNormalization`,且 `foldInGuards` 变化时 `data.getStructure().clear()`;Rust:只调自创 `recover_jump_tables` 预扫 + 计数,**四个调用全无**,且恒返回 NO_CHANGE(rs:2592-2598 两个分支同值)。**已知缺口 #5d(ActionSwitchNorm 闭包)属实** |

---

## 2. 五个已知缺口专项复核(ROADMAP #21)

| # | ROADMAP #21 声称 | 复核结论 | 证据 | 严重度 | 所需地基 |
|---|---|---|---|---|---|
| 1 | JumpBasicOverride::findStartOp 缺失且 trialNorm 恒 -1 | **属实** | findStartOp(cc:1791)全缺;trial_norm stub rs:3194-3199 恒 -1。注意:注释归因 DynamicHash 缺失**已过时**(src/dynamic.rs:803 `find_varnode` 已在),真缺口是 findStartOp + EmulateFunction(fd) 迭代 | P1(仅手工 override 路径)但它是 override 全链的闸门 | EmulateFunction 修复(#3)+ findStartOp(纯 mark 扫描)+ DynamicHash 接线 |
| 2 | PathMeld 不按 parent/SeqNum 归并截断 | **属实** | meldOps cc:832-894 的 parent/lastBlock/SeqNum::getOrder 排序与 newCutoff 返回在 rs:380-413 全无;truncatePaths(cc:901)缺失,meld rs:372 注释自认保守 | P0(菱形汇合 switch 的 common path 计算错误→varnodeIndex/range 全错) | PcodeOp.parent + SeqNum order 比较(PATHMELD-0001 已登记,依赖 BLOCK-0001/OPBANK-0001) |
| 3 | EmulateFunction 无 loader/LOAD/MULTIEQUAL | **属实** | get_varnode_value fallback 0(rs:3953);LOAD 无内存读(rs:3997-4027 走 evaluate_binary);MULTIEQUAL 无 lastOp 选择(需 fallthruOp cc:200);CALL/CALLOTHER 不忽略;BRANCH/BRANCHIND 不抛错 | **P0(地址表计算核心)** | LoadImage trait(src/loadimage.rs:75)与 MemoryImage(src/memstate.rs:480)**已存在**,缺 Funcdata→arch→loader 桥;lastOp 跟踪;per-opcode execute 分派(可借 emulate.rs:112 execute_current_op 骨架) |
| 4 | JumpBasic guard/range 未对齐 | **属实且更严重** | ① calc_range **丢弃守卫交集**(rs:2038-2040)→ 守卫从不限制 range;② analyze_guards pathout≥0 首轮 break(rs:2729-2791)→ Basic2 守卫全空;③ check_unrolled_guard(已实现 rs:1829)是死代码且 GuardRecord 构造绕过 quasiCopy;④ indpathstore 缺 FlipPath;⑤ value_match 缺 oneOffMatch/LOAD→2 分支;⑥ 缺 isBoolOutput 分支 | **P0(本审计最重新发现:任何带守卫 switch 的 JumpBasic 必败)** | CircleRange::intersect 完整版(RANGE-0001,READY,rs:205 step!=1 保守保持非空不可用)+ PcodeOp isBoolOutput + FlowBlock getFlipPath |
| 5 | Basic2 subtype、JumpAssisted、model selection、ActionSwitchNorm 闭包均未对齐 | **属实(4 项全部)** | Basic2:fold_in_guards 清空全部 guards(rs:3097)+ backward 无 throw;JumpAssisted:全 stub + getTableSize 差 1;model selection:无 Assisted/Basic2 尝试 + 自创 Trivial 回退 + 硬编码 1024(rs:3792-3836);ActionSwitchNorm:四调用全无 + 恒 NO_CHANGE(coreaction.rs:2550-2598) | P0(端到端 switch 语句不成立) | 前四项 + ExecutablePcode evaluate(INJECT-0001)+ JumpAssistOp 接线(userop.rs:338 结构已在)+ 表级 matchModel/recoverLabels/foldInNormalization/foldInGuards |

## 2.1 新发现缺口(ROADMAP #21 未登记)

1. **calcRange 丢弃守卫交集**(rs:2038-2440 区域,精确 rs:2038-2040)——最重;见上表 #4①。
2. **analyzeGuards pathout≥0 首轮 break**(rs:2718-2735, rs:2789-2791)。
3. **checkUnrolledGuard 死代码 + base_vn/bits_preserved=0 构造**(rs:1829, rs:1870-1894;Ghidra cc:1354/1359 构造器走 quasiCopy)。
4. **PathMeld::is_load_in_path 系版本发明**(rs:214;oracle 12.0.4 无 isLoadInPath),并污染 findSmallestNormal 接受条件(rs:2085 vs cc:1184)。
5. **GuardRecord::value_match 缺 oneOffMatch/LOAD→2**(rs:559-562 vs cc:652-674)。
6. **buildLabels 迭代自身 range 而非 orig 模型 range、无 contains/warning**(rs:2523-2571 vs cc:1506-1544)。
7. **buildAddresses 失败注入 Address::new(0)**(rs:2410-2421;Ghidra 异常终止)。
8. **JumpBasic::clone 克隆全部字段而非仅 jrange**(rs:2679-2688 vs cc:1613-1619)——部分克隆管线悬空引用。
9. **foldInNormalization 裸写 inrefs[0]**(rs:2574-2592 vs cc:1546-1553 `opSetInput`)。
10. **JumpBasicOverride::setup_trivial 值语义反转**(values 应为地址偏移;rs:3183 vs cc:1882-1898)。
11. **clearCopySpecific 字段清反**(rs:3202 vs cc:1943-1950)。
12. **addBlockToSwitch last_block 语义错**(rs:3730 vs cc:2517)。
13. **表级 13 方法缺失**(switchOver/trivialSwitchOver/foldInNormalization/matchModel/recoverLabels/recoverMultistage/checkForMultistage/sanityCheck/block2Position/isReachable/numIndicesByBlock/getIndexByBlock/setOverride)+ 拷贝构造器 + encode/decode。
14. **stageJumpTable 的 partial 克隆简化链(truncatedFlow + "jumptable" action 策略)缺失**(funcdata.rs:7271-7273 自认)——**最重依赖地基**,见 §4 Layer 0。

---

## 3. 依赖链排序的移植路线

### Layer 0 —— 地基(全部上层的前置)

| 序 | 项 | 依赖 | 说明 |
|---|---|---|---|
| 0.1 | **EmulateFunction 重写为 EmulatePcodeOp 语义**:per-opcode dispatch(executeLoad 走 `load_fill`、MULTIEQUAL 走 lastOp 选择、CALL/CALLOTHER fallthru、BRANCH/BRANCHIND 抛错)、ctor 持 fd、getVarnodeValue loader fallback | LoadImage/MemoryImage 已在(src/loadimage.rs:75, src/memstate.rs:480);需 Funcdata→loader 桥 | 解锁 #3、#1、buildAddresses 正确性 |
| 0.2 | **PathMeld::meldOps parent/SeqNum 排序 + truncatePaths** | PATHMELD-0001(已登记) | 解锁菱形路径、Basic2 append 正确性 |
| 0.3 | **CircleRange::intersect 完整移植**(step≠1 不再保守) | RANGE-0001(已登记,READY) | calc_range 守卫限制的实际生效前提 |
| 0.4 | **PcodeOp isBoolOutput / FlowBlock getFlipPath 可用性核实** | 现有 op.rs/block.rs | calcRange 与 analyzeGuards 各需一处 |

### Layer 1 —— JumpBasic 核心算法(地基之上最小可验证闭包)

1. calc_range:守卫交集写回 + isBoolOutput + warning 路径保留(修 §2.1#1)。
2. analyze_guards:完整 cc:1046-1112(pathout 步进/unrolled 接线/FlipPath/other-switch)。
3. value_match 补 oneOffMatch/LOAD→2(接线已有 one_off_match)。
4. 删除 is_load_in_path 版本漂移(或按 oracle 恢复 cc:1184 原条件)。
5. build_addresses 失败语义(异常/失败码替代 Address::new(0))。
6. JumpBasic::clone 收敛为仅 jrange;fold_in_normalization 走 fd.op_set_input。

**最小可验证 fixture(FX-BASIC)**:单守卫 switch(x) {4 case}(gcc -O0 x86-64):双侧观察 `pathMeld` 公共 varnode 序列、jrange range/step、addresstable、label 序列。

### Layer 2 —— 子类型模型闭包

1. **JumpBasic2**:fold_in_one_guard 单 guard 语义、backward throw、(依赖 0.2 的 append 正确性)。
2. **JumpBasicOverride**:find_start_op + trial_norm(依赖 0.1)+ find_likely_norm + DynamicHash 接线(dynamic.rs:803 已在)+ setup_trivial/clear_copy_specific/set_addresses/recover_model 重写。
3. **JumpAssisted**:userops.getOp→JumpAssistOp 判型 + `ExecutablePcode::evaluate`(pcodeinject.rs 现无 evaluate,依赖 INJECT-0001)+ getTableSize+1 + 四方法 + foldInGuards 变化检测。

**fixture**:FX-BASIC2(switch+default 经 MULTIEQUAL 合流)、FX-OVERRIDE(JumpTable::setOverride 手工地址表)、FX-ASSISTED(带 jumpassist 伪 op 的 fixture,可由 cspec 构造)。

### Layer 3 —— 表级 API + 恢复状态机

switchOver/block2Position/numIndicesByBlock/getIndexByBlock/addBlockToSwitch 修正/表级 sanityCheck(thunk/isReachable/warning)/recoverAddresses 异常语义/拷贝构造器/matchModel(含 multistage restart)/recoverLabels/recoverMultistage/checkForMultistage/setOverride/encode/decode。

**fixture**:FX-SWITCHOVER(地址→块映射 + default maxcount 判定;需 FlowInfo.target)。

### Layer 4 —— 管线闭包(最后)

1. `stage_jump_table` 补 partial 克隆 + `truncated_flow` + fspec "jumptable" action 策略注册与切换(fspec.rs 需 allacts 等价物)。**这是与 oracle 行为对齐的决定性一步:oracle 的 JumpBasic 看到的是简化后的直线数据流**。
2. `ActionSwitchNorm::apply` 完整闭包(matchModel→recoverLabels→foldInNormalization→foldInGuards→structure clear)并删除 coreaction.rs 内自创 `recover_jump_tables` 预扫(改为 flow 驱动)。
3. `switch_over_jump_tables` 接真实现。

**fixture**:FX-E2E —— curl/httpd 12.0.4 golden(ORACLE-0002)中含 switch 的函数子集双侧差分;`tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c`。

---

## 4. 拟登记 TODO 清单

> 已存在并应继续沿用的 ID(本审计不重复登记):`JUMPTABLE-0001`(模型恢复闭包,P0 BLOCKED)、`PATHMELD-0001`(P0,= 本文 0.2)、`RANGE-0001`(P0 READY,= 本文 0.3)、`INJECT-0001`(ExecutablePcode,JumpAssisted 依赖)、`JUMPTABLE-GAPS-2026-08-22`(本审计自身)。以下为建议新登记项;验收统一为 locked 12.0.4 双侧 jumptable 恢复 fixture(oracle e40ed130 重放,fixture 记录 arch/compiler spec/options/输入指纹)。

| ID | 优先级 | 标题 | write-set | 依赖 | 验收 |
|---|---|---|---|---|---|
| `JUMPTABLE-EMULFN-0001` | P0 | EmulateFunction 1:1 重写(LOAD/MULTIEQUAL/CALL 忽略/BRANCH 抛错/loader fallback/lastOp) | `src/jumptable.rs`(EmulateFunction)、`src/funcdata.rs`(loader 访问器,如需)、`docs/api/jumptable.md` | loader 桥(loadimage.rs 已有 trait) | FX-EMULPATH:guard+ADD+LOAD 表单路径双侧 emulatePath 观察值序列 MATCH |
| `JUMPTABLE-CALCRANGE-0001` | P0 | calcRange 守卫交集写回 + isBoolOutput | `src/jumptable.rs`、API 文档 | RANGE-0001 | FX-BASIC:双侧 jrange(range/step/size)与 addresstable MATCH |
| `JUMPTABLE-GUARDS-0001` | P0 | analyzeGuards 完整移植 + checkUnrolledGuard 接线 + value_match 补全 | `src/jumptable.rs`、API 文档 | — (与上并行) | FX-GUARD:双侧 selectguards 序列(cbranch/readOp/indpath/range/quasiCopy base)MATCH |
| `JUMPTABLE-SELECTION-0001` | P0 | JumpTable::recover_model 模型选择顺序(Assisted→Basic→Basic2,去 Trivial 回退,maxtablesize 读 arch) | `src/jumptable.rs`、`src/arch.rs`(max_jumptable_size)、API 文档 | JUMPTABLE-EMULFN-0001 | FX-SELECTION:三类构造各一 fixture,双侧所选模型类型/size MATCH |
| `JUMPTABLE-OVERRIDE-0001` | P1 | Override 闭包:findStartOp/trialNorm/findLikelyNorm/setupTrivial/clearCopySpecific/recoverModel/encode/decode | `src/jumptable.rs`、`src/dynamic.rs`(接线)、API 文档 | JUMPTABLE-EMULFN-0001 | FX-OVERRIDE:手工 adset 双侧 values/addrtable/labels MATCH |
| `JUMPTABLE-ASSISTED-0001` | P1 | JumpAssisted 全方法 + JumpAssistOp 接线 + getTableSize+1 | `src/jumptable.rs`、`src/userop.rs`、`src/pcodeinject.rs`(evaluate)、API 文档 | INJECT-0001 | FX-ASSISTED 双侧 addresstable/labels MATCH |
| `JUMPTABLE-TABLEAPI-0001` | P0 | 表级 13 方法(switchOver/matchModel/recoverLabels/foldInNormalization+switchVarConsume/recoverMultistage/checkForMultistage/sanityCheck/block2Position/isReachable/numIndicesByBlock/getIndexByBlock/setOverride/addBlockToSwitch 修正/拷贝 ctor/encode/decode) | `src/jumptable.rs`、`src/flow.rs`(target)、API 文档 | PATHMELD-0001 | FX-SWITCHOVER 双侧 block2addr/defaultBlock MATCH |
| `JUMPTABLE-PIPELINE-0001` | P0 | stageJumpTable partial 克隆简化链(truncatedFlow + "jumptable" 策略)+ ActionSwitchNorm 闭包 + 去自创预扫 | `src/funcdata.rs`、`src/fspec.rs`、`src/coreaction.rs`、`src/flow.rs`、API 文档 | Layer 1-3 全部 | FX-E2E:curl_1204 golden switch 函数子集差分 defects=0 |
| `JUMPTABLE-HYGIENE-0001` | P1 | 卫生项:删 is_load_in_path 版本漂移、buildLabels orig-range 迭代、clone 仅 jrange、foldInNormalization 走 op_set_input、buildAddresses 失败语义、Basic2 foldInOneGuard/backward-throw、setup_trivial 值语义 | `src/jumptable.rs`、API 文档 | 各自局部 | 逐项双侧 fixture(合并进上述 FX-*) |

---

## 5. 结论

1. ROADMAP #21 所列 5 缺口**全部属实**;其中 guard/range 缺口比记载严重一个量级(calc_range 直接丢弃交集,守卫形同虚设),PathMeld/EmulateFunction 两项与记载一致。
2. 新发现 14 项未登记缺口,以 **calc_range 交集丢弃**、**analyze_guards pathout 首轮 break**、**JumpBasic::clone 全量克隆**、**表级 13 方法缺失** 为最重。
3. 最重依赖地基是 **stageJumpTable 的 partial-clone 简化链(truncatedFlow + "jumptable" action 策略)**:oracle 的一切 jumptable 算法都以"已在部分克隆上跑完简化"为输入前提;Rust 在未简化 IR 上直接跑,即使逐函数对齐也难复现 oracle 行为。其次为 EmulateFunction 的 LOAD/MULTIEQUAL 语义 + Funcdata→loader 桥(部件已备:loadimage.rs trait、memstate.rs MemoryImage、dynamic.rs DynamicHash::find_varnode,均为"已建成未接线"状态)。
4. `isJumptableRecoveryOn` 调用闭包:oracle 在 action.cc:566、funcdata.cc:175、heritage.cc:2714/2723、coreaction.cc:2284/3906 抑制恢复期副作用;Rust funcdata.rs:991/999/6974/7052/7267 已有 flag 与部分使用,但 partial 克隆缺失使其仅在 stop_processing 一处实际生效。

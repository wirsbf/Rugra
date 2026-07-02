# 批5 函数级对齐审计报告（2026-07-02）— SSA/Action 基础

> 纯只读并发审计。9 个 Agent。判档：✅ALIGN / ⚠️DIFF / ❌MISSING / ➕EXTRA。

## 批5 跨文件头号根因（续编 R70+）

| # | 根因 | 文件:行 | 直接症状 | Ghidra 对照 |
|---|---|---|---|---|
| R70 | **heritage 无 collect/disjoint-range pass + 无 size normalization** | heritage.rs | 重叠尺寸 varnode（栈内存常态）SSA 静默错链；`size=4` fallback 是地雷 | heritage.cc:2677-2772, 383-605 |
| R71 | **heritage 无 setInputVarnode → rename 空栈提升缺失** | heritage.rs/funcdata | 无 reaching def 的自由读悬空而非变正式输入 | heritage.cc:2500-2518 |
| R72 | **heritage deadRemovalAllowed 硬 true + getDeadCodeDelay 硬 2** | heritage.rs | deadcode-delay 集成全断（06-29 doc 标的）| heritage.cc:2817-2848 |
| R73 | **Action::perform 硬 1 迭代 + ActionGroup::perform 硬 2 迭代上限** | action.rs:90,265 | repeatapply 即便设了也跑不到收敛 | action.cc:303-350 do-while 无界 |
| R74 | **ActionGroup::apply 条件 dispatch（非 repeatapply 子调 apply 非 perform）** | action.rs:241 | 子组无 repeatapply 时不经 perform → onceperfunc/repeatapply flag 被忽略 | action.cc:514 |
| R75 | **Rule::get_opcodes 无"全 opcode"默认路径** | action.rs:174 | RuleCollapseConstants/PropagateCopy/EarlyRemoval 静默少覆盖（ruleaction 系统性 gap 的根源）| action.cc:707-714 base push ALL |
| R76 | **build_full_pipeline_actions 平铺进 universal 非 Ghidra 嵌套** | action.rs:785-787 | mainloop/stackstall/fullloop/merge 塌成单序列 | coreaction.cc:5462-5739 |
| R77 | **ActionInputPrototype 建抛 ParamActive + 硬 param_{N}** | coreaction.rs:4186-4224 | 48 param_ 占位真根因（非 fspec 层 0 trial）| coreaction.cc:4924 FuncCallSpecs activeinput |
| R78 | **FuncCallSpecs 无 op/fd/stackPlaceholderSlot + 无 buildOutputFromTrials** | fspec.rs | 无 stack-param placeholder + 无 spacebase-relative 解析；返回值不挂 CALL op | fspec.cc:5770 + hh:1671-1674 |
| R79 | **ParamTrial::split_lo 数学错**（size+addr 都错）| fspec.rs:625 | 双精度返回分裂错 | fspec.cc:1856 |
| R80 | **register_trial 不 markKilledByCall** | fspec.rs:692 | trial-use 判决偏 | fspec.cc:1973 |
| R81 | **FuncProto::is_input_locked 全锁 vs Ghidra 首锁/voidinputlock** | fspec.rs:180 | lock 语义错 | fspec.cc:3906 |
| R82 | **HighVariable::merge_internal 死代码 + 无 numMergeClasses** | variable.rs:133 + merge.rs | 实际 merge 经 merge_force 绕过；投机合并类不追踪→Ghidra 后拆的不能拆 | variable.cc:626,640-646 |
| R83 | **HighVariable highflags 脏枚举全缺 + 无 HighIntersectTest** | variable.rs | merge 无脏门控 + 无 copy-shadow 豁免→uVar 爆炸（确认 merge 审计）| variable.hh:119-131 + cc:947-1201 |
| R84 | **constseq RuleStringCopy/Store 丢类型/symbol 守卫** | constseq.rs:407-419,470-485 | 整数数组/非 addrTied 也被字符串合并→误触发 | constseq.cc:954-972,986-1002 |
| R85 | **dynamic hash 位布局完全不同 + transtable 是 identity 非 lumping** | dynamic.rs:305,30 | 产 hash 与 Ghidra 不兼容，永不互通 | dynamic.cc:370-379, 24-63 |
| R86 | **userop register_builtin_by_id 错 UserOpType（StringData 非 Datatype）** | userop.rs:378 | MEMCPY/STRNCPY/WCSNCPY 路由错 | userop.cc:449-477 |
| R87 | **userop VolatileRead/Write extract_annotation_size 读错 varnode** | userop.rs:178,196 | size 取错对象 | userop.cc:143-150,174-178 |
| R88 | **cpool CPoolRecord encode/decode 漏 value/data 分支 + 构析 flag** | cpool.rs | string_literal/primitive 不往返 | cpool.cc:32-155 |
| R89 | **options 28/38 是桩（hide_exts/inplace_ops/flowoptions 全不动作）** | options.rs:252-279 | 设选项零效果（确认 printc 审计）| options.cc 全 |

---

## 报告 1: heritage.rs — SSA 引擎

**Summary**: **核心数据结构 + 两主算法在且结构对**（dominator-frontier phi 放置 via calcDomFrontier + Cytron rename dom-tree DFS）。**但引擎三承重方式分歧，实质不完整——非 faithful drop-in**:

1. **per-space disjoint-range pass 循环全缺**。Ghidra heritage()（cc:2677-2772）是单函数迭代每地址空间，free varnode 收入 TaskList of **不相交内存范围** via LocationMap::add（cc:34-71 交集账），然后**每不相交范围**驱动 placeMultiequals/rename 一次。Rugra place_multiequals/rename 操作**整 vbank**（按 (space,addr) 分组），无不相交覆盖、无 collect/refinement/removeRevisitedMarkers。**单最大语义 gap**。
2. **size-normalization / refinement 机器（Ghidra 对重叠 varnode 正确性的心脏）缺**。collect/normalizeReadSize/normalizeWriteSize/concatPieces/splitPieces/buildRefinement/refineRead-Write-Input/remove13Refinement/refinement/guardInput **全缺**。两 varnode 部分重叠地址（如 4 字节写 + 1 字节读同址）时，Ghidra 插 PIECE/SUBPIECE 使尺寸统一再放 phi。Rugra phi 放置键精确 (space,addr)，insert_multiequal_direct 硬回退 `size=4`（heritage.rs:833）——**静默正确性地雷**。
3. **管线是定制 2-pass 非 Ghidra 单 heritage()/mainloop 迭代**。coreaction.rs:23-63（ActionHeritage::apply）硬编：pass1 place+rename → DeadCode → discover_and_guard_stack_stores_fd → pass2 place+rename。Ghidra discover→collect→guard→place→rename **在一个** heritage() 调用内。

**Pipeline 接线**: ActionHeritage::apply 从不调 Heritage::heritage()；用 place_multiequals_direct + rename_direct 两次夹 DeadCode。无 buildADT（用 calc_dom_frontier 不同算法）；无 processJoins；无 per-space 循环；infolist **永不填**（getInfo/delay 门是死码）；establish_range/finalize_range 空桩。

**关键修复**（见 R70-R72 +）:
1. P0 移植 collect() + disjoint-range pass 进 heritage()/place_multiequals。现 phi 键精确 (space,addr) 不能处理重叠范围（栈内存常态）。是"跨块 def 链断"根因类。接 globaldisjoint.add 真交集逻辑（cc:34-71）
2. P0 移植 size-normalization 三件：normalizeReadSize/normalizeWriteSize/concatPieces/splitPieces（cc:383-605）。删 heritage.rs:833 `size=4` fallback
3. P0 使 deadRemovalAllowed/getDeadCodeDelay/setDeadCodeDelay/seenDeadCode 真（buildInfoList 填 infolist，从 space 取 delay/deadcodedelay）。numHeritagePasses 须返 pass-delay 非 bare pass
4. P1 重写 discover_and_guard_stack_stores_fd 匹配 discoverIndexedStackPointers（cc:987-1103）：加 MULTIEQUAL/SEGMENTOP/INDIRECT/非 const INT_ADD 遍历 + traversals 位掩码 + 仅 traversals!=0 时 guard。现过 guard const 偏移 store + **漏所有真索引**（SP+var）
5. P1 INDIRECT 创建移入 guardStores（cc:1554）+ 恢复 (container==storeSpace&&usesSpacebasePtr())||(spc==storeSpace) 门控
6. P1 加 rename 空栈输入提升 + INDIRECT 同 op 特案（cc:2500-2518）。需移植 Funcdata::setInputVarnode
7. P2 guardCalls/guardReturns 效果表征（现空桩）+ guardLoads COPY-guard + handleNewLoadCopies/analyzeNewLoadGuards（需 ValueSet solver）+ 恢复单 heritage()/mainloop 接线

**注（非缺陷）**: Rugra 用 Cytron 迭代 DF（block.rs:1129），Ghidra 用 Bilardi-Pingali ADT——两都正确放 phi，可接受替代。domchild/augment/flags/depth/pq/merge 字段死。

---

## 报告 2: action.rs — Action/Rule 框架

**Summary**: **三先前审计头号 bug 全确认，发现第四关键 bug（迭代上限）使 repeatapply gap 比报告更糟**。

| 先前审计声明 | 验决 | 证据 |
|---|---|---|
| mainloop/fullloop 用 ActionGroup::new 非 rule_repeatapply | ✅确认+更糟 | action.rs:797,816 ActionGroup::new(flags=0)；Ghidra coreaction.cc:5487,5489 rule_repeatapply。**且**即便设了，两 perform 都硬限 1-2 迭代（下）仍不收敛 |
| ActionPool dispatch gap（无"全 opcode"）| ✅确认系统性 | Ghidra Rule::getOpList base（cc:707-714）push 全 opcode。3 规则靠此。Rust Rule::get_opcodes 返 Vec 无默认全路径；add_rule 只索引返 opcode |
| 两 builder 不一致 | ✅确认 | set_default_actions 真；build_full_pipeline 返**平 Vec** 直接加根 universal（action.rs:785-787），把 Ghidra 深嵌套（mainloop/stackstall/fullloop/merge）塌成单顶层序列 |
| ActionSetCasts 注释掉 | ⚠部分/现重复混淆 | set_default_actions 仍注释（action.rs:868），但 build_full_pipeline 含（coreaction.rs:7063）——从错路径跑 |

**新关键——迭代上限彻底击败 repeatapply**:
- 默认 Action::perform（action.rs:87-92）`if iterations>1 break`——限 **1 迭代**
- ActionGroup::perform（action.rs:262-267）`if iterations>2 break`——限 **2 迭代**
- Ghidra Action::perform（cc:303-350）`do{...}while(lcount<count&&(flags&rule_repeatapply))`——**无界**，跑到收敛
- **净**: 即便 stackstall（唯一正确有 rule_repeatapply，action.rs:829）最多跑 simplify pool 2×，非收敛

**关键修复**（见 R73-R76 +）:
1. P0-1 删 Action::perform 迭代上限（action.rs:90）。替 Ghidra 无界 do-while。**单最高杠杆修——无则 P0-2 无用**
2. P0-2 删 ActionGroup::perform override（action.rs:259-287）或至少 iterations>2 上限。更好：删 override 让继承默认 Action::perform（P0-1 后）
3. P0-3 修 ActionGroup::apply 调子 perform() 非 apply()（action.rs:241）。无条件 self.actions[i].perform（匹配 cc:514）
4. P0-4 mainloop/fullloop 设 rule_repeatapply（action.rs:816,797）
5. P0-5 Rule::get_opcodes 支"全 opcode"（action.rs:174）——改 Option<Vec> None=全 或加 applies_to_all() 默认 + ActionPool::add_rule 检测。修 RuleCollapseConstants/PropagateCopy/EarlyRemoval 声全
6. P1-6 修 ActionRestartGroup::apply 收敛检查（action.rs:350 res<0→res!=0）+ 先使 ActionGroup::apply 收敛返 0
7. P1-7 删 ActionSetCasts 注释重复
8. P1-8 加 start-break/action-break/status_mid 状态机到 Action::perform
9. P2-9 impl ActionDatabase::cloneGroup/addToGroup/deriveAction + setCurrent
10. P2-10 恢复 build_full_pipeline 正确嵌套

**观察**: build_simplify_pool/build_cleanup_pool/build_oppool2 是高质量忠实部（正确序+相分离+ping-pong 避）。bug 全集中在执行器（perform/apply/get_opcodes）+ 管线接线。

---

## 报告 3: fspec.rs — 调用约定/参数恢复

**Summary**: Rust 只建模 17 类中 5（EffectRecord/ProtoParameter-lite/FuncProto-partial/FuncCallSpecs-partial/ParamTrial/ParamActive）。缺 ParamEntry/ParamList*/FspecSpace/ParameterPieces/PrototypePieces/ProtoStore*/ParameterBasic/ParameterSymbol/ProtoModelMerged/ScoreProtoModel/UnknownProtoModel。

**HEADLINE**:
1. **buildOutputFromTrials 在 Ghidra 存在（fspec.cc:5770-5860）——coreaction P1"方法不存在"错**。方法全实现（~90 行：重排用输出 trial、1-trial/2-trial 案、建 SUBPIECE、销毁 INDIRECT）。**真**：在 Rust fspec.rs 不存在（只 build_input_from_trials 移植）。故 Rust 侧 gap 真，Ghidra 侧否认不真。
2. **ParamActive trial 在 Rust 存在**（fspec.rs:546-722 API 忠实）。**但 param_N 根因不在 fspec 层"FuncCallSpecs 0 trial"**——是 **ActionInputPrototype::apply（coreaction.rs:4186-4224）建抛 ParamActive::new(false)，从不存 FuncCallSpecs，从不调 derive_input_map，硬编 param_{N}**。FuncCallSpecs 自己 active_input（func_link_input→init_active_input 填）被该 action 忽略。这是 param_N 真根因。（修它的 fspec 基础设施全在但该 action 不用）
3. **check_input_trial_use 仅 model-match**——确认 coreaction P1
4. **setSpacebasePlaceholder/assumedOutputExtension 都不建模**——FuncCallSpecs 无 stack_placeholder_slot 字段。是 func_link_input/output stack-param + 小返回缺失片
5. **多静默语义 bug**: split_lo 产错 size/offset；slotbase/maxpass 初始化错；register_trial 漏 markKilledByCall；offset_unknown 哨兵异；is_input_active 语义异

**关键修复**（见 R77-R81 +）:
1. P0 param_N 根因（coreaction.rs 非 fspec.rs，但修需 fspec）: ActionInputPrototype::apply 须用 FuncCallSpecs active_input + derive_input_map/check_input_trial_use/build_input_from_trials + 从解析 trial 名——非建抛 ParamActive + 硬 param_{N}。**单修退 48 param_ 占位**
2. P0 ParamTrial::split_lo 数学错（fspec.rs:625-627）：C++ splitLo(sz)→addr+(size-sz),size=sz。Rust addr+sz,size-sz。修
3. P0 移植 buildOutputFromTrials（fspec.rs）——Ghidra 确实有（cc:5770）。ActionActiveReturn 解返回 trial 需要
4. P1 is_input_active/is_output_active/clear_active_* 语义（加显式 flag，容器常在）
5. P1 register_trial 须 markKilledByCall（fspec.rs:692, cc:1973）
6. P1 FuncCallSpecs 缺 op/fd/stackPlaceholderSlot/name/effective_extrapop/paramshift + spacebase-placeholder 机器
7. P1 FuncCallSpecs 构造分歧——改取 CALL PcodeOpRef
8. P2 FuncProto::is_input_locked/clear_unlocked_input/set_input_lock 三耦合 bug
9. P2 offset_unknown 哨兵 i64::MIN→0xBADBEEF
10. P2 ParamActive 初值（slotbase 0→1, maxpass 4→0）
11. P2 which_trial overlap vs equality
12. P3 ProtoParameter flag 位布局不兼容 ParameterPieces
13. P3 FuncProto/FuncCallSpecs ~55 方法缺（model 委托/getter/flag-toggle + 高值 hasModel/isModelUnknown/assumedInput-OutputExtension/setPieces/getPieces/checkInputJoin）

---

## 报告 4: constseq.rs — 字符串拷贝优化器（非 CSE）

**⚠️ 前提纠正**: constseq **非** CSE。是**常量序列/字符串拷贝优化器**——检测 COPY/STORE 写常量字符到连续内存，替成单 strncpy/wcsncpy/memcpy CALLOTHER。审计名（getCseHash/cseElimination/RuleSelectCse/ActionCse）在 op.cc/funcdata_op.cc/ruleaction.cc/coreaction.cc（Rust 全移植）**非 constseq**。grep constseq.cc/.hh + Rust constseq.rs **零** CSE 名。constseq 实际是 StringCopy/StringStore 字符串合并优化器，**实质 L3 对齐**（数据结构 WriteNode/ArraySequence/StringSequence/HeapSequence + 两 Rule + CALLOTHER-builder + transform + 6 单测）。

**Pipeline 接线**: RuleStringCopy（action.rs:692）/RuleStringStore（action.rs:693）接 cleanup 池；getOpList COPY/STORE 对；BUILTIN id 对。

**关键修复**（见 R84 +）:
1. interfere_between 语义错（rs:80-104）：Ghidra evaltype+白名单；Rust 黑名单。CPOOLREF/NEW/SEGMENTOP 巧合合。重写
2. check_interference 重实现非移植（rs:110-168）：分离 collectCopyOps 和 干涉截断 checkInterference + 移植双向走
3. form_byte_array 简化非移植（rs:193-214）：缺大端、null 终止符、连续区计数、moveOps 截断。**wide-char/大端正确性 gap**
4. **RuleStringCopy/Store apply_op 丢类型/symbol 前提**：Ghidra 门 ct->isCharPrint()+!isOpaqueString()（+StringCopy outvn->isAddrTied()+queryContainer SymbolEntry；+StringStore ptr TYPE_PTR）。Rust 守卫纯 is_constant()+opcode+偏移算术。无 char-print/addrTied/SymbolEntry 检查→尝试合并 Ghidra 拒绝的整数数组/非 addrTied 临时→误触发 strncpy/wcsncpy/memcpy。**最高风险功能分歧**
5. 次要 MAXIMUM_SEQUENCE_LENGTH 1024→131072；未用 is_store/dest_ptr_addr 接 constructTypedPointer/HeapSequence basePointer+baseOffset；docstring 1146→1004 行

---

## 报告 5: variable.rs — HighVariable

**Summary**: **HighVariable 存在且在管线用**——先前"varmap 审计"HighVariable=0 引用**事实错**。引用在 merge.rs/coreaction.rs/cover.rs/action.rs；ActionAssignHigh 每 Varnode 构造一个。uVar_ 爆炸风险真，但根因**非缺类**——是合并/脏机器的**浅、非忠实重实**。

**三关键检查全失败**:
1. merge/mergeInternal → merge_internal 在但**非忠实且未用**。真合并路径（merge.rs::merge_force/merge_speculative）内联合并不调 merge_internal。审计方法是死码
2. numMergeClasses → **缺**。无字段、访问器、投机合并类追踪。Varnode.mergegroup 在（varnode.rs:90）但从不被任何合并增量/偏移
3. updateCover/updateInternalCover/脏 flag → update_internal_cover 在（饿、无条件）。updateCover（组/片感外部 cover）**缺**。整个 highflags 脏枚举缺——update_internal_cover 无条件跑非 coverdirty 门控

**关键修复**（见 R82-R83 +）:
1. P0 numMergeClasses/投机类追踪——Ghidra mergeInternal 分投机合并 Varnode 入独立合并类。Rust 无 num_merge_classes、无 Varnode.mergegroup 变更、merge_speculative 无条件并入一平实例列表。经忠实 mergeInternal+numMergeClasses 重实合并非 ad-hoc merge_force/merge_speculative
2. P0 真 merge 管线绕过 merge_internal——要么删 merge_internal 要么（更好）使 merge_force/merge_speculative 委托之，移植 cc:626-666 body
3. P1 highflags 脏枚举全缺——加 highflags:u32 + 11 位枚举，update_internal_cover 门 coverdirty，加 coverDirty/typeDirty/flagsDirty setter
4. P1 HighIntersectTest 缺（确认 merge 审计）——Ghidra 合并正确性依赖 HighIntersectTest::intersection。Rust merge_speculative 用裸 Cover::intersects 无 copy-shadow 豁免→COPY 输入输出 cover 在 COPY op 合法重叠判"同时活"不合并，而 Ghidra 合并。**uVar_ 增殖直接因**。移植 HighIntersectTest（或至少加 copy-shadow 豁免）
5. P2 has_name/get_type_representative/get_name_representative/strip_type 非忠实
6. P2 VariableGroup/VariablePiece 子系统全缺
7. **非问题更正**: 前提"varmap 审计 HighVariable=0 引用"+"CRITICAL 是否定义"**两都驳**。定义且用跨 ≥4 模块。真关键性是 merge_internal/numMergeClasses/HighIntersectTest 浅

---

## 报告 6: userop.rs

**Summary**: enum/常量/flag 编码 + UserOpManage 容器忠实翻译，**但三语义错使专例子类层不安全消费**：(1) SegmentOp::execute 硬编实模式 `<<4` 对保护模式 x86-16 错；(2) volatile/string 内建用错 UserOpType（Ghidra 建 DatatypeUserOp）；(3) volatile extract_annotation_size 读错源。L2.5 骨架一致。引用准确度全对。

**Pipeline 接线**: arch.rs:267 userops 在；constseq.rs:290-291 register_builtin_by_id 活消费。SegmentOp 集成**不全**——segment_ops HashMap 在但 register_op 不填它（Ghidra registerOp cc:515-526 经 dynamic_cast 索引）→get_segment_op 实践总 None。

**关键修复**（见 R86-R87 +）:
1. ❌ SegmentOp::execute 硬 `<<4` 只对 x86-16-real；x86-16.pspec 用 `<<16`。存 pspec 解码字段或返 None（不折）
2. ❌ register_builtin_by_id 错 UserOpType——MEMCPY/STRNCPY/WCSNCPY 须 DatatypeUserOp（cc:449-477）非 StringData
3. ❌ VolatileRead/Write extract_annotation_size 读错 varnode——须取 &PcodeOp 读 getOut/get_in(2)
4. ⚠️ register_op 须索引 SegmentOps（cc:515-526）
5. ⚠️ Volatile/StringsOp 构造丢 display flag
6. ⚠️ UserOpManage::get_op 须回退 builtin_map
7. 次要 supports_index 无 Ghidra 对应→baseinsize/innerinsize；register_builtin "strcpy"→"strncpy"

---

## 报告 7: dynamic.rs

**Summary**: **产 hash 与 Ghidra 位不兼容，opcode 翻译表不做其 doc 声称的 lumping，~40% 公共 API（uniqueHash/findVarnode/findOp 解析往返）全未移植**。如写，Rugra hash 永不被 Ghidra 解析反之亦然。**零调用者，全死码**。

**三承重错**:
1. **hash 位布局是不同设计非 Ghidra**。Ghidra 包（LSB→MSB）: 32 CRC|5 slot|7 opcode|4 method|1 not-attached|3 pos|3 total。Rust: 32 CRC|6 method|6 opcode，**无 slot 字段**——method 写入 Ghidra 留给 slot 的位。每个 getter 因此移错位，get_slot_from_hash 硬返 -1
2. **translate_opcode 是 identity 非 lumping 表**。doc 说"Lumps 变体...Faithful to transtable"但 body 每 opcode 返 opc as u32。Ghidra transtable（cc:24-63）塌 INT_SUB→INT_ADD, INT_LEFT→INT_MULT, INT_NOTEQUAL→INT_EQUAL 等。Rust 啥都不塌
3. **BFS 子图展开器 + 解析 API 未实**。gatherUnmarkedVn/gatherUnmarkedOp（迭代展开核）、moveOffSkip/dedupVarnodes/uniqueHash(×2)/findVarnode/findOp/gatherFirstLevelVars/gatherOpsAtAddress 全缺。calc_hash_vn/calc_hash_op 单层展开误解 method 索引

**关键修复**（见 R85 +）:
1. hash 位布局改 Ghidra 精确包（cc:370-379）；重写 7 getter+clear_total_position；实 get_slot_from_hash
2. translate_opcode 实 lump（镜像 transtable cc:24-63）；修 ToOpEdge::hash_into 丢零字节早断用地址尺寸
3. piece_together_hash：seed 0x3ba0fe06 非 0xffffffff；删 ^=0xffffffff；hash 常量根偏移字节；扫 op_edge 找 attached op（带 skip-op 回退）导 opcode/slot/is_not_attached；addr_result 用 attached op seqnum 地址非 root.get_offset()
4. build_vn_up 须 push ToOpEdge(def_op,-1)（vn 是输出）。CAST/skip-op 遍历恢复
5. 移植 BFS 核 + 解析 API（gather*/moveOffSkip/uniqueHash/findVarnode/findOp）+ 修 calc_hash_vn/op method 分派

---

## 报告 8: cpool.rs

**Summary**: 查询/查找机制（CPoolRecord + getRecord via CheapSorter-keyed map）忠实正确，**但 marshaling 层实质不全且静默丢数据**——与 L3 保真声明矛盾。8 tag/flags 枚举精确，CPoolRecord 字段集/CheapSorter 序/BTreeMap 查找精确。

**关键 gap**:
- ❌ CPoolRecord::encode/decode 语义未移植——Rust 内联版**漏构析 flag、<value> 元素、<data> hex-dump 元素、类型引用**。串字面量/原始值**不往返**（string_literal 编空 <token> 无 <data>，重解码为空）
- ❌ ConstantPool::decodeRecord 缺；encode/decode 不在 ConstantPool trait
- ⚠️ type:Datatype* 替 type_name:String——破坏 encodeRef/decodeType 语义
- ⚠️ marshal 名分发 + 数字 ID 0 全用 vs Ghidra 注册 ID（ELEM_CPOOLREC=110 等）

**关键修复**（见 R88 +）:
1. ❌ CPoolRecord encode/decode 实质不全（阻 L3）——移植全 encode/decode 含构析 writeBool/<value>/<data>/<token>↔<data> 分支/LowlevelError。加往返测
2. ❌ 解 type 字段——接 TypeFactory 或文档延迟
3. ❌ 加 decodeRecord 到 trait + hoist encode/decode 到 trait
4. ⚠️ marshal ID 对齐——若 marshal crate 镜像 Ghidra ID-key 二进制分派，ID 0 碰撞将腐解码
5. ⚠️ put_record 错处理漂——传 LowlevelError 非 log+continue

---

## 报告 9: options.rs

**Summary**: 注册/分发脚手架忠实移植，**但 38 选项中仅 ~10 真变状态**。printc 审计投诉（"无 hide-exts"/"无 in-place ops"）**效果上正确**：那些选项注册为 no-op 桩返确认字串不触任何。**L3 声明不义**——结构 L1/L2（注册表+少数活 setter）包在完整看 API 表面里。

**三结构事实**:
1. **注册过计 1**。Rust 注册 38；Ghidra 37。差 OptionHideExtensions——Ghidra 声明类+impl apply 但**从不 registerOption**（死码）。Rust 注册。无害保真偏离
2. **toggle_option! 宏（rs:220）死码**——0 调用点。38/28 选项经 stub_option! 宏（rs:238）——纯 no-op：格式 "{desc}: {p1}" 不变任何
3. **ArchOption trait + OptionDatabase 分发健全**。键差：Ghidra 键 uint4 ElementId；Rust 键名 String。功能等价但绕 ElementId 注册表

**37/38 集对等精确**——每 Ghidra 选项有 Rust 对应反之（减 HideExtensions 过注册）。4 桶: A 活忠实(7) / B 活不全(2: SplitDatatypes/NanIgnore 设位但丢 allacts.toggleAction/enableRule) / C 桩返字串不变(28，含 hide_exts/inplace_ops/null/convention/nocast + 4 flowoptions + ... 全 stub) / D 仅注册错(1 HideExtensions)。

**关键修复**（见 R89 +）:
1. 关键（阻 printc 保真）: 实 5 PrintC-耦合桩为真 setter（hide_exts/inplace_ops/null/convention/nocast）+ c-language 守卫。直解 printc 审计两发现
2. 关键（影响流分析）: 4 flowoptions 桩 + JumpLoad 须 OR/AND-clear FlowInfo flag。现设选项零效果
3. 高: 完成 B 桶 SplitDatatypes/NanIgnore 加 allacts.toggleAction/enableRule
4. 高: 错语义匹配 Ghidra——on_or_off 拒未知；set 未知选项/DefaultPrototype 未知模型应报错
5. 中: 重写 decode_one 镜像 Ghidra 严格位置 parse
6. 低: 删 HideExtensions 过注册；删死 toggle_option! 宏
7. 低: 恢复丢分支（AliasBlock/NanIgnore/SplitDatatypes/ReadOnly "unchanged"/空守卫）

---

## 批5 总结

- 9/9 报告完成
- 头号根因 20 个（R70-R89）入修复清单
- **R70（heritage 无 normalization）+ R82-R83（HighVariable 无 numMergeClasses/HighIntersectTest）是 uVar_/变量合并失败的 SSA 层根因**
- **R73-R76（action 迭代上限 + dispatch + 平铺）是 Action 不收敛的框架层根因**——单最高 ROI（删上限）
- **R77（ActionInputPrototype 抛 ParamActive + 硬 param_N）是 48 param_ 占位的真根因**——修在 coreaction 非 fspec
- **constseq/dynamic/userop/cpool/options 揭示"代码在但行为桩/错"**——比纯缺更隐蔽
- **更正两个先前审计误判**: buildOutputFromTrials 在 Ghidra 确实有（coreaction P1 否认错）；HighVariable 在 Rust 确实定义且用（varmap 审计"0 引用"错）

下一步: 批6 最后 ~22 文件。

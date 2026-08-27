# `merge.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/merge.rs`

## 模块说明 (Module Doc)

High-level variable merging logic

Corresponds to Ghidra's `merge.hh`. This module is responsible for
merging multiple SSA Varnodes into a single HighVariable.

## 导出的公共 API (Public API)

### `pub struct Merge`

Manages the process of merging Varnodes into HighVariables

Corresponds to Ghidra's `Merge` class. Groups SSA varnodes that
represent the same logical variable into `HighVariable` instances,
then assigns human-readable names to each group.

### `pub fn new() -> Self`

Create a new Merge instance

### `pub fn clear(&mut self, fd: &mut Funcdata)`

Clear all existing HighVariables and reset merge state

### `fn live_varnode_set(fd: &Funcdata) -> HashSet<usize>` (private)

Liveness for merge. Builds the set of varnode Arc pointers that are still
referenced (as input or output) by any **alive** op — drawn from
`fd.obank.alivelist` plus block-level ops not marked DEAD. The result is
cached in `Merge::live_set` once per `merge_all` run and consulted by every
`loc_tree` traversal.

Why membership-in-alive-op-set, not `vn.def`/`vn.descend`: after
copy-propagation redirects `user.inrefs[slot]` to a new source, the old
varnode's `vn.def` still points at the now-marked-dead COPY op, and
`vn.descend` becomes empty — even though the varnode is still live (the
new consumer references it). So def/descend are unreliable post-optimization
signals; the only authoritative liveness source is "is this varnode in some
alive op's inrefs/output?". Input varnodes (function parameters) are always
live.

This is what makes `high.instances` authoritative when merge runs after
dead-code in the pipeline.

**Note (2026-07-02)**: `live_set` is now consulted only for cover computation.
`ensure_all_have_high` and `assign_names` no longer filter by it — they
iterate the full `loc_tree`, faithful to Ghidra's `Funcdata::setHighLevel`
(funcdata_varnode.cc:595) and `ActionNameVars::linkSymbols`
(coreaction.cc:2940-2976). The prior live_set filter left implied/CAST-output
and free Varnodes without a HighVariable name, forcing printc into the
`uVar_{offset}` fallback (341 placeholders in curl).

### `pub fn merge_all(&mut self, fd: &mut Funcdata)`

Perform the full merging + naming pipeline. Phase order:
1. `live_varnode_set` → cache authoritative live varnodes
2. `merge_addr_tied` → force exact-location runs inside maximal overlapping
   processor/spacebase clusters and form offset-aware `VariableGroup`s
3. `ensure_all_have_high` → singleton HighVariables for EVERY Varnode in
   `loc_tree` lacking one (faithful to `Funcdata::setHighLevel`,
   funcdata_varnode.cc:595 — no live_set filter)
4. `group_partials` → reconstruct marked PIECE/CONCAT trees in sorted
   PcodeOpTree order into offset-aware `VariableGroup`s (merge.cc:967-976,
   1374-1407), allowing
   structured pointer expressions to use the root HighVariable.
5. `compute_varnode_covers` → per-Varnode liveness covers (precise def→use
   range, NOT propagated through CFG successors — that over-approximation
   broke ActionMarkImplied's inflateTest; `propagate_cover_through_cfg` is
   now `#[allow(dead_code)]` disabled)

`protoPartial` ordering evidence: Ghidra registers roots from the ordered
`ActionPool::processOp` traversal (`action.cc:822`), and `groupPartials`
consumes that vector without sorting (`merge.cc:970-975`). Rugra's action
iterator advances the ordered `PcodeOpTree` (`action.rs:1400-1414`), and
`group_partials` consumes that same order. The HashSet only deduplicates root
identity after collection and cannot alter first-seen order. `groupWith` has
no duplicate/failure branch (`variable.cc:574-605`), so repeated offsets are
permitted rather than silently inventing an error path. The regression test
`test_compare_order_selects_strictly_earlier_op` asserts the -1/+1 polarity.
5. `merge_by_cover` → merge copy-related disjoint-cover pairs
6. `update_high_covers` → sync each HighVariable.cover from members
7. `assign_names` → Ghidra-style auto-naming

### `fn update_high_covers(&mut self, fd: &mut Funcdata)` (private, 2026-06-29)

Re-derive every HighVariable's internal cover by calling
`high.update_internal_cover()`. Collects distinct HighVariables reachable
from loc_tree varnodes (deduped by Arc pointer). Must run after
merge_by_cover finalizes instance sets so high.cover reflects all members.
ActionMarkImplied (later in pipeline) consults high.cover.

### `fn update_high_cover(high)` 调用点修复（2026-08-15，`COVER-REBUILD-SELFLOCK-0001`）

`update_high_cover` 对 high 自身 instances、piece Varnode 及相交
HighVariable 的 instances 逐个改调 `Varnode::update_cover_locked(&instance)`
（原来是 `instance.write().update_cover()`）。旧路径在持 root Varnode 写锁
的 `&mut self` 里再进入 `Cover::rebuild` 读取同一 Arc，遇到 MULTIEQUAL
slot 与 root 同一 Arc 的图（parseconfig 真实输入）即永久自锁；新入口由
`update_cover_locked` 在持锁窗口内快照 def/descend/implied 并以 Arc 身份
重建，不再重入。完整自锁拓扑（slot2 self-reference + 双槽读）由
`tests/oracle/cover_rebuild_1204.*` 行为门禁覆盖；`ActionMergeType`
caller 闭包与 cleanup 后动作顺序仍归 `PIPE-MERGETYPE-ORDER-0001`。

### `pub fn mark_implied(vn: &Arc<RwLock<Varnode>>)` (2026-06-29)

Faithful to Merge::markImplied (merge.cc:1595). Sets the IMPLIED flag on a
varnode. Ghidra also marks coverdirty on the def op's inputs; Rugra
recomputes covers wholesale per merge_all so only the flag is set. Called
by ActionMarkImplied when checkImpliedCover passes.

### `pub fn inflate_test(a: &Arc<RwLock<Varnode>>, high: &HighVariable) -> bool` (2026-06-29)

Faithful to Merge::inflateTest (merge.cc:1616). Tests if inflating varnode
`a`'s cover to cover `high` causes an intersection with a sibling instance
of a's own HighVariable (excluding `a` itself / its copy-shadow). Returns
true if there IS an intersection (varnode CANNOT be implied). The
authoritative check in ActionMarkImplied::checkImpliedCover.

### `pub fn merge_addr_tied(&mut self, fd: &mut Funcdata)`

Locked `Merge::mergeAddrTied`（`merge.cc:609-648`）入口。它按
`VarnodeLocSet` 的 location 顺序扫描，整空间只接受
`IPTR_PROCESSOR`/`IPTR_SPACEBASE`；每个地址段用
`VarnodeBank::overlapLoc`（`varnode.cc:1791-1820`）形成最大传递重叠簇，
并且每个精确 `(space,offset,size)` run 只读取第一个成员的 raw flags。
簇含 `ADDRTIED` 时先对整个重叠簇 `unifyAddress`，再按
input → written `SeqNum` 顺序以首个 High 为 survivor 强制合并每个精确
run，最后把不同 offset/size 的 High 以相对首地址的 offset 放入同一
`VariableGroup`。这不是简单的 `(Address,size)` 哈希分组。

`try_merge_addr_tied` 是 Result-bearing Rust 内核，保留当前覆盖路径上 locked
`mergeRangeMust`/`groupWith` 的错误文本，包括
`Cannot force merge of range`、`Forced merge caused intersection`、
`Duplicate VariablePiece` 和 speculative merge-class 错误。现有
`merge_addr_tied -> ()` Action 边界只能把 Err 转成 panic，异常类别仍与
C++ `LowlevelError` 不同，因此 production 边界明确为 **MISMATCH**，不得用
相同文本冒充完整异常通道 MATCH。

`AddrTiedLocRange` 的 gate flags 字段为 `head_flags`（自 `first_flags`
更名）：只记录每个精确 `(space,offset,size)` run **头成员**（`VarnodeLocSet`
顺序首位）的 flags。这是对 locked `overlapLoc`（`varnode.cc:1791-1820`）的
插桩验证结论：`:1798` 读首 run 头的 flags，`:1813` 只对**后续 run 的头**做
OR，而 `:1800/:1815` 的 `endLoc(size,addr,written)` 跳跃（`upper_bound` 于
`(addr,size,written,SeqNum(m_maximal))`）会越过同位置的**全部**后续成员——
同 run 的非头成员永不参与 gate。`merge_addr_tied_inner` 的 cluster 级
`head_flags` 折叠复现该跨 run 头联合（簇扩展条件
`next.offset <= running maxOff` 与 `:1804` 的延续条件一致）。
`tests/oracle/merge_overlaploc_1204.*`（runner
`tools/run_merge_overlaploc_oracle.sh`）双侧字节一致地钉住两个方向：
正例 cross-run 头联合门控（raw 头 + 重叠 run 的 addrtied 头 → run1 a+b
合并为 2-instance High、run2 c 独立），负例同位置后置成员不门控
（唯一 addrtied 成员非头 → 无合并，`hi=1, same=a~b=0`）；per-member OR
变体（把同 run 后续成员 flags 也 OR 进 gate）在负例上分歧（错误合并
`hi=2`），证明该 fixture 可鉴别该类回归。双侧 fixture 均在两个 case 之间
reset `rule_onceperfunc` 子 Action（C++ `Action::reset` / Rust
`ActionState::reset_for_function`），否则第二个 Funcdata 上的子 Action 全部
命中 `status_end` 短路（`action.cc:343-344/:352-356`），负例将退化为空转。

地址空间仍有一个表示层缺口：`Ram/Register/Overlay` 可确定为 PROCESSOR，
`Stack` 可确定为 SPACEBASE，locked `OtherSpace::INDEX == 1` 可确定为
PROCESSOR；`AddressSpace::Other(non-1)` 已丢失真实 `AddrSpace::getType()`，
实现选择 fail-closed。自定义 processor 或 spacebase（locked
`translate.cc:47-60` 允许任意 index 的多个 SpacebaseSpace）因而是源码已证明的
**MISMATCH**。

`tests/oracle/merge_addrtied_gates_1204.*` 使用真实双侧
`Funcdata/VarnodeBank/PcodeOp/HighVariable/VariablePiece/VariableGroup`
生产结构和 production `mergeAddrTied` 入口，投影 raw flags、输入/写入身份、
最大重叠簇、High 成员顺序、piece offset/size、group size/身份及 canonical
projected 成员、异常文本。C++ observer 从 tracked nodes 重建成员后按
`(offset,size)` 排序，而 Rust observer 读取实际 `group.pieces`；0/4/10 又恰按
升序插入，因此相等只证明该 projected order，不证明真实容器 comparator/迭代
顺序。门禁只决定性覆盖 register/ram/locked OTHER@index1/stack 进入，以及
unique/join 跳过；Overlay、Iop/Fspec、Const 等其余 variant 仍 **UNTESTED**。
其余覆盖包括首成员
ADDRTIED gate、mixed input/written 实例及其当前观察顺序、传递重叠及 0/4/10
mixed-size grouping、implied forced error。由于 input 恰在 written 之前创建，
且 written 的 `SeqNum` 与创建顺序同向，该 fixture 尚不能区分真正的
input→written→SeqNum comparator 与 creation-index 排序，故这一排序规则仍为
**UNTESTED**。此外未覆盖 duplicate piece、forced intersection、
neither-grouped speculative merge-class error 及 pre-existing piece group。
若已有一侧 grouped，旧 `merge_highs` 路径仍会在
`numMergeClasses != 1` 时记录后继续，而 locked Ghidra 会在 dirty
flags/symbol 与 piece-transfer 突变后抛 `LowlevelError`；这是源码已证明的
**MISMATCH**，并非单纯 fixture 缺口。若两侧都 grouped，旧路径仍是
debug-assert/release-false，同属 required-merge closure **MISMATCH**。
implied error 的 MATCH 也只限投影出的 payload、Varnode/High/group/topology；
High cover/type/nameRep/symbolOffset、Varnode mergegroup/cover/type/addlflags、
piece intersection/cover、group symbolOffset、Merge cache/copyTrims 与精确 op 边
仍未形成全状态闭包，记为 **UNTESTED**。该 error case 也在任何成功 exact-run
merge 之前即遇 IMPLIED，因而没有证明先发生部分突变后再抛错的 traversal timing。
传递重叠 case 证明了扩展与 `next.offset == maxOff + 1` 排除，但没有
`next.offset == maxOff` 输入，故 inclusive `<=` 边界仍 **UNTESTED**。
另一个刻意不合成的状态是 `opUninsert` 后的
dead-op/non-free written output：locked `mergeAddrTied` 本身确实没有 alive
过滤，但 `BlockVarnode::set` 会解引用已清空的 defining-op parent，说明它不在
该 Action 的合法调用前提内；Rust 同样不应在 merge 层自创 live_set 门。
因此只有列出的投影可判 MATCH，函数整体保持 MISMATCH/L2。

### `pub fn merge_test(&self, v1: &Varnode, v2: &Varnode) -> bool`

Test whether two varnodes can be merged into the same HighVariable.

Returns true if they share the same address space and size, and
neither is a constant or annotation (which should never be merged).

### `pub fn merge_force(&mut self, vn1: Arc<RwLock<Varnode>>, vn2: Arc<RwLock<Varnode>>)`

Force-merge two varnodes into the same HighVariable.

If vn1 already has a HighVariable, add vn2 to it (or vice versa).
If neither has one, create a new HighVariable for both.

### `pub fn assign_names(&mut self, fd: &mut Funcdata)`

Assign human-readable names to all HighVariables in the function.

Iterates every Varnode in `loc_tree` except constants and annotations
(faithful to `ActionNameVars::linkSymbols`, coreaction.cc:2940-2976).
Free Varnodes are named too — see the TODO in source: Ghidra skips `isFree()`
because its printc routes free Varnodes to `pushUnnamedLocation` (raw address),
but Rugra's printc still emits them (SSA-completeness gap), so they need a
name to avoid the `uVar_{offset}` fallback.

Naming follows Ghidra conventions:
- Stack negative offset → `local_Xh`
- Stack positive offset → `param_stack_Xh`
- Register → `uVarN`
- Unique temp → `uVarN`
- RAM global → `DAT_XXXXXXXX`

### `pub fn merge_adjacent(&mut self, fd: &mut Funcdata)`

当前实现覆盖 locked Ghidra 12.0.4 `Merge::mergeAdjacent`
（`merge.cc:983-1012`）的主循环：按 alive op 顺序对每个非 call op 的输出
尝试与其各输入合并。已覆盖门链：
`mergeTestBasic`（out/in）→ **`outputTypeLocal()==inputTypeLocal(i)` 类型门**
（:1001，`adjacent_local_types_match` 以 `LocalTypeKey` 规范等值 + 经
`factory_nochar_distinct` 比较 `get_base/get_base_no_char` 的实际 canonical
`Arc`）→ 尺寸相等 →
`mergeTestAdjacent`（:175-218 全守卫链）→ 非相交 cover 时推测合并
（`merge_speculative_by_vn(..., true)`，输出侧存活）。但 local-type 门仍是
上层 `LocalTypeKey` 模型，不是 Ghidra TypeFactory/TypeOp 返回的实际 canonical
对象身份；自定义 core 名称和多 non-char INT1 的 nochar 关系已闭合，Java
ZEXT、CPOOLREF/CALLOTHER/INDIRECT 等仍绑定
`TYPEOP-LOCALTYPE-DISPATCH-0001`。因此本函数保持 MISMATCH/L2。

### `pub fn merge_multi_entry(&mut self, fd: &mut Funcdata)`

对齐 locked Ghidra 12.0.4 `Merge::mergeMultiEntry`（`merge.cc:908-963`）。
按拥有 ≥2 个全尺寸 SymbolEntry 的 Symbol 重建分组（Rugra 从 Varnode 的
mapentry 反向指针重建；Symbol 按 SymbolNameTree 顺序 `(name, nameDedup)`
排序遍历，database.hh:366-370），对每个符号以 `mergeList[0]` 的 High 为
anchor：`testCache.updateHigh(anchor/newHigh)`（:930-935）→
`mergeTestRequired(anchor, newHigh)` 门（:936-941）失败时 `setMergeProblems`
（`dispflags |= merge_problems`，database.hh:240）+ `newHigh.setUnmerged()`
（variable.hh:168）+ `conflictCount`，continue → `merge(anchor, newHigh,
false)`（:942-947，anchor 存活）失败时同样标记；结束按 :950-961 的精确
warningHeader 文案报告（`Unable to[ fully] merge symbol: N[-- Some instance
varnodes not found.][-- Some merges are forbidden]`）。skipCount 在 Rust
重建中恒为 0（无 linked Varnode 的 SymbolEntry 上游不可见，无 ScopeLocal
multi-entry 注册表）。

### `pub fn merge_marker(&mut self, fd: &mut Funcdata)`

对齐 `Merge::mergeMarker`（merge.cc:889-902）：按 alive op 顺序遍历非
indirect-creation 的 marker op，INDIRECT → `merge_indirect`，MULTIEQUAL →
`merge_op`。

### `merge_indirect` / `snip_output_interference` / `collect_inputs`（私有）

对齐 `Merge::mergeIndirect`（merge.cc:846-882）全路径：`!isAddrForce` →
直接 `mergeOp`（:850-853）；否则先 `mergeTestRequired(out,in)` +
`merge(in_high, out_high, false)`（**输入侧存活**，:857，与 mergeOp 的
输出侧存活方向相反），失败后 `snip_output_interference`（:862；内部
`collect_inputs` 沿 previousOp-INDIRECT 链收集输出 high 的读
merge.cc:783-802，按 `PcodeOpNode::compareByHigh`（expression.hh:54，High
指针序）分组，每组一个 `allocate_copy_trim` snip COPY + 读重定向
:822-837），再试合并（:864-867）；最后兜底用 `allocate_copy_trim` 剪断
INDIRECT 本身（:871-877）并重合并，失败打 `[MERGE]` stderr 日志（Ghidra
:881 throw 的既定降级）。union 解析继承（:872-875 / :417-428）保守省略。

### `build_dominant_copy` 尾合并（私有）

对齐 merge.cc:1235-1237：`count > 0 && domCopyIsNew` 时直接执行
`HighVariable::merge(domHigh, NULL, true)` —— **null testCache**：无
`testCache.intersection` 预检、无 `moveIntersectTests`（Rust 直调
`merge_highs`，不经过 `merge_speculative`）；speculative 类语义由
`u.mergeGroup += numMergeClasses`（variable.cc:640-646）观察。

### `merge_highs` 的 (Some,Some) piece 臂（私有）

对齐说明：oracle variable.cc:699-711 对 speculative 抛 LowlevelError（经
`Merge::merge` 的常见 speculative 调用由 mergeTestAdjacent
（merge.cc:208-209）拒绝双 piece 候选；buildDominantCopy 直调传新分配、
无 piece 的 unique。非 speculative 则应走 `piece->mergeGroups` + 成对
`mergeInternal` + `markIntersectionDirty`。`merge_addr_tied` 现在会真实生产
piece/group，因此旧注释所称“全局不可达”已不成立：后续 required merge
若同时收到两个 grouped High，当前 `debug_assert!`/release `false` 仍与
oracle 不同，作为独立调用闭包缺口保持 **MISMATCH**，不在本切片窄投影的
MATCH 范围内。

### `wire_unique_high`（私有，RUGRA-GLUE）

Ghidra `Funcdata::newUnique` 立即为新 unique Varnode 调 `assignHigh`
（funcdata_varnode.cc:88-89）；Rugra `new_unique` 不分配 High，故
`allocate_copy_trim` 与 `build_dominant_copy` 的 dominant COPY 输出在此
补接（否则 :879/:766/:1236 的合并对 None High 静默 no-op、mergeOp phase-2
对 trim 输入过度剪枝）。funcdata.rs 侧 latent 缺口已登记 TODO。

### `pub fn merge_by_datatype(&mut self, fd: &mut Funcdata)`

对齐 locked Ghidra 12.0.4 `Merge::mergeByDatatype`（`merge.cc:359-401`）。
它按 `loc_tree` 顺序扫描完整生产范围，先排除 free 和
`mergeTestBasic` 不合格 Varnode，再用 HighVariable 的 mark 位稳定去重；mark
在分组前按收集顺序清除。分组只接受同一个 `Datatype *`（Rust 中为
`Arc::ptr_eq`），不会把结构相等但身份不同的类型合并。

每组由 `merge_linear` 执行 locked `merge.cc:272-292` 顺序：先更新所有
High Cover，按首个 Cover block、首实例完整存储地址、无定义优先、定义
p-code 地址四级排序；随后按 high-stack 插入顺序尝试第一个通过
`mergeTestSpeculative` 且 Cover 不相交的候选。

Cover 相交采用 `HighIntersectTest` 的双向缓存、block refinement、
copy-shadow/partial-copy-shadow 判定和成功合并后的缓存迁移。成功时第二个
HighVariable 的实例有序 drain 到第一个，merge-group、piece ownership、
Varnode→High 反向引用和最终 Cover 同步更新。该路径没有迭代次数上限、
提前退出或按规模近似。

函数接口目前固定为整个 `fd.vbank.loc_tree`，而 Ghidra 公共函数接受任意
`[startiter,enditer)` 子范围；因此完整接口行为仍记为 `MISMATCH`，本次
direct full-loc 函数投影单独做 oracle 门禁。当前 Rust `ActionMergeType::apply`
还会新建 `Merge` 并重跑 `merge_all`，而 locked Ghidra 持久使用
`data.getMerge()` 且只调用 `mergeByDatatype(beginLoc,endLoc)`；因此 Action
调用闭包及 cache 生命周期明确仍为 `MISMATCH`，不属于该 direct fixture 的
`MATCH` 声明。
`MERGE-DATATYPE-SCALE-0001` 的 locked same-input fixture 只把该 projection
中的 free 过滤规模、Basic 过滤、类型指针身份、跨空间/同存储稳定顺序、
merge-group、survivor/反向 High 引用与 mark 清理判为 `MATCH`。相交
block/copy-shadow/partial-shadow/piece、缓存迁移复用、speculative 各拒绝守卫、
Cover-block/null-def comparator 层级和大量 eligible High 的规模路径仍为
`UNTESTED`；它们不会因窄 projection 的零差分而升级。

### `pub struct BlockVarnode`

Represents a varnode within a specific block for merging purposes

 
### 2026-07-01：补全 Merge 9 步序列
merge_required(mergeAddrTied+groupPartials+mergeMarker)、merge_marker(MULTIEQUAL/INDIRECT IO 合并)、merge_copy(COPY 链 cover-guarded 合并)、merge_adjacent(同 op IO 推测合并)、merge_by_datatype(类型分组+线性合并)、hide_shadows(copy-shadow 分析)、copy_marker(internal COPY NONPRINTING 标记)。+merge_speculative 原语。merge_all 重排为完整 9 步。group_partials 已补齐 PIECE root 的有序重建与 VariableGroup 分组。

### 2026-07-01（续 2）：merge_multi_entry + dominant_copy
merge_multi_entry（merge.cc:908-963）：按 SymbolEntry Symbol 分组，多入口符号合并。dominant_copy（merge.cc:1415-1436）：COPY 链 cover-guarded 合并选主导。3 新测试。9 步 merge 全部实装（allocateCopyTrim 仍受缺失 union 基础设施限制）。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- `merge_linear_speculative` → `merge_linear`（对齐 `Merge::mergeLinear` merge.hh:110。原 Rust 名多出 `_speculative` 后缀，Ghidra 方法名无此后缀）。

### 2026-07-03（续）：命名对齐 Ghidra（camelCase→snake_case）
- `copy_marker` → `mark_internal_copies`（对齐 `Merge::markInternalCopies` merge.hh:1444）。

### 2026-07-03（续 2）：修正 Ghidra 引用行号
- `mark_internal_copies` 的 `// Ghidra:` 注释行号从 merge.hh:1444（实为 merge.cc 行号）修正为 merge.hh:134（声明所在）。

### 2026-07-04：merge_opcode/process_copy_trims 对齐 Ghidra（消除 3 个自创方法）
- `merge_copy` → `merge_opcode(fd, opc)`（对齐 `Merge::mergeOpcode` merge.cc:326）。签名改为通用 OpCode 参数；用 `merge_test_required`（新增，对齐 merge.cc:102-166）+ `merge_speculative`（cover 相交静默跳过，对齐 merge.cc:1565-1575）。删除原来的 `intersects_except_at` 豁免（Ghidra 无此豁免）。
- `dominant_copy` → `process_copy_trims`（对齐 `Merge::processCopyTrims` merge.cc:1415）。删除原自创的 cover-extent dominant 合并，改为忠实 no-op（copyTrims 列表为空）。剩余缺口：snip 子系统未移植。
- 删除 `merge_by_cover` + `merge_by_cover_single_pass`（无 Ghidra 对应的自创迭代补偿 pass）。
- 删除死代码 `merge_speculative_by_vn_except` + `merge_speculative_except`（原被 merge_copy/dominant_copy/merge_by_cover 调用，现已无调用者）。
- 删除 4 个基于自创行为的测试（test_merge_by_cover_*, test_dominant_copy_*, test_copy_marker_*）——它们的断言依赖 cover-except 豁免合并，与 Ghidra 的 cover-skip 语义冲突。
- merge_all 顺序对齐 Ghidra coreaction.cc:5717-5729（删 merge_by_cover，merge_copy→merge_opcode，dominant_copy→process_copy_trims）。

### 2026-07-04（续）：移植 snip/trim 子系统（copyTrims 填充链路）
移植 Ghidra merge.cc 的 forced-merge + snip 数据流改写子系统：
- `allocate_copy_trim`（merge.cc:411）：创建 COPY op + unique 输出，push 进 copy_trims。union 解析路径省略（无 union 基础设施）。
- `snip_reads`（merge.cc:443）：截断一组读取到临时变量。
- `eliminate_intersect`（merge.cc:489）：检测单读 cover 相交并标记 snip（含 copy_shadow/partial_copy_shadow 检查）。
- `unify_address`（merge.cc:581）：对同地址组消除相交。
- `merge_addr_tied` 接入 unify_address（forced merge 前 snip，对齐 merge.cc:631-632）。
- `process_copy_trims` 改为遍历 copy_trims + 按 high 计数 + 清空（对齐 merge.cc:1420-1434）。dominant-copy 替换（processHighDominantCopy）待移植。
- 新增 Merge.copy_trims 字段（对齐 merge.hh:87）。
- 基础设施：BlockVarnode 完善（Ord/set/find_front）、varnode_def_loc/op_loc helpers。

### 2026-07-04（续 3）：完整移植 dominant-copy 替换子系统
- 移植 `process_high_dominant_copy`（merge.cc:1316）：对收到 ≥2 trim COPY 的 high，按同源 Varnode 分组，对每组调 build_dominant_copy。
- 移植 `find_all_into_copies`（merge.cc:1295）+ `compare_copy_by_in_varnode`（merge.cc:1045）：收集 high 的所有外来 COPY，按输入 Varnode + block index + order 排序。
- 移植 `build_dominant_copy`（merge.cc:1151）：支配树 LCA 选 dominant block（find_common_block_n），cover 检查可替换性（intersect_char>1），totalReplace+opDestroy 替换冗余 COPY。
- `process_copy_trims` 接入 process_high_dominant_copy（之前只计数，现在真正替换）。
- 移植 `merge_test_must`（merge.cc:241）+ 接入 merge_addr_tied（对齐 mergeRangeMust 的 mergeTestMust 门控）。
- 新增 `Cover::intersect_char`/`CoverBlock::intersect_char`（cover.cc:269/59）返回 0/1/2。
- 新增 `BlockGraph::find_common_block_n`（block.cc:796）N-way 支配树 LCA。
- 新增 `BlockBasic::get_stop_addr`（近似 block.cc:2328 getStop）。
- 新增 `Funcdata::op_insert_end`（funcdata.hh:461）+ `op_mark_non_printing`（funcdata.hh:519）。
- 新增 `Varnode::has_cover`（varnode.hh:284）。

### 2026-07-04（续 4）：hide_shadows 重写 + ActionHideShadow 委托
- `hide_shadows` 拆分为 `hide_shadows_of(fd, high) -> bool`（对齐 `Merge::hideShadows(high)` merge.cc:1070）+ `hide_shadows(fd)`（遍历所有 high）。
- `hide_shadows_of` 现在真正应用 opSetInput 重写（之前只分析不重写）。用 copy_shadow + cover.contain_varnode_def_at + op_set_input。
- `ActionHideShadow::apply` 从内联地址匹配逻辑改为委托 `Merge::hide_shadows_of(high)`（对齐 coreaction.cc:4831-4845 遍历 high + 调 hideShadows）。

### 2026-07-04（续 5）：移植 mergeOp per-op forced-merge 路径
移植 Ghidra mergeMarker 的 per-op forced-merge 子系统（merge.cc:656-902）：
- `trim_op_input`（merge.cc:692）：在 op 前插入 COPY trim（经 allocateCopyTrim → 填 copy_trims），替换 slot 输入。MULTIEQUAL 时 pc 取入边块的 getStop，插入到入边块末尾。
- `trim_op_output`（merge.cc:656）：把 op 输出移到 stubby unique，COPY 还原原输出。用原始 newOp（不填 copyTrims）。
- `merge_op`（merge.cc:719）：三阶段 forced merge — 非cover限制 trim → cover 限制迭代 trim（trimOpInput/trimOpOutput）→ 真正 merge。
- `collect_inputs`（merge.cc:783）+ `snip_output_interference`（merge.cc:811）：INDIRECT 输出干扰检测 + snip。
- `merge_indirect`（merge.cc:846）：snipOutputInterference + mergeOp。
- `merge_test_with_list`（merge.cc:1657）：HighIntersectTest 替代（用 aggregate_high_cover + intersect_char）。
- `merge_marker` 从 merge_force 改为委托 merge_op/merge_indirect（对齐 merge.cc:889-902）。

### 2026-07-04（续 6）：移植 redundant-copy 标记子系统
移植 Ghidra markInternalCopies 的冗余 COPY 标记路径（merge.cc:1112-1367）：
- `shadowed_varnode`（merge.cc:1271）：判断 vn 是否被同 high 的另一个 instance 完全相交（intersect_char==2）。
- `check_copy_pair`（merge.cc:1112）：domBlock 支配 subBlock + 构造 range cover + 检查中间写入。
- `mark_redundant_copies`（merge.cc:1249）：从后往前对每个 subOp 找 domOp，checkCopyPair 通过则标记 nonprinting。
- `process_high_redundant_copy`（merge.cc:1345）：findAllIntoCopies(filterTemps=false) + 按同源分组 + markRedundantCopies。
- `mark_internal_copies` 重写为忠实 markInternalCopies（含 shadowedVarnode 无后代检查 + multi-copy 累积 + processHighRedundantCopy）。
<!-- annotation-pass: 2026-08-15 -->
 
 
 

### 2026-08-15：MERGE-PERSISTENT-STATE-0001 — Funcdata 持久 Merge 挂载
对齐 Ghidra 的 Merge 生命周期：`Merge covermerge` 是 Funcdata 的按值成员
（funcdata.hh:96），构造于 Funcdata 构造器（funcdata.cc:39 `covermerge(*this)`），
被所有 merge-family Action 经 `data.getMerge()`（funcdata.hh:440）共享，
仅在 `Funcdata::clear()`（funcdata.cc:108）时 `Merge::clear()`（merge.cc:1580-1587）。

- `MergePersistentState`（pub struct）：跨 Action 持久通道挂载——
  `test_cache`（merge.hh:86 HighIntersectTest）、`copy_trims`（merge.hh:87）、
  `live_set`（RUGRA-GLUE 存活前提，对应 Ghidra "vbank 只含存活 varnode"）。
  `clear()` 对齐 merge.cc:1580-1587；`channel_sizes()` 供 fixture 观测。
- `Merge::attach(&mut self, fd)` / `detach(&mut self, fd)`：Action 级入口在
  进入时从 `Funcdata::merge_state` 取回通道、退出时写回（coreaction.rs 每个
  apply 各建 `Merge::new()`，等价于 Ghidra 单一持久对象）。`attached` 守卫防止
  嵌套入口（merge_all → merge_addr_tied 等）中途二次往返。首次 attach 且
  live_set 为空时按当前 fd 重建存活前提。
- 接线入口（全部 attach/detach 包裹）：`merge_all`、`merge_addr_tied`、
  `merge_required`、`merge_marker`、`merge_multi_entry`、`merge_opcode`、
  `merge_adjacent`、`merge_by_datatype`、`hide_shadows_of`、`hide_shadows`、
  `process_copy_trims`、`mark_internal_copies`、`assign_names`。
- `merge_speculative` 重写为忠实 `Merge::merge`（merge.cc:1565-1575）：
  `testCache.intersection` 检查（惰性建 cover，variable.cc:1148-1156）→
  `move_intersect_tests`（variable.cc:681，HighVariable::merge 内）→ 吸收
  instances → `update_high_cover`（merge.cc:1572 `high1->updateCover()`）。
  原实现的 aggregate-cover 空前提（cover 未建时恒接受）被替换。
- `Merge::clear(fd)` 补 `live_set.clear()` + `fd.merge_state.clear()`。
- fixture：`tests/oracle/merge_persistent_1204.{cc,rs,metadata.json}` +
  `tools/run_merge_persistent_oracle.sh`（pinned base ec03e2f79136 +
  merge.rs overlay + funcdata.rs 四 hunk 确定性重建；8 行投影 6 行逐字节
  一致，2 行 MISMATCH 绑定 VARNODE-COPYSHADOW-ARC-0001）。

### 2026-08-16（复核 REWORK）：深度计数、门链、并集重建、点覆盖约定
复核 REJECT 修正（M1/M2）+ 吸收 `MERGE-HIGHCOVER-UNION-0001`：
- `attach_depth: u32` 替换 `attached: bool`——仅 0→1 时从 `Funcdata::merge_state`
  取回通道、仅 1→0 时回写；嵌套入口（merge_all → merge_marker 等）纯 no-op，
  精确镜像 Ghidra 单一持久对象（通道永在对象内，内层不可能"移出"）。修复
  merge_all 中途 detach 导致 compute_varnode_covers 读空 live_set 的回归。
- `merge_adjacent` 补全门链（merge.cc:996-1007）：`mergeTestAdjacent`
  （merge.cc:175-218，已有忠实 port 现接入循环）+ `outputTypeLocal ==
  inputTypeLocal` 类型门（:1001，经 `adjacent_local_types_match` 以比较族
  BOOL-out/INT-in 元类型规则实现，typeop.cc:925-1068 ctor 表；metain==metaout
  族与尺寸检查重合）。
- `merge_force` 三分支在吸收实例后置 HighVariable `COVERDIRTY`
  （variable.cc:660-663 mergeInternal 副作用）——后续 updateCover 重建并集
  cover；此前 survivor 保留单实例 cover 致相交判定用陈旧前提（tB 误并）。
- `compute_varnode_covers` def-no-read 约定修正：零读者=点 `[def,def]`，
  有更晚块读者=live-out `[def,MAX]`（对齐 oracle Cover::rebuild 编码；
  原无条件 MAX 与惰性重建路径不一致）。
- 测试前提修正（src/merge.rs tests）：single_entry 测试补 Ghidra 生产前提
  ——LOAD 指针输入为 spacebase（mergeTestBasic 拒绝，merge.cc:255-264）+
  entry 挂接先建 high 并置 SYMBOLDIRTY（variable.cc:421-432 才能看见）。
- fixture 新增 case_pipeline_tail（含 merge_all 生产入口）消除嵌套盲区；
  **13/13 行逐字节一致，overall=MATCH**（pinned base=e87ebfc5+overlay）。

### 2026-08-16（复核二轮 REWORK）：深度平衡、ctor 表类型门、吸收方向/类语义
复核二轮 REJECT 三项修正：
- **M1**：`hide_shadows_of` 的 singlelist≤1 早退前补 `self.detach(fd)`（与
  process_copy_trims 同型），堵住 merge_all→hide_shadows 每 high 泄漏 +1 导致
  通道永不回写的缺陷；`Merge::clear` 的 depth 重置改为 `debug_assert!` 平衡性
  断言（release 兜底保留）。fixture pipeline_tail 增加 Rust canary 断言
  （merge_all 后 `merge_state.channel_sizes()` live/cache 非空，无 stdout 影响）。
- **M2**：废弃 10-比较族黑名单，改为 `LocalTypeKey`（Base/BaseNoChar/TypeCode
  按 kind+metatype+size 规范等值）+ `local_meta_pair` 全 ctor 表（typeop.cc
  925-2566：含 CARRY/SCARRY/SBORROW/FLOAT_NAN/INT2FLOAT/TRUNC/POPCOUNT/
  LZCOUNT/INSERT/EXTRACT 等）+ 逐 slot override（shift slot1 getBaseNoChar、
  INSERT/EXTRACT slot0 UNKNOWN、INDIRECT slot1 TypeCode、PTRADD/PTRSUB 全 slot
  INT、CPOOLREF INT-in、CALLOTHER UNKNOWN 回退）。Java-mode 变体
  （selectJavaOperators typeop.cc:118-140）与 cpool/userop 记录类型登记 UNTESTED。
- **M3**：`merge_speculative` 增加 `isspeculative` 参数并按 merge.cc:1565-1575
  委托新共享吸收 `merge_highs`（variable.cc:675-712 全语义：piece 分派 +
  `merge_internal` + moved 实例重排 + vn.high 重指 + updateCover）；全部调用点
  按.oracle 方向/旗标校正——mergeOpcode(:346 out 存活/false)、mergeAdjacent
  (:1010 **out 存活**/true，修复原 in/out 倒置)、mergeMultiEntry(:943 anchor/
  false)、mergeOp(:766 out/false)、buildDominantCopy(true)。fixture 新增
  `groups=` 投影（varnode.hh:186 getMergeGroup）双侧逐字节观察存活方与
  speculative 类语义（mergeadjacent 后 P/Q1/Q2=1、tC=0 证明输出侧存活）。

### 2026-08-16（复核三轮窄面）：FLOAT_TRUNC 臂 + getBaseNoChar 等值语义
- `local_meta_pair`：FLOAT_TRUNC 移出 (Int,Int) 分组，单列 `(Int, Float)` 臂
  （typeop.cc:1913 `TypeOpFunc(t,CPUI_FLOAT_TRUNC,"TRUNC",TYPE_INT,TYPE_FLOAT)`，
  无 override → :1001 门拒绝同尺寸 float 输入）。
- `LocalTypeKey` 弃 derive(PartialEq)，手写等值：`getBaseNoChar(s,m)` 仅在
  `(s==1, TYPE_INT, type_nochar 已注册)` 时返回独立条目（type.cc:3619-3626），
  否则与 `getBase(s,m)` 同 canonical 指针——`BaseNoChar(Int,s)==Base(Int,s)
  for s!=1`；fixture 架构未注册 1 字节 INT（type.cc:3131/3220-3222）故 size-1
  也塌缩为同 base，生产 cspec 注册故保留 (Int,1) 区隔。两处注释同步更正。
- fixture 新增 `case_type_gate`（4 行）：INT_LEFT 移位量 size==输出≠1 通过门
  并在 mergeadjacent 合并（groups SH:1/TSH:0 输出侧存活）；FLOAT_TRUNC 同尺寸
  float 输入被拒。runner **17/17 overall=MATCH**。

### 2026-08-19（MERGE-PERSISTENT-STATE-0001 r2-M2 残差）：nochar 等值改为工厂注册态驱动
- 复核登记的两处 MISMATCH：FLOAT_TRUNC `(Int,Float)`（typeop.cc:1913）与
  `getBaseNoChar` 方向（type.cc:3619-3626）——两处在 HEAD 已正确；残余缺陷是
  `(Int,1)` 无条件视为不等。按源码：`getBaseNoChar(1,TYPE_INT)` 仅在
  `type_nochar` 已注册时返回独立条目（type.cc:3622-3623，cacheCoreTypes 自
  注册的 1 字节非 ASCII INT 核心类型填充，:3220-3221），且 `getBase(1,
  TYPE_INT)` 是 `typecache[1][INT]` 的 ASCII char（:3225-3229 优先覆盖；
  无 char 时单个非 ASCII int 自填 :3240-3242 → 两指针相同）。ASCII char 与
  non-char INT1 共存是产生不同指针的常见生产状态；多个 non-char INT1 也可能因
  typecache first-fill 与 type_nochar 后写产生不同身份。最终判定只能比较工厂实际
  canonical 对象，不能化约为名称或“是否同时存在某两类”的布尔规则。
- `LocalTypeKey` 弃手写 `PartialEq`，改为 `local_type_key_eq(a,b,
  nochar_distinct)`；`merge_adjacent` 每次 walk 经 `factory_nochar_distinct`
  读取 `fd.get_arch()→arch.types` 的实际 `get_base(1,INT)` 与
  `get_base_no_char(1,INT)` Arc 身份；无工厂 = type_nochar null 世界 → 相等。
- fixture 扩展三 case（12 行，runner 17→29）：`float_trunc_cast`（同尺寸
  cast 形 FLOAT_TRUNC + COPY 对照）、`char_gate_null`（无 1 字节 INT 核心类型
  → T1/SH1 与 4 字节对照 T4/SH4 同样合并，type.cc:3624 fallthrough）、
  `char_gate_char`（第二 FixtureArchitecture 以自定义名称注册 non-char/ASCII
  INT1 → T1/SH1 被拒、T4/SH4 仍合并；Rust 侧同样 clear→register custom
  names→cache 后挂 `fd.set_arch`）。runner **29/29 covered projection=MATCH**，
  整体仍为 **MISMATCH**。
- 单测新增 `local_type_key_eq` 双世界断言与 `factory_nochar_distinct`
  三态注册断言（仅回归；oracle 证据在 fixture）。
- 2026-08-20 独立复核 REJECT：`factory_nochar_distinct` 以固定名称
  `char`/`int1` 推断缓存身份，而 Ghidra `cacheCoreTypes` 按任意名称 core type
  的属性与 DatatypeSet 遍历更新实际 `type_nochar/typecache` 指针；另 Java ZEXT
  和 CPOOLREF local type 已可由源码证明分叉。修复必须下沉 TypeFactory/TypeOp，
  本节原“工厂状态驱动”仅对 fixture 的两个已测世界成立。
- r2 已关闭上述名称启发式：`a4a2fe9` 提供 canonical cache/nochar Arc，
  `factory_nochar_distinct` 直接 `Arc::ptr_eq`；fixture 使用
  `signed_byte_custom`/`ascii_glyph_custom` 仍保持投影一致。Java/CPOOL 与
  持久通道残差不变。
- 2026-08-23 (TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001)：
  `factory_nochar_distinct` 迁移到 faithful `get_base_result`/
  `get_base_no_char_result`（Ghidra getBase/getBaseNoChar 为 non-const，
  type.cc:3619-3660，故取写锁）；oracle 的 LowlevelError（如未初始化
  alignment map，type.cc:3300-3302）在 merge walk 无法传播，按 throw 语义
  显式 panic 带上下文。reachable 状态（缓存命中/工厂注册态）输出与旧
  lenient twin 逐 Arc 等价；三态注册单测同步迁移。

### 2026-08-16（MERGE-PREEXISTING-GATES-0001）：五项预存在门/方向缺口
- `merge_indirect` 全路径重写（merge.cc:846-882）：isAddrForce 门、
  **输入侧存活**的 merge 尝试（:857/:865/:879，方向与 mergeOp 相反）、
  忠实 `collect_inputs`（previousOp-INDIRECT 链 + piece/group 匹配 +
  (op,slot) 对，merge.cc:783-802）与 `snip_output_interference`
  （compareByHigh 分组 + 每 High 一个 snip COPY + 读重定向，:811-839）、
  `allocate_copy_trim` 剪断 INDIRECT 兜底。旧行为（无条件 trim_op_output
  + mergeOp）删除。
- `build_dominant_copy` 尾合并改为 oracle :1236 的 null-testCache 直调
  （`merge_highs`，无 intersection 预检/moveIntersectTests），不再走带
  cache 的 `merge_speculative`；speculative 类由 mergeGroup=1 观察。
- `merge_multi_entry` 补 :936 mergeTestRequired 门 + setMergeProblems/
  setUnmerged + conflictCount/mergeCount + 精确 warningHeader 文案
  （:950-961）；Symbol 按 (name,nameDedup) 确定性排序遍历。
- `compare_just_loc`（variable.rs，配套 docs/api/variable.md 同步）补
  space 维：`Address::operator<` 全序（space 索引先于 offset，
  address.hh:375-393），跨空间重叠 offset 不再误序。
- `merge_highs` (Some,Some) piece 臂：debug_assert 钉 oracle 契约
  （variable.cc:699-711），release 保守跳过 + 如实注释（Ghidra 侧经
  Merge::merge 调用者不可达）。
- RUGRA-GLUE `wire_unique_high`：补 Ghidra newUnique 的 assignHigh 半边
  （funcdata_varnode.cc:89），修 trim unique 无 High 导致的静默 no-op 与
  mergeOp phase-2 过度剪枝（funcdata.rs latent 缺口另行登记）。
- fixture `merge_gates_1204`（4 case 14 行）+ runner：14/14 双侧字节一致
  （sha 9878946d…），merge_persistent_1204 复跑 17/17 不劣化（仅
  merge_rs_sha256 重 pin）。

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`Merge::assignNames`（自创的 merge 期 per-High 命名，注解曾错指
merge.hh:83）删除：Ghidra 的 merge 序列（coreaction.cc:5718-5729）没有命
名步骤，Merge 也没有 assignNames。变量命名唯一来源是
`ActionNameVars::apply`（coreaction.cc:2978-3000）的符号驱动管线；死代码
`register_name` 表（错注 merge.hh:83 Merge::registerName）一并移除，其表
内容由 `ActionRestructureVarnode` 安装进 ScopeLocal.register_names。

### 2026-08-17：cover 端点 setter 化（`COVER-TWOPIECE-RESIDUAL-0001` 配套）

`compute_varnode_covers` 与（已禁用的）`propagate_cover_through_cfg` 中对
`CoverBlock::start/end` 的直接字段赋值改为 `set_begin/set_end/set_all`
调用：CoverBlock 引入指针身份域（`start_id/end_id`，对齐 Ghidra
`PcodeOp*` 哨兵语义）后，字段直写会破坏投影域与身份域的同步不变式。
区间值与语义零变化（详见 docs/api/cover.md 表示法一节）。

## 2026-08-23：MERGE-CLEAR-LIFECYCLE-0001 — 持久通道补齐与 clear 语义

- `MergePersistentState`（funcdata.hh:96 covermerge 挂载）补齐 Ghidra
  `Merge::clear`（merge.cc:1580-1587）清除的全部四个通道：
  新增 `proto_partial: Vec<PcodeOpRef>`（merge.hh:88，groupPartials 生产
  路径仍为 no-op，归 MERGE-PROTOPARTIAL-GROUP-0001）与
  `stack_affecting_ops`/`stack_affecting_populated`（merge.hh:85
  StackAffectingOps 的 opList/is_pop 镜像；`StackAffectingOps::populate`
  未移植）。`clear()` 现清 testCache/copyTrims/live_set(GLUE)/protoPartial/
  stackAffectingOps+is_pop 全部通道。
- 新增 RUGRA-GLUE fixture 观测/存入钩子：`channel_sizes_extended()` 与
  `fixture_deposit_test_cache()`/`fixture_deposit_channels()`（与既有
  `channel_sizes()` 同一前提：锁定 C++ fixture 经 #define private/class
  struct 直接读成员）。
- 观察投影：merge_clear_lifecycle_1204 双侧对拍中 merge 通道
  （testcache 2→0、copytrims 1→0、protopartial 1→0、stackops 1→0、
  stackpop 1→0）全部 MATCH；生产路径填充（intersection 真实缓存、
  groupPartials、StackAffectingOps::populate）保持 UNTESTED 登记。
- `fd.getMerge()` 持久化重构（Actions 直接共享单一 Merge 对象）仍归
  COREACTION-STATEFUL-MERGE-0001；本改动只覆盖其 clear 生命周期通道语义。
<!-- annotation-pass: 2026-08-23 -->

## 引用行号勘误（2026-08-23，root，legacymig 复核跟进）

merge.rs 两处 `type_nochar` 置空引用由 type.cc:3131 修正为 3128（clearCache 内；3131 是 charcache 循环行）。复核确认语义无误，仅引用偏移 3 行。

## 2026-08-23（VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001 编译适配）：v_type 访问器改 TypeCell 域

HighVariable 的 `v_type` 缓存迁入 `TypeCell`（`RwLock<Arc<Datatype>>`，Ghidra `mutable Datatype *type` variable.hh:141 的 Rust 锁域，详见 docs/api/variable.md）。merge.rs 四处编译必需适配，语义不变：
- `:1141` `Arc::ptr_eq(&hi.v_type.get(), &ho.v_type.get())`（merge.cc:107-109 双锁类型等同检查，指针等同语义保持）
- `:1255` 同上（out/input 类型等同）
- `:3312` `first.read().v_type.get()`（updateType 后读缓存）
- `:3320` `Arc::ptr_eq(&datatype, &high.v_type.get())`

-  已降私有（R16 建议⑤）：残余调用均在同文件测试内，防再次误接为管线入口。


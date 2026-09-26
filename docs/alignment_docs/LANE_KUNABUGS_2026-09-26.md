# LANE KUNABUGS — kuna 移植期 6 上游 bug + losses 账本挖掘 × 我方残差族对照（2026-09-26）

> **归档注记（2026-09-26,Lane TODO-BOOK）**: 本报告归档自内存盘
> `/dev/shm/rugra-reports/LANE_KUNABUGS_2026-09-26.md`（来源车道 KUNABUGS,2026-09-26
> 交付,纯调研零 src 改动;内存盘易失,本件为 docs/alignment_docs/ 持久化归档,
> 除本注记外与源文件逐字节一致）。

> 车道: KUNABUGS（纯调研,零 src 改动,产物=本报告）。
> 取材: github.com/Noelo-Lab/kuna,浅克隆后 `git fetch --unshallow`（2149 commits）,
> losses 账本与 upstream-bugs.md 从 git 历史 `ba2c07df^` 复活（2026-07-28 "Major text
> reduction" 删除前的最后版本）。clone 收尾已删。
> 对照物: 我方残差族 = CURL_CANON_ATTRIBUTION_2026-09-26.md（新鲜口径 267 行,A45/B29/C29/D46/
> E22/F24/G12…）/ HTTPD_MAIN_ATTRIBUTION_2026-09-26.md（main 499,F1-F8/RETADDR）/
> MIRROR_RESIDUAL_FAMILIES_2026-09-26.md（F-TYPE/F-RESIDE/F-DECL/…）/ SQFACE_ATTRIBUTION_
> 2026-09-26.md（CASTFUSE/STACKSLOT/ZEXT/UNAFF…;sq 镜面现行 4530=CSPEC-GLOBAL 落地后）。
> 派单种子数字（curl 182/httpd 229/sq 4530）中 curl/httpd 已被后续车道消化,以各归因文档
> 新鲜口径为准。
> **诚实纪律**: kuna 的描述是二手观察。本报告一切"命中"只产生**验证票建议**（用我方锁定
> oracle e40ed130 直跑验证）,不直接产生修复动作。本车道未跑任何 oracle fixture,全部
> 结论为桌面研究 + 我方 src 只读 grep 核查。

---

## 0. 摘要（一句话版）

**6 个上游 bug 全部已被 KUNAUB 车道（docs/alignment_audit/KUNA_UB_CROSSCHECK_2026-09-26.md）
对照完毕且票已立,本车道独立复核一致（唯一新增细节: UB-1 的 ZPULL/SPULL 形态是 kuna 锚点
cef869af 的 post-12.0.4 master 新增 opcode,12.0.4 的等价面是"表长=CPUI_MAX=74 恰好等长、
get_opname 无护栏"的潜伏 OOB）;本车道的真正增量在 losses 账本——从 302 条中筛出 ~35 条
含一手 C++ 行为观察的条目,对照后得到 3 个强命中簇（F-RESIDE/STACKSLOT 的 heritage 时序+
merge 平局簇、CASTFUSE-A 的 copyTrim 再物化新根因候选、RETADDR 的 pass 数敏感性）、
6 个支持性证据命中、1 个对我方 P0 BLOCKED 链（DB-LOCALSCOPE 簇）的独立第三方确认,
以及 12 条明确排除（含我方已忠实移植、kuna 曾踩坑的 8 个位点——反向证明我方这些域健康）。**

---

## 1. 取材过程（挖掘方法学,可复现）

1. `git clone --depth 1 https://github.com/Noelo-Lab/kuna` → HEAD `0096e98`（浅克隆仅 1 commit）。
2. `docs/history.md` 自述: losses 账本（LOSS-001–252,~250 条）与 `docs/rust-port/` 全树于
   **2026-07-28 commit `ba2c07df`（"Major text reduction and README rewrite"）删除**,
   "full text lives in git history before that date"。
3. `git fetch --unshallow` → 2149 commits 全历史到手。
4. 复活: `git show ba2c07df^:docs/rust-port/losses.md`（3687 行,302 个条目标题,含
   CLOSURE/CORRECTION/UPDATE 追加条）与 `git show ba2c07df^:docs/rust-port/upstream-bugs.md`
   （97 行,6 bug 全文）。
5. 辅助面: `docs/history.md` 的 DIV 冻结索引（185 条）与 Convergences 表（9 条 kuna 自身
   port-bug 修复回上游的记录——对我方是"易错点清单"）。
6. kuna 上游锚点: `GHIDRA_REV=cef869af`（2026-06-01 master）。**注意: 该锚点晚于我方
   oracle 12.0.4（e40ed130）**,涉及 post-12.0.4 新增 opcode（ZPULL/SPULL）的条目需逐条
   判定 12.0.4 是否同体;KUNAUB 车道已做逐文件 master↔12.0.4 差分（六 bug 所在文件
   12.0.4 后零/近零改动,结论"逐字节同体"）,本车道在 UB-1 上补充了一个例外细节（§2）。

---

## 2. 6 个上游 Ghidra 潜伏 bug 全表

> 完整对照（12.0.4 存在性 + 我方 Rust 形态 + 分类 + 票）已由 **KUNAUB 车道**完成:
> `docs/alignment_audit/KUNA_UB_CROSSCHECK_2026-09-26.md`（含 K4 ASan 实证、K6 二分 miss
> 实测）。本表仅做独立复核摘要 + 本车道新增细节。**六 bug 均为 crash/UB 边缘,不解释任何
> 我方残差族**（残差是输出形态分歧,不是崩溃差异）;KUNAUB 四票（KUNAUB-SDIV-0001 P2 /
> CHARREF-0001 P3 / PAGECOPY-0001 P3 / IDENTS-PIN-0001 P3）维持,不重复立票。

| # | kuna 编号 | bug（Ghidra 函数/文件） | 12.0.4 判定 | 我方形态 | 本车道增量 |
|---|---|---|---|---|---|
| 1 | UB-1 | `get_opname` OOB @ CPUI_MAX（opcodes.cc `opcode_name[]` 表长比 enum 短 1;`get_opname(CPUI_SPULL=74)` 越界、`get_opname(CPUI_ZPULL=71)` 返回陈旧名 "EXTRACT"） | **存在但形态不同**: 12.0.4 `CPUI_MAX=74`（opcodes.hh:130）且表恰 74 项（"BLANK".."LZCOUNT"）——**ZPULL/SPULL 是 kuna 锚点 cef869af 的 post-12.0.4 master 新增 opcode**,其"表短 1"形态不在我方 oracle;12.0.4 的等价面是 `get_opname` 无护栏（opcodes.cc:60-64）,`opc==CPUI_MAX` 时读越界（in-tree 不可达,KUNAUB 判 RUGRA-SAFE） | enum 穷尽 match,结构免疫 | **版本细节**: kuna 的 UB-1 行号/形态不可直接套用 12.0.4;KUNAUB 的 K1 分析（CPUI_MAX 边界）才是 12.0.4 正典形态。我方独立数表验证: 74 项/CPUI_MAX=74,无 ZPULL/SPULL |
| 2 | UB-2 | `OpBehaviorIntSdiv/IntSrem::evaluateBinary` INT64_MIN / -1 SIGFPE（opbehavior.cc:507/:529,仅守 in2==0） | ✅ 存在（本车道亲读 opbehavior.cc:507-541 确认 `num/denom`/`val % mod` 无防护） | Rust 除法溢出恒 panic（crash↔crash 镜像） | 无新增;维持 KUNAUB-SDIV-0001 |
| 3 | UB-3 | `convertCharRef` 有符号溢出（xml.cc:2337-2358,`val *= mult; val += cur` int4 无护栏） | ✅ 存在（**行号与 kuna 引用逐字一致**——该函数 12.0.4 与 cef869af 同体） | 镜像 i32 累加;release 回绕=de facto | 无新增;维持 KUNAUB-CHARREF-0001 |
| 4 | UB-4 | `rangemap::erase` 悬垂读（zip() 可把 sub-range 扩到记录 range 之下,erase 从 `lower_bound(getFirst())` 起步漏删 → 悬垂记录指针/读已释放内存） | ✅ 存在（KUNAUB ASan 实证 heap-use-after-free） | Vec+serial 游标,stale→None | 无新增;维持 RUGRA-SAFE 记录 |
| 5 | UB-5(前) | `MemoryBank::getPage/setPage` 非字对齐 skip 越界（memstate.cc:113/:153,`startalign < addr` 比较对象错为页起点;setPage 全字路径 `*((const uintb*)val)` 无视 wordsize 读 8 字节） | ✅ 存在（本车道亲读 memstate.cc:95-171 确认死修剪同体） | 镜像同一死修剪 + slice panic;当前零调用方 | 无新增;维持 KUNAUB-PAGECOPY-0001 |
| 6 | UB-5(后,kuna 误标重复编号) | pcodeparse 关键字表排序违规（`"||"`(0x7c7c) 列在 `"abs"` 前,二分双双 miss → pcode snippet 里 `||`/`abs` 无法作关键字,降级为标识符） | ✅ 存在（本车道亲读 pcodeparse.cc:2727-2737/2776 确认 idents[] 第 8/9 项逆序 + findIdentifier 二分） | 表序+算法逐字节镜像,行为等价 | 无新增;维持 KUNAUB-IDENTS-PIN-0001 |

> history.md 自述"six latent bugs (UB-1..UB-5)"——第 6 个 bug 在 upstream-bugs.md 里被
> 误标了重复的 UB-5 编号,实际是 6 bug 5 编号。已如实记录,不编造第 6 编号。

---

## 3. losses 账本精选（302 条 → 与我方已移植域+输出可见行为重合的条目）

> 筛选标准: ①条目含**一手 C++ oracle 行为描述**（非 kuna 内部 port 进度记录）;②域与我方
> 已移植面（varnode/op/block/funcdata/heritage/merge/varmap/printc/ruleaction/coreaction/
> blockaction/jumptable/condexe/prettyprint/typeop/cast/fspec/type）重合;③行为可观察
> （影响反编译输出形态或管线状态机）。kuna 的 W5-W10 大量 SEAM/deferral 条目（"X 未移植"）
> 对我方无信息量,已排除。**我方移植态列 = 本车道对我方 src 只读 grep 的核查结果**。

### 3.1 强相关条目（含我方移植态核查）

| LOSS | C++ 行为（一手描述,kuna 锚行号） | kuna 处理 | 我方移植态（grep 亲证） |
|---|---|---|---|
| **113** | `Merge::mergeLinear` 的 `sort(highvec,…,compareHighByBlock)`（merge.cc:282）是 **不稳定 std::sort**;三键链（earliest-cover-block→首实例地址→def 地址）完全相等的两个不同 high 之间顺序**未指定**,可改变 mergeLinear 的栈代表选择 | 稳定 sort_by,kuna 自称确定性改良,自证其语料输出等价,但明文留了"若真输入出现平局需重推导"的恢复判据 | **同款形态**: 我方 merge.rs:4630 也是稳定 `sort_by(compare_high_by_block)`（merge.rs:956 三键链忠实）。与 kuna 同一分歧类 |
| **139** | `BlockGoto::gotoPrints`（block.cc:2929）= `gotoTarget->getFrontLeaf() != getParent()->nextFlowAfter(this)` 才印 goto——**目标是下一打印块时抑制冗余 goto** | 未移植 nextFlowAfter,恒发 goto（OVER-emit） | **我方忠实**: block.rs:6181 goto_prints + block.rs:4262 next_flow_after,printc.rs:16046-16116 emit_block_goto 已门控。非命中 |
| **145** | `ScopeLocal::restructureVarnode` C++ 尾链: `clearUnlockedCategory(-1)`/`clearUnlockedCategory(function_parameter)`/`clearCategory(fake_input)`/`fakeInputSymbols()`/`state.sortAlias()`/`markUnaliased(state.getAlias())`/`checkUnaliasedReturn`/`annotateRawStackPtr()`——**unaliased 标记让后续 pass 删除 INDIRECT;零偏移 raw-stack PTRSUB 占位符** | 尾链整体缺失（W10 期） | **我方有主体**: varmap.rs:3649-3668 有 fake_input_symbols/sort_alias/mark_unaliased。`checkUnaliasedReturn`/`annotateRawStackPtr` 未在 grep 面出现——**待核**（并入 STACKSLOT 验证票的检查单） |
| **146** | `MapState::gatherOpen` 的 LoadGuard/StoreGuard `addGuard` 双循环（varmap.cc:1241-1248）+ `MapState::addGuard`（:1004-1039,step/outSize 折算、"LOAD size 整除 step → 假装 LOAD 尺寸数组"、getAlignSize≠step 未知型回退、range-locked minItems 数学） | 忠实空转（其 IR 无 guard） | **我方忠实**: varmap.rs:1607/1612 add_guard 双循环在。非命中 |
| **147** | `Funcdata::syncVarnodesWithSymbol` 掩码构造: `mask=mapped`,仅 `(fl&addrtied)==0` 时加 `addrtied\|addrforce`——**"We can CLEAR but not SET the addrtied flag"**;无符号分支 `lm->isUnmappedUnaliased(vn)` 设 `nolocalalias` | kuna 加了 `else { mask \|= addrtied }` SET 臂（W3 骨架补偿）+ nolocalalias 硬编码 0 | **我方忠实**: funcdata.rs:3874-3892 逐字掩码不对称（CLEAR-only,无 SET 臂）。非命中（FUNCDATA-SCOPE-SYNC-0001 已按此语义交付） |
| **149/194** | `Heritage::guardCalls`（heritage.cc:1469-1526）: `unknown_effect`/`return_address` **无条件** `newIndirectOp`（1512,holdind 时 setAddrForce,1518 return_address 时 setReturnAddress）;`killedbycall` `newIndirectCreation`（1521-1524） | 先全注释,后 persist-only 收窄（C++ 无 persist 条件） | **我方忠实**: heritage.rs:2038-2075 无条件发射 + set_addr_force + set_return_address + killedbycall new_indirect_creation。非命中 |
| **150** | `Heritage::guard` 自由读多读者（descend != 1）→ **`throw LowlevelError("Free varnode with multiple reads")`** = 函数级中止/重启 | 降级为静默 guard 继续跑 | **我方同款降级**: heritage.rs:2651-2675 注释明言"Rugra logs instead of throws"。两侧同向偏离 C++（我方已文档化的已知分歧;若 oracle 在我方语料上从不触发该 throw 则不可观察——golden 全函数有输出,推定 inert） |
| **154-F1** | printc 声明器 `ptr_expr`/`array_expr` RPN 优先级（printc.cc:75/78,array_expr prec 66 > ptr_expr prec 62;**指针在数组外层才加括号**）: `int4 (*)[1]` vs `int4 *a[1]` 两种嵌套 | kuna 括号化方向写反（潜伏 printer bug） | **我方机制在**: printc.rs:2002-2022 注释明写两 token 优先级与 pointer-to-array 顺序。但 httpd 镜面 F-ARRCAST 残差（`(xunknown1 [8]*)` 非法 C）说明 **cast 形声明器**仍有缺口——支持性命中（§4） |
| **167/178** | `JumpBasic::foldInGuards`/`foldInOneGuard`（+ `BlockBasic::noInterveningStatement`/`Funcdata::pushBranch`/`JumpTable::addBlockToSwitch`）把 range-guard 折进 BlockSwitch——**default: 臂在 switch 内**;且 fold 必须在 merge（S6）后跑（pre-merge IR 上 noInterveningStatement 会假阳性） | 未移植（keystone 门控关闭） | **我方有**: jumptable.rs:1571/5258 + coreaction.rs:3325 fold_in_guards 已接线。非命中（我方 SWITCH-GOTO 族根因在别处,MSTRUCT 票持有） |
| **179** | `ActionSetCasts` cast 循环走**活迭代器**（coreaction.cc:2812-2872 `for(iter=bb->beginOp();…;++iter)`）: `castOutput` 的 offset-0 PTRSUB opInsertAfter 插入件会被 `++iter` **重访** | Vec 快照,不重访（kuna 实测其语料零效应） | **同款形态**: coreaction.rs:7373-7381 快照 collect。kuna 侧零效应实测降低先验,但 A 族（PROTOCAST 45 行）恰在 castOutput 域——低优先验证点 |
| **180** | `ActionSetCasts::apply` 把 `count += resolveUnion/castInput/castOutput` 累进 **Action 成员 count**（框架 lcount<count → count_apply++/警告/action-break） | 丢弃 count（`let _count`） | **我方忠实**: coreaction.rs:7528-7535 `self.count += changes` + take_count_delta。非命中 |
| **190** | `Funcdata::setVarnodeProperties`（funcdata_varnode.cc:25-42）: IR 构造期对每个未映射 varnode 再查一次 `localmap->queryProperties`（usepoint 已知后）,entry 命中 `setSymbolProperties` 否则 `setFlags(vflags&~typelock)` | no-op 延后,global 存活改由 heritage 路径交付 | **我方有**: funcdata.rs:6250 set_varnode_properties,含 ScopeLocal 腿（FUNCDATA-SETVARNODE-SCOPELOCAL-0001 DONE;+32/+4 骨架代价已登记 SETVARNODE-SCOPELOCAL-CONSUMER-0001）。非命中 |
| **191** | `ActionDirectWrite` 的 `possibleInputParam` **无 has_store() 条件**（C++ 只查模型） | kuna 加了 has_store() 门（多余条件） | **我方忠实**: fspec.rs:870/3101 possible_input_param 无 has_store 门。非命中 |
| **197/200/235** | for 循环链: `BlockWhileDo::findLoopVariable`（block.cc:3164）+ iterateOp 迁移到尾块（opUninsert/opInsertAfter,isMoveable 门,block.cc:3373-3396）+ `finalTransform`/`finalizePrinting` + `emitForLoop`（printc.cc:2955-3006）;**`has_overflow_syntax()` 守卫对 overflow 形 while(true){…break} 循环拒绝 reroll**;kuna 实测其阻塞项是 RSP 噪声/L4/L5 param-spill promotion（即 for 成形依赖干净 RSP 链） | 忠实移植但 INERT（上游前置缺失） | **我方在飞**: block.rs:7074 find_loop_variable + blockaction.rs:8790 for_loop_final_transform 已接线（HTTPDMAIN-F8-FORLOOP-0001 placement note 在码）。**支持性命中**: kuna 证据链确认 F8 验证 fixture 必须在 F1（noreturn/RSP 链）修复后跑,否则 findLoopVariable/testTerminal 会因 RSP 噪声 decline |
| **202** | `PrintC::pushPartialSymbol` 的 **ARRAY 臂**（printc.cc:2062-2076,`TypeArray::getSubEntry` 元素下降→下标项）+ allowCast SUBPIECE-cast 臂（:2094-2105）+ `!succeeded` 人工字段名（:2106-2117） | 三臂未移植,回落裸符号名 | **我方有 ARRAY 臂**: printc.rs:4757 array_get_sub_entry + :18185 push_partial_symbol。但 curl L 族残差仍在（`buffer._0_4_` vs `buffer[LIT]._0_4_`）→ 我方缺口在**路由/到达条件**而非臂本身——支持性命中（§4） |
| **229-CORRECTION** | **`Merge::allocateCopyTrim`（merge.cc:411）在 firstuse 地址再物化显式 COPY**（`data.newOp(1,addr)`）——被 RulePropagateCopy 前折的映射 COPY,若动态哈希（`DynamicHash::gatherFirstLevelVars`,dynamic.cc:655）在用点需要一枚 COPY,merge 会**重新插回**;映射绑定在 COPY 前折时须保在 HighVariable 上 | kuna 的 copy_trim_op 对该动态哈希 temp 永不触发（映射绑定随 High 销毁丢失） | **未核**（我方 merge.rs copy_trim 对动态哈希 temp 的再物化路径需 fixture 钉）——**CASTFUSE-A 新根因候选**（§4） |
| **231-RESOLVED** | C++ `syncVarnodesWithSymbols`（funcdata_varnode.cc:993）**从不 tie 无符号的处理器寄存器**（inScope 对寄存器恒 false）→ **循环承载的返回寄存器 phi 折进输入参数**（`startval = startval + N;`）;判别器 = phi 是否处于 SSA def-use 环（loop-carried）vs 只到 RETURN（ACYCLIC,保持 tied `// acc`） | kuna 的 marker-tie workaround 过度 tie 循环承载返回寄存器,六轮诊断后修复 | **我方 sync 忠实**（无 kuna workaround）,但该 C++ 判别行为（loop-carried 返回寄存器折参）应入 F-RESIDE/UNAFF fixture 库 |
| **237-CORRECTION** | **pre-heritage 栈 store→load 转发**: kuna 缺它导致 longdouble 崩塌;C++ 有"pre-heritage stack store-load forwarding"且双侧首 heritage 后逐字节一致;另一观察: post-heritage 相邻 LOAD-piece 折叠为宽 LOAD | kuna 修回上游 | **未核**——我方 heritage.rs 有 LoadGuard 机制（heritage.rs:444,load_guard_search）,但 store→load 转发**时序**未对拍。**F-RESIDE 最强候选根因**（§4） |
| **238** | C++ `PrintC::emitVarDecls`/`pushSymbol` 对部分恢复局部发**声明行尾注释**（`int4 a_simple; // tmp`） | 未复现（cosmetic） | 低优先: 我方 F-DECL 族的注释面独立跟踪 |
| **247-v2** | **C++ 在后续完整 mainloop 迭代中重新引入 STORE**（pass 7: `s..d1:1 = DIL`）,RuleStoreVarnode 再把它转回 d1 字节家,自持;Rust 折后**不再 re-split** | kuna 侧缺 re-introduction | **直接支持 RETADDR 族**: golden 保留 `local_d0 = 0x12b869`（retaddr 槽复用+`bumpDeadcodeDelay` 延迟）而消 0x12ba0c;我方相反——**死存储存活边界是 mainloop pass 数敏感的**,单 pass fixture 会钉错边界（§4） |
| **248-ROOT v5/v6/RESOLVED** | ①addrtied 栈参 hole-fill 残渣必须 COLLAPSE+DCE,且**触发 pass 2-5 的 re-heritage**;②typed-stack-element 字节级 refinement + addrForced-INDIRECT direct-write DCE 同属一个 heritage 子系统;③**真根: `ProtoStoreSymbol::setInput`（fspec.cc:3174）在原型 attach 时把锁定参数映射进 scope EntryMap** → restructure/sync 期 `findOverlap(s0x8,4)` 解析出参数 entry → sync 清 addrforce → DeadCode DCE 掉 INDIRECT+CONCAT22;④`Scope::addMap` 的 persist 判定必须对**全局 scope 根**（database.cc:1141 `getGlobalScope()`）——kuna 判到了 ScopeLocal 私有 DB 的无父根上,所有栈局部错染 persist → guardReturns 建 addrforce 返回 COPY → 死 `&struct.field[idx]` 溢出物化 | 六波诊断后 2 行修复（link_proto_params 前置 + L4 inflateTest 臂启用） | **对我方 P0 BLOCKED 链的独立确认**: 我方 DB-LOCALSCOPE-MAP-0001（BLOCKED）+ PROTOSTORE-SYMBOL-0001（BLOCKED）+ FUNCDATA-LOCALSCOPE-OWNERSHIP-0001（BLOCKED）正是③的对应面;我方 funcdata.rs:6278 自注"Rugra's ScopeLocal carries no live SymbolEntry (DB-LOCALSCOPE-MAP-0001 split)"=同根类。kuna 用最小复现（锁定参数 `int2 y`@s0x8 → sync 清 addrforce → DCE）证明该根产生**栈槽物化+多余 INDIRECT+re-heritage 循环**三症状——与我方 STACKSLOT-MATERIALIZE（sq OTHER 2203）/UNAFF-EXTRAOUT（555）症状面吻合（§4） |
| **249** | **deadcode 驱动的寄存器范围 re-heritage**: ActionDeadCode 删 op 后 heritage 必须对该寄存器范围（RAX→EAX）重跑 | kuna 侧不点火 | 支持性命中: 我方 RETADDR 分析已引 heritage.cc:2571/2716-2728（overlap→bump→restart）,kuna 独立观察同一耦合 |
| **Convergence: arraysubfield** | 部分访问**数组类型符号**必须进入 `PrintC::pushPartialSymbol`（kuna 曾整类漏路由） | 修回上游 | 我方有臂但 L 族残差在——路由条件待钉（§4） |
| **Convergence: phiopflags** | MULTIEQUAL 的 op 属性三元组 = `special\|marker\|nocollapse`（typeop.cc:1944-1947 ctor）,kuna 手写表只给了 marker | 修回上游 | **我方忠实**: op.rs:220 `CPUI_MULTIEQUAL => special \| marker \| nocollapse`。注意 typeop.rs:2583 `TypeOpMulti::get_flags()=0` 是死路径不一致（真 flags 从 op.rs opcode_flags 来,grep 未见 TypeOp::get_flags 行为消费者）——卫生项,非残差 |
| **Convergence: subright** | `RuleSubRight::applyOp`（ruleaction.cc:7271）后半段（非最低位截断）是独立逻辑,kuna 曾只抄了前半 | 修回上游 | 未核——便宜检查项（§5 低优先清单） |
| **Convergence: jtsharepartial** | BRANCHIND 恢复 = 克隆 raw p-code 进部分 Funcdata、建块、跑缩减 "jumptable" action 集;**部分反编译与父共享 scope/符号面** | 修回上游 | 未核——并入 jumptable 域检查单 |
| **Convergence: cspecprotos** | C++ `parseCompilerConfig` 读**全部** `<prototype>` 模型,kuna 曾只读一个 | 修回上游 | 我方有 parse_compiler_config（FUNCPROTO-MODEL-BIND-0001 用真实 cspec 字节）。非命中 |

### 3.2 明确排除条目（防后人翻案,附理由）

| LOSS/类 | 排除理由 |
|---|---|
| 001/002/004/005/006/007/010/011/250/251/252 | 依赖替换/构建/加载器/分析器层（zlib/bfd/bison/regex/demangler/FID/PDB）——非我方反编译器域 |
| 008/009/016/018/019/020/021/022/026/027/028 | SLEIGH 编译器/运行时内部与 marshal 细节——我方走 vendored kuna-sleigh,且非输出可见 |
| 029-038（W3 seam 群）/042-044/046/049/053-078/082-084/092-094/103-112/114/118-119/121-123/127-130/162/165-166/172/178/184/188/192/195-196/199/204/206/209-210/213/215/218-224/226-227/233-236/239/243-246 | kuna 移植期 SEAM/deferral/进度记录——描述"kuna 没移植 X",不含 C++ 行为增量;其中 W10 诊断链（231/235/237/248 系列）已按 CORRECTION/RESOLVED 终态提炼进 §3.1 |
| 014/015/039/055/064/068/081/085/086/087/089/091/108/152/177 | 忠实于 C++-UB 的整数宽度/回绕/移位族——全部为**非物理输入**（≥2^31 栈偏移、8 字节以上 varnode 移位、畸形 spec）才可达,kuna 自判 latent/unreachable;我方语料（curl/httpd/sasquatch x86-64）不可达。注: 014=UB-2 决策已入 KUNAUB 票 |
| 017/024/032/041/051/052/124/125/131/132/134/136/143/144/151/174/176 | 控制台/选项解析/架构引导/驱动层边缘（前缀解析、垂直 tab、restart 数据流、pspec 子元素——143 单列为 §5 验证票因 inferptrbounds 与 F4 谱系相关） |
| 080/116/117/120/156/158/159/160/161/163/173/181/182/185/186/189/193/197(部分)/198/200/203/207/208/212/214/216/217/219/220/225/228/230/232/234/240/241/242 | kuna 自身管线状态记录（INERT/DORMANT/REJECTED 分支）或其 angr 发散面;其中对 C++ 机制的增量（emitScopeVarDecls 序/emitForLoop/pushPartialSymbol/checkAddressOfCast/unionMap 缓存/ScoreUnionFields）已提炼进 §3.1 与 §4 对应族 |
| DIV-2..DIV-185 群 | kuna 有意发散（option 化决策）,非 oracle 行为描述;仅 Convergences 表 9 条是"修回上游"的 oracle 行为确认,已全部过目（§3.1 收 5 条,余 4 条排除: callsitestackargs=fspec 试验评分我方无症状、funcptrencoding=ARM thumb 域、maxlennop=SLEIGH 运行时、ObjectLoadImage=加载器） |

---

## 4. 残差族对照结论（逐族: 命中/不命中 + 验证方法）

> "命中"定义: kuna 条目描述的 C++ 行为**可能解释我方该族**,产生验证票建议。
> "支持性命中": 不直接解释,但为既有票提供 C++ 锚行号/机制确认/fixture 设计输入。
> 所有验证均以我方锁定 oracle fixture 实证为最终裁决。

### 4.1 强命中簇（三簇）

**簇 1 — F-RESIDE / STACKSLOT-MATERIALIZE（heritage 时序 + merge 平局 + 参数入 scope）**

我方症状: golden 用寄存器 HighVar（`puVar7=puVar8` 拷贝链）,Rugra 全程栈槽承载（MIRATTR
F-RESIDE ~25 行,P1 写域空闲）;sq OTHER 桶 2203 行=中链值栈槽物化+栈符号分型（STACKSLOT 票面）。

kuna 证据链（三条独立观察汇聚）:
- LOSS-237-CORRECTION: C++ 有 **pre-heritage 栈 store→load 转发**;kuna 缺它时值落栈槽
  （longdouble 崩塌的根因）,补上后双侧首 heritage 逐字节一致;
- LOSS-113: mergeLinear 的 `std::sort` 不稳定,三键全等 high 间的顺序未指定——**栈代表
  选择**可异;我方与 kuna 同用稳定排序（merge.rs:4630）;
- LOSS-248-RESOLVED: 锁定参数不入 scope EntryMap → sync 走无符号回退 → addrforce 存活 →
  INDIRECT+hole-fill 不被 DCE → re-heritage pass 2-5 → 栈槽物化。我方 DB-LOCALSCOPE-MAP-0001
  分裂正是同根（funcdata.rs:6278 自注）。

**验证方法**（F-RESIDE fixture 增补,写域 heritage.rs+merge.rs 空闲）:
1. `my_get_line` 单函数,双侧在**首 heritage 边界** dump IR（RUGRA_DUMP_FUNC vs oracle
   golden_dump_1204 同名插桩）,逐 op 对比 LOAD 的读源（寄存器链 vs 栈槽）——钉 store→load
   转发时序;
2. 构造三键全等双 high 的合成用例（同 earliest-cover-block/同首实例地址/def 同空）,跑 oracle
   merge（golden_dump harness）与我方 merge_linear,对比栈代表选择——钉 LOSS-113 平局面;
3. 锁定参数栈槽（kuna 最小复现形: `int2 y`@s0x8,size-2,nolocalalias）双侧 sync 后 addrforce
   状态——钉参数入 scope 链（依赖 DB-LOCALSCOPE 簇解锁,fixture 可先行设计）。

**簇 2 — CASTFUSE-A（sq 2797 行池: explicit/implied 标记 + 表达式融合）**

我方症状: oracle `iVar9 = CONCAT31(Var4,xVar7);` 独立语句被读 2 次,Rugra 融合进 store;
独立 cast 语句 774 vs 928（−154=我方过度内联计数证据）;SQFACE 已列根因候选 ①标记路径放行
多读者 ②标记时点读者数<2。

kuna 增量（LOSS-229-CORRECTION）: **根因候选 ③**——C++ `Merge::allocateCopyTrim`
（merge.cc:411）会在 firstuse 地址**再物化显式 COPY**（动态哈希 `gatherFirstLevelVars`
要求用点有 COPY 时,merge 重新插回;映射绑定在前折时保在 High 上）。kuna 的 copy_trim 对
该类 temp 永不触发 → 该显式化的中间值被内联。若我方同缺,CASTFUSE-A 的 `iVar9` 类独立
语句正是其输出面。

**验证方法**: `--one 405`（CodeSpec）fixture,dump CONCAT31 输出 vn 的
（readers 数,is_implied,is_explicit,cover）+ 用点地址处是否存在 oracle 再插入的 COPY
（oracle 侧 golden_dump 加 `DynamicHash::gatherFirstLevelVars` 探针）;对照我方 merge.rs
copy_trim 对动态哈希 temp 的再物化路径。写域 coreaction.rs+merge.rs（机制 C 白名单,CR 必附）。

**簇 3 — RETADDR（死存储存活边界 + pass 数敏感性）**

我方症状: golden 保留 `local_d0=0x12b869`（retaddr 槽复用+bumpDeadcodeDelay）消
`0x12ba0c`;我方恰好相反;canary 链我方消 golden 留。

kuna 增量: LOSS-247-v2——**C++ 在后续完整 mainloop 迭代里重新引入 STORE**（pass 7
`s..d1:1 = DIL`）,RuleStoreVarnode 再转回字节家,自持;单 pass 视角会得出错误存活边界。
LOSS-249: deadcode 后 re-heritage 寄存器范围（RAX→EAX）必须点火。LOSS-135: ActionDeadCode
四个子行为（markConsumedParameters/INDIRECT 源标记/BRANCHIND switch-var 掩码/
holdStackAliasStores）取恢复值而非保守默认。

**验证方法**（RETADDR 既有票 fixture 规格增补）: 三形态 fixture（死 canary+retaddr 槽复用+
永不复读槽）必须跑**完整 mainloop 迭代数**并逐 pass 对拍（非单 pass）;在 pass 边界记录
STORE 重引入事件。写域 coreaction.rs/ruleaction.rs/heritage.rs（跨持有,随 RETADDR 票）。

### 4.2 支持性命中（既有票的 C++ 锚/机制确认,不新立票）

| 我方族/票 | kuna 证据 | 增量价值 |
|---|---|---|
| **CURLCANON-FIELDARR-CANON-0001**（L 族 5 行,`buffer._0_4_` vs `buffer[LIT]._0_4_`） | arraysubfield 收敛 + LOSS-202: C++ pushPartialSymbol 有 ARRAY 臂（printc.cc:2062-2076 getSubEntry 元素下降）;kuna 曾整类漏路由数组符号 | 我方有臂（printc.rs:4757）但残差在 → 缺口在**到达条件**（哪些数组符号进 push_partial_symbol/元素下标计算）,fixture 直接对 file2string buffer 站点双侧 trace 路由 |
| **MIRATTR-F-ARRCAST**（httpd 镜面 4 行,`(t [N]*)` 非法 C） | LOSS-154-F1 + LOSS-217-SEAM C: C++ 机制=printc.cc:75/78 `ptr_expr`(prec 62)/`array_expr`(prec 66) RPN 优先级,指针在数组**外层**才括号化 `(t (*) [N])`;checkAddressOfCast 地址-of 臂渲染 `&sym` 并消多余 cast | kuna 曾犯同向括号化错误——我方 printc.rs:2002-2022 机制注释在但 cast 形仍错;修复票直接引 printc.cc:75/78/264-300 锚 |
| **MIRATTR-F-DECL / CURLCANON-I 族**（声明序+多余声明） | LOSS-217 + DIV-52: C++ `emitScopeVarDecls` 走 **Scope 符号**（cat≥0 类目序/cat=-1 MapIterator 地址序/multi-entry `isPiece && getFirstWholeMap()!=entry` 只发首项）,非 HighVariable;全局 scope 符号 named-but-not-declared | 确认我方 F-DECL 票面两序源正确;补第三细节: multi-entry 折叠条件 |
| **HTTPDMAIN-F5**（if/else 取向翻转,post-F1 复测中） | LOSS-205: kuna 侧 `if (10 < a1)`+交换 then/else vs oracle `if (a1 <= 10)`——同一 negateCondition/flip 机制域的独立第三方案例 | F5 复测若仍存,对照 blockaction.cc:1801-1833 规则序时把条件规范化面纳入 |
| **HTTPDMAIN-F8-FORLOOP-0001**（在飞） | LOSS-197/200/235: C++ 链 findLoopVariable→iterateOp 迁移→emitForLoop + `has_overflow_syntax()` 守卫;kuna 阻塞项=RSP 噪声/param-spill | **依赖序确认**: F8 验证必须在 F1（noreturn 数据）修复后的干净 RSP 链上跑,否则 testTerminal 假 decline |
| **CURLCANON-UNIONSTORE-ARBITRATION-0001**（D 族 46 行,最大 curl 池） | LOSS-169/184: C++ unionMap 缓存（funcdata.cc:915-1115）+ ScoreUnionFields 活驱动填缓存 + **按地址命中缓存**;resolveInFlow 缓存 miss = 跑 scorer 并缓存评分字段型 | D 族 fixture（oracle resolveInFlow drill）设计输入: 逐站点解析决策要连同缓存命中/miss 行为一起钉 |
| **CURLCANON-PROTOCAST-INPUTS-0001**（A 族 45 行） | LOSS-153(b): C++ `ActionDefaultParams` 对有恢复原型的被调做 `fc->copy(otherfunc->getFuncProto())`——锁定调用点用**被调自己的原型**而非默认模型;LOSS-179: setcasts 活迭代器重访 castOutput 的 offset-0 PTRSUB 插入件 | ①我方 CALLSPEC-COPY-0001（FUNCPROTO-MODEL-BIND 残差登记）正是 153(b) 的对应面——**建议优先级上调**,A 族 gp/my_get_line 站点的被调（fopen/fgets/fclose）恰是有恢复原型的 libc 调用;②LOSS-179 快照-vs-活迭代器为低概率检查项（kuna 实测零效应） |
| **UNAFF-EXTRAOUT**（sq 555 行） | LOSS-242: xmm0 既是 float8 参数又是返回寄存器时 C++ 把输入拆成两个 4 字节输入;LOSS-248: 参数入 scope 影响 unaffected 判定 | UNAFF fixture 检查单增补: 参数/返回双职寄存器的输入拆分形态 |
| **DB-LOCALSCOPE 簇**（DB-LOCALSCOPE-MAP-0001/PROTOSTORE-SYMBOL-0001/FUNCDATA-LOCALSCOPE-OWNERSHIP-0001,P0 BLOCKED） | LOSS-248-RESOLVED 全文 = 该簇的**独立第三方根因确认**（kuna 用 2 行修复证明: 参数入 scope → sync 清 addrforce → DCE → 栈槽物化/多余 INDIRECT/re-heritage 三症状全消） | 不新立票;**解锁该簇的优先级论证增强**——kuna 的最小复现形（锁定参数 s0x8 size-2 → findOverlap 解析 → addrforce 清）可直接作 fixture 模板 |

### 4.3 不命中（排除理由记录）

| 我方族 | 排除理由 |
|---|---|
| curl B29（helpf varargs） | kuna 同域未移植（LOSS-149 输入半独立）,无 C++ 行为增量;我方票面机制（param trials/保存链）不变 |
| curl C29（bool 元类型）/N4（const 限定） | debugproto/DWARF 域,kuna 无对应观察（其 DWARF 是自建分析器层） |
| curl E22（静态作用域名）/H7（imagebase）/O3（DAT 槽宽） | 驱动层根因已钉死（CURLATTR §4E）,kuna 无对应面 |
| curl J11（_init/csu FID 原型） | headless 分析器知识,kuna 的 FID 是自建 .fid（LOSS-251）,无 oracle 行为增量 |
| httpd F1/F2/F6/F7 | 驱动数据面（noreturn 台账/rebase/串模型/签名台账）;kuna 的 noreturn/字符串分析在其 analysis 层（DIV-19/22/110）,非 decompiler oracle 行为 |
| httpd F4（webtype,DONE） | 已修（infer_ptr_spaces 寄存器空间泄漏）;kuna LOSS-143 的 pspec 子元素面单列为 §5 P3 验证票（inferptrbounds 同族预防） |
| F-TYPE/SEXT/ZEXT 主根 | 我方根因=varmap 符号层中毒（S2FIX 钉死）;kuna LOSS-138 的 11 个 propagateType 弃权我方**不存在**（coreaction.rs:8048 中央 match 覆盖 XOR/AND/OR/SUBPIECE/compare 族/PTRADD/PTRSUB/LOAD/STORE…,XOR/AND 臂逐字对齐 typeop.cc:1422-1440 含 enum/float 门+spacebase rewrap）——**反向健康证明** |
| sq SWITCH-GOTO | foldInGuards（jumptable.rs:5258）与 gotoPrints（block.rs:6181）我方均在——kuna 对应缺失面我方不缺;族根因归 MSTRUCT 票不变 |
| sq WARNING-FACE | 已修（GLOBALOVERLAP-PROXY） |
| F-WRAP/F-STRFOLD/F-LOAD/F-WARN/F-PLTNAME/F-CODENAME/F-VOIDRET | kuna 无对应 C++ 行为观察增量（其 printc 移植忠实面我方票面机制行号已齐） |
| 6 上游 bug 全部 | crash/UB 边缘 ≠ 输出形态分歧;KUNAUB 四票维持 |

---

## 5. 可派生验证票建议（汇总）

> 全部为**验证票**（fixture 先行,证据未钉死前不动 src）;按预期收益/成本排序。

| 建议 ID | P | 目标族 | 一句话 | 验证方法摘要 |
|---|---|---|---|---|
| `KUNABUGS-STORELOAD-FWD-0001` | **P1** | F-RESIDE/STACKSLOT | heritage 栈 store→load 转发时序未对拍（LOSS-237: C++ pre-heritage 转发,缺失则值落栈槽） | my_get_line 单函数双侧首 heritage 边界 IR dump,逐 op 对比 LOAD 读源 |
| `KUNABUGS-COPYTRIM-REMAT-0001` | **P1** | CASTFUSE-A | Merge::allocateCopyTrim（merge.cc:411）对动态哈希 temp 的 firstuse 再物化——SQFACE 未列的根因候选③ | --one 405 双侧 dump（readers,implied,explicit,cover）+ oracle gatherFirstLevelVars COPY 探针 |
| `KUNABUGS-RETADDR-PASSCOUNT-0001` | **P2**（并入 RETADDR 既有票规格） | RETADDR | 死存储存活边界是 mainloop pass 数敏感的（LOSS-247-v2: C++ pass 7 重引入 STORE;LOSS-249: deadcode→re-heritage） | 三形态 fixture 跑完整迭代数逐 pass 对拍,记录 STORE 重引入事件 |
| `KUNABUGS-MERGE-SORT-TIE-0001` | P2 | F-RESIDE/STACKSLOT | merge.rs:4630 稳定排序 vs oracle std::sort 不稳定——三键全等平局面的栈代表选择（LOSS-113;预期 MATCH,kuna 自证其语料等价,但这是 C++ 唯一未指定序） | 合成三键全等双 high fixture,双侧 merge_linear 对比代表选择 |
| `KUNABUGS-PARSEPROCESSOR-CHILDREN-0001` | P3 | arch 卫生（F4 谱系预防） | parse_processor_config 子元素覆盖 vs architecture.cc:1176-1239 全清单（LOSS-143: volatile/incidentalcopy/jumpassist/segmentop/register_data/data_space/inferptrbounds/default_symbols/default_memory_blocks/address_shift_amount/properties + 未知元素 throw） | grep 对照我方 arch 分派面,缺口列表登记（x86-64 语料多数不可观察,volatile/inferptrbounds 为真实行为面） |
| `KUNABUGS-ZEXT-PIECE-CONV-0001` | P3 | sq OPNAME-LEAK | RulePieceStructure 的 convertZextToPiece/findReplaceZext（LOSS-168）在 CONCAT 语境把 ZEXT 转 PIECE——ZEXT 泄漏 107 位点的第二候选根因（主根因=metatype 中毒已判） | 对 GetOptimum/CodeReal 泄漏函数检查我方 rule 的 ZEXT→PIECE 转化到达率 |
| 既有票补强（不新立） | — | A 族/DB 簇/UNAFF/F-DECL/L 族/F8/F5/D 族 | 见 §4.2 表——CALLSPEC-COPY-0001 优先级上调建议;DB-LOCALSCOPE 簇解锁论证增强（kuna LOSS-248 独立确认）;F-DECL 补 multi-entry 折叠条件;L 族路由 trace;F8 依赖序（post-F1）;F5 条件规范化面;D 族缓存行为入 drill | — |
| 低优先检查单（不立票,随手核） | P4 | — | ①LOSS-210: 我方 merge inflate 路径 partialCopyShadow 的端序源读 `a`(this) 还是 `b`——kuna 曾读错,一字级;②LOSS-136: 我方 ActionPrototypeTypes（partial port,coreaction.rs:11334）是否像 C++ 一样**不**bump count（bump 会引发伪 restart）;③Convergence-subright: RuleSubRight 后半段完整性;④Convergence-jtsharepartial: jumptable 部分子编译的 scope 共享;⑤typeop.rs:2583 TypeOpMulti::get_flags()=0 死路径卫生（真 flags 走 op.rs:220,确认无行为消费者后加注释或对齐） | grep+单测级 |

---

## 6. 复现口径

```bash
# 取材（clone 收尾已删,以下为复现路径）
git clone https://github.com/Noelo-Lab/kuna && cd kuna
git show ba2c07df^:docs/rust-port/losses.md > losses.md        # 3687 行,302 条
git show ba2c07df^:docs/rust-port/upstream-bugs.md > ub.md     # 6 bug 全文
# 我方 oracle 判定锚（本车道亲读）
ghidra/.../cpp/opcodes.cc:29-48/60-64, opcodes.hh:130          # UB-1（12.0.4 形态）
ghidra/.../cpp/opbehavior.cc:507-541                            # UB-2
ghidra/.../cpp/xml.cc:2337-2358                                  # UB-3
ghidra/.../cpp/rangemap.hh:281-326/177-188                      # UB-4
ghidra/.../cpp/memstate.cc:95-171                               # UB-5a
ghidra/.../cpp/pcodeparse.cc:2727-2760/2776-2790                # UB-5b
ghidra/.../cpp/merge.cc:282, merge.hh:152-174                   # LOSS-113
ghidra/.../cpp/typeop.cc:1944-1947                              # phiopflags
# 我方 src 核查锚（只读 grep,零改动）
src/merge.rs:4630（stable sort_by）/ src/heritage.rs:2038-2075（guard_calls 忠实）/
src/funcdata.rs:3874-3892（sync 掩码忠实）/ src/coreaction.rs:7528（setcasts count 忠实）/
src/coreaction.rs:7373（快照迭代,LOSS-179 同款）/ src/op.rs:220（MULTIEQUAL flags 忠实）/
src/varmap.rs:1607-1612（addGuard 在）/ src/blockaction.rs:8790（F8 在飞）/
src/coreaction.rs:8048（propagateType 中央 match,LOSS-138 不适用）
```

## 7. 收尾声明

- kuna clone（/dev/shm/rugra-tests/kunabugs/kuna）与复活文件已删除;核心引用已全部誊入本文。
- 本车道零 repo src 改动、零 examples 改动、零 commit;唯一产物=本报告。
- 诚实纪律重申: §4/§5 全部"命中"均为**验证票建议**——kuna 的观察是二手的,且其锚点
  cef869af 晚于我方 oracle 12.0.4;任何修复动作必须以我方锁定 oracle e40ed130 的
  fixture 实证为前提。§3.1 的"我方忠实"判定基于 grep 亲证,不等于 B2 门禁的 MATCH——
  各域函数的 MATCH 状态以 FUNCTION_MAP 账本为准。

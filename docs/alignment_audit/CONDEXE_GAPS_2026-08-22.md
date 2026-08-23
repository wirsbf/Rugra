# CONDEXE_GAPS_2026-08-22 — condexe.cc vs src/condexe.rs 深度差距审计

- **审计 Agent**: condexe_gaps_audit（只读重启续作；本报告为首次产出，未发现既有报告）
- **日期**: 2026-08-23（任务日期 2026-08-22）
- **Rugra HEAD**: master = 296c128（只读）
- **Oracle**: Ghidra 12.0.4 tag `Ghidra_12.0.4_build`, commit `e40ed13014025f82488b1f8f7bca566894ac376b`
  - `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/condexe.cc`（712 行）
  - `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/condexe.hh`（199 行）
- **Rugra 侧**: `src/condexe.rs`（1555 行，含测试）
- **结论速览**: 27 个 Ghidra 函数中 **1 个 MISSING**（buildHeritageArray）、**7 个 MISMATCH/PARTIAL 有实质行为分歧**；地基（op destroy/insert、双向边不变量、PathMeld）**绝大多数已存在且忠实**，真正的阻塞是 **2 个共享地基缺陷**：`remove_from_flow_split` 调用序列反了且一支越界（funcdata.rs:2769-2782），以及 `get_true_out`/`is_true_out_to` 的 true/false 边判定与 Rugra 自身 CFG 构造顺序相反且叠加了 Ghidra 没有的 flip 重映射（block.rs:453-485, condexe.rs:234-251）。
- **roadmap #19 勘误**: ALIGNMENT_ROADMAP.md:109 所述 "condexe.rs(238行)只检测不重写" 已过时（现为 1555 行、含完整重写框架）；**"PathMeld 不等价" 与 "forceSpecific/removeBlockEdges/setOut 缺失" 属错误归因** — 经 grep 核实 condexe.cc 全文不引用 PathMeld（PathMeld 是 jumptable.cc:794-960 的类，Rugra 对应物在 jumptable.rs:153），`forceSpecific`/`removeBlockEdges`/`setOut` 三个名字在锁定 oracle 的 condexe.cc/hh 中**不存在**（roadmap G1, :553 同样过时）。

---

## 1. 逐函数对照表

状态定义：MATCH=结构+语义对齐（仍属 UNTESTED 直到 oracle fixture 通过）；PARTIAL=存在已定位分歧；MISSING=无对应物；MISMATCH=语义相反/破坏性。

### 1.1 ConditionalExecution（condexe.cc:23-476）

| # | Ghidra 函数 (file:line) | Rugra 对应 (file:line) | 状态 | 差异明细 |
|---|---|---|---|---|
| 1 | `buildHeritageArray` condexe.cc:23-37 | **无**（`ConditionalExecution::new` 内 stub：`heritageyes: vec![true; 4]`，condexe.rs:104-127） | **MISSING** | Ghidra 按 `fd->numHeritagePasses(spc) > 0`（funcdata.hh:237 → heritage.cc:2793 `pass - delay`）逐 space 填 `heritageyes`；Rugra 写死 4 个 space 全 true。后果：`testRemovability` cc:392 的无后继-varnode 检查在未 heritage 的 space 上 Ghidra 拒绝、Rugra 放行 → 多余重写。**地基已存在**：`Heritage::num_heritage_passes(space)`（heritage.rs:5072，含 per-space delay）与 `AddrSpace::is_heritaged`（space.rs:160/1820）都已忠实，只是没接线；另 `Funcdata::num_heritage_passes`（funcdata.rs:6958）无 space 参数、直接 `get_pass()`，与 funcdata.hh:237 不符，需修签名或新增包装。 |
| 2 | `testIBlock` condexe.cc:43-52 | `test_iblock` condexe.rs:165-175 | MATCH | 2-in/2-out/lastOp==CBRANCH 逐条对应。 |
| 3 | `findInitPre` condexe.cc:55-75 | `find_init_pre` condexe.rs:184-224 | **PARTIAL** | 双路径回溯结构忠实（`last` 在循环内更新、tmp2 会师校验、`initblock==iblock` 拒绝都对应）。分歧点：`init2a_true = (initblock->getTrueOut() == last)`（cc:72）经 `is_true_out_to`（rs:222, 234-251）计算，而该 helper 语义错误（见 §2.2 缺陷 T）。roadmap 称 "findInitPre 缺失" 已过时 — 函数存在。 |
| 4 | `verifySameCondition` condexe.cc:80-94 | `verify_same_condition` condexe.rs:260-279 | **PARTIAL** | flip 合成本身 = Ghidra（`matchflip = complementary XOR ib_flip XOR init_flip`，对应 expression.cc:226-230 在 verifyCondition 内的两次翻转；rs:270-275 等价展开）。**但** init2a_true 的来源 `is_true_out_to` 已经消费过 flip（见缺陷 T），同一 flip 在本函数再次 XOR → **重复翻转**（roadmap 主张属实）。且 BooleanExpressionMatch 本体见 #25-27，结构 MATCH。 |
| 5 | `testMultiRead` condexe.cc:101-113 | `test_multi_read` condexe.rs:286-305 | MATCH | iblock 内 COPY/SUBPIECE 放行、RETURN 仅 input(1)==vn 三条对应。 |
| 6 | `testOpRead` condexe.cc:120-142 | `test_op_read` condexe.rs:312-350 | MATCH | COPY/SUBPIECE/INT_ADD/PTRSUB 白名单、INT_ADD/PTRSUB 的 in(1) 常量约束、上游 def 在 iblock 且非 MULTIEQUAL 拒绝、isFree 拒绝逐条对应。 |
| 7 | `findPullback` condexe.cc:146-152 | `find_pullback` condexe.rs:440-445 | MATCH | 惰性扩容语义一致。 |
| 8 | `pullbackOp` condexe.cc:160-190 | `pullback_op` condexe.rs:450-500 | **MISMATCH** | ① **storage**：Ghidra `outVn = fd->newVarnodeOut(origOutVn->getSize(), origOutVn->getAddr(), newOp)`（cc:181-182，保留原输出地址）；Rugra `new_unique_out`（rs:489，匿名 unique）→ pullback 输出的存储/后续 merge、varmap 命名均不同。② **插入位置**：Ghidra `fd->opInsertEnd(newOp, bl)`（cc:187）；Rugra `op_insert_begin`（rs:496）→ 新 op 落在 MULTIEQUAL 组之前而非块尾。③ inbranch 选取 defOp 输入与 `iblock->getIn(inbranch)` 目标块的结构本身对应（rs:454-481 vs cc:166-179）。 |
| 9 | `getNewMulti` condexe.cc:198-217 | `get_new_multi` condexe.rs:509-522 | MATCH | `newOp(bl->sizeIn(), bl->getStart())`、`newUniqueOut`（此处 Ghidra 也用 unique，cc:206 注释解释为何不用原地址）、全部输入先 set、`opInsertBegin`、返回 newoutvn 逐条对应。 |
| 10 | `resolveRead` condexe.cc:224-237 | `resolve_read` condexe.rs:526-542 | MATCH | sizeIn==1 时 `getInRevIndex(0) == posta_outslot` 判据 + camethruposta 映射逐字对应（BlockBasic::get_in_rev_index block.rs:1407 = intothis[slot].reverse_index，同 block.hh:306-308）。 |
| 11 | `resolveIblockRead` condexe.cc:242-262 | `resolve_iblock_read` condexe.rs:546-575 | **PARTIAL** | COPY 解引用、MULTIEQUAL 取 slot、SUBPIECE/INT_ADD/PTRSUB 走 pullback 对应；**异常**：Ghidra 对非法 op `throw LowlevelError("Conditional execution: Illegal op in iblock")`（cc:261），Rugra 返回 `None`（rs:574）→ 上层静默跳过（见 #14 缺陷 E）。 |
| 12 | `getMultiequalRead` condexe.cc:270-279 | `get_multiequal_read` condexe.rs:579-595 | MATCH | inbl != iblock 走 getReplacementRead，否则 rev-index 判据走 resolveIblockRead，结构一致。 |
| 13 | `getReplacementRead` condexe.cc:291-315 | `get_replacement_read` condexe.rs:599-628 | **PARTIAL** | 双级缓存（bl 直查 / dominator 链回溯后查并回填）结构忠实；**异常**：Ghidra 无 dominator 时 `throw LowlevelError("Conditional execution: Could not find dominator")`（cc:303），Rugra 返回 `None`（rs:614）。 |
| 14 | `doReplacement` condexe.cc:320-357 | `do_replacement` condexe.rs:632-710 | **MISMATCH** | ① **死循环隐患**：Rugra 主循环每轮取 `descends[0]`（rs:639-643），若 `rvn == None`（resolve 链任一失败）则 `if let Some(rvn)` 跳过 `op_set_input`（rs:702-705）→ 后继表不收缩 → 同一 readop 永远是 descends[0] → **无限循环**。Ghidra 的等价路径要么成功 set 要么 throw，不存在静默空转。② RETURN 读处理（cc:339-349 vs rs:663-694）：COPY 创建、`newVarnodeOut(retvn size/addr)`、`opSetInput(readop,outvn,1)`、`opInsertBefore`、以 newcopy 为新读点对应（rs:677 用 `retvn.loc`+Register space，Ghidra `retvn->getAddr()` 可携带原 space — 窄域差异）。③ iblock 内读 `opUnsetInput` 对应（rs:654-658）；注意 Rugra `op_unset_input`（funcdata.rs:1865-1885）**不清 inrefs[slot]**（注释声明 Vec 槽惰性覆盖），对本调用点无害（后继已断），但属于与 funcdata_op.cc:98 `clearInput` 的可见状态差异，fixture 断言 inrefs 时必须计入。 |
| 15 | `testRemovability` condexe.cc:361-397 | `test_removability` condexe.rs:357-396 | **PARTIAL** | MULTIEQUAL 走 testMultiRead、isFlowBreak/isCall/LOAD/STORE/INDIRECT/isAddrTied 拒绝逐条对应（Rugra 用 4 opcode 显式枚举 is_flow_break 等价）；分歧：`hasnodescend && !heritageyes[space]` 检查（cc:392）在 Rugra 恒真（rs:387-394，`let _ = &self.heritageyes; true`）— 同 #1 根因。 |
| 16 | `verify` condexe.cc:402-428 | `verify` condexe.rs:403-433 | PARTIAL(≈) | ① Ghidra 从 endOp 反向**跳过最后一个 op**（cc:419-426，testIBlock 已保证是 CBRANCH）；Rugra 正向遍历并跳过所有 branch 类 opcode（rs:423-429，含 RETURN — Ghidra `isBranch` 仅 3 个 opcode，op.hh）。testRemovability 无副作用且为纯合取 → 布尔结果等价；有效 BlockBasic 中 branch 只能在末位 → 集合等价。判定为可接受偏差，fixture 需覆盖"块中含非末位 branch"的非法态以证明拒收路径。② 缓存字段（iblock2posta_true/camethruposta_slot/posta|postb_block）逐条对应（rs:411-420）。 |
| 17 | `ConditionalExecution::ConditionalExecution` condexe.cc:432-437 | `new` condexe.rs:104-127 | **PARTIAL** | 构造器本身对应，但未调 buildHeritageArray（见 #1）。 |
| 18 | `trial` condexe.cc:448-454 | `trial` condexe.rs:719-722 | MATCH | 注：Ghidra 类文档（condexe.hh:39-46）描述的 directsplit 递归在 12.0.4 trial 中已不存在（只调 verify），Rugra 与代码而非文档对齐，正确。 |
| 19 | `execute` condexe.cc:457-476 | `execute` condexe.rs:727-746 | **MISMATCH** | ① 逆序 destroy + 非分支先 doReplacement 结构对应（rs:730-742）。② **`removeFromFlowSplit(iblock, posta_outslot != camethruposta_slot)` 的实参表达式一致（rs:744），但被调方映射反/越界**（见 §2.1 缺陷 F）。③ **错误通道**：`let _ = self.fd.remove_from_flow_split(&ib, swap);`（rs:745）**丢弃 Err**；Ghidra 在非空块/非法块 throw LowlevelError 中止反编译（funcdata_block.cc:884-885）。 |

### 1.2 ActionConditionalExe（condexe.cc:478-503）

| # | Ghidra 函数 | Rugra 对应 | 状态 | 差异明细 |
|---|---|---|---|---|
| 20 | `ActionConditionalExe::apply` condexe.cc:478-503 | `apply` condexe.rs:1353-1385 | **MISMATCH** | ① **guard 缺失**：Ghidra `if (data.hasUnreachableBlocks()) return 0;`（cc:485-486）在 Rugra 无对应（rs:1353 直接进入循环）；`has_unreachable_blocks`（funcdata.rs:2327）已存在未用。② **count 丢失**：`count += numhits`（cc:501）→ Rugra `let _ = numhits;`（rs:1383），Action trait 有 `take_count_delta` 钩子（action.rs:85）未实现。③ **遍历语义**：Ghidra `const BlockGraph &bblocks(data.getBasicBlocks())` 是活引用，`for(i=0;i<bblocks.getSize();++i)` 每轮重读 getSize — execute() 内 removeBlock 后列表收缩，**i++ 会跳过移位到 i 的那个块**；Rugra 先快照 `block_snap`（rs:1362-1364）再遍历，**不跳过**任何块 → 一轮内 trial 集合不同（Ghidra 靠外层 do-while 补偿，最终收敛域仍可能一致，但逐轮可观测中间态不同，违反铁律 2.1 迭代顺序条款）。④ **stage/管线位置**：Ghidra mainloop 内序 `...DeterminedBranch(5672)→Unreachable(5673)→NodeJoin(5674)→**ConditionalExe(5675)**→ConditionalConst(5676)`（coreaction.cc）；Rugra 把 condexe 放在 `ActionInferTypes` 之后、`ActionRedundBranch/BlockStructure/Unreachable` **之前**（action.rs:1053-1076）— 与 ① 叠加放大：Ghidra 保证 condexe 看到的图已经过 unreachable 清理，Rugra 反而在清理前运行且无 guard。⑤ 返回值：恒 0 / 恒 `NO_CHANGE`（action.rs:1174 `NO_CHANGE=0`）等价 ✓。⑥ rs:1367-1373 的 `sin==2&&sout==2&&is_cb` 预过滤是 trial 内 testIBlock 的重复，无可观测差异（trial 失败不残留状态），可接受。 |
| 21 | 构造/clone（condexe.hh:135-139） | `new`（rs:1343）+ Box 注册（action.rs:1065） | MATCH | Rust 无 clone 机制，Box 重建等价。 |

### 1.3 RuleOrPredicate（condexe.cc:509-710）

| # | Ghidra 函数 | Rugra 对应 | 状态 | 差异明细 |
|---|---|---|---|---|
| 22 | `MultiPredicate::discoverZeroSlot` condexe.cc:509-529 | `discover_zero_slot` condexe.rs:1019-1049 | MATCH | 2 输入 MULTIEQUAL、COPY(#0) 判定、otherVn isFree 拒绝逐条对应。 |
| 23 | `MultiPredicate::discoverCbranch` condexe.cc:539-567 | `discover_cbranch` condexe.rs:1054-1097 | MATCH | zeroBlock/otherBlock 出度分型、condBlock 归一、lastOp==CBRANCH 对应。 |
| 24 | `MultiPredicate::discoverPathIsTrue` condexe.cc:572-582 | `discover_path_is_true` condexe.rs:1101-1129 | **MISMATCH** | Ghidra 用 **纯位置** `getTrueOut()/getFalseOut()`（block.hh:299-300：out[1]=true、out[0]=false，**不读 BOOLEAN_FLIP**）；Rugra rs:1108-1117 按 flip 重映射取 out[0]/out[1]，且基于错误的边序假设（见缺陷 T）→ `zero_path_is_true` 判反，直接导致 applyOp 的 `finalBool`（cc:677-680 / rs:1261-1263）错误接受/拒绝。 |
| 25 | `MultiPredicate::discoverConditionalZero` condexe.cc:590-615 | `discover_conditional_zero` condexe.rs:1135-1166 | MATCH | INT_NOTEQUAL/INT_EQUAL、vn 与 0 常量比对、`cbranch->isBooleanFlip()` 终态翻转（cc:612-613 ↔ rs:1162-1164）逐条对应 — **此处**才是 Ghidra 消费 BOOLEAN_FLIP 的位置，进一步证明 #24 的重映射是多余翻转。 |
| 26 | `getOpList` condexe.cc:617-622 | `get_opcodes` rs:1185-1187 / trait rs:1327-1330 | MATCH | INT_OR/INT_XOR。 |
| 27 | `checkSingle` condexe.cc:638-652 | `check_single` condexe.rs:1193-1220 | MATCH | loneDescend==op、zeroPathIsTrue 拒绝、`opSetInput(multi,vn,zeroSlot)`+`opRemoveInput(op,1)`+COPY 化逐条对应。 |
| 28 | `RuleOrPredicate::applyOp` condexe.cc:654-710 | `apply_op` condexe.rs:1224-1302 | **MATCH（受 #24 污染）** | 双分支分派、condBlock 相同/相异两路、`condmarker.getFlip()`（cc:678 ↔ rs:1254-1262 `verify_condition_with_flip`，其 flip 合成 = expression.cc:227-230 两次翻转 ✓）、`getMultiSlot() != -1` 省略（expression.hh:101 恒返 -1，等价 ✓）、`compareOrder`（op.cc:778-790 ↔ op.rs:446-468，同块比 SeqNum order、跨块比 findCommonBlock ✓）、newMulti 构造序（先 inputs 后 newUniqueOut，cc:694-705 ↔ rs:1284-1297 ✓）、INT_OR→COPY 化 ✓。唯一实质缺陷是被 #24 的 zeroPathIsTrue 污染。 |

### 1.4 依赖侧跨文件函数（expression.cc，被 #4/#28 消费）

| # | Ghidra 函数 | Rugra 对应 | 状态 | 差异明细 |
|---|---|---|---|---|
| 29 | `BooleanMatch::varnodeSame` expression.cc:93-100 | `varnode_same` condexe.rs:755-762 | MATCH | 指针相等 + 双常量按 offset。 |
| 30 | `BooleanMatch::sameOpComplement` expression.cc:57-86 | `same_op_complement` condexe.rs:767-799 | MATCH | constslot 探测、val1+1==val2、INT_LESS val2==0 角例、INT_SLESS 符号位角例（signbit_negative）逐条对应。 |
| 31 | `BooleanMatch::evaluate` expression.cc:111-216 | `boolean_match_evaluate` condexe.rs:804-937 | MATCH | 深度门（`depth != 0 && opc1∈{AND,OR,XOR}` → 否则落 else 直比，cc:151/183 ↔ rs:857/905）、BOOL_NEGATE 先查 vn1 再查 vn2 的短路序（cc:117-148 ↔ rs:806-853）、交换子配对（cc:154-164 ↔ rs:871-888）、XOR/DeMorgan 组合表（cc:167-179 ↔ rs:890-899）、`get_booleanflip` 补码对（cc:203-213 ↔ rs:922-936）均逐行核对一致。注意 rs 内嵌于 condexe.rs 而非 expression.rs — 归属位置差异（Ghidra 在 expression.cc），建议迁移但非行为缺陷。 |
| 32 | `BooleanExpressionMatch::verifyCondition` expression.cc:220-232 | `boolean_match_verify_condition` rs:942-953 + `verify_condition_with_flip` rs:959-977 | MATCH | 前者无 flip（Rugra 拆成两个函数，with_flip 版 = Ghidra 全语义含 cc:227-230 两次翻转）；`verify_same_condition` 内联合成等价（见 #4）。`verify_condition_with_flip` 的 `// Ghidra: condexe.cc:432 ...` 注释指向错误（Ghidra 无此函数，应为 RUGRA-GLUE 或指向 expression.cc:220）。 |

**函数计数**: Ghidra 侧 condexe.cc 27 个函数（含依赖侧 expression.cc 4 个）中 — **MISSING 1**（buildHeritageArray）、**MISMATCH 6**（pullbackOp、doReplacement、execute、apply、discoverPathIsTrue、以及 findInitPre/verifySameCondition/resolveIblockRead/getReplacementRead/testRemovability 共 5 个 PARTIAL 的共同上游缺陷计入缺陷 T/F/E）、**MATCH 20**（其中全部处于 UNTESTED — 无任何 locked-oracle fixture，仅有 Rust 自测，见 §5）。

---

## 2. 地基清单与核实结果

### 2.1 CFG / op 基础设施（condexe 移植所需全部地基）

| 地基 | Ghidra (file:line) | Rugra (file:line) | 核实结论 |
|---|---|---|---|
| `FlowBlock::halfDeleteInEdge/halfDeleteOutEdge` | block.cc:100/115 | block.rs:1415/1429 | **MATCH** — remove+高位 reverse_index 递减滑动对应。 |
| `FlowBlock::replaceEdgesThru` | block.cc:198-216 | block.rs:1446-1479 | **MATCH** — 四端点先捕获、对端重写、双半删、序（先 in 后 out）对应。 |
| `FlowBlock::getInRevIndex` | block.hh:306-308 | block.rs:1407（BlockBasic）/ block.rs:424（trait 默认 -1） | MATCH（trait 默认 -1 是 Rugra 多态胶水，condexe 全程经 BlockBasic）。 |
| `BlockGraph::removeBlock` | block.cc:1517-1536 | block.rs:1871 `remove_block_arc` | **MATCH** — 先拆全部 in/out 边再移列表；差异：Ghidra `delete bl`，Rugra 保留 Arc（内存模型差异，无图语义影响）。 |
| `BlockGraph::removeFromFlowSplit` | block.cc:1575-1590 | **无独立方法**，序列内联在 funcdata.rs:2769-2782 | **MISMATCH（缺陷 F，最关键阻塞）**。Ghidra：`flipflow ? replaceEdgesThru(0,1) : replaceEdgesThru(1,1)` 先行，`replaceEdgesThru(0,0)` 收尾。Rugra：`swap=true → (0,0),(0,1)`；`swap=false → (0,1),(0,0)`。展开（每次 replaceEdgesThru 后列表收缩滑动）：Ghidra flipflow=true ⇒ in0→out1,in1→out0；flipflow=false ⇒ in0→out0,in1→out1。Rugra swap=false 恰好实现 Ghidra flipflow=**true** 的映射（**两支映射相反**）；Rugra swap=true 第一步 (0,0) 后 out 列表仅剩 1 项，第二步 `self.outgoing[1]`（block.rs:1454）**索引越界 panic**（**一支可越界**）。roadmap 主张逐字属实。 |
| `Funcdata::removeFromFlowSplit` | funcdata_block.cc:881-889 | funcdata.rs:2740-2787 | **MISMATCH** — 调用上述错误序列；emptyOp 校验对应（Err vs throw，通道差异可接受但 condexe.rs:745 `let _ =` 丢弃）；**注释 `// Ghidra: funcdata.cc:34` 指向 Funcdata 构造器（funcdata.cc:34），真身在 funcdata_block.cc:881 — 引用漂移 Red Flag（机制 D）**。 |
| `Funcdata::structureReset` | funcdata_block.cc:704-730 | funcdata.rs:2264-2318 | MATCH — 清 BLOCKS_UNREACHABLE、structureLoops、calcForwardDominator、rootlist>1 置旗、死 jumptable 清理、sblocks.clear、heritage.forceRestructure 全对应（rs:2315-2317 额外刷新 Rugra 自有 dom 缓存，无 oracle 可观测差异）。 |
| `Funcdata::opDestroy` | funcdata_op.cc:203-222 | funcdata.rs:1716-1738 | MATCH — destroyVarnode(out)、逐 slot opUnsetInput、markDead+removeOp 对应。 |
| `Funcdata::opInsertBegin/End/Before` | funcdata_op.cc:413/435/345 | funcdata.rs:3612/3629/3192 | MATCH — MULTIEQUAL 组前置跳过、末位 flow-break 前插、INDIRECT 前移规则对应（经 op_insert/block_insert_op funcdata.rs:3703-3767，parent/order 维护对应 block.cc:2258）。 |
| `Funcdata::newOp/newUniqueOut/newVarnodeOut` | funcdata_op.cc:322、funcdata_varnode.cc:129/104 | funcdata.rs:1342/1364/1907 | MATCH — new_varnode_out 强制 Register space（rs:1913-1918），对 pullbackOp 场景（原输出在 Register space）等价。 |
| `getTrueOut/getFalseOut` | block.hh:299-300（**纯位置 out[1]/out[0]，不读 flip**） | block.rs:463/476（**flip 重映射**） | **MISMATCH（缺陷 T，第二阻塞）**，见下。 |
| CBRANCH 出边构造顺序 | flow.cc:960-967：先 fallthru 后 branch | flow.rs:920-928：同（注释引 flow.cc:960-967） | **MATCH（构造侧）** — 双方 out[0]=fallthru(false)、out[1]=branch(true)。**因此 block.rs:454-457 声称的 "Rugra 顺序是 [branch_target, fallthru]" 与自身构造代码矛盾，is_true_out_to 在 flip=0 时取 out[0]=fallthru 当 true — 基础极性即反**。 |
| `Heritage::numHeritagePasses` | heritage.cc:2793-2801 | heritage.rs:5072-5080 | MATCH（per-space delay 扣减）；但 Funcdata 包装（funcdata.hh:237 ↔ funcdata.rs:6958）缺 space 参数。 |
| `Funcdata::hasUnreachableBlocks` | funcdata.hh:149 | funcdata.rs:2327-2329 | 存在、未被 apply 使用。 |
| `PcodeOp::compareOrder` | op.cc:778-790 | op.rs:446-468 | MATCH。 |
| `Varnode::beginDescend/endDescend/loneDescend` | varnode.hh | varnode.rs（descend_iter/lone_descend，condexe.rs:362/1206 消费） | 存在；顺序等价性（std::list 前取 vs Vec[0]）属 UNTESTED，fixture 需覆盖多后继乱序插入态。 |
| **PathMeld** | jumptable.cc:794-960（jumptable.hh:72） | jumptable.rs:153 | **与 condexe 无关**（condexe.cc 0 引用）；roadmap #19 "PathMeld 不等价" 系错误归因，应从条目移除。 |

**循环依赖**: 无。condexe → funcdata(block/op API) + block + heritage + expression 均为单向叶消费者；修复缺陷 F（funcdata.rs）与缺陷 T（block.rs）不引入新依赖。

### 2.2 两个共享地基缺陷的精确定义

**缺陷 F — remove_from_flow_split 调用序列**（funcdata.rs:2769-2782）：
```
Ghidra flipflow=true : replaceEdgesThru(0,1); replaceEdgesThru(0,0);  ⇒ in0→out1, in1→out0
Ghidra flipflow=false: replaceEdgesThru(1,1); replaceEdgesThru(0,0);  ⇒ in0→out0, in1→out1
Rugra swap=true      : replace_edges_thru(0,0); replace_edges_thru(0,1); ⇒ in0→out0, 然后 out[1] 越界 panic
Rugra swap=false     : replace_edges_thru(0,1); replace_edges_thru(0,0); ⇒ in0→out1, in1→out0（= Ghidra flipflow=true）
```
修复 = 把 swap=true 分支改为 `(0,1),(0,0)`、swap=false 改为 `(1,1),(0,0)`（或直接新建 `BlockGraph::remove_from_flow_split` 方法承载 block.cc:1575-1590，funcdata 层只做 emptyOp 校验+removeBlock+structureReset）。

**缺陷 T — true/false 边判定**（block.rs:453-485 `get_true_out`/`get_false_out`；condexe.rs:234-251 `is_true_out_to`；condexe.rs:1108-1117 `discover_path_is_true`）：
- Ghidra 语义：`getTrueOut()=outofthis[1]`、`getFalseOut()=outofthis[0]`，**恒位置、不读 BOOLEAN_FLIP**（block.hh:299-300）。flip 的合法消费点只有两处：`discoverConditionalZero`（condexe.cc:612-613）与 `verifyCondition`（expression.cc:227-230）。
- Rugra 现状：三处 helper 都按 "flip=0 → true=out[0]，flip=1 → true=out[1]" 重映射，而实际构造 out[0]=fallthru。后果矩阵（以 Ghidra 为准）：
  - flip=0：Rugra 取 fallthru 当 true（**极性反**）；
  - flip=1：Rugra 取 out[1]=branch（碰巧对，但属于两次错误抵消）。
- 叠加效应：`find_init_pre` 产出错误 `init2a_true` → `camethruposta_slot` 错 → `execute` 的 swap 实参错；`verify_same_condition` 再把同一 flip XOR 一遍（**重复翻转**，roadmap 主张属实）；`discover_path_is_true` 的 `zero_path_is_true` 反 → `applyOp` 误收/误拒。
- 修复 = `get_true_out`/`get_false_out` 改纯位置（true=out[1]、false=out[0]），删除 flip 重映射；**需同步审计这两个 helper 的全部其他消费方**（grep get_true_out/get_false_out 全仓），它们共享同一错误约定，单独修 condexe 而不改 helper 会把正确消费方改坏 — 建议一次 commit 内完成 helper+全部消费方迁移并各自附 fixture。

### 2.3 错误通道（缺陷 E）

Ghidra 两个 LowlevelError（condexe.cc:261 非法 iblock op、cc:303 dominator 丢失）+ funcdata_block.cc:885 非空块拆流，在 Rugra 均被 `Option::None`/`Result::Err` 吞掉；condexe.rs:745 显式 `let _ =` 丢弃 Err，do_replacement 的 None 路径还会死循环。修复方向：resolve 链改 `Result<Varnode, CondexeError>` 向上传播，`apply` 顶层映射为 Ghidra 的 abort-this-function（与 funcdata.rs:2260-2263 既定 panic 隔离策略一致或 Err 中止均可，但必须**终止**而非继续）。

---

## 3. 分阶段移植方案（最小闭包，每步独立 fixture）

> 验收统一口径：locked 12.0.4 oracle 双侧 IR/CBB 投影 fixture（输入指纹 + op/vn/block 全量投影 diff，见 §5）。每步 write-set 无交集时可并行。

### Phase 0 — CFG 真值地基（最高优先，阻塞一切）
1. **CONDEXE-CFG-0001**：修复/新建 `BlockGraph::remove_from_flow_split`（承载 block.cc:1575-1590），funcdata.rs:2740 改为薄包装（emptyOp 校验 + 调用 + remove_block + structure_reset），修正错误注释（→ funcdata_block.cc:881）。
   - fixture：4 块菱形（init/prea/iblock 含 2MULTIEQUAL/posta 合流）× swap∈{true,false} × flip∈{0,1}，断言拆除后每块的 in/out 邻接 + reverse_index 全等 oracle。
2. **CONDEXE-TRUEOUT-0002**：`get_true_out`/`get_false_out` 纯位置化 + 全部消费方迁移。
   - fixture：同上菱形断言 init2a_true/camethruposta_slot/zero_path_is_true 三个布尔与 oracle 一致。

### Phase 1 — Action 外壳（依赖 Phase 0）
3. **CONDEXE-ACTION-0003**：apply 加 `has_unreachable_blocks` guard（cc:485）；实现 `take_count_delta` 回传 numhits（cc:501）；活列表遍历（每轮重读 get_size，等价 Ghidra 移除后跳位语义）；**管线移位**：action.rs:1065 的 add_action 移到 NodeJoin 之后、ConditionalConst 之前（coreaction.cc:5675）。
   - fixture：含 unreachable 块的函数（Ghidra 侧 apply 前后 IR 不变断言）；count 经 ActionRegistry 统计投影。

### Phase 2 — 数据流重写内核（依赖 Phase 0）
4. **CONDEXE-HERITAGE-0004**：`Funcdata::num_heritage_passes(space)` 修正签名（funcdata.hh:237），实现 `build_heritage_array`（cc:23-37：arch.num_spaces/get_space/is_heritaged + heritage.rs:5072），`test_removability` 接入 `heritageyes[space.getIndex()]`（cc:392）。
   - fixture：unique-space（已 heritage）vs stack-space（delay=1 时 pass-delay≤0）varnode 的放行/拒绝双侧对照。
5. **CONDEXE-PULLBACK-0005**：`pullback_op` 改 `new_varnode_out(size, orig_out.addr)`（cc:182）+ `op_insert_end`（cc:187）。
   - fixture：iblock 内 SUBPIECE 被两侧路径各读一次 → 断言新 op 的块位/序（SeqNum order）/输出地址三投影。
6. **CONDEXE-ERROR-0006**：resolve 链 Result 化，消灭 do_replacement None-死循环路径与 `let _ =` 丢弃（rs:745）。
   - fixture：构造非法 iblock op（如 LOAD）与断链 dominator 两类坏输入，断言双侧同样中止且中止点一致（错误消息投影）。

### Phase 3 — 全函数 oracle 门禁（依赖 0-2）
7. **CONDEXE-FIXTURE-0007**：为 27 函数逐个补 locked-oracle 双侧 fixture（当前全部 MATCH 项均为 UNTESTED）；最小语料 = ① 双 if(a) 串联折叠（cc 文档形态一）② directsplit 形态 ③ posta/postb 合流于 exitblock 的 MULTIEQUAL 下推（getNewMulti 路径）④ RETURN 值流经 iblock（doReplacement COPY 路径）⑤ RuleOrPredicate 双零槽/单零槽两形态。端到端接 `tools/compare_ghidra.py` 差分（curl/httpd 回归，注意 golden 仍为 11.3.2，只作回归信号，ORACLE-0002 前不得当对齐证据）。

**明确不做**：PathMeld 相关任何改动（非依赖）；`verify` 的遍历方向改写（已证等价，fixture 覆盖即可）；`new_varnode_out` 的 space 泛化（Register-only 对 condexe 场景闭合）。

---

## 4. 拟登记 TODO 清单

| ID | 标题 | write-set | 依赖 | 验收 |
|---|---|---|---|---|
| CONDEXE-CFG-0001 | BlockGraph::removeFromFlowSplit 忠实化（swap 序列 + 越界） | src/block.rs（新增方法）、src/funcdata.rs:2728-2787、docs/api/block.md、docs/api/funcdata.md | 无 | 菱形×{swap,flip} CBB 投影 fixture 双侧 MATCH |
| CONDEXE-TRUEOUT-0002 | getTrue/FalseOut 纯位置化 + 消费方迁移 | src/block.rs:453-485、src/condexe.rs:234-251/1108-1117、grep 所得全部消费方、docs/api/block.md | 无（与 0001 并行需分文件租约） | init2a_true/camethruposta_slot/zero_path_is_true 布尔 fixture MATCH |
| CONDEXE-ACTION-0003 | apply guard/count/活列表遍历/管线移位 | src/condexe.rs:1346-1389、src/action.rs:1053-1076 | 0001,0002 | unreachable-guard fixture + ActionRegistry count 投影 |
| CONDEXE-HERITAGE-0004 | buildHeritageArray + per-space numHeritagePasses 接线 | src/funcdata.rs:6958、src/condexe.rs:104-127/357-396、src/heritage.rs（如需 space 枚举）、docs/api/funcdata.md | 无 | stack-delay 拒绝/unique 放行双侧 fixture MATCH |
| CONDEXE-PULLBACK-0005 | pullbackOp storage+插入位置 | src/condexe.rs:450-500 | 0002 | SUBPIECE pullback 三投影（块位/order/addr）fixture MATCH |
| CONDEXE-ERROR-0006 | resolve 链 Result 化 + 死循环消灭 + Err 不丢弃 | src/condexe.rs:546-710/727-746 | 0001 | 非法 op/断链 dominator 中止点 fixture MATCH |
| CONDEXE-FIXTURE-0007 | 27 函数 locked-oracle fixture 补全（UNTESTED→MATCH） | tests/（fixtures 目录）、tools/（如需投影器） | 0001-0006 | ①-⑤ 语料全量 IR/CBB 投影零差异 |

roadmap 联动：#19 行需改写（238行→1555行、删除 PathMeld/forceSpecific 错误归因、登记本报告 ID）；G1（:553）三个函数名应替换为本清单。

## 5. oracle 元数据（所有 fixture 必须携带）

- oracle commit: `e40ed13014025f82488b1f8f7bca566894ac376b`（Ghidra_12.0.4_build）
- 源文件: condexe.cc/condexe.hh/expression.cc/block.cc/funcdata_block.cc/funcdata_op.cc/flow.cc/coreaction.cc/heritage.cc/op.cc
- 架构/compiler spec/analysis options/输入指纹：随每个 fixture 落盘（当前无一满足 → 全部 MATCH 项状态实为 UNTESTED，模块维持 L2，禁止宣称 L3）

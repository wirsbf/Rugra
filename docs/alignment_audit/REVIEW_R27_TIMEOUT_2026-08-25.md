# R27 — Cross-Review: e24e6896 超时修复（selectGoto 不终止 / Heritage O(n²) / main print panic）

- Reviewer: 独立复核 Agent（机制 C），只读主仓
- Oracle: `e40ed13014025f82488b1f8f7bca566894ac376b`（已验证 `ghidra/` HEAD 与锁定 oracle 一致）
- 复核对象: master `e24e6896`（当前 HEAD `92dba7a5`，其间含 `45b56ccb` 管线行为改动，见 §4 时间线）
- 判定: **Cross-Review: APPROVE**（附 5 条非阻塞观察项，均非本 commit write-set 引入）

## 方法声明

独立打开并逐行读取全部必读 Ghidra 源码（不接受实现 Agent 的 Evidence 块自证）：
`block.hh:100-160/336-347`、`block.cc:240-256/295-330/1085-1110`、`varnode.cc:60-79/1218-1228/1255-1400/1900-1935`、
`varnode.hh:47-55/108/169/373`、`funcdata_varnode.cc:330-375`、`op.cc:975-1000`、`op.hh:310`、
`printc.cc:2660-2775/3231-3268`、`comment.cc:330-410`、`comment.hh:195-252`。
Rugra 侧读 `src/{block,varnode,op,printc,comment}.rs` 修复函数全文及调用闭包（blockaction/funcdata/heritage/tracedag）。
未运行 cargo（约束）；差分核实使用只读 `tools/compare_ghidra.py`。

## 1. block.rs downcast 链修复 — 通过

**Ghidra 语义（独立核实）**：`intothis/outofthis` 是 FlowBlock **基类私有成员**（block.hh:127-128），
`setOutEdgeFlag/clearOutEdgeFlag`（block.cc:240-256）是基类非虚方法：写 `outofthis[i].label |= / &= ~lab`
并经 `reverse_index` 写镜像 `intothis` 半边。无循环、无动态派发——**每个子类型共享同一存储**（BlockCopy 经
`class BlockCopy : public BlockGraph` 继承同一份）。

**Rugra 修复核实**：
- trait 新增 `out_edges_mut/in_edges_mut`（无默认体），10 个实现者（BlockBasic/Goto/If/WhileDo/DoWhile/
  InfLoop/List/Condition/Switch/Copy）各路由自身 `outgoing/incoming`——编译强制全覆盖。
- 5 个 mutator（set/clear_out_edge_flag、clear_edge_flags、set/clear_in_edge_flag）+ `set/clear_out_edge_flag_mirrored`
  的 self-edge 分支全部经访问器路由，两半边仍共持同一 write guard。
- 旧链的 `downcast_mut::<BlockGraph>()` 实为**死分支**（BlockGraph 未 `impl FlowBlock`，`dyn Any` downcast 恒
  `None`），旧代码实际只覆盖 BlockBasic——与「goto 标记在结构化块上静默丢失 → TraceDAG 重复提案同一边」的根因陈述一致。
- 消费端核实：`TraceDAG::is_loop_dag_out/in`（tracedag.rs:188/203，对照 block.hh:342/345 四 flag 掩码）读
  out/in 两个半边；`findSpanningTree` 四 label 分支（block.rs:2037-2065）与 Ghidra block.cc:1092-1105 的
  tree / back|loop / forward / cross 逐条对应且全部走 mirrored；Ghidra `setLoopExit`（block.hh:294）仅写 out
  半边，Rugra blockaction.rs:784/796 的非 mirrored 调用与之一致。goto 实际写路径
  `set_goto_branch_on_block → set_out_edge_flag_all_types`（两半写、11 类型宏链，历史补丁，非本次改动）自洽。

## 2. varnode.rs Heritage O(n²) 修复 — 通过

**Ghidra 语义（独立核实）**：
- `VarnodeBank::setInput`（varnode.cc:1358-1369）：前置 throw（not free / constant，文本核对）→
  两树 stored-iterator erase → `vn->setInput()` → `xref`。`setInput()` = `setFlags(input|coverdirty)`
  （varnode.hh:169 逐字核实）。
- `VarnodeBank::destroy`（varnode.cc:1272-1280）：integration 检查（getDef / hasNoDescend）→ 两树
  stored-iter erase。无所有权预检——erase 即所有权证明。
- `Funcdata::setInputVarnode`（funcdata_varnode.cc:341-373）：`beginDef(input, addr+size)` = 
  `lower_bound(searchvn)`，searchvn 恒为 **size 0 的 input varnode**（VarnodeBank 构造逐字注释，varnode.cc:1219-1223）；
  `iter != beginDef()` 时 `--iter` **仅检查紧邻前驱一条**，且仅当前驱 `isInput()` 才做双向 overlap 检查；
  精确 (size,addr) 匹配返回既有，否则 throw "Overlapping input varnodes"。
- `VarnodeCompareDefLoc`（varnode.cc:60-79）：def 分组（`(f-1)` 无符号技巧：input < written < free）→
  written 比 def SeqNum → addr → size → 双 free 比 createIndex。

**Rugra 对应核实**：
- `set_input`（varnode.rs:2968）：前置 Err 文本一致 → `erase_loc_identity/erase_def_identity` 的 residency
  bool（对 Ghidra UB 路径的安全化，合法输入下不可观察）→ `set_flags(INPUT|COVERDIRTY)` 逐位对应 → `xref`。
  与 `transition_input`（prevalidated 入口）主体完全一致，无入口漂移。
- `erase_*_identity`：`take(等键)` → `Arc::ptr_eq` 快路径 O(log n)；键冲突回退 O(n) identity retain。
  Ghidra 的 std::set 在 xref 冲突时走 `replace` 合并、树内无等键共存，故快路径是常规情形；回退仅服务
  「vn 不在树中但同键他者在」的非法输入。语义 = stored-iterator erase。✓
- `set_input_varnode`（varnode.rs:3111）：search 键 `new_with_space(0, vn_space, vn_end) + INPUT` 与
  Ghidra searchvn 构造逐项一致；`def_tree.range(..search).next_back()` = strict-less 最大元素 =
  **lower_bound 的前驱**（两侧等键均被排除，边界语义数学等价）；`is_input` 前置、双向 overlap、精确匹配
  返回既有、部分重叠 WARN 降级（既有登记的故意偏差，非本次引入，commit 如实披露）。
  `VarnodeDefRef::cmp` 与 VarnodeCompareDefLoc 逐条对应（含 `wrapping_sub(1)`；`Arc::ptr_eq` 短路是
  Rust 读锁安全的必要等价）。✓
- 调用路径核实：heritage.rs:4097/4107（rename 推广）正是修复受益点；修复前该路径每次全量 loc_tree 扫描
  （带逐元素读锁），修复后 O(log n) 前驱查询。声明与代码一致。

## 3. printc.rs 窗口重开 — 通过

**Ghidra 协议（独立核实）**：`emitBlockBasic`（printc.cc:2683-2745）每基本块
`setupBlockList(bb)`（start=lower_bound((idx,0,0)), stop=upper_bound((idx,MAX,MAX))，comment.cc:379-390）→
逐打印 op `emitCommentGroup(inst)`（opstop=upper_bound((idx,order,MAX))，comment.cc:362-373）→
块尾 `emitCommentGroup(NULL)`（opstop=stop）。`hasNext = start != opstop`、`getNext = *start++`（comment.hh:250-251）。

**Rugra 修复核实**（emit_block_basic_rpn printc.rs:2549 / emit_block_ops printc.rs:2702）：flattened ops
遍历中，每个 parent-block 边界先 `emit_comment_group(None)`（drain 离开块尾部，cc:2742）再
`setup_block_bounds(new)`（cc:2684），循环尾 drain；首块 `cur_block=None` 不 drain——正确。
- 单块 slice（正常逐块调用）与 Ghidra 序列**逐序一致**；多块混入 slice 模拟同样的逐块 setup/drain 序列。
- panic 消除不变量成立：新鲜窗口内 `start = lower_bound((idx,0,0)) ≤ opstop = upper_bound((idx,order,MAX)) ≤
  stop ≤ commmap.len()`；drain 终态 `start == stop`；边界先 drain 后 setup 重置 start。**不存在
  `start > opstop` 或 rank 越界的路径** → `get_next` 的 `commmap[rank]` 索引安全。二分实现为标准
  `partition_point`（lower/upper_bound 投影正确）。
- op 无 parent 的段不 setup（同旧行为），`setup_op_stop` 的无 parent 守卫使 opstop 不动——无 panic 路径，
  对 Ghidra 解引用 UB 路径的安全化。

## 4. E2E 声明与 result/curl_cur.c 一致性 — 通过（时间线已理清）

- 复核实测（只读工具）：当前 result/curl_cur.c 全量 **defects=0 / numbering=1 / skeleton 2713**；
  GetStr skeleton diff 3 行（`if(*string != (char *)LIT) { free(*string); }` 丢失）；124/124 函数与 golden 匹配。
- **时间线**（commit date）：e24e6896 @12:43:42 → 45b56ccb（src/options.rs 启用 splitcopy/splitpointer
  转发，主管线行为改动）@12:49:31 → result/curl_cur.c mtime **12:57** → 704d1046「true baseline
  established」@12:58:03。即当前 result 是 **45b56ccb 之后**的基线，非 e24e6896 当时文件。
- 704d1046 在 TODO_BOARD 登记了该基线：「真基线 skeleton 2713/0/1；**GetStr 单跑字节一致（组合树 3 行差为
  后续集成效应）**」。numbering=1 与 GetStr 差异均已登记、已归因，不构成 e24e6896 的未解释缺陷。
- 6 个修复函数（GetStr/my_get_line/file2string.part.0/parseconfig.constprop.0/glob_range/main）全部在
  result 中有完整定义输出——「0 timeout 0 panic 首次全函数产出」声明与文件一致。
- 备注：45b56ccb 自身改变 C 输出却无 `## Differential` 块（options.rs 不在机制 B 白名单，门禁未触发）——
  属**该提交**的门禁覆盖缺口，建议后续将主管线行为耦合的 options 改动纳入差分门禁，非 e24e6896 责任。

## 5. GetStr 字节一致声明 — 通过（附限定）

e24e6896 时刻声明「GetStr skeleton IDENTICAL」。当前组合树 3 行差已由账本归因为 45b56ccb 集成效应，
时间线、TODO_BOARD 登记、commit 声明三方一致。本复核受「禁 cargo」约束无法重跑单函数二进制独立复验
单跑字节一致，采信的是三方一致的书面证据链（诚实披露该限定）。

## 判定

三项修复的 Ghidra 决定性语义（引用参数 / 遍历顺序 / 计数器 / 排序键）逐条独立核对全部成立，
未发现 MISMATCH。所有偏差点均为既有债务或安全化适配，不属于 e24e6896 的 write-set。

## Cross-Review: APPROVE

## 非阻塞观察项（建议登记，均非本次引入）

| # | 位置 | 内容 | 风险 |
|---|---|---|---|
| O1 | src/funcdata.rs:2270 `set_goto_branch` | 结构化块分支调非 mirrored `set_out_edge_flag`（仅写 out 半边；Ghidra setGotoBranch 写两半）；越界时不 throw（Ghidra throw）。活路径（funcdata.rs:2252）仅 BlockBasic 可达（`last_op` 只在 BlockBasic 分支返回 Some），结构化分支实际不可达 | 低（代码债，建议改用 mirrored 版本并补越界 Err） |
| O2 | src/block.rs BlockCopy | 空边向量依赖「BlockCopy 永不出现在结构化边写路径」的隐含前提（Rugra 副本节点为 BlockBasic）。前提目前成立（BlockCopy 仅 printc 侧包装） | 低（前提若失效会静默 no-op，建议注释补调用域约束说明——现有注释已部分覆盖） |
| O3 | src/blockaction.rs:1623 | stale comment：仍描述 `set_out_edge_flag_mirrored` 的旧 downcast 行为（本 commit 已 accessor 化） | 极低（注释漂移） |
| O4 | src/varnode.rs `set_def` | 仍保留 O(n) `owns_loc_ref/owns_def_ref` 预检（未随 set_input 同步优化）；另 `VarnodeDefRef::cmp` 的 written 分支只比 `op.start` 而非完整 SeqNum（order 分量丢失，同块同 addr 同 size 双写理论上误判 Equal——既有基础设施，无已观察触发） | 低（性能与理论正确性债，非本次范围） |
| O5 | 45b56ccb（非本 commit） | 主管线行为改动无 `## Differential` 块；机制 B 白名单不含 options.rs，建议扩充白名单或在其 Differential 政策中覆盖「经 allacts 影响输出的模块」 | 中（流程缺口，防未来同类漂移无解释落地） |

## 附：本次差分实测命令与结果（只读）

```
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only
  → skeleton 2713 / defects=0 (0/124) / numbering=1     [45b56ccb 后基线，已登记]
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func GetStr -v
  → skeleton diff 3 行 / defects=0 / numbering=0        [已归因 45b56ccb 组合效应]
```

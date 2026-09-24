# BLOCKACTION-ALIVELIST-GLUE-0001 Lane 报告（wt/alivelist）

日期 2026-09-23。worktree `/dev/shm/rugra-worktrees/alivelist`（wt/alivelist，自
master **6b4ca15a**，基线亲测）。oracle=Ghidra 12.0.4 **e40ed130**（worktree ghidra
HEAD 核对相等）。CARGO_TARGET_DIR=`/dev/shm/rugra-targets/sb-alivelist`。
写域：`src/blockaction.rs` + `docs/api/blockaction.md`（+TODO_BOARD 行）。

## 0. 一句话结论

**旧 glue 的地址连续性代理本身就是在误杀活 op（curl 314 / httpd 646 个 alivelist
条目），"补全 kill 副作用"方向错误且实测破坏打印；修复=检测改为 oracle 语义的
block 作用域（逐 BlockBasic op 列表、首个 BRANCH/RETURN 之后），kill 走完整
`op_uninsert`（markDead+removeOp）。新检测全语料命中 0，alivelist 不变式恢复，
三门禁/双投影/`--func main` 全部与基线恒等。**

## 1. oracle 副作用清单（铁律 1，先读源码）

- `ActionFinalStructure::apply`（blockaction.cc:2186-2197）：五个图调用
  （orderBlocks/finalizePrinting/scopeBreak/markUnstructured/markLabelBumpUp）+
  无条件 `return 0`。**不删任何 op**。
- Ghidra 里 "unconditional BRANCH/RETURN 之后的 op" 不存在：flow 生成期在每个
  分支处切块（BlockBasic op 列表以 terminator 结尾），flow 跟随不下探
  unconditional 分支之后。**alive ⟺ 在块内**（`PcodeOpBank::markAlive`
  op.cc:1017-1023 / `markDead` op.cc:1028-1034）。
- oracle 删 alivelist 条目的唯一正典路径 = `Funcdata::opUninsert`
  （funcdata_op.cc:164-173）：`obank.markDead(op)`（alivelist erase + `dead`
  flag 置位 + deadlist push_back）+ `op->getParent()->removeOp(op)`
  （block.cc:2292-2297：setParent(null) + 块 op 列表 erase）。
  （`opDestroy` 另有 varnode 解链；本 glue 场景 Ghidra 没有对应物，
  opUninsert 语义即"从活列表+块中退役"。）

## 2. 旧 glue 双重缺陷（实验证据）

1. **检测缺陷**：alivelist 是 mark-alive 插入序，非块内地址序；`cur_addr < prev ||
   cur_addr > prev + 32` 的"同块"代理把**地址相邻的下一个块**的活 op 误判为
   同块死代码。census（env 探针，本目录 curl_fix.stderr.log）：curl 误收 314、
   httpd 误收 646，全部 parent_block=Some(...)，含 CPUI_INDIRECT（call 输出定义）
   与 CPUI_COPY。
2. **kill 半途**：只 `alivelist.remove(idx)`，不置 DEAD、不清 block——alivelist
   消费者（printc 后备注解/审计 census）失明。

**关键反证实验**（curl_fix.c，本目录）：若按 Lane DR 原假设只"补全副作用"
（对误杀集做 op_uninsert），main 直接出现 `(Configurable *;` 级 RPN 断裂 +
`unique0x…` 裸名泄漏——证明被杀的是活数据流，检测本身必须重做。

**@0x2669 真相**：main spill 半 `pFStack_240 = __stream;` 在 bb12 内位于
terminator（BRANCH @0x2680）**之前**（main_base.stderr.log dump 4675-4693 行），
是活 op；JUNK_REPORT 的"不在 census"正是旧 glue 误杀产物。其消除属
merge/copyTrims 域（MERGE-COPYNOISE 系，diff-high 家族），非本 lane。

## 3. 修复内容

`src/blockaction.rs` ActionFinalStructure::apply 内 unreachable-op 清理：
- 检测：遍历 `fd.bblocks`（0..get_size），逐块 `get_ops()` 下标序，块内首个
  `CPUI_BRANCH | CPUI_RETURN` 之后的 op 收集为残留（oracle 不变量下不可能存在）；
- kill：`fd.op_uninsert(&op)`（funcdata.rs:4669，funcdata_op.cc:164-173 的忠实
  移植 = `mark_dead` + `block_remove_op`）；
- 收集先行、退役后置（op_uninsert 变异 alivelist/block，不可边迭代边删）。
- `docs/api/blockaction.md` 同步新增 2026-09-23 节。

## 4. main 前后形态

- 打印侧：**逐字节不变**（curl_final.c ≡ curl_fix2.c；基线对比仅 20 行既有
  diff 行的 cast 形态互换 `(int8*)`↔`(int*)`，golden 均为 `(long)`，两侧本就是
  diff 行，skeleton 计数不变；来源=printc 后备注解路径按 alivelist 数 use，
  alivelist 恢复完整后选型变化——方向性正确，残差属 cast/type-inference 域）。
- `RUGRA_DUMP_FUNC=main`：@0x2669/3726515638 基线（误删后）→ 修复后回归 census
  （op 在块内、alive、正常打印）——审计不再失真。

## 5. 三门禁（基线=亲父 6b4ca15a 亲测）

| 门禁 | 基线 6b4ca15a | 修复后 | 判定 |
|---|---|---|---|
| curl 全语料 skeleton/defects/numbering | 2585/0/0 | **2585/0/0** | 恒等 |
| httpd 全语料 skeleton/defects/numbering | 2333/0/0 | **2333/0/0** | 恒等 |
| `--func main` skeleton | 583 | **583** | 恒等 |
| gcc 语法审计（curl） | 82 OK/25 FAIL | **82 OK/25 FAIL** | 恒等 |
| next_url stage 投影 | （pinned MATCH） | base vs fix **字节级一致** | 保持 |
| match_url stage 投影 | （pinned MATCH） | base vs fix **字节级一致** | 保持 |
| `cargo test --lib`（--test-threads=1） | 19 失败（亲父同集） | **19 失败，与基线逐名恒等** | 无新增 |

**commit = `aa9efad7`**（wt/alivelist，3 文件：src/blockaction.rs + docs/api/blockaction.md + docs/TODO_BOARD.md；hooks 全过：annotations/refs/机制A）。机制 C Cross-Review 待 root 派发后方可并入 master。

（stage_bisect.py 当前树内版本解析旧格式与 v1.2.1 投影不兼容，故按近期 lane
惯例做 base-vs-fix 字节级保持验证。）

## 6. 登记/未决

- `BLOCKACTION-ALIVELIST-GLUE-0001`：**交付待复核**（本 commit）；机制 C
  Cross-Review 待 root 派发（blockaction.rs 在核心算法白名单，无
  `## Cross-Review: APPROVE` 不得并入 master）。
- 未决（非本域）：spill/restore 对消除（merge/copyTrims，MERGE-COPYNOISE 系）；
  cast 形态 `(int8*)/(int*)` vs golden `(long)`（type-inference/cast 域）；
  stage_bisect.py 与 v1.2.1 投影格式漂移（工具域，建议登记）。

## 7. 本目录产物

- `curl_base.c`/`httpd_base.c`/`curl_fix.c`（误杀集补全实验，RPN 断裂证据）/
  `curl_fix2.c`/`httpd_fix2.c`/`curl_final.c`/`httpd_final.c`（≡fix2）。
- `main_base.stderr.log`：bb12/@0x2669 块上下文证据（dump 4675-4693 行）。
- `failures_{fix,fix_st,base_st}.txt`：单线程失败集恒等证据（19/19 同名）。
- `commit_msg.txt` + `fix1.py/fix2.py/strip_probe.py/doc_patch.py/todo_patch.py`：
  可复现补丁与提交文本。
- （已回收：*.projection 对拍产物 22MB、probe 期 stderr、源码快照副本。）

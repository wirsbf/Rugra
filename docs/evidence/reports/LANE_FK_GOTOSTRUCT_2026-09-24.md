# Lane FK (gotostruct): PRINTC-GOTOSTRUCT-RESID-0001 根因闭环 — 域勘误移交（诊断性交付）

Worktree: **/dev/shm/rugra-worktrees/gotostruct**（wt/gotostruct，基 master 35f5867e，FE 刚并入）
Oracle: Ghidra 12.0.4 e40ed130；正典 golden = tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c（headless）
实际写域落点: `src/blockaction.rs`（RUGRA-GLUE 探针 only：RUGRA_BS_DUMP=3 stuck1 dump + debug_dump_graph addr 列）+ `docs/api/blockaction.md` + `docs/TODO_BOARD.md`

## ① 结构差根因一句话

**4 个结构族站点不是 Rugra 结构器的决策缺陷——插桩锁定 oracle 证明同输入下 oracle 的 collapseAll 同样 STUCK 并标记同族 goto 边（ap_no2slash: oracle 两标记 #6→#9/#6→#2 与 Rugra SELECTGOTO #6→#8/#6→#2 同位同序）；golden 的干净 while 形态是管线 fixpoint 重工作循环的涌现产物——oracle 每函数多轮重入 ActionBlockStructure（structureReset 触发；ap_no2slash 6 轮），重工作由 ActionDoNothing×5/ActionNodeJoin×3（ap_fini_vhost_config: DoNothing×10+NodeJoin×7+ReturnSplit×2；ap_pregsub: DoNothing×5+NodeJoin×2+ReturnSplit×2）驱动，直到 CFG 形状可直接 WhileDo/IfElse 零 goto 标记；Rugra 动作树同槽位但重工作不等价触发（ap_no2slash 1 轮 vs 6、ap_parse_vhost_addrs 1 vs 6），终态树停留 oracle 中间态（goto 包裹 latch）。第 5 站点（0x104c5e 拼写族）= headless Java 分析器符号（DecompilerSwitchAnalysisCmd.java:322/350 `switchD_<dispatch>` 命名空间 + `caseD_<hex>`/`default`，经 queryCodeLabel 命中 emitLabel），direct-runner golden 同位印 `code_r0x00004c5e`——非 printc 缺口。**

## ② 方法（可复现）

自建插桩 oracle：`tools/regen_ghidra_golden.py` 的 golden_dump_1204 harness（BfdArchitecture+锁定 sleigh_specs，BFD 2.38）+ 锁定 commit git-archive 的 blockaction.cc/funcdata_block.cc 补丁（BSTRACE/BSTRACE_FUNC/BSTRACE_RESET env 门控：entry 图 dump/规则命中/goto 标记/structureReset caller/终态树递归 dump 含 gotoPrints）。全部材料在 `/dev/shm/rugra-tests/sb-gotostruct/oracle/`（patch_bstrace.py / patch_bsreset.py / *_trace.stderr / *_oracle.json），二进制 golden_dump_nopie（caller addr2line 用）。

关键实证链：
1. **ap_no2slash（9 块小函数，输入两侧一致——direct-runner golden 与 headless golden 同形零 goto）**：oracle 轮 1 规则序列 DoWhile#7→Cat#6→STUCK(8)→GOTOMARK #6→#9→GOTO 包裹→GOTOMARK #6→#2→GOTO 包裹→…收敛；与 Rugra 单轮完全同构。
2. **oracle 6 轮重入**（entry nblocks 10→8→9→10→7→8），末两轮 7/8 块图直接 `WhileDo#1` 零 STUCK 零标记——FINALTREE=干净 List[Copy,WhileDo[Copy,If[Copy,List[Copy,WhileDo[Copy,Copy]],Copy]],Copy]。
3. **reset caller 统计**（addr2line）：DoNothing(removeDoNothingBlock)/nodeJoinCreateBlock/nodeSplit(ReturnSplit)/ActionRedundBranch/ActionDeterminedBranch/removeUnreachableBlocks——全在 coreaction 域。首个具体缺口例：oracle DoNothing 删 ap_no2slash 0x2e86b 前导块（其两条 COPY 上游已被判死→hasOnlyMarkers 通过）；Rugra 侧拷贝未死→不删→无 reset→单轮。
4. glob_set 输入两侧不同（Rugra 19 块 5-case switch vs harness 35 块含 0x4f43 ctype 越界吸收）——该站点对比以 headless golden 为准，机制同族。

## ③ 前后数字（基线=亲父 35f5867e 亲测）

| 门禁 | 基线 | 交付 | Δ |
|---|---|---|---|
| curl (124 fn) | 2152/0/0 | **2152/0/0** | 0（输出字节恒等） |
| httpd (29 fn) | 2225/0/0 | **2225/0/0** | 0（输出字节恒等） |
| 三投影 (RUGRA_MIRROR=1) | MATCH×3 | **MATCH×3** | next_url(335/96457)/match_url(340/80385)/parseconfig.constprop.0(335/130099) vs sb-ord191/sb-parseconfig 钉板 |

- 逐函数零回退（diff -q curl/httpd 双 IDENTICAL——探针 env 未设时零行为变化，构造性保证）。
- cargo test --lib：1677 passed/18 failed——失败集=预存 flaky 家族（funcdata alignment/ssa 16+heritage 1，与 FE 记录同树摆动形态）；blockaction 域 9/9 全绿。
- 结构修复本体移交：`ACTION-REWORKFIX-STRUCT-0001`（P2，coreaction 域，四站点+标号地址错配同族）+ `DRIVER-SWITCHD-LABEL-0001`（P3，driver 符号层，switchD_caseD 拼写族），TODO_BOARD 已登记含修复方向/验收标准/证据指针。

## ④ 机制声明

- **机制 B**（blockaction.rs 白名单）：差分门禁 defects=0/numbering=0（双语料输出与基线字节恒等）。
- **机制 C**（blockaction=核心算法白名单）：本 commit 仅 RUGRA-GLUE env 门控探针（debug-only，无算法/行为改动），未附 Cross-Review 块；按字面规则 blockaction commit 需独立复核，请求 root 集成时快速复核（改动面：debug_dump_graph 重排+addr 列、collapse_all_5step 一处 env 判断）。
- **机制 A**：commit message 不含触发词，无 Evidence 块（无对齐性改动）。

## ⑤ 回收

- 证据保留 `/dev/shm/rugra-tests/sb-gotostruct/`（oracle/ 插桩树+patch 脚本+traces、curl/httpd base+final 双门禁日志、三投影 m_*.projection+bisect、stuck/bstrace stderr、repro.sh/run_projections.sh）。
- `result/curl_cur.c` + `result/httpd_cur.c` 已回流（gitignored）。
- `/dev/shm/rugra-targets/sb-gotostruct`（CARGO_TARGET_DIR）保留至 root 集成合并后回收。
- oracle/locked-cpp 构建树（~100MB，含 libdecomp.a）保留至 root 集成（ACTION-REWORKFIX-STRUCT-0001 认领者可直接复用 golden_dump_nopie 复现 traces；若需回收，patch 脚本+harness 可全量重建）。

## ⑥ 复核请求

blockaction.rs=机制 B 白名单已过（0/0）。机制 C：debug-only 探针无算法改动，root 快速复核即可。**核心移交物=根因证据链**（插桩 oracle traces），ACTION-REWORKFIX-STRUCT-0001 认领者应直接以 `BSTRACE=1 BSTRACE_FUNC=<fn> ./golden_dump_nopie one sleigh_specs examples/<bin> <idx> out.json` 复现 oracle 侧决策序列，与 Rugra `RUGRA_BS_TRACE=1/RUGRA_TRACE_SELECTGOTO=1` 逐轮对照。

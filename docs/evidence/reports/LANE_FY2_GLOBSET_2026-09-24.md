# Lane FY2 (globset): ACTION-REWORKFIX-STRUCT-0001 移交项① — glob_set 终态树差收口

Worktree: **/dev/shm/rugra-worktrees/globset**（wt/globset，基 master 9458a61b，ghidra symlink 已建）
Oracle: Ghidra 12.0.4 e40ed130；正典 golden = tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c
写域: `src/blockaction.rs` + `docs/api/blockaction.md` + `docs/TODO_BOARD.md`（机制 B+C 白名单——复核请求见 ⑤）
**Commit: f9110317**（机制 A Evidence 4/4 勾选 + Differential 块 + 机制 C 复核请求均在 message）

## ① 树分歧定因（一句话）

**FK oracle harness 缺 noreturn 建模是"输入不可比"的成因（控制台模式 `call exit@plt` 落穿进 glob_range，glob_set 假输入 35 块）；用 setNoReturn 补丁重建 golden_dump_nr（链接 FK 同一插桩 libdecomp.a）后 oracle 三轮 19/19/18 与 Rugra 逐块可比——FO 观察的"双 latch / BlockSwitch case→BlockIf / switch exit=4c52"全部为假输入伪影。真根因 = 两个 Ghidra 机制缺失：(A) `ruleCaseFallthru`（blockaction.cc:1729-1762，作用于 pre-formation dispatch：fallthru case 的 out(0) 标 goto → 后续 Goto 包裹移除边 → 共享目标 sizeIn 降 1 → switch 以全 5 case 成形、exit=循环头）在 Rugra 是自创批处理 `collapse_case_fallthru`（只扫已成形 BlockSwitch，卡住图上永不点火）→ selectGoto 剥 switch 真 case 边 → 尾块出循环；(B) `try_rule_switch` 的 `case_consumed` 漏 `default_case` → dispatch→default 边外挂 → switch 假双出边 → InfLoop（需单一自落入）不匹配 → 多包一层 DoWhile。**

## ② 修复（commit f9110317，三件套）

1. `try_rule_case_fallthru(i)`（src/blockaction.rs:5974）：1:1 移植 cc:1729-1762——per-block、扫描中 `nonfallthru>1` 即时早退、`getOutRevIndex(0)` 反查共享目标另一入边 == switch 自身的恒等判定、逐候选 `set_goto_branch_on_block(curbl, 0)` 只标边不建结构。
2. `collapse_internal` 第二趟（cc:1838-1848）：改 per-block 交错扫描（先 ifnoexit 再 casefallthru，首个命中 break）——原实现"全图 ifnoexit + 批处理 fallthru"重排了 oracle 决策序。
3. `case_consumed` 追加 `default_case` 索引（cc:1714-1720 的 -cs- 向量含 default，identifyInternal 消费它；出边经既有 `dedup_edges_all_types` 收敛，对齐 selfIdentify→dedup block.cc:930）。

## ③ glob_set 前后（终轮 mark→rule 序列双侧逐事件一致）

- 修复前终态：`goto LAB_00104c20` 回边 + `code_r0x00104c7c` 尾块出循环、switch 4 case（R 边被 multigoto peeled）、finalize 18→2 残块。
- 修复后终态：mark 序列 = 4d30→4d0e / cat3 / 4d24→4d0e / cat13 / List3.out1→R / 4c48.out1→4d04 / List3.out0→4c5e / head.out1→4c5e / **casefallthru 标 4c48-region→4c5e** / goto#12 / **switch 5 cases exit=head(#1)** / cat#1 / **InfLoop#1** / cat#0 —— 与修正版 oracle trace 逐事件一致；finalize 18→1 全塌缩（oracle FINALTREE nblocks=1 同形）。
- 输出：`do { if-chain; switch { ['[','{'-err, '\\', ']' , default:LAB_4c5e=latch 体, '}':code_r0x4c7c=tail 体 } } while(true)` 与 golden 同构；残差 = LAB_/code_r vs switchD_caseD 标签拼写（DRIVER-SWITCHD-LABEL-0001 域，headless Java 符号层，非本域）。

## ④ 三门禁 + 三投影 + 逐函数（基线 = 亲父 9458a61b 亲测，本 worktree 同 profile 重跑）

| 门禁 | 基线 | 交付 | Δ |
|---|---|---|---|
| curl (124 fn) | 2145/0/0 | **2130/0/0** | −15（getparameter 532→520 + glob_set 71→68，均 golden-closer、defects/numbering 双 0；全 corpus 仅此 2 函数变化——getparameter 为同根因第二站点：假 `if switch(...)` 13 行渲染消除 + case 出口 goto→break） |
| httpd (29 fn) | 2057/0/0 | **2057/0/0** | diff -q **字节恒等**，零移动 |
| 三投影 (RUGRA_MIRROR=1) | — | next_url(335/96457) **MATCH** + match_url(340/80385) **MATCH**；parseconfig 对 sb-oracle pin 首散点 **opline 367 零移动**（对 FO 交付态首实质差 = stage209 oppool1 CROSSBUILD→INT_ADD，getparameter 结构修复的下游重派生，stage186 指纹不动） | 零回退 |

- cargo test --lib：18 failed == 亲父 19 的真子集（funcdata flaky 族名单 diff 只少 1，零新增）。
- gcc 审计：82 OK / 25 FAIL == 基线。
- 机制 B：blockaction.rs 白名单，差分 defects=0/numbering=0（Differential 块已入 commit）。

## ⑤ 机制声明 + 复核请求

- **机制 A**：commit f9110317 含 `## Alignment Evidence` 块（ruleCaseFallthru cc:1729 逐字签名 + collapseInternal 第二趟 cc:1838-1848 + newBlockSwitch cc:1714-1721/cc:1904-1919 三段摘录，四类语义 4/4 勾选，check_alignment_evidence.py 通过）。
- **机制 C 复核请求**：blockaction.rs = 核心算法白名单。改动面：try_rule_case_fallthru 新函数（~90 行，1:1 移植）+ collapse_internal 第二趟扫描重排（~20 行）+ try_rule_switch case_consumed 追加 default（~10 行）。**请求 root 集成时独立 cross-review**（reviewer 自读 blockaction.cc:1729-1762/1838-1848，重点核对：①nonfallthru>1 的扫描中早退时机；②getOutRevIndex(0)→target.getIn(1-inslot) 的恒等判定；③第二趟 per-block 交错的 break 时机；④default 消费后的 dedup 收敛）。

## ⑥ oracle 侧新证据资产（重启即丢，结论已录 TODO/docs）

- `/dev/shm/rugra-tests/sb-globset/golden_dump_nr{,.cc}`：noreturn 修正版 harness（setNoReturn 于 exit/_exit/_Exit/abort/__stack_chk_fail/__assert_fail，经 queryCall→copyFlowEffects→checkForFlowModification flow.cc:641-647 截断）。**教训**：任何含 exit() 的函数用 FK 原 harness 做 trace 对照都会吞并后续函数——后续 lane 复用请带 NR 补丁。
- `glob_set_nr.trace`：修正版 oracle 三轮全 trace（19/19/18 块 + mark/rule/FINALTREE）。
- Rugra 侧：curl_trace/curl_dump2（基线）、curl_fix2_trace/curl_fix_dump2（修复后）、双 httpd、三投影、failure 名单。

## ⑦ 残余移交（TODO_BOARD ACTION-REWORKFIX 行已更新）

1. ap_pregsub LAB_0012e414 vs LAB_0012e410（0x2e410 块 var 级 dead-code 域）——FO 移交项②，不变。
2. curl glob_set switchD_caseD 拼写族 —— DRIVER-SWITCHD-LABEL-0001（driver 符号层），不变；glob_set 残余 skeleton 68 行全部归此项 + 表达式形差。
3. ACTION-REWORKFIX-STRUCT-0001 的 glob_set 站点关闭；其余站点是否仍开按 TODO 重新评估。

## ⑧ 回收

- `/dev/shm/rugra-worktrees/globset-base`（亲父基线对照 worktree）+ `/dev/shm/rugra-targets/sb-globset-base`：已回收。
- `/dev/shm/rugra-targets/sb-globset`（本 lane CARGO_TARGET_DIR）：保留至 root 集成合并后回收。
- `result/curl_cur.c` + `result/httpd_cur.c` 已回流（gitignored）；工作区 clean（HEAD=f9110317）。

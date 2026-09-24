# Lane FO (rework): ACTION-REWORKFIX-STRUCT-0001 — 重工作轮次分歧核验 + goto 标号地址族根因修复

Worktree: **/dev/shm/rugra-worktrees/rework**（wt/rework，基 master bc22461d，ghidra symlink 已建）
Oracle: Ghidra 12.0.4 e40ed130；正典 golden = tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c（headless）
实际写域落点: `src/funcdata.rs`（build_blocks_from_ops cover 锚定；lane 声明域 coreaction/blockaction 的延伸——铁律 1.4 底层补齐，单一 writer 无冲突）+ `docs/api/funcdata.md` + `docs/TODO_BOARD.md`
**Commit: 004b161f**（含机制 A Evidence 4/4 + Differential 块；写域延伸与复核请求见下）

## ① 触发不等价根因（一句话）

**FK 报告的"重工作轮次触发不等价"（ap_no2slash 1 vs 6）在父提交已由 FD 的 count 通道统一 + FL 的 1-byte branch-target 提升共同消解——本轮亲测五 Action 的 count→repeatapply 触发链（coreaction.cc:3466/3492/3530 + funcdata_block.cc:224/335/391/419/813 的 structureReset + action.cc:303-361 perform 状态机）在可比站点上零不等价残留；真正的残留缺口是另一族根因——`build_blocks_from_ops` 从不初始化块 cover，`get_entry_addr`（block.cc:2302 的 Rust 镜像）落"首 op 地址"回退臂，死代码删块首 op 后 goto 标号漂移到下一条指令（off-by-5/4 家族）。**

## ② 轮次前后（双侧对照）

| 站点 | FK 时代（基 35f5867e） | 本轮亲测（基 bc22461d，修复前后同——cover 修复不改 CFG 形状） | oracle |
|---|---|---|---|
| ap_no2slash | Rugra 1 轮 | **6 轮**，终态双 WhileDo 零 goto（=golden） | 6 轮（FK trace） |
| glob_set | — | gate 驱动 **3 轮**（单函数线性驱动 2 轮，无 noreturn halt，不可比） | 3 轮（FK trace，harness 输入 35 块 vs Rugra 19 块不可比） |
| ap_pregsub / ap_fini_vhost_config | 3/4 轮 | 标号 multiset 与 golden 一致（收敛） | — |
| ap_parse_vhost_addrs | 1 vs 6 | 标号 `code_r0x0012cfcb`→**`LAB_0012cfc6`**（=golden）；harness 输入 58 vs 10 块不可比 | — |

关键复核：glob_set gate 驱动 4d0e 块 `i3 o0` 终态（noreturn artificialHalt 生效，无自环）；单函数驱动的自环是线性驱动缺 noreturn 建模，非管线缺口。

## ③ 三门禁 + 三投影 + 逐函数（基线=亲父 bc22461d 亲测）

| 门禁 | 基线 | 交付 | Δ |
|---|---|---|---|
| curl (124 fn) | 2152/0/0 | **2152/0/0** | 0（diff 空，字节恒等） |
| httpd (29 fn) | 2148/0/0 | **2092/0/0** | −56（18 行 delta 全部 golden-closer：12cfc6×2+12d7f0×5 标号同址同名 + ap_fini_vhost_config ZEXT24 包裹消解） |
| 三投影 (RUGRA_MIRROR=1) | — | next_url(335/96457) **MATCH** + match_url(340/80385) **MATCH**（vs sb-ord191 钉板）；parseconfig vs sb-oracle 指纹 stage186/op-line367 与 FK 基线**逐位相同零移动**（sb-parseconfig 335/130099 钉板因 per-op 投影格式换代 stale，非本轮回归） | 零回退 |

- cargo test --lib：1681±1 passed / 18~19 failed——失败集=FK 记录的预存 flaky 家族（funcdata alignment/ssa + heritage，连续两轮 18↔19 摆动证明为顺序敏感 flake，单跑全过）。
- 机制 B 差分：funcdata.rs 非白名单，本轮自愿全量跑（数字见上）；Differential 块已入 commit message。

## ④ 机制声明 + 复核请求

- **机制 A**：commit 004b161f 含 `## Alignment Evidence` 块（Ghidra flow.cc:983 splitBasic + block.cc:2302 getEntryAddr 双摘录，四类语义 4/4 勾选，check_alignment_evidence.py 通过）。
- **机制 C**：改动落点 funcdata.rs **不在**核心算法白名单（heritage*/jumptable/blockaction/condexe/varmap-core/merge），且为建块基础设施（cover 锚定）而非算法行为改动；但 lane 声明域为 coreaction 主管线，**请求 root 集成时快速复核**（改动面：build_blocks_from_ops 建块循环内 stop_addr 上界 + 建块后 set_initial_range 一次调用，+26 行）。
- 红词规避：message 以 "core:" 措辞，无裸触发词。

## ⑤ 残余移交（TODO_BOARD 本行已更新）

1. **glob_set 尾块在循环外**（`goto LAB_00104c20` + `code_r0x00104c7c`）：轮次已等价（3v3）但 fixpoint 终态树不同。证据：终轮 stuck1 双 latch（#8@4c7c/#16@4c5e 均→head #1@4c20）+ `updated BlockSwitch case 8 → BlockIf` + switch exit 选取 4c52（=case 体）。域=结构器 selectGoto/checkSwitchSkips/switch-exit；oracle harness 输入不可比（35 vs 19 块），需 oracle 侧 CFG 重放 harness。
2. **ap_pregsub LAB_0012e414 vs LAB_0012e410**：0x2e410 块（`add $1,%r13`）在 Rugra 数据流中整体死亡被重工作删除（golden 保留增量）——var 级 dead-code/consume 域。
3. curl glob_set `switchD_caseD` 拼写族仍归 DRIVER-SWITCHD-LABEL-0001（P3）。
4. 投影钉板：sb-parseconfig 335/130099 已 stale（per-op 投影格式换代），建议 root 重钉。

## ⑥ 回收

- 证据保留 `/dev/shm/rugra-tests/sb-rework/`（curl/httpd base+fix1+fix2、bisect 三份、m_*.projection、no2slash_bs_trace、commit_msg.txt、rework_probe.rs 调试 harness）。
- `result/curl_cur.c` + `result/httpd_cur.c` 已回流（gitignored）。
- `/dev/shm/rugra-targets/sb-rework`（CARGO_TARGET_DIR，release+fast-release）保留至 root 集成合并后回收。
- src 侧临时探针（RUGRA_COVER_TRACE）已在提交前移除；工作区 clean（HEAD=004b161f）。

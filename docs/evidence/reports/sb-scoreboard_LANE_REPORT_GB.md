# LANE REPORT GB — 两级"完整对齐"记分板快照（SCOREBOARD-GB-0001）

- **Branch**: `wt/scoreboard`, base = master `5727faea`, head = **dfec7b76** `docs: two-tier parity scoreboard snapshot at master 5727faea (GB lane)`
- **Owner**: sb-scoreboard (fixer-GB)。只读分析,零 `src/` 改动。
- **交付**: `docs/alignment_docs/ALIGNMENT_SCOREBOARD_2026-09-24.md` + `docs/TODO_BOARD.md` 一行（SCOREBOARD-GB-0001）。

## 数字摘要（两级）

| 层级 | curl | httpd |
|---|---|---|
| L1 gate（skeleton diff=0） | **51**/124（真代码 1=GetStr；ELF glue 4；导入桩 46） | 0/29（全量 1/470=ap_update_mtime） |
| L1 strict（body 逐字节） | 4/124（全为桩） | 0 |
| L2 投影 MATCH | **next_url 335/96457、match_url 340/80385、parseconfig 335/130099（×3 MATCH）**；getparameter ord186 / myprogress ord399 / main ord5 | main ord83（294 stages/878973 ops，Δ+1350） |

基线复核：curl 2135/0/0 == 预期；httpd 2057/0/0 == 预期；httpd 全量 38672/1/0 == FX；双跑恒等；
resid 判类自校验 sum(n_mc) 精确复现门禁总数。趋势（wave 3718/3576 → 2135/2057）：curl −42.6%、httpd −42.5%。

## top-3 观察

1. **httpd 真 L1 = 0 是最大记分板空白**（最小残差 ap_pregfree 2 行；4 行档 3 个）——单 wave 破零成本低。
2. **getparameter 序数新前沿 186 未登记**（oppool2 栈偏移常量 `c:4e8 vs c:4f0`、CROSSBUILD `fb10 vs fb18`），155→186 建议登记新 TODO 派车道。
3. **投影 MATCH ≠ 文本 MATCH**：三个 MATCH 投影函数文本层仍有 49-92 行残差（ZSEXT/RAWSTACK/DAT_LAB 族），两级互补。

## 验证链（复现）

- `/dev/shm/rugra-tests/sb-scoreboard/run_gates.sh`（三门禁+双跑+7 投影）+ `run_projections.sh`（stage_bisect 对拍）
- oracle 投影 4 pin sha256 复核全 MATCH（next_url 默认 pin + curl/main + getparameter + httpd/main）
- 产物：`gates/`（compare/byteexact/bisect/resid summary+detail/skeleton_identical/top_family_attribution）
- 脚本：`byte_exact_scan.py`（L1 严格字节扫描器）、`resid_decomp_gb.py`（FP 判类法路径适配）

## 回收

- `/dev/shm/rugra-targets/sb-scoreboard`（release 全量,~10G 级）已删除。
- 巨型投影中间产物（getparameter 74M / curl main 190M / httpd main 67M rugra 侧投影）已删除,保留 bisect 结论 + 小件证据。
- worktree `/dev/shm/rugra-worktrees/scoreboard` 保留待 root 集成 merge（分支 wt/scoreboard）。

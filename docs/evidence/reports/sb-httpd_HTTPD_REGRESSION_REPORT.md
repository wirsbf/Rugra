# HTTPD Regression Report — Lane I (root 收尾)

- Date: 2026-09-21
- Method: git bisect in worktree `/home/ls/Rugra-wt-sb-httpd` (branch reset clean)
- Signal: `httpd_decompile` stdout vs `tests/golden/ghidra_httpd_1204.c` via `compare_ghidra.py --summary-only`, skeleton total; good ≤2500, bad ≥3000
- Baselines: W4 (70f4449) = **2344**/0/0 (sha 429433e7…); HEAD (0acde30) = **3576**/0/0 (sha 6535cbdc…)

## Bisect verdict

**First bad commit: `79bb0f61c720` — "align: CALLSPEC-DRIVER-0001 flow-time callspec anchoring on the inject path"** (2026-09-01, touches src/flow.rs, src/funcdata.rs 等 4 files, +63/-1)

| commit | subject (abbr) | httpd skeleton | verdict |
|---|---|---:|---|
| 70f4449 | W4 merge_trim_lane fixture (good anchor) | 2344 | good |
| c21f7fd | x86_lift rol/ror flags | 2344 | good |
| 2589853 | docs codegen-divergence | 2344 | good |
| 0f8fc1b (parent of bad) | FUNCDATA-SCOPELOCALOVERFLOW fixture gate | **2344** | **good** |
| 79bb0f6 | CALLSPEC-DRIVER-0001 inject-path anchoring | **3576** | **BAD** |
| 0acde30 | HEAD | 3576 | bad |

线性序: 0f8fc1b 是 79bb0f6 唯一父提交,bisect 判定无歧义。curl 同期 3718→3711(-7) 未受损,httpd 独受影响。

## Function-level regression profile (0f8fc1b → 79bb0f6, top movers)

main 653→1180 (+527) / ap_fini_vhost_config 258→625 (+367) / ap_pregsub 222→345 (+123) /
ap_update_vhost_from_headers 221→319 (+98) / ap_getword 44→56 / ap_parse_vhost_addrs 50→63 /
ap_strcmp_match 60→77 / ap_matches_request_vhost 24→46 / ap_make_dirstr_parent 22→27 /
ap_strcasecmp_match 92→103 / ap_ht_time 84→94 / ap_field_noparam 31→37 /
ap_vhost_iterate_given_conn 36→43 / ap_pregcomp 15→17 / ap_strcasestr 57→60 —
+1232 分布在 20+ 函数,与"每个 CALL op 都新建 FuncCallSpecs"的全局性改动形态一致。

## Commit intent (from message)

`Funcdata::inject_raw_ops`(线性扫描驱动路径:httpd main、prototype workers)生成的 CPUI_CALL
带静态 has_callspec flag 但没有 FuncCallSpecs 对象。该 commit 把 `FlowInfo::setupCallSpecs`
(flow.cc:683-686) 的核心移植到该边界:per CALL op new FuncCallSpecs(op)
(fspec.cc:4931-4938 目标捕获) + opSetInput…

## Next

Lane N(根因): 对照 Ghidra flow.cc/fspec.cc 原文核对该移植的边界条件/时序/去重语义,
找出 httpd 侧 +1232 的语义分歧点(curl 为何不受影响也要解释),先根因后修复。

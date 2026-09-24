# Lane DQ 终报 — GETPARAM-OPPOOL-COUNT-0001 (wt/wt-ord65)

- worktree: /dev/shm/rugra-worktrees/wt-ord65, branch wt/wt-ord65
- commits: **0b996bed** (fix) + de95c192 (board hash fill); base = master 94f3bf58
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f82488b1f8f7bca566894ac376b (projection pin sha256 92c66176… 复跑验证通过)
- 日期: 2026-09-23

## 根因(一句话)

rugra `LoadGuard::establish_range/finalize_range/analyze_new_load_guards` 是
TODO(value-set-analysis) stub(守卫恒为全栈 `[0,highest]`,而 rangeutil.rs 早已移植了
ValueSetSolver),使 `RuleIndirectCollapse` 的 store-guard 臂
(ruleaction.cc:3203-3218)`isGuarded(stack:fa70/fad0)` 恒 true→return 0,
oppool1 run[1] 少 3×indirectcollapse+2×multicollapse;次级残差 = 求解器对全部
guard sink 返回 empty range→load 守卫过宽→`handle_new_load_copies` 对 stack:fc40
误设 ADDRFORCE→`RulePropagateCopy` cc:3948 marker 守卫拒 op 0x3f52:1a6e(-2)。

## 分解(drill 窗口 + 双侧探针)

- run[1](proj ord 65)块差 740 vs 734:earlyremoval-1 / indirectcollapse-2 /
  multicollapse-2 / propagatecopy-1。
- oracle 探针(archive 树 stderr, INDCOL/PROPCOPY/AFWALK/HNLC):
  - STORE 0x3f52:52 守卫 = `[fb08,ffffffffffffffff] step=8 state≤1`,
    `guarded(stack:fa70/fad0)=0` → collapse。
  - load 守卫收敛 `[fb08..ffa7]` 等 state=2 → force COPY@3f3f:2a out=stack:fc40
    `inRanges=0` → 不设 ADDRFORCE → propagatecopy 触发。
- rugra 探针(修复前):store 守卫 `[0,ffffffffffffffff] state=1` → 全部
  `guarded_out=true` → 不 collapse;修复后 store 守卫与 oracle 逐字段一致
  (step 8vs0 不入 isGuarded)。

## 修复(全部 heritage.rs;ruleaction.rs 证伪——移植本身忠实,零改动)

1. `LoadGuard::establish_range(&ValueSetRead)` 全量移植 heritage.cc:740-785
   (含 uintb 回绕 clamp)。
2. `LoadGuard::finalize_range(&ValueSetRead)` 全量移植 heritage.cc:787-813。
3. `Heritage::analyze_new_load_guards(fd)` 全量移植 heritage.cc:834-900:
   接 rangeutil.rs ValueSetSolver(establish+WidenerNone;任一 state==0→
   WidenerFull+finalize)。
4. `find_address_forces` 补 cc:637 `vn->isAddrForce() continue` 停走守卫
   (此前只有注释没有检查)。

## 门禁数字

| 门禁 | 数字 | 基线 | 判定 |
|---|---|---|---|
| getparameter Phase 2 | ord 65 count **734→738**(oracle 740;残差 -2 已登记) | 734 | 改善 4/6 |
| curl E2E compare | **2665/0/0** | 2665/0/0 | PASS 恒等 |
| httpd E2E compare | **2331/0/0** | 2331/0/0 | PASS 恒等 |
| next_url Phase 2 | **MATCH** | MATCH | PASS 保持 |
| match_url Phase 2 | **MATCH** | MATCH | PASS 保持 |
| getparameter golden | 748 skeleton / 0 defects / 0 numbering | 748/0/0 | PASS 不变 |
| heritage:: lib tests | 12 pass, 1 fail(test_heritage_creation delay 模型) | master 主仓同败 | 预存,无关 |

## 未决(移交 root)

1. **RANGEUTIL-VSEMPTY-0001**(新排队): 求解器对全部 guard sink 返回
   empty range(系统未填充/迭代不传播;约束机制 stub 之外连基础路径都没跑通)。
   修复后 ord 65 预期后移。证据=本目录 gp.rugra.vs_drill.stderr(VSProbe 行) vs
   gp.oracle.hnlc.stderr(HNLC-DBG)。
2. 机制 C Cross-Review: PENDING(heritage 白名单域,commit 0b996bed 带
   ## Alignment Evidence 4/4)。
3. B2 正式 tests/oracle fixture 按 RAM 盘约定留 root 集成挑拣。
4. `test_heritage_creation` 的 stack delay=2 断言在主仓 521a99b8 同败,master 既有。

## 产物清单(本目录,重启即丢)

- drill_window.py / oppool_passes.py / run1_div.py / run1_norm_div.py / run1_heads_div.py — drill 分解
- gp.oracle.projection(pin 复跑)/ gp.rugra.master.projection / gp.rugra.fix2.projection / gp.rugra.final.projection
- gp.rugra.master.drill / gp.rugra.fix.drill — 修复前后 drill
- probe/ — oracle 插桩树 + build_indcol_probe.sh(INDCOL/PROPCOPY/AFWALK/HNLC 探针)
- gp.oracle.probe*.stderr / gp.rugra.*_drill.stderr — 双侧决策 trace
- curl_fix.log / httpd_fix.log / curl_final.log — E2E

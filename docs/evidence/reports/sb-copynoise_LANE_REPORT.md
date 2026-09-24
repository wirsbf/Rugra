# MERGE-COPYNOISE-DIFFHIGH-0001 lane 证据包(wt/sb-copynoise,自 master cfd6b40a)

日期:2026-09-22。oracle:Ghidra 12.0.4 e40ed130(worktree ghidra symlink HEAD 核对相等)。

## 1. 判决翻转:登记嫌疑根因被证伪

- `propagate_cover_through_cfg`(successor [0,MAX] 填充)在判决基线 77e97b4 就已是
  `#[allow(dead_code)]` 禁用态(git show 77e97b4:src/merge.rs 4515 行 NOTE 在案)。
- `Merge::merge_all` 全仓调用点仅 3 处,全在 `#[cfg(test)]`(merge.rs:4705/4763/4875);
  生产管线(coreaction.rs)走逐 Action 细粒度路径(ActionMergeRequired/MergeCopy/...),
  与 oracle coreaction.cc:5718-5729 同构。⇒ `compute_varnode_covers` 生产零调用。
- 生产 cover 来源=惰性链:calc_cover(funcdata.rs:4947/4977,= funcdata_varnode.cc:40/53)
  → COVERDIRTY → update_cover_locked(varnode.rs:1037 = varnode.cc:233)
  → Cover::rebuild_from_root_snapshot(cover.rs = cover.cc:477-496 前驱回填,忠实)。
- E2E 佐证:修复前后 curl/httpd 输出 byte-identical(cmp 通过)。

## 2. 真根因探针(RUGRA_DBG_COPYMERGE,探针已从提交版移除)

方法:merge_opcode 记 [COPYSEE](op ptr,b1/b2,失败原因 r1/r2)+[COPYMERGE](候选对),
mark_internal_copies 记 [COPYMARK](幸存 diff-high 对);op/varnode ptr 配对。
数据:probe2/probe3/probe4.log(本目录)。

| 观测 | 数值 |
|---|---|
| merge_opcode 候选对(diff-high) | 3785 对(3477 req+inter 双过) |
| CopyMarker 幸存 diff-high | 1969 对 |
| 幸存 op 曾被 merge_opcode 看到 | 1955/1958(仅 3 个后生) |
| 幸存 op basic 失败原因(out/in) | ok/implied 775;implied/ok 573;ok/nocov 140;implied/nocov 152;implied/implied 31;pp/ok 2 |
| **涉 implied 一侧的幸存** | **1531/1957(78%)** |
| basic 双过仍未合并(ok/ok) | **312**(→ MERGE-COPYNOISE-OKOK-0001) |

结论:merge_test_basic 对 implied 的拒绝与 oracle merge.cc:255-264 同语义(忠实);
噪声主杠杆=**implied 标记后打印层未折叠**(MarkImplied×printc,归 printc/implied lane),
次杠杆=312 ok/ok 对未合并(去向待钉死)。cover 范围层不是本症状的主杠杆。

## 3. 门禁

- cargo test --lib:1648 passed/18 failed——18 个失败在 pristine base(cfd6b40a,
  /dev/shm basewt 复跑)同样失败(跨测试污染,预存在);merge:: 7/7 + 新形状测试通过。
- curl E2E:skeleton 3654,defects=0,numbering=0(result/curl_cur.c vs
  tests/golden/ghidra_curl_1204.c);修复前后 byte-identical。
- httpd E2E:skeleton 2459,defects=0,numbering=0;byte-identical。
- --func:main 1199/0/0;glob_set 97/0/0(gp 不在本语料,124/124 函数匹配)。
- 自赋值语句:修复前 907 → 修复后 907(生产零调用 ⇒ 恒等,如实报告)。
- diff-high 幸存:修复前后同(1969 对,byte-identical ⇒ IR 恒等)。

## 4. B2 状态

compute_varnode_covers(改动函数):**NO_ORACLE**——无真实 oracle 对拍;证据=Rugra
形状回归测试 test_compute_varnode_covers_backfills_intermediate_blocks(三块链:
def 块 [def,MAX]/中间块全块/读块 [0,read],旧近似下中间块缺失必败)+ E2E 不变性。
生产 cover 链(Cover::rebuild):本 lane 未改动,E2E 门禁维持基线。

## 5. 文件清单

- probe2.log/probe3.log/probe4.log:三轮探针(最终轮含 r1/r2 原因)。
- curl_before.c / curl_after.c / curl_final.c:base/修复/提交版输出(三者一致)。
- httpd_before.c / httpd_fix.c:httpd base/修复输出(一致)。
- basewt/:pristine base cfd6b40a worktree(复测 18 失败预存在 + before E2E)。

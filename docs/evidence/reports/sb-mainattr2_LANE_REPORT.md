# Lane GI/GI2 终报 — main 残差重归因 + printc STORE 单发射修复

- 交付 commit: **8e3d061d**（wt/mainattr2，亲父 b5b949dd）
- GI（前代）在账本写毕、提交前遇配额墙中断；GI2（本 agent）接手同 worktree，
  全量独立复跑验证后提交。账本 = `docs/alignment_docs/MAIN_RESID_ATTRIBUTION_2026-09-24.md`（含 §6 复验章）。
- 另登记新 TODO `TESTLIB-STATE-CONTAMINATION-0001`（18 个亲父既有 lib-test 失败=测试间状态污染）。

## 修复（PRINTC-STORE-DBLEMIT-0001）

merge 33418058 冲突解错 → STORE 地址双发射（`*ADDR*ADDR = v`，httpd 140/curl 19 行）。
恢复 printc.cc:500-517 opStore 单发射：deref 形仅一次 dereference token+pushVn(in1,m)；
usearray 形零 token+m|=print_store_value。

## 前后数字（双侧亲测）

| 门禁 | 前(b5b949dd) | 后(8e3d061d) |
|---|---|---|
| curl E2E canon | 1822/0/0 | **1744/0/0** |
| httpd E2E canon | 1756/0/0 | **1700/0/0** |
| 逐函数 | — | curl 14 改善/0 回退; httpd 9/0 |
| gcc 审计 | curl 102OK/22FAIL; httpd 13/16 | **104/20; 23/6** |
| 双发射行 | 140/19（拼接口径） | **0/0** |
| 五投影 | — | **MATCH ×5**（仅 META side/producer 头行异） |
| main 单函数 | curl 417 / httpd 715 | curl 413 / httpd 715 |

## main 新账本（top-3 修复建议）

1. **SP 下标族 ~210**（httpd main）：ruleaction INT_ADD→PTRADD 元素重标度 + varmap
   SP-alias 指针类型（FV2/FW2/FS3 让渡在账）；direct golden 亲证 `piVar10[-1] = X`
   库级正确形态 152 处。
2. **glibc 原型参数名 48**（curl main 单族第一大）：`__haystack/__ptr/__filename` 位点
   收敛到裸参数名（fspec/libc ingest，FP 图谱 M 族）。
3. **WARN unreachable 31**（httpd main）：Rugra 结构化多产不可达块再删（canon 1/direct 0），
   blockaction finalization 域，与 main 结构族同根。

（战略备选：headless 层追平——字符串恢复+local_* 命名，httpd 111+/curl ~115，FI 判例域需 root 裁决。）

## 复验方法备注

- 五投影 MATCH 判据 = 与锁 oracle projection 逐字节 diff，仅 META `side=`/`producer=`
  两头行不同（sb-oracle/ 与 sb-parseconfig/ 底档）。
- 双发射两口径：拼接形 `\)\*\(`、严格重复组 `\*(\([^=]*\))\1`，修复后均 0。
- 确定性 = 复跑逐函数表与前代 after 表逐项相等（httpd 30/30、curl 80/80）。

## 回收

- 证据归档：/dev/shm/rugra-reports/sb-mainattr2/（main_resid.py+perfunc/detail/lost 表）。
- 已回收：/dev/shm/rugra-tests/sb-mainattr2/、/dev/shm/rugra-targets/sb-mainattr2{,-bisect}。
- worktree /dev/shm/rugra-worktrees/mainattr2 保留待 root 集成。

# BLOCKSTRUCT-MULTIGOTO-0001 Lane 交付报告（wt/sb-multigoto）

日期: 2026-09-22 | base master 781722e | HEAD 3167bbe
Commits: 7c84622(M1 语义表) → 4be3442(M2 block+blockaction) → b3e08b9(M2 printc)
→ 91ae3f8(dedup 单锁纪律修复) → fd78bb6(pub+docs/api) → 3167bbe(port: 终稿含 Evidence+Differential)

## 交付
- BlockMultiGoto 类型 + newBlockMultiGoto + ruleBlockGoto isSwitchOut arm +
  checkSwitchSkips/grabCaseBasic/scopeBreak/markUnstructured/goto-case 发射全链接线。
- 配套: dedup_edges_all_types 单锁纪律重写（解锁本 lane 暴露的 OOB 崩溃 + 中间挂起队列版的收敛挂死）。
- docs: alignment_docs/BLOCKMULTIGOTO_M1_SEMANTICS.md(四类语义核对表)、docs/api 三件、ROADMAP 2026-09-22 补记。

## M3 数字
| 项 | baseline | lane | 说明 |
|---|---|---|---|
| curl defects / numbering | 0/0 | **0/0** | 机制 B 可提交条件满足 |
| curl skeleton | 3711 | **3386** | −325 |
| getparameter 函数级 | 869 | **539** | −330(38%),111×cc:1705 拒绝环解除 |
| glob_set 函数级 | 91 | 96 | +5 残差登记 B2-MG-RESID-3 |
| curl panic/timeout/decompiled | 0/0/76 | **0/0/76** | 中途曾 1 panic(gp OOB)→已修 |
| httpd 全量 diff | — | **0 行** | 与 baseline 逐字节一致 |
| cargo test --lib 串行 | 17 失败 | **17 失败(同集)** | 0 新增 0 修复 |
| B2 fixture | — | **MATCH**(9 行,双侧 oracle 直跑) | .cc 60e62f4e…/.rs 6fc451b1…/oracle stdout fb2f919f… |

## 残留(全部登记,不硬凑)
1. B2-MG-RESID-1: fixture family C(copy_switch_consumption 合成形)双侧分歧撤下——oracle 侧
   collapse 前 goto mark 丢失(未成 multigoto),Rugra 侧 mark 存活但形成异形 switch(exit 作 case)。
   真实输入消费路径已由 curl gp E2E 证据覆盖。root 分诊。
2. B2-MG-RESID-2: family A loop_exit_conflict 形——Rugra 遗留 cascade 复合 switch 被 multigoto 包裹、
   oracle 全解。legacy cascade 域,非 newBlockMultiGoto 缺陷。root 分诊。
3. B2-MG-RESID-3: glob_set +5 骨架变化(defects=0)。
4. switch case 真实 label(recoverLabels+finalizePrinting 排序)=JUMPTABLE-TABLEAPI-0001(P0-A 域)。
5. gp 完整 switch 恢复需 P0-A(SwitchNorm)联合——root 集成 E2E 验收。

## root 集成待办
- fixture 三件(/dev/shm/rugra-tests/sb-multigoto/blockmultigoto_1204.{cc,rs,metadata.json} +
  run_blockmultigoto.sh)固化 pinned runner 入库(本分支按内存盘规则未入 repo)。
- 机制 C 独立复核(blockaction.rs 白名单;Evidence 块在 3167bbe commit message)。
- 与 P0-A(wt/sb-switchnorm)联合 curl/httpd 验收 gp switch 终态。

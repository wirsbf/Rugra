# 证据资产清单 MANIFEST — wave 收官固化（AI_NATIVE L1 数据集底册）

- **生成**: 2026-09-24 · lane **EVMANIFEST** · worktree `wt/evmanifest` @ master `dc7a0d0a`
- **oracle**: Ghidra 12.0.4 tag `Ghidra_12.0.4_build` commit `e40ed13014025f82488b1f8f7bca566894ac376b`
- **动因**: AGENTS RAM 盘纪律下证据散落三处且重启即丢。本清单 + `docs/evidence/` 入库构成持久层;
  本 wave 全部车道（DP..GL,49 commits `5727faea..dc7a0d0a`）的结论性文档自此可追溯。
- **配套记分板**: `docs/alignment_docs/ALIGNMENT_SCOREBOARD_2026-09-24.md`（快照 2 = dc7a0d0a wave 终章实测）。

---

## 0. 分级定义

| 级 | 含义 | 处置 |
|---|---|---|
| **ARCHIVED** | 结论性文档/小数据件,已入 git（本 commit） | 永久 |
| **MUST-KEEP** | oracle 侧真值,仅存 RAM;重建依赖易失 oracle 环境（`/tmp/rugra-ghidra-bfd-2.38`,重启丢;重建=直连 https 拉 binutils-dev deb） | 集中到 `/dev/shm/rugra-tests/sb-oracle/` 单一根 |
| **REGEN** | Rugra 侧产物（C 输出/投影/bisect/构建缓存）,capture 命令见 §4 | 可丢,已清 |
| **RECLAIM** | 已按分级清理（180 项,~86G）,记录见 §5 | 已清 |
| **ACTIVE** | 在飞车道（worktree 存活）,本 lane 未触碰 | 勿动 |

## 1. `docs/evidence/`（本 commit,138 文件,1.5M）

| 路径 | 内容 | 来源 |
|---|---|---|
| `reports/`（110 份 .md） | 全 wave 车道终报:LANE_REPORT/LANE_*/CR 判例/GOLDEN_CONTRACT/ROOTCAUSE/TRIAGE/AUDIT/DESIGN 等;命名 `<源目录>_<原名>` 或原名 | `/dev/shm/rugra-reports/`(顶层+子目录)、`/dev/shm/rugra-tests/<lane>/`、`.fixture-staging/` |
| `data/` | goldenct 三方 JSON（consensus/threeway/bridge_gap2）、FP resid 判类法脚本 `resid_decomp_fp.py`、8cf844a1 残差 summary/compare ×4、dc7a0d0a 门禁证据（curl/httpd compare+byteexact+skeleton_identical+7 bisect txt）、rettemplate 探针源码、oracle 合并日志、资产盘点 TSV、清理执行记录 | 同上 |
| `data/evmanifest-tools/` | 本 lane 复现脚本:run_gates.sh（门禁链）、byte_exact_scan_ev.py（GB 字节级扫描器 + by_key 2 元组 bug 修复）、skeleton_identical_ev.py、make_inventory.py | lane scratch |

去重规则:与 `docs/` 既有文件 sha256 相同跳过（7 份,如 GOLDEN_CONTRACT_QUANT/M1_SEMANTICS/HTTPD_FLOW_MIRROR 已在
`docs/alignment_docs/`）;同内容多副本保留首份（10 份 COPY-DUPE）。

## 2. `/dev/shm/rugra-reports/`（车道终报档案区,17M,保留不动）

- 110 份 .md 已复制入 `docs/evidence/reports/`（**ARCHIVED**）。
- 保留原位:大件证据目录（`sb-joinstop/` 9.8M gates 输出、`LANE-DP-EVIDENCE/` 5M、`sb-jtmarkup|rulresid|mainattr2|spindex|typesettle/` 等）= **REGEN**（capture 见 §4）;
  其中 oracle 侧件（`oracle_ap*`、`pushabsorb_ir_1204.*`）已**复制**入 `sb-oracle/lane-evidence/LANE-DP-EVIDENCE/`（**MUST-KEEP**）。
- `guardlift/evidence/`、`sb-goldenct/` 等结论 .md 均已 ARCHIVED。

## 3. `/dev/shm/rugra-tests/`（81.1G → 3.0G）+ `rugra-targets/`（21G → 13G）+ `.fixture-staging/`（98M → 4K）

### MUST-KEEP 单一根: `/dev/shm/rugra-tests/sb-oracle/`（1.1G）

| 内容 | 规模 | 说明 |
|---|---|---|
| canonical oracle 投影 8 件 | ~350M | `next_url`(6.0M) `curl.match_url`(5.4M) `curl.myprogress`(5.7M) `curl.file2string.part.0`(6.1M) `curl.glob_word`(13M) `curl.getparameter.constprop.0`(71M) `curl.main`(194M) `httpd.main`(65M) |
| `lane-evidence/<lane>/`（97 文件,185M,30 车道） | 185M | 全盘扫描 `*oracle*` 非 .sh 文件,sha256 对 sb-oracle 顶层/tests//tools/ 去重后合并;编译型探针二进制已剔（.cc 源+stderr 流保留）。大件:`sb-vsempty/gp.oracle.projection`(74M)、`gp.oracle.probe4.stderr`(31M)、`curl.parseconfig.oracle.projection`(10M)、`sb-parseconfig/snap81_oracle.txt`(6.5M)、sb-integration L3/L5/L6/adj 投影(25M) |
| `drift/`、capture 日志、M1/M2 报告 | ~5M | oracle 投影 capture 过程记录（ARCHIVED 的 .md 也在 `docs/evidence/reports/sb-oracle_*.md`） |

### 保留（REGEN 证据链/在飞）

| 路径 | 大小 | 分级 | 说明 |
|---|---|---|---|
| `sb-scoreboard/` | 2.4M | REGEN-保留 | GB 快照 1 复现链（run_gates/run_projections + gates/ 原始输出）,被记分板 §8 引用 |
| `sb-residmap/` | 794K | REGEN-保留 | FP resid detail 台账（summary 已 ARCHIVED） |
| `sb-evmanifest/` | ~170M | REGEN | 本 lane 复现链（gates/ 含 7 投影原件;txt 已 ARCHIVED,投影可再生） |
| ACTIVE 10 车道 | ~1.5G | ACTIVE | `l1zero sb-b2bank sb-boomattr sb-emitterhang sb-fmfn sb-l1zero sb-testiso sb-vnhandover sb-vsempty testiso`（worktree 存活:b2bank 19:49 在飞、testiso 19:49 在飞等） |
| 残留 | <1M | root 属主 | `sb-okokprobe/wt/.rugra-cache`、`sb-candgen/wt_rust/.rugra-cache`（root 属主,agent 无权限,留 root 清扫） |

### rugra-targets/ 保留

ALIVE: `sb-b2bank sb-emitterhang sb-testiso sb-fmfn-base sb-l1zero-base sb-vsempty-base sb-vnhandover(0) sb-evmanifest`;
未认领 09-24 件: `sb-main-check`(2.0G) `sb-pltparent`(3.0G)（保守保留,root 裁定）。已清 12 项 ~8G（chainmerge 族/cm3/goldenct/junk-probe/svs/cr-* 基线等）。

### .fixture-staging/（已清空）

`sb-parseconfig/`(98M): 9×10M 投影——oracle 件已并 `sb-oracle/lane-evidence/sb-parseconfig/`,Rugra 侧投影 REGEN;
`sb-rettemplate-fixtures/`(124K): sleigh_probe/lift_fixture 源码已 ARCHIVED 到 `docs/evidence/data/rettemplate-fixture/`。

## 4. 重生成命令表（REGEN 类 capture）

```bash
# —— 门禁 E2E（curl 1438/0/0 · httpd 门禁面 1447/0/0 @ dc7a0d0a）——
CARGO_TARGET_DIR=/dev/shm/rugra-targets/<lane> cargo build --release --examples   # 3m51s
$TGT/release/examples/curl_decompile > curl.c                                     # curl 全量
$TGT/release/examples/httpd_decompile > httpd_gate.c                              # 门禁面 32 fn
MAX_FUNCS=840 $TGT/release/examples/httpd_decompile > httpd_full.c                # ⚠ dc7a0d0a 在 114/840 SEGV(记分板 §D)
python3 tools/compare_ghidra.py curl.c tests/golden/ghidra_curl_1204.c --summary-only

# —— L1 逐函数清单 ——
python3 docs/evidence/data/evmanifest-tools/skeleton_identical_ev.py <rugra.c> <golden.c> <label>   # gate 口径
python3 docs/evidence/data/evmanifest-tools/byte_exact_scan_ev.py   <rugra.c> <golden.c> <label>   # 严格字节口径

# —— Rugra 侧投影 ——
RUGRA_MIRROR=1 RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=<fn> RUGRA_STAGE_PROJ_OUT=<out.proj> \
  $TGT/release/examples/curl_decompile
# 注:GJ 符号层(dc7a0d0a)后 parseconfig/getparameter 用裸名,不带 .constprop.0

# —— 对拍(MATCH 判定) ——
python3 tools/stage_bisect.py --v1 <oracle.proj> <rugra.proj>

# —— oracle 侧投影(MUST-KEEP;重建需 oracle 环境) ——
tools/run_stage_projection_oracle.sh <corpus> <entry_hex> <fn>     # 依赖 /tmp/rugra-ghidra-bfd-2.38(易失)
tools/build_stage_drill_oracle.sh …                                # drill 流
# oracle 环境重建:直连 https 拉 binutils-dev deb 解包(apt 代理不可用),见 docs/VERIFICATION_GUIDE.md

# —— FP resid 判类法（残差台账）——
python3 docs/evidence/data/resid_decomp_fp.py    # 8cf844a1 版;dc7a0d0a 重算待下 lane
```

## 5. 清理执行记录

`docs/evidence/data/EVMANIFEST_CLEANUP_LOG_2026-09-24.md`（180 项逐条 size+理由;前置安全检查:回收候选内源码快照
零未提交 src 改动）。汇总:`rugra-tests` 81.1G→3.0G · `rugra-targets` 21G→13G · `.fixture-staging` 98M→4K ·
`/dev/shm` 91%→76%（释放 ~86G）。

## 6. 与 AI_NATIVE L1 的衔接

本清单即数据集准备第一步:① `reports/` 110 份 = 每 lane 的判类/根因/验收叙事;② `data/` 门禁 txt = dc7a0d0a 终态
逐函数观测;③ MUST-KEEP oracle 投影 = 双侧全管线中间态真值。后续数据集构建以 `docs/alignment_audit/FUNCTION_MAP.md`
为函数账本入口、本 MANIFEST 为资产索引。

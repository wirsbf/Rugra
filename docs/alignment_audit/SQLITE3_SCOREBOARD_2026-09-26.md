# SQLITE3 第五语料终版记分板 — 集成态 fresh 全量（2026-09-26，GEN5C）

> 车道：GEN5C（wt/gen5 合并收口）｜集成基 = master `f183385c`（= 0c353d5a + wt/gen5 合并，
> src/examples 零字节改动）｜oracle = Ghidra 12.0.4 `e40ed130`（锁定）。
> golden = `tests/golden/ghidra_sqlite_1204.direct-runner.c`（sha256
> `90950e1fa11d03eb77bf73abb24664e7fad3b9abc05ee11cf302f399a2636244`，143012 行，
> 来自 wt/gen5 `ff06b3c7`，本次合并零丢失落地——合并前后 git 侧 diff 为空亲证）。
> 驱动 = `examples/gen_decompile`（master 修复版：jtdest 全空间流契约 1ff2f5a1 +
> DIVCHAIN 724a76f4 + PFLUSH e1ee7de6 全在场），fast-release 集成态构建
> （`CARGO_TARGET_DIR=/dev/shm/rugra-targets/gen5c`，touch examples 强重链）。
> 本档为第五语料**终版记分板**：GEN5 中报（`GEN5_SQLITE_CORPUS_SCOREBOARD_2026-09-26.md`，
> 基 efc28f4a）的三张 worker-failure 票（3 TIMEOUT + 27 PANICKED）全部由后续修复闭环，
> 本轮 fresh 跑为合并后集成态的权威确认。

## 1. 终版头条（fresh 全量镜像臂，RUGRA_GEN_MIRROR=1）

- 运行形态：`mirror_shard_sqlite.py` 16 分片 × 顺序 `--one i`（hermetic 逐函数语义
  并行化包装，与 GEN5 中报同协议；脚本存 `/dev/shm/rugra-reports/gen5c-evidence/`）。
- **172s 完成，零重试轮**（中报同协议 795s 含重试——非终止函数烧墙是当时的主要成本）。

| 指标 | 终版（f183385c 集成态） | GEN5 中报（efc28f4a） | Δ |
|---|---|---|---|
| ok / 总单元 | **1385/1385** | 1355/1385 | **+30** |
| TIMEOUT | **0** | 3 | −3 |
| PANICKED | **0** | 27 | −27 |
| 误退出 | 0 | 0 | 0 |
| Matched | **1385** | 1355 | +30 |
| **skeleton** | **31214** | 17652 | +13562（口径基数变化，见 §3 分解） |
| **defects** | **0**（0/1385 函数） | 0 | = |
| **numbering** | **0** | 0 | = |
| 骨架恒等函数 | **971/1385（70.0%）** | 874/1355（64.4%） | +97 |
| 全量 wall（16 分片） | **172s** | 795s | −78% |

骨架恒等分解：旧 1355 匹配函数 874→**965**（+91）+ 30 个新完成函数 **6/30** 恒等
（`sqlite3BitvecTestNotNull` diff=0——与 DIVCHAIN 车道双侧 B2 fixture
`divchain_sqlite_bitvec_1204` 的字节恒等 MATCH 记录一致）。

## 2. 三修复贡献分解（DIVCHAIN / PFLUSH / JTDEST）

中报 30 个非 ok 函数的终局逐函数归因（官方口径 per-function skeleton diff 见 §4）：

| 修复 | 票 | sqlite 面贡献 | 证据 |
|---|---|---|---|
| **DIVCHAIN** `724a76f4` | PATHOSLOW-DIVCHAIN-0001 DONE | **11 非终止函数全部终止**：①3 个 shard-TIMEOUT（idx 55/57/114 Bitvec 三兄弟）→ OK；②4 个慢规则相后 panic（idx 834/835/836/1055）规则管线完成（1055 VdbeExec 139s）；③4 个慢但 <600s OK（idx 788/946/1321/1322）加速 | idx55 skeleton diff=0（字节 MATCH）；CR-DIVCHAIN APPROVE；B2 fixture `d50168fc` |
| **PFLUSH** `e1ee7de6` | SQATTR-PENDINGBRACE-IDENTITY-0001 DONE | **27 PANICKED 全部 → OK**，逐函数 defects=0/numbering=0；中报"半径 ×13.5（sq 2→sqlite 27 站点）"的 panic 主导族在 sqlite 面**清零** | PFLUSH 车道 27/27 索引重跑记录 + 本轮全量零 panic 亲证 |
| **JTDEST** `1ff2f5a1`+`63640303` | BINSWEEP-JTDEST-UNLINKED-0001 DONE | sqlite 镜像面**直接贡献 0**：not-linked 错误族从未在 sqlite 镜像臂观测（修复域=非 mirror 臂有界流契约，sqlite 跑全在 mirror 臂）；驱动为 master 修复版（gen5 分支旧有界驱动被合并规则淘汰） | canon 双语料零扰动（§6）；本合并 examples 以 ancestry 自动取 master 侧 |
| （窗口内其他修复） | VZEXT/F8FOR/CURLE 等 | 旧 1355 匹配函数骨架 **17652→15616（−2036）**：ZEXT 泄漏 98→23、SEXT 166→90（VZEXT 域）；for 形增益（F8FOR，MSTRUCT-FORSPLIT SUPERSEDED）；骨架恒等 +91 | 本轮 vs 中报对照（未做逐 commit A/B，聚合记） |

**ok 增量核算**：+30 = 3（DIVCHAIN 直接）+ 27（PFLUSH 直接，含 DIVCHAIN 解锁的 4 个
慢函数 panic 面——两修复对该 4 函数为接力关系：DIVCHAIN 使规则相完成、PFLUSH 使印刷相完成）。

## 3. skeleton 17652→31214 的口径分解（非回归）

| 成分 | 行数 | 说明 |
|---|---|---|
| 旧 1355 匹配函数（集成态新值） | 15616 | 中报 17652 − 2036（窗口修复增益） |
| 30 个新完成函数 | +15598 | 中报不计入（非 ok 单元无骨架口径）；其中四巨物 VdbeExec 5890 + vmprintf 2827 + mprintf 2822 + Pragma 2730 = 14269（91.6%） |
| **合计** | **31214** | 与 compare 总数恒等（15616+15598=31214 ✓） |

中报已预告该口径效应：goto/case/switch 差额（1233/484/13）"全部由 30 个非 ok 函数的
golden 体解释（≥gap）"——这些函数完成后其真实差入账。face 级佐证：goto 3671→4667
（golden 4869）、case 1002→1212（golden 1354）、unaff 5237→6089（golden 6203）、
extraout 1136→1835（golden 1845）——全部向 golden 收拢而非发散。

## 4. 30 个新完成函数逐名表（官方 normalize_skeleton 口径）

| idx | 地址 | 函数 | 中报状态 | 终版 diff | 备注 |
|---|---|---|---|---|---|
| 55 | 0x1f320 | sqlite3BitvecTestNotNull | TIMEOUT | **0** | 字节 MATCH（DIVCHAIN B2 fixture 同源） |
| 57 | 0x1f420 | sqlite3BitvecClear | TIMEOUT | 12 | DIVCHAIN |
| 114 | 0x26150 | sqlite3BitvecSet | TIMEOUT | 12 | DIVCHAIN |
| 94 | 0x209d0 | sqlite3AlterBeginAddColumn | PANICKED | **0** | PFLUSH |
| 214 | 0x35fe0 | sqlite3StartTable | PANICKED | **0** | PFLUSH |
| 219 | 0x36e80 | sqlite3AddPrimaryKey | PANICKED | **0** | PFLUSH |
| 285 | 0x3c160 | sqlite3FindFunction | PANICKED | **0** | PFLUSH |
| 412 | 0x4f5c0 | sqlite3FkActions | PANICKED | **0** | PFLUSH |
| 955 | 0xd0dd0 | sqlite3BeginTrigger | PANICKED | 4 | PFLUSH |
| 491 | 0x8cdf0 | sqlite3GenerateConstraintChecks | PANICKED | 8 | PFLUSH |
| 844 | 0xb12b0 | sqlite3ResolveSelectNames | PANICKED | 32 | PFLUSH |
| 954 | 0xd08e0 | sqlite3RunParser | PANICKED | 48 | PFLUSH |
| 643 | 0x974f0 | sqlite3_exec | PANICKED | 23 | PFLUSH |
| 953 | 0xd0460 | sqlite3_db_status | PANICKED | 67 | PFLUSH |
| 216 | 0x36640 | sqlite3AffinityType | PANICKED | 67 | PFLUSH |
| 302 | 0x3f290 | sqlite3ExprAffinity | PANICKED | 69 | PFLUSH |
| 411 | 0x4ef70 | sqlite3FkCheck | PANICKED | 65 | PFLUSH |
| 418 | 0x550f0 | sqlite3Fts3EvalPhraseStats | PANICKED | 37 | PFLUSH |
| 218 | 0x36d00 | sqlite3AddDefaultValue | PANICKED | 12 | PFLUSH |
| 227 | 0x390e0 | sqlite3_complete | PANICKED | 75 | PFLUSH |
| 1315 | 0xf00d0 | sqlite3WalFrames | PANICKED | 68 | PFLUSH |
| 827 | 0xaa960 | sqlite3_str_vappendf | PANICKED | 115 | PFLUSH |
| 419 | 0x553f0 | sqlite3Fts3EvalPhrasePoslist | PANICKED | 140 | PFLUSH |
| 93 | 0x20560 | sqlite3AlterFinishAddColumn | PANICKED | 95 | PFLUSH |
| 765 | 0xa1690 | sqlite3PagerSetPagesize | PANICKED | 342 | PFLUSH |
| 172 | 0x31570 | sqlite3BtreeInsert | PANICKED | 38 | PFLUSH |
| 836 | 0xad3c0 | sqlite3Pragma | PANICKED | 2730 | DIVCHAIN+PFLUSH 接力 |
| 835 | 0xad2e0 | sqlite3_mprintf | PANICKED | 2822 | DIVCHAIN+PFLUSH 接力 |
| 834 | 0xad250 | sqlite3_vmprintf | PANICKED | 2827 | DIVCHAIN+PFLUSH 接力 |
| 1055 | 0xd95f0 | sqlite3VdbeExec | PANICKED | 5890 | DIVCHAIN+PFLUSH 接力（30609B 五语料最大单函数） |

## 5. 残差族终版分布（全量 31214 行全分类）

pair 分类器（21125 对可分类；其余为纯增/删单边行）：

| 族 | 行数/函数数 | 中报（17652 基） | 票务 |
|---|---|---|---|
| OTHER（cast token+栈/Ram churn 主成分） | 12108/380 | 5317/398 | 拆解归并下两族（四巨物入账主因） |
| CAST-SHAPE | 4633/249 | 3908/224 | GEN4-SQ-CASTFUSE-DEPTH-0001 |
| SWITCH-GOTO | 2370/97 | 3779/85 | MSTRUCT-SWITCHGOTO-SELECTGOTO-0001 |
| UNAFF-EXTRAOUT | 1413/66 | 2235/81 | GENSMOKE-S4/S2 |
| OPNAME-LEAK | 271/66 | 1263/88 | GEN4-SQ-ZEXT-OPNAME-0001（**VZEXT 后 ZEXT 98→23、SEXT 166→90**） |
| LOOPSHAPE | 216/19 | 810/12 | MSTRUCT-FORSPLIT（F8FOR 后 pair 口径收缩；hunk 口径见下） |
| CAST-TEMP-HOIST | 69/27 | 146/12 | GEN4-SQ-CASTFUSE-DEPTH-0001 |
| WARNING-FACE | 29/11 | 58/9 | 既有警告族杂项 |
| TYPE-SPELL | 15/15 | 37/14 | F-TYPE/S2-TYPEINFER |
| BRANCH-INVERT | 1/1 | 8/1 | GEN4-SQ-BRANCH-INVERT-0001 |

hunk 分类器（31214 行全分类；多行连续块视角，for↔while 整块迁移在此膨胀）：
LOOPSHAPE 8058/18、SWITCH-GOTO 5785/96、OTHER 5662/336、CAST-SHAPE 5235/227、
UNAFF-EXTRAOUT 3124/90、CAST-TEMP-HOIST 1967/17、OPNAME-LEAK 1055/34、CMP-ORIENT 227/9、
WARNING-FACE 54/9、TYPE-SPELL 39/15、BRANCH-INVERT 8/1。
四巨物主导：VdbeExec 5890（LOOPSHAPE 2347+CAST-TEMP-HOIST 1743+SWITCH-GOTO 1047）、
vmprintf/mprintf/Pragma 各 ~2800（LOOPSHAPE ~1600 领跑）——**while↔for 形与 cast 临时
物化是新入账函数的主残差**，与全语料既有族同谱（FORSPLIT/CASTFUSE），零新族。

## 6. 面级终版对照（Rugra / golden）

| 面 | Rugra | golden | 中报 Rugra | 备注 |
|---|---|---|---|---|
| WARNING 行 | 2586 | 2579 | 2393 | 新完成函数带警告入账，轻微过冲 +7 |
| switch / case / goto | 60/1212/4667 | 61/1354/4869 | 48/1002/3671 | 向 golden 收拢 |
| unaff_ / extraout_ | 6089/1835 | 6203/1845 | 5237/1136 | 向 golden 收拢 |
| Ram 符号 | 1486 | 1550 | 814 | 与 ram0x 122 合看=覆盖缺口（RAMNAME 族） |
| ram0x 兜底 token | 122 | 0 | 129 | GEN4-SQ-RAMNAME-0001 |
| ZEXT/SEXT 泄漏 | **23/90** | 15/3 | 98/166 | VZEXT 域收益（SEXT 余=VARMPOISON 派生） |
| FUN_ 回退 | 0 | 0 | 0 | — |

oracle 压力面复现保持：unreachable-block/jumptable Too-many-branches/typeprop 不收敛
警告在匹配函数上近 parity（中报 1613/319/10 vs golden 1760/327/12 的关系在集成态维持，
WARNING 总量 2586 vs 2579）。

## 7. 确定性

- Rugra 侧抽检 4/4 字节恒等（idx 55/302/836/1055 独立重跑 vs 分片块 cmp 全同）。
- 全量 16 分片零重试轮（重试协议 3 轮一轮未用——首轮即全绿）。
- oracle 侧 determinism 12/12 字节恒等（GEN5 中报，golden 侧）。

## 8. canon 双语料零扰动（合并只加 golden/docs 的亲证链）

1. **结构层**：`git diff 0c353d5a f183385c -- src/ examples/ Cargo.toml Cargo.lock`
   = 空集（合并只动 TODO_BOARD/记分板/golden/README 五文件）。
2. **行为层**：集成态 canon httpd 与合并前档案（03:31，post-F8FOR master 态）
   **cmp 字节恒等**（255/0/0，34 函数）；canon curl 双跑字节恒等（sha256
   `638ffcb3…`），与 02:50 档案（pre-F8FOR，247/0/0）仅差 F8FOR 交付在案的 for 形
   （config-for）与一行语句迁移——全部归因 c961ed8d（03:02 合并，早于本合并）。
3. sqlite3 golden 合并不动 curl/httpd 数字：三门禁差分
   curl **246/0/0**（124/124 matched）、httpd **255/0/0**（34/34 matched）。

## 9. 复现配方

```bash
# 集成态构建
CARGO_TARGET_DIR=/dev/shm/rugra-targets/gen5c cargo build --profile fast-release --example gen_decompile
# 全量镜像（16 分片，~172s）
python3 /dev/shm/rugra-reports/gen5c-evidence/mirror_shard_sqlite.py 1385
# 差分（终版头条数字）
python3 tools/compare_ghidra.py /dev/shm/rugra-tests/gen5c/sqlite_mirror.c \
  tests/golden/ghidra_sqlite_1204.direct-runner.c --base 0 --summary-only
# 族分类/面计数/逐名表
python3 /dev/shm/rugra-reports/gen5c-evidence/scoreboard_gen5c.py
python3 /dev/shm/rugra-reports/gen5c-evidence/newcomers_official.py
```

分片脚本现状注记（DOCGUIDE-GEN5-SHARD-EVIDENCE-0001）：`mirror_shard_sqlite.py`
与 `capture_oracle_gen5.py` 实况**未失**（存 `/dev/shm/rugra-reports/gen5-evidence/`，
本轮复用并适配到 gen5c-evidence/：二进制/输出路径改指集成态，cwd 改主仓）；但内存盘
资产重启即丢的性质不变，版本化裁决仍待 root。终版记分板数字以本轮 fresh 跑为准。

## 10. 建议（root 裁决项）

1. **sqlite 镜像门禁第 5 面**（中报建议重申）：本轮终态实测 31214/0/0/1385 可作
   pre-fix 钉值候选——`tools/verify_mirror_gate.sh --corpus sqlite` + baselines 行
   （写域=tools/，本车道禁触）。ok=1385/1385 与 defects/numbering 双零可设硬断言。
2. 四巨物（VdbeExec/vmprintf/mprintf/Pragma，14269 行=45.7%）是 sqlite 面收敛的
   最大单点——LOOPSHAPE（for 形）+CAST-TEMP-HOIST 两族合计占其 60%+，修 F8FOR 残差
   票（F8FOR-REJECT-RESIDUAL-0001）与 CASTFUSE 的收益在 sqlite 面将直接放大。

## 11. GENWIRE 重启环附录（2026-09-26，wt/genwire 链②收口后 fresh 全量）

PIPE-RESTART-0001 解锁链②（gen 驱动 RestartFlowCallback 接线）落地后的第五语料棘轮增量：

- 驱动 `examples/gen_decompile` 安装重启回调（镜像 curl 先例 `48a66fab`，裸面单流契约
  follow_flow_range(0, u64::MAX, empty_protos) 双遍同形）+ `ScopeLocal::clear_symbols_wholesale`
  id 配对一致性修复（varmap.rs/funcdata.rs，重启第二遍在 populated scope 上清空 seam 的
  panic 根因；详证 LANE_GENWIRE 终报）。
- **重启环首次生产点火**：3 函数（sqlite3_config/sqlite3_db_config/sqlite3_test_control，
  `--one` 603/608/623）第二遍真实执行，输出带 `Restarted to delay deadcode elimination
  for space: stack` 警告头（oracle 重启指纹）。
- **棘轮数字（fresh 16 分片全量，205s，ok=1385/1385）**：skeleton **31214→…→27318（本档
  基线，master `512c5600` 现态）→27178（GENWIRE 后）**，defects=0/numbering=0 不变；
  −140 精确=3 函数改善（config 129→78 / db_config 18→11 / test_control 205→123，
  TRIGFACE §③ oracle 侧量化 272 行的方向与域落地：栈槽去物化+类型精化+警告重定位）。
- **零回退铁证**：1385 块逐块对照基线，**恰 3 块差异**（603/608/623），其余 1382 块字节恒等。
- root 重钉已执行（**MERGEBATCH17, 2026-09-26**）：`tools/mirror_gate_baselines.tsv` sqlite 行首钉
  ceiling **27178** / floor **1385**（todo_id=GENWIRE-SQLITE-RATCHET-REPIN-0001,
  pinned_commit=wt/genwire tip `28e3fb26`——27178 实测锚;`tools/verify_mirror_gate.sh`
  sqlite 臂同批上线,单进程全量形态与 vsh/sq 同契约,SQLITE3_BINARY 可覆盖语料路径;
  16 分片 mirror 臂为记分板测量协议,门禁臂为单进程全量——两协议口径差若实测显形,
  以门禁臂实测重钉并注记）。

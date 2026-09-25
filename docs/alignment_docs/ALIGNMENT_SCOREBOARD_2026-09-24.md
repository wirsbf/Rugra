# 对齐记分板 — 两级"完整对齐"清单快照（2026-09-24 双快照：wave 终章 dc7a0d0a + GB 版 5727faea）

- **快照 2（本文档上半，§A~§F）**: master **dc7a0d0a**（wave 终章,GL lane 合入点）· lane EVMANIFEST · worktree `wt/evmanifest`
  · `cargo build --release --examples`（3m51s）· `CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-evmanifest`
  · 产物 `/dev/shm/rugra-tests/sb-evmanifest/gates/`（关键 txt 已入库 `docs/evidence/data/`）
- **快照 1（GB 版,原正文 §0~§8,基线 5727faea）**: 保留作历史对照,其数字不再代表当前 master。
- **oracle**: Ghidra 12.0.4 tag `Ghidra_12.0.4_build` commit `e40ed13014025f82488b1f8f7bca566894ac376b`；
  canon golden = `tests/golden/ghidra_{curl,httpd}_1204.c`；投影 oracle = `/dev/shm/rugra-tests/sb-oracle/`（RAM MUST-KEEP,
  资产底册见 `docs/evidence/MANIFEST.md`）。

---

# 快照 2 — wave 终章（dc7a0d0a,2026-09-24 EVMANIFEST 亲测）

## A. 双语素门禁实测（与任务书预期核对）

| 门禁 | 实测 | 任务预期 | 判定 |
|---|---|---|---|
| curl E2E vs `ghidra_curl_1204.c` | **1438 / 0 defects / 0 numbering**（124/124 匹配） | 1438/0/0 | ✅ 一致 |
| httpd 门禁面 vs `ghidra_httpd_1204.c` | **1447 / 0 / 0**（**32**/32 匹配,面从 29→32:GA/GJ switchD default 三函数新入面） | 1447/0/0 | ✅ 一致 |
| curl 双跑确定性 | stdout `cmp` **恒等** | — | ✅ |
| resid 判类自校验 | skeleton_identical 生成器 sum=1438/1447 与门禁总数精确相等 | — | ✅ |

## B. 第一级（C 文本 diff=0）清单刷新 vs GB

### curl gate 口径 **59/124（47.6%）**（GB 51 → +8,零丢失）

新增 8 个全部是**真代码小函数**（GG2 车道战果在 master 复核确认）:`deregister_tm_clones, register_tm_clones,
__do_global_dtors_aux, frame_dummy, my_fwrite, SetHTTPrequest, hugehelp, main_free`。真代码合计 **9**（含存量 `GetStr`）+ 桩 50。
⚠ GG2 亲报的 `main_init`/`glob_url` 零差在 dc7a0d0a **回吐为 2 行**（同窗还有 `_init` 8 行、`FUN_00102020`/`__cxa_finalize`/
`progressbarinit`/`SetHTTPrequest` 第二形态各 2 行）——回归窗 af6c5ee2→dc7a0d0a（GK/GL 集成带）,未派车道,建议 root bisect。

### httpd 门禁面 gate 口径 **6/32（18.8%）**（GB 0/29 → 破零）

真代码 3:`ap_pregfree`（GD）、`ap_stripprefix`、`ap_count_dirs`（后两者为 dc7a0d0a 新晋,归属车道待认领）;
桩 3:三个 `switchD_…::default`（GA/GJ driver 符号层）。

### 严格字节口径（GB byte_exact_scan 同口径,含空行,头行除外）

- curl **47/124（37.9%）** = 10 dunder/EXTERNAL 单行桩 + **37 个 PLT-thunk 投影体逐字节同**（FU PLT 桩发射族+GJ 符号层战果;GB 时仅 4）。
- httpd 门禁面 **3/32（9.4%）**,全为真代码（`ap_count_dirs/ap_pregfree/ap_stripprefix`）——httpd 真 L1 字节级从 0→3。

## C. 第二级（阶段投影 MATCH）— **五投影 MATCH 确认（5/7）**

| # | 函数 | stages | ops（ora=rug） | 判定 | vs GB |
|---|---|---:|---:|---|---|
| 1 | curl `next_url` | 335 | 96 457 | **MATCH** | 保持 |
| 2 | curl `match_url` | 340 | 80 385 | **MATCH** | 保持 |
| 3 | curl `parseconfig` | 335 | 130 099 | **MATCH** | 保持（注:GJ 符号层后投影名不带 `.constprop.0`,META func_name 差异为已知无害） |
| 4 | curl `getparameter` | 371 | **913 373** | **MATCH** | **新晋**（GB ord186 +158 ops → GE 1b2cc000 修复后精确相等） |
| 5 | curl `myprogress` | 402 | 84 249 | **MATCH** | **新晋**（GB ord399 setcasts 5v6 → FV/81cdfa2b 修复） |
| 6 | curl `main` | 299 | 2 414 145 vs 2 413 571（−574） | 分歧 | 前沿不动:op-line 1792 `extrapopsetup` seqnum `2d04:c15` vs `2d04:c0e` |
| 7 | httpd `main` | 294 | 878 973 vs 878 983（**+10**） | 分歧 | 首分歧仍 result/count 2 vs 1（round 0）;Δops 由 GB +1350 收窄至 +10 |

MATCH 率 **5/7（71.4%）**,双侧 stages 恒等 7/7,restarts 全 0。GG2 亲报"五投影 MATCH"在 master dc7a0d0a 复核成立。

## D. ⚠ 新开口项：httpd 全量面段错误（HTTPD-FULL-SEGV）

`MAX_FUNCS=840 httpd_decompile` 在 **114/840 `ap_content_length_filter`** 段错误（exit 139,`[COLLAPSE] ruleBlockGoto`
+ `finalize_structure: 18 -> 1` 之后、打印期前;无 panic、无 TIMEOUT、无 not-settling）。GD2（1cc776b1）时全量 473 fn/
25989 行可完 → 回归窗 1cc776b1..dc7a0d0a（GI/GJ/GK/GL 集成带）。**门禁面 32 fn 不受影响**。建议 root 登记 P0 TODO 并派 triage。

## E. wave 全程趋势（gate 口径 skeleton 行数）

| 检查点 | curl | httpd 门禁 | 备注 |
|---|---:|---:|---|
| wave 起点（任务书口径） | 3718/0/0 | 3576/0/0 | |
| 8cf844a1（FP 残差图） | 2147/0/0 | 2059/0/0 | |
| 9458a61b（FX） | 2145/0/0 | 2057/0/0 | |
| 5727faea（GB 快照 1） | 2135/0/0 | 2057/0/0 | |
| **dc7a0d0a（本快照）** | **1438/0/0** | **1447/0/0** | |

**全 wave:curl −2280 行（−61.3%）、httpd −2129 行（−59.6%）,defects/numbering 全程 0。**

## F. 记分板汇总（dc7a0d0a）

| 层级 | 口径 | curl | httpd 门禁面 | 合计 |
|---|---|---:|---:|---:|
| L1 gate | 逐函数 skeleton diff=0 | **59**/124（47.6%） | **6**/32（18.8%） | 65/156（41.7%） |
| L1 strict | 函数体逐字节相等 | 47/124（37.9%） | 3/32（9.4%） | 50/156（32.1%） |
| L1 真代码 | gate 口径剔除桩 | **9** | **3** | **12** |
| L2 投影 | stage+snapshot identical | **5/6**（curl 函数） | 0/1（httpd main） | **5/7（71.4%）** |
| L2 结构 | stages 恒等 | 6/6 | 1/1 | 7/7 |

**读法**:wave 终点的真实存量 = 5 个投影 MATCH + 12 个真代码文本零差（curl 9/httpd 3）+ 50 个桩形零差（含 37 个逐字节
PLT-thunk 体）。两级互补:投影 MATCH 的 getparameter/parseconfig/myprogress 文本层仍有 79/64/45 行残差,文本零差的
小函数未做投影级验证。**下一 wave 最高价值目标**:① HTTPD-FULL-SEGV triage（阻塞全量面一切度量）;② §B 2 行级微回归窗
bisect（7 函数,小成本）;③ curl/httpd main 两投影前沿（−574 seqnum 时序 / result-count 2v1）。

---

# 快照 1 — GB 版原文（master 5727faea,2026-09-24,历史对照）

- **性质**: 只读分析 + 文档交付（Lane GB；零 `src/` 改动）
- **基线**: master `5727faea`（"core: switch case labels synthesized in driver symbol layer (FT lane)"）
- **oracle**: Ghidra 12.0.4 tag `Ghidra_12.0.4_build` commit `e40ed13014025f82488b1f8f7bca566894ac376b`；
  本 golden = `tests/golden/ghidra_{curl,httpd}_1204.c`（canon 门禁基线）+ `.direct-runner.c`（EG2/FI 裁定库级真值）；
  投影 oracle = 4 个 pin 全部 sha256 复核通过（next_url 默认 pin + curl/main + curl/getparameter.constprop.0 + httpd/main，见 §2.1）
- **环境**: worktree `/dev/shm/rugra-worktrees/scoreboard`（branch `wt/scoreboard`），`cargo build --release --examples`
  （3m47s），`CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-scoreboard`
- **产物**: `/dev/shm/rugra-tests/sb-scoreboard/`（gates/ 全部原始输出 + 两份 resid 台账）

本文档回答一个问题：**当前时刻，"函数级完整对齐"到底有多少？** 用两个口径度量并给出全量清单：
**第一级** = C 文本逐函数 diff=0（gate 口径 + 严格字节口径）；**第二级** = 阶段投影 MATCH（stage+snapshot 全同）。
两级都是函数级判据（机制 B2 的 `MATCH` 状态入口），但覆盖面不同：L1 看终态 C 文本，L2 看全管线中间态。

---

## 0. 基线复核（亲测，亲父 5727faea）

| 门禁 | 实测 | 任务预期 | 判定 |
|---|---|---|---|
| curl E2E vs `ghidra_curl_1204.c` | **2135 / 0 defects / 0 numbering**（124/124 函数） | 2135/0/0 | ✅ 一致 |
| httpd 门禁面 29/29 vs `ghidra_httpd_1204.c` | **2057 / 0 / 0** | 2057/0/0 | ✅ 一致 |
| httpd 全量 MAX_FUNCS=840 vs direct-runner | **38672 / 1 / 0**（470 函数；panic=0 TIMEOUT=0） | — | == FX 基线（9458a61b）逐数相同 |
| curl 双跑确定性 | stdout `cmp` **恒等** | — | ✅ |
| resid 判类自校验（FP `resid_decomp` 判类法） | curl sum(n_mc)=2135 OK / httpd sum(n_mc)=2057 OK | — | ✅ 逐函数底表精确复现门禁总数 |

与 8cf844a1（FP 残差图基线）相比：curl **2147→2135（−12，FT/ff971049 switchD case 标签层）**，httpd 2059→2057（−2）。
与 9458a61b（FX）相比：curl 2145→2135（−10 同上），httpd/httpd-full 全持平。

---

## 1. 第一级：C 文本级 diff=0 清单

### 1.1 口径

- **gate 口径**（`compare_ghidra.py` 逐函数 skeleton diff = 0，即 `[Skeleton] identical`）：项目标准"该函数 diff=0"。
- **严格字节口径**（本 lane 新增 `byte_exact_scan.py`）：函数体文本（含空行/换行，不含 `/* ---- 0x… ---- */` 头行，
  canon 头行带 +0x100000 基址故排除）**逐字节相等**。这是 L1 的最强形态，gate 口径的真子集。

### 1.2 curl：51/124（41.1%）

| 类别 | 数量 | 清单 |
|---|---:|---|
| **真代码** | **1** | `GetStr`@0x36d0 |
| ELF glue | 4 | `_fini`@0x5478, `__libc_csu_fini`@0x5470, `_ITM_deregisterTMCloneTable`@0x19010, `_ITM_registerTMCloneTable`@0x19130 |
| 导入桩 | 46 | PLT 投影 44：`__ctype_b_loc __cxa_finalize __fprintf_chk __isoc99_sscanf __printf_chk __sprintf_chk __stack_chk_fail __vfprintf_chk __xstat` + curl_lib 11（`curl_easy_*`×6/`curl_formparse`/`curl_getdate`/`curl_getenv`/`curl_slist_append`/`curl_slist_free_all`/`curl_version`）+ libc 24（`exit fclose fgets fileno fopen fputc free fwrite isatty malloc maprintf memcpy puts realloc strcat strchr strcpy strdup strequal strlen strnequal strrchr strstr strtol time`）；EXTERNAL 块 2：`__libc_start_main`@0x19078, `__gmon_start__`@0x19088 |
| **合计** | **51** | |

**严格字节口径：4/124（3.2%）** — `_ITM_deregisterTMCloneTable`, `_ITM_registerTMCloneTable`, `__gmon_start__`, `__libc_start_main`（均为单行 `return 0;` 形桩）。

**要点**：51 个里 **真代码只有 GetStr 一个**（74 字节小函数）。所有头部大函数（main 487、getparameter 532、file2string 113…残差见 §5）无一达到 L1。
最小残差真代码梯队（gate 口径）：hugehelp 1 / main_free 1 / main_init 3 / glob_url 2 / SetHTTPrequest.part.0 2 — 距 L1 均差 1-3 行。

### 1.3 httpd：门禁面 0/29；全量（vs direct-runner）1/470

- 门禁面 29 函数（vs canon golden）：**0 个 diff=0**；最小残差 `ap_pregfree` 2 行，其后 `ap_get_server_built`/`ap_getword_nc`/`suck_in_APR` 各 4。
- httpd 全量 470 函数（vs direct-runner golden，L2 仪表盘基线）：**1 个 skeleton-identical = `ap_update_mtime`**；1 个 defect = `ap_get_server_name` 空 else（L21，FX 时代父链演化复现，已登记 HTTPD-FULLEMPTY-ELSE residual）。
- 严格字节口径：httpd 两侧均 0。

---

## 2. 第二级：阶段投影 MATCH 清单

### 2.1 投影 pin 复核（先于对拍）

锁定 oracle 投影 4 个 pin 逐一 sha256 复核：next_url（默认 pin）、curl/main、curl/getparameter.constprop.0、httpd/main（metadata `functions` map）——**全部 MATCH**。
match_url/parseconfig/myprogress 为盘上既有 oracle 产物（sb-oracle/、sb-parseconfig/），以 stats（stages/ops）核对一致后用于对拍。

### 2.2 对拍结果（stage_bisect --v1，RUGRA_MIRROR=1 正典 bundle）

| # | 函数 | stages（ora=rug） | ops oracle | ops rugra | Δops | 判定 | 首分歧 |
|---|---|---:|---:|---:|---:|---|---|
| 1 | curl `next_url` | 335 | 96 457 | 96 457 | 0 | **MATCH** | — |
| 2 | curl `match_url` | 340 | 80 385 | 80 385 | 0 | **MATCH** | — |
| 3 | curl `parseconfig.constprop.0` | 335 | 130 099 | 130 099 | 0 | **MATCH** | — |
| 4 | curl `getparameter.constprop.0` | 371 | 913 373 | 913 531 | +158 | 分歧 | **ord 186** `oppool2` op-line 367：`INT_ADD c:4e8` vs `c:4f0`、CROSSBUILD 偏移 `fb10` vs `fb18`（栈偏移 +8 常量族） |
| 5 | curl `myprogress` | 402 | 84 249 | 84 254 | +5 | 分歧 | **ord 399** `setcasts` result/count 5 vs 6（= 已登记 `MYPROGRESS-SETCASTS-ORD399-0001`，OPEN） |
| 6 | curl `main` | 299 | 2 414 145 | 2 413 571 | −574 | 分歧 | **ord 5** `extrapopsetup` op-line 1792：同形 op 的 seqnum 时序 `2d04:c15` vs `2d04:c0e`（op 创建顺序差，内容同） |
| 7 | httpd `main` | 294 | 878 973 | 880 323 | +1350 | 分歧 | **ord 83** `condconst` result/count 2 vs 1 |

**MATCH 率 3/7（42.9%）**；双侧 stages 恒等 7/7（结构骨架层数无差），restarts 全 0。

### 2.3 序数推进轨迹（对照 TODO 账本）

- `getparameter`：7 → 55（GETPARAM-PHASE2）→ 65（ACTIVEPARAM-TRIAL）→ 155（RANGEUTIL-CONSTGEN 后 switchnorm）→ **186**（本快照，oppool2 栈偏移常量 +8；155→186 = switchnorm 车道战果，新前沿未登记新 TODO）
- `myprogress`：→ 150（OPPOOL2-CONSTSPLIT 定位）→ **399**（VARMAP-STACKBOUNDARY 修复后移；setcasts 5v6 = MYPROGRESS-SETCASTS-ORD399-0001 OPEN）
- `match_url`：12 → 55 → 70 → 164 → 191 → **MATCH**（2026-09-23 序列收敛）
- `parseconfig`：81 → 320 → **MATCH**（JOINBLOCK-STOPADDR 收口）
- `next_url`：**MATCH** 自 2026-09-22 起保持（本快照复核通过）

### 2.4 规模记录（stages/ops）

- 三 MATCH 投影合计 1010 stages / 306 941 ops 全同；
- 两 main 投影（curl+httpd）合计 3 293 118 oracle ops（curl 2.41M = 单函数最大，httpd 0.88M），Δops −574/+1350（±0.05-0.15%）；
- getparameter 371 stages / 913K ops，Δ +158 ops（+0.017%）——**序数推进已深入管线后段（oppool2 在 186/371 = 50% 处）**。

---

## 3. httpd 全量 L2 仪表盘快照

| 指标 | 值 |
|---|---|
| 函数覆盖 | 470/840 上限（MAX_FUNCS=840，panic=0 / TIMEOUT=0） |
| skeleton（vs direct-runner） | **38672** |
| defects | **1**（ap_get_server_name 空 else L21 — 亲父预存 residual） |
| numbering | **0** |
| skeleton-identical | 1（ap_update_mtime） |
| not-settling（stderr 中止型） | **0**（TYPEPROP-NONSETTLING 中止族已清零） |
| not-settling（打印警告型，stdout 注释） | **4**：`ap_run_create_connection`, `ap_discard_request_body`, `ap_http_chunk_filter`, `ap_mpm_run`（coreaction.cc:5390 `localcount>=7` 警告形，能完成=对齐"仅警告"语义） |
| 其他打印警告 | Globals-'_'-overlap 9 fn ×1、Removing-unreachable-block ~500 条（Ghidra 同类正常警告）、Heritage-after-dead-removal 1、Restarted-delay-deadcode 1 |

趋势：not-settling 打印警告 22（ER 时代）→ 5（EO2）→ **4**（本快照）；中止型 2→0 后保持 0。

---

## 4. 趋势（wave 起点 → 当前）

| 检查点 | curl | httpd 门禁 | 备注 |
|---|---:|---:|---|
| wave 起点（任务书口径） | 3718/0/0 | 3576/0/0 | httpd 处于主仓回归态（W4 good=2344，+1232 回归在账） |
| 8cf844a1（FP 残差图） | 2147/0/0 | 2059/0/0 | EQ3 round-3 + FL 叠加首测 |
| 9458a61b（FX） | 2145/0/0 | 2057/0/0 | driver init 三件收口 |
| **5727faea（本快照）** | **2135/0/0** | **2057/0/0** | FT switchD 标签层 −10（curl） |

- **全 wave：curl −1583 行（−42.6%）、httpd −1519 行（−42.5%）**，defects/numbering 全程 0。
- L1 清单扩张：真代码 byte-MATCH 从 0（wave 前 file2string.part.0 曾达 143→0 后又波动）到本快照 gate 口径 51（其中桩 50）+GetStr；
  httpd 门禁面仍 0——**httpd 语料一个真代码 L1 都还没有**，是下一 wave 最直接的记分板目标。
- L2 投影 MATCH：wave 期初 0 → 3（next_url 2026-09-22，match_url/parseconfig 2026-09-23，本快照全保持）。

---

## 5. TOP 残差函数表（FP residmap 判类法，5727faea 重算）

自校验：sum(n_mc) 精确等于门禁总数（curl 2135 / httpd 2057）。can=对 canon golden 残差；dir=对 direct-runner 距离；
分类列 = 净增行判类（BRIDGE=direct 同函数逐字 / CAST=cast 归一后命中 / GAP=双基线皆无）+ 净删（LBOTH=双基线都有而缺 / LHEAD=仅 canon 有）。
族标注 = 本快照逐行重测（regex 族，FP §4 的 A/B/C 结构族不带 regex 标签，按 FP 结论续用）。

### 5.1 curl TOP-14（+PLT 桩簇）

| # | 函数 | can | dir | 净增分类摘要 | 族归属（本快照实测 tag） |
|---|---|---:|---:|---|---|
| 1 | getparameter | 532 | 780 | GAP 145 + LHEAD 165 主体 | DWARF 局部（B 族）主体 + DAT_LAB:7 ZSEXT:5 RAWSTACK:3 SWITCHD:3（FP: E/F 同域） |
| 2 | main | 487 | 921 | GAP 149 + LBOTH 40 + LHEAD 134 | RAWSTACK:30 SUBPIECE:23 CONCAT:5（FP: A 邻域 cast-write + M glibc 别名） |
| 3 | file2string | 113 | 118 | GAP 36 + LHEAD 55 | RAWSTACK:19 + 字符串字面量（C 族） |
| 4 | next_url | 92 | 147 | GAP 33 + LHEAD 37 | ZSEXT:11（A 下标形邻域，FP: SEXT48 显式算子） |
| 5 | parseconfig | 83 | 154 | GAP 29 + LHEAD 41 | DAT_LAB:11 IN_REG:8（constprop 命名行） |
| 6 | helpf | 77 | 199 | GAP 36 + LHEAD 37 | RAWSTACK:38 IN_REG:10（格式串域） |
| 7 | glob_range | 69 | 115 | GAP 30 + LHEAD 30 | ZSEXT:6 |
| 8 | myprogress | 64 | 96 | GAP 21 + LHEAD 30 | FS_OFF:6 RAWSTACK:6（浮点/extraout 域遗留） |
| 9 | my_get_token | 61 | 71 | GAP 19 + LBOTH 7 | 无标签干净 GAP 行 |
| 10 | glob_set | 61 | 196 | GAP 21 + LHEAD 20 | SWITCHD:3（I 族在账：JUMPTABLE-TABLEAPI） |
| 11 | match_url | 49 | 121 | GAP 20 + LHEAD 24 | ZSEXT:2（投影已 MATCH；文本层残差=命名/打印域） |
| 12 | my_get_line | 47 | 248 | GAP 13 + LHEAD 22 | FS_OFF:6 RAWSTACK:4（canon 侧函数） |
| 13 | glob_word | 16 | 316 | GAP 6 | canon 侧（canon↔direct 自差 330） |
| 14 | PLT 桩簇 | 11×9=99 | 7 | GAP 4 + LHEAD 5 ×9（strcpy/strchr/strrchr/fgets/memcpy/malloc/realloc/fopen/strcat/strdup/strstr 同形） | WARN:3/桩（D 族残尾，FS 后剩 ~1/3 强度：FP 时 11×12=132 → 现 11 行×9 fn） |

curl 三分类总账：BRIDGE 178 / CAST 44 / OVER 24 / **GAP_STRICT 686** / **LOST_BOTH 72** / **LOST_HEADLESS 782**（FP@8cf844a1: 182/44/20/688/72/790 — 总体微降，结构不变）。

### 5.2 httpd TOP-12

| # | 函数 | can | dir | 净增分类摘要 | 族归属（本快照实测 tag） |
|---|---|---:|---:|---|---|
| 1 | main | 761 | 778 | GAP 139 + LBOTH 203 + LHEAD 221 | WARN:32 SWITCHD:20 DAT_LAB:16（FP: A NEG-IDX 116 LBOTH + I + B/C + J） |
| 2 | ap_fini_vhost_config | 346 | 310 | GAP 79 + LBOTH 23 + LHEAD 103 | RAWSTACK:17 IN_RIP:10 ZSEXT:9（FP: H+G+E/F/B） |
| 3 | ap_update_vhost_from_headers | 152 | 184 | GAP 42 + LHEAD 66 | DAT_LAB:14 RAWSTACK:12 RVAL_ASSIGN:4 |
| 4 | ap_getparents | 109 | 133 | GAP 35 + LBOTH 26 | ZSEXT:17 |
| 5 | ap_pregsub | 91 | 99 | GAP 24 + LBOTH 16 + LHEAD 28 | ZSEXT:7（FL 后 −70 战果保持） |
| 6 | ap_ht_time | 53 | 127 | GAP 17 + LHEAD 14 | RVAL_ASSIGN:10（canon 侧函数） |
| 7 | ap_strcasecmp_match | 51 | 50 | GAP 18 + LBOTH 14 | ZSEXT:2 |
| 8 | ap_vhost_iterate_given_conn | 48 | 36 | GAP 19 | RAWSTACK:2（raw-param 命名域 EQ3 ③） |
| 9 | ap_parse_vhost_addrs | 45 | 307 | GAP 10 | canon 侧（自差 330） |
| 10 | ap_update_vhost_given_ip | 45 | 37 | GAP 11 + LHEAD 23 | IN_REG/IN_RIP/ZSEXT 各 2 |
| 11 | ap_strcasestr | 42 | 37 | GAP 13 + LBOTH 14 | IN_REG:2 |
| 12 | ap_strcmp_match | 40 | 42 | GAP 16 | ZSEXT:2 |

httpd 三分类总账：BRIDGE 166 / CAST 24 / OVER 90 / **GAP_STRICT 511** / **LOST_BOTH 405** / **LOST_HEADLESS 645**（FP: 166/24/90/512/406/645 — 净变化 −2）。

族规模横切（GAP+OVER 口径）：curl RAWSTACK 72 / ZSEXT 37 / DAT_LAB 14 / SUBPIECE 14 / WARN 11；httpd ZSEXT 45 / RAWSTACK 38 / IN_REG 32 / WARN 31 / RVAL_ASSIGN 27 / IN_RIP 21 / DAT_LAB 20。FP top-3 选题（FQ 下标形 / FR 打印机械修 / FS PLT 桩）有效性不受影响；FS（PLT 桩）已从 132 → ~99 行（部分被 FT 前置车道吸收）。

---

## 6. 记分板汇总

| 层级 | 口径 | curl | httpd | 合计 |
|---|---|---:|---:|---:|
| L1 gate | 逐函数 skeleton diff=0 | **51**/124（41.1%） | 0/29 + 1/470（全量 vs direct） | 51/153 门禁面（33.3%） |
| L1 strict | 函数体逐字节相等 | 4/124（3.2%） | 0 | 4/153（2.6%） |
| L1 真代码 | gate 口径剔除桩 | **1**（GetStr） | **0** | 1 |
| L2 投影 | stage+snapshot identical | 3/6（curl 函数） | 0/1（httpd main） | **3/7（42.9%）** |
| L2 结构 | stages 恒等（结构层数） | 6/6 | 1/1 | 7/7 |

**读法**：两级合看，当前"完整对齐"的真实存量 = 3 个投影 MATCH 函数（next_url/match_url/parseconfig）+ 1 个真代码文本全同（GetStr）+ 50 个桩形文本全同。投影 MATCH 的三个函数文本层仍有 49-92 行残差（§5.1 #4/#5/#11）——**投影 MATCH ≠ 文本 MATCH**，两级互补缺一不可。

## 7. 观察与建议（供 root 排题）

1. **httpd 真 L1 = 0 是最大空白**：最小残差 ap_pregfree 仅 2 行、4 行档 3 个（ap_get_server_built/ap_getword_nc/suck_in_APR）——单 wave 内 httpd L1 破零（目标 3-5 函数）成本低、记分板收益直接。
2. **getparameter 序数新前沿 186 未登记**（oppool2 栈偏移 +8 常量族，`c:4e8 vs c:4f0`/CROSSBUILD `fb10 vs fb18`）；与 FP 时代 155 switchnorm 相比已前移 31 stage，建议登记新 TODO 行再派车道。
3. PLT 桩簇（D 族）残强 ~99 行 ×同形复制——FS 选题剩余价值仍在（S 难度）；curl RAWSTACK 72 行横切 8 函数（E 族）为无争议 GAP 大头。

## 8. 产物清单（/dev/shm/rugra-tests/sb-scoreboard/）

- `run_gates.sh` / `run_projections.sh`（复现链：三门禁+双跑+7 投影+对拍）
- `gates/`：curl.c(+run2)/httpd_gate.c/httpd_full.c + *.compare.txt + *.byteexact.txt + 7×projection + 7×bisect.txt + projections.log + skeleton_identical.txt + top_family_attribution.txt
- `curl_resid.summary.txt`/`httpd_resid.summary.txt`/`{curl,httpd}_resid.detail.txt`（FP 判类法重算，自校验通过）
- `byte_exact_scan.py`（L1 严格字节扫描器）/ `resid_decomp_gb.py`（FP 脚本路径适配版）
- target：`/dev/shm/rugra-targets/sb-scoreboard`（lane 收尾回收）

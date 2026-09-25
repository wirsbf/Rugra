# Lane FP — 合并态（master 8cf844a1）全量残差图谱

- 日期: 2026-09-24 (Asia/Shanghai)
- worktree: /dev/shm/rugra-worktrees/residmap, branch **wt/residmap**, 基 = 亲父 **8cf844a1**（链集成态: d09fa30f × 54fa3f82, 含 FL bc22461d）
- oracle: Ghidra 12.0.4 e40ed130; CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-residmap（fast-release）
- 性质: 只读分析（零 src 改动）; 写域 = /dev/shm 产物 + docs 报告 + TODO 登记
- 方法: EV `delta_decomp.py` 判类法的合并态版本（`resid_decomp.py`, 本目录）——
  diff 基 = canonical golden（门禁准绳）, 判据基 = direct-runner golden（EG2/FI 裁定库级真值）;
  逐函数骨架（compare_ghidra.normalize_skeleton 同口径）± 多重集相消, 净增/净删逐行判类
  + 形态族标注。**自校验: 逐函数 diff 计数精确复现 compare 工具总门禁数（curl 2147 / httpd 2059）**。

## 1. 基线复验（root 委托项, 亲测）

| 门禁 | 实测 | 任务预期 | 判定 |
|---|---|---|---|
| curl E2E canon | **2147/0/0**（124/124, 35.4s） | 2147/0/0 | ✅ 一致 |
| httpd E2E canon | **2059/0/0**（29/29, 3.9s） | 2153/0/0 | **优于预期 −94** |
| 双跑确定性 | curl/httpd `cmp` 双双恒等 | — | ✅ |

httpd −94 归因: 任务书预期 2153 = EQ3 round-3 在 **54fa3f82**（cm3 测试合并）上的数字;
8cf844a1 是 root 的正式集成 merge, 多携带 **FL 车道**（bc22461d, 分支目标 1 字节 code-ref）
——EQ3 §5-4 明言"FL 叠加态未经亲测,并入后建议重跑双语素门禁"。本次即该叠加态的首测:
FL 改善在合并形态上生效, httpd −94（ap_pregsub 161→91 = −70 领衔）, curl 不变。
**链集成态双优结论在正式 master 上成立且更强**。

## 2. 三分类总账（multiset 视图; diff 计数 = multiset + 搬移行）

| 类 | curl | httpd | 含义 |
|---|---:|---:|---|
| BRIDGE（= direct 同函数逐字） | 182 | 166 | 库级正确桥接行（direct 有, canon 无） |
| CAST（cast 归一后命中基线） | 44 | 24 | 同构形, cast 拼写差 |
| OVER_BRIDGE / OVER_CANON / OVER_CAST | 5/14/1 | 5/15/70 | 超出基线多重数的份 |
| **GAP_STRICT（双基线皆无）** | **688** | **512** | 合并态净增的无证据行 |
| **LOST_BOTH（双基线都有, merged 缺）** | **72** | **406** | 真缺内容行 |
| **LOST_HEADLESS（仅 canon 有, direct 无）** | **790** | **645** | headless Java/DWARF 层专有形（FI 判例域） |
| 搬移行（diff 计数 − multiset） | 352 | 216 | 同文本换位 |
| **canon 门禁总数（diff 视图）** | **2147** | **2059** | |
| 对 direct 总距离（参照） | 4236 | 2702 | canon↔direct 自身距离: 4379 / 2597 |

要点: 合并态在双基线间**略偏 canon 侧**（canon 距离 < direct 距离, 两语素皆然）——
EV 时代"merged 更远离 direct"的形态已反转。残差大头从"净增带标签族"迁移到
**GAP 无标签干净行 + LOST 侧**（EV 只分解 master→merged 净增, 未做对 canon 的 LOST 分解, 本图首次成账）。

## 3. top-20 逐函数残差 + 形态族标注

### httpd（29 函数全序, 括号 = can/dir 距离）

| # | 函数 | can | dir | 主导族 |
|---|---|---:|---:|---|
| 1 | main | 761 | 778 | **A**（NEG-IDX 写 116 LOST_BOTH + cast-write ~44 GAP）+ I（switch/goto ~60）+ B/C（local/字符串 221 LHEAD）+ J（WARN 31）+ G（in_RIP） |
| 2 | ap_fini_vhost_config | 348 | 314 | H（rval 赋值 7）+ G（in_RIP 5）+ E+F+B（LHEAD 103） |
| 3 | ap_update_vhost_from_headers | 152 | 184 | GAP 42 混合（in_/extraout 残尾, EQ3 ② 域）+ LHEAD 66 + BRIDGE 25 |
| 4 | ap_getparents | 109 | 133 | GAP 35 + LBOTH 26 + CAST 5 |
| 5 | ap_pregsub | 91 | 99 | GAP 24 + LHEAD 28（FL 已收 −70） |
| 6 | ap_ht_time | 53 | 127 | canon 侧函数（dir 远）; LHEAD 14 = 时间格式串（C 族） |
| 7 | ap_strcasecmp_match | 51 | 50 | GAP 18 + LBOTH 14 |
| 8 | ap_vhost_iterate_given_conn | 48 | 36 | raw-param 命名域（EQ3 ③）; GAP 19 |
| 9 | ap_parse_vhost_addrs | 45 | 307 | **canon 侧函数**（canon↔direct 自差 330）; GAP 10 |
| 10 | ap_update_vhost_given_ip | 45 | 37 | GAP 11 + LHEAD 23 |
| 11 | ap_strcasestr | 42 | 37 | GAP 13 + LBOTH 14 |
| 12 | ap_strcmp_match | 40 | 42 | GAP 16 |
| 13 | ap_make_dirstr_prefix | 40 | 40 | GAP 10 + LBOTH 14 |
| 14 | ap_getword | 36 | 28 | GAP 9 |
| 15 | ap_field_noparam | 30 | 24 | GAP 10 + LHEAD 11 |
| 16 | ap_os_is_path_absolute | 28 | 35 | GAP 7 + LHEAD 13（typed 拼写 gcc 失败族, EQ3 ⑤） |
| 17 | ap_make_dirstr_parent | 22 | 22 | GAP 8 + LHEAD 11 |
| 18 | ap_matches_request_vhost | 20 | 56 | canon 侧; GAP 6 |
| 19 | ap_count_dirs | 18 | 18 | GAP 5 + LBOTH 8 |
| 20 | ap_init_vhost_config | 14 | 14 | GAP 4 + LBOTH 4 |

### curl（124 函数; 15-26 位为同形 PLT stub 簇）

| # | 函数 | can | dir | 主导族 |
|---|---|---:|---:|---|
| 1 | getparameter | 532 | 780 | **B**（local_5b8/5a8 DWARF 局部 165 LHEAD 主体）+ E（pCStack_5b8）+ F（SUB81/ZEXT18）+ DWARF 全局 aliases 结构形 |
| 2 | main | 487 | 923 | A 邻域（GAP 151: cast-write + CONCAT44/71 部分写槽）+ M（glibc 别名）+ B（LHEAD 134）+ LBOTH 40 |
| 3 | file2string | 113 | 118 | E + 字符串字面量; LHEAD 55 |
| 4 | next_url | 92 | 147 | **A**（`glob->pattern[V].content…` vs `*(&glob->pattern + SEXT48(V))->…` 下标形）+ 枚举名（UPTSet）|
| 5 | parseconfig | 83 | 154 | GAP 29 + LHEAD 41（constprop 命名行） |
| 6 | helpf | 77 | 199 | 字符串格式域 GAP 36 + LHEAD 37 |
| 7 | glob_set | 71 | 196 | I（switchD/标号族, FK 已移交）+ GAP 25 |
| 8 | glob_range | 69 | 115 | GAP 30 + LHEAD 30 |
| 9 | myprogress | 65 | 97 | GAP 22 + BRIDGE 6（extraout 域 EQ 遗留） |
| 10 | my_get_token | 61 | 71 | GAP 19 + LBOTH 7 |
| 11 | match_url | 50 | 110 | GAP 15 + BRIDGE 6 |
| 12 | my_get_line | 47 | 248 | canon 侧; GAP 13 |
| 13 | glob_word | 16 | 316 | canon 侧（canon↔direct 自差 330） |
| 14 | _start | 12 | 13 | 参数定型残尾 GAP 6 |
| 15-26 | strcpy/strchr/strrchr/fgets/memcpy/malloc/realloc/fopen/strcat/strdup/strstr/__ctype_b_loc | **11×12=132** | 7 | **D 族: PLT stub 同形批量**（见 §4-D） |
| 27+ | _init 10 / __libc_csu_init 9 / __do_global_dtors_aux 8 / tm_clones×2/frame_dummy 4 | | | D/签名行小残尾 |

## 4. 家族聚类与量化（修复难度 S/M/L）

| 族 | 形态 | curl 行 | httpd 行 | 判类 | 涉及域（猜测） | 难度 |
|---|---|---:|---:|---|---|---|
| **A 下标形缺失** | canon/direct `plVar12[-1] = 0x12ba26;`（httpd main ×116/canon ×133/direct）vs merged `*(undefined8 *)((int *)V - 8) = …`; curl `glob->pattern[V].content` vs `*(&glob->pattern + SEXT48(V))->content` | ~41 | ~170 | LOST_BOTH+GAP | printc PTRADD/PTRSUB 下标发射 + varmap 指针→元素 typelock | **M** |
| **B headless DWARF 局部** | `local_5b8`（带类型）/ `/* Unresolved local var */` 警告 | 154 | 108 | LOST_HEADLESS | 驱动 DWARF 局部符号层（FI"后续口径"域） | L-M |
| **C headless 字符串/常量** | `puts("…")`/`__printf_chk(1,"…")`/`&DAT_` 字符串实参 | 19 | 85+ | LOST_HEADLESS | 驱动数据段字符串恢复 | M |
| **D PLT stub 形态** | 签名缺返回类型、**`return = uVar1;`（不可编译 C）**、`PTR_00116e90` 裸地址（canon `PTR_strcpy_…`）、缺 param-lock 警告 | **132（12 fn ×11）** | — | GAP+LHEAD | printc 返回发射 + 符号标签命名 + 警告集 | **S** |
| **E typed-stack 槽** | `uStack_248/pCStack_5b8/pFStack_240/aiStack_858` 声明+使用（RAWSTACK 残尾 71/38） | 60 | 20 | GAP | varmap ScopeLocal 高层提升/槽合并 | M |
| **F 宽度后缀算子** | `ZEXT48/SEXT14/SUB81/SUB84/ZEXT18` 印成显式算子; curl 语料双基线 0 命中 | 51 | 50 | GAP | ruleaction subvar/transform 折叠 | M |
| **G in_RIP 寻址** | `*(undefined8 **)(in_RIP + LIT)`、`V = in_RIP` | — | 21 | GAP | RIP 相对 typelock（CHAINMERGE-INRIP 已登记） | M（在账） |
| **H 对右值赋值** | `*V + LIT = V;`（不可编译 C, 缺陷级） | — | 27（5 fn） | GAP | printc 指针算术赋值发射 | S-M |
| **I switch/goto 结构** | `case LIT:`×19、`goto LAB`×22、`switchD_caseD` 标号 ×20+7 | 7 | 76 | LOST | JUMPTABLE-TABLEAPI + ACTION-REWORKFIX-STRUCT（均已登记） | M（在账） |
| **J WARN 地址格式** | `(,2c07d)` vs canon `(ram,0x0012c463)` | 12 | 31 | OVER | printc 警告格式 | S |
| **K EV 主族残尾** | in_ 参数寄存器 32+9 / EXTRAOUT 1 / RAM 4+1 / CONCAT 2+5（全部 OVER 类） | 17 | 39 | OVER | param attach 域（已登记） | 残尾 |
| **L 签名行差异** | `void main(undefined4 V,undefined8 V)` 参数无名、`getparameter_constprop_0` 下划线名 | 42 | 48 | 混合 | printc 原型/参数命名 | S |
| **M glibc 别名 churn** | `__dest/__s/__ptr/__haystack/__filename` 位置差 | 148 | 43 | 混合 | libc 原型 ingest 命名 | M（弥散） |
| **N register 空间泄漏** | `long registerLIT;`/`register0x00000000` + 畸形 cast 行 | 9 tok | 4 tok | GAP | lifter/printc | S |
| **O DAT_LAB 裸标号超量** | LAB_/DAT_ 超基线多重数 | 22 | 20 | OVER | 标签域（EX2 后残尾） | S |

> 注: 行数为 multiset 口径, 一行可属多族; A/B/C 为最大三族。gcc 审计口径的 25 FAIL（curl）
> 与 D/H 族（`return = V;`、rval 赋值）及 typed 拼写直接相关。

## 5. 对照旧 EV 台账（delta_decomp.md, 2026-09-23, 停车链时代）——族存亡

| EV 族（当时规模） | 现状 | 判定 |
|---|---|---|
| in_ 参数寄存器 158 记号/148 行 | 32+9, 全 OVER 类 | **基本消亡**（EH/EY2/RC 参数定型吸收） |
| RAM 裸全局 59 | 4+1 | **消亡** |
| CONCAT 拼装 48 | 2+5 | **消亡**（FF CONCAT/RAM 车道战果稳固） |
| EXTRAOUT 变体命名 39 | 1 | **消亡** |
| unique 空间泄漏 4 | 0 | **消亡** |
| puVar 过度物化栈写 74（main） | **变形**: cast 指针写 `*(undefined8 *)((int *)V - 8) = …` + NEG-IDX 缺失（A 族） | **形态迁移**（非消亡: 物化→cast 化, 且基线形以 `p[-1]` 出现） |
| WARN 格式 41 | 43（31 httpd main + 12 curl） | 存活, 量稳 |
| in_RIP 21 | 21 | 存活, 量不变（登记在案） |
| ZSEXT 22 | 101（44+38 GAP + over） | **增长 ~4.5×** |
| RVAL_ASSIGN 净+7 | 27 | **增长 ~4×**（缺陷级） |
| SUBPIECE 拼写 4 | 18 token | 增长 |
| BADTYPE 9 | 2+2 | 残尾 |
| （EV 未成图） | **新浮现**: A 下标形缺失（httpd 最大单族 116 LOST_BOTH）、B/C headless 层（LOST 侧首 decomposition, 1435 行）、D PLT stub 簇（132）、N register 泄漏、L 签名行 | **新族** |

结构性结论: EV 时代的"带标签净增族"（in_/RAM/CONCAT/EXTRAOUT）已被链+master 各车道消灭 85-100%;
残差重心移到三类——①**形态等价但印法不同**（A/E/F/L/J: ~500 行）、②**headless 专有层**（B/C: 1435 行,
库级无罪但门禁计数在账）、③**结构/内容真缺口**（I + LOST_BOTH 中非 A 部分）。
EV 台账作为车道选题依据已过时, 本图接管。

## 6. 下一波选题建议 top-3（按杠杆排序; FM/FN/FO 在飞车道排除）

### FQ（首推）: PTRADD/PTRSUB 下标形发射 + 指针元素 typelock —— A 族
- 证据: httpd main 双基线同形 `p[-1] = const`（canon ×116 / direct ×133）而 merged 印 cast 解引用;
  curl next_url/glob 族 `glob->pattern[V].content` vs `*(&glob->pattern + SEXT48(V))->content` 同族。
- 杠杆: httpd −150~−250（main/ap_fini/update_vhost 链）, curl −30~−60。**双基线同形 = 无争议库级正确形态**。
- 域: printc 表达式发射（Ghidra printC 对 PTRSUB 常量偏移×指针元素类型走下标形）+ varmap typelock 前提;
  建议先在 oracle 侧核实下标形触发条件（指针类型 + 偏移整除元素宽 + 常量符号）再动 printc。
- 难度 M; 验收 = httpd ≤1900 / curl ≤2120 且 defects/numbering 双零、三投影 MATCH 保持。

### FR: 打印侧机械批修（H+J+N）—— RVAL_ASSIGN 27 + WARN 地址格式 43 + register 泄漏 13
- 含**不可编译 C 缺陷类**（`*V + LIT = V;`）, 与 gcc 审计 FAIL 集直接挂钩; 单点小改、面窄。
- 杠杆: −80~−150（httpd 为主）; 难度 S-M; 验收 = 该三 token 族语料清零 + 双门禁不回退。

### FS: PLT stub 形态批修 —— D 族
- 12 函数 ×11 行 = 132 行 curl 门禁（6.1%）, 同形复制粘贴级; 顺带收 `return = uVar1;` 缺陷形
  与 `PTR_00116e90`→`PTR_strcpy_00116e90` 符号标签族（另有 ~94 行 PTR_ 标签差可同域收割）。
- 难度 **S**; 面窄（printc 返回发射 + 驱动符号标签 + stub 警告集）; 验收 = 12 stub 函数 diff ≤3。

### （战略备选, 不计入 top-3 快车道）
B+C headless 层驱动模拟（DWARF 局部命名/类型回附 + 字符串常量, 1435 行 LOST_HEADLESS）——
FI 判例已裁"库级无罪, 追平 headless 属 varmap/fspec 驱动域新工作"。若 root 决定追,
是一次性大杠杆（curl getparameter 532 中 ~165 直接相关）, 但工程量大且改变"库真值"口径, 建议独立立项裁决。

## 7. 产物清单（/dev/shm/rugra-tests/sb-residmap/）

- curl_8cf844a1.c / httpd_8cf844a1.c（+ *_run2.c 双跑恒等）+ *.stderr + *.compare.txt（逐函数门禁底表）
- resid_decomp.py（判类脚本, gate 自校验通过）/ token_census.py
- curl_resid.summary.txt / httpd_resid.summary.txt / curl_resid.detail.txt / httpd_resid.detail.txt
  （124+29 函数 × 10 类逐行台账）
- merged_residmap.md（本文件）
- target: /dev/shm/rugra-targets/sb-residmap（lane 收尾回收）

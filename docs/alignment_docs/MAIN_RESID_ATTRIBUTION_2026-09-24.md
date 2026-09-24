# Lane GI — main 残差重归因（httpd main + curl main）

- 日期: 2026-09-24 (Asia/Shanghai)
- worktree: /dev/shm/rugra-worktrees/mainattr2, branch **wt/mainattr2**, 基 = 亲父 **b5b949dd**（GH lane 顶）
- oracle: Ghidra 12.0.4 e40ed130; canon golden = `tests/golden/ghidra_<bin>_1204.c`;
  direct-runner golden = C++ 库真值判据基（EG2/FI 判例口径）
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-mainattr2（fast-release）
- 性质: 归因优先 + 域内修复一件（printc STORE 双发射合并冲突修复）
- 可重跑脚本: /dev/shm/rugra-tests/sb-mainattr2/main_resid.py（BOOL/NAME/NUM/TYPE/MIXED/OTHER/IND
  逐行判类 + LIB/CANON/GAP 双侧 golden 判性; gate 自校验通过 417/715）

## 0. 基线复验（亲父 b5b949dd 亲测）

| 门禁 | 实测 | 任务预期 | 判定 |
|---|---|---|---|
| curl E2E canon | **1822/0/0** (124/124) | ≈1845 | ✅ 量级一致（略优） |
| httpd E2E canon | **1756/0/0** (32 fn) | ≈1778 | ✅ 量级一致（略优，GH 核心类型修正收益） |
| main 单函数 | curl main 417 / httpd main 715 | — | FP 时代 487/761 → 双降 |

EV 台账确认过时：FP 图谱（8cf844a1）的 main 残差 487/761 已被 GE/GC/GF/GH 四连降 +
链上各车道压缩到 417/715；EV 主族（in_/RAM/CONCAT/EXTRAOUT）在 main 内已消亡。

## 1. 修复（src/printc.rs，本 lane 域内）

**PRINTC-STORE-DBLEMIT-0001** — FR 车道 merge 33418058（75d51e03 × 4aee0d60）冲突解错：
FQ 侧的手射 `tag_op("*")`+pushVn 与 FR 侧的 dereference token 协议路径**双双保留**，
STORE 地址发射两次 → 全语料 175 行不可编译 C（httpd 145 / curl 30; httpd main 98）。
根因钉死（实验二分）: 亲父 75d51e03 httpd 双发射=0；33418058=145；此后各代恒 145。
FR 的 Differential 声明 "httpd identical" 与事实不符（merge 后未复跑 httpd 门禁）。

修法（printc.cc:500-518 opStore 单发射语义）: deref_form → 仅 pushOp(dereference token)
+pushVn(in1)；usearray → 仅 `m|=print_store_value`（无 token）。删除手射 `*` 前缀与
重复 pushVn。修正了 usearray 形此前也被错误压 token 的问题（FR 路径 push 的是
self.mods 而非带 flag 的 m）。

## 2. 前后数字（亲父 b5b949dd 本地复现基线，亲测）

| 门禁 | 前 | 后 | 判定 |
|---|---|---|---|
| curl E2E canon | 1822/0/0 | **1744/0/0** (−78) | 全改善 |
| httpd E2E canon | 1756/0/0 | **1700/0/0** (−56) | 全改善 |
| 逐函数 | — | curl 14 fn 改善 / httpd 9 fn 改善 | **零回退** |
| 双发射行 | httpd 145 / curl 30 | **0 / 0** | 清零（续跑复核计数口径: 拼接形 `\)\*\(` httpd 140/curl 19、严格重复组 `\*(\([^=]*\))\1` httpd 129/curl 12，修复后两口径均 0/0） |
| gcc 审计 | curl 102OK/22FAIL, httpd 13OK/16FAIL | **104/20**, **23/6** | httpd −10 FAIL |
| 五投影 (RUGRA_MIRROR=1) | next_url/match_url/myprogress/getparameter/parseconfig | **MATCH ×5 保持** | ✓ |
| 双跑确定性 | — | curl/httpd cmp 恒等 | ✓ |
| printc/cast 单测 | — | 12/12 + 20/20 | ✓ |

main 单函数: curl 417→413（−4）; httpd main 715 持平（双发行与单发行对 canon 基各算 1 行差，
下标族另案——见 §3）。

## 3. main 新分解账本（修复后态；n_mc = canon 基 diff 数）

### httpd main = 715（net+ 230 / net− 407 / 搬移 78）

| 族 | 行数 | 判性（canon/direct 双侧） | 域 | 修复建议 |
|---|---:|---|---|---|
| **SP cast-store**（`*(undefined8 *)((int *)V - LIT) = X`） | **101 GAP**（main 97 + 邻域） | **LIB 可修**: direct main 有 **150** 处 `piVar10[-1] =` 下标形（少数早期 store 同位 deref 形 `(int8)piVar10 + -8`）; canon 134 处 `plVar12[-1]` | ruleaction INT_ADD→PTRADD 元素重标度 + varmap SP-alias 类型（**FQ3 已让渡 FV2/FW2/FS3 后继，在账**） | 杠杆 ~210（GAP 101 + LOST 对偶 ~110）; 注意 Rugra 印法 `(int *)p - 8` 是 C 元素算术（语义错 -32B），oracle `(int8)p + -8` 是整数算术 |
| 语句/声明 LOST（`if(V==LIT){`×15、`}`×37、apr_pool_tag/apr_array_make 链、`code *V;`） | 170 LIB_BOTH | 同语句异控制形: Rugra while(true)+goto+break, 双 golden 结构化 if 块 | blockaction 结构域（JUMPTABLE/ACTION-REWORKFIX-STRUCT 在账; 与 HTTPD-MAIN-POSTBLOCKSTRUCT-HANG 相邻） | 结构化收敛后此族随 SP 族一起落 |
| **headless 字符串**（`V = "LIT"` ×8、ap_log_error("LIT"…)） | 67 HEAD | direct main 字符串 = 0 | FI 判例域（driver 字符串恢复层） | root 裁决是否追 headless 层 |
| **headless DWARF 局部命名**（`local_d0/local_c8/local_70` 声明+使用; Rugra = uStack_*/auStack_*） | 44 HEAD | direct 用 xStack_a8/xVar（库世界无 local_* 命名） | FI 判例域 | 同上 |
| **WARN unreachable**（`/* WARNING: Removing unreachable block(ram,LIT) */`） | 31 GAP | canon main = 1, direct = 0 | blockaction 结构差（Rugra 结构化多产出 31 个不可达块再删） | 归 blockaction finalization 域; 与 B 结构族同根 |
| 裸标号/goto（`LAB_0012b8c0:` 等） | 12 GAP | 双 golden 无此形 | blockaction | 同 B |
| RAWSTACK 声明差（uStack_40 vs local_40） | 9 GAP | direct 有 xStack_40 同位（类型字母差） | 命名域（E 族残尾） | 低杠杆 |
| 参数/in_RIP/TYPE/BOOL 杂项 | ~21 | 混合 | 各在账小族 | — |
| 搬移行（同文本换位） | 78 | — | diff 计数口径 | 随结构族消 |

> 结构总判: httpd main 残差三大块 = **SP 下标族 ~210（库级可修, 在账）+ headless 层 111+
> 块结构 ~43 + WARN 31**; 双发射缺陷族（本 lane 修复前占 98 行门禁读数）已清零。

### curl main = 413（net+ 155 / net− 138 / 搬移 120）

| 族 | 行数 | 判性 | 域 | 修复建议 |
|---|---:|---|---|---|
| **glibc 原型参数名**（`strstr(__haystack,"LIT")` vs canon `strstr(V,"LIT")`） | **48 GAP** | 双 golden 无 `__haystack`（direct 裸 BFD 无 libc 签名; canon headless 用裸 V） | fspec/libc 原型 ingest 命名（FP 图谱 M 族, 在账弥散） | **curl main 单族第一大**; 参数 attach 点收敛可一次收割 |
| 配置语句异形（`V = (char *)LIT`/`V = false`/for 头等 LOST + 对偶 plus） | ~80 混合（HEAD 84 + LIB_BOTH 35 中大半） | 同语句异形 | 混合（headless+类型小族） | 随各族收敛 |
| **RAWSTACK 槽命名**（uStack_248/puStack_238/iStack_230 声明+使用 vs canon local_*） | 28（23 GAP + **5 LIB**） | direct curl main 有 iStack_230/xStack_270 同名同位（5 行逐字 LIB 正确仍计 canon 差） | 命名域 + headless（local_*） | FI 判例域 |
| **piece/concat token**（`CONCAT44(uStack_248._4_4_,argc - LIT)`、`(union_5a7)V._8_16_`） | 12 GAP | 双 golden 无 `._8_16_` 拼写; union_5a7 vs anon_union_16_3… = DWARF-ANON-TYPENAME-0001 | ruleaction 部分写折叠（FF 族残尾）+ 匿名命名（在账 NO_ORACLE） | 在账 |
| 字符串实参（`strnequal("LIT",…)` plus / `strstr(V,"LIT")` minus） | 16 | plus 侧 = glibc 名 + 双侧字符串都有; minus 侧 HEAD | M 族 + headless | 同 M 族 |
| 局部命名/BLOCK_SHAPE/param | 11 | HEAD/结构 | 在账小族 | — |
| 搬移行 | 120 | — | diff 口径 | — |
| SP cast-store | 2 GAP | 同 httpd 族（curl main 少量; corpus 52 行集中在 next_url 13/getparameter 8） | 同 FQ3 让渡域 | 同 httpd |

> curl main 无 WARN 族、无双发行残尾; 三大块 = **glibc 参数名 48 + headless 语句/命名 ~115 +
> piece token 12**。

## 4. top-3 修复建议（按杠杆排序）

1. **ruleaction INT_ADD→PTRADD 元素重标度（SP-alias 动态栈写）** — httpd main ~210 行
   （GAP 101 + LOST 对偶 ~110）+ curl corpus 52。direct golden 亲证库级正确形态 =
   `piVar10[-1] = X`（150 处）; 前置 = SP-alias 变量获得指针类型（varmap 域）+
   INT_ADD→PTRADD 重标度（ruleaction 域, FV2/FW2/FS3 让渡在账）。附带修掉
   `(int *)p - 8` 的 C 元素算术语义错位。
2. **glibc 原型参数名 attach 收敛（curl main 48）** — `__haystack/__ptr/__filename` 位点
   收敛到裸参数名; FP 图谱 M 族（curl 148/httpd 43 → 现 main 单户 48）; fspec/libc
   ingest 域。
3. **WARN unreachable 计数差（httpd main 31）** — Rugra 结构化产出 31 个不可达块
   （canon 1/direct 0）; blockaction finalization 域, 与 main 结构族同根; 修复入口 =
   复盘 main 的 while(true)+goto 生成路径上多产生的空后继块。

### （战略备选, 不计入 top-3）
headless 层追平（httpd 111 + curl ~115: 字符串恢复 + local_* 命名）——FI 判例域,
需 root 裁决是否立项 driver 层模拟; 一次性大杠杆但改变"库真值"口径。

## 5. 产物清单（/dev/shm/rugra-tests/sb-mainattr2/）

- main_resid.py（判类脚本, gate 自校验 curl 417/httpd 715 通过）
- {curl,httpd}_b5b949dd.c（基线输出）/ {curl,httpd}_main.udiff.txt / {curl,httpd}_main.detail.txt
- {curl,httpd}_main.lost.txt / *_before|after.perfunc.txt（逐函数零回退底表）
- httpd_main_fixed.projection + 五投影 *.projection（MATCH ×5 底档）
- verify/（GI2 续跑独立复跑输出: {curl,httpd}_cur.c + run log）

## 6. GI2 续跑独立复验（配额墙中断后接手 agent 亲测，2026-09-24）

前代在账本写毕、提交前中断。本节为接手 agent 在同一 worktree / 同一 dirty 态上的
**全量独立复跑**结果（非转抄上表）:

| 检查 | 亲测值 | 与 §2 声明 |
|---|---|---|
| curl E2E canon 门禁 | **1744 / 0 defects / 0 numbering**（124 fn） | ✅ 一致 |
| httpd E2E canon 门禁 | **1700 / 0 / 0**（32 fn） | ✅ 一致 |
| 基线复核（b5b949dd 存档输出对 canon） | curl 1822/0/0; httpd 1756/0/0 | ✅ 一致 |
| gcc 审计 | curl **104 OK/20 FAIL**; httpd **23 OK/6 FAIL** | ✅ 一致 |
| 双发射 | 两口径均 **0/0** | ✅ 一致 |
| main 判类 gate 自校验 | curl 413 / httpd 715 双 OK | ✅ 一致 |
| 逐函数 | curl 14 改善/0 回退（124 fn）; httpd 9/0（32 fn） | ✅（§2 的 13 已更正为 14） |
| 确定性 | 复跑逐函数表与前代 after 表**逐项相等**（httpd 30/30, curl 80/80） | ✅ |
| 五投影 | next_url/match_url/myprogress/getparameter.constprop.0/parseconfig.constprop.0 与 oracle projection 逐字节相等，仅 META `side=`/`producer=` 两头行异 | ✅ MATCH ×5 |
| SP 族锚点复数 | rugra-httpd main 101 行 `((int *)V ± N`; direct 152 / canon 136 下标形 | ✅ §3 口径成立 |
| printc/cast 单测 | 12/12 + 20/20 | ✅ |

已知无关项: `cargo test --lib` 全量有 **18 个既有失败**（funcdata SSA/alignment 系 +
heritage::test_heritage_creation），单跑皆过、单线程复现、且在亲父 b5b949dd 原始
printc.rs 下同样 18 个失败 — 为亲父已存在的测试间状态污染，非本修复引入，不在本 lane
write-set 内（建议另立 TODO）。


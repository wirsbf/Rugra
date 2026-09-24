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


## 7. GK 后续（wt/spindex，2026-09-24）：SP 下标族 ruleaction 环节落地

§3/§4-1 的 SP 下标族两环节之一（ruleaction INT_ADD→PTRADD 改写）已修复
（`RULE-SPINDEX-UNSIGN-0001`，见 TODO_BOARD GK 行）：`AddTreeState::
calc_subtype` 头部 `tmpoff < size` 比较在有符号化移植下把负字节偏移
（向下生长栈 SP-alias）误入 `offset = tmpoff` 分支清零 multsum 并判
`valid=false`，oracle（ruleaction.cc:6256，uint8×int4 → 无符号）走模除
路径生成 PTRADD。亲测（基=亲父 75b5d18f）：httpd 1698→**1628**（main
715→645，SP-cast 形 101→40、下标形 33→94，向 canon 136/direct 152
收敛）；curl 1744→1745（唯一 +1 = main 破损 for 单行变 oracle 同构
while 两行）；双门禁 defects/numbering 0/0；逐函数零回退；五投影
MATCH ×5；ptrarith_addtree oracle fixture 5 用例双侧重跑 MATCH。

varmap 环节（SP-alias 符号类型 `long[4]` 固定点 + local_d0/local_d8
缺失）未动，登记 `VARMAP-SPALIAS-RETYPE-0001` +
`RULEACTION-SPALIAS-INDIRECTPTR-0002`（含探针实证的符号表/alias 轮
演变数据与调查入口）。

---

# Lane MAIN2 续章（wt/main2，2026-09-24 晚）— 当前态重分解 + 印刷域三件修复

- 基 = 亲父 **37014110**（SPALIAS 顶）亲测基线：curl **1329/0/0**、httpd 门禁面 **1445/0/0**（==任务书预期）。
- oracle: Ghidra 12.0.4 e40ed130; canon = `tests/golden/ghidra_httpd_1204.c`;
  direct-runner = 库真值判据基。CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-main2。
- 探针（未入库）：examples/main2_probe.rs = httpd driver 副本 + 终态 op/类型 dump
  （MAIN2_OPDUMP/MAIN2_OPDUMP_FUNC）；判类器 = sb-mainattr2/main_resid.py 适配路径。

## 1. 修复前重分解（httpd main = 645，自校验 OK）

| 族 | Rugra 侧 | canon 侧 | 判性 | 域 |
|---|---:|---:|---|---|
| **SP-cast 印刷族** `((int *)V ± LIT)` | 40 | — | GAP（canon/direct 皆无此形;direct= `(int8)p + -8` 整数算术,canon= `((long)p + -8)`/下标形） | printc（本 lane 修复） |
| `(undefined8 *)` 值 cast 杂项 | 49 | 5 | 混合 | printc/typeprop |
| WARN unreachable | 31 | 1 | 结构差 | blockaction finalization |
| SWITCHD/goto/case | 9+ | 43 | 跳表边 | JTEDGE 车道（并行） |
| 字符串字面量 | — | 69 | HEAD | FI 判例域 |
| local_* DWARF 命名 | — | 24 | HEAD | FI 判例域 |
| 下标形 `V[-LIT]` | 2 | 61 | 双侧目标形（direct 152/canon 134） | typeprop 传播层（TYPEPROP-ADDRSLOT-PERSIST-0001） |
| `V + -LIT` 正典拼写 | 0（全被后处理改写为 `- LIT`） | 666（语料级） | **纯印刷差** | prettyprint（本 lane 修复） |

## 2. 根因链（探针实证）

SP-cast 族链（以 0x2b86f `= 0x2b874` LINE-store 为例，终态投影+类型 dump）：
```
INT_ADD out=u:…92[long] in=CAST(RSP→long)[long], c:-8
CAST(RSP→long)                       ← setcasts metain 臂（oracle 同构 (int8)/(long)）
CAST(INT_ADD-out → register:20)      ← 消费侧 ptr(valueType) CAST（oracle 无：其地址已是 ptr 型）
```
oracle：InferTypes 值→地址反向传播（TypeOpLoad/Store::propagateType，typeop.cc:493-498/563-566）
+ typeOrder（SUB_PTR=6 < SUB_INT_PLAIN=17，type.hh:105-118）把 ptr(valueType) 落到 INT_ADD 输出
→ setcasts 时地址已是指针 → getInputCast 返回 null → 无消费侧 CAST → 印 `(int8)p + -8`。
Rugra：该传播未持久化（终态高类型=long）→ 忠实 getInputCast 插 CAST → 再被 printc
load_addr_direct 印刷期戳覆写 `int *` → `(int *)p - 8`（4× 语义错位）。
**印刷层三缺陷（本 lane 修）**：①prettyprint `+ -N`→`- N` 改写（消灭全部 666/1096 正典形）；
②CAST 内联臂读 v_type 原名（泄漏戳名）而非 oracle 的 def-facing 高类型+结构拼写（printc.cc:448-464）；
③load_addr_direct 戳覆写 setcasts 定型 CAST（INDPTR 判决 PRINTC-PTRSTAMP-CAST-OVERWRITE-0001）。
**传播层缺口（登记 TYPEPROP-ADDRSLOT-PERSIST-0001，coreaction 域）**=剩余 ~17 `(int *)` 与
canon 侧 61 下标形的根源。

## 3. 修复与前后（亲测，基线=亲父 37014110）

| 门禁 | 前 | 后 | 判定 |
|---|---:|---:|---|
| httpd E2E canon | 1445/0/0 | **1405/0/0**（−40） | defects/numbering 保持 0 |
| curl E2E canon | 1329/0/0 | **1262/0/0**（−67） | 同上 |
| httpd main 单函数 | 645 | **643** | SP-cast 族 40→1 |
| 逐函数 | — | httpd 5 改善/0 回退；curl 8/0 | 零回退 |
| 五投影 | MATCH×5 | **MATCH×5 保持** | stage+snapshot identical |
| gcc 审计 | curl 103/21、httpd 16/13 | 同数 | 恒等 |
| 双跑确定性 | — | cmp 恒等（双侧） | ✓ |
| 单测 | — | printc 15/15、prettyprint 6/6 | ✓ |

修复后 httpd main SP 族形态：`*(undefined8 *)((long)puVar10 + -8) = 0x2b874;`
——与 canon `((long)plVar11 + -8) = 0x12b874;` **逐字同形**（变量名/基址差归命名/加载域）。

## 4. 修复后残差分解（httpd main = 643）

OTHER 137 / TYPE 6 / BOOL 1 / NAME 18 / MIXED 5 / LOST 314（HEAD 179 + LIB_BOTH 135）。
族排序：字符串 69（HEAD）> 下标形 61（typeprop 域）> SWITCHD/goto 43（JTEDGE）>
local_* 24（HEAD）> WARN 31（blockaction）> `(undefined8 *)` 杂项 ~43（混合）。
三大块判定：**headless 层 ~203（字符串+命名+类型播种，FI 判例域）+ typeprop 传播层 ~61-78
（TYPEPROP-ADDRSLOT-PERSIST-0001，coreaction 域）+ 结构/JTEDGE ~74（并行车道）**。

## 5. 产物（/dev/shm/rugra-tests/sb-main2/）

gates/{curl,httpd}_{base,final,final2}.c + compare 输出 + 五投影 *.projection + perfunc.py +
main_resid.py（sb-mainattr2 适配）/census.py / probe/opdump_main.txt（终态 op+类型 dump）。

---

# Lane AFINI 续章（wt/afini，2026-09-25）— ap_fini_vhost_config 符号集差归因（负结果：varmap/merge 无缺陷）

基=亲父 4160d9e7 亲测复现：httpd **1405/0/0**、curl **1262/0/0**、ap_fini_vhost_config
canon skeleton **239**。任务假设（VHOST ④移交）：符号集差=extraout_RDX×3/uVar15/in_RIP/
unique 集形状，gold 知道这些符号而 Rugra 不知道（或反之），落在 varmap/merge 域。

## 1. 裁决：四族符号差逐族定性（证据=双侧 golden 三方对照 + IR 探针）

对照三方：canon golden（headless 桥接层）、direct-runner golden（无 Java 分析器的库级
truth，ap_fini@0x2d020）、Rugra 两种驱动形态（default=iced 线性注入；RUGRA_MIRROR=1=
SLEIGH 全镜像=oracle 加载契约）。

| 族 | canon golden | direct-runner golden | Rugra default(iced) | Rugra MIRROR | 裁决 |
|---|---|---|---|---|---|
| extraout_{DX,RDX,RDX_00/01/02} | ap_fini **0** 处（全文件仅 7 函数有） | ap_fini **11 refs/5 decls** | ap_fini 8 refs | ap_fini **11 refs/5 decls** | **MIRROR=逐字 parity；canon 侧残差=headless Parameter-ID 桥接层（FI 判例域，库不可也不应复现）** |
| in_RIP | 0（2000+ 函数全无） | 0 | **23 refs/6 函数** | **0** | **iced lifter rip 相对寻址不折叠（x86_lift.rs parse_operand/compute_mem_addr 无 rip 分支）；SLEIGH 路径天然折叠** |
| unique0x\<rep-offset\>（STORE 址/读点印成 unique0x000a0830 形） | 无此形（有 DAT_ 符号） | piRam00000000000a0830（读+写**同一**符号名） | 无（iced 走 in_RIP 形） | 8 refs（读=plRam…，写=unique0x…） | **persist 全局 HIGH 在 channel-absent 动作管线下无符号无名 → printc 未名位置回退混用 vn 自身空间+name-rep 偏移（printc/driver 域）** |
| uVar15 vs uVar8（unique 计数形状） | uVar8 | uVar5/uVar10 | uVar13/uVar15 | uVar6/uVar11 | **共享计数器位置漂移，随上述 decl 集差被动产生，无独立缺陷** |

## 2. oracle 机制对照（本 session 逐行读，hook 回执）

- **extraout 命名**=database.cc:2423-2518 `ScopeInternal::buildVariableName`
  `indirect_creation` 臂（:2492-2503 `"extraout_"+registerName`）：call 输出 COPY 的
  间接创建 varnode 专属，direct-runner 侧 ap_fini 5 符号/11 引用，Rugra MIRROR 逐数相同
  （全 corpus 4 函数 5/5、3/3、11/11、3/3 refs/decls 全 parity）。
- **persist 全局符号**=funcdata_varnode.cc:1653 `Funcdata::mapGlobals`（ActionGlobalMap
  coreaction.hh:885）:persist varnode 分组→`queryProperties`→miss 时
  `discoverScope`+`buildVariableName(addrtied|persist)`→`addSymbol`（oracle 中符号生而
  有名 piRam…）；:1156 `Funcdata::linkSymbol`+ActionNameVars::linkSymbols
  （coreaction.cc:2925-2981）经 `Scope::queryProperties`（database.cc:1266-1287
  mapScope+stackContainer 走到 global scope）`setSymbolEntry` 挂回 varnode/high →
  printlanguage.cc:237-243 `pushSymbolDetail` 读 high 符号名，读/写同形。Rugra 的
  channel-absent 基线（driver 显式决策：print-only DB 安装）使 mapGlobals 只写
  Funcdata.symbol_table 代理、linkSymbol 无法回挂 → 读走 printc 代理梯（plRam 形）、
  STORE 址实例（unique 空间 phi/CAST 输出）落到未名位置回退。**注意 Rugra 回退
  `unnamed_location_token(vn.space, rep.offset)` 与 oracle
  `pushUnnamedLocation(rep->getAddr())`（地址=空间+偏移同取自 rep）尚有一处空间取值
  差异**——即便回退，oracle 形也应是 `ram0x000a0830` 而非 `unique0x000a0830`。
- **rip 相对寻址**：x86-64 .sla 的 rip 相对构造器在 SLEIGH 语义期折叠为绝对
  `*[ram]:8 abs`（x86_lift.rs:1574-1600 既有注释+probe 引：oracle pcode=ram:0x2270 直连）；
  comis/push/lea 臂已实现该折叠，**parse_operand/compute_mem_addr/parse_dest_operand 的
  通用 Memory 臂漏掉 rip**（base=rip 走 get_register("rip")→0x288 → INT_ADD(RIP,abs)+LOAD，
  RIP 读前无写→in_RIP 输入符号，database.cc:2476-2486 irregular-input 臂命名）。

## 3. canon-gate ap_fini=239 的成分测量（209 行双侧 LCS 分类）

stackdecl 52（local_ vs Stack 命名=HEAD 桥接层）/other 90（表达式形状=explicitization
域 coreaction：memcmp 实参/指针载入的前置具名化，gold int4 iVar4+int8 iVar11 vs Rugra
内联）/vardecl 31（同前因的 decl 集差）/globalref 18（DAT_ vs pxRam=HEAD）/
in_RIP 10（iced lifter）/extraout 8（HEAD：canon 无 extraout）。
**varmap.rs/merge.rs 名下成分为零**——MIRROR 形态下 ap_fini 的 varmap 符号族
（extraout 全家、stack 形状 [256]/[16]/8 字节 860、in_FS_OFFSET）与库级 oracle 全 parity，
唯一直接残差=1 个 decl（gold iVar4=memcmp 结果临时，explicitization 域，非符号命名域）。

## 4. 移交（新登记）

1. `X86LIFT-AFINI-RIPFOLD-0001`（P2）：parse_operand/compute_mem_addr/parse_dest_operand
   rip 折叠（写域 src/disasm/x86_lift.rs+docs/api/disasm/x86_lift.md；对照 comis 臂
   :3997-4010 与 push 臂 :1574-1600 既有实现；预期 canon gate httpd 显著下降——in_RIP
   23 refs/6 函数 + uStack_860/85c 4+4 分裂与 auStack_58[24] 同为其 iced pcode 形状级联）。
2. `PRINTC-AFINI-UNIQUELOC-0001`（P3）：persist 全局 HIGH 未名实例的回退形
   （printc 未名位置回退混 vn 空间与 rep 偏移 vs oracle `pushUnnamedLocation(rep->getAddr())`；
   根修复方向=动作期 DB 通道安装（driver 决策域）或回退形修正（printc.rs））。

## 5. 验证（本 lane 零 src 改动，门禁=亲父基线复测）

curl **1262/0/0**、httpd **1405/0/0**（亲测复现）、ap_fini 239 维持（无 src 改动的
预期恒等）；投影 bank `tools/verify_projection_bank.sh` **25/25 MATCH**（含五投影
next_url/match_url/getparameter/myprogress/parseconfig）；cargo test --lib 1708P/1F
（唯一失败 test_nonzeromask_pipeline_wiring=VHOST 报告在案的基线预存）。
产物=/dev/shm/rugra-tests/afini/（httpd_{base,mirror}.c、apfini_{rug,gold}.txt、
probe1/probe2.err IR 探针 dump）。
## 6. ADDRSLOT 车道复核（2026-09-25,wt/addrslot 基亲父 4160d9e7——TYPEPROP-ADDRSLOT-PERSIST-0001 判定）
**结论:MAIN2 对下标形 61 的根因假设(InferTypes 值→地址反传/typeOrder 持久化未持久化)被探针证据推翻;
传播与持久化两层均在工作。真实根因迁移到 varmap 域:栈符号数组元素粒度(1B vs canon 8B)经由
spacebase downChain 符号解析→RulePtrArith scale-1 PTRADD→setcasts 忠实 undo 的完整链条。**
### 6.1 探针证据链(全部 /dev/shm/rugra-tests/addrslot/,可复现,RUGRA_DBG_ADDRSLOT 门控)
1. **基线复现**:httpd E2E canon **1405/0/0** == 亲父;main 单函数 643;census 下标形 LOST=61
   (main_resid.py 自校验 643 OK)。配对形态:canon `V[-LIT] = LIT;` ↔ Rugra
   `*(undefined8 *)((long)V + -LIT) = LIT;`。
2. **反传存在**:STORE slot2→slot1 边探针(httpd_dbg2.err,905 事件):main 范围 300 次
   `new=Pointer/8 cur=Some("Int/8") better=true`——值→地址反传全面开火;目标即 INT_ADD/PTRADD/MULTIEQUAL 出边。
3. **持久化存在**:逐 cycle writeBack 探针(httpd_ci.err):ci4575(2c2da:1848 INT_ADD 出边)cycle0
   `perm=Unknown/8 tmp=Pointer/8`→落库;cycle1/2 无 diff 行(perm==tmp==Pointer)。全 3 cycle 持久。
4. **终态身份**:终态 opdump(RUGRA_DUMP_FUNC=main):`2c2da:14766 CAST out=Pointer/8[ci4575]
   in=Int/8`——原 ptr varnode 存活为 CAST 出边;INT_ADD 出边换成新 ci48595(Int/8)。
   这是 setcasts castOutput 的 cc:2594-2609 合法拼接(token=arithmeticOutputStandard=long ≠ 出边高类型
   ptr),oracle 同输入同样会插。Varnode::updateType 单参版(varnode.cc:456-464)无 typeOrder 门槛,
   Rugra update_type(varnode.rs:1383)等价——"未持久化"不成立。
5. **PTRADD 创建又回滚**:RulePtrArith 探针(httpd_pa2.err):成功族 `2b86f:76 slot=0
   types=Pointer,Int → ADDTREE`(转换发生);setcasts 探针(httpd_pu.err):39 次
   `PTRA_UNDO op=2b86f:76 sz=1 ct=(Pointer,8)`——**undo 因 scale(1)≠终态 pointee 尺寸(8)**,
   忠实于 coreaction.cc:2740-2746。scale=1 来自 AddTreeState 创建时 pointee=unknown1。
6. **symbol 解析在跑但元素粒度错**:TypeSpacebase::get_sub_type 探针(httpd_gs2.err):
   `off=-200(=-0xc8) sym dt=Array/32 elem=(Unknown,1,32)`——**Rugra undefined1[32] vs canon
   `long local_c8[4]`(8B 元素)**;-0x58=Array/24×1B vs canon local_70=long[6];符号边界+元素粒度双重分歧。
7. **RSP 直系仅 4 后继**(httpd_sb.err SBREF):帧引用经 COPY(RSP)→RBP 链,Rugra/oracle 同构
   (oracle propagateSpacebaseRef 也只走直系,coreaction.cc:5276)。
### 6.2 完整根因链(oracle 视角)
canon:`long local_c8[4]`(RangeHint 8B 元素)→ TypeSpacebase::getSubType(type.cc:2947-2968,
`scope->queryContainer`→symbol 类型)→ downChain 数组包裹(type.cc:1084-1131,INT_ADD allowWrap)→
基指针=ptr(long)(8B pointee)→ RulePtrArith 建 **scale-8** PTRADD → setcasts cc:2740-2746 尺寸匹配不回滚
→ 印 `plVar12[-1]`。Rugra:symbol=undefined1[32] → 同链给 ptr(undefined1) → **scale-1** PTRADD →
STORE 反传后期把 pointee 改善为 8B(ptr-vs-ptr typeOrder=0 不竞换,但 offset-0 直存边在 Int 在位时先落
undefined8)→ setcasts 忠实 undo → INT_ADD+`(long)` 输入 cast+`*(undefined8 *)` 地址 cast=61 族形态。
**首因=RangeHint dtype 丢失**:varmap.rs create_entry(varmap.cc:617-631 镜像)在 `hint.dtype=None`
时 fallback `make_int_info(types,1)`(varmap.rs:3559)→ 1B 元素数组。hint 的 dtype 源头
(RuleStoreVarnode/RuleLoadVarnode→hint)未携带 STORE 值/LOAD 出边的 8B 类型,且 -0xc8 区间合并为
32B 无类型整块(边界+粒度双差)。**修复域=varmap(RangeHint 收集/分区/类型携带),非 coreaction**;
InferTypes 域(本车道写域)无需改动——值/LD 出边类型已正确喂给(varnode 侧 Unknown/8=undefined8)。
### 6.3 移交与验证要求
- 新归因 ID 沿用 `TYPEPROP-ADDRSLOT-PERSIST-0001` 更名语义 → **VARMAP-RANGEHINT-ARRAYELEM-0001**
  (P2,varmap 域,机制 C 白名单):验收=httpd main 下标形 61 收敛+`-0xc8 族符号 8B 元素`+三门禁
  (curl 1262/httpd 1405 亲父数)+零回退+五投影 MATCH。
- 探针脚本/日志留存 /dev/shm/rugra-tests/addrslot/(main_resid.py+census.py 已适配本 worktree 路径;
  httpd_{base,dbg2,ci,pa2,pu,gs2,sb}.* 为证据;基线 httpd_base.c 与撤针后输出 cmp 恒等)。

## 7. RANGEHINT 车道复核（2026-09-25,wt/rangehint 基亲父 7a63a1b1——VARMAP-RANGEHINT-ARRAYELEM-0001 判定）

**结论:§6.2 的"首因=RangeHint dtype 丢失"假设被 oracle 侧仪器化运行推翻。锁定 oracle 的反编译器库
对 main 的 RangeHint 流与终态符号表与 Rugra 逐位一致（-0xc8 = 1B 元素 undefined1[32] 双侧同形）;
canon 的 `long local_c8[4]` 是 analyzeHeadless 桥接层（整程序分析回灌）效应,非 varmap/库层分歧。
varmap 域可修的唯一真实移植偏差（addGuard null-ct 早退）已补齐,行为中性（E2E 逐字节恒等）。**

### 7.1 oracle 侧证据链（/dev/shm/rugra-tests/rangehint/diag/,可复现）

1. **仪器**:stage_drill_1204.cc 诊断变体（副本 + `fd->getScopeLocal()->turnOnDebug()` + 终态
   `printEntries` dump;编译走 tools/build_stage_drill_oracle.sh 同链,git-archive 锁定
   e40ed130,-DOPACTION_DEBUG;`setarch -R env -i STAGE_DRILL_FUNC=main STAGE_DRILL_ADDR=0x2b820`）。
   开启 varmap.cc:1263-1266 的 MapState debug → 逐 pass "Add Range" 流。
2. **hint 流**:main 全程 11 个 restructure pass,-0xc8(0xff..f38) **每个 pass 都只有 1B hint**
   (`ffffffffffffff38:1 xunknown1`),从不出现 8B;pass2+ 的 8B hint 在 -0xd0/-0xa8/-0x9c/-0x40
   （-0xa8/-0x9c/-0x40 与 Rugra 一一对应;-0xd0 的调用返回地址槽 hint 双侧均不存活为符号）。
   即 **oracle 库自己也不会给 -0xc8 造 8B 元素 hint**——§6.2 假设的"canon 经 RangeHint 8B 元素"
   路径在库层不存在。
3. **终态符号表**（诊断 harness @DONE 后 dump）:
   `axStack_c8 : s0xff..f38:32 xunknown1[32]`、`xStack_a8 : xunknown8`、`axStack_9c : xunknown4[23]`
   （92B）、`xStack_40 : xunknown8` —— 与 Rugra main 输出 `undefined1[32] auStack_c8;
   undefined8 uStack_a8; undefined4[23] auStack_9c; undefined8 uStack_40` **逐符号同形同界**。
4. **direct-runner golden 独立佐证**:ghidra_httpd_1204.direct-runner.c main 同为
   `xunknown1 axStack_c8[32]` + `*(xunknown8 *)((int8)piVar10 + -8) = 0x2b874;` 形
   （与 Rugra 的 `*(undefined8 *)((long)puVar10 + -8)` 同构）——纯库真值与 Rugra 一致,canon
   独有的 `long local_c8[4]`/`plVar12[-1]` 属 main_resid 域判定中的 HEAD（headless 桥接层）。
5. **canon↔direct 差量本身是已知事实**:main_resid 域判定 LOST/HEAD=153（canon-only、direct 亦无）,
   下标形族在其内;分析=analyzeHeadless 先跑整程序 auto-analysis（Decompiler Parameter ID 等,
   跨函数原型/类型回灌、栈帧分析）再 decompileFunction——库单函数隔离跑不可能复现。

### 7.2 Rugra 侧对位探针（撤针前采集,/dev/shm/rugra-tests/rangehint/httpd_probe*.err）

- gatherOpen AddBase@-0xc8:12 pass base=undefined8(非指针→ct=NULL→1B,同 Ghidra varmap.cc:1230)、
  6 pass base=Pointer(undefined1)（符号反馈,pointee 1B→仍 1B）。双侧同陷 1B 反馈环——oracle 亦然。
- addGuard:全程仅 2 个 step=8 STORE guard（min=-2136/-64,均非 -0xc8）;Rugra add_guard 此前在
  地址输入 v_type=None 时早退（Ghidra 无此分支,ct 恒非 null——funcdata_varnode.cc:107/132/153-154
  构造即装 getBase(s,TYPE_UNKNOWN),varnode.cc:639-645 原样返回）。**已修**:None 臂代以工厂
  `undefined<addr_size>`,与 varmap.cc:1009-1038 单流一致。curl/httpd E2E 输出与基线 cmp 恒等
  （None 路径在双语料不触发,行为中性)。
- gather_varnodes 栈 varnode 探针:-0xc8..-0xb0 无栈 varnode（双侧同——指令形为 lea 基指针寻址,
  RuleStoreVarnode 的 spacebase+const 判定（ruleaction.cc:4173-4227 correctSpacebase 需 isInput）
  不触发);-0xa8 的 INDIRECT/MULTIEQUAL 栈 varnode 双侧同在。

### 7.3 处置

- **VARMAP-RANGEHINT-ARRAYELEM-0001 判定否定**（varmap 域无可收敛改动;验收条款"下标形收敛"对
  库真值不可达)。下标形 61 族的 canon 侧形态归 **headless 桥接层差异**（与 STRING_LIT/RAM 等
  HEAD 族同类）,若未来要收敛需整程序分析回灌（参数 ID/跨函数类型/栈帧分析)——超出当前桥接
  范围,登记为桥接层限制,不开库层 TODO。
- varmap 域交付:addGuard null-ct 移植补齐（见上,行为中性+Ghidra 行级对齐）。
- 工件:/dev/shm/rugra-tests/rangehint/（diag/ 仪器化 harness+构建脚本+oracle drill 输出+
  symdump;main_resid.py/census.py 已适配本 worktree;curl/httpd base+fix 输出恒等证据)。

# §8 RENUM 续章（wt/renum，2026-09-25）— 门控 main 644 三类逐行分解 + 编号机制审计（判定：编号域零缺陷，SYMDB 阻塞项①退役）

## 8.1 基线（亲父 master 0cdbc81c，本 worktree 亲测，fast-release）

- httpd 门控 RUGRA_SYMDB=1：**1328/0/0**（defects=0 numbering=0）。
- httpd 默认：1472/0/0；curl E2E：1099/0/0；投影 bank 71/71 MATCH。
- main：门控 skeleton diff **644**（n=0 核心 −333/+311）；默认态 694。

## 8.2 三类行数表（任务①口径；skeleton 归一化把 `xVarN`/`param_N` 抹成 V——纯编号差对 skeleton 计数器贡献恒为 0 行）

| 类 | 定义 | 行数（占 644） | 判定 |
|---|---|---|---|
| (a) 编号/命名序一致仅计数器放大 | 深归一化（去 cast/栈名拼写/符号后缀）后与 golden 相等的行对 | **0–5**（5 对仅差 cast） | FLAGBASE "~67 行 puVarN 级联" 是**归一化文本距离度量的伪影**，skeleton 计数器不可见 |
| (b) 真偏号 | 结构等价但变量身份映射与全局双射冲突 | **0** | 编号/发射机制 oracle 忠实（见 8.4 探针）；编号值差异全部为上游变量集/类型差异的衍生 |
| (c) 内容差（字符串/类型/结构——HEAD 族） | 其余 | **644（100%）** | 见 8.3 子族分解 |

(b) 类核验细节：`VarN` 使用序列与 golden 的恒等匹配率 0.0（门控/默认同），但该差异由变量集不同（15 vs 16 槽位、类型前缀族不同、唯一 dynamic 符号 puVar10）派生——非槽位分配机制缺陷。

## 8.3 (c) 类子族（n=0：golden 侧 −333 / rugra 侧 +311）

| 子族 | 证据行 | 归属 |
|---|---|---|
| DWARF 行号存储 `local_d0 = 0x…` | golden 侧 14 行 | canon 独有命名形；纯库真值为 `*(xunknown8*)((int8)piVar10 + -8) = 0x2b874;` cast 指针算术形（direct-runner golden 同形=Rugra 现形）→ **HEAD**（§7.1 判例延伸） |
| 推荐栈名/参数名声明 `local_d8/local_c8[4]/local_a8/__s1` | golden 侧 ~10 decl+使用行 | analyzeHeadless Parameter-ID/栈帧分析回灌（nameRecommend 通道，coreaction.cc:2984 `recoverNameRecommendationsForSymbols`；Rugra coreaction.rs:9125 在案 RUGRA-GAP）→ **HEAD**；direct-runner 同为 `axStack_c8[32]/xStack_a8` |
| 结构族 `if(V==LIT){` vs `goto LAB;while(true){` | golden 24 + rugra 44 行 + "other stmt" 主体（两侧 215/186） | 纯库真值同 Rugra 的 goto+while 形（direct-runner 亲证）→ canon if-block 形 **HEAD**；库内残余结构差在案 MAIN-RC3-STRUCTURED-EMIT-0001/BLOCKACTION 族登记 |
| 类型/cast 族 `(char*)/(undefined8*)/(long)`、`undefined1[32]` vs `long[4]`、`code*` vs `void(*)()` | 声明 61/61 行 + 语句内 cast | canon 的精确类型来自整程序分析回灌（跨函数类型/原型锁定）→ 主体 **HEAD**；库内类型渲染残差在案 TYPE-UNKNOWN-0001 族登记 |
| `param_2` 指针性 `undefined8*` vs `undefined8` | 1 行（签名） | fspec/原型域（CANON 桥接差异），非 printc/varmap |

粗粒度形态覆盖估计（coarse normalizer）：canon 侧 333 changed 行中 **236（70%）** 的形态存在于 direct-runner 纯库真值中（= Rugra 对应行与库真值同形，canon 行只是桥接层富化）；**97 行** canon 独有形态（严格 HEAD 上界）。

## 8.4 编号/发射机制审计（(b)=0 的机制证据；临时探针已撤，撤后 E2E cmp 恒等）

scope 快照（门控 main，`emit_scope_local_var_decls` 探针）：

```
static rank-1 (register): pcVar1..pVar8(start 0x0), puVar9(0x20), puVar11(0x20),
  pcVar12(0x28), param_2(0x30), param_1(0x38), plVar13(0xa0), puVar14(0xa8),
  puVar15(0xb8), in_FS_OFFSET(0x110)
static rank-2 (stack, 偏移降序): auStack_c8, uStack_a8, auStack_9c, uStack_40
dynamic (尾部): puVar10 (hash 0x22327fca60c34b)
```

与 Ghidra 机制逐点对照（printc.cc:2518 emitScopeVarDecls = MapIterator(maptable 空间序×rangemap splice 序) 先、dynamic 列表尾；database.cc:2434 buildVariableName index 计数；coreaction.cc:2978 ActionNameVars::apply 的 namerec 序；type.hh:273/424/457 printNameBase——TypeCode 名 "code"→pc 前缀）：
- 编号序=符号创建/静态条目 splice 序 ✓；in_FS_OFFSET(0x110) 排 puVar15(0xb8) 后 ✓（同为 rank-1，splice 序）；
- 栈条目偏移降序 ✓（golden local_d8..local_40 同向）；
- puVar10 落 dynamic 尾=**Ghidra dynamic 尾部语义的正确行为**（该符号经 dynamic hash 映射——变量集本身与 canon 不同，系上游类型/合并状态差异的衍生，非 varmap/printc 缺陷）；
- nameBase 链（p/pc/au/l/i/u 前缀）oracle 忠实（type_system/datatype.rs:1119 镜像 type.hh 虚派发）。

## 8.5 处置

- **RENUM 判定：编号/命名域（printc.rs/varmap.rs）零缺陷，零 src 改动**（AFINI/RANGEHINT 判例延续）。
- FLAGBASE 终报 SYMDB 默认化余项① "main 重编号级联 ~67 行" **退役**（度量伪影，skeleton 不可见）；余项仅 ②已清（DATASYMS）+③ap_pregfree +2（独立登记）。SYMDB 默认化在编号/稳定性维度**无剩余阻塞**。
- canon main 644 的收敛路径=HEAD 桥接层整程序回灌（不开库层 TODO，§7.3 判例）+ 已登记结构/类型族。
- 工件：/dev/shm/rugra-tests/sb-renum/（classify.py/classify2.py/skel_diff.py/varseq*.py + main_skel.diff + main_classified*.txt + decls2.err 探针 + 双态输出）。

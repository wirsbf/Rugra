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

# GP978 Token-Level Triage — getparameter.constprop.0 skeleton 978 归因

- 日期: 2026-09-22 | Lane: BW (只读 triage) | 产物路径: `/dev/shm/rugra-tests/sb-switch/GP978_TRIAGE.md`
- 基线: master `d847accde06e57b4740255737af81162de4ec3d0`,`result/curl_cur.c`(9月22日 10:16, 全量 curl=3751/0/0)
- Oracle golden: `tests/golden/ghidra_curl_1204.c`(Ghidra 12.0.4)
- 官方门禁复跑(只读): `compare_ghidra.py --func getparameter` → **diff=978 defects=0 numbering=0** ✅(与任务背景一致)
- 提取: master gp = `result/curl_cur.c` L2164-2893(730 行); golden gp = L1649-2125(477 行); 已存 `/dev/shm/rugra-tests/sb-switch/gp_{master,golden}.c`
- 方法: difflib.SequenceMatcher 原文对齐 + 复用 `tools/compare_ghidra.py` 的 `normalize_skeleton` 逐 zone/逐 case 分解; 脚本 `triage_{gp,sk,zones,cases,fine}.py`
- 口径差注记: 我方全文复刻 unified_diff 计 990, 与官方 978 差 12 行(parse_functions 函数体切界/尾空行口径), zone 占比结论不受影响。**下文均以官方 978 为总量、zone 份额按比例折算并附原始计数。**

## 1. 结构事实总账(先于分类)

| 项 | master(Rugra) | golden(oracle) | 判定 |
|---|---|---|---|
| switch 个数 | **2** 个(均为 `switch(iVar31)`) | 1 个 `switch((int)pCVar10 - 0x23U & 0xff)` | master 多发射 1 个重复桥 switch |
| case 标签总数 | **96**(switch#1 48 + switch#2 48) | 48 | 任务背景"94"实为 96(48×2), golden"40"实为 48, 以下按实测 |
| case 值集合 | 0,0xf,0x10,0x15,0x16,0x1e,0x1f,0x20,0x21,0x22,0x23,0x25,0x26,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x30,0x31,0x32,0x33,0x35,0x36,0x3e,0x3f,0x40,0x41,0x42,0x43,0x45,0x46,0x49,0x4a,0x4b,0x4c,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57 | **完全相同** | ✅ 零值错、零集合差 |
| case 顺序 | 与 golden 逐一相同(序列相等, 脚本断言 True) | — | ✅ 零序错 |
| default 位置 | **第 49 位(末位)**, gp_master L594 | **第 2 位**(case 0 之后), gp_golden L121 | ❌ PRINTC-SWITCH-EMIT-0001(default 位置族)实证 |
| case 值形态 | 直接 hex 相对值(`0x23` 等) | 同为 hex 相对值, 但 switch 头显式带归一化子式 `- 0x23U & 0xff` | 头表达式差(见 §3) |
| switch#2 形态 | 48 个空 case(47×`break;` + 0x4e×`goto code_r0x00004030;`), 无 default, 且悬挂在孤立 `if`(无条件式)之后: `if \n switch(iVar31){...}{...}` — **非法 C** | 无此物 | ❌ 新结构残差(见 §5) |

## 2. ① case 值形态逐一对照(结论: 全对)

- 值集合: 48==48, 集合差 = ∅(含顺序逐位相等)。
- **default 位置**: master 末位(L594) vs oracle 第 2 位(L121), 即 CR-BO 登记的 PRINTC-SWITCH-EMIT-0001。difflib 上表现为: golden L121-130 的 10 行 default 块以 [insert] 出现在 case 0 之后; master L594-602 的 10 行 default 块以 [delete] 出现在 0x57 之后 — **块内容语义等价(见下), 纯位置差 ≈ 20 行 diff**。
- default 体形态次级差: golden 为 `if((char)V=='\0'){helpf..;V=2;}else{helpf..;V=2;} goto`; master 为拍平 goto 链 `if(SUB81(config_00,0)=='\0') goto code_r0x000047BB; helpf;V=V;V=2; helpf;V=V;V=2; goto` — if/else 大括号结构丢失 + 2 个 `V=V` 自噪。归 PRINTC-SWITCH-EMIT-0001 族(default 体拍平)。
- switch 头: golden `(int)pCVar10 - 0x23U & 0xff`(字母-char 减最小 case 值 0x23='#' 再掩码 — GCC 跳表归一化的显式恢复) vs master `iVar31`(子式折叠进变量, 头上不显式)。语义同派发, 形态差 2 行 — 归 PRINTC-SWITCH-EMIT-0001 族(头形态)。

## 3. ② case 体内容差(48 case 逐一 skeleton diff)

逐 case 分类(原文 skeleton 级): **11 个 MATCH**(0xf,0x10,0x1f,0x29,0x3e,0x43,0x46,0x49,0x4b,0x51,0x53 — 逐 token 相等), **37 个有差**。37 个再分:

**(a) 真差(语句缺失, 2 例, ~10 行)** — 唯一的 switch 内语义损失:
- `case 0x23`(master L225-237 vs golden L177-189): golden 在 guard `if((httpreq!=POST)&&(httpreq!=UNSPEC)) goto LAB_00104736;` 之后有 **`::config.httpreq = HTTPREQ_POST; break;`**; master 只有 guard 的 `goto code_r0x00004736;`, **赋值与 break 全缺 → 直落 case 0x25(curl_slist_append headers 路径)**。
- `case 0x35`(master L330-336 vs golden L259-266): 同型, golden 尾部 **`::config.httpreq = HTTPREQ_CUSTOM; break;`** 全缺 → 直落 case 0x36(strtol 路径)。
- 两例均为"guard 在、else 路径语句整体蒸发", 指向 case 尾块(last-block)发射/collapse, 非跳表值错。

**(b) 形态差(内容同在, ~35 case, ≈615 行)** — 全部可归到四个系统性族:
1. **变量身份(varmap)**: master 保留参数名 `nextarg/flag/config_00`, golden 经自身 copy-prop 重命名 `local_5b8/pCVar10`(golden 侧 58 处 `local_5b8`); master `&config`/`&(&config)->field`(18 处) vs golden `&::config.field`(34 处) — 同一对象两种符号基。
2. **死存储噪声**: master 独有 `uVar2x = uVar2x;` 自赋值 53+30+3=86 行原文(skeleton `V = V;` 122 行)、`uVar25 = nextarg;` 11 行、`sStack_588 = uVar27;` stat 溢出保存 3 处 — golden 均无。
3. **常量/符号恢复**: master 裸地址 `0x175xx`(15 处) vs golden `&::config.<field>`; 枚举名 master `(HttpReq)0x3`(6 处)/数字 timecond vs golden `HTTPREQ_POST/UNSPEC/HEAD/CUSTOM/TIMECOND_*`(12 处); `(bool)` 强转 6 处缺失; `stdout@@GLIBC_2.2.5` vs `stdout`(3 处); 函数名后缀 `_constprop_0/_part_0`(getparameter/parseconfig/SetHTTPrequest/file2string 4 个)。
4. **伪函数/标签形态**: `SUB81/SUB84/SEXT48/ZEXT`(12 处) vs golden 普通强转; 标签前缀 `code_r0x…`(23 处) vs `LAB_…`(23 处, 一一对应)。
- 附: `case 0x4e`: master `goto code_r0x00004030;` vs golden `break;` — 2 行, 但该 goto 是为绕开 §5 的重复 default-check 而生, **归并到 switch#2 工件族**, 不独立计真差。
- 附: golden 侧自身噪声(`strequal()/curl_formparse()/curl_getdate()` 空参、`/* Unresolved local var */` 注释、`helpf("unknown option -%c.\n")` 丢参)在 master 侧反而带参 — 方向上 master 不劣, 计为 golden 侧观测噪声。

## 4. ③ switch 外残差(zone 分解)

zone 骨架行数: A 序言(master L1-160)=144 sk vs golden 113 sk; B switch#1 = 440 vs 349; C switch#2+尾 = 126 vs 10。zone 级 diff(主侧-/金侧+): **A=102+71=173, B=369+278=647, C=120+4=124**(合计 944, 折官方 978 同比)。

- **C(124 行, ~13%)= 纯新增工件**: switch#2 重复桥(98 行原文/48 空标签)+ 孤立 `if`(无条件式, 与 switch 拼成 `if \n switch(...){...}{...}` 非法 C)+ 重复发射的 default-check 块(helpf Unknown option 在 switch#1 default 与尾部块**各出现一次**, golden 仅 1 次)+ `code_r0x000047BB` 标签 + 尾循环 De Morgan 拆解(`if(...||...) goto 4049; } while(true);` vs golden `while((...!= '\0') && (..., *usedarg==false));`, 等价下放, ~8 行)。
- **A(173 行, ~18%)**: 声明块 ~135 行(stack 覆盖名 `sStack_588/auStack_4f8/acStack_4e8/iStack_40` vs golden `local_5b8/now/statbuf/aliases[50]`; **`aliases[50]` 数组零恢复**, master 全程 `*(undefined8 *)(in_RSP - 0x4f8 + SEXT48(iVar31) * 0x18)` 裸指针算术; `int8 in_RSP/in_FS_OFFSET` 截断类型) + 0x96 次初始化循环 **~45 行真性乱码**(master 循环体写 `::config.*` 全局与 `*flag = *uVar27`, golden 为干净结构链 `pCVar13->useragent = *ppuVar12; ppuVar12++; pCVar13 = &pCVar13->cookie;` — 存储目标误恢复) + `for (var_8; uVar25 != 0; ...)` **未声明计数器 var_8**(printc 丢失循环计数变量, 真 printc 缺陷)。
- 序言长选项解析段(~68 行): `in_FS_OFFSET = in_FS_OFFSET;`、`**uVar25` 双解引用形态、`V = *flag;` 类噪声 — 均为 varmap/死存储族, 与 switch 无关的既有残差。

## 5. 978 归因账本(折算到官方总量)

| 类别 | 行数(≈) | 性质 | 归属 |
|---|---|---|---|
| switch#2 重复桥+孤立 if+重复 default-check | ~121 | 新增工件(不应存在, 含非法 C) | 新 ID SWITCH-BRIDGE-DUP-0001(BO/BL 三部曲暴露) |
| case 0x23/0x35 尾语句+break 缺失 | ~10 | 真语义差(fallthrough) | 新 ID SWITCH-CASE-TAIL-0001 |
| default 位置+体拍平+头形态 | ~24 | 位置/形态差(内容等价) | PRINTC-SWITCH-EMIT-0001(既有) |
| 0x96 初始化循环乱码 + var_8 未声明 | ~45 | 真性恢复错(存储目标) | JUMPTABLE/varmap 残差(aliases 零恢复同源) |
| 声明块类型/命名形态 | ~135 | 形态差 | varmap 残差(既有族) |
| 死存储自赋值/stat 溢出/`V=nextarg` | ~150 | 形态差(可 DCE) | varmap/死存储残差(既有族) |
| 变量身份 nextarg↔local_5b8、&config↔&::config.field | ~180 | 形态差 | varmap 残差(既有族) |
| 0x175xx 裸地址↔字段名、枚举、(bool)、stdout@@、_constprop_0 后缀 | ~90 | 形态差 | 符号/typemap 残差(既有族) |
| SUB8x/SEXT/ZEXT 伪函数、code_r↔LAB 标签前缀、尾循环下放 | ~60 | 等价变换/形态 | 既有族(skeleton 口径可见) |
| 序言长选项解析噪声 | ~163 | 形态差(§4 A 剩余) | 既有族 |
| 合计 | ≈978 | | |

## 6. 净评估(对照 529 时代)

- **方向 = 净改善, 且是"从无到有"级**: 529 时代 switch/case 内容缺席(golden ~350 行 switch 全部为 golden-only 差异); 现在 master 侧 **48/48 case 全部在场、值集合与顺序 100% 等于 oracle、11 个 case 体逐 token MATCH、全函数 221/710 骨架行相等、defects=0 numbering=0**。
- 上涨的 449(978−529)分解: 新内容以不匹配形态落盘(~330, 主侧 switch 内容形态噪声) + **新工件 switch#2 族 ~121(恶化项, 三部曲引入, 单点可回收最大块)** + default 位移 ~20。即: 上涨主因是"真实内容出现+一个新发射工件", **不是** case 值错/序错(实测为零)。
- switch 内真正的语义净损失只有 0x23/0x35 两处尾语句缺失(~10 行)。
- 与 golden 的 gp 对比结论: **case 分派层(值/序/集合)已对齐; 差异重心移到①重复桥工件 ②varmap 形态噪声 ③case 尾发射**。

## 7. 登记建议(不落 repo, 供主 Agent 采编)

1. **PRINTC-SWITCH-EMIT-0001**(既有, 补证): default 末位 vs oracle 第 2 位(gp_master L594 / gp_golden L121); 增补子证: default 体 if/else 拍平为 goto 链、switch 头缺 `- 0x23U & 0xff` 归一化子式。
2. **新 ID SWITCH-BRIDGE-DUP-0001**: switch#2 重复桥(48 空 case)+孤立无条件式 `if` 拼接(非法 C)+default-check 双重发射+`code_r0x000047BB`+case 0x4e `goto 4030` 改道; ≈121/978 行; 溯源 BO label 管道/BL 递归发射。
3. **新 ID SWITCH-CASE-TAIL-0001**: case 0x23 缺 `httpreq=POST;break;`、0x35 缺 `httpreq=CUSTOM;break;`(guard 在、else 路径整体蒸发→fallthrough)。
4. **JUMPTABLE/varmap 残差**: `aliases[50]` 零恢复(裸 `in_RSP-0x4f8+0x18*i` 算术)、0x96 初始化循环存储目标乱码、`for (var_8;…)` 未声明计数器 — 建议并入既有 varmap 残差 TODO 并附本证。
5. 改善留证: §1 表(值集合/顺序断言)、§3 的 11 个 MATCH case 清单、221 相等骨架行、978/0/0 官方复跑输出。

## 8. 改善证据清单(可直接引用)

- `case 值序列相等: True`(triage_zones.py 断言, 48==48, default 位置 49 vs 2)
- MATCH case: 0xf 0x10 0x1f 0x29 0x3e 0x43 0x46 0x49 0x4b 0x51 0x53
- 官方: `getparameter.constprop.0 diff=978 defects=0 numbering=0`
- 工件实录: `result/curl_cur.c` L2767-2768 `if \n switch(iVar31) {`; L594 区 `default:` 末位; case 0x23 尾 L235-238 直落 `case 0x25`

*脚本与中间产物: `/dev/shm/rugra-tests/sb-switch/triage_*.py`, `gp_master.c`, `gp_golden.c`, `sk_master.txt`, `sk_golden.txt`*

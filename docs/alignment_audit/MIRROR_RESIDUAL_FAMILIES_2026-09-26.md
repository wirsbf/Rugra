# MIRATTR 车道终报 — 镜面残差（direct-runner 口径）剩余族分类 @ HEAD 9d027a33（2026-09-26, ora-4 只读归因）

## 0. 口径勘误（重要）：账面数字已过期

历史账面 curl 200 / httpd 297 / vsh 41 为各 lane 异基线拼贴（200=MSTRUCT 基线、297=STRNCPY 基线、41=S2FIX 基线）。S2FIX（a894ca93+2689f914，已入 HEAD）之后亲测：

| 面 | 账面 | **HEAD 实测** | 证据 |
|---|---|---|---|
| curl 镜 | 200 | **132**（74 fn, 0/0） | /dev/shm/rugra-tests/swgoto/{curl_mirror_base.c,cmp_base.txt} |
| httpd 镜 | 297 | **265**（29 fn, 0/0） | /dev/shm/rugra-tests/mirattr/httpd_head.c（本车道诊断产物） |
| vsh 镜 | 41 | **41**（71 fn, 0/0） | /dev/shm/rugra-tests/varmp/vsh_mirror_base.c |

原 /tmp/rugra-mirror-gate.SaPrch 已不存在；最近完整快照 ACQF6n(17:00)=211/301/51 亦为 pre-S2FIX。本报告全部分类基于 HEAD 实测 132/265/41，逐函数归一化骨架 diff 存档于 /dev/shm/rugra-tests/mirattr/{curl,httpd,vsh}_head*.txt。

## 1. 已具名族在 HEAD 口径的行数（排除勿重复，仅校准账面）

| 已具名族 | curl | httpd | vsh | 备注 |
|---|---|---|---|---|
| for-split 拆分 | ~9（my_get_line/helpf/file2string） | ~34（ap_fini×4≈16、ap_set_nvhost 7、ap_matches 5、main 6） | 4 | MSTRUCT-FORSPLIT-DECOMP-0001 |
| switch goto 桥/fixpoint 同根（含 httpd main if/else 搬迁 ~50、case 体吊出、悬空 `code_r` 标号、glob_set do 包装、ap_ht_time 早 return 6） | ~31（glob_set 22+glob_word 9） | ~63 | 0 | MSTRUCT-SWITCHGOTO-SELECTGOTO-0001；**ap_ht_time 早 return 6 行为该族新位点**（MSTRUCT 时被 strncpy 13 行掩盖） |
| WhileDo 入口标号 | （含上） | 0 | 1 | MSTRUCT-WHILEDO-LABEL-PRINTC-0001 |
| do-nothing 警告 | 2（main+_start） | 0 | 1 | MSTRUCT-DONOTHING-WARN-0001 |
| overflow while(true)+break | 0 | ~12（ap_getparents） | 0 | typeprop 派生，随 F-TYPE 自愈 |
| CALLOTHER strncpy 印刷 | 0 | 2（裸 `;`） | 0 | STRNCPY-PRINT-CALLOTHER-0001（IR 对已产出，printc 两臂待接） |
| &DAT 字符串族 | — | — | — | canon 侧；镜面侧同域异机制新族见 F-STRFOLD（勿混淆：canon=queryContainer IR 级，镜面=pushConstant 打印级） |

## 2. 剩余未具名族分类总表

| 族 | curl/httpd/vsh 行数 | 根因(oracle 行) | 修法 | write-set | 优先级 |
|---|---|---|---|---|---|
| **F-TYPE 类型拼写/metatype**（含 SEXT48/ZEXT48 派生、`(int8)`/`(xunknown8*)` cast、char*/int8* 槽型、`[LIT]` 数组元素型、`(int4)` 索引 cast、双重 cast） | **~28 / ~34 / 26** | varmap 符号层中毒环（S2FIX 已定位）；SEXT/ZEXT=cast.cc:443-470 metatype 门 | gatherOpen 毒化闸/restructure int8 反哺闸（S2FIX 遗留切断点） | varmap+coreaction（双持有；VARMPOISON 车道在跑） | **P0-收益最大** |
| **F-RESIDE 循环承载值驻留：寄存器高层变量 vs 栈槽** | **~25 / 0 / 0** | golden 用寄存器 HighVar（`puVar7=puVar8` 拷贝链），Rugra 全程走栈槽（iStack_10d8/puStack_1120）且 `pxStack_1130` 提前 hoist | heritage merge/拷贝传播分歧，需 IR 级 fixture 定位后对齐 | heritage.rs+merge.rs（未被持有） | **P1-单族收益最高且写域空闲** |
| **F-DECL 声明序+多余声明** | ~9 / ~13 / 1 | printc.cc:2516-2570 emitScopeVarDecls：cat≥0=类目序、cat=-1=MapIterator 地址序、multi-entry 首整映射；死槽不映射 | 对齐两序源；补"映射后死亡槽"不声明（xStack_40/88/5a/58/1048） | varmap+printc（双持有） | P2 |
| **F-RAM 全局名形 ram0x vs xRam** | 0 / **~16** / 0 | database.cc:2455-2472 persist/addrtied 臂：printNameBase(ct)+大写空间名+2*addrSize 补零 hex | 统一未名全局回退到 oracle 形（带 ct 前缀）；消除同址双名（ram0x/iRam 并存） | varmap（持有；PIRAM 车道在跑——勿撞） | P2（并入 PIRAM） |
| **F-LOAD load/copy 物化** | 2 / ~7 / 3 | golden 物化 `p1=p+1;p=p+1;c=*p1`（多 def 循环承载 var 保独立 PTRADD 拷贝）；Rugra 折成 `c=p[1];p=p+1`（printc.cc opPtradd load-value 语境→下标） | HighVariable 合并分组对齐（需 IR 钉死是 merge 还是 copy-prop） | varmap/ruleaction/printc（持有） | P3 |
| **F-WARN `_` 全局重叠警告** | 0 / **7** / 0 | funcdata_varnode.cc:1718 mapGlobals inconsistentuse（用宽>符号项宽才警）；golden 0 警 | 驱动符号注册对齐 oracle harness：跳过 size-0 NOTYPE `_` 边界符（_edata/_end/__bss_start，readelf 亲证） | **examples/httpd_decompile.rs（空闲）** | **P1-便宜** |
| **F-STRFOLD 镜面字符串字面量折叠缺失** | 1 / **3** / 0 | printc.cc:1744-1816 pushConstant TYPE_PTR→isCharPrint→**pushPtrCharConstant(1698-1722)**：resolveConstant+isReadOnly+printCharacterConstant→字面量；失败才走默认 cast+hex（Rugra 现状） | 接通 print_character_constant 的 string_manager 读回（stringmanage.cc getStringData 惰性读载镜像；STRNCPY 车道只接了 STRINGDATA hash 通道）+isReadOnly 校验 | printc（持有）+stringmanage.rs（空闲） | P2 |
| **F-ARRCAST 数组指针 cast 形 `(t [N]*)` vs `(t (*) [N])`** | 0 / **4** / 0 | printc.cc:264-300 pushTypeStart+buildTypeStack+ptr_expr(:75)/array_expr(:76) 的 C 声明器括号化 | 补 PTR→ARRAY 链的声明器渲染（现输出为非法 C） | printc（持有） | P2-便宜但小 |
| **F-WRAP 折行点**（`;` 独行/`{` 折行/逗号换行侧） | 4 / 4 / 0 | prettyprint Oppen 机制 MIRROR3 已核等价 → 残差在 printc 侧 token 流 spacing/bump 差异 | 逐 token diff 定位（ap_update_vhost_from_headers 逗号、my_get_line `;`、glob_set `{`） | printc（持有）+prettyprint.rs | P3 |
| **F-CMPMISMATCH compare 工具误配对** | **6（幻影）** / 0 / 0 | compare_ghidra.py match_functions：golden 基址 0 存成 `addr-0x100000`(负键)，Rugra 镜像地址永不命中→全走 by_name；`SetHTTPrequest` 剥后缀撞名 last-wins 误配（亲证 part.0↔part.0 真差=0） | golden 双键存储（raw+norm）或补 `addr-2*base` 探测 | **tools/compare_ghidra.py（空闲）** | **P0-最先做**：−6 幻影+防未来门禁误配 |
| **F-UNAFF 额外调用输入 varnode** | 0 / 0 / **3** | 名字 `unaff_100002ef` 本身是 oracle 忠实回退（database.cc:2448-2452 getRegisterName 空→unaff_+8hex）；真差=Rugra 给 virLogMessage 多挂第 11 个 unaffected 输入（偏移 0x100002ef 疑 unique/镜像空间非寄存器） | 调用输入装配对齐（fspec 参数计数/unaffected 通道）；先 IR dump 钉空间 | heritage.rs（空闲）/funcdata（持有） | P3 |
| **F-PLTNAME PLT thunk 调用名** | **2** / 0 / 0 | printc.cc:592-631 opCall：FuncCallSpecs 名空→genericFunctionName(:3357) `func_0x<addr>`；oracle harness 无 dynsym/PLT 名，Rugra 驱动解析了 `__cxa_finalize` | 镜像态驱动不注入 PLT-thunk dynsym 名（对齐 oracle harness 符号集） | examples（空闲） | P3-便宜 |
| **F-CODENAME 代码空间常量函数名** | 0 / 0 / **1** | printc.cc:1744-1816 pushConstant subtype TYPE_CODE→**pushPtrCodeConstant(1729-1743)** queryFunction→`main`；Rugra 印裸地址 | 核 printc.rs:14146 query_function_addr 分支为何不点火（参数类型未到 TYPE_CODE=fspec 派生 or 分支缺失） | printc（持有）+fspec | P3 |
| **F-VOIDRET void return**（已登记） | 0 / 2 / 0 | MIRROR3-RETURNVOID-PRINTC-0001（printc opReturn 裁剪） | 按登记执行 | printc（持有） | P3 |

行数合计：新族 ~236 + 已具名 ~159 ≈ 395，与实测 438 的差额为 httpd main 内类型/cast 杂项（计入 F-TYPE 的保守下界）。

## 3. 关键根因亲读记录（oracle 行号，本 session 亲读）

- **F-STRFOLD**：printc.cc:1698-1722 `pushPtrCharConstant`（resolveConstant→`isReadOnly(stringaddr,1,Address())`→`printCharacterConstant`）；:1729-1743 `pushPtrCodeConstant`（`queryFunction`→`getDisplayName`）；:1744-1816 `pushConstant` 分派（TYPE_PTR→isCharPrint/TYPE_CODE；默认=typecast+force_hex，即 Rugra 现印的 `(char *)0x…` 形）。**亲证**：Rugra httpd 镜面 `= "` 折叠数=0，golden 同 29 函数集 ≥5 处（`"0.0.0.0"`/`"255.255.255.255"`/`"4.2) 9.4.0"`，golden 3880/3894/3927 行）。Rugra 臂存在（printc.rs:14064/14128）但从不点火 → 读回/readonly 通道断线。
- **F-TYPE/SEXT48**：printc.cc:786-810 `opIntZext/opIntSext`→cast.cc:443-470 `CastStrategyC::isSextCast`（out=INT/UINT ∧ in=INT/BOOL 才走 opTypeCast 双 cast 形 `(int8)(int4)V`，否则 opFunc=`SEXT48(x)`）。Rugra printc.rs:17411/17449 臂在、is_sext_cast 在 → **SEXT48 是 metatype 中毒的派生症状**（in 型 xunknown≠INT），随 F-TYPE 收敛自愈，无独立 printc 工作量。
- **F-DECL**：printc.cc:2516-2570 `emitScopeVarDecls`（cat≥0→`getCategorySymbol(cat,i)` 类目序；cat=-1→`MapIterator` 地址序；`isMultiEntry→getFirstWholeMap` 只发首项；dynamic 追加遍历）。多余声明=映射了已死槽（golden 只映射存活 use）。
- **F-RAM**：database.cc:2455-2472（persist/addrtied：`ct->printNameBase` + 大写空间名 + `setw(2*addrSize)` 补零 hex）→ `xRam00000000000a11b8`；Rugra 另有 `ram0x000a11b8` 无型路径且同函数同址双名并存（httpd_head.c 90/92 行 ram0x vs 108 行 iRam，亲证）。
- **F-WARN**：funcdata_varnode.cc:1700-1719 `mapGlobals`：entry 存在但 `(addr+sz)-1 > entry 末` → `inconsistentuse` → :1718 `warningHeader("Globals starting with '_'…")`。httpd symtab 亲证含 `_edata/_end/__bss_start/__data_start`（size-0 NOTYPE）与 `_IO_stdin_used`(size 4)——Rugra 驱动注册了小项，oracle harness 注册形态避开了触发。
- **F-PLTNAME**：printc.cc:592-631 opCall（`fc->getName().size()==0`→genericFunctionName:3357-3367 `func_`+printRaw）；golden 1026 行亲证 `func_0x000022e0(…)` vs Rugra `__cxa_finalize(…)`。
- **F-ARRCAST**：printc.cc:264-300 pushTypeStart/buildTypeStack + :75-76 `ptr_expr{unary_prefix}`/`array_expr{postsurround}`——`(t (*) [N])` 由 RPN 声明器优先级括号化产生；Rugra `(xunknown1 [8]*)` 为非法 C（gcc 审计面）。
- **F-RESIDE**：golden my_get_line（golden 1223-1290 亲读）`puVar8/puVar11/iVar13` 寄存器承载+`puVar7=puVar8` 拷贝，栈槽仅在 while(true) 前落一次；Rugra 全程栈槽承载+顶部 hoist。op 集合同构、驻留/合并决策不同 → heritage/merge 域，需双侧 IR dump 钉死（建议 fixture：`RUGRA_MIRROR=1` 单函数 IR vs oracle harness golden_dump）。
- **F-CMPMISMATCH**：compare_ghidra.py:100-107（golden `norm_addr=addr-0x100000` 负键）+ :95（三探测全 miss）→ :98 by_name；strip 后缀撞名（golden 仅 `SetHTTPrequest`×2，亲证）last-wins 误配；正确配对下 part.0 真差=0（亲测）。

## 4. 优先级建议（单族收益/修复难度）

1. **F-CMPMISMATCH**（tools，空闲，~5 行改动）：立即做——消 6 幻影行 + 根除门禁误配对风险（floor/族统计都被它污染）。
2. **F-RESIDE**（heritage/merge，空闲，25 行单函数）：先 IR fixture 定位（半天级）再修；本轮唯一"大块收益+写域空闲"组合。
3. **F-WARN**（examples 驱动，空闲，7 行）：跳过 size-0 `_` NOTYPE 符号即可，一小时级。
4. **F-TYPE**（varmap+coreaction 双持有）：收益最大（~88 行）但本轮不可动；VARMPOISON 车道在跑，本报告的 S2FIX 遗留切断点（gatherOpen 毒化闸/restructure 反哺闸）+"SEXT48/overflow/数组元素型/cast 链全部是其派生"结论直接供其续作。
5. **F-STRFOLD / F-ARRCAST / F-VOIDRET / F-CODENAME**（printc 持有）：解封后按此序做，机制行号已备齐。
6. **F-RAM** 归并 PIRAM 在跑车道；**F-DECL/F-LOAD** 待 varmap/printc 解封后以本报告机制为入口。
7. **F-PLTNAME/F-UNAFF**：小；F-UNAFF 先钉空间归属（疑 unique 空间错配）。

**只读合规**：本车道零 repo 文件改动；诊断产物均在 /dev/shm/rugra-tests/mirattr/（httpd_head.c 为亲跑门禁口径输出+逐函数 diff 三件）。

# HTTPDMAIN 归因报告 — httpd `main` canon 残差 499 行（2026-09-26, ora-6 只读归因）

**输入**：`result/httpd_cur.c`（@master 9d027a33，main=L14-552）vs `tests/golden/ghidra_httpd_1204.c`（main=L3486-4019）。
**基线**：`compare_ghidra.py --func main` → **diff=499, defects=0, numbering=0**。原始逐行 diff 789 行；修复 image-base 后 647；再归一化临时变量名后 473（即 ~174 行是纯变量命名，由 F1/F4/F7 的类型与 web 切分驱动，非独立根因）。
**亲读验证**：oracle 侧逐行读了 block.cc:1095-1101（spanning tree 边分类）、blockaction.cc:1378-1446/1801-1833（if 规则级联）、ruleaction.cc:4194-4341（RuleStoreVarnode）、coreaction.cc:3809-4062（ActionDeadCode）、heritage.cc:2571-2582（bumpDeadcodeDelay）、printc.cc:1698-1721（pushPtrCharConstant isReadOnly 门）、printc.cc:2955-3006（emitForLoop）、block.cc:3155-3210/3373-3383（findLoopVariable+iterateOp 迁移）、stringmanage.cc:427-475、coreaction.cc:2895-2990（ActionNameVars）。Rugra 侧核对了 block.rs:3421（find_spanning_tree 忠实）、flow.rs:791/1306-1320（noreturn 机制在）、blockaction.rs:4702-4990（try_rule_proper_if 有 negate）、printc.rs:5639（emit_for_loop 在但死代码）。

## 已具名子集在 main 的状态（勿重复归因）

| 子集 | main 内状态 |
|---|---|
| switch goto 桥（SWGOTO 车道） | **main 内已双侧一致**（switchD_/code_r0x 标签、case 集、goto 全同）——0 残差，无需 SWGOTO 处理 |
| do-nothing 警告 | golden 有 1 行 `/* WARNING: Subroutine does not return */`（L268），Rugra 0 行——归入 F1 级联（flow.cc:646 ↔ flow.rs:1320 机制已在，缺 noreturn 数据） |
| CALLOTHER strncpy 族 | main 内 **0 行**（在其他函数） |

## 分拣表

| 族 | 行数(骨架基准) | 根因（oracle 亲读行） | Rugra 缺口 | 修法 | write-set | 依赖 |
|---|---|---|---|---|---|---|
| **F1 noreturn 缺失级联** | **~300**（含全部子项） | Ghidra Java 侧 NoReturnFunctionAnalyzer 标 exit 为 noreturn → flow.cc:646 发 WARNING、exit 块无 fallthrough → block.cc:1095-1101 把 0x2c3b9→0x2b86f 判 **cross edge**（0x2b86f 已完成）→ 无环 → blockaction.cc 规则级联把共享错误尾排到函数尾（嵌套 if）。亲读反汇编证实 0x2c3b9 `lea "apr_pool_create()"; jmp 2b86f` 是 goto 非 backedge | httpd 驱动无 noreturn 台账（examples/httpd_decompile.rs:63 自述 "no known-noreturn marking"）→ exit(1) 有假 fallthrough → 0x2b86f 在 DFS 栈上 → backedge → 假 while(true) 环。**机制全在**：flow.rs:791 set_no_return、flow.rs:1306-1309 artificial_halt(NORETURN)、flow.rs:1320 WARNING——只缺数据 | 把 curl 驱动的 `KNOWN_NO_RETURN_ELF_NAMES`/`is_known_no_return`/`mark_known_no_return_function`/`known_no_return_callee_protos`（curl_decompile.rs:1893-1999，FLOW-NORETURN-DATA-0001）移植进 httpd 驱动 | `examples/httpd_decompile.rs`（空闲） | 无。**最大单杠杆**，一次解锁 F1 全部级联 |
| F1a 级联：假环+goto 头结构 | ~120 | 同上（blockaction 结构化差异全由假 fallthrough 派生） | Rugra 头部 `while(true){err1…LAB_0012b8c0…break;LAB_0012c3b9}` vs golden 嵌套 if+尾部 err1 | F1 修复后自动消失 | （随 F1） | F1 |
| F1b 级联：retaddr 槽形态（命名局部 vs 指针写） | ~16 | ruleaction.cc:4319 RuleStoreVarnode：地址=spacebase+const 的 STORE→命名局部 COPY；经 MULTIEQUAL/COPY 的指针写不触发→指针形态。golden 头部 14 处 `local_d0=0x12…` + 2 处 push 槽；指针区双侧同为 `plVar12[-1]` | Rugra 因假 merge 使 RSP 从头就是 MULTIEQUAL → 全部指针形态。RuleStoreVarnode 已移植（ruleaction.rs:17495） | F1 修复后 RSP 恢复 raw chain → 规则自动触发 → 形态自动对齐 | （随 F1） | F1 |
| F1c 级联：err1 尾重定位+phi churn+死代码 | ~40 | golden 把 err1 尾排在函数尾、`plVar11` 独立变量；Rugra 排头部+`plVar16=plVar12-0x10`（exit 后死代码）+phi 物化 3 行 | 同 F1 | F1 修复后重排；残余风险：`plVar11/plVar12` 双变量切分是 merge.rs HighVariable 分组，可能留 ~4 行命名差 | （随 F1；残余归 merge.rs） | F1 |
| **F2 image-base 常量显示增量** | **~140**（实测原始 diff 789→647） | oracle analyzeHeadless 以 0x100000 载入 PIE → inst_next 常量原生 0x12b8d3；golden 全部 136 个 retaddr 常量为 0x12xxxx | Rugra 内部 base-0，仅标签/DAT 名走 `display_image_base`（funcdata.rs:1237 print_raw_code_addr 只被 flow.rs:2230/jumptable.rs:4810/warning 调用），**普通常量渲染不加增量** → 0x2b874 vs 0x12b874（136/136 全错，无一例外） | (a) printc 常量渲染对落图内的地址常量加 display delta（贴层修复）；(b) 驱动原生以 0x100000 载入（干净但波及全部 fixture/golden/pin） | (a) `src/printc.rs`+`src/funcdata.rs`；(b) `examples/httpd_decompile.rs`+载入层 | **V4/V5 通道决策待用户**；与 F4 部分耦合 |
| **F4 类型推断：flag web char\* vs int** | ~16 语句行（+驱动 ~100 纯命名行） | golden 把 web{0,1,0x17a422,…} 统一为 **int**：oracle 程序在 0x17a422 无 char\* 数据类型（lea 常量无类型，char\* 只经调用参数原型进入——printc.cc:1698 pushPtrCharConstant 需 pointee isCharPrint） | Rugra 对字符串地址 lea 常量做 PTRSTAMP（printc.rs:10130 PRINTC-PTRSTAMP 区）→ web 统一 char\* → 常量 1 被按 base-0 地址 1 解析成 `"ELF\x02\x01\x01"`×3、`"ptemp"` vs `0x17a422`、`(char*)0x0`×2、`(char*)apr_app_initialize`×3、缺 `(char *)`/`(long)` 强转×3、`puVar18` vs `lVar16`(+0x33) | 字符串指针 stamping 收敛到 oracle 口径：仅锁定调用原型/程序数据类型路径赋 char\*，裸 lea 常量保持无类型；web 统一序让 int 胜出 | `src/printc.rs`+类型传播层（coreaction.rs） | F2（若选 (b) 原生 rebase 则 "ELF" 行自动变体）；独立可先行做差分 fixture |
| **F5 configtest if/else 分支取向翻转** | ~50-100（与 F1 重叠，post-F1 复测） | blockaction.cc:1378 ruleBlockProperIf **先试 i=0**（fallthrough 作子句）→ `negateCondition`（block.cc:294）→ golden `if (iVar3==0){正常路}`；硬件是 `jne 2c214`（2c12a），out(0)=fallthrough=正常路（block.hh:299-300 getFalseOut=out(0)） | blockaction.rs:4705 try_rule_proper_if **有** dir==0 negate（忠实）——取向差异非规则缺失，疑为 F1 假环改变子句合格性/规则命中序，或 flip 态丢失 | **先修 F1 再复测**；若仍在：对照 blockaction.cc:1801-1833 规则序（Goto→Cat→ProperIf→IfElse）逐规则 diff 该分支的命中路径 | `src/blockaction.rs` | F1（可能整体吸收） |
| **F8 for↔while 循环形成缺失** | ~5（main；全语料所有 for 循环同病） | block.cc:3155 `BlockWhileDo::findLoopVariable`（找环变量 MULTIEQUAL+尾增量）+ block.cc:3373-3383 iterateOp **迁移到尾块**（opUninsert/opInsertAfter）→ printc.cc:3001/2955 emitForLoop | **完全缺失**：blockaction.rs 全部 6 处构造 `for_init:None, for_iter:None`（3230/5610/7058/7165…），`find_loop_variable` 不存在 → printc.rs:5639 emit_for_loop 是**死代码** → 模块注册环打印成 while+顶部自增 | 移植 findLoopVariable + iterateOp 迁移（含 isMoveable 门），接通 blockaction→block.rs→printc.rs 既有死代码 | `src/block.rs`+`src/blockaction.rs`（printc.rs 侧已就绪无需动） | 无（可与 F1 并行,write-set 无交叠）;**与 MSTRUCT-FORSPLIT-DECOMP-0001 同族——本行根因更深（findLoopVariable 整体缺失 vs 渲染器收窄）,以本行为准** |
| **F6 引用数据符号/字符串模型反转** | 3 | optoption 已**钉死**：0x7b82f 起有更长串 `"k:C:c:…X"`（亲读二进制 0x7b826-0x7b850），代码引用 0x7b831 是**串内部**→oracle 建串于 0x7b82f、内部引用打 DAT_ 标签→`&DAT_0017b831`。"plog"(4字符) 疑 strings analyzer min-length=5 跳过→Data Reference 建 DAT_；"ptemp"(5) 建串✓。**"err"(3) golden 却渲染字面量——未钉死**，需 canon .gpr 数据模型 dump | Rugra 纯 decompiler 侧 StringManager（stringmanage.rs:488 忠实）无分析器数据模型：0x17a41d/0x17b831 渲染成串（应 &DAT），0x17a253 建了 DAT_（应 "err"）——**与 oracle 恰好逐地址反转** | 驱动侧镜像 oracle 程序数据模型（串/DAT 创建规则：min-length、串内部引用）；先用 oracle .gpr dump 三地址实证规则再实现 | `examples/httpd_decompile.rs` | F2（DAT 名已带增量，串解析用 base-0——rebase 决策影响实现） |
| **F7 nameRecommend 未移植** | ~1-2（骨架基准；raw ~4） | coreaction.cc:2984 `recoverNameRecommendationsForSymbols`（varmap.cc:1507/1614 NameRecommend 存储）+ coreaction.cc:2858 lookForFuncParamNames：锁定原型参数名（strcasecmp 的 `__s1`）推荐给喂参局部 | coreaction.rs:9691 **RUGRA-GAP 明文**："no name-recommendation store is ported yet"；且 httpd 驱动无 libc 签名台账→strcasecmp 参数名不锁定→双缺（机制+数据） | (1) 移植 NameRecommend 存储+recover（varmap 侧）；(2) httpd 驱动补 libc 签名（参数名+类型，同时救 F6 的 "err"） | `src/coreaction.rs`+`src/varmap.rs`；数据侧 `examples/httpd_decompile.rs` | 数据半可先行；机制半等车道释放 |
| **F3 双重强转打印 bug** | 1 | printc.cc:448 opTypeCast：每个 CAST op 恰发一次强转（输出类型）；ActionSetCasts（coreaction.cc:2702-2712）装的是终态 cast，无嵌套冗余 | printc.rs 对 `*(undefined1 *)((undefined1 *)(long)plVar12+0x33)` 发两层 `(undefined1 *)`（switch 头，L277）；其余表达式无此病→print 侧 PTRSUB/LOAD 链的强转去重缺失 | print 侧冗余嵌套 cast 折叠（内层与外层同型即省略） | `src/printc.rs` | 无（1 行，随手修） |

## 🔴 硬地板族（单列）——V4/V5 通道决策待用户

**RETADDR-HTTPD（retaddr 处理 + 死存储存活簿记）**——已知硬地板族（前值 15×2）在 httpd main **再现且放大为 ~135×2**：

1. **常量值**：136 个 retaddr 常量全缺 0x100000（F2，~140 行）——这是 retaddr 值本身错，非形态问题。
2. **死存储存活边界**（F1 修复后仍可能残余 ~3-5 行）：
   - golden **保留** `local_d0 = 0x12b869`（第一个 call 的 retaddr，槽位后续被 __fprintf_chk/ap_log_error 栈参复用+heritage.cc:2571 bumpDeadcodeDelay/2716-2728 overlap 逻辑延迟栈上 deadcode）与 `local_40 = *(u8*)(in_FS_OFFSET+0x28)`（死 canary 链，Rugra 其他函数能渲染 canary、main 被自己的 deadcode 消掉——local_40 声明还在但无写入）；
   - golden **消除** 0x12ba0c/0x12ba19（local_e0 从未被读→RuleStoreVarnode 转 COPY 后 ActionDeadCode coreaction.cc:3925 删除）；
   - Rugra 现状**恰好相反**：消 0x2b869、留 0x2ba0c/0x2ba19、消 canary。
   - oracle 机制链：ruleaction.cc:4319（STORE→命名 COPY）→ coreaction.cc:3925-4062（consume 传播）→ heritage.cc:2571/2716-2728（overlap→bump→restart）。Rugra 的 ActionDeadCode/heritage 已移植但**存活边界不一致**——需要最小化双侧 fixture（死 canary + retaddr 槽复用 + 永不复读槽三形态）逐 pass 对拍。
3. **write-set**：`src/coreaction.rs`、`src/ruleaction.rs`、`src/heritage.rs`——跨持有车道，且 F2 的 V4/V5 决策（原生 rebase vs 显示增量）会改写 retaddr 常量的正确性判据。**V4/V5 通道决策待用户，本轮不动。**

## 修复顺序建议（依赖图）

```
F1 (driver, 空闲, ~300行) ──┬──> 复测 F5 (可能全吸收, blockaction.rs)
                            ├──> 复测 F1b/F1c 残余 (merge.rs 命名切分 ~4行)
                            └──> F3 的 0x2ba0c/0x2ba19 两行是否自动对齐
F8 (block.rs+blockaction.rs, 空闲, ~5行) —— 与 F1 完全并行, write-set 无交叠
F2 (printc.rs/funcdata.rs) —— 等 V4/V5 决策 + 车道释放
F4 (printc.rs/coreaction.rs) —— 可先做双侧 fixture 设计, 等车道
F6 (driver 数据模型) —— 先 .gpr dump 实证三地址规则; 数据半与 F7 共享签名台账
F7 (coreaction.rs/varmap.rs + driver 数据) —— 数据半可先行
F3 (双重占用) —— fixture 先行, 修复等车道
```

**验证口径**：F1 修复后必须重跑 `compare_ghidra.py --func main`（预期 499→~180±30：剩 F2 ~140 + F4 ~16 + F3 ~5 + F6 3 + F8 5 + F5 残余）；F1/F8 各自独立可验证（F1：exit(1) 后无死代码+无假环；F8：`for (ppuVar14 = &ap_prelinked_modules; …)` 出现）。所有差分非零可提交进度，但每处残余按铁律 3 绑 TODO ID。

**归档说明**：本报告为只读归因，未改任何文件；fixture/中间产物在 `/dev/shm/rugra-tests/httpdmain/`（rugra_main.c/golden_main.c/归一化 diff 阶梯：789→647→473→461），重启即丢，root 需要可自行复现（提取区间：Rugra L14-552，golden L3486-4019）。

**后续裁定（2026-09-26 Lane F4WEBTYPE 收口）**：F4 行的"写域=src/printc.rs+类型传播层"预判部分失效——printc 侧 PTRSTAMP 是渲染非戳型；真根因=arch.rs `add_to_global_scope` 把 cspec `<global>` 的 `<register name="MXCSR"/>` 范围推入 `infer_ptr_spaces`（oracle architecture.cc:680 delay-0 过滤恒排除寄存器空间），4 字节字符串地址常量因此过 Register 4==4 尺寸门被 ActionConstantPtr→RulePtrsubCharConstant 折成 char\* 常量污染 int 网。修复后 main F4 主体族全消（39→13，残余=F6/F8/RETADDR/命名 web 已登记族）。详见 TODO_BOARD HTTPDMAIN-F4-WEBTYPE-0001 DONE 行。

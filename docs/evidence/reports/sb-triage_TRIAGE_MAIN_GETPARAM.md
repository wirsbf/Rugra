# TRIAGE: main + getparameter.constprop.0 文本差分定性预分类

- 日期: 2026-09-22 | Lane V (Phase 3 前置分诊, 纯只读)
- 输入: `/dev/shm/rugra-tests/sb-baseline/curl_new.c` (Rugra) vs `tests/golden/ghidra_curl_1204.c` (oracle 12.0.4)
- 工具: `tools/compare_ghidra.py --func <f> -v` + python difflib 全文对齐(函数体按 marker 提取)
- 工件: 本目录 `cmp_main.txt` / `cmp_getparam.txt` / `difflib_full.txt` / `main_{rugra,ghidra}.c` / `gp_{rugra,ghidra}.c` / `extract_and_diff.py` / `quantify.py`
- 门禁现状: 两函数 defects=0, numbering=0(全量 124/124 匹配)→ 差异全部在 skeleton 层(结构/形态)

## 0. 顶层数字

| 函数 | oracle 行数 | rugra 行数 | skeleton diff | difflib 形态 |
|---|---|---|---|---|
| main | 479 | **949 (2.0×)** | 1248 | 62 replace 块 (377→844 行) + 5 insert + 2 delete |
| getparameter.constprop.0 | 476 | 484 (1.0×) | 869 | 16 replace 块 (443→346) + 2 insert(113 行) + 2 delete |

- oracle 两函数 identity 自拷贝 = **0**;rugra main 203 + gp 51 → 拷贝噪声是单侧的。
- difflib 变更行合计 main 1238 ≈ 工具口径 1248,gp 910 ≈ 869(对齐方式差异),口径互相印证。

## 1. 分类统计表(main)

rugra 侧 949 行中 **C1+C2+C3 = 491 行(52%)为纯拷贝噪声**;剥掉 identity+marker 后剩 643 行(oracle 479)。

| ID | 类别 | 计数(行/处) | 怀疑域 |
|---|---|---|---|
| C1 | 恒等自拷贝 `X = X;` | **203** | merge/varmap(copy-prop/自copy 合并缺失;w-selfcopy 域) |
| C2 | spill/restore 乒乓 `uStack_240 = uVarN; … uVarN = uStack_240;` | **185**(uStack_240 出现 119 次;`uStack_240 = …` 40 处) | 同上(寄存器-栈槽往返未折叠) |
| C3 | 死标记存 `UStack_388 = 0x…`(函数内地址 0x25f7…0x336b) | **103**(oracle 同语义仅 3 处 `uVar29 = 0x1027da` 形态) | varmap 符号物化 + dead-store(与 C1/C2 同族) |
| C4 | 全局结构体字段寻址 `DAT_00xxxxx` vs `::config.field`;函数指针常量 | DAT 引用 97 vs oracle `::config.` 104;`0x3460` vs `my_fwrite` | database/symbol + varmap |
| C5 | 类型/cast/extop:`undefinedN/int8/uint1/unkbyte7` 声明、`SEXT/ZEXT/SUBxx/CONCATxx` 泄漏 | 未定形声明 19 + extop 行 17(`SEXT48(iVar14)`、`CONCAT71(uStack_240,…)`) | typeop(ActionSetCasts)+ heritage 部分 varnode |
| C6 | 栈局部提升失败:`in_RSP - 0xNN`、`UStack/uStack/iStack/pcStack` vs 命名局部 | in_RSP 11 处(`(bool *)(in_RSP-0x1f8)` vs `&progressbar`) | varmap ScopeLocal/MapState |
| C7 | 控制流形态:`code_r0x…` 标签 vs `LAB_…`;do-while 双计数 | code_r 标签 19 vs LAB 27;`} while (uVar4 + 1 < argc)` 双算增量 | printc 标签发射 + blockaction(少量) |
| C8 | 常量规范化 | `+ 18446744073709551615`(应 -1)×2、`UStack_388 = 10999`(=0x2af7,同类常量别处用 hex)、`iVar11 = '&'` vs oracle `0x26` | printc 常量发射 |
| C9 | 调用原型/参数 | `curl_version(argc,argv,in_RDX,0)` vs `curl_version()`;`maprintf("curl/7.1…")` vs `maprintf()`;`_IO_FILE*` vs `FILE*` | fspec/funcdata callspec(CALLSPEC 域) |
| C10 | 畸形 C(空 cast) | `*(( *)uVar2)` ×4 | printc |
| C11 | 大对象拷贝/struct splice(URLGlob 3531B 主体) | ~50 行:rugra 原始循环 `*uVar2 = *uVar16` + 整体 cast `*(URLGlob*)(in_RSP-0x388)` vs oracle 逐字段 splice(`glob.pattern[8].content…`) | heritage/merge 大对象 |

样例(双侧对照):
- C1: `+ uVar18 = uVar18;` / `-`(无对应)
- C2: `+ uVar13 = uStack_240; … + uStack_240 = uVar13;` / `- uVar29 = 0x1027da;`(oracle 物化为寄存器一次性)
- C4: `+ if (DAT_00117550 == (char *)0x0)` / `- if (::config.outfile == (char *)0x0)`
- C5: `+ uStack_240 = CONCAT71(uStack_240,__stream_00 == 0);` / `- bVar19 = __stream_00 == (FILE *)0x0;`
- C6: `+ getparameter_constprop_0(pcVar1+1,uVar13,(bool *)(in_RSP-0x1f8),config)` / `- getparameter(pcVar11+1,pcVar7,(bool *)&progressbar,config)`
- C10: `+ } while (*(( *)uVar2) != '\0');` / `- } while (cVar1 != '\0');`

## 2. 分类统计表(getparameter.constprop.0)

| ID | 类别 | 计数 | 怀疑域 |
|---|---|---|---|
| C1' | copy 中继链/自拷贝 | 乒乓 84 + identity 51 + relay 对 8(`uVar27=uVar30;` 紧跟 `uVar33=uVar27;`);uVar27/30/33 三角 ~50 实例 | merge/varmap(w-selfcopy) |
| C12 | **switch 结构丢失**(最大单块) | oracle 348 行 40-case `switch((int)pCVar10 - 0x23U & 0xff)` → rugra 顺序代码 + `code_r0x…` 标签;`default:` 内联进直落代码;悬空语句 `(0x57 < (int *)(int)config_00 - 0x23);` + 空语句 `;`(switch 头残骸) | blockaction/jumptable |
| C4' | 全局结构体/spacebase | DAT 46 + `__spacebase_1_0` 16;`GetStr(&((Configurable *)((int *)(__spacebase_1_0 *)0x0 + 0x17520))->proxy,…)` + 死偏移物化 `uVar30 = 0x175a8;`(LEA 中间值未折叠) | database/symbol + varmap |
| C6' | 栈数组提升 | `*(undefined8 *)(in_RSP - 0x4f8 + SEXT48(iVar32) * 0x18)` vs `aliases[iVar14].letter`;aliases 初始化游标 `uVar33` 误写 `*flag = *uVar27;`(写进参数!) | varmap ScopeLocal |
| C5' | 类型/extop | 未定形声明 13 + extop 11(`SUB81(config_00,0)`、`SEXT14`、`ZEXT18`、`SUB84(lVar29,0)`) | typeop |
| C7' | 标签 | code_r 15 vs LAB 23 | printc |
| C9' | 调用原型 | oracle 5 处 no-arg(`strequal()`、`curl_getdate()`、`curl_formparse()`…)vs rugra 带参 6 处 | fspec |
| C13 | 符号误归因/数据流分歧候选 | `fclose(stdin)` vs `fclose(pCVar9)`;`p_Var31 = stdin` 后 `if ((int *)p_Var31 - (int *)stdin != 0)`;canary 重载 `*(int8 *)(uVar30 + 0x28)` vs `*(long *)(in_FS_OFFSET + 0x28)`(main 同型: `uVar5 + 0x28`) | varmap 别名(copy 链连锁 or 独立别名缺陷) |
| C14 | 声明形态 | `undefined8[2] auStack_4f8; char[1192] acStack_4e8;` vs `LongShort aliases[50]` | varmap + 类型恢复 |

样例:
- C12: `- switch((int)pCVar10 - 0x23U & 0xff) { case 0x45: … }` / `+ DAT_001175b8 = DAT_001175b8 ^ 0x20; … uVar27 = uVar27;`(case 体直落)
- C13: `- if (pCVar9 != stdin) { fclose((FILE *)stdin); }` / `+ if ((int *)p_Var31 - (int *)stdin != 0) { fclose(stdin); }`

## 3. 看板红旗验证: copy-pair oscillation

**再现 ✓,形态一致且扇出放大。** `CODEGEN-DIVERGENCE-REDFLAG-0001`(commit 2589853,三次目击 cur→cur2→cur4):
- 精确对 `uVar27 = uVar30;` + `uVar33 = uVar27;` 当前快照 8 处(gp_rugra.c:183-184, 227-228, 241-242, 293-294, 363-364, 371-372, 396-397, 429-430);
- 逆向 `uVar30 = uVar33;` 7 处(155, 277, 411, 420, 460, 465, 476);
- 整体 uVar27↔uVar30↔uVar33 三角 ~50 实例 —— 不再是孤立一对,而是同一根因(寄存器 save/restore 链未折叠)的规模化表现。与证词"w-selfcopy 域内、迭代序敏感"一致;main 中同族以 `uStack_240`/`uVar13` 乒乓(119 处)和 203 条恒等自拷贝出现。
- 结论: 优先级不变,归 w-selfcopy;其修复预计同时消解两函数最大差异类。

## 4. main 大块重复模式与根因数上界

- 重复模式 TOP3(单一模式重复 N 次 = 高扇出):
  1. 调用点噪声簇:`curl_easy_setopt`/`curl_slist_free_all`/`free`/`fclose`/`helpf` 等每个调用前挂 2-3 行 `UStack_388=0x…; uVar13=uVar13; uVar18=uVar18;` —— 仅 setopt 块(~40 连发调用)即 ~120 行;全函数调用点前挂噪声 192 行。
  2. 恒等自拷贝 + 乒乓:491 行(52%)。
  3. DAT 全局引用:97 处,形态完全同构。
- **根因数上界 ≈ 10**(按类别 11 归并:C1/C2/C3/C11 → copy/merge 族 1-2 个;C4/C6 → varmap 符号+栈提升 2 个;C5/C8/C10 → 打印/类型化 2-3 个;C7 标签 1;C9 原型 1;C13 别名 0-1)。
- **众数估计 5-7 个算法级根因**;copy 族单项解释 main ~40% skeleton diff(491/1248),copy 族+C4+C6 合计 ~85%。
- gp 根因数上界 ≈ 8(switch 丢失 1 + copy 族 1 + 全局符号 1 + 栈数组 1 + extop/类型 1-2 + 原型 1 + 符号误归因 0-1)。
- 两函数共享根因 ≈ 5-6(copy 族、全局符号、栈提升、extop、标签方案、常量规范化、原型)→ 预测 stage-bisect 的多数首分歧应在共享根因上。

## 5. 对 stage-bisect 首批的优先级建议

| 优先 | 差异类 | 预期首分歧位置 | 理由 |
|---|---|---|---|
| **P0** | copy/spill-restore 族(C1/C2/C3/C1') | **oppool1** 即应分叉:COPY op 存活数/重复赋值 op 数 | 两函数最大体量(main 52%);oracle 在早期 action(heritage/merge/copy-prop)后即折叠,op 池形态差应最早可见。若 oppool1 的 COPY 类 op 计数对拍无差异反而说明分叉更早(heritage) |
| **P1** | gp switch 丢失(C12) | **blockaction** 阶段投影(结构块类型: switch vs 顺序+goto) | 单块 348 行,机械可判;首分歧应能直接落到 jumptable/blockaction 的具体 Action |
| **P2** | 全局符号/::config(C4/C4') | database/fspec 阶段(早于 oppool1) | 若 oppool1 首分歧排除 copy 族后仅剩符号引用差异,则归此类;修复面窄(database 映射) |
| P3 | extop/标签/常量/原型(C5/C7/C8/C9) | printc/后期投影 | 打印层为主,等结构层收敛后收益才可见 |

**交叉核对点**: 若机械归因给出的 main 首分歧不在 copy 族或全局符号族,与本分诊冲突,应优先怀疑归因管线漏拍早期阶段(heritage/merge 投影缺失)。

## 6. 附: 畸形/可疑清单(供 defects 门禁升级参考)

- `*(( *)uVar2)` ×4(main)—— 空 cast,非法 C,`tools/audit_syntax.py` 候选;compare 工具 defects=0 未捕捉。
- `(0x57 < (int *)(int)config_00 - 0x23);` + 孤 `;`(gp)—— switch 头残骸成悬空表达式语句。
- `*flag = *uVar27;`(gp aliases 初始化游标写进参数 flag)+ `fclose(stdin)`(gp)—— 数据流语义分歧候选(可能是 copy 链连锁,修复 w-selfcopy 后需复核)。
- `for (var_8; …; var_8 = var_8 + 18446744073709551615)`(main×2, gp×1)—— 循环计数 var 未声明泄漏 + 无符号 -1;oracle 对应 `for (config = 0x26; …; config = &config[-1].field_0x12f)`(结构体步长迭代)。

# Lane FU2 (wt/pltstub): RESIDMAP-PLTSTUB-EMITSHAPE-0001 交付报告
Commit: ebcc6932 (wt/pltstub, 基 9458a61b)
Oracle: Ghidra 12.0.4 e40ed130; canon: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c
写域: src/{printc,printlanguage,prettyprint}.rs + examples/curl_decompile.rs + docs/api 三件 + TODO_BOARD

## 桩形缺口一句话
PLT stub 同形 132 行族 = 四缺口叠加:①pushType 裸 get_name() 对工厂匿名指针
(空名)印零文本→签名丢返回类型 ②CALLIND 直印臂绕过 RPN 栈→assignment ` = `
分隔符跨语句泄漏(`uVar1(...)( );`+`return = uVar1;` 不可编译形) ③驱动
reloc 查找漏 .rela.plt(JUMP_SLOT 在 goblin pltrelocs)→`PTR_00116e90` 裸标签
④P6 单用内联臂把合法 `uVarN = <callind>();` 整行内联清除(oracle 无文本
后处理)。

## 前后(curl strcpy @0x2310)
前:
  strcpy(char *__dest,char *__src)   ← 空返回类型
  undefined8 uVar1;
  uVar1(*(code *)PTR_00116e90)();    ← 不可编译
  return = uVar1;                    ← 不可编译
后:
  char * strcpy(char *__dest,char *__src)
  undefined8 uVar1;
  uVar1 = (*(code *)PTR_strcpy_00116e90)();
  return uVar1;
canon 余差=局部类型 2 行(heritage 合并丢 Step3 typelock→RESIDMAP-PLTSTUB-
VARTYPE-0001 已登记)+警告 3 行(PLTSTUB-WARNLOSS-0001/JUMPTABLE fail_thunk 域)。
void stub(free)体 `(*(code *)PTR_free_00116e80)(); return;` 全字节 MATCH;
__libc_csu_init 隐式 LOAD 目标 `(code *)` 面形 MATCH。

## 三门禁(亲父 9458a61b 亲测,parent worktree 独立构建对照)
| 门禁 | 亲父 | 本 lane |
|---|---|---|
| curl skeleton/defects/numbering | 2145/0/0 | **2005/0/0 (−140)** |
| httpd skeleton/defects/numbering | 2057/0/0 | 2068/0/0 (+11=canon 形语句保留,golden:5913 见证,命名/类型差同 VARTYPE 残差根) |
| 三投影 | — | next_url/match_url **MATCH×2**(sb-oracle 钉板);parseconfig/getparameter **与亲父字节恒等** |
| gcc 审计 | 82OK/25FAIL | **104OK/20FAIL** |
| 确定性 | — | curl/httpd 双跑字节恒等 |
| lib 测试(串行) | 1682/18 | 1682/18 失败集恒等 |

## 让渡/移交
- FR2→FR3 右值族(`*V + LIT = V;`)与本案不同根(H=指针算术赋值发射,
  本案=CALLIND assignment 泄漏),无让渡。
- 残差登记:RESIDMAP-PLTSTUB-VARTYPE-0001(P2,heritage/merge 域,机制 C)。
- PRINTC-CALLIND-RPN-ASSIGN-0001 / PRINTC-CALLIND-P6-NULLIFY-0001 → DONE。
- T5(驱动给 stub callspec 装 locked output)经 cast.cc:300-384 语义核实为
  **反 canon**(oracle 的 stub callspec 不锁输出,`(char *)` 来自未锁 token
  vs typelocked 局部),已撤——留给 VARTYPE 车道按正确机制闭合。

## 工件(/dev/shm/rugra-tests/sb-pltstub/)
curl_final2.c / httpd_final2.c(+*_run2 恒等) / curl_parent.c / httpd_parent.c /
proj_{next_url,match_url,parseconfig,getparam}*.projection / pfix/(P6 落盘
证据) / dump_strcpy.stderr(IR) / commit_msg.txt / LANE_REPORT.md

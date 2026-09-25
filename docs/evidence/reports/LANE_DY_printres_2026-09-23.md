# Lane DY: printc 打印阶段残差簇修复 — sb-printres 交付报告
Commit: 7c8dc431 (wt/printres, base master 47c9ad79)
Oracle: Ghidra 12.0.4 e40ed130; golden: tests/golden/ghidra_curl_1204.c / ghidra_httpd_1204.c
写域: src/printc.rs + docs/api/printc.md(prettyprint/blockaction/block/driver/examples 全部只读)

## ① 复现分类(skeleton 行贡献量化,见 classify.txt)
| 族 | curl | httpd | 裁决 |
|---|---|---|---|
| EQLEAK CALLIND ` = ` 泄漏 | 44 | 0 | 协议修复就绪,被 prettyprint P6 拦截 |
| INFLOOP 尾距 | 4 | 6 | printc 发射已修;被 trim 门拦截 |
| LABSPELL code_r vs LAB_ | ≤128 (64/75 occ) | ≤76 (38/45 occ) | 数据域(driver/varmap) |
| BARE_TRUE | 38 | 30 | 类型域(varnode 面向类型非 bool) |
| UNREACH_FMT `(,33b3)` | 9 | — | funcdata.rs(被占) |
| COMMENT_WARN 大头 437 行 | — | — | 上游分析态差(jumptable 90=flow 域;Unknown-cc 51vs24=fspec;Unresolved-local 30=varmap) |

## ② 已落地(commit 7c8dc431)
- emit_structured_infloop 尾距逐字面镜像 cc:3112-3120(emit 层字节=oracle;最终文本被 prettyprint
  trim 门回改,登记 PRINTC-POSTFIX-WHILETAIL-TRIM-0001,解锁后 curl−4/httpd−6)。
- CALLIND 臂保留旧直印 channel + 完整协议分析注释;全 setter 插桩证据链入 TODO。

## ③ 根因闭环(未落地,登记待派)
1. **PRINTC-CALLIND-RPN-ASSIGN-0001**:RPN 协议臂(pushOp(fc)+pushOp(deref)+cc:649-669)在
   EmitNoMarkup/EmitPrettyPrint 隔离测试+corpus 低层字节 dump 三重证实渲染
   `uVar1 = (*(code *)PTR_00116e98)(); return uVar1;`(=golden 同形);
   **PRINTC-CALLIND-P6-NULLIFY-0001**(prettyprint P6 单用内联把合法赋值行清空)=阻塞。
   Heisenbug 排查路径:CIMARK 前缀使行脱离 P6 的 `uVar^` 门即存活 → TLOW 低层插桩定位。
2. **PRINTC-LABSPELL-LABSYMS-0001**(最大族):30/35 curl、19/23 httpd code_r 地址与 golden
   LAB_/joined_r 精确重合(基址 0x100000);oracle 拼写来自 emitLabel cc:3173-3181
   queryCodeLabel(前端 LAB_ 符号),Rugra 无该数据恒走 cc:3183-3192 泛型臂。修域=driver/varmap。
3. **PRINTC-LABEL-WITHOUT-GOTO-0001 勘误**:UNSTRUCTURED_TARG 从未经 markUnstructured 落位
   (mark_front_leaf/BlockGoto 门/BlockIf/BlockSwitch 全量 trace 零命中 0x37b2);叶 BlockCopy
   flags=0x230020 vs original 0x30000(0x20 创建后出现);goto 从未达 emit_block_goto。修域=
   blockaction/block flags 生命周期。
4. **PRINTC-CALLIND-CODECAST-0001**:oracle setcasts 对 calltarget 插 CAST(code*)
   (typeop.cc:744-750);Rugra mirror 以 typed INPUT 直载,printc 以 `(code *)` 字面传输。

## 三门禁 + 双投影(commit 后复测)
- curl 124 函数 defects=0 numbering=0 skeleton **2614 == 基线**,逐函数 diff 恒等零回退
- httpd 29 函数 defects=0 numbering=0 skeleton **2331 == 基线**
- next_url + match_url Phase 2 投影 **双 MATCH**(stage_bisect --v1 vs sb-oracle 钉板)
- printc 单测 12/12;gcc 审计 curl 82OK/25FAIL==基线;lib 串行 1650/18==基线集

## 工件(/dev/shm/rugra-tests/sb-printres/)
curl_base.log / curl_inf.log / httpd_base.log / httpd_inf.log / classify.txt /
main_body.diff / low.err(TLOW 低层字节) / postfix.err / raw.err(TRAW 前后缀对照) /
commit_msg.txt / LANE_REPORT.md

## 未决(全部已登记 TODO_BOARD)
PRINTC-CALLIND-P6-NULLIFY-0001(解禁 −44)、PRINTC-POSTFIX-WHILETAIL-TRIM-0001(−4/−6)、
PRINTC-LABSPELL-LABSYMS-0001(−128/−76,数据域)、PRINTC-CALLIND-CODECAST-0001、
PRINTC-LABEL-WITHOUT-GOTO-0001(修域勘误 blockaction/block)。

# LANE REPORT — RESIDMAP-NEGRIDX-PRINTFAMILY-0001 (wt/idxemit, FQ3)

- worktree: /dev/shm/rugra-worktrees/idxemit, branch wt/idxemit
- base: master-side parent **3925922a**(MERGED_RESIDMAP 图谱交付)
- commit: **2955dd84**(单 commit:printc 下标形三件套 + varmap PTRSUB/PTRADD 偏移臂 + docs/api×2 + TODO 行 + dispatch_op_rpn 注释锚修复;amend 前身 5c01d503)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b(gate health OK;annotations/refs/evidence 全过)
- 三代续跑:FQ(varmap 臂)→FQ2(printc 接线)→FQ3(本 session:审 diff→补全→门禁→提交)。FQ/FQ2 中断根因=**HEAD 上 dispatch_op_rpn 缺 `// Ghidra:` 注释锚的潜伏违规**——printc.rs 一旦 staged 即被 pre-commit 拒绝;本 session 补 typeop.hh:170 锚后解锁。
- 证据: /dev/shm/rugra-tests/sb-idxemit/;target: /dev/shm/rugra-targets/sb-idxemit/(留待复核/集成后清扫)

## ① 缺口一句话

A 族(FP top1,~41/~170 行):httpd main `plVar12[-1]=…`(canon ×116/direct ×133)vs merged `*(undefined8 *)((int *)V - 8)`;curl `glob->pattern[V].content` vs `*(&glob->pattern + SEXT48(V))->content` —— 下标形发射链断裂(checkArrayDeref/值 mod 缺失)+ 栈 PTRSUB 符号回查缺失 + varmap PTRSUB/PTRADD 栈偏移回解缺失。

## ② 交付(oracle 行号锚定)

1. **printc checkArrayDeref**(printc.cc:353-369)+ **opLoad/opStore 值 mod 接线**(cc:487-518):`usearray && !force_pointer → print_load/store_value`,经 nodepend.vnmod→rpn_recurse→dispatch_op_rpn 传给 CPUI_PTRADD 臂(cc:880-893)消费成 `p[i]`。
2. **printc opPtrsub STRUCT/UNION 臂 arrayvalue**(cc:1011-1016/1037-1038/1053-1054):fieldtype==ARRAY 抹 `&`+valueon 形加 `[0]`。实证 `pUVar15->literal`→`pUVar15->literal[0]`(canon:742 同形);`(&glob->` 10→0。
3. **printc opPtrsub SPACEBASE 臂栈符号回查**(cc:1057-1097 stand-in 扩展):spaceid==Some(Stack) 且全局容器 miss 时查 ScopeLocal 快照 find_container_entry(=Scope::findContainer,database.cc:2262-2282),整符号命中(entry.start==off && entry.offset==0 ↔ cc:1084-1086 off==0)打印符号名;ARRAY 符号按 cc:1064-1067 抹 `&`;mid-symbol 仍 PARTIALSYM 残差。实证 `&0xffffffffffffff38`→`auStack_c8`(direct oracle:3198 `piVar10=(int8*)axStack_c8` 同形),httpd 17 处裸偏移全消。
4. **varmap resolve_rsp_offset_signed PTRSUB/PTRADD 臂**(gatherOffset,varmap.cc:830-849):PTRSUB≡INT_ADD;PTRADD 常量索引×stride、变索引仅 stride==1 跟进;严格模式(vs oracle 宽松部分和)注释在案(固定 hint 通道 + gather_open 对偶)。

## ③ 三门禁 + 三投影(亲父 3925922a 基线亲测,commit 后复跑字节恒等)

| 门禁 | 结果 | 基线 | 判定 |
|---|---|---|---|
| curl E2E 124 fn | **2119/0/0**(−28) | 2147/0/0 | ✅ ≤2120 |
| httpd E2E 29 fn | **1899/0/0**(−160) | 2059/0/0 | ✅ ≤1900 |
| gcc 审计 | **82 OK/25 FAIL** 恒等 | 82/25 | ✅ |
| next_url 投影 | 92 行,defects=0 | 92 | ✅ 保持 |
| match_url 投影 | 46 行,defects=0 | 46 | ✅ 保持 |
| parseconfig 投影 | 83 行,defects=0 | 83 | ✅ 保持 |
| 确定性 | 双跑字节恒等;probe 前后字节恒等 | — | ✅ |
| printc/varmap 单测 | 12/12、45/45 | — | ✅ |
| lib 串行 | 1682/18(失败集=FUNCDATA-TESTS-FLAKY-0001 既有集逐名同) | 18 | ✅ |

移动分布(httpd):main −40、ap_fini_vhost_config −54、ap_update_vhost_from_headers −18、ap_getparents −12、ap_ht_time −12、ap_pregsub −8 等 11 函数。

## ④ 判据注(负向偏移族为什么保留 deref 形)

~102 处 `*(undefined8 *)((int *)puVar10 - 8)` 维持 deref 形**非缺陷**:直接 oracle golden(ghidra_httpd_1204.direct-runner.c:3206-3217)同位同形 `*(xunknown8 *)((int8)piVar10 + -8)`——该族 print 时 IR=CAST(undefined8*,INT_ADD(CAST(int*,X),−8)),checkArrayDeref 按 oracle 语义必 false。彻底转 `p[-1]` 需 ruleaction 域 INT_ADD→PTRADD 元素重标度(**让渡 FV2/FW2/FS3**);canon `plVar12[-1]`/`long local_c8[4]` 全形另需 analyzer+DWARF 类型流,非纯反编译可达。正向下标族(`puVar10[0xb]`/`glob->literal[i]`)已由本 lane 打通(direct oracle:3228-3230 `piVar10[-1]`/`piVar10[0xb]` 同机制)。

## ⑤ 机制 C 复核请求

varmap.rs(AliasChecker 域)+printc.rs(机制 B 白名单)均已过机制 A/B 门禁;**请求独立 Cross-Review(commit 2955dd84)**,重点:①check_array_deref 判定键/SEGMENTOP 解包层(cc:358-368);②值 mod 单一份布(nodepend.vnmod 传递 vs oracle pushVn(m));③arrayvalue 置位序(先 arrayvalue=valueon 再 valueon=true,cc:1014-1015)与 `[0]` 终端后缀;④栈符号回查的整符号守卫(entry.offset==0 ↔ cc:1084-1086 off==0)与 mid-symbol 回退;⑤varmap PTRADD 臂 stride==1 条件与 wrapping 算术。approve 前不入主管线。

## 回收

- 本报告归档 /dev/shm/rugra-reports/;sb-idxemit/ 保留最终双输出+基线双输出+commit_msg(复核证据),中间探针产物已清;target 目录留 root merge 后清扫。

# Lane FR/FR2/FR3 — RESIDMAP-PRINTBATCH 交付报告

- 日期: 2026-09-24 | branch **wt/printbatch** | 亲父基线 **4256a1a7**
- 交付 commits: **`d0d5a78d`**(代码+docs/api) + **`4aee0d60`**(TODO 行)
- oracle: Ghidra 12.0.4 e40ed130(ghidra/ HEAD 核验一致)
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-printbatch

## 三族修法(H+J+N)

| 族 | 规模(基线) | 修法 | Ghidra 锚点 |
|---|---|---|---|
| **H 右值赋值**(缺陷级) | httpd 27 行/5 fn | STORE 地址改经 `rpn_tok_dereference` token 协议发射,括号决策交 printlanguage.cc:287-292 unary_prefix(prec 62)包裹低优先级地址表达 → `*p+3=X` 变 `*(p+3)=X` 合法左值 | printc.cc:512 `pushOp(&dereference,op)` |
| **J WARN 地址格式** | 43(31 httpd+12 curl) | 新 `Funcdata::print_raw_code_addr`(space.cc:206 printRaw: `0x`+2*sz 零填充,sz 按 >>32/>>48 收缩)+ `display_image_base` 传输(canon 驱动 0x100000,同 code_label 层);三警告族接线:Removing unreachable block(space 名 "ram"+printRaw)/PIC 警告/jumptable 恢复失败消息;flow partial 克隆继承基址 | space.cc:206-216, funcdata_block.cc:371-379, flow.cc:1381-1385, jumptable.cc:2626-2640, address.hh:305 |
| **N register 泄漏** | 13 tok(9 curl+4 httpd) | `dispatch_op_rpn` 补 FLOAT_INT2FLOAT/FLOAT_FLOAT2FLOAT/FLOAT_TRUNC 三臂(此前落空 catch-all **静默丢操作数**)+`rpn_def_inline_reachable` 补齐 → 隐式 XMM 浮点临时按 printlanguage.cc:526 内联 def,myprogress 印 canon 同形 `(float)uVar7 / (float)(dltotal + ultotal)`/`__sprintf_chk((double)fVar8,...)` | printc.cc:830-842, printc.hh:326-327, typeop.cc:1864-1880, printlanguage.cc:514-540 |

## 前后数字(亲测)

| 门禁 | 亲父 4256a1a7 基线 | 交付态 | 判定 |
|---|---|---|---|
| curl E2E canon compare | 2145/0/0 | **2131/0/0**(−14,唯一形变函数=myprogress) | 改善,零回退 |
| httpd E2E canon compare | 2057/0/0 | **2057/0/0**(H/J/N 形变不触 canon 骨架行) | 持平,零回退 |
| 双跑确定性 | cmp 恒等 | cmp 恒等(curl/httpd 双语素) | ✅ |
| **gcc 审计 curl** | 25 FAIL | 25 FAIL(残余=typed 拼写族 EQ3 ⑤ `int8/uint8/Configurable`+PLT stub 族 FS,均在册他域) | ==基线 |
| **gcc 审计 httpd** | **21 FAIL** | **20 FAIL**(ap_make_dirstr_prefix 翻正) | **✅ 硬验收达标(FAIL 下降)** |
| token 族清算 | — | register0x: curl 9→0 / httpd 4→2;rvalue-defect 形 0/0;旧 WARN 形 0/0 | ✅(httpd 残 2 见下) |
| cargo test --lib 单线程 | 18 失败(台账基线家族) | 1682 通过/18 失败(失败集==rulresid 台账:funcdata alignment 族+test_heritage_creation,逐名一致零新增) | ✅ |
| annotations --all / refs --strict / 机制 A | 绿 | 绿(d0d5a78d 含完整 Alignment Evidence 块过 commit-msg 门禁) | ✅ |

## 残差移交(N 族深处根因链,供后继车道)

1. **httpd main register0x00000000(RAX)×2**:未恢复跳表的开关变量(`switch((int*)*(( *)()(int*)(uint1)register0x0*4+0x88530)+0x88530)` 空体)——**I 族 JUMPTABLE-TABLEAPI 域**(canon 同位置=switchD_caseD 标号+goto code_r...),非打印层;Ghidra 侧 ActionNameVars::lookForBadJumpTables(coreaction.cc:2790)有 "UNRECOVERED_JUMPTABLE" 命名路径可对照。
2. **N 族诊断证据链**(探针已移除,结论如下):
   - markimplied round-1 对 XMM0/XMM1 全部实例判 implied=true(FLOAT_MULT 输出因 inflate_test 正确判 explicit,==canon fVar9 行为);
   - ActionMarkExplicit::multipleInteraction 的 purgelist(核心 cc:3091-3135)在 merge 组重入时对 0x1240 清 implied(某 desccount=2 变体的 marked-input 链);
   - **最终 print 时泄漏 varnode 状态: implied=true / explicit=false / high 无符号 / 高名空**——即 varmap link_symbol(has_name 门,variable.cc:717-747)未给它铸符号,且 RPN 隐式内联被 `rpn_def_inline_reachable=false` 拒绝(FLOAT 转换臂缺失,本次已修)→ 本次修复后该链断在打印层已闭环;若未来再现(其它 opcode),查 rpn_def_inline_reachable 覆盖与 dispatch 臂总性(Ghidra TypeOp 虚 dispatch 是全 opcode 总表)。
   - Ghidra 不变量: implied varnode 永不并入多实例 High(merge.cc:249-263 mergeTestBasic `isImplied→false`;variable.cc:728-731 融合即 throw)——Rugra merge 路径的对应守卫未在本次核验,登记为后续核对项。

## 提交与白名单

- `d0d5a78d`:src/{printc,funcdata,flow,jumptable}.rs + examples/{curl,httpd}_decompile.rs + docs/api/{printc,funcdata,flow,jumptable}.md(10 文件,+249/−10)
- **机制 B 差分门禁**:printc.rs 白名单——curl defects=0/numbering=0(skeleton −14 全部=myprogress 对齐改善)、httpd defects=0/numbering=0(字节恒等),无未解释缺陷
- **机制 C**:jumptable.rs 触白名单但仅改错误消息文本拼写(LowlevelError 通道/触发条件/判零逻辑零改动)——**Cross-Review: PENDING(排队 root 集成时,同 w-pltwarn 先例)**
- **机制 E**:编辑前 printc.cc/printc.hh/printlanguage.cc/typeop.cc/typeop.hh/space.cc/funcdata_block.cc/flow.cc/jumptable.cc/address.cc·hh 均本 session 亲读并录回执

## 产物(/dev/shm/rugra-tests/sb-printbatch/,回收保留项)

- curl_n1.c / curl_n2.c / httpd_n1.c / httpd_n2.c(交付态双跑)+ curl_base.c / httpd_base.c(亲父基线)
- commit_msg.txt(过机制 A 的 message 原文)/ canon_myprogress.c / wip_myprogress.c
- 诊断中间产物(probe*.c/stderr)已按回收纪律清理

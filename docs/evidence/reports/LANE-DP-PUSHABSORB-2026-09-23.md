# Lane DP — HTTPD-CALL-PUSH-0001 RC3(push 吸收链)交付报告
- 分支: wt/sb-pushabsorb(worktree /dev/shm/rugra-worktrees/pushabsorb,基 master af98f92e + merge wt/sb-httpdmain@b00bf54d+fb935792)
- Oracle: Ghidra 12.0.4 e40ed130(x86:LE:64:default / gcc cspec / analyzeHeadless defaults=canonical;库级 BFD 契约=direct-runner)
- 构建口径: fast-release 迭代 + release 验收;CARGO_TARGET_DIR=/dev/shm/rugra-targets/pushabsorb

## 1. RC3 语义一句话
oracle 的 push"吸收"在库级管线=INT_ADD RSP,8 bump(ActionExtraPopSetup,extrapop 已知)+SP 链净零+固定槽 COPY 化(RuleStoreVarnode);**固定槽 push COPY 在 oracle 库级最终 IR 里存活、只是打印抑制/桥接层吸收——analyzeExtraPop 写回与 setEffectiveExtraPop 是每调用点 extrapop 的记账面,未知 extrapop 平台才走 StackSolver 重写**。

## 2. 契约判决(本 lane 核心发现,GOLDEN-CONTRACT-PUSHABSORB-0001)
- canonical `ghidra_httpd_1204.c` = 真实 analyzeHeadless 产物(provenance.json fixture_id=ghidra_1204_headless_golden):push 存储不打印。
- `ghidra_httpd_1204.direct-runner.c`(库级 BFD 单函数契约= Rugra RUGRA_MIRROR 同契约):**保留 `xStack_50 = 0x2cffb;` 等固定槽 push 打印**(extraout/xStack 系 4557 处)。
- 自建 oracle fixture(/dev/shm/rugra-tests/sb-pushabsorb/pushabsorb_ir_1204.cc,锁 e40ed130)复现库级行为:最终 IR 含 push COPY(consume=MAX/DW)+调用 INDIRECT(DELAY_SLOT/RA),C 输出打印 `xStack_50 = 0x2cffb;` → DL"28/29 函数吸收"系对 canonical(桥接层)读数,库级不可达也不应复刻。
- 推论:master 52b016f1(RET-OP3)单侧落地致 canonical 口径 httpd 4252/0/4、curl 4085/0/0(实测),同族未吸收——canonical 门禁要恢复需先决契约准绳(root 决策项)。

## 3. 代码交付(fspec/funcdata 域登记项全闭合)
- fspec.rs: FuncCallSpecs.effective_extrapop 存储 + set/get(fspec.hh:1687-1688;ctor 初始化 cc:4927)。
- coreaction.rs: analyze_extra_pop 完整写回端口(INDIRECT+call→setEffectiveExtraPop(soln-soln2);op→INT_ADD(spcbase,soln) 重写;cc:261-318,签名 &mut);早退守卫归位 cc:264-267(arch evalfp_called/defaultfp 模型源,替换误用的 funcp 投影);ActionExtraPopSetup cc:1454 setEffectiveExtraPop 写回。
- httpd/curl 实测 extrapop 已知(8)→守卫早退,写回不触达(E2E 不变);未知 extrapop 写回路径 UNTESTED(无 32 位语料,B2 件待建)。

## 4. 门禁数字(全 release 口径,RUGRA_MIRROR)
| 状态 | httpd(canonical) | curl | 备注 |
|---|---|---|---|
| master af98f92e(lane 基) | 2331/0/0(DL 测) | 2689/0/0(DL 测) | 停车基线 |
| master 当前 52c9abd5 | 4252/0/4 | 4085/0/0 | RET-OP3 52b016f1 引入回归(实测) |
| 本分支合流(RC1+RC2+RC3) | **2137/0/16** | **4073/0/0** | ≤2331 ✓ defects=0 ✓ numbering 16 ✗(VARMAP-DUPDECL-EXTRAOUT-0001,varmap/printc 域) |
| 同上 vs direct-runner golden | 1981/0/16 | — | 库级同契约读数 |
- main --func: 合流态 >300s wall(~8.5s CPU 阻塞)挂起于 `[BLOCKSTRUCT] main finalize_structure: 89 -> 12` 后 → HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001;DL 旧基 665→892 的演化在当前基不可复现(挂起先于打印)。
- callspec-identity fixture:当前 master 已红(active_input API 漂移+base 落后),本 lane 重钉尝试后按原样回退,登记 CALLSPEC-FIXTURE-APIDRIFT-0001。

## 5. 移交
①GOLDEN-CONTRACT-PUSHABSORB-0001(root 裁决 canonical vs direct-runner 准绳);②VARMAP-DUPDECL-EXTRAOUT-0001(numbering=0 阻塞项);③HTTPD-MAIN-POSTBLOCKSTRUCT-HANG-0001;④CALLSPEC-FIXTURE-APIDRIFT-0001;⑤同族:headless 桥接输入建模 lane(参数锁/栈帧传递)。

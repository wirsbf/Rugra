# httpd main 归因报告（Lane DL, wt/sb-httpdmain）— 2026-09-23

- Oracle: Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`（x86:LE:64:default / gcc cspec / analyzeHeadless defaults）
- Rugra 基线: master `8fd23706`（本 worktree HEAD）
- 语料: `examples/httpd`（PIE, stripped, 动态链接 libapr/libaprutil/libc）；golden = `tests/golden/ghidra_httpd_1204.c`
- E2E 基线（本 lane 亲测, sha256 90dfaa04…）: httpd **2331/0/0**，其中 **main = 665**（语域最大差异函数；任务书写的 ~1180 是 Lane I 回归时代的数字，Lane N 修复后已回落）
- 方法: compare_ghidra.py 归一化骨架 diff + difflib 分类（Lane V 分类学），辅以锁定 oracle `.sla` 模板 dump（`/dev/shm/rugra-tests/sb-httpdmain/sleigh_probe`，SLEIGH `oneInstruction` 实测）

## 1. 差异分类（baseline main, 665 行 = −514 golden-only / +151 rugra-only）

归一化后 golden 532 行 vs rugra 169 行（仅 ~18 行匹配——整函数栈模型分歧）。

| 类别 | 行数(约) | 代表样例 | 怀疑域 |
|---|---:|---|---|
| push-store（返回地址/槽位存储缺失） | 126 | golden `V[-LIT] = LIT;`（`local_d0 = 0x12b869;` / `plVar12[-1] = 0x12ba26;`）vs rugra 完全缺失 | **disasm/x86_lift.rs（lifter CALL 模板）→ 已修，见 §2 RC1** |
| case 体/语句块缺失（switch 空体塌陷） | ~318 | golden 15 个 case 的体 vs rugra `switch(...) { }` 空体 + 体被拍到循环外（`strcasecmp(); if (iVar2 == 0) {` 连行） | jumptable/switch 结构化 + printc 断行（后续 wave） |
| 调用带参（args 全缺） | 41 | golden `V = apr_getopt(V[LIT],&DAT_LIT,V,V);` vs rugra `apr_getopt();` | funcLinkInput/callspec 层（inject 路径, "Unknown calling convention"）— CALLSPEC 族 |
| switch case 标签 + goto 标签 | 29 | `case 0x43:` / `LAB_0012bfd8:` / `switchD_0012ba94_caseD_40:` | 同 case 体类 |
| 裸调用（无参无返回捕获） | 64 | rugra `apr_app_initialize();` | 同"调用带参"（同根） |
| 裸 varnode 泄漏 | 28 | `SUB84(register0x000a5c49,0)` / `uRam00000000000aa233` / `ZEXT14` | varmap 覆盖 + lifter 形态 |
| 全局存储走指针 | 16 | rugra `*param_2 + 0xa11b8 = puStack_a8;` vs golden `ap_server_pre_read_config = ...` | PIE GOT 全局符号化（varmap/symbol 层） |
| 声明集合差异 | ~30 | rugra `in_register_00000020`/`in_register_00000288` 泄漏声明, golden `undefined8 *puVar8;` 等 | 同 args 缺失（参数未建立→寄存器泄漏） |

**top 类 = push-store 缺失 + 由它触发的整函数栈模型分歧**（126 行直接 + 栈槽/声明级联）。

## 2. 根因链（含 Ghidra 证据）

### RC1（已修, 本 lane 域 disasm/x86_lift.rs）
锁定 oracle `.sla` 的 `call rel32` 模板实测为**三 op**:
```
INT_SUB  RSP <- RSP, 8
STORE    ram[RSP] <- const(inst_next, 8)     ← 返回地址 push
CALL     <- ram:target
```
`call rax` 为四 op（`COPY tmp <- RAX` 先于 RSP 调整 → rsp 相对间接目标用 pre-push 指针）。`ret` 为三 op（`LOAD tmp <- ram[RSP]; INT_ADD RSP; RETURN tmp`）。Rugra lifter 此前只发射裸 CALL（旧注释声称"faithful to ia.sinc"是错的——.sla 实测推翻）。golden main 的 131 条 push 存储（98 条紧邻调用）正是该模板在"callee 不可见（外部 PLT）+ SP 不可解"时的存活形态。

### RC2（已修, 本 lane 域 examples/httpd_decompile.rs — 驱动层）
httpd runner 此前只挂裸 `Architecture::new()`（无 cspec）→ 所有函数 "Unknown calling convention"（stderr 逐函数告警）、defaultfp 缺失。已按 curl worker 同序补 cspec 解析链（x86-64-gcc.cspec → archid/register_xref/commentdb/TypeFactory/PcodeInjectLibrary/UserOpManage → `parse_compiler_config`，defaultfp=`__stdcall` extrapop=8）。

### RC3（**登记不写** — 落在 fspec.rs/funcdata.rs，已被并发车道占用）
push 吸收链。oracle 行为（证据）:
- golden httpd **28/29 函数吸收 push**（ap_fini_vhost_config 等全吸收）, **只有 main 保留**（SP 在循环里变深度 → StackSolver 不可解 → 动态形态 `plVar12[-1] = …` 存活; 见 coreaction.cc:261 `analyzeExtraPop`: 解出后 `op→INT_ADD(spbase,const)` 重写 + `fc->setEffectiveExtraPop`）。
- 已知 extrapop（defaultfp=8）时 analyzeExtraPop 早退（cc:271-273），SP 跨调用恢复走 **call 的 INDIRECT spacebase bump（funcdata/heritage 层）**；固定槽 push 死存储由 ActionDeadCode 消灭（coreaction.cc:4025-4063 的 located-varnode 扫描; 模型 effect 表的 return_address 槽（fspec.cc:2690, `<returnaddress><varnode space="stack" offset="0"/>`）不消费 caller 帧内负偏移槽）。
- Rugra 缺口: `analyze_extra_pop`（src/coreaction.rs:11483）是骨架——INDIRECT-bump 写回 + `setEffectiveExtraPop` 存储均标注 CALLSPEC-0001 未做；funcdata 侧 spacebase bump 未接。后果（实测）: RC1 单独 httpd 2331→**2667**（push 以 uStack_168.. 序列整体存活）; RC1+RC2 → **2542**（cspec 又暴露 extraout_RDX/in_RCX 等 model 应用缺口）+ main 4 个重复声明（uVar8/13/14/15——同槽双符号, varmap 级联）。

## 3. 验证记录

| 门禁 | 基线 | RC1+RC2 后 | 结论 |
|---|---|---|---|
| httpd E2E | 2331/0/0 | 2542/0/**4** | **未过**（阻塞于 RC3, 占用域） |
| curl E2E | 2689/0/0 | **2689/0/0**（亲测, curl 主路径走 SLEIGH lifter 不经 x86_lift; RC1 只影响其 prototype pre-pass） | 过, 字节级 totals 恒等 |
| --func main | 665 | 892（+227, 形态见 §2 RC3） | 未过（同上） |

改善面（RC1+RC2 vs 基线, 逐函数）: ap_update_vhost_from_headers 212→178 / ap_pregsub 212→181 / ap_update_vhost_given_ip 57→47 / ap_getword 44→36 / ap_matches_request_vhost 25→24 / ap_getparents 137→130 / ap_pregcomp 15→14 / ap_strcasestr 50→47; 回归根: main 665→892 + ap_fini 383→404 + ap_ht_time 80→96 + 若干小函数 +~30。

## 4. 交付状态

- RC1/RC2 修复**暂驻本 lane 分支**（wt/sb-httpdmain），**CALLSPEC-0001（RC3）落地并复测 2542→≤2331 前不得并入 master**。
- RC3 根因 + 方案已登记 TODO board（HTTPD-CALL-PUSH-0001 → 依赖 CALLSPEC-0001）。
- 后续 wave 建议顺序: ① CALLSPEC-0001（占用车道, analyzeExtraPop 写回 + setEffectiveExtraPop + funcdata spacebase bump）→ 复测本分支两提交; ② main 的 switch 空体塌陷（jumptable/printc 断行）; ③ 调用 args 全缺（funcLinkInput inject 路径）; ④ RET 模板三 op 化（与本修复同族, P-code 完整性遗留项）。

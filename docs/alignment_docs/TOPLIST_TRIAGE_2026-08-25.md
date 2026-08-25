# A90 — Top-10 差距函数排序与根因分流（只读）

- 日期: 2026-08-25 | Agent: A90 (只读分流, 零仓库改动, 零 cargo)
- 输入: fresh 全量 `/tmp/rugra-reports/e2e-post-timeout-fix.stdout` (sha256 `fad3edf4fad2f5005bf5484e8b553bb77be608d4d0b6feb4a0f81ad5dbc67152`, 124/124 函数全产出)
- Golden: `tests/golden/ghidra_curl_1204.c` (12.0.4 正典)
- 工具: `python3 tools/compare_ghidra.py <fresh> golden --summary-only`
- 基线复核: **Total skeleton diff = 2713 / defects = 0 / numbering = 1** — 与正式基线 2713 一致
- 排除: synthetic import stub (diff≤7 外部桩) + hugehelp(18)/progressbarinit(21)/my_fwrite(17)（专属 Agent 在跑）

---

## 1. Top-10 清单（真实内部函数, skeleton diff 降序; 合计 2098/2713 = 77% 集中度）

| # | 函数 | diff | 一句话根因假设 |
|---|---|---|---|
| 1 | main | 724 | 组合体: struct 局部(URLGlob/OutStruct/ProgressData/stat/errorbuffer)全部未恢复 → 91 个 `in_ram_*`+37 行 extern DAT 声明; config 初始化 for + argv 解析 do-while 双循环丢失; `argc` 误型 `char*`; 14 处弃置条件 |
| 2 | getparameter.constprop.0 | 491 | 88-case 跳表恢复失败 → `switch(...) {}` 空壳(48 case 体 0 恢复) = 已知 `JUMPTABLE-PIPELINE-0001` 段2/段3 BLOCKED 的 E2E 投影 |
| 3 | parseconfig.constprop.0 | 150 | my_get_line 配置行 while 循环整体丢失(调用退化为直线)+9 处 `(cond);` 弃置分支+分支倒挂(`pFVar5==0` 分支内跑 my_get_line)+return 后僵尸代码直线输出 |
| 4 | file2string.part.0 | 127 | `while(fgets)`+`do-while(strlen)` 双循环消失, 112 行函数剩 ~2 条语句; `code_r0x00003BE8:` 裸标签泄漏; A36 报告的 heritage/breakpool 回归域(0→143)收敛残余 |
| 5 | next_url | 120 | URLGlob/URLPattern **成员导航失败**: 168 处 `->literal` 首成员退化+裸偏移(`+0x38/0x41/0x42...`); 双向迭代 do-while 丢失; `next_url::beenhere` 函数级静态符号缺失 |
| 6 | glob_set | 116 | glob 家族同源: struct 域导航失败+5 处弃置条件+循环丢失 |
| 7 | glob_range | 107 | 同上, 20 处 struct-field 表达式差异最重 |
| 8 | match_url | 102 | 返回类型/含 struct 值传参数型未恢复(`long match_url(char*,long,long)` vs `char* match_url(char*,URLGlob)`); **空 LHS 赋值 ` = (...)` 4 处+裸 var 语句** = emit 级语法破坏但 defects 计数漏检 |
| 9 | my_get_line | 82 | A36 披露的 heritage/breakpool 交互回归域(83→168 后收敛); 循环内分支条件丢失 2 处 |
| 10 | glob_word | 79 | glob 家族同源: struct 导航+循环丢失 |

次级(未入榜): my_get_token 78 / helpf 72 / myprogress 66 / glob_url 17 / __do_global_dtors_aux 14 / _start 13 / __libc_csu_init 13 / _init 10。

## 2. 全局 Smoking Gun（跨函数共性, 比 per-fn 更可操作）

对**整个输出**统计（Rugra vs golden）:

| 指标 | Rugra | Ghidra golden | 含义 |
|---|---|---|---|
| for/while 循环 | **3**（仅 my_get_token/my_get_line/glob_set) | 38 | 回边循环结构 ~92% 丢失 |
| goto | **0** | 56 | 非结构化区域完全不输出 goto |
| switch case | **0** | 53 | case 体 0 恢复(2 个 switch 均空壳) |
| 弃置条件语句 `(cond);` | **47**（13 函数: main 14/parseconfig 9/glob_set 5/glob_range 5/...) | **0** | 分支条件布尔未被 if/while 消费 → 结构化丢边或 mark_implied 失败 |
| `register0x…` 泄漏 | 220 (18 种) | 0 | 未符号化 varnode 直接进 C 文本 |
| `unique0x…` 泄漏 | 142 (24 种) | 0 | 同上(unique 空间临时量) |
| `in_ram_*` 声明 | 103 (91 种) | 0 | unlinked-ref 家族(B2 域, 已登记) |
| `stack0xfff…` 泄漏 | 18 | 0 | 同 raw-varnode 家族 |
| `code_r0x…:` 裸标签 | 7 | 0 | 非结构化块入口以原始地址标签输出 |
| 裸字符串地址实参 `0x62f8 /* 25336 */` | 117 | 0 | 字符串/DAT 符号解析未接线(B3/PRINTC-PTRCONST 生产接线待 D3 域) |
| `extraout_*` 变量 | 18 处 | 0 | 未消费寄存器写以 extraout 泄漏(同 unlinked 家族) |
| 空 LHS 赋值 ` = (...)` / 裸 var 语句 | 4 / 4 | 0 | emit 级语法破坏, compare 的 defect 正则漏检 |

**核心结论**: top-10 的 2098 行差距不是 10 个独立 bug, 而是 **4 个横切家族的函数级投影**:
- **F1 循环/分支结构化丢失**（循环 38→3、goto 56→0、case 53→0、弃置条件 47）— 贡献最大;
- **F2 struct 类型/成员导航失败**（`->literal` 175 处 + 裸偏移; next_url/glob_* 家族）;
- **F3 raw varnode/符号泄漏**（register/unique/stack/code_r/in_ram ≈ 490 处 + extraout）;
- **F4 字符串/DAT 常量解析未接线**（117 处裸地址实参; 已有 D3 域登记, 非新 TODO）。

## 3. Top-5 逐函数发散症状与管线阶段分叉假设

### 3.1 main（724）
症状: ① Ghidra 恢复 `URLGlob glob / OutStruct outs,heads / ProgressData progressbar / stat fileinfo / bool errorbuffer[256]` 等 struct 局部; Rugra 全部退化为 `abStack_388/uStack_230/...` 原始栈偏移 + 91 个 `in_ram_*` 全局读注入 + 头部 37 行 `extern long DAT_...`。② config 置零 for 循环、argv 选项 do-while 均丢失; `curl_easy_setopt` 调用序列保留但布尔实参以 `ZEXT48((undefined4)DAT & 0x20)` 泄漏。③ 头部 2 条 WARNING 注释(golden 无)。④ `int main(char *argc,...)` 签名错误。
阶段假设: **varmap(ScopeLocal 符号建立)×typeop(局部类型传播)×blockaction(循环) 三域叠加**; `in_ram_*`/extern DAT 属 B2 unlinked-ref 域; argc 误型 = 入口 main 原型未取(驱动/fspec 域, 独立可修)。

### 3.2 getparameter.constprop.0（491）
症状: golden 475 行/48 case/17 goto; Rugra 36 行, `switch((int*)(int)(long)*((int*)unique0x00009500) + 0x7018) { }` **完全空壳**; 函数入口逻辑(getopt 风格 flag 解析)只剩 `strlen(unique0x…)` 碎片。
阶段假设: **flow→jumptable 恢复管线**(已知 `FLOW-JUMPTABLE-GETPARAM-0001`: 恢复跑在 raw Funcdata 无 SSA/基本块 + flow.rs:2561 吞失败; `JUMPTABLE-PIPELINE-0001` 段2 funcdata/fspec/段3 flow 仍 BLOCKED)。修复后预期 -400+。

### 3.3 parseconfig.constprop.0（150）
症状: golden 105 行含 4 循环+8 goto; Rugra 71 行直线: `if (pFVar5 == 0x0) { my_get_line(pFVar5); }` 分支倒挂(fopen 失败分支内读文件)、9 处 `(cond);` 弃置、`return 0` 后 free/my_get_line/my_get_token 僵尸序列直线输出。
阶段假设: **循环结构化(blockaction 域) + 分支条件消费(mark_implied/结构化丢边)叠加**; 与 A36 披露的 heritage/breakpool 回归同域。

### 3.4 file2string.part.0（127）
症状: golden 112 行(while(fgets) + do-while(strlen) + realloc 拼接); Rugra 31 行: 一条 `fgets((long*)((int*)in_RSP - 328), 0x100)` + `(pcVar4 == 0);` + `code_r0x00003BE8:` 裸标签 + `__stack_chk_fail(0,0,0,0)`。
阶段假设: **A36 域(heritage merge/breakpool 交互)致循环体块在结构化前丢失**; raw varnode/label 泄漏为伴生症状(F3)。

### 3.5 next_url（120）
症状: golden 有 `next_url::beenhere` 静态符号、`glob->pattern[i].type/.content.Set.elements` 级导航、双向 do-while; Rugra 168 处 `(&(&(...register0x0->literal)->literal...) + 0x42)` **每层成员解析都退化为 union 首成员 `.literal`+原始字节偏移**, 两个迭代循环消失, `__printf_chk(1, 0x14910 /* 84240 */)` 字符串未解析, 尾部 `code_r0x000050E7:` + return 后僵尸块。
阶段假设: **类型传播未把 URLGlob/URLPattern 复合类型附着到指针链**(typeop/varmap 域), PTRSUB 偏移→成员解析失败; 循环丢失同 F1。

## 4. TODO 候选（避开在跑租约: coreaction.rs=A70/A82/A88, typeop.rs=A71, blockaction.rs=A72）

### T1 `PRINTC-RAW-VARNODE-QUARANTINE-0001` (P0)
- write-set: `src/printc.rs` + `docs/api/printc.md`（发射前与 root 确认 printc 租约; 与排队中的 PRINTC-WARNING-COMMENT/PRINTC-SWITCH-EMIT 串行）
- 内容: Ghidra printc 从不把 unique/register/stack 空间原始 varnode 名写进 C 文本(它走 ScopeLocal 符号或 unnamed-location 注释路径, printc.cc emit 变量名路径); Rugra 现有 register0x 220/unique0x 142/stack0x 18/code_r 标签 7 ≈ 387 处泄漏。
- 依赖: 无 src 依赖(B2 unlinked-ref 家族的 raw-space 子族; 不与 coreaction/typeop/blockaction 重叠)
- 验收: 全输出正则 `register0x|unique0x|stack0x|code_r0x` 计数归零; skeleton 差分显著下降; `--func file2string/next_url/match_url` 复核。

### T2 `BRANCHCOND-DISCARDED-DIAG-0001` (P0, 诊断型, 只读+fixture)
- write-set: `tests/oracle/branchcond_diag_1204.*` + runner + `docs/alignment_docs/`（零 src 改动）
- 内容: 47 处 `(cond);` 弃置条件归因: 逐处判定属 (a) `COREACTION-MARKIMPLIED-COUNT-0001`(coreaction.cc:3426/3454, 已 QUEUED) (b) blockaction 结构化丢边 (c) condexe/cleanup 域, 产出归属表。
- 依赖: 无（诊断不占租约; 结论分别喂给 MARKIMPLIED/BLOCKSTRUCT 后继）
- 验收: main 14+parseconfig 9+glob_set 5+glob_range 5 全部有双侧 Ghidra 行为证据归属; 每归属项绑定既有或新 TODO ID。

### T3 `VARMAP-STRUCT-OFFSET-MEMBER-0001` (P1)
- write-set: `src/varmap.rs` + docs + fixture（若诊断发现 PTRSUB 偏移→成员解析在 typeop 侧, 则改依赖 A71 释放后发射, 先做 varmap 侧 symbol 附着切片）
- 内容: next_url/glob_* 家族 175 处 `->literal` 首成员退化+裸偏移; Ghidra 由 attached datatype 的 offset→member 解析(varmap.cc ScopeLocal 复合符号路径)产生 `pattern[i].type` 级导航。
- 依赖: T2 归因结论(确认解析层归属); A71 若涉 typeop
- 验收: next_url 168 处 `->literal` 归零(或降为合法 literal 访问); `--func next_url/glob_url` skeleton 显著下降。

### T4 `MAINPROTO-ARGC-INT-0001` (P2, 小而确定)
- write-set: `examples/curl_decompile.rs`(驱动) 或 `src/fspec.rs` 入口原型注册 + docs
- 内容: `int main(char *argc,char **argv)` → golden `int main(int argc,char **argv)`; Ghidra 对 main 符号应用 C 主函数原型; Rugra 把 argc 传播成了 char*(引发后续 `strrchr(argc,...)` 误用串)。
- 依赖: 无（两文件均不在租约)
- 验收: main 签名行与 golden 字节一致; 全局 skeleton −1 起步且无回归。

### T5 `COMPARE-EMPTYLHS-DEFECT-CATEGORY-0001` (P2)
- write-set: `tools/compare_ghidra.py` + `tools/audit_syntax.py`
- 内容: match_url 4 处空 LHS 赋值 ` = (...)`/4 处裸 var 语句是真实 emit 缺陷但 defects=0 漏检; 给 compare 工具加 `empty-LHS assignment` 与 `bare var statement` 两类 defect 正则, 防止此类语法破坏静默过关。
- 依赖: 无（纯工具, 只读仓库内文件由 root 串行合入）
- 验收: 新正则在 fresh 输出上计 8 处(4+4)且 golden=0; 登记 emit 缺陷 TODO 后计数随修复归零。

## 5. 备注
- `/tmp` 配额被其他 agent 的 ~6GB debug 二进制打满(本 agent 未删除任何他人文件; 分析走 `$HOME/.a90tmp` TMPDIR)。
- match_url 的 numbering=1 为全输出唯一编号问题, 与空 LHS 赋值同源(符号缺失导致的声明/使用不闭合)。
- glob_url(17)/my_get_token(78)/helpf(72)/myprogress(66) 的症状均落在上述 F1-F4 家族内, 无独立新根因。

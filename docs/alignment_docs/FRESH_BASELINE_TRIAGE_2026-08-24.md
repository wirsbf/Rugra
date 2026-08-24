# B6 — Fresh 基线逐函数分流报告（2026-08-24）

只读分流 Agent 产出。未修改仓库任何文件、未运行 cargo/build。

## 0. 基线与口径

- fresh 基线：`/home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/curl.stdout.c`
  （SHA-256 `fc9a33ba…91d60e7`，commit `f7b3c31` release 单次运行，与交接文档 §1 一致）。
- golden：`tests/golden/ghidra_curl_1204.c`（12.0.4 锁定 oracle）。
- 全局 compare：**123 函数匹配，skeleton diff 总计 2409，defects=2（helpf/file2string.part.0 各 1 个
  empty-else，即已知 `PIPE-ORDER-EMPTYELSE-0001` 症状迁移，非新增），numbering=1（match_url）**。
  stderr 噪音未混入（`2>/dev/null`）。
- 排除 ~48 个 synthetic import stub 与已认领三函数（hugehelp/progressbarinit/my_fwrite）后，
  真实内部函数按 skeleton diff 排序的头部：getparameter 504、glob_word 176、parseconfig 163、
  next_url 154、my_get_line 151、glob_set 139、file2string 137、helpf 131、match_url 129、
  glob_range 111、myprogress 103、my_get_token 94。

## 1. Top 5 真实函数与最早管线分叉假设

### 1.1 `getparameter.constprop.0` — diff=504（Rugra 67 行 vs Ghidra 475 行）

症状：body 塌缩到 golden 的 14%。golden 的 `switch((int)pCVar10 - 0x23U & 0xff)`（48 个 case，
约 350 行）在 Rugra 输出中**完全缺失**；另有条件语句化 ×6（`(*flag == '-');`）、
字符串实参数字化（`helpf(0x6255 /* 25173 */)` ×4）、寄存器泄漏（`uVar_8f00`/`in_register_00000110`/
未声明 `vn_9d00`/`uVara8`/`uVarb8`）、伪造死循环
`while (config == 0) { config = config - 1; … }`。

**最早分叉假设：flow/discovery 阶段（Action 树之前，`ActionStart → followFlow`）**。
stderr `[STEP]`：`flow done 124ms raw_ops=677 bblocks=36` —— 48-case 跳转表函数至少需要
50+ 基本块；36 块说明间接跳转的 jumptable 目标未恢复，case 体从未成为可达块，
后续结构化/死代码阶段将其整体丢弃。指令确实被线性 lift（2609 字节 ≈ 677 ops），
缺的是**间接分支目标发现**（jumptable 恢复链路），而非反汇编本身。

### 1.2 `glob_word` — diff=176（98 vs 151 行）

症状：输出头部 5 条 `/* WARNING: Possible PIC construction … Changing call to branch */`
（0x4b4c/0x4cf2/0x4e5a/0x4f22/0x4b7b）；golden 中 **PIC 警告为 0**。10 级指针链
（`byte * * * * * * * * * *`）、字符串数字化（`puts(0x14962 /* 84322 */)` vs
`puts("internal error")`）、空 while 体、内联泄漏的 `code_r0x00004AF0:` 标签、
被当作数据的返回地址 store（`*(in_RSP-48) = 0x4b0d`）。

**最早分叉假设：flow 阶段跨函数体过度追踪**。关键证据：5 个警告中 3 个地址
（0x4cf2/0x4e5a/0x4f22）落在 glob_set（0x4bc0–0x4d50）/glob_range（0x4d60–）**函数体内部**，
但警告挂在 glob_word 头上 —— 说明 glob_word 的 flow trace 沿尾跳进入了被调函数体，
`visited` map 被污染后 `FlowInfo::checkContainedCall`（flow.cc:1359-1404，Rugra 忠实移植于
`src/flow.rs:2023 check_contained_call`）把合法 CALL 误判为 PIC 改成 BRANCH：
call spec 被删 → 参数/返回类型丢失 → 下游类型塌缩成 10 级指针链；
CALL 语义残留的返回地址压栈变成常量 store。函数尺寸 344 vs golden 323 也支持过度追踪。

### 1.3 `parseconfig.constprop.0` — diff=163（81 vs 105 行）

症状：13 处条件语句化（golden 是活分支，如 `(0xf9 < piVar3);` 对应
`if (0xf9 < sVar4) { free(); goto; }`）、循环守卫反相（`while (in_RBP == 0)` vs golden
`line != 0x0`）、恒真自比较 `if (*uVar_c900 == *uVar_c900) { return; }`、尾部泄漏标签
`code_r0x00003EF1:`/`code_r0x00003ED0:`、负偏移栈参数泄漏 `in_stack_fffffffffffffeb7`、
getparameter 调用带 5 个实参且引用未声明 `uVarb0`。

**最早分叉假设：结构化阶段（`ActionBlockStructure` 前后的 goto 级联）**。stderr：41 块中
21 条边被 TraceDAG 标 "likely goto"、`goto cascade rounds=10`、`finalize_structure: 41→33
(removed 8 DEAD)` —— goto 过度标记把条件块孤立，CBRANCH 被当冗余丢弃，布尔运算残留为裸
表达式语句。恒真自比较则疑似规则阶段 compare 输入被污染（INT_EQUAL(x,x)）。

### 1.4 `next_url` — diff=154（91 vs 99 行）

症状：输出头带 `/* WARNING: Type propagation algorithm not settling */`；
`&(&(&…->literal)->literal…)->literal` 指针字段链（与 progressbarinit 的 7 层 `->total`
同族，即 TypeOpPtrsub::propagateType/downChain/STOP 旗标缺口，TYPE-PTRWIDTH-PTRSUB-0001
partial 后续）；6 处条件语句化；畸形赋值发射（` = (uVar18 = uVar18 + 1);`、
`if ( = (bool)…`、`* = uVar28 = bVar1;`）；原始 P-code 算子名直接出现在 C 表达式
（`SUB44`/`SEXT48`/`ZEXT48`，全文件 31 处，golden 0 处）。

**最早分叉假设：mainloop 18-Action 链尾部的 InferTypes 不收敛（NonzeroMask→InferTypes
未到达不动点）**，每轮给指针叠一层字段解引用；printer 侧再叠加 cast 渲染缺口
（printc.rs:1586-1650 对 INT_ZEXT/INT_SEXT/SUBPIECE 回退到 rpn_operator_name_ext 名称形式，
而 Ghidra printc.cc 在 C 模式永远发 `(int)` 类 cast）。

### 1.5 `my_get_line` — diff=151（119 vs 69 行，过度展开）

症状：声明爆炸 —— `extraout_var` ×5、`in_register_00001240…13c0` ×8、
`in_stack_ffffffffffffedb8`、`uVar_100002eb` 类回绕十六进制名（= 负偏移按 u64 打印）；
两个空 do-while 体（strlen 惯用法循环体丢失）；strlen 惯用法块重复展开；
`__stack_chk_fail(0,0,0,0,…,14 个实参)`。

**最早分叉假设：varmap/ScopeLocal + merge(extraout) 域** —— 4096 字节局部数组未被恢复为
`bool buf[4096]`（golden 有），extraout varnode 未被合并/吸收（varmap.rs:2781 的
`extraout_` 命名本身是 database.cc:2434 忠实分支，泄漏说明上游 merge/action 未消掉它们），
大栈帧（>4096）偏移到名字的映射出现符号回绕。与在板 `MERGE-DATATYPE-SCALE-0001`
（my_get_line_diag，MISMATCH）同域，建议并入而非新开。

## 2. 跨函数症状簇（按扇出排序）

| 簇 | 计数 | 函数分布 | 最相关阶段 |
|---|---|---|---|
| A 条件语句化 `(expr);` | 68 处 / 14 函数 | parseconfig 13、glob_word 11、my_get_token 7、getparameter 6、next_url 6 | blockrecovery 结构化 + deadcontrolflow（`PIPE-ORDER-EMPTYELSE-0001` 只覆盖 empty-else defect，此簇更广） |
| B 指针/字符串常量数字化 | ~40 处 | getparameter、glob_word、parseconfig、myprogress | ActionConstantPtr(leased coreaction) + PrintC constant_to_pointer/StringManager（print 侧可独立修） |
| D 栈/寄存器名泄漏（in_register_/in_stack_/uVar_10000xxx） | 85+ 处 | my_get_line、myprogress、parseconfig、glob_word | varmap/ScopeLocal + 寄存器名表 |
| E 原始算子名 SUB44/SEXT48/ZEXT48 | 31 处 / golden 0 | next_url、myprogress | printc cast 渲染 |
| F `code_r0x…` 标签泄漏 | 11 处 / 8 函数 | glob_word 2、myprogress 2、parseconfig 2… | blockaction goto + printc emitLabelStatement |
| C 类型不收敛→字段链 | next_url、progressbarinit | InferTypes/TypeOpPtrsub（已在板，TYPE-PTRWIDTH-PTRSUB-0001 + 交接 §3） |

## 3. 新 TODO 候选（避开在占租约：typeop/variable/database/funcdata/ruleaction/coreaction/jumptable/action/subflow.rs、tests/oracle/lanedivide_*）

### 3.1 `FLOW-TAILCALL-OVERTRACE-0001` — P0

- 根因域：flow 沿尾跳/尾 call 追进被调函数体，污染 `visited`，`checkContainedCall` 误发
  CALL→BRANCH（glob_word 5 处，golden 0 处）。
- Ghidra 对照：`flow.cc:1359-1404 FlowInfo::checkContainedCall` + flow 追踪边界逻辑
  （`FlowInfo::flow`/`branchcallback`/`FallthruCallBack` 等，移植前逐行读）。
- Rugra 入口：`src/flow.rs:2023 check_contained_call`（移植本身已忠实，误触发源头在
  visited 构造）。
- write-set：`src/flow.rs`、`docs/api/flow.md`、本 TODO 行。
- 依赖：无（flow.rs 空闲）。
- 验证：`cargo run --release --example curl_decompile` 后 grep "Possible PIC" 计数 5→0；
  `python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func glob_word -v`
  skeleton 176 显著下降；全量 summary 无新 defect。

### 3.2 `FLOW-JUMPTABLE-GETPARAM-0001` — P0（先只读诊断）

- 根因域：getparameter 48-case 跳转表未恢复（`raw_ops=677 bblocks=36`），switch 体整体缺失。
- Ghidra 对照：`jumptable.cc JumpTable::recoverAddresses` + `flow.cc` 的
  `FlowInfo::doComplexJumpTable`/jumptable 恢复调度。
- 诊断目标：定位丢失在 flow.rs 的间接分支调度（如 `tablelist`/BRANCHIND 收集）还是
  jumptable.rs 内部恢复算法；**若在 jumptable.rs 则 BLOCKED 等 jumptable 租约释放**，
  本 TODO 只登记证据不改文件。
- write-set（诊断后定）：`src/flow.rs` + docs（若确在 flow 侧）。
- 依赖：jumptable.rs 租约（仅当修复点在其内）。
- 验证：`--func getparameter.constprop.0` skeleton 504 显著下降、输出出现 switch/48 case。

### 3.3 `BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001` — P0

- 根因域：TraceDAG "likely goto" 过度标记（parseconfig 41 块 21 条边）→ goto 级联 →
  条件块孤立/DEAD 移除 → CBRANCH 丢失、布尔运算残留为裸语句（全文件 68 处/14 函数）；
  同链路产出尾部 `code_r0x` 标签泄漏（11 处）与空 while/do 体。
- Ghidra 对照：`blockaction.cc` 结构化主循环 + `action.cc RuleBlockGoto`
  （goto 仅在结构容不下时标记；条件布尔永不允许孤儿化）；先读
  `RuleRedundantBranch`/`RuleDeterminedBranch`（coreaction.cc:5652/5657 对应域，
  该文件租约在 coreaction —— 本 TODO 修复点预期在 blockaction.rs，若根因确在
  RedundBranch/DeterminedBranch 则改登记并 BLOCKED）。
- Rugra 入口：`src/blockaction.rs`（stderr `[COLLAPSE] TraceDAG marked … likely goto edges`、
  `goto cascade`、`finalize_structure removed N DEAD` 打点处）、`src/tracedag.rs`。
- write-set：`src/blockaction.rs`（+`src/tracedag.rs` 如需）、对应 docs/api、本 TODO 行。
- 依赖：与 `PIPE-ORDER-EMPTYELSE-0001` 分工——该 TODO 收敛 empty-else defect，本 TODO 收敛
  条件孤儿簇；串行避免同文件冲突（EMPTYELSE 若也动 blockaction 需排期）。
- 验证：全文件 bare-paren 语句 68→≤5；`--func parseconfig.constprop.0`（163↓）、
  `--func glob_word`（176↓）；机制 B 差分门禁 defects 不得新增。

### 3.4 `PRINTC-CAST-OPNAME-LEAK-0001` — P1

- 根因域：INT_ZEXT/INT_SEXT/SUBPIECE 在表达式位回退到算子名文本（`SUB44(x,0)`/
  `SEXT48`/`ZEXT48`，31 处，golden 0 处）；Ghidra printc.cc C 模式只发 C cast。
- Ghidra 对照：`printc.cc` `PrintC::opIntZext/opIntSext/opSubpiece`（cast 判定与
  `pushCast`/`constant_to_pointer` 路径，移植前逐行读）。
- Rugra 入口：`src/printc.rs:1586-1650`（`rpn_operator_name_ext("ZEXT"/"SEXT"/"SUB")` 回退）。
- write-set：`src/printc.rs`、`docs/api/printc.md`、本 TODO 行。
- 依赖：无（printc.rs 空闲；机制 B 白名单文件，需跑差分门禁）。
- 验证：`grep -cE "SUB4|SEXT4|ZEXT4" 输出` = 0；`--func next_url -v` skeleton 154↓；
  `tools/compare_ghidra.py … --summary-only` 差分门禁。

### 3.5 `PRINTC-PTRCONST-DAT-SYMBOL-0001` — P1

- 根因域：指针类型常量实参打印成裸 `0x61e4 /* 25060 */`（~40 处，如
  `curl_getenv(0x61e4)`、`fopen(filename, 0x61c2)`），golden 打 `&DAT_001061e4` 或字符串
  字面量（合法字符串经 StringManager）。
- Ghidra 对照：`printc.cc PrintC::pushConstant → constant_to_pointer` + `stringmanage.cc`
  StringManager 查询；注意与 hugehelp §3.1.3（ActionConstantPtr 在 Action 阶段建 PTRSUB，
  coreaction 租约在占）分工——本 TODO 只做 **print 侧已存在的指针常量渲染**，
  不触碰 ActionConstantPtr。
- Rugra 入口：`src/printc.rs`（常量→指针渲染）+ `src/stringmanage.rs`（字符串有效性查询）。
- write-set：`src/printc.rs`、`src/stringmanage.rs`、对应 docs、本 TODO 行。
- 依赖：无（两文件均空闲；机制 B 门禁）。
- 验证：`(0x[0-9a-f]{4} /\*` 模式计数 ~40→≤ 个位数（余下留 hugehelp 域）；
  `--func parseconfig.constprop.0 -v` skeleton 163↓；差分门禁。

### 不新开、建议并入既有 TODO

- my_get_line 声明爆炸/extraout/大栈帧命名 → 并入 `MERGE-DATATYPE-SCALE-0001`（同函数同域，
  在板 MISMATCH）与 `MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001`。
- next_url 类型不收敛字段链 → 交接文档 §3.2 已有完整路线（TypeOpPtrsub/downChain/STOP，
  coreaction/typeop 租约在占）。
- helpf/file2string empty-else defect → `PIPE-ORDER-EMPTYELSE-0001` 症状迁移，更新其
  evidence 即可。
- match_url numbering=1 → 对照 `TYPED-DECL-GAP-0001`（重复 uVarN 声明族）。

## 4. 报告元数据

- oracle：Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`；
  golden `tests/golden/ghidra_curl_1204.c`。
- fresh 输入指纹：`fc9a33baaab1310929b78b508b27f6810fd5e2eca7da80bf17d2a584e91d60e7`
  （commit `f7b3c31`）。
- 工具：`python3 tools/compare_ghidra.py`（summary + `--func … -v`），stderr 噪音未混入。
- 命令样例：
  `python3 tools/compare_ghidra.py /home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/curl.stdout.c tests/golden/ghidra_curl_1204.c --summary-only`

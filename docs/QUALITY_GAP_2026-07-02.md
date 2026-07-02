# Rugra vs Ghidra 反编译质量差距诊断（2026-07-02）

> 对比基准：`result/curl_cur.c`（Rugra 最新输出）vs `result/ghidra_curl_ref.c`（Ghidra 参考）
> 对象：curl 二进制的同一组用户函数

## 1. 总体差距（量化）

| 指标 | Rugra | Ghidra | 差距 |
|---|---|---|---|
| 输出行数 | 1596 | 3500 | 0.46× |
| 用户函数数 | 24 | ~30 真实 | Rugra 还多出 4 个伪函数（见 §3.1） |
| `while` | 39 | 34 | 接近 ✅ |
| `for` | 0 | 4 | Rugra 一个都没有 ❌ |
| `if` | 172 | 208 | 0.83× |
| `switch` | 18 | 2 | **Rugra 过度 switch 化（9×）❌** |
| `goto` | 2（且语法错误） | 61 | Rugra 结构化过度，但 goto 是坏的 |
| 强制类型转换 cast | 114 | 339 | 0.34× |
| `memcpy` | 0 | 6 | ❌ |

**结论**：行数只有 Ghidra 的 46%，但不是因为 Rugra 更精炼——而是因为大量变量/表达式根本没正确解析，导致输出**残缺且语法错误**。

## 2. 致命缺陷（Rugra 独有，Ghidra 完全没有）

这些是**语法错误或语义垃圾**，Ghidra 输出里一个都没有：

| 缺陷类型 | Rugra 出现次数 | 根因层 |
|---|---|---|
| `if () goto ;`（空条件 + 空 goto，**语法错误**） | 2 | 控制流结构化 + printc |
| `if ()`（空条件括号） | 4 | printc 条件 emit |
| `uVar_<十六进制>` 占位变量名（**215 次！**） | 215 | **varmap/HighVariable 缺失（见 §4）** |
| `uVar_<字母>` 占位名 | 9 | 同上 |
| `uVar_uVar_` 嵌套畸形名 | 1 | printc 字符串拼接 bug |
| `StackX_*` 占位栈变量名 | 116 | varmap ScopeLocal 未真正映射 |
| `param_N` 未命名参数 | 77 | 原型/参数识别未完成 |
| `while (...) {}`（空循环体） | 7 | 控制流结构化 + body emit |
| `else {}`（空 else） | 10 | 同上 |
| `switch ((iVar1 ^ iVar1))`（自异或=0 的 switch） | 存在 | 表达式化简 Rule 缺失 |

**Ghidra 对照**：以上 10 类缺陷在 `ghidra_curl_ref.c` 中**全部为 0**。

## 3. 结构性差距

### 3.1 函数级：Rugra 凭空多出 4 个伪函数

Rugra 输出了 Ghidra 没有的：`SetHTTPrequest_part_0`、`file2string_part_0`、`getparameter_constprop_0`、`parseconfig_constprop_0`。

`_part_0` / `_constprop_0` 后缀说明 Rugra 把**同一个函数的部分基本块**当成了独立函数——这是**控制流/调用图分析**的 bug：没有正确合并，或把函数内联展开后的副本当新函数。

Ghidra 对应的 `file2string`/`parseconfig`/`getparameter`/`SetHTTPrequest` 是完整单函数。

### 3.2 函数体大小：多个函数 Rugra 只有 Ghidra 的一半

| 函数 | Rugra 行 | Ghidra 行 | ratio |
|---|---|---|---|
| next_url | 57 | 103 | 0.55 ❌ |
| match_url | 44 | 82 | 0.54 ❌ |
| my_get_token | 37 | 61 | 0.61 ❌ |
| glob_set | 58 | 87 | 0.67 ❌ |

这些函数 Rugra 严重"漏译"——大量语句没生成出来，因为变量没解析、表达式没化简、条件没重建。

### 3.3 next_url 实例对照

**Rugra**（残缺）：
```c
void next_url(void * param_1) {
  byte bVar1;
  ...
  long uVar_1075;   // 占位名
  ...
  if (!((long)bVar1)) return;   // bVar1 从哪来？未初始化
  __sprintf_chk((piVar1 + lVar1), 1, -1, ("%0*d"), lVar2);  // 参数类型全错
  while (uVar_1075 == 0) { }    // 空循环体！
  ...
  switch ((long)((iVar1 ^ iVar1))) {   // switch(0) — 自异或未化简
```

**Ghidra**（正确）：
```c
char * next_url(URLGlob *glob) {   // 有真实参数类型
  char cVar1;
  ...
  iVar4 = glob->size;              // 结构体成员访问
  if (next_url::beenhere != 0) {   // 静态变量
    iVar7 = iVar4 / 2;
    if (1 < iVar4) {
      ppcVar6 = glob->literal + (long)iVar7 * 3;
      do { ... } while (...);      // 真实循环
```

差距根源：① 参数原型没识别（Ghidra 是 `URLGlob *glob`，Rugra 是 `void * param_1`）；② 结构体成员访问没恢复（`glob->size`）；③ 局部变量全是占位名；④ 循环体丢失。

## 4. 根因分析（按层）

### 🔴 根因 1：HighVariable / HighSymbol 链未建立（最严重）

**证据**：
- `src/varmap.rs`（1935 行）**完全不引用 `HighVariable`**（`grep -c HighVariable src/varmap.rs = 0`）
- `src/variable.rs` 定义了 `HighVariable` 结构体，但 varmap 不构建它
- `src/printc.rs:1483`：Unique 空间的 varnode 直接 fallback 到 `format!("uVar_{:x}", vn.get_offset())`

**Ghidra 对照**：`varmap.cc`（1620 行）的核心就是 `HighVariable` ← `VarnodeLocDef` ← `SymbolEntry`/`HighSymbol` 链。每个 SSA varnode 通过 heritage 合并后归属到一个 HighVariable，HighVariable 再绑定到 HighSymbol（有真实名字如 `pcVar9`、`sVar2`），print 阶段查 HighSymbol 拿名字。

**Rugra 现状**：heritage 跑了（1390 行），但产物没接到 HighVariable；printc 看到 Unique varnode 就生成 `uVar_<offset>`。这就是 215 个 `uVar_xxx` 的来源。

**这是单一最大根因**——解决了它，§2 里 215+116 个占位名问题大部分消失。

### 🔴 根因 2：参数原型 / Funcdata 输出签名未恢复

**证据**：77 个 `param_N`、所有函数返回 `void`、参数类型几乎全是 `long`/`void *`。

**Ghidra 对照**：`coreaction.cc` 的 `ActionPrototype*` 系列（ActionPrototypeTypes/ActionPrototypeWarnings/ActionActiveParam...）+ `paramid.cc` 推断参数个数/类型。Rugra 的 `paramid.rs` 是 L1 骨架（AGENTS.md 记录），未接入。

### 🔴 根因 3：控制流结构化过度 switch 化 + 空 body

**证据**：switch 18 vs 2（9×）；7 个空 while；10 个空 else；2 个 `if () goto ;`。

**Ghidra 对照**：`blockaction.cc` 的结构化对 if/else/while/switch/do-while 有精确的多路判定。Rugra 倾向于把多分支 if-else 链误判成 switch，且 body emit 阶段会丢失语句（空循环体）。

### 🔴 根因 4：表达式化简 Rule 缺失

**证据**：`switch ((iVar1 ^ iVar1))`（XOR 自身 = 0 未化简）、`__sprintf_chk` 参数类型错乱。

**Ghidra 对照**：`ruleaction.cc` 的 RuleXorCollapse / RuleSubCompares 等。Rugra ruleaction.rs 有 ~100 个 struct 定义，但接入主管线和实际触发的覆盖度不足。

### 🔴 根因 5：结构体成员访问未恢复

**证据**：Ghidra 输出 `glob->size`、`*(int *)(ppcVar6 + 7)`；Rugra 输出 `(piVar1 + lVar1)` 这种裸指针算术。

**Ghidra 对照**：`varmap.cc` 的结构体重建 + type 系统的 `TypeStruct`。Rugra 类型系统对结构体推断未完成。

## 5. 修复优先级（ROI 排序）

| 优先级 | 任务 | 影响 | 对应 Ghidra 源 |
|---|---|---|---|
| P0 | 建立 HighVariable ← HighSymbol 链，接入 printc | 消除 215+116 占位名 | varmap.cc 全文 + variable.hh |
| P1 | 参数原型恢复（ActionPrototype 系列） | 消除 77 个 param_N + void 返回 | coreaction.cc:4609+ |
| P1 | 结构化 switch 过度化修正 | switch 18→~2 | blockaction.cc |
| P2 | 表达式化简 Rule 接入 | 消除 switch(0) 等 | ruleaction.cc |
| P2 | 结构体成员访问恢复 | glob->size 等 | type.cc + varmap.cc |
| P3 | 空 body / 空 else / 空 if 修复 | 语法正确性 | blockaction.cc + printc.cc |

## 6. 验证方法

```bash
# 重新生成 Rugra 输出
cargo run --release --example curl_decompile > result/curl_cur.c 2>result/curl_cur.err

# 对比指标
python tools/audit_syntax.py result/curl_cur.c

# 函数体对照
diff <(grep -A100 'next_url' result/curl_cur.c) <(grep -A100 'next_url' result/ghidra_curl_ref.c)
```

## 7. 一句话总结

**Rugra 的输出不是"差一点"，而是底层变量映射（HighVariable/HighSymbol）这条主干根本没接通**——heritage 产出了 SSA，但没向上汇聚成有名字的高级变量，导致 printc 层只能吐 `uVar_xxx` 占位符。这是 215 个垃圾变量名、77 个未命名参数、大量残缺语句的总根因。优先级 P0：把 varmap 的 HighVariable 链真正建立起来并接入 printc。

---

## 8. 进度更新（2026-07-03 实测）

### 8.1 寄存器名泄漏根因已修复（commit dd585d7）

**根因修正**：07-02 报告把 `uVar_<hex>` 占位名归因于"HighVariable 链未建立"，但 07-03 的 `[DBG-DET]` 诊断显示 HighVariable 链**已经建立**（merge.rs 跑通），问题是 `Merge::assign_names`（merge.rs:560-574）给 HighVariable 起的是**带 SSA 后缀的原始寄存器名**（`RAX_7`、`RDI_6`、`EAX_13`），而 printc 的 `is_raw_register_name` 只精确匹配 `"RAX"`（不带后缀）→ 后缀名直接泄漏进 C 输出。

**修复**：`is_raw_register_name` 先剥掉尾部 `_<digits>` SSA 后缀再查寄存器名表，让 `RAX_7`/`RAX_71` 与 `RAX` 走同一条既有 raw-register → `<prefix>_<offset>` → `compact_name_for` 重编号链（对齐 Ghidra `buildVariableName` database.cc:2501-2504 + `assignDefaultNames` database.cc:2862）。

**量化效果**（`tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl.c --summary-only`）：

| 指标 | 07-02 | 07-03 | 变化 |
|---|---|---|---|
| 寄存器名泄漏（RAX_/EAX_/... 全量） | 177 | **0** | ✅ 全消 |
| defect 函数数 | 17/24 | **7/24** | ✅ -10 |
| 剩余 defect 类型 | 寄存器泄漏 + 空 else + 调用丢失 | **全是空 else body-collapse** | 收敛到单一根因 |

### 8.2 当前唯一可见缺陷：empty-else body-collapse

7 个 defect 函数（main/my_fwrite/my_get_line/file2string/glob_word/next_url/match_url）的 defect 全是 `empty else block`。这是 §3.3 的控制流结构化 + body emit 问题（独立根因，与命名无关）：

- `my_fwrite`：Rugra 10 行 vs Ghidra 22 行，缺 fwrite/fopen 调用、缺 if-body 主体（`if(param_4==0){...} else {}` 的 else 空但 if-body 也残缺）。
- 根因层：blockaction 结构化 + printc body emit（QUALITY_GAP §P3）。
- 下一步对齐目标。

### 8.2.1 body-collapse 根因 #2 已修：ActionDeadCode 杀 CALL（commit 981f412）

**真根因**（比 §8.2 推测的"结构化"更深）：`ActionDeadCode::apply` Step 4（coreaction.rs:247）对所有"输出从未被消费"的 op 一律 `mark_dead`，**包括 CALL/CALLIND**。但 CALL 有副作用（fwrite/fopen/malloc 写内存/做 I/O），Ghidra 的 `ActionDeadCode`（coreaction.cc:4038-4044）明确区分：
```c
if (op->isCall()) data.opUnsetOutput(op);  // 保留 CALL，只丢未用的返回值
else               data.opDestroy(op);      // 完全移除
```
Rugra 漏了这个分支，把 fwrite/fopen 等 CALL 当普通 op 杀掉 → 所有含 CALL 的 if/else body 整体消失。

**修复**：Step 4 分两路——CALL/CALLIND 死输出 → `fd.op_unset_output`（对齐 `opUnsetOutput`）；其余 → `mark_dead`（不变）。

**量化效果**（`compare_ghidra.py`）：

| 指标 | 修前 (§8.1 后) | 修后 (981f412) |
|---|---|---|
| defect 函数数 | 7/24 | **5/24** |
| my_fwrite defect | 1 (empty else) | **0**（else body 现含 fwrite 调用，if body 现含 fopen） |
| my_get_line defect | 1 (empty else) | **0** |
| main defect | 10 | **7** |
| gcc 语法审计 OK | 17/24 | **20/24** |

剩余 5 个 defect 函数（main×7/glob_word×2/getparameter/next_url/match_url 各 1）的 empty-else 是**非 CALL 根因**（已确认 my_fwrite 的 CALL 已存活但仍可能有其他结构化问题）。下一轮对齐目标。

### 8.2.2 empty-else 根因 #3 已修：is_block_body_empty 对齐 emit_block_ops（commit 2cca0ea）

**真根因**：`is_block_body_empty` 与 `emit_block_ops` 的 op 跳过逻辑不一致。前者对"末尾 op 是 CBRANCH/BRANCH/RETURN/CALL"的块一律判非空，但末尾分支是控制流转移（Ghidra `emitBlockIf` printc.cc:2895 用 `setMod(no_branch)` 抑制），不是 body 语句。只含 dead 计算 op + 末尾 CBRANCH 的块被误判为"非空"，但 `emit_block_ops` 实际什么也不输出 → 产生 `if (cond) {} else {}` 空括号。同时未检查 `is_implied()` 输出（emit_block_ops:334-338 跳过）。

**修复**：删除"末尾分支 → 非空"提前返回；逐 op 扫描精确镜像 `emit_block_ops` 跳过集（CBRANCH/BRANCH/COPY/MULTIEQUAL/INDIRECT + is_implied + RIP-rel + stack-setup + inlined + dead-output 纯计算 op）。CALL/CALLIND 不在跳过集，真正含 call 的 body 仍正确判非空。

**量化效果**（`compare_ghidra.py`，§2 致命缺陷类全部清零）：

| 指标 | §8.2.1 后 | 2cca0ea 后 |
|---|---|---|
| Total Rugra defects | 12（5/24 函数） | **0（0/24 函数）** ✅ |
| main defect | 7 | **0** |
| glob_word defect | 2 | **0** |
| getparameter/next_url/match_url | 各 1 | 各 **0** |
| curl 空 else{} | 多处 | **0** |
| httpd 空 else{} | 多处 | **0** |
| 寄存器名泄漏 | 0 | 0（保持） |

**§2 的 10 类致命缺陷现状**（对照 Ghidra 全为 0）：
- `if () goto ;` 语法错误、`if ()` 空条件、`uVar_<hex>` 占位名、`uVar_<字母>`、`uVar_uVar_` 嵌套、`StackX_*`、`param_N`、空 while body、`else {}`、`switch(自异或)` → **命名类已全消（寄存器泄漏+compact 重编号），空 else/空 body 已消（is_block_body_empty 对齐）**。剩余 §2 之外的问题：numbering 顺序（§8.3）、表达式优先级（`(long)x & -33 != '['`，独立根因）。

### 8.3 number 计数说明

numbering issues 408→597 的增量**不是新引入的编号 bug**，而是：
1. diff 工具的跨函数同名声明重叠计数（`bVar4` 在 my_fwrite 与 myprogress 各声明一次，工具计为 duplicate）—— 工具限制，非真实缺陷。
2. 既有的声明非单调序（lVar 声明顺序与编号不一致）—— §P3 body 问题的一部分，非本次命名改动引入。

my_fwrite 内部无真重复声明（bVar4/lVar1/lVar2/lVar3/lVar5/lVar6 各一次）。

### 8.2.3 gcc 语法审计 17/24 → 23/24（commits 6ce06f8, 6ab6c43）

本轮修了 3 类 gcc 语法错误，把 gcc 审计从 17/24 推到 **23/24 OK**：
- **glob_set lvalue**（6ce06f8）：`piVar13 + lVar11 * ... = 1`（复合表达式赋值，非法左值）→ `*(long *)(piVar10 + lVar14*8 + 0x50) = 1`（整体解引用，合法左值）。对齐 Ghidra `opStore`（printc.cc:500-518）永远把 STORE 地址包在一元 `*` 下。新增 `capture_varnode_text` 判断 base 是裸标识符还是复合表达式。
- **myprogress self-XOR**（6ab6c43）：`return piVar5 ^ piVar5`（指针自异或，非法）→ `return 0`。根因是 `xor eax,eax; ret`（zero-return 惯用法）的 INT_XOR 在 cleanup-pool 时已 dead，RuleTrivialArith 折叠不到，print-time RETURN 重构经 copy-prop 渲染出非法 XOR。新增 `capture_inline_expr_text` + `is_textual_self_xor` 在 print-time 把 `X ^ X` 文本折成 `0`（对齐 Ghidra RuleTrivialArith ruleaction.cc:2413）。
- **cleanup pool 加 RuleTrivialArith**（6ce06f8）：Rugra-local，对齐 Ghidra mainloop repeatapply 对 late-created op 的再简化效果。

剩余 1/24 fail：main 的 "expected expression before ','"（CALL 参数 emit 问题，独立根因）。

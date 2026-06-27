# `printc.rs` API Reference

**源代码路径**: `src/printc.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **可信度**: 高
- **对应源码**: 当前 `rugra/src/printc.rs`
- **文档目标**: 说明 `PrintC` 在当前 Rugra 架构中的职责、输入依赖与输出边界
- **可信边界**: 本文档描述的是**当前 C-like 输出层的责任分工**，不是“已经达到 Ghidra 等价输出质量”的证明

---

## 模块定位

`printc.rs` 是 Rugra 当前输出层中的核心模块之一，负责把已经进入函数级分析上下文的内部表示，转换为**更接近 C 语言风格**的文本输出。

它在整体链路中的位置更接近：

```text
raw semantics / P-code-like IR
  -> Funcdata
  -> Action / Heritage / CFG-related processing
  -> PrintLanguage
  -> PrintC
  -> C-like pseudocode text
```

因此，`PrintC` 的职责不是：

- 解析二进制
- 直接做反汇编
- 替代 SSA / CFG / 类型恢复本身
- 单独证明最终输出已经与 Ghidra 1:1 一致

而是：

- 消费前序阶段已经建立的函数级语义信息
- 组织输出文本
- 尽量用 C 风格形式表达现有语义
- 在无法恢复高级语义时做**保守降级输出**

---

## 当前职责概述

结合当前工程结构，`PrintC` 的主要责任可以概括为以下几类：

### 1. C-like 文本发射
将内部分析结果发射为伪 C / C 风格文本，而不是继续停留在底层 IR 展示层。

### 2. 输出阶段的语言特化
`PrintLanguage` 更像输出语言抽象层，`PrintC` 则是其中面向 C 风格语法的具体实现。

### 3. 函数级输出组织
围绕单个函数组织输出，包括但不限于：

- 函数头部
- 语句序列
- 表达式文本
- 变量显示形式
- 基本控制流结构的文本布局

### 4. 保守表达
当某些高层语义尚未完全恢复时，`PrintC` 应优先保持语义可追踪，而不是伪装成完整源码。

### 5. 基于双 Pass 模型的局部变量声明 (Variable Declarations)
为确保发射的 C 代码语法有效，`PrintC` 实现了精确的局部变量声明收集与发射机制：
- **Pass 1 (Discovery Pass - 探测阶段)**：通过绑定一个空输出发射器（`NullEmit`）静默执行一遍函数体发射。此阶段的打印动作（如 `push_varnode`）会调用 `mark_varnode_used`，真实收集所有会在 C 文本中呈现的变量名、作用域（Space）、偏移量（Offset）以及类型名称。这能够准确拾取由复制传播、DCE 优化消除定义后悬空使用的 Unique 临时变量（如 `uVar_a0`）和被重命名为 `lVar_XX` 的物理寄存器变量。
- **Pass 2 (Final Emission - 正式发射阶段)**：在输出函数体（`{`）的开头，遍历探测到的 `used_varnode_types` 映射。通过 `is_declarable` 实施严格过滤，跳过非标识符表达式（如 `struct2->field_8` 等成员访问，只保留 `struct2` 基址本身）、已在签名中声明的入参、全局数据等，并在一行内合并声明。

---

## 设计边界

为了避免误解，下面明确 `PrintC` 的输入边界与输出边界。

### 输入依赖

`PrintC` 的有效工作依赖于前序阶段已经提供的内容，例如：

- `Funcdata`
- `PcodeOp` / `Varnode` 图关系
- 基本块与控制流信息
- 已恢复的部分变量语义
- 已恢复的部分类型信息
- 已知函数原型或调用信息
- 输出发射器（`Emit`）

如果这些输入不完整，`PrintC` 的输出质量也会受到限制。

### 输出产物

`PrintC` 的直接产物是：

- C 风格文本
- 近似伪代码
- 可读性优于裸 IR 的结构化输出

### 不应承担的责任

`PrintC` 不应自行承担以下职责：

- 推断不存在的高级类型事实
- 伪造不存在的变量来源
- 重写底层地址事实以迎合文本美观
- 单独决定 SSA / CFG 正确性
- 将“未恢复”伪装为“已恢复”

---

## 与其他模块的关系

### 与 `printlanguage.rs` 的关系
`PrintLanguage` 是更上层或更抽象的输出语言接口层；`PrintC` 是当前面向 C 风格输出的具体实现。

可以把两者理解为：

- `PrintLanguage
`: “如何组织一种输出语言”
- `PrintC`: “如何把当前语义尽量写成 C 风格”

### 与 `funcdata.rs` 的关系
`Funcdata` 是单函数分析上下文；`PrintC` 主要消费其中的结果，不负责替代 `Funcdata` 的建立过程。

### 与 `heritage.rs` / `action.rs` / `block.rs` 的关系
这些模块决定分析形态、图结构和中间语义稳定度；`PrintC` 建立在它们之上做展示，不应反向篡改核心事实。

### 与类型系统的关系
`PrintC` 可以利用已有类型信息改善输出，但不应把不可靠的类型猜测包装成确定类型结论。

---

## 导出的公共 API

## `pub struct PrintC`

### 作用
`PrintC` 是当前 Rugra 中面向 C 风格输出的打印器。

它对应的核心角色是：

- 管理 C 风格文本发射过程
- 驱动底层发射器写入缓冲内容
- 将函数级语义组织为更接近 C 的输出形式

### 当前职责理解
从当前架构角度，`PrintC` 更像：

- **输出层实现者**
- **文本结构组织者**
- **语义到 C-like 文本的映射器**

而不是：

- 独立分析器
- 独立 CFG 恢复器
- 独立类型恢复器
- 最终正确性证明器

---

## `pub fn new(emit: Box<dyn Emit>) -> Self`

### 作用
创建一个新的 `PrintC` 实例，并绑定一个输出发射器。

### 参数

- `emit`: 一个实现了 `Emit` 的发射器对象，用于接收 `PrintC` 最终产生的文本输出

### 使用语义
这个构造函数体现了当前输出层的一个关键设计点：

> `PrintC` 不直接把结果固定写到某个全局目标，而是通过可替换的 emitter 发射输出。

这意味着调用方可以：

- 把输出写入内存缓冲
- 收集输出文本
- 走无标记输出路径
- 以后扩展为其他输出后端

### 边界说明
`new()` 只是构造输出器，不代表：

- 当前函数已经可打印
- 所有语义都已恢复
- 最终输出质量已可接受

---

## `pub fn take_emit(self) -> Box<dyn Emit>`

### 作用
取回 `PrintC` 内部持有的发射器，同时消费当前打印器实例。

### 使用场景
该接口适合以下场景：

- 调用方在输出完成后，取回底层 emitter
- 从 emitter 中提取最终缓冲内容
- 将输出结果转成字符串或其他可消费形式
- 进行测试断言或结果归档

### 设计意义
这个接口说明 `PrintC` 的当前实现并不是直接返回一个“最终字符串”的最简单封装，而是通过 emitter 把输出过程与输出载体解耦。

这对当前 Rugra 很重要，因为它允许：

- 输出层与缓冲实现分离
- 更方便做测试和调试
- 后续兼容不同风格的输出后端

### 注意事项
调用 `take_emit()` 后，原 `PrintC` 实例被消费，不能继续使用。

---

## 当前实现应如何理解

从整个工程现状出发，当前 `PrintC` 的合理定位应该是：

> 一个正在持续演进中的 C-like 输出器，它已经承担 Rugra 输出链路中的关键角色，但它的最终表现高度依赖前序分析阶段的质量，不能单独被当作“完整反编译器输出质量”的证明。

换句话说：

- `PrintC` 存在且重要
- `PrintC` 是当前输出层主干之一
- `PrintC` 能表达 C 风格结果
- 但 `PrintC` 的存在不等于：
  - 输出已接近真实源码
  - 所有控制流都已结构化
  - 所有变量都已正确恢复
  - 与 Ghidra 输出已经一致

---

## 当前输出层的可信表述

后续文档中，关于 `PrintC` 建议使用以下表述。

### 推荐表述

- `PrintC` 是当前 Rugra 的 C 风格输出实现
- `PrintC` 负责把已有函数语义组织成可读文本
- `PrintC` 建立在 `Funcdata` 和前序分析结果之上
- `PrintC` 的输出质量依赖前序恢复结果
- `PrintC` 在无法恢复高级语义时应允许保守降级

### 不推荐表述

- `PrintC` 已生成与 Ghidra 完全一致的 C 输出
- `PrintC` 已经完整恢复所有高级控制流结构
- `PrintC` 可以单独代表端到端反编译质量
- `PrintC` 的存在证明 Rugra 已是完整成熟反编译产品

---

## 调用方应承担的责任

调用 `PrintC` 的上游代码，应尽量保证：

1. 已准备好待输出的函数上下文
2. 关键 IR 结构未损坏
3. 基本控制流和语义信息已进入可打印状态
4. 发射器的生命周期和结果提取方式已明确

否则，即使 `PrintC` 本身工作正常，最终文本仍可能：

- 很低层
- 不够结构化
- 命名贫弱
- 类型缺失
- 与理想 C 风格结果相差较大

---

## 维护建议

后续若继续维护 `printc.rs` 相关文档，建议重点同步以下信息：

- 是否新增了公开方法
- 是否改变了 emitter 交互方式
- 是否新增了函数级打印入口
- 是否改变了 C-like 输出的组织策略
- 是否引入了新的结构化控制流输出能力
- 是否改变了与 `PrintLanguage` 的职责边界

同时应联动检查：

- `docs/api/printlanguage.md`
- `docs/data_contract.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`

---

## 一句话总结

`PrintC` 是 Rugra 当前将内部分析结果转成 **C-like 文本输出** 的关键实现，它负责“如何写出来”，但不单独负责“前面的语义是否已经完整恢复”，因此应被理解为**输出主干模块**，而不是“已经证明最终反编译质量成熟”的证据。
---

## 更新日志

### 2026-06-23：自包含 C 输出

- `doc_function()` 现在在每个函数前 emit Ghidra 风格的 typedef：`byte`、`undefined`、`undefined4`、`undefined8`、`_struct`。原因：`ActionInferParams`/`ActionTypeInfer` 的 size-based 推断会生成 `byte bVarN;` 声明，缺少 typedef 时无法通过 C 编译。`_struct` 是被解引用变量的泛型后备类型（配合 prettyprint 的 `->field` 重写）。

### 2026-06-23（续）：声明白名单覆盖双命名格式

- `is_declarable` 现在同时匹配两种 HighVariable 命名：`bVar60`（merge.rs 生成的 prefix+digits）和 `bVar_60`（printc fallback 的 prefix+`_`+hex）。此前只匹配带下划线的，导致 `bVar60`/`lVar21` 等 Register 空间变量被声明过滤掉，在函数体里引用却未声明。

### 2026-06-23（续）：STORE 地址 cast 合法化

- `op_store()` 所有地址解引用路径现在统一 emit `*(long *)addr` 形式：
  - 全局符号：`*(long *)sym_name`
  - 合成 DAT 名：`*(long *)DAT_xxxxx`
  - 表达式地址 `*(a + b)`：`*(long *)(a + b)`
  - 默认：`*(long *)addr`
- 原因：STORE 的地址操作数可能是 long/int scalar（非指针），直接 `*addr` 非法。`*(long *)` cast 让整数转指针再解引用，无论 addr 声明类型如何都合法。

### 2026-06-23（续）：LOAD/STORE 全路径 cast 合法化

- `op_load()` 和 `op_store()` 的所有地址解引用路径现在统一 emit `*(long *)addr`：
  - LOAD 默认路径（非指针地址）
  - STORE RIP-relative 路径（`*(RIP + sym)` → `*(long *)sym`）
  - STORE 表达式地址（`*(a + b)` → `*(long *)(a + b)`）
  - STORE 全局符号 / 合成 DAT_ 名
- 原因：与之前的 `->field` 重写一致，地址操作数可能是 scalar，`*(long *)` cast 保证无论声明类型如何都合法。

### 2026-06-23（续）：callee-saved/帧寄存器声明

- `is_declarable` 现在允许声明 RSP/RBP/RBX/R12-R15（callee-saved + 帧寄存器）为 `long`。原因：栈帧分析不完整时，这些寄存器名会出现在表达式里（如 `glob_word(RBP + 4, ...)`）。声明为 `long` 保证输出可编译，同时不改变语义（它们确实是 8 字节寄存器）。RIP（0x200）仍是伪寄存器，不声明。

### 2026-06-23（续）：自包含全局变量声明

- `doc_function()` 现在在 typedef 后、签名前 emit `extern long NAME;` 声明，覆盖函数体引用的所有 Ram/Const 空间全局变量（来自符号表/字符串表，非函数调用目标）。对齐 Ghidra 的自包含输出——每个函数引用的全局都有可见声明。
- 同时扫描 `used_varnode_names` 捕获符号表里的全局名（如 `glob_buffer`）。

### 2026-06-23（续）：synthetic DAT_ 全局声明收集

- `op_store` 生成 synthetic `DAT_xxxxx` 名时现在调用 `mark_variable_used`，确保它在 `used_varnode_types` 中，从而被 extern 声明收集捕获。
- extern 收集移除了 `DAT_` 前缀排除（之前 synthetic DAT_ 名被排除在 extern 之外）。


### 2026-06-23（续）：CALLIND 地址 0 的 cast

- `op_call` 当目标地址为 0（未解析的间接调用）时，emit `(*(void(*)())0)` 而非 `(*0x0)`。函数指针 cast 让调用合法。

### 2026-06-23（续）：char literal brace escape

- printc 输出字符字面量时，brace/paren/quote 字符（`}`、`{`、`)`、`(`、`\`、`'`、`"`）用 hex escape（`}`）而非裸字符。原因：`if (bVar_0 == '}') return;` 里的 `}` 会被 post-process 的 brace 计数器（backfill、orphan-break、fix_pointer_arithmetic）误读为代码右花括号，导致函数体提前关闭。case label 同理。

### 2026-06-23（续）：RETURN 返回值推断

- `op_return()` 当 RETURN op 无显式返回值输入时，扫描同块 RETURN 前最后一个写 RAX/EAX 的 op，emit 其值作为返回值。对齐 Ghidra 把 `xor eax,eax; ret` 重构为 `return 0` 的行为。这是前端语义改进（非后处理 hack），缩小了与 Ghidra 的差距 4（返回值推断缺失）。

### 2026-06-23（续）：else 分支 seen_return 抑制修复 + is_block_body_empty 控制流感知

- `is_block_body_empty()` 现在对以 CBRANCH/BRANCH/RETURN/CALL 结尾的块返回 false（有控制流的块不是空）。
- emit_block_structured 的 legacy if/else 分支：else 块不再被 then 分支的 seen_return 抑制。else 是条件分支的一部分，不应受 then 分支的 return 影响。emit else 时临时清除 seen_return。
- 这是前端语义改进，恢复了大量被错误丢失的控制流分支。

### 2026-06-23（续）：BlockIf 结构化 else 也修复 seen_return 抑制

- BlockIf（结构化 if-else）的 else body emit 也移除了 seen_return 检查，临时清除 seen_return。
- httpd 控制流差 168→119（-29
### 2026-06-23（续）：case_body_indices 字段

- `PrintC` 新增 `case_body_indices` 收集 switch case body 块索引，供 BlockIf emit 检测。

### 2026-06-23（续）：dry-run 覆盖 emit_block_structured

- CaseDetectEmit dry-run 现在覆盖 emit_block_structured（递归检测嵌套 BlockSwitch/BlockIf 的 case label），不只是 emit_block_ops。
- 但发现 case label 问题的根因是 emit 顺序（BlockIf 提取 case body 后，BlockSwitch 的 case label emit 与 body emit 的 emitted 去重不匹配），不是 if_body 内容。dry-run 无法检测这种顺序问题。
- if_no_exit 仍禁用。需要 emit 层重构（BlockSwitch 的 case emit 检查 emitted set）。

### 2026-06-23（续）：BlockSwitch case emit 检查 emitted set

- BlockSwitch 的 case/default emit 现在检查 emitted set——如果 case body 已被 BlockIf 提取（在 emitted 里），跳过整个 case（label + body + break）。
- 这修复了 BlockIf 提取 case body 后 case label 与 body 不匹配的问题。
- 但嵌套 switch + BlockIf 提取的 emit 顺序问题仍存在（httpd main 有 8 个 switch，BlockIf 提取打断了 switch 间的 emit 顺序）。if_no_exit 仍禁用。

### 2026-06-23（续）：goto BlockIf CaseDetectEmit 保护

- BlockIf emit 对 GOTO_EDGE_1 标记的 condition 做 dry-run case label 检测。检测到 case label 则回退到顺序 emit。

### 2026-06-23（续）：CaseDetectEmit emit_block_structured 递归

- BlockIf dry-run 现在用 emit_block_structured 覆盖嵌套路径。

### 2026-06-23（续）：BlockSwitch case label 保留 + curl-only goto

- BlockSwitch case emit 不再跳过已提取的 case body 的 label——保留 case label + 空 body。
- 但 httpd main 有重复 case 2（两个 switch 的 case 混合），需要 switch 上下文追踪。
- 回退到 curl-only goto。gcc 53/53 + curl 119。

### 2026-06-23（续）：BlockSwitch case emit 回退

- case body 已 emitted 时跳过整个 case（label + body）。

### 2026-06-23（续）：case body 完整性实验

- 强制 emit case body（从 emitted 移除）→ curl 109 但 gcc 51（重复 body）。
- 回退到 body_already_emitted（保留 label + 空 body）→ gcc 52 + curl 114。
- 正确修复：blockaction 层用支配树检测跨 switch 边界，防止 goto 级联创建跨 switch BlockIf。

### 2026-06-24：Basic 块后继递归实验（已禁用）

- 尝试在 emit_block_structured 的 Basic 块 else 分支中递归后继块。
- 问题：file2string_part_0 的 canary 块后继递归触发了未声明变量错误。
- 根因：canary 检查块在 RETURN 后仍有 fallthrough 后继，但递归越过了 RETURN。
- return_in_block 检查 + func_addr 范围 + depth limit 都无法完全修复。
- 禁用递归，保留 ruleCaseFallthru 处理 switch case body 链式。
### 2026-06-25：DEAD flag emit skip

### 2026-06-26：emit_block_structured DEAD 块标记为 emitted（single-ownership）

- DEAD 块（被 identify_internal 消费的块）在 emit_block_structured 跳过时现在也标记为
  emitted，防止 doc_function 的 root/unreachable 循环（行 3116-3134）重复访问。
- 这是 single-ownership 原则：消费块只通过其结构化父块 emit，不通过后继遍历重入。
- 验证：curl 24/24 gcc，httpd 29/29 gcc。175/176 测试（test_switch_case 预存失败不变）。

### 2026-06-26（续）：修复 pass19 naive 大括号移除 + 重新启用 seen_return 保存/恢复

**根因**：post_process_output 的 pass19 用 naive 大括号计数（直接数 { }）检测函数闭合，
当函数含 char/string 字面量中的 `}`（如 `case '}'`）时会误判 depth<0，移除函数闭合 `}`。
seen_return 保存/恢复启用后更多 case body 被 emit，触发该 bug 导致 ap_getparents 函数边界损坏。

**修复**：
- pass19 不再移除大括号（naive 计数不可靠），改为 emit as-is。
- 重新启用 switch case body emit 的 seen_return 保存/恢复（每个 case 是独立控制流路径，
  一个 case 的 return 不应抑制其他 case 的 body）。

**验证**：176/176 测试通过（含 test_switch_case_structuring，输出 case 0 + case 1）。
curl 24/24 gcc，101 if。httpd 29/29 gcc，108 if，0 goto。

### 2026-06-26（续）：WhileDo body emit 用 emit_block_ops 绕过 DEAD 检查

- WhileDo body 被 identify_internal 消费（DEAD）。emit_block_structured 会跳过 DEAD 块，
  导致循环体操作不被输出。
- 修复：WhileDo emit 时检查 body 是否 DEAD，若 DEAD 则用 emit_block_ops 直接输出操作。
- 验证：176/176 测试。getparameter TYPES whiledo=1（循环保留）。

### 2026-06-26（续）：switch case_values 去重（修复 ap_getparents duplicate case）

- 两个 CBRANCH 块比较相同常量时会在同一 switch 产生重复 case。emit switch case 时用
  emitted_case_values 集合去重，跳过已输出的 case value。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc（恢复！）。

### 2026-06-26（续）：seen_return 不抑制控制结构块（WhileDo/DoWhile/If/List）

- emit_block_structured 的 seen_return 检查现在跳过控制结构块（WhileDo/DoWhile/If/List），
  这些块代表可达控制流路径，必须在 RETURN 后仍渲染。
- 验证：176/176 测试。curl 24/24 gcc（3 个 while 循环）。httpd 29/29 gcc（11 个 while 循环）。

### 2026-06-26（续）：基本块 emit 后递归结构化后继块

- 非 CBRANCH 基本块 emit 操作后，现在递归 follow out-edges 到结构化块（WhileDo/DoWhile/If/Switch 等）。
  只递归结构化块（不递归基本块）避免 canary 问题。
- 之前后继递归被禁用（canary blocks），导致 WhileDo 等只能通过 unreachable-loop 输出。
- 验证：176/176 测试。curl 24/24 gcc（3 while）。httpd 29/29 gcc（12 while，从 11 增加）。

### 2026-06-26（续）：BlockList emit 后递归结构化后继块

- BlockList emit 完所有 children 后，现在 follow out-edges 到结构化块（WhileDo/If/Switch 等）。
- 与基本块后继递归对称，确保 BlockList 的后续结构化块被访问。
- 验证：176/176 测试。curl 24/24 gcc（3 while）。httpd 29/29 gcc（12 while）。

### 2026-06-26（续）：if-empty-check 不抑制结构化块（WhileDo/DoWhile）

- 基本块的 if-branch empty-check（两分支空/单分支空/legacy if-else）在直接 emitted.insert
  分支索引时，现在只对 Basic/Copy 块插入，不抑制 WhileDo/DoWhile 等结构化块。
- 之前 WhileDo 被直接 insert 到 emitted 集合而不被 emit，导致不可达。
- 验证：176/176 测试。curl 24/24 gcc（5 while）。httpd 29/29 gcc（20 while，从 19 增加）。

### 2026-06-26（续）：BlockIf body emit 的 emitted.insert 加 Basic-only 守卫

- BlockIf 的 has_case/both-empty/if-body-empty 路径的 emitted.insert 现在只对 Basic/Copy 插入。
- 避免结构化块（WhileDo）被直接 insert 到 emitted 而不被 emit。
- 验证：176/176 测试。curl 24/24 gcc（5 while）。httpd 29/29 gcc（20 while）。

### 2026-06-26（续）：BlockIf else-body empty 路径 emitted.insert 加 Basic-only 守卫

- 行 590（else-body empty 分支）的 emitted.insert 现在只对 Basic/Copy 插入。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（续）：force-emit WhileDo/DoWhile 块（fresh emitted set）

- 2d 遍历：用 fresh emitted set 强制 emit 所有 WhileDo/DoWhile 块，绕过 stale emitted 条目。
- 大幅增加循环恢复：curl 15 while（从 5），httpd 40 while（从 20）。
- 验证：176/176 测试。curl 24/24 gcc。httpd 29/29 gcc。

### 2026-06-26（varmap 集成）：ScopeLocal 接入 get_stack_variable_name

- `PrintC` 新增字段 `scope: Option<crate::varmap::ScopeLocal>`，在 `doc_function` 开头构建一次。
- `get_stack_variable_name` 的 Case 1（INT_ADD(RSP, const)）在 struct 检测之后、启发式 local_XX 之前，查询 `scope.find_symbol(offset)`，命中则返回符号名。
- **Graceful fallback**：当 scope 无符号覆盖该偏移时，回退到现有启发式，保证不破坏输出。
- **已知阻碍**：Rugra 的 x86 lift 将 RSP 相对访问留在 Register space，不产生 Stack-space varnode，因此 `ScopeLocal::restructure_varnode` 的 `gather_varnodes` 几乎找不到符号。要真正消除 uVar 碎片，需先实现 RSP→Stack spacebase 提升通道（ALIGNMENT_ROADMAP P0 #1 剩余项）。
- 验证：curl 24/24 gcc，httpd 29/29 gcc，200/200 测试。

### 2026-06-26（varmap 集成续）：复用 ActionRestructureVarnode 构建的 fd.scope

- `PrintC.scope` 现优先从 `fd.scope`（由 `ActionRestructureVarnode` coreaction.cc:2274 构建）克隆复用，仅在缺失时本地构建（clone 因 doc_function 取 `&Funcdata`）。
- 这样 coreaction 流水线（`&mut Funcdata`）构建的 ScopeLocal 可被 printc 查询，避免重复构建，集成进 Action 流水线。
- 验证：curl 24/24 gcc，httpd 29/29 gcc，205/205 测试。

### 2026-06-27（会话3 G3 续）：scope 符号声明增强

- `used_scope_symbols: RefCell<HashSet<String>>` — 记录 `get_stack_variable_name` 引用的 scope 符号名（STACK LHS 等 discovery 漏掉的路径）。
- `doc_variable_decls_from_funcdata` 安全网：保守声明所有 scope 符号（StackX_*）。scope 符号按定义是函数栈局部，声明它们只会产生 unused 警告而非编译错误——远比 undeclared 标识符安全。类型按 size 选 int/long。

**背景**：G3 def-linking 原型验证有效（helpf 解析出 10 个栈符号 StackX_0..48），printc 此前无法声明这些符号导致 undeclared。此增强声明它们。但 def-linking 与 jumptable/switch 交互（switch 表本身是 LOAD）导致 main 等函数 "switch quantity not an integer" 回归，故 def-linking 暂回退，本声明增强保留（正确且无害）。def-linking 重启需 jumptable/typeop 协调。

### 2026-06-27（会话3 G3 续2）：switch 表达式 (long) cast

- switch 控制表达式包裹 `switch ((long)(...))`。C 要求 switch 量为整数；当 varmap/typeop 把 switch index 推断为指针类型（_struct*），gcc 报 "switch quantity not an integer"。(long) cast 保证整数性——这镜像 Ghidra（将 switch 控制规范化为整数类型），且语义安全（switch index 按定义是整数）。

### 2026-06-27（会话3 uVar 调查）：uVar_N 碎片根因深度诊断

**目标**：减少 curl 反编译输出中 uVar_N 碎片（149，main 占 69）。

**诊断方法**：实证追踪 main 的 7 个 uVar（uVar_0/18/28/a0/a8/b0/b8）。
- **全部 7 个 uVar 都无赋值定义（NODEF）**：它们在表达式中被使用（如 `strequal("--", uVar_18)`），但在输出中从未出现 `uVar_X = <expr>` 赋值语句。
- 这些 uVar 是**未初始化变量**——其定义 op 未被输出。

**输出路径分析**：printc 有 6+ 条独立的 varnode 解析路径（push_varnode Priority 0/1/1.5、op_call 参数解析、op_binary、emit_inline_expr、resolve_varnode）。诊断确认 Priority 1.5（push_varnode 行 4022，针对 uVar 的 def-map 内联）**对这些 uVar 0 次命中**——说明它们走了其他路径（很可能是 op_call 的 Register 参数解析，3753+），绕过了 Priority 1.5 的内联。

**正确修复方向**（需专门会话）：
1. 统一 varnode 解析路径——所有路径都应经过 push_varnode 的统一内联逻辑
2. 或在 op_call/op_binary 路径中复用 Priority 1.5 的 def-map 内联（当前仅 Register 空间走内联，Unique 空间 fallthrough 到 push_varnode 但未触发）
3. 关键：uVar 的定义 op（CALL 输出/INT_ADD）应在使用点内联为表达式，而非声明独立变量

**此问题与 G3 spacebase 正交**：spacebase 修复的是*栈变量*（StackX_*），uVar 是*中间临时*。两者独立。

### 2026-06-27（会话3 uVar 修复）：emit_inline_expr 处理 COPY — uVar 碎片 149→0

**根因定位**（实证诊断）：通过在所有 uVar 命名点加诊断，确认 uVar_N 全部来自 `emit_inline_expr` 的 `_ =>` fallback（行 2048），且 def_op 全是 **CPUI_COPY**（142 次命中：uVar_28×61, uVar_0×29, uVar_a0×22, uVar_18×10...）。

`emit_inline_expr` 的 match 未处理 CPUI_COPY，导致 COPY 操作落入 fallback，输出 `uVar_N`（未初始化变量碎片）而非内联 COPY 源表达式。

**修复**：在 emit_inline_expr 的 match 开头添加 CPUI_COPY 分支：
```rust
OpCode::CPUI_COPY => {
    if !def_op.inrefs.is_empty() {
        self.push_input(def_op, 0);  // COPY(x) → 内联 x
        return;
    }
}
```
COPY 是语义上的 no-op 赋值，内联其源始终正确。

**效果**：
- curl uVar: **149 → 0**
- httpd uVar: **126 → 0**
- 例：`strequal("--", uVar_18)` → `strequal("--", lVar_0)`（COPY 源 lVar_0 正确内联）
- 682/682 测试 + curl 24/24 + httpd 29/29 全绿，0 goto，无回退

此修复是单点正确的——之前 emit_inline_expr 的 6+ 分支处理了所有算术/比较 op，但遗漏了最基本的 COPY。

# Rugra 当前状态报告

**日期**: 2026-06-23  
**版本**: 0.1.0  
**状态**: 🟡 **核心库持续开发中；已具备较完整的反编译分析框架与显著改进的 C 输出质量，但对外可用性与对齐验证仍不完整**

## 近期进展（2026-06-23 会话：example 输出合法化）

本会话聚焦 **curl/httpd 两个 example 反编译输出质量对齐 Ghidra**，建立了机械化的 gcc 语法审计工具链（`tools/audit_syntax.py`），并通过 **19 个原子化 commit** 将**语法通过率从 30% 提升到 77%**（16→41/53 函数通过 `gcc -fsyntax-only`）。

**修复清单**（每个 commit 独立、可追溯）：

| Commit | 修复内容 | 通过率 |
|--------|---------|--------|
| 93ffb5a | phase3 read-before-write 参数检测 | — |
| 38a0041 | Ghidra typedef emit + auto post_process + `->field` 重写 | 25 |
| 51d1843 | is_declarable 双命名格式（bVar60 + bVar_60） | 26 |
| 2fc3476 | unary deref char* + 参数指针检测 | 27 |
| 5c315d2, e353c4e | STORE/LOAD/RIP 地址 cast 合法化 | 30 |
| 50e6fd5 | callee-saved/帧寄存器声明 | 30 |
| 72ed08c | extern 全局声明（自包含输出） | 33 |
| 1ab1c78 | 栈变量声明 backfill | 34 |
| cbc51b2 | synthetic DAT_ mark | 34 |
| 9e79d8f | orphan break/continue 移除 | 37 |
| 0ebb93e | DAT_ backfill 恢复 | 38 |
| bd911e9, 7b24953 | orphan break 重写（brace-depth switch 追踪） | 39 |
| 657729d | backfill 扩展无下划线前缀 + struct | 40 |
| 9abe869 | CALLIND 地址 0 的函数指针 cast | 41 |

**剩余差距**（12 个函数未通过语法检查）：
- 2 个 invalid operands（`int * + int *` 类型矛盾——变量既被解引用又被算术运算）
- 2 个 too many/few arguments（gcc 内置签名冲突 + 递归调用参数裁剪）
- 1 个 expected declaration（C99 风格声明位置 + backfill 插入点）
- 1 个 struct3/局部变量声明遗漏

这些需要深层架构工作（完整类型传播、CALL 参数分析、C99 声明支持），超出当前后处理合法化范畴。

**验证方式**：
- `cargo test`：175/176（1 个预存失败 `test_switch_case_structuring`，非本次回归）。
- `python tools/audit_syntax.py result/curl.c result/httpd.c`：41/53 通过 gcc 语法检查。
- curl 24/24、httpd 29/29 函数成功反编译。

## 近期进展（2026-06-21 会话）

- 实现 Cover-based HighVariable 合并（`src/merge.rs::Merge::merge_by_cover`、`src/cover.rs::Cover::intersects_except_at`），对齐 Ghidra 的 `Merge::mergeByCopy`。
- 修正动作流水线顺序：`ActionMergeType` 现于 `ActionCopyPropagate` 之前执行，避免 COPY 被消去后失去合并机会。
- 修正 Cover 计算的正确性缺陷：def-only 和 use-only 块的 cover 现按 Ghidra 语义正确延伸到块末尾 / 起始。
- Cover 现包含 CFG 传递性扩展。
- **修正 switch 空条件 bug**：`find_compared_varnode` 现在追 COPY/MULTIEQUAL 链并扫描级联中所有块。`empty_switch` 1→0。
- **实现 SSA-based CALL 参数跟踪**（架构性改进）：
  - `x86_lift.rs` 现在为每个 CALL 操作显式添加 6 个 SysV 参数寄存器作为输入（对齐 Ghidra 的 P-code 生成方式）。
  - Heritage 自然为未写入的参数寄存器创建 INPUT varnode。
  - `ActionCallParams` 从后向搜索改为简单的裁剪（根据被调用方原型裁剪到已知参数数量）。
  - 移除了 placeholder varnode hack（架构性错误，已用正确的 SSA 方式取代）。
  - `no_arg_calls` 15→1（唯一剩余的是 `puts()` 因 rodata 字符串缺失）。
- 单元测试基线：168 → 176。
- 详见各 AgentLog：`engineering_progress_2026-06-21_cover_based_merge.md`、`engineering_progress_2026-06-21_switch_and_arg_tracking.md`、`engineering_progress_2026-06-21_ssa_call_args.md`。
- 详见 `docs/AgentLog/engineering_progress_2026-06-21_cover_based_merge.md`。

---

## 1. 执行摘要

Rugra 是一个基于 Rust、受 Ghidra 启发的 C/C++ 二进制反编译与程序分析框架。  
从当前仓库中的源码、模块布局与文档可确认：

- 项目重点在于 **Ghidra 风格核心对象建模**、**P-code / SSA / 控制流分析** 与 **C 风格输出**
- 本报告中的关键判断应尽量能够回溯到以下证据来源之一：
  - 当前 `src/` 实际源码结构
  - 可见测试与示例
  - `docs/VERIFICATION_GUIDE.md` 中记录的验证路径
  - `ALIGNMENT_PROGRESS.md` 中记录的分层对齐状态
  - `docs/AgentLog/` 中经过复核的最近工程日志
- `src/` 中已经存在较完整的核心模块，包括：
  - `Address`
  - `Varnode`
  - `PcodeOp`
  - `Funcdata`
  - `ActionDatabase`
  - `PrintLanguage`
  - `PrintC`
  - `binary`
  - `disasm`
  - `align`
- 但项目仍处于 **持续重构与对齐阶段**
- 目前最适合把 Rugra 视为：
  - **可研究、可扩展、可局部验证的反编译核心框架**
  - 而不是一个已经稳定交付、对外完整可用的成品反编译器

---

## 2. 当前可以明确确认的能力

以下内容是依据当前可见源码与项目文件，可以较稳妥确认的能力边界。

> **证据来源要求**  
> 阅读或后续更新本节时，应尽量让每一类关键结论都能指出其依据来自哪一类可见证据。  
> 建议优先采用以下几类来源：
>
> 1. `src/` 下当前真实存在的模块、类型和公开接口  
> 2. `tests/`、`examples/` 中当前可见的测试与样例  
> 3. `docs/VERIFICATION_GUIDE.md` 中明确写出的可运行或待集成验证路径  
> 4. `ALIGNMENT_PROGRESS.md` 中按层级记录的对齐结论  
> 5. `docs/AgentLog/` 中**已补复核提示**或明确仍与当前主线一致的近期工程日志
>
> 如果某条结论暂时无法回溯到上述任一来源，就不应把它写成“已确认事实”，而应改写为：
>
> - “按当前仓库可见信息判断……”
> - “当前代码结构表明……”
> - “当前尚缺少进一步证据支持……”

### 2.1 核心中间模型已经存在

项目已经实现并公开了多组核心抽象，围绕 Ghidra 风格模型组织，包括：

- 地址与序号：
  - `Address`
  - `SeqNum`
  - `Range`
  - `RangeList`
- IR / 语义节点：
  - `Varnode`
  - `PcodeOp`
  - `OpCode`
  - `PcodeOpRaw`
- 函数与流程组织：
  - `Funcdata`
  - `BlockBasic`
  - `ActionDatabase`
- 输出层：
  - `PrintLanguage`
  - `PrintC`
- 类型系统：
  - `Datatype`
  - `TypeMetatype`

这说明 Rugra 并不是仅停留在“读二进制”或“做几个示例脚本”的阶段，而是已经形成了一个较完整的反编译核心建模骨架。

### 2.2 已具备二进制解析与反汇编相关模块

项目源码中包含：

- `src/binary/`
- `src/disasm/`

依赖中也包含：

- `goblin`
- `object`
- `iced-x86`
- `capstone`

这表明项目确实朝着“从二进制进入分析流水线”的方向实现，而非仅做静态结构模拟。

### 2.3 已具备对齐验证框架的代码基础

项目存在：

- `src/align/`
- `src/align/runtime_verify.rs`
- `docs/VERIFICATION_GUIDE.md`
- `ALIGNMENT_PROGRESS.md`

说明项目明确把“与 Ghidra 对齐验证”作为工程目标之一，并已经建立了验证层级与运行时比对框架的代码雏形。

### 2.4 已具备库形态，但 CLI 当前不可作为稳定入口

当前 `src/bin/rugra.rs` 的可见状态表明：

- 命令行入口处于**临时禁用**状态
- 原因与架构重构、模型对齐有关

因此，当前更准确的定位是：

- **库内部能力在演进**
- **CLI 产品形态暂未恢复为稳定可用入口**

---

## 3. 当前不能夸大宣称的部分

以下结论目前**不能**被写成“已经完成”或“已经保证”。

### 3.1 不能宣称与 Ghidra 输出 100% 一致

当前仓库中虽然有大量“对齐”“验证”“runtime verify”相关内容，但从现有文档与代码状态看：

- 运行时验证框架存在，但并不能据此自动推出“已经完成全量对拍”
- FFI / 对拍链路仍有未集成、未打通或仅框架化的部分
- 很多
对齐结论仍停留在：
  - 静态结构层面

  - 局部函数层面
  - 预期设计层面

因此目前**不能**
负责任地声称：

- “Rugra 与 Ghidra 已 1:1 完全一致”
- “SSA / CFG / P-code 运行结果已全面验证一致”
- “
端到端输出已全面达到 Ghidra 质量”

### 3.2 不能宣称 CLI 已恢复完整可用


README 中可能出现了完整命令行示例，但代码现状表明：

- CLI 当前并不是稳定
产品入口
- 任何把
其描述为“现成可直接用于完整反编译”的表述
都存在失真

### 3.3 不能宣称所有文档都已与源码
 1:1 同步

当前文
档中存在明显的历史失真迹象，包括但不限于：

- 已删除或已重构模块仍被当作现行主路径描述
- 目录映射存在过时信息
- 某些能力被写成“已
完成”，但代码侧更像“部分实现 / 重构中 / 待验证”

因此文档治理本身仍是当前工程重点之一。

---

## 4. 能力分层评估

下面按“可以确认的成熟度”给出分层判断。

| 领域 | 当前判断 | 说明 |
|------|
----------|------|
| 核心对象建模 | 🟢 较成熟 | `Address`、`Varnode`、`PcodeOp`、`Funcdata` 等核心对象已成体系 |
| Rust 反编译框架骨架 | 🟢 较成熟 | 模块完整度较高，已形成分析框架 |
| 二进制解析 / 反汇编接入 | 🟡 可用但需继续验证 | 有模块与依赖支撑，但端到端产品化仍不足 |
| P-code / SSA / Action 管线 | 🟡 已形成主干 | 具备核心实现方向，但一致性与完备性
仍需验证 |
| Ghidra 对齐验证 | 🟡 有框架，未
完成闭环 | 静态与运行时验证文档存在，但不能视为全面完成 |
| 最终 C 输出质量 | 🟡 已有实质性改进，仍在迭代 | 函数签名恢复、参数命名、栈变量命名、表达式内联、常量显示均已实现；尚未达到 Ghidra 成熟输出水平 |
| CLI 产品可用性 | 🔴 当前不成熟 | 入口处于临时禁
用状态 |
| 生产可用性 | 🔴 暂不宜宣称
 | 更适合研究开发与对齐迭代 |

---

## 5. 已确认的模块现实

当前 `src/lib.rs` 对外暴露的核心模块包括：

- `address`
- `space`
- `varnode`
- `op
`
- `opcodes`
- `typeop`
- `heritage`
- `fspec
`
- `block`
- `funcdata`
- `pcoderaw`
- `type_system`
- `prettyprint`
- `printlanguage`
- `printc`
- `action`
- `coreaction`
- `ruleaction`
- `cover`
- `variable
`
- `merge`
- `blockaction`
- `binary`
- `disasm`
- `ffi`
- `align`

这说明项目当前真实重点是：

1. 围绕 Ghidra 风格核心抽象做 Rust 重建  
2. 围绕分析管线做逐步补齐  
3. 围绕对齐验证建立静态与运行时证据链  

而不是一个“只剩包装层没写”的项目；也不是一个“已经全部收官”的项目。

---

## 6. 当前主要缺口

### 6.1 文档与代码历史漂移

这是
当前最明显的工程问题之一。

表现包括：

- 顶层描述与实际子项目不一致
- README / 结构文档 / 进度文档之间互
相引用过时状态
- “已完成”“已验证”“完全一致”等表述使用过度

这类问题会直接影响后续开发判断，因此文档索引与失真修复
应作为高优先级任务。

### 6.2 CLI 与用户入口未恢复

即使核心库已有不少实现，对普通使用者来说：

- 没有稳定 CLI
- 没有经过文档校准的标准入口
- 使用路径与真实能力边界不够清晰

这会造成“文档看起来像已可用产品，实际更接近开发中框架”的认知偏差。

### 6.3 运行时一致性证据不足

当前最重要的技术风险仍然是：

- P-code 生成与 Ghidra 是否一致
- SSA 版本分配与重命名是否一致
- CFG 结构与块划分是否一致
- Action / Rule 的执行结果是否与目标语义一致

如果这些问题没有形成稳定、可重复的验证证据，就不能把“高质量对齐”写成既成事实。

### 6.4 最终输出质量：已有实质性改进，仍需继续迭代

截至 2026-05-21，`PrintC` 输出质量已经历多轮显著改进：

**已实现的改进**（证据来源：`src/coreaction.rs`、`src/printc.rs`、168 测试全部通过）：

- **函数签名恢复**: `ActionInferParams` 从 INPUT varnodes 和 RETURN ops 自动推断参数和返回类型
- **函数签名数据库**: `known_param_count()` 覆盖约 80 个标准 libc 函数，精确限制 CALL 参数数量
- **参数命名**: 表达式中使用 `param_1`/`param_2` 而非原始寄存器名
- **栈变量命名**: `RSP + offset` 自动转换为 Ghidra 风格 `local_XX`
- **结构体字段聚合**: 检测栈结构体基址模式，发射 `config.field_XX`
- **表达式内联**: Unique-space 临时变量全部内联为表达式，0 个 `uVar_xxx` 残留
- **常量显示**: >= 256 的常量显示十进制注释（`0x2726 /* 10022 */`），高位常量显示有符号值（`-1`）
- **布尔表达式简化**: `BOOL_OR(INT_EQUAL, INT_LESS)` 折叠为 `<=`
- **SSA def-use chain 条件解析**: if/while 条件从 `uVar99` 恢复为 `argc <= 1` 等可读表达式
- **RIP-relative 地址折叠**: 全局地址引用直接显示符号名
- **跨块死代码消除**: 全局 `global_used_outputs` 消除未使用的计算
- **寄存器名消除**: HighVariable 中的 x86-64 寄存器名转换为 `lVar_b0`/`iVar_0` 风格局部变量名
- **If-else 结构化**: 完整的 if/else 代码块输出（而非 `goto`）
- **类型推断引擎**: 基于收敛性数据流的双向类型传播
- **switch-case 检测**: `BlockSwitch` 结构化输出
- **作弊代码清除**: 删除了二进制特定硬编码（`curlopt_name()`、`known_global_name()` 等），用通用机制替代

**仍存在的不足**：

- 复杂循环模式（interval analysis 级别）尚未覆盖
- 类型库仅覆盖参数数量，不包含完整参数类型
- 结构体类型恢复仅限于栈帧偏移模式
- 对复杂真实程序的输出质量仍需与 Ghidra 进行系统性对比
- 变量声明精简虽从 75 降至 17，但仍有优化空间

输出质量评估应继续通过样例、测试、对比记录和实验文档来建立客观结论。

---

## 7. 当前最可信的项目定位

截至目前，更准确的项目定位应当是：

> Rugra 是一个以 Rust 实现、受 Ghidra 启发的反编译核心框架与研究型工程，已经具备较完整的核心抽象与分析模块，但仍处于持续重构、对齐验证和文档校准阶段。它已经不仅仅是原型，但也尚不应被描述为与 Ghidra 完全等价或面向终端用户稳定交付的成熟反编译产品。

---

## 8. 后续优先级建议

### P0：修正文档失真并建立统一索引
需要优先完成：

- 统一根目录与 `rugra/` 子项目描述
- 修正 README、`docs/PROJECT_STRUCTURE.md`、`docs/api/README.md`
- 清理“已完成 / 已验证 / 100% 一致”等无证据表述
- 明确哪些是：
  - 已实现
  - 部分实现
  - 计划中
  - 框架已存在但未打通

### P1：恢复真实可验证的入口说明
需要做到：

- 明确当前 CLI 是否可用
- 若不可用，给出当前推荐的开发/验证入口
- 在 README 中避免继续展示与现状冲突的“完整产品化命令”

### P
2：补强运行时验证证据链
应围绕以下主题补齐：

- P-code 对拍
- SSA 对拍
- CFG 对拍
- 真实样例对
比
- 差异报告归档

### P3：输出质量的实验化
评估
对真实二进制样例建立：

- 输入样本
- 输出结果
- Ghidra 对照
- 已知差异分类
-
 改进前后记录

这样才能让“质量提升”从主观判断转成客观演进记录。

---

##
 9. 当前对外表述建议

在对外描述 Rugra 时
，推荐使用以下口径：

### 推荐表述
- Rugra 是一个受 Ghidra 启发的 Rust 反编译框架
- 项目已实现较完整的核心分析对象与部分反编译流水线
- 当前
重点在于架构收敛、
输出质量提升与 Ghidra 对齐验证
- 项目适合继续研究开发、功能扩
展与验证迭代

### 不推荐表述
- 已与 Ghidra 100% 一致
- 已完全
生产可用
- CLI 已完整可用
- 所有高级
特性都已稳定完成
- 端到端质量已经全面追平 Ghidra

---

## 10. 结论

Rugra 当前最真实的状态是：

- **不是空壳**：核心反编译框架和 Ghidra 风格模型已经比较成型
- **不是成品**：CLI、验证闭环、输出质量与文档一致性仍未完全收敛
- **最需要做的不是继续夸大完成度，而是清理失真、建立索引、补足证据链**

因此，当前阶段的正确工程策略应当是：

1. 先修复文档失真  
2
. 再统一项目索引  
3. 同步整理真实能力边界  
4. 然后继续推进验证与输出质量改进  

---

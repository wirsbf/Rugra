# AGENTS.md

此文件为 AI 编码助手在 **Rugra** (Ghidra 的 Rust 重置版) 项目中工作时提供专属的开发与合规指导。

## 🦀 Project Overview

Rugra 是一个基于 Rust 开发的生产级、受 Ghidra 启发的 C/C++ 二进制反编译器。它致力于实现与 Ghidra 近乎一致的中间语义和输出。
整个架构分为核心流水线：
**二进制解析(ELF/PE/Mach-O) → 汇编指令(iced-x86) → P-code IR 提升(Lifting) → SSA 构建与类型推导 → C 代码生成**。

详细架构设计、当前版本状态以及一致性追踪参见 `README.md` 和 `CURRENT_STATUS.md`。

## 📝 Session Protocol (每次会话的强制铁律)

**历史教训：过去开发中经常出现文档与代码脱节、进度更新不及时、不规范的情况。从现在起，任何以“下次补”为由的偷懒都是不可被接受的违规行为。**

> ⚠️ **【最高指令】全自动化 24 小时无休止推进架构 (24/7 Autonomous Execution Pipeline)**
> AI 拥有完全的自主决策权，**绝不等待指令，绝不主动停机**。无论是排查 Bug、实现对齐、还是编写文档，你都必须 24 小时、无休止地推进该项目。无论遇到什么编译错误、测试失败或逻辑不通，你必须自动捕获错误、自行调试、网络搜索，连续尝试直至解决。只有整个 Rugra 项目在 `CURRENT_STATUS.md` 中被标记为 100% 完工时，才允许歇息。遇到分歧时，自行根据 Ghidra 源码逻辑（标杆）拍板，**不要向人类求助**。

> 🔴 **【原子化提交铁律 — Commit Per Change】（2026-06-23 新增，最高执行优先级）**
>
> **禁止积累未提交改动。** 每完成一个逻辑自洽的改动单元，必须**立即** `git commit`，绝不允许“攒一批一起提交”或“最后再统一整理”。这是对抗历史教训（226 个文件、3 万行未提交改动堆积、无法分离、无法 review）的根本纪律。
>
> 具体执行规则：
>
> 1. **改动单元的定义**：一个 bug 修复、一个 Action 实现、一组对齐测试、一批 API 文档同步——每个都是独立的 commit。禁止把不相关的改动塞进同一个 commit。
> 2. **提交时机**：
>    - 修复一个 bug 并通过验证 → 立即 commit。
>    - 实现一个 Action/Rule → 立即 commit。
>    - 更新一批 `docs/api/*.md` → 立即 commit。
>    - 写完一个 example 或测试 → 立即 commit。
>    - **绝不在会话结束时留下“一坨”未提交改动。**
> 3. **提交前的必检（由 pre-commit hook 自动执行）**：
>    - `cargo test` 必须通过（允许预存失败，但禁止新引入回归）。
>    - `tools/check_doc_sync.py` 必须通过：staged 的每个 `src/*.rs` 必须有对应的 `docs/api/*.md` 同步变更。
> 4. **Commit message 规范**：使用动词祈使句 + 类别前缀（见下方 💡 Commit Style）。message 体必须说明：改了什么、为什么改、如何验证。禁止空泛的“update”“fix bug”。
> 5. **禁止 `git commit --no-verify`** 绕过 hook，除非有明确的技术阻塞原因并在 message 中注明。
> 6. **会话收尾必检**：每次会话结束前，`git status` 必须显示 working tree clean（除 parent dir 与 rugra 无关的杂物外）。若有未提交改动，必须先整理成 commit 再结束会话。

在使用 AI 助手迭代开发时，每次会话必须严格且同步地遵循以下步骤，缺一不可：

1. **会话首读与摸底**：首先读取当前的 `AGENTS.md` 熟悉本目录规范。然后必须并查阅 `CURRENT_STATUS.md`、`GAP_ANALYSIS.md` 和 `ALIGNMENT_PROGRESS.md`，精确掌握当前项目与 Ghidra 对齐的功能鸿沟和验证进度。**同时运行 `git status` 确认 working tree 干净——若有前序会话遗留的未提交改动，必须先整理成 commit 再开始新工作。**
2. **文档与代码同批次绑定**：
   - 所有架构决策、基建更新、模型抽象（如核心类的映射对应），必须与代码修改在**同一个 Commit** 中完成说明的撰写。
   - 只要发生了对齐进度的攻克（例如新的 Class 或 FFI Fuction 通关），必须当场更新 `ALIGNMENT_PROGRESS.md` 中的复选框与对应的验证状态，并与代码改动一起 commit。
   - 违反此规则的提交会被 pre-commit hook（`tools/check_doc_sync.py`）自动拦截。
3. **架构严谨性**：涉及核心对象（`Varnode`, `PcodeOp`, `Address` 等）的代码时，必须保证 Rust 源码的方法具有完全对应的 Ghidra 语义实现记录。
4. **强制收尾清算（未通过测试和未更文档禁止结束）**：
   - 必须确保所有的逻辑修改能通过全局或领域内的 `cargo test`。
   - 若引入了 FFI 对拍代码或跑通了新的测试用例，必须更新测试报告与文档。
   - 彻底梳理 `CURRENT_STATUS.md` 和 `ALIGNMENT_PROGRESS.md` 的版本日志。这是每次谈话后绝对必须执行的强性收尾动作。
   - **`git status` 必须 clean**——这是会话结束的硬性门槛。

## 🧪 Consistency & Verification (一致性红线)

Rugra 需要强验证，而 **Rugra 更加依赖与原版 Ghidra 对拍的一致性（Alignment）**：

> 🔴 **【Ghidra 源码对齐铁律 — Read Ghidra Source Before Claiming Limits】（2026-06-25 新增）**
>
> **禁止声称"架构极限"。** Rugra 的目标是达到或超越 Ghidra 的反编译质量。Ghidra 能做到的，Rugra 也必须能做到。如果 Rugra 输出不优于 Ghidra，则不是架构极限，而是实现不足。
>
> 具体执行规则：
>
> 1. **遇到任何"做不到"的情况，必须先读 Ghidra 源码**：`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/` 下有完整 Ghidra 反编译器 C++ 源码。遇到控制流结构化、类型传播、变量名恢复等问题，必须先查看 Ghidra 对应的实现（如 `blockaction.cc`、`coreaction.cc`、`type.cc` 等），理解其算法，然后完整移植到 Rugra。
> 2. **不要简化版**：Ghidra 的算法必须完整实现。简化版会导致输出质量差距。如果 Ghidra 用边标志系统（`f_switch_out`/`f_goto_edge`/`f_irreducible`/`f_back_edge`），Rugra 也必须实现等效的边标志系统。
> 3. **不要用文本后处理代替 P-code 级分析**：`struct_recover.py` 和 `rename_vars.py` 是临时工具，真正的目标是 P-code 级类型传播引擎（ActionTypePropagate）和 DWARF debug_info 集成。
> 4. **Ghidra 源码路径**：`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`。关键文件：
>    - `blockaction.cc` — 控制流结构化（collapseInternal、ruleBlock*、selectGoto）
>    - `coreaction.cc` — 核心分析动作（ActionTypePropagate、ActionInferParams）
>    - `block.hh` — FlowBlock 边标志定义（f_switch_out 等）
>    - `type.cc` / `typeop.cc` — 类型系统与类型传播
>    - `varmap.cc` / `varmap.hh` — 局部变量映射与栈帧重构
>    - `jumptable.cc` — 间接跳转表分析
>    - `condexe.cc` — 条件执行分析（RuleOrPredicate）
>    - `merge.cc` — HighVariable 合并

> 🔴 **【Ghidra 源码先读铁律 — Read Ghidra Source Before Implementing ANY Module】（2026-06-26 新增）**
>
> **移植任何 Ghidra 模块之前，必须先完整阅读对应的 Ghidra C++ 源码。** 不允许凭记忆或推测实现。
>
> 具体执行规则：
>
> 1. **实现顺序**：对于 ALIGNMENT_ROADMAP.md 中列出的每个 L1（缺失）或 L2（部分实现）模块，实现前必须：
>    a. 打开 `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/<module>.cc` 完整阅读
>    b. 打开对应的 `.hh` 头文件理解类结构和接口
>    c. 理解该模块依赖的其他模块（如 varmap.cc 依赖 funcdata、type、variable）
>    d. 然后才开始编写 Rust 代码
> 2. **禁止"多会话项目"借口**：遇到技术难题时，禁止声明"这是一个多会话项目"。必须继续尝试不同方案，阅读 Ghidra 源码找答案。每轮交互必须有实质性推动（不一定是代码改动，可以是 Ghidra 源码分析、方案设计、调试追踪），但禁止重复"目标尚未完成"。
> 3. **禁止空轮**：每轮对话必须有实质性产出之一：
>    - 新代码 commit
>    - Ghidra 源码深度分析（记录到 ALIGNMENT_ROADMAP.md 或 docs/alignment_docs/）
>    - Bug 根因定位（记录修复方案）
>    - 测试验证证据（输出对比、gcc 审计、if/while 计数）
>    - 禁止纯"状态声明"轮（如"目标尚未完成，需要多会话"）

> 🔴 **【L1/L2/L3 路线图维护铁律 — Keep ALIGNMENT_ROADMAP.md Updated】（2026-06-26 新增）**
>
> **每个模块的状态变更必须当场更新 ALIGNMENT_ROADMAP.md。**
>
> 1. **L1→L2**：开始实现某模块时，立即在 ALIGNMENT_ROADMAP.md 中将其从 📋 L1 改为 🔧 L2，记录实现方案。
> 2. **L2→L3**：完成实现并通过验证后，立即改为 ✅ L3，附测试证据。
> 3. **新模块发现**：实现过程中发现新的 Ghidra 模块依赖，立即添加到 ALIGNMENT_ROADMAP.md 的 L1 列表。
> 4. **禁止路线图过时**：ALIGNMENT_ROADMAP.md 必须始终反映当前真实状态。

RugraVSR 需要强验证，而 **Rugra 更加依赖与原版 Ghidra 对拍的一致性（Alignment）**：
任何涉及 P-code 生成、SSA 构造或控制流分析等阶段的改动：
- 🔴 **SSA 版本分配（Version Allocation）**：必须保证 100% 相同配置下与 Ghidra 的行为严格一致，不容任何妥协。
- 必须基于 `src/align/` (对齐目录) 编写和通过相应的静态类与 FFI 的跨语言验证测试（`runtime_verify`）。
- 有关执行对拍的命令及失败处理，请查阅 `docs/VERIFICATION_GUIDE.md`。

## ⚙️ Build & Test Commands

使用标准的 Cargo 流程管理所有构建、测试。遇到需要 FFI 交互验证的环节，要启用专门的 Feature。

- 构建标准 Release 二进制：`cargo build --release`
- 运行所有核心纯 Rust 单元测试：`cargo test`
- 运行针对与 Ghidra C++ FFI 对拍的测试（需要本地构建对应库）：`cargo test --features ffi-test runtime_verify::`
- 生成所有库代码的文档（用于检视类结构演化）：`cargo doc --open`

> 若对构建和验证的具体步骤有疑问，请复查 `docs/VERIFICATION_GUIDE.md`。

## 🛠 Coding Conventions (高质量 Rust 规范)

- 严格遵循现代工业级 Clean Code 标准的生产级代码。
- **默认强制启用强静态类型与不可变性**（尽可能使用 `let` 而避免 `let mut`，优先传递借用而非拷贝大结构体）。
- **卫语句（Early Returns）**：最大化逻辑清晰度降低圈复杂度。在解析复杂的二进制结构或遇到畸形（Malformed）字节流时，务必第一时间通过模式匹配/`?` 返回完整的错误上下文。
- **避免静默失败**：严格按照 `anyhow::Result` 和 `thiserror` (定义在 `src/error.rs` 中)返回具有明确上下文的异常，不要擅自 `.unwrap()`。
- 所有名称（包括由于对齐 Ghidra 而引入的模型）都使用精准语义化英文（`snake_case` 或 `PascalCase`为主，常量为 `SCREAMING_SNAKE_CASE`）。绝不可混杂缩写或魔术数字。

## 🐛 调试输出规范 (Debug Output Convention)

**所有调试输出必须遵循以下约定：**

### 1. 格式要求
- 使用 `eprintln!`（输出到 stderr），不要用 `println!`（污染 stdout 的反编译结果）。
- 必须使用 `[TAG]` 前缀格式，便于 grep 过滤和批量清除。
- 函数名和关键变量必须出现在日志中。

### 2. 已有的标准 TAG（保持一致）
| TAG | 用途 | 示例 |
|-----|------|------|
| `[ACTION]` | 动作流水线每步耗时 | `[ACTION] main / heritage 401.9µs` |
| `[STEP]` | 生命周期里程碑 | `[STEP] main inject done 4.8ms bblocks=102` |
| `[INJECT]` | P-code 注入阶段 | `[INJECT] main phase2 done bblocks=68` |
| `[COLLAPSE]` | 控制流结构化 | `[COLLAPSE] main loops 148µs blocks=102` |
| `[BLOCKSTRUCT]` | 块结构构建 | `[BLOCKSTRUCT] main build_copy done sblocks=16` |
| `[PREPASS]` | 预遍原型收集 | `[PREPASS] Collected 156 prototypes` |
| `[DECOMP]` | 逐函数反编译进度 | `[DECOMP] 1/30 main @ 0x25a0` |
| `[PTRSTAMP]` | 指针类型标记 | `[PTRSTAMP] main stamped 238 varnodes` |

### 3. 临时调试 vs 永久日志
- **永久日志**（保留）：上述标准 TAG，用于持续监控反编译质量。它们在 release 模式下通过 `eprintln!` 输出到 stderr，不影响 stdout 的 C 代码输出。
- **临时调试**（必须删除）：一次性排查用的 `[DBG]`、`[DEBUG]`、`[VNDBG]`、`[HUNGDBG]` 等 TAG，在提交前必须全部删除。
- **判断标准**：如果一段调试日志的生命周期不超过单次开发会话，它就是临时的。

### 4. 禁止事项
- ❌ 禁止在 `println!` 中输出调试信息（会混入反编译 C 代码输出）。
- ❌ 禁止在根目录或 `src/` 目录下创建临时 `.txt`、`.log` 调试输出文件。
- ❌ 禁止保留 `// TODO: remove this debug` 注释。
- ✅ 调试输出文件统一放 `result/` 目录，并在提交前清理过期的中间产物。

## 📁 Artifacts & Document Routing (子文档内容描述与归属)

本项目的进展性文档有着严格的分类要求。各文档的具体作用如下，绝不能把信息记错位置或随意丢弃在根目录：

| 文档名称 | 存放的内容描述 |
| ------ | ----------- |
| `CURRENT_STATUS.md` | **项目当前整体状态与可靠性评估**。包括核心问题回答（能不能用？差在哪里？）、已完成的重大阶段、整体一致性验证指标以及待解决的关键风险。 |
| `GAP_ANALYSIS.md` | **功能鸿沟对比记录**。用于记录 Rugra 和 Ghidra (标杆) 相比，在核心实现、高级特性上还缺了哪些模块和算法。 |
| `ALIGNMENT_PROGRESS.md` | **静态/动态类层面的对齐进度跟踪**。记录了诸如 `Address`, `Varnode`, `Pcode` 等类和算法层面的 Ghidra 源码映射实现状况，是日常开发最直接依赖的“闯关表”。 |
| `docs/VERIFICATION_GUIDE.md` | **输出一致性验证的实操手册**。说明了当前能够执行何种层次的对拍（单元测试、FFI 接口联动对拍等）、必要的环境准备（编译 Ghidra C++ 库），以及排查常见验证错位的方法。 |
| `docs/alignment_docs/` | **具体的硬核对齐规则存放目录**。诸如各类寄存器映射表或内部 P-code 的指令对照规范等详细的长篇技术说明应放此。 |

- **代码必须是低耦合高内聚的长期可维护产物**，绝对禁止随意地在项目根目录倾倒临时测试文件（测试应纳入统一的集成测试夹或 `tests/` 目录中）。
- 如果实现了新的突破性阶段特性（例如完整支持了一个新的反编译后端或优化 Pass），请将其同步更新到核心报告文件内，确保**没有历史债**遗留。

## 📖 API 文档实时维护铁律 (docs/api/ Synchronization)

`docs/api/` 目录是与 `src/` 严格 1:1 映射的**全量代码接口参考文档**。以下规则不可违背：

1. **代码变更必须同步文档**：任何对 `src/` 下 `.rs` 文件的修改（新增/删除/重命名 `pub` 级别的结构体、枚举、函数、常量），都必须在**同一个 Commit** 中同步更新 `docs/api/` 下对应的 `.md` 文件。
2. **禁止使用纯自动提取**：API 文档必须由开发者（或 AI 助手）基于对源码的**精读理解**手动撰写。每个公共接口必须包含：
   - 完整的函数签名（不可截断）
   - 中文语义解释（这个函数/结构体是干什么的、在反编译流水线中扮演什么角色）
   - 参数与返回值的含义
   - 与 Ghidra 对应类/方法的映射关系（如有）
3. **新增文件必须新增文档**：在 `src/` 下新建任何 `.rs` 文件时，必须同时在 `docs/api/` 对应位置创建同名 `.md` 文件。
4. **删除文件必须清除文档**：删除源文件时必须同步删除对应的 API 文档。
5. **定期校准**：可执行 `python tools/generate_api_docs.py` 生成骨架草稿，但生成后**必须人工补充语义说明**，不可直接提交纯机器产出。

## 💡 Commit Style

请使用符合规范的动词祈使句。针对这个受Ghirdra高度启发的项目，可以通过类别前缀标明是对齐开发、核心构建亦或基建等：
```text
align: verify SSA parameter propagation logic matching Ghidra 11.0 output
core: implement reaching definitions pass in analysis engine
```

## 🎯 反编译质量评估 (Decompilation Quality Status)

**目标：** 与 Ghidra 反编译质量对齐，以 `curl` 和 `httpd` 等真实二进制为验证基准。

**当前进展（2026-06-22）：**

Rugra 已具备完整的反编译流水线（`Funcdata -> Heritage/SSA -> MergeType -> TypeInfer -> CopyPropagate -> BlockStructure -> PrintC`），24/24 个 curl 函数成功反编译。关键能力：

- C 风格控制结构输出（if/else, while, switch/case, do-while）
- SSA 构建与 HighVariable 合并（Cover-based merge）
- 函数参数跟踪（lifter 发射 arg 寄存器 + prototype DB 裁剪）
- Hungarian 命名（`piVar_` 指针变量, `iVar_` 整数变量）
- 字符串常量、结构体字段访问恢复
- Switch 条件提取（CBRANCH cascade + BOOL_OR 检测）
- OOM 防护（GuardAlloc + 循环检测）

**剩余差距（按优先级排序）：**

1. **高级变量合并**：`HighVariable` 合并覆盖率有限（Cover 传递性传播不完整），导致部分 `uVar` 碎片残留。
2. **控制流结构化**：4-5 个残留 `goto`（不可归约 CFG），需移植 Ghidra `blockaction.cc` 的块复制/分裂算法。
3. **for 循环恢复**：需要归纳变量分析（Induction Variable Analysis）。
4. **类型传播深度**：ActionTypeInfer 已实现基础传播，但指针类型覆盖率不足（需要更完整的 def-use 链追踪）。
5. **库签名匹配**：无标准库函数签名数据库（libc/winapi）。

**验证方式：**
- `cargo test`：176 个单元测试。
- `cargo run --release --example curl_decompile`：curl 反编译质量验证。
- `cargo run --release --example httpd_decompile`：httpd（strip 二进制）反编译质量验证。
- 输出中的 `goto`、`uVar`、`empty_switch`、`no_arg` 计数作为质量指标。

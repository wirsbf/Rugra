# AGENTS.md

此文件为 AI 编码助手在 **Rugra** (Ghidra 的 Rust 重置版) 项目中工作时提供专属的开发与合规指导。

## 🦀 Project Overview

Rugra 是一个基于 Rust 开发的生产级、受 Ghidra 启发的 C/C++ 二进制反编译器。它致力于实现与 Ghidra 近乎一致的中间语义和输出。
整个架构分为核心流水线：
**二进制解析(ELF/PE/Mach-O) → 汇编指令(iced-x86) → P-code IR 提升(Lifting) → SSA 构建与类型推导 → C 代码生成**。

详细架构设计、当前版本状态以及一致性追踪参见 `README.md` 和 `CURRENT_STATUS.md`。

## 📝 Session Protocol (每次会话的强制铁律)

**历史教训：过去开发中经常出现文档与代码脱节、进度更新不及时、不规范的情况。从现在起，任何以“下次补”为由的偷懒都是不可被接受的违规行为。**

在使用 AI 助手迭代开发时，每次会话必须严格且同步地遵循以下步骤，缺一不可：

1. **会话首读与摸底**：首先读取当前的 `AGENTS.md` 熟悉本目录规范。然后必须并查阅 `CURRENT_STATUS.md`、`GAP_ANALYSIS.md` 和 `ALIGNMENT_PROGRESS.md`，精确掌握当前项目与 Ghidra 对齐的功能鸿沟和验证进度。
2. **文档与代码同批次绑定**：
   - 所有架构决策、基建更新、模型抽象（如核心类的映射对应），必须与代码修改在**同一个 Commit / 批次**中完成说明的撰写。
   - 只要发生了对齐进度的攻克（例如新的 Class 或 FFI Fuction 通关），必须当场更新 `ALIGNMENT_PROGRESS.md` 中的复选框与对应的验证状态！
3. **架构严谨性**：涉及核心对象（`Varnode`, `PcodeOp`, `Address` 等）的代码时，必须保证 Rust 源码的方法具有完全对应的 Ghidra 语义实现记录。
4. **强制收尾清算（未通过测试和未更文档禁止结束）**：
   - 必须确保所有的逻辑修改能通过全局或领域内的 `cargo test`。
   - 若引入了 FFI 对拍代码或跑通了新的测试用例，必须更新测试报告与文档。
   - 彻底梳理 `CURRENT_STATUS.md` 和 `ALIGNMENT_PROGRESS.md` 的版本日志。这是每次谈话后绝对必须执行的强性收尾动作。

## 🧪 Consistency & Verification (一致性红线)

RustVSR 需要强验证，而 **Rugra 更加依赖与原版 Ghidra 对拍的一致性（Alignment）**：
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

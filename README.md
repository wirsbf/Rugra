# Rugra 🦀

**一个基于 Rust 的、受 Ghidra 启发的 C/C++ 二进制反编译与程序分析框架**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)

---

## 项目定位

`Rugra` 是一个使用 Rust 编写的二进制分析与反编译实验性框架，目标是围绕 Ghidra 风格的核心语义模型，逐步构建以下能力：

- 二进制格式解析
- 指令反汇编与提升
- P-code 风格中间表示
- SSA、控制流与数据流分析
- 类型与变量恢复
- C 风格伪代码输出
- 与 Ghidra 核心语义做对齐验证

当前仓库中的主要工程位于 `rugra/`，其代码结构和文档显示，项目重点是**反编译与程序分析**，而不是其它类型的二进制识别流水线。

---

## 当前状态

### 已确认的现状

从当前代码与文档可以确认：

- 项目是一个 **Rust 库优先** 的反编译框架
- 核心模块围绕 Ghidra 风格对象展开，例如：
  - `Address`
  - `Varnode`
  - `PcodeOp`
  - `Funcdata`
  - `ActionDatabase`
  - `PrintC`
- 已包含以下源码模块：
  - `src/address.rs`
  - `src/space.rs`
  - `src/varnode.rs`
  - `src/op.rs`
  - `src/opcodes.rs`
  - `src/funcdata.rs`
  - `src/heritage.rs`
  - `src/printc.rs`
  - `src/action.rs`
  - `src/block.rs`
  - `src/binary/`
  - `src/disasm/`
  - `src/align/`
- 存在针对 Ghidra 对齐的验证框架与文档：
  - `ALIGNMENT_PROGRESS.md`
  - `docs/VERIFICATION_GUIDE.md`
  - `src/align/runtime_verify.rs`

### 需要明确说明的限制

当前版本**不能**在文档层面声称以下内容已经完全成立：

- 不能声称“已达到生产级”
- 不能声称“与 Ghidra 100% 输出一致”
- 不能声称“所有 CLI 功能均可直接使用”
- 不能声称“多架构已经全面支持”
- 不能声称“端到端质量已稳定达到商业反编译器水平”

这些结论都需要以真实代码状态、测试结果和验证报告为准。

---

## 当前架构概览

Rugra 当前的核心思路是：

```text
Binary
  ↓
Binary Parsing / Loading
  ↓
Disassembly / Lifting
  ↓
P-code-like IR / Raw P-code injection
  ↓
Funcdata + ActionDatabase pipeline
  ↓
SSA / Heritage / CFG-related analysis
  ↓
PrintLanguage / PrintC
  ↓
C-like pseudocode
```

更具体地说，当前工程的重心在于：

1. **将底层二进制与指令语义映射到 Rugra 的内部对象模型**
2. **围绕 `Funcdata` 组织分析流程**
3. **通过 `ActionDatabase` 驱动一系列分析与转换**
4. **逐步对齐 Ghidra 的核心对象语义与部分运行时行为**
5. **输出结构化程度不断改进的 C 风格结果**

---

## 代码结构

### 根级关键文件

- `Cargo.toml`：Rust 包配置
- `src/lib.rs`：库入口与公共模块导出
- `src/bin/rugra.rs`：CLI 入口
- `CURRENT_STATUS.md`：当前状态报告
- `GAP_ANALYSIS.md`：与 Ghidra 的能力差距分析
- `ALIGNMENT_PROGRESS.md`：对齐进度跟踪

### 核心源码模块

#### 核心对象与 IR
- `src/address.rs`
- `src/space.rs`
- `src/varnode.rs`
- `src/op.rs`
- `src/opcodes.rs`
- `src/pcoderaw.rs`

#### 函数级分析核心
- `src/funcdata.rs`
- `src/heritage.rs`
- `src/block.rs`
- `src/blockaction.rs`
- `src/merge.rs`
- `src/variable.rs`
- `src/cover.rs`

#### Action / Rule 体系
- `src/action.rs`
- `src/coreaction.rs`
- `src/ruleaction.rs`

#### 类型与输出
- `src/type_system/`
- `src/typeop.rs
`
- `src/prettyprint.rs`
- `src/printlanguage.rs`
- `src/printc.rs`

#### 二进制与反汇编
- `src/binary/`
- `src/disasm/`

#### 对齐与验证
- `src/align/`
- `src/
ffi.rs`

### 文档
系统

- `docs/PROJECT_STRUCTURE.md`
- `docs/TODO_BOARD.md`
- `docs/VER
IFICATION_GUIDE.md`
- `docs/api/`
-
 `docs/AgentLog/`
- `docs/alignment_docs/`
- `docs/decisions/`
- `docs/method/`
- `docs
/workflow/`

---

## CLI 现状

当前 `src/bin/r
ugra.rs` 的
实现处于**临时禁用/占
位状态**，会输出提示信息，而不是提供完整命令行功能。

因此
，下面这些典型命令**不应再
被视为当前版本已验证可用的公开能力**：

-
 `rugra decompile ...`
- `rugra analyze ...`
- `rugra pcode ...
`

如果后续 CLI 恢复并补齐参数解析、子命令和文档，再重新更新本 README。

---

## 库使用方式

当前更适合把 Rugra 理解为一个**可继续演化的库框架**，而
不是已经封装完毕的终端产品。

一个更贴近当前代码状态的使用思路是：

1. 构造或获取目标函数的 `Funcdata`
2. 注入或生成原始 P-code / 指令语义
3. 通过 `ActionDatabase` 运行分析流程
4. 使用 `PrintLanguage` / `PrintC` 生成输出

示意流程：

```text
create Funcdata
  ↓
inject raw operations or lifted semantics
  ↓
run ActionDatabase
  ↓
inspect CFG / SSA / variables / types
  ↓
render C-like output with PrintC
```

> 注意：上面的流程代表当前架构方向，不等同于
“对所有真实二进制都已形成稳定、统一、可直接调用的公开 API”。

---

## 构建与测试

### 构建

```bash
cargo build
cargo build --release
```

### 测试

```bash
cargo test
```

### 文档

```bash
cargo doc --open
```

### 与 Ghidra 对齐验证


如需查看对齐与验证相关信息，请优先阅读：

- `ALIGNMENT_PROGRESS.md`
- `docs/VERIFICATION_GUIDE.md`
- `CURRENT_STATUS.md`

如果涉及 FFI 或运行时对拍，需根据本地环境额外配置
相应依赖与验证链路。

---

## 对齐
验证说明

Rugra 的一个重要目标是与 Ghidra 的核心语义模型进行对齐，但这件事必须分层理解。

### 当前已具备的基础

- 已有一组静态对齐与结构级验证模块
- 已有运行时验证框架雏形
- 已有针对若干核心对象的对齐文档与测试入口

### 当前不能夸大的
结论

以下结论目前都不应写成既成事实：

- “所有 P-code 生成与 Ghidra 完全一致”
- “
SSA 版本分配已经全部通过对拍”
- “控制流结构恢复已经达到 1:1 对齐”
- “最终 C 输出
已经与 Ghidra 完全等价”

这些都应该以实际验证结果为准，并在以下文档中
体现：

- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- `docs/VERIFICATION_GUIDE.md`

---

## 文档索引


为了避免文档与代码状态脱节，建议按下面
的入口阅读：

### 先看全局定位
- `README.md`

### 再看项目结构
- `docs/PROJECT_STRUCTURE.md`

### 再看当前进展
- `CURRENT_STATUS.md`
- `GAP_ANALYSIS.md`
- `ALIGNMENT_PROGRESS.md`

### 再看待办与
最近变更

- `docs/TODO_BOARD.md`
- `docs/AgentLog/`

### 查 API 与源码映射
- `docs/api/`

### 查验证方法
- `docs/VERIFICATION_GUIDE.md`

---

## 适合关注这个项目的人

如果你对下面这些方向感兴趣，这个项目会比较值得关注：

- Rust 实现的反编译器框架
- Ghidra 风格中间语义与对象模型
- 二进制分析与逆向工程
- P-code / SSA / CFG / 类型恢复
- 将传统 C++ 反编译器架构迁移到 Rust 的工程实践

---

## 开发约束

本
项目强调以下原则：

- 以真实代码状态为准
- 代码与文档必须同批次同步
- 不把未验证结果写成完成状态
- 尽量保持模块职责清晰
- 优先修复失真文档与错误索引

- 与 Ghidra 的“对齐”必须依赖可说明的验证依据

---

## 近期
优先事项

按当前可见文档，后续更合理的重点
包括：

1. 修正文档失真与错误索引
2. 明确
 `src/` 与 `docs/api/` 的映射关系
3. 收敛 README、状态文档、进度文档之间的矛盾表述

4. 继续补齐运行时验证链路
5. 持续改进 `Funcdata -> ActionDatabase -> PrintC` 的端到端质量
6. 在 CLI 真正恢复后，再重新公开命令行使用说明

---

## 许可证

Rugra 使用 Apache 2.0 许可证。

---
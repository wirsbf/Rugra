# Rugra 🦀

**一个基于 Rust 的、灵感源自 Ghidra 的 C/C++ 二进制反编译器**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/yourusername/rugra)

---

## 🎯 项目愿景

Rugra 旨在提供一个**生产级、内存安全的反编译器**，用于分析已编译的 C/C++ 二进制文件。完全使用 Rust 语言从零构建，它结合了：

- 🔒 **内存安全** - Rust 的所有权系统防止了常见的内存漏洞
- ⚡ **高性能** - 基于 LLVM 后端的零成本抽象优化
- 🏗️ **现代架构** - 清晰、模块化的设计，易于扩展
- 🌐 **多架构支持** - 支持 x86, x64, ARM, MIPS, RISC-V 等
- 🧪 **生产就绪** - 全面的测试覆盖和健壮的错误处理

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/rugra.git
cd rugra

# 构建项目
cargo build --release

# 运行测试
cargo test

# 安装命令行工具
cargo install --path .
```

### 代码示例

```rust
use rugra::{Decompiler, Architecture};

fn main() -> anyhow::Result<()> {
    // 加载二进制文件
    let binary_data = std::fs::read("program.exe")?;
    
    // 创建针对 x86-64 的反编译器实例
    let mut decompiler = Decompiler::new(Architecture::X86_64)?;
    decompiler.load_binary(&binary_data)?;
    
    // 反编译指定地址的函数
    let c_code = decompiler.decompile_function(0x401000)?;
    println!("{}", c_code);
    
    Ok(())
}
```

### 命令行使用

```bash
# 反编译单个函数
rugra decompile binary.exe --address 0x401000

# 批量反编译所有函数
rugra decompile binary.exe --all

# 输出到文件
rugra decompile binary.exe --address 0x401000 -o output.c

# 分析二进制结构
rugra analyze binary.exe
```

## 📚 架构设计

Rugra 遵循多阶段的反编译流水线：

```
┌─────────────┐
│   二进制    │  (ELF, PE, Mach-O)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   加载器    │  解析二进制格式
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   反汇编    │  x86/ARM/MIPS → 汇编指令
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  P-code IR  │  架构无关的中间表示 (Lift)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  SSA 构建   │  静态单赋值形式转换
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   分析引擎  │  控制流/数据流分析, 类型推断
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   AST 生成  │  高级抽象语法树
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   C 代码生成 │  生成可读的 C 代码
└─────────────┘
```

### 核心组件

#### 1. **二进制解析** (`src/binary/`)
- 基于 `goblin` 支持 ELF, PE, Mach-O 格式
- 提取符号表和重定位信息
- 段 (Section) 和 节 (Segment) 映射
- **PLT 解析**：自动识别外部导入函数 (如 `printf`)

#### 2. **P-code 中间表示** (`src/pcode/`)
- 灵感源自 Ghidra 的中间表示语言
- 包含 60+ 种操作码
- 架构无关的语义表达
- P-code 示例:
  ```
  # x86: add eax, ebx
  $U10:4 = INT_ADD eax:4, ebx:4
  eax:4 = COPY $U10:4
  ZF:1 = INT_EQUAL $U10:4, 0:4
  ```

#### 3. **分析引擎** (`src/analysis/`)
- **控制流分析**: CFG 构建, 循环检测 (Dominator Trees)
- **数据流分析**: Use-def 链, 到达定值 (Reaching Definitions)
- **SSA 构建**: 支配边界计算, Φ (Phi) 节点放置
- **类型推断**: 基于约束的类型恢复系统
- **变量恢复**: 栈变量识别, 寄存器分配分析
- **优化**: 常量折叠, 代数简化, 死代码消除

#### 4. **代码生成** (`src/codegen/`)
- 格式化良好的 C 代码输出
- 类型重构
- 控制流结构化 (恢复 if/while/for)
- **智能变量命名**: 消除原始寄存器名 (如 `uVar1`, `param_1`)
- **字符串恢复**: 自动将指针解析为字符串字面量

## 🎨 功能特性

### 当前已实现 ✅

- [x] 项目结构与构建系统
- [x] 核心类型系统 (Address, Architecture, Types)
- [x] P-code IR 定义 (60+ opcodes)
- [x] 实用工具模块 (位操作, 格式化等)
- [x] 全面的测试套件
- [x] 二进制解析 (ELF/PE/Mach-O)
- [x] 反汇编 (x86-64 via iced-x86)
- [x] P-code 生成 (Lifting)
- [x] 控制流图构建 (CFG)
- [x] SSA 构建 (支配树, Phi 节点)
- [x] 数据流分析 (到达定值, Use-Def 链)
- [x] 类型推断 (基于数据流的全局传播)
- [x] 优化 (常量折叠, 增强版 SSA 死代码消除, 代数简化, 控制流简化)
- [x] 结构体恢复 (自动从指针访问模式推断结构体布局)
- [x] C 代码生成 (结构化控制流, 变量命名, `struct.field` 语法支持)
- [x] PLT/GOT 解析 (外部函数名恢复)
- [x] 字符串字面量恢复 (指针转字符串)

### 项目状态与路线图 🗺️

Rugra 已完成了最初的 8 阶段开发路线图，实现了一个能够处理复杂真实二进制文件（如 `curl`）的功能性反编译器。然而，与 Ghidra 或 IDA Pro 等行业标杆相比，仍有一定差距。

请参阅 [**GAP_ANALYSIS.md**](GAP_ANALYSIS.md) 了解详细的功能差距对比。

#### Phase 1-8: 核心基础 (已完成)
- [x] **Phase 1-3**: 反汇编与 P-code 提升 (x86-64)
- [x] **Phase 4**: 控制流分析 (CFG, 循环检测)
- [x] **Phase 5**: 变量恢复 (栈与寄存器分析)
- [x] **Phase 6**: SSA 形式构建
- [x] **Phase 7**: 数据流分析
- [x] **Phase 8**: 优化与简化
- [x] **Phase 8.5**: 细节打磨 (字符串恢复, 内存修复, 命名优化)

#### Phase 9: 高级特性与优化 (已完成)
- [x] **Phase 9**: 高级特性与优化 (已完成)
- [x] **控制流简化**: 自动识别并消除死分支，简化间接跳转。
- [x] **迭代式结构体恢复**: 自动从指针算术 (`p+8`) 中逆向出结构体定义并生成 `p->field_8` 代码。
- [x] **类型系统重构**: 引入统一的 `DataType` 系统，支持更复杂的类型传播。
- [x] **增强型死代码消除**: 利用 SSA 版本信息移除未使用的寄存器定义。

#### Phase 10: 控制流重构与函数分析 (已完成)
- [x] **For 循环恢复**: 自动识别并重构 `for (init; cond; inc)` 循环结构。
- [x] **Switch 语句恢复**: 初步支持通过级联 If-Else 链识别 Switch 结构。
- [x] **调用语义恢复**: 基于 x86-64 ABI 自动恢复函数调用的参数和返回值。
- [x] **PLT/GOT 修复**: 修复了 PLT 桩代码导致的控制流穿透和幽灵变量问题。
- [x] **函数签名优化**: 自动使用符号名并推断返回类型。

#### Phase 11+: 未来展望
- [ ] **高级 Switch 恢复**: 支持跳转表 (Jump Table) 形式的 Switch。
- [ ] **类型库**: 自动识别标准库函数 (libc) 及其参数类型。
- [ ] **多架构支持**: 添加 ARM64 和 MIPS 翻译器。
- [ ] **C++ 支持**: 虚函数表 (vtable) 恢复。

## 🔬 技术细节

### 支持的架构

| 架构 | 状态 | 备注 |
|--------------|--------|-------|
| x86 32-bit   | 🚧 计划中 | Intel/AMD 32-bit |
| x86-64       | ✅ 已支持 | 主要开发焦点 |
| ARM 32-bit   | 📅 路线图 | ARMv7 |
| ARM64        | 📅 路线图 | AArch64 |
| MIPS         | 📅 路线图 | MIPS32/64 |
| RISC-V       | 📅 未来 | RV32/RV64 |
| PowerPC      | 📅 未来 | PPC32/64 |

### 二进制格式

- ✅ ELF (Linux)
- ✅ PE (Windows)
- ✅ Mach-O (macOS)

## 🧪 测试

```bash
# 运行所有测试
cargo test

# 运行特定测试
cargo test test_pcode_generation
```

## 📖 文档

```bash
# 生成并打开文档
cargo doc --open
```

## 🤝 贡献

欢迎贡献代码！

## 📜 许可证

Rugra 基于 Apache 2.0 许可证开源。

---

**状态**: ✅ **核心功能已完成** - 功能性反编译器

**当前版本**: 0.3.0 (Alpha)

**最后更新**: 2024
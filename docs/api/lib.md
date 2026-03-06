# `lib.rs` API Reference (库入口与模块注册中心)

**源代码路径**: `src/lib.rs`

## 模块说明 (Module Doc)

整个 Rugra crate 的根入口文件。负责声明和组织所有子模块，定义公开的 re-export 接口，并包含（目前被注释掉的）顶层 `Decompiler` 驱动结构体。

---

## 模块组织 (Module Layout)

### 核心 Ghidra 对齐层 (各 `pub mod`)

| 模块 | Ghidra 对应 | 职责 |
|------|-------------|------|
| `address` | `address.hh` | 地址、序列号、范围 |
| `space` | `space.hh` | 地址空间模型 |
| `varnode` | `varnode.hh` | 数据元节点 |
| `op` | `op.hh` | P-code 操作 |
| `opcodes` | `opcodes.hh` | 操作码枚举 |
| `typeop` | `typeop.hh` | 类型化操作行为 |
| `heritage` | `heritage.hh` | SSA 构造 |
| `fspec` | `fspec.hh` | 函数原型 |
| `block` | `block.hh` | 基本块与控制流图 |
| `funcdata` | `funcdata.hh` | 函数级容器 |
| `pcoderaw` | `pcoderaw.hh` | 未加工 P-code |
| `type_system` | `type.hh` | 数据类型系统 |
| `prettyprint` | `prettyprint.hh` | Token 发射接口 |
| `printlanguage` | `printlanguage.hh` | 打印语言框架 |
| `printc` | `printc.hh` | C 语言打印器 |
| `action` | `action.hh` | 分析行动框架 |
| `coreaction` | `coreaction.hh` | 核心分析行动 |
| `ruleaction` | `ruleaction.hh` | 操作码优化规则 |
| `cover` | `cover.hh` | 变量生存跨度 |
| `variable` | `variable.hh` | 高级变量 |
| `merge` | `merge.hh` | 变量合并 |
| `blockaction` | `blockaction.hh` | 控制流结构化 |

### 高级前端层

| 模块 | 职责 |
|------|------|
| `binary` | ELF/PE/Mach-O 二进制解析 |
| `pcode` | P-code 程序容器（旧版 API） |
| `analysis` | 控制流/数据流/类型分析 |
| `codegen` | C 代码生成 |
| `disasm` | 反汇编器 |
| `translator` | 指令→P-code 翻译器 |

### 内部工具模块 (`mod`, 非 `pub`)

*   `error`: 错误类型。
*   `types`: `Architecture` 枚举等类型定义。
*   `utils`: 通用工具函数。

---

## 公开 Re-exports

`pub use` 导出了所有核心类型的快捷访问路径：`Address`, `SeqNum`, `Range`, `BlockBasic`, `Funcdata`, `FuncProto`, `AddressSpace`, `OpCode`, `Datatype`, `Architecture` 等。

## 版本信息

*   `pub const VERSION: &str`: 从 `Cargo.toml` 编译时注入的版本号。
*   `pub fn version() -> &'static str`: 版本查询函数。

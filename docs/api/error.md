# `error.rs` API Reference (统一错误体系)

**源代码路径**: `src/error.rs`

## 模块说明 (Module Doc)

本模块使用 `thiserror` 宏定义了整个 Rugra 反编译器中**所有可能出现的错误类型**，并提供了统一的 `Result<T>` 类型别名与 `.context()` 链式错误上下文包装。

---

## 导出的公共 API (Public API)

### `pub type Result<T> = std::result::Result<T, Error>`

全局统一的 Result 类型别名。所有公开函数均应当返回此类型。

### `pub enum Error` (错误分类枚举)

按反编译管道的各个阶段精细分类：
*   `BinaryParse(String)` / `UnsupportedFormat(String)` / `NoBinaryLoaded`: 二进制加载阶段。
*   `InvalidAddress(u64)` / `AddressNotFound(u64)` / `FunctionNotFound(u64)`: 寻址阶段。
*   `DisassemblyError(String)` / `UnsupportedArchitecture(String)`: 反汇编阶段。
*   `PcodeGeneration(String)` / `InvalidPcode(String)`: P-code 译码阶段。
*   `ControlFlowAnalysis(String)` / `DataFlowAnalysis(String)`: 分析阶段。
*   `TypeInference(String)` / `SSAConstruction(String)`: 类型推断与 SSA 构造阶段。
*   `CodeGeneration(String)`: 代码生成阶段。
*   `Io(std::io::Error)` / `Generic(String)` / `Multiple(Vec<Error>)`: 通用错误。

### `pub trait ErrorContext<T>` (错误上下文包装)

为任何 `Result<T, E: Into<Error>>` 提供 `.context("msg")` 和 `.with_context(|| ...)` 方法，用于在错误传播链路上逐层附加诊断描述信息。

# `types.rs` API Reference (基础类型定义库)

**源代码路径**: `src/types.rs`（内部模块，非 `pub`）

## 模块说明 (Module Doc)

本文件定义了 Rugra 全局使用的基础值类型和枚举，包括简化版地址、目标架构描述、数据类型格子 (Type Lattice)、调用约定和字节序等。**注意**：此处的 `Address` 是旧版简化模型（基于 `u64` 的 newtype），与对齐 Ghidra 的 `address.rs` 中的 `Address`（包含 `AddressSpace`）不同。

---

## 导出的公共 API (Public API)

### `pub struct Address(u64)` (简化地址)

*   `new(addr: u64)` / `as_u64()` / `offset(i64)` / `is_null()` / `is_aligned(u64)`: 基础地址运算。

### `pub enum Architecture` (目标 CPU 架构)

支持：`X86`, `X86_64`, `ARM`, `ARM64`, `MIPS`, `MIPS64`, `RISCV32`, `RISCV64`, `PPC`, `PPC64`。
*   `pointer_size()` / `is_64bit()` / `register_count()` / `name()`: 架构属性查询。

### `pub enum TypeKind` (基本数据类型种类)

用于旧版分析管道的类型枚举：`Void`, `Bool`, `Int8`~`UInt64`, `Float32`/`Float64`, `Pointer`, `Array`, `Struct`, `Union`, `Function`, `Unknown`。
*   `size_bytes()` / `is_integer()` / `is_signed()` / `is_float()` / `is_pointer()`: 类型判定。

### `pub enum DataType` (丰富数据类型表示)

用于类型推断格子运算的代数数据类型：
*   `Unknown(usize)` / `Void` / `Bool` / `Int(usize, bool)` / `Float(usize)` / `Pointer(Box<DataType>, usize)` / `Array(Box<DataType>, usize)` / `Struct(String)`。
*   `pub fn meet(&self, other: &DataType) -> DataType`: **类型格子的 meet 运算**（最大下界），用于在 Phi 节点处合并两个分支的类型。

### `pub enum CallingConvention` (调用约定)

`C`, `Stdcall`, `Fastcall`, `Win64`, `SysV64`, `AAPCS`, `Unknown`。

### `pub enum Endianness` (字节序)

`Little` / `Big`，含 `native()` 编译期检测。

### `pub struct StructDef` / `pub struct FieldDef` (结构体定义)

管理自动推断或用户声明的结构体字段布局。

### `pub fn parse_type_string(s: &str, size: usize) -> DataType`

从 C 风格类型字符串解析为 `DataType`（支持 `int`, `unsigned long`, `float`, `void`, `struct xxx`, 指针 `*` 等）。

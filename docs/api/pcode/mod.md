# `pcode/` API Reference (P-code 中间表示层)

**源代码路径**: `src/pcode/`

## 模块说明 (Module Doc)

本子目录提供了 Ghidra 启发的 P-code 中间表示 (IR)：一种体系结构无关的寄存器传输语言 (RTL)，用作从机器码到高级 C 代码转换的桥梁。

---

## 子文件导航

### `mod.rs` (入口与 Re-exports)

*   Re-export 了 `crate::varnode::*`、`crate::op::*`、`crate::address::SeqNum`、`crate::space::AddressSpace` 以保持向后兼容。
*   `pub struct PcodeId(u64)`: P-code 操作的唯一标识符。`new(id)`, `as_u64()`, `next()`。

### `program.rs` (P-code 程序容器)

旧版 `Program` 结构体，管理一组 P-code 操作序列。包含：
*   操作树 (`optree`)
*   唯一 ID 分配器 (`uniqid`)
*   入口地址 (`entry_point`)
*   操作创建 (`create`)、查找、遍历 API

> **注意**: 新的 Ghidra 对齐架构应使用 `funcdata.rs` 中的 `Funcdata` + `PcodeOpBank` + `VarnodeBank` 替代此旧版 `Program`。

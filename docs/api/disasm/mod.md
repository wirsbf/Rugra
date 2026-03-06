# `disasm/` API Reference (反汇编引擎)

**源代码路径**: `src/disasm/`

## 模块说明 (Module Doc)

提供体系结构相关的反汇编器，将原始机器码字节流转化为结构化的 `Instruction` 对象，供后续 P-code 翻译器消费。

---

## 导出的公共 API (Public API)

### `pub struct Instruction` (反汇编指令)

*   **`address`**: 指令所在虚拟地址。
*   **`bytes`**: 原始字节。
*   **`mnemonic`**: 助记符（如 `"mov"`, `"add"`）。
*   **`text`**: 完整文本表示。
*   **`operands: Vec<Operand>`**: 操作数列表。
*   **`metadata: InstructionMetadata`**: 辅助元数据。
*   快捷方法：`is_branch()`, `is_call()`, `is_return()`, `next_address()`, `branch_target()`。

### `pub enum Operand` (操作数)

`Register { name, size }` / `Immediate { value, size }` / `Memory { base, index, scale, displacement, size }`。

### `pub struct InstructionMetadata`

`is_branch`, `is_conditional`, `is_call`, `is_return`, `branch_target`, `reads_memory`, `writes_memory`, `reads_registers`, `writes_registers`。

### `pub trait Disassembler` (反汇编器接口)

*   `fn disassemble(&mut self, code, start_address) -> Result<Vec<Instruction>>`: 批量反汇编。
*   `fn disassemble_one(&mut self, code, address) -> Result<(Instruction, usize)>`: 单条反汇编。

### `pub fn create_disassembler(arch) -> Result<Box<dyn Disassembler>>`

工厂函数。当前支持 `X86_64`（基于 `iced-x86`）。

---

### `x86_64.rs` (x86-64 反汇编器实现)

`pub struct X86_64Disassembler`: 使用 `iced-x86` crate 实现的 64 位 x86 反汇编器，自动提取寄存器读写信息和分支目标。

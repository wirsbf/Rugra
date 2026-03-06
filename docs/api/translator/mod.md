# `translator/` API Reference (指令→P-code 翻译引擎)

**源代码路径**: `src/translator/`

## 模块说明 (Module Doc)

将 `disasm` 模块产出的体系结构相关 `Instruction` 转化为体系结构无关的 P-code 操作序列。这是从机器码到中间表示的关键翻译层。

---

## 子文件导航

### `mod.rs` (入口与 Trait 定义)

*   `pub trait Translator`: 翻译器接口。`fn translate(&self, inst: &Instruction) -> Result<Vec<PcodeOperation>>`。

### `registers.rs` (寄存器映射表)

x86-64 寄存器到 P-code Varnode 地址空间的映射定义（如 `RAX → register:0:8`, `EAX → register:0:4`）。

### `x86_64.rs` (x86-64 翻译器实现)

`pub struct X86_64Translator`: 将 x86-64 指令翻译为 P-code 操作序列。每条 x86 指令可能展开为多条 P-code 微操（如 `ADD` 展开为 `INT_ADD` + 标志位设置）。

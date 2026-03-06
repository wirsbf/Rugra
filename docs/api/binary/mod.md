# `binary/` API Reference (二进制文件解析加载器)

**源代码路径**: `src/binary/`

## 模块说明 (Module Doc)

负责解析和加载各种二进制可执行文件格式（ELF/PE/Mach-O），提取入口地址、函数符号表、PLT 导入函数等元信息，并提供反汇编入口。

---

## 导出的公共 API (Public API)

### `pub enum BinaryFormat`

`Elf` / `Pe` / `MachO` / `Raw`。

### `pub struct Binary` (解析后的二进制文件)

*   `pub fn parse(data: &[u8]) -> Result<Self>`: **自动识别格式** (ELF/PE/Mach-O) 并解析。内部使用 `goblin` crate 进行跨平台解析。
*   `pub fn entry_point(&self) -> Address`: 获取入口地址。
*   `pub fn architecture(&self) -> Architecture`: 目标架构。
*   `pub fn get_functions(&self) -> Vec<Address>`: 全部已发现函数列表。
*   `pub fn get_function_name(&self, addr) -> Option<&String>`: 按地址查函数名。
*   `pub fn read_string_at(&self, addr) -> Option<String>`: 从二进制中读取 null-terminated 字符串。
*   `pub fn disassemble_function(&self, addr, arch) -> Result<Vec<Instruction>>`: 反汇编指定函数（委派给 `disasm` 模块）。

#### ELF 解析细节

自动提取 `.symtab` 中的 `STT_FUNC`/`STT_OBJECT` 符号，以及 `.plt`/`.plt.sec` 中的动态导入函数。

#### PE 解析细节

从 PE 导出表和 COFF 头中提取函数符号。

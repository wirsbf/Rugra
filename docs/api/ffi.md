# `ffi.rs` API Reference (C/FFI 外部对拍接口)

**源代码路径**: `src/ffi.rs`

## 模块说明 (Module Doc)

本模块为 Rugra 提供 C-ABI 兼容的外部函数接口 (FFI)，**主要用途是嵌入到 Ghidra 的 C++ 反编译管线中进行实时对拍比较**，验证 Rust 端的常量折叠、P-code 生成等核心逻辑是否与 Ghidra 完全一致。

---

## 导出的公共 API (Public API)

### C-ABI 导出函数 (`#[no_mangle] pub extern "C"`)

*   **`rugra_evaluate_constant(opcode, size_out, val1, size1, val2, size2, has_val2) -> u64`**  
    **核心对拍函数**。接收一个 Ghidra 操作码整数和一对常量输入值，调用 Rugra 内部的 `evaluate_constant_op` 引擎进行常量折叠计算，返回结果值（已按输出大小进行掩码截断）。此函数被 Ghidra 插件在编译时链接并在每次常量折叠时同步调用以比较结果。

*   **`rugra_version() -> *const c_char`**: 返回 Rugra 版本号的 C 字符串指针。

*   **`rugra_init_test_program()`**: 初始化一个空白的内部测试 Program，供后续 FFI 测试调用。

*   **`rugra_add_test_op(...)`**: 向当前测试 Program 中注入一条模拟的 P-code 操作（含操作码、输出 Varnode 等），用于从 Python/C++ 端构建 Rugra 分析状态以进行对拍。

*   **`rugra_observe_jumptable(op_addr, table_addr, size)`**: 从 Ghidra 端接收跳转表恢复结果，执行基本验证（大小、对齐、空指针检查）并打印诊断日志。

*   **`rugra_compare_pcode(op_addr, opcode, out_vn, inputs, input_count)`** (`unsafe`)  
    **终极对拍函数**。将 Ghidra 传来的某个 P-code 操作与 Rugra 内部状态逐字段比较（操作码、输出 Varnode 偏移/大小、输入数量），打印所有不一致的 `[RUGRA DIFF]` 日志。

### 内部辅助

*   `fn map_ghidra_opcode(opcode: i32) -> Option<PcodeOp>`: Ghidra C++ 整型操作码到 Rust 枚举的映射表。
*   `pub struct VarnodeFFI`: `#[repr(C)]` 的 Varnode 跨语言数据传输结构。

# `bin/rugra.rs` API Reference (CLI 可执行入口)

**源代码路径**: `src/bin/rugra.rs`

## 模块说明 (Module Doc)

Rugra 反编译器的命令行可执行程序入口。当前为最小化桩实现。

---

## 功能

*   `fn main()`: 程序入口，用于启动 CLI 反编译流程。
*   后续将接入 `clap` 参数解析以支持 `--input`, `--function`, `--output` 等命令行选项。

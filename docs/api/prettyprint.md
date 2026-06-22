# `prettyprint.rs` API Reference

## 文档状态

- **状态**: 已核对（当前有效）
- **对应源码**: 当前 `rugra/src/prettyprint.rs`

**源代码路径**: `src/prettyprint.rs`

## 模块说明 (Module Doc)

Pretty printing and token emission

Corresponds to Ghidra's `prettyprint.hh`

## 导出的公共 API (Public API)

### `pub trait Emit`

Trait for emitting decompilation tokens

This provides a generic interface for "printing" decompiled code,
allowing for different output formats (plain text, XML, HTML with markup, etc.)

### `pub struct EmitNoMarkup`

Simple emitter that produces plain text with no markup

### `pub fn new() -> Self`

创建并初始化一个不带任何标记的 `EmitNoMarkup` 纯文本发射器。

### `pub fn get_output(self) -> String`

获取发射器缓存的最终格式化 C 代码字符串，同时消费该发射器实例。
在该方法内部，发射器会对收集到的原始行序列进行**多达 15 趟的后处理 Pass** 以极大改善输出质量。包括：
- **死代码消除**：如删除 `return;`/`break;` 后的不可达代码。
- **孤立控制流清理**：如合并连续重复的 `goto`、移除空 `else` 代码块的空行、重写 `return void()` 表达式等。
- **双括号规范化 (Pass 15)**：在最后一趟后处理中，将函数调用多余的括号（如 `puts());`）规范化为 C 语言的标准形式 `puts();`。

### `pub struct NullEmit`

Emitter that discards all output (used for discovery pass)

### `pub fn new() -> Self`

创建一个静默发射器，所有的打印输入均会被丢弃。常用于 Discovery Pass (探测阶段) 以静默跑通反编译打印管线以搜集已使用的变量。

---

## 更新日志

### 2026-06-23：输出合法化与控制流规范化

- `get_output()` 现自动调用 `post_process()`，确保所有调用方（含 example）都得到规范化输出（此前 example 直接取原始 output，跳过了后处理）。
- 新增 `rewrite_struct_deref()`：将所有 `IDENT->field_N` 重写为 `*(long *)(IDENT + 0xN)`。原因：printc 多处 emit `ptr->field_N`，但我们不追踪具体 struct 布局，无法保证 `ptr` 指向匹配的 struct 类型。cast 形式无论 base 声明类型如何都合法。
- `try_convert_ptr_add()` 与 second pass 的 `*var + N` 模式同样改为 emit cast 形式。
- while-break 折叠 pass：`while(cond){stmt;break;}` → `if(cond) stmt`。
- 空 switch case 移除 pass：删除 `case N: { break; }` fallthrough 组。

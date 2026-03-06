# `prettyprint.rs` API Reference

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

*暂无代码注释*

### `pub fn get_output(self) -> String`

*暂无代码注释*


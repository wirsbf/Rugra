# `printlanguage.rs` API Reference

**源代码路径**: `src/printlanguage.rs`

## 模块说明 (Module Doc)

Base language printing interface

Corresponds to Ghidra's `printlanguage.hh`

## 导出的公共 API (Public API)

### `pub trait PrintLanguage`

Trait for emitting decompiled code in a specific source language

Corresponds to Ghidra's `PrintLanguage` class. This trait provides
the interface for converting P-code and other IR structures into
human-readable source code.

### `pub struct PrintLanguageCapability`

Capability object for registering language printers

### `pub fn new(name: &str) -> Self`

*暂无代码注释*


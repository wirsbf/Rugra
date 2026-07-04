# `printlanguage.rs` API Reference

## 文档状态

- **状态**: ✅ **L3（2026-06-28 完整对齐）**——PrintLanguage trait 覆盖全部 Ghidra 虚方法 + escape_character_data + scope/format 管理。2 单元测试。


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

 
<!-- annotation-pass: 2026-07-04 -->

# `translator/registers.rs` API Reference

## 文档状态

- **状态**: 历史遗留（仅供参考）


**源代码路径**: `src/translator/registers.rs`

## 模块说明 (Module Doc)

Register mapping for architecture-specific translators

This module provides register mapping functionality to convert
architecture-specific register names to P-code varnodes.

## 导出的公共 API (Public API)

### `pub trait RegisterMap`

Trait for register mapping

Implementers provide mappings from register names to P-code varnodes.

### `pub struct X86_64RegisterMap`

x86-64 register map

Maps x86-64 register names to P-code varnodes with proper offsets and sizes.

### `pub fn new() -> Self`

Create a new x86-64 register map

### `pub fn get_flag(&self, flag_name: &str) -> Option<Varnode>`

Get varnode for a flag register

 

# `analysis/api/mod.rs` API Reference

**源代码路径**: `src/analysis/api/mod.rs`

## 模块说明 (Module Doc)

API Knowledge Base for Rugra Decompiler

This module provides information about standard library functions (libc, etc.)
to assist in type recovery and parameter mapping during decompilation.

## 导出的公共 API (Public API)

### `pub struct ApiPrototype`

Represents a function prototype for an external API call

### `pub fn new(name: &str, ret: DataType, params: Vec<DataType>) -> Self`

Create a new API prototype

### `pub fn variadic(mut self) -> Self`

Set variadic flag

### `pub struct ApiRegistry`

Registry of known API prototypes

### `pub fn new() -> Self`

Create a new registry and populate it with common symbols

### `pub fn get_prototype(&self, name: &str) -> Option<&ApiPrototype>`

Find a prototype by function name

### `pub fn register(&mut self, proto: ApiPrototype)`

Register a new prototype


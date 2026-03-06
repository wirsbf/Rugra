# `analysis/high_variable.rs` API Reference

**源代码路径**: `src/analysis/high_variable.rs`

## 模块说明 (Module Doc)

High-level variable analysis

This module implements the concept of "High Variables" (HighVariable),
which groups multiple low-level SSA Varnodes into a single logical variable.
This is crucial for producing readable C code, as it reverses the SSA splitting
and register allocation artifacts.

## 导出的公共 API (Public API)

### `pub struct HighVariable`

A high-level variable representing a single logical entity in the decompiled code.

### `pub struct HighVariableMap`

Manages the mapping between Varnodes and HighVariables

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn get_high_variable(&self, ssa_name: &str) -> Option<&HighVariable>`

Find the HighVariable for a given SSA variable name

### `pub fn construct_high_variables(`

Construct High Variables from SSA form and Variable Analysis results


# `codegen/mod.rs` API Reference

**源代码路径**: `src/codegen/mod.rs`

## 模块说明 (Module Doc)

C code generation module for Rugra Decompiler

This module converts the analyzed P-code IR into structured C code.
It handles control flow recovery, expression folding, and type-aware formatting.

## 导出的公共 API (Public API)

### `pub fn generate_c_code(`

Generate C code for a function analyzed in the given FunctionAnalysis.

### `pub enum Statement`

*暂无代码注释*

### `pub enum Expression`

*暂无代码注释*

### `pub enum BinaryOp`

*暂无代码注释*

### `pub enum UnaryOp`

*暂无代码注释*

### `pub struct CFormatter`

*暂无代码注释*

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn format_statement(&self, stmt: &Statement) -> String`

*暂无代码注释*

### `pub fn format_expression(&self, expr: &Expression) -> String`

*暂无代码注释*


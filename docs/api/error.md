# `error.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/error.rs`

## 模块说明 (Module Doc)

Error types for Rugra

This module defines all error types used throughout the decompiler.
We use `thiserror` for ergonomic error handling.

## 导出的公共 API (Public API)

### `pub type Result<T> = std::result::Result<T, Error>`

Result type alias for Rugra operations

### `pub enum Error`

Main error type for Rugra

- `Lowlevel(String)` represents Ghidra's aborting `LowlevelError` category and
  preserves its explanatory message.

### `pub trait ErrorContext<T>`

Helper trait for adding context to errors

<!-- annotation-pass: 2026-07-04 -->

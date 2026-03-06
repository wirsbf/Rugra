# `type_system/cast.rs` API Reference

**源代码路径**: `src/type_system/cast.rs`

## 模块说明 (Module Doc)

Type casting and promotion strategies

Corresponds to Ghidra's `cast.hh`. This module defines the rules
for when explicit casts are required in the output C code and how
types are promoted during arithmetic operations.

## 导出的公共 API (Public API)

### `pub trait CastStrategy`

Interface for determining when a cast is necessary

Corresponds to Ghidra's `CastStrategy` class.

### `pub struct CastStrategyC`

Standard C-language casting strategy

Corresponds to Ghidra's `CastStrategyC` class.

### `pub fn new(promote_size: usize) -> Self`

*暂无代码注释*


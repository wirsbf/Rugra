# `memstate.rs` API Reference

**源代码路径**: `src/memstate.rs`
**Ghidra 对应**: `memstate.hh` / `memstate.cc` (946行)
**状态**: 📋 L1→🔧 L2（MemoryBank + MemState 核心实现）

## 模块说明

内存存储/状态：为 LOAD/STORE 模拟提供字节级读写。
对应 Ghidra 的 `memstate.hh`。

## 导出的公共 API

### `pub struct MemoryBank`
单一地址空间的内存存储。对应 Ghidra `MemoryBank`。
- `new(space, word_size, page_size)` — 构造
- `set_value(offset, size, val)` / `get_value(offset, size)` — 小范围值读写
- `set_chunk(offset, val)` / `get_chunk(offset, size)` — 任意字节序列读写
- `construct_value(bytes)` / `deconstruct_value(val, size)` — 字节↔值编解码

### `pub struct MemState`
跨地址空间的内存管理。对应 Ghidra `MemState`。
- `set_bank(name, bank)` / `get_bank(name)` / `get_bank_mut(name)`

测试：memstate::tests 4 个。

## 2026-06-26（续）：memstate.rs 完善实现

新增完整内存银行子类：
- `MemoryImage` — 只读 LoadImage 后端银行（memstate.hh:90）：read/get_value/len/is_empty
- `MemoryPageOverlay` — 写时复制覆盖银行（memstate.hh:106）：write/read/get_value/is_page_overlayed/num_pages
- `MemoryBank::insert_word/find_word/clear` — 字对齐访问 + 清空

测试：新增 3 个（memory_image + page_overlay_write_read + page_overlay_with_underlie）。

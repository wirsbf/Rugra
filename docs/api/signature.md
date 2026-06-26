# `signature.rs` API Reference

**源代码路径**: `src/signature.rs`
**Ghidra 对应**: `signature.hh` / `signature.cc` (1505行)
**状态**: 📋 L1→🔧 L2（Signature/SignatureEntry/SignatureDB 骨架已实现）

## 模块说明

函数签名匹配，用于识别已知库函数。
对应 Ghidra 的 `signature.hh`。

## 导出的公共 API

### `pub struct Signature`
32 位特征哈希。对应 Ghidra `Signature`。

### `pub struct SignatureEntry`
数据流特征生成节点。对应 Ghidra `SignatureEntry`。

### `pub struct SignatureDB`
已知函数签名数据库。对应 Ghidra `SignatureDB`。
- `register_function(name, sigs)` — 注册函数签名
- `lookup_hash(hash)` — 按哈希查找函数名
- `num_functions()` — 已注册函数数

测试：signature::tests 3 个。

# `float_emulate.rs` API Reference

**源代码路径**: `src/float_emulate.rs`
**Ghidra 对应**: `float.hh` / `float.cc` (773行)
**状态**: 📋 L1→🔧 L2（FloatFormat IEEE754 单/双精度编解码 + 15 个 op 操作）

## 模块说明

浮点格式编解码与运算模拟。对应 Ghidra 的 `float.hh`。

## 导出的公共 API

### `pub enum FloatClass`
浮点编码分类（Normalized/Infinity/Zero/Nan/Denormalized）。

### `pub struct FloatFormat`
IEEE754 浮点格式描述。对应 Ghidra `FloatFormat`。
- `new(size)` — 构造单/双精度格式
- `get_host_float(encoding, &mut class)` — 编码→f64
- `get_encoding(host)` — f64→编码
- `extract_fractional_code/sign/exponent_code` — 位域提取
- 15 个 op 操作：`op_equal/op_less/op_add/op_sub/op_mult/op_div/op_neg/op_abs/op_sqrt/op_floor/op_ceil/op_nan/op_int2float`

测试：float_emulate::tests 5 个。

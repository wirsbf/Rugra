# `float_emulate.rs` API Reference

**源代码路径**: `src/float_emulate.rs`
**Ghidra 对应**: `float.hh` / `float.cc` (773行)
**状态**: ✅ **L3（2026-06-28 完整对齐）**——全部 FloatFormat 方法覆盖，含 set/get 编码操作 + zero/infinity/nan encoding。12 单元测试。
**2026-07-02 修复（R101）**: `max_exponent` 由硬编码 254/2046 改为 255/2047，对齐 Ghidra `float.cc:59 maxexponent = (1<<exp_size)-1`。原 off-by-one 使 `get_host_float` 的 `exp_code == max_exponent` 检查错过全 1 指数 → infinity/NaN 被误读为 normalized 值。
**2026-08-23 修复（FLOAT-OPINT2FLOAT-SIGN-0001）**:
- `op_int2float(a, size_in)` 改为 oracle 符号语义：`sign_extend(a, 8*sizein-1)`（address.hh:543）丢弃
  sizein 符号位以上的比特并符号扩展后再 `(double)` 转换（float.cc:611-617）。原实现按无符号 `a as f64`
  解释输入且忽略 `size_in`，负整数输入与 oracle 分歧。
- `op_float2_float` 由 host-double 中转改为 1:1 位级 `convert_encoding` 端口（float.cc:352-419），含
  静态 `round_to_nearest_even`（float.cc:276-288，uintb 进位回绕语义）。注意 oracle
  `extractFractionalCode`/`setFractionalCode` 是 **64 位字顶对齐**约定（float.cc:113-119/144-153），
  convert_encoding 内部使用顶对齐局部位操作，而右侧对齐的公共 helper 只服务 host-double 路径。
- `get_host_float` 的 NaN 分支补上编码符号（float.cc:253-254 `return sgn ? -nan : +nan;`）。
- 注释行号修正：`op_int2float`→float.cc:611、`get_nan_encoding`→float.cc:205、`get_size`→float.hh:66。
- 新增 2 个符号语义回归测试；oracle 证明见 `tests/oracle/float_int2float_sign_1204`
  （runner `tools/run_float_int2float_sign_oracle.sh`，锁 e40ed130）。

## 模块说明

浮点格式编解码与运算模拟。对应 Ghidra 的 `float.hh`。

## 导出的公共 API

### `pub enum FloatClass`
浮点编码分类（Normalized/Infinity/Zero/Nan/Denormalized）。

### `pub struct FloatFormat`
IEEE754 浮点格式描述。对应 Ghidra `FloatFormat`。
- `new(size)` — 构造单/双精度格式
- `get_host_float(encoding, &mut class)` — 编码→f64（NaN 带符号，float.cc:253-254）
- `get_encoding(host)` — f64→编码
- `extract_fractional_code/sign/exponent_code` — 位域提取（frac 为右对齐取值语义；oracle 顶对齐
  约定见 `convert_encoding` 内部）
- `convert_encoding(encoding, &formin)` — 位级格式互转（float.cc:352-419）
- `op_int2float(a, size_in)` — 有符号整数→浮点（sign_extend 自 size_in 字节，float.cc:611-617）
- `op_float2_float(a, &outformat)` — 精度转换（= outformat.convert_encoding(a, self)，float.cc:622-626）
- 15 个 op 操作：`op_equal/op_less/op_add/op_sub/op_mult/op_div/op_neg/op_abs/op_sqrt/op_floor/op_ceil/op_nan/op_int2float`

测试：float_emulate::tests 14 个（含 INT2FLOAT 符号扩展与 convertEncoding 位级回归）。

## 2026-06-26（续）：float_emulate.rs 完善实现

新增完整浮点操作（覆盖 float.hh 全部 op 方法）：
- op_not_equal (!=) / op_less_equal (<=) / op_trunc (float→int) / op_round / op_float2_float (精度转换)
- 新增 op_div 测试 + 5 个新操作测试

现在覆盖 Ghidra FloatFormat 的全部 17 个 op 方法。
<!-- annotation-pass: 2026-08-23 -->

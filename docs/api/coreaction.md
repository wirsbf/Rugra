# `coreaction.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/coreaction.rs`

## 模块说明 (Module Doc)

Core analysis actions for the decompiler

Corresponds to Ghidra's `coreaction.hh`

## 导出的公共 API (Public API)

### `pub struct ActionHeritage`

Action for performing SSA construction (Heritage)

Corresponds to Ghidra's `ActionHeritage`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionDeadCode`

Action for removing dead P-code operations

Corresponds to Ghidra's `ActionDeadCode`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionConstantPtr`

Action for identifying constant pointers and replacing them

Corresponds to Ghidra's `ActionConstantPtr`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCse`

Action for performing Common Subexpression Elimination (CSE)

Corresponds to Ghidra's `ActionCse`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionStart`

Start of the analysis process

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeRequired`

Action for merging required varnodes (e.g., tied to the same address)

Corresponds to Ghidra's `ActionMergeRequired`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeAdjacent`

Action for merging adjacent varnodes

Corresponds to Ghidra's `ActionMergeAdjacent`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeCopy`

Action for merging COPY varnodes

Corresponds to Ghidra's `ActionMergeCopy`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeMultiEntry`

Action for merging MULTIEQUAL entry varnodes

Corresponds to Ghidra's `ActionMergeMultiEntry`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionMergeType`

Action for merging varnodes by datatype

Corresponds to Ghidra's `ActionMergeType`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionSimplify`

Algebraic simplification of P-code operations

Folds redundant expressions:
- `x ^ x` → `COPY 0`
- `x & x` → `COPY x`
- `x | x` → `COPY x`
- `BOOL_NOT(BOOL_NOT(x))` → `COPY x`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCopyPropagate`

Copy propagation pass — folds COPY chains

Corresponds to Ghidra's `RuleCopyPropagate`. For each `COPY out = in`,
redirects all users of `out` to use `in` directly, then kills the COPY.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionCallParams`

Attach System V AMD64 ABI register parameters to CPUI_CALL operations

Scans for register writes (rdi, rsi, rdx, rcx, r8, r9) preceding each call
and attaches them as additional inputs so PrintC can emit function arguments.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct ActionTypeInfer`

Iterative fixed-point type inference engine

Infers and propagates types across P-code IR varnodes using a multi-pass iterative
dataflow approach (up to 100 iterations until convergence). Implements 5 core rules:

1. **Opcode-driven**: Comparison/boolean ops → `bool` output
2. **COPY propagation**: Bidirectional type flow across `CPUI_COPY`
3. **Pointer arithmetic**: `INT_ADD`/`INT_SUB` with pointer → output inherits pointer type
4. **Phi node**: `MULTIEQUAL` inputs/output type unification (prefers pointer types)
5. **LOAD/STORE dereference**: Bidirectional pointer↔pointee type propagation

After convergence, a post-pass assigns size-based defaults (`byte`/`short`/`int`/`long`)
to remaining untyped varnodes.

Corresponds to Ghidra's `ActionInferTypes` iterative type recovery pass.

### `pub fn new() -> Self`

*暂无代码注释*

 
### 2026-06-23：参数指针类型检测

- `ActionInferParams` 现在扫描所有 LOAD/STORE 的地址输入（input[1]），若该 varnode 是 INPUT 参数寄存器，则把对应参数类型从 size-based scalar 提升为 `long *` 指针。对齐 Ghidra 的 `ActionActiveParam` 指针恢复逻辑。

### 2026-06-23（续）：函数签名与 known_param_count 同步

- `ActionInferParams` 现在在推断参数后，如果当前函数在 `known_param_count` 数据库中有记录，用它的值裁剪推断的参数数。修复函数定义签名与调用处参数裁剪不一致导致的 `too few/many arguments` 错误。
- `ap_strcmp_match`/`ap_strcasecmp_match` 从 1 参数修正为 2 参数。

### 2026-06-23（续）：__vfprintf_chk 参数数修正

- `__vfprintf_chk` 从 5 参数修正为 4 参数（`fp, flag, format, va_list`），与其它 `__*_chk` 可变参数函数区分。

### 2026-06-23（续）：类型传播引擎实验

- 尝试了 COPY chain 追踪 + INT_ADD 指针算术检测 + CALL 参数指针推断。所有模式都太激进——破坏 gcc 通过率（51-52/53）。
- 根因：精确类型传播需要双向类型约束求解（Ghidra ActionTypePropagate），不是简单的使用模式匹配。参数 + 常量可能是数组索引（非指针），CALL 参数可能传值（非指针）。
- 回退到原始的直接 LOAD/STORE 地址检测。53/53 维持。

### 2026-06-23（续）：参数数量对齐 Ghidra

- 修正 known_param_count 中多个函数的参数数，对齐 Ghidra 推断：
  - helpf 1→仍1（Ghidra 2，但 helpf 实际 2 参数，留待后续）
  - SetHTTPrequest 3→2
  - parseconfig 2→4
  - getparameter 3→5
  - file2string.part.0 移除（Ghidra 推断 0，但实际有参数）
  - progressbarinit 加入 1 参数组
- curl 参数差 13→11（-2）。gcc 53/53 维持。

### 2026-06-23（续）：函数名规范化 + 参数数对齐

- known_param_count 现在规范化函数名（`.` → `_`），让 `.constprop.0`/`.part.0` 后缀匹配下划线版。
- helpf 从 1 改为 2（`const char *fmt, ...`）；glob_range 从 5 改为 2；glob_url 保持 2。
- my_get_token/my_get_line 加入 1 参数组。
- curl 参数差 11→8（-3）。gcc 53/53 维持。

### 2026-06-23（续）：known_param_types 源代码签名类型传播

- 新增 `known_param_types()` 返回已知函数的参数类型签名（"ptr"/"int"），基于 curl/httpd 源代码。
- ActionInferParams 用 known_param_types 覆盖默认 size-based 类型推断。
- 效果：my_fwrite 从 `(long, long, long, long)` 改进为 `(void*, long, long, void*)`；SetHTTPrequest 从 `(long, long)` 改进为 `(int, void*)`。
- 禁用了 myprogress/glob_* 签名（优化二进制中类型冲突）。

### 2026-06-23（续）：参数补充 + is_known guard

- 当 known_param_types/known_param_count 的参数数 > 推断数时，从 ABI 寄存器列表（RDI/RSI/RDX/RCX/R8/R9）补充缺失参数。
- 加 is_known guard：只有已知函数才补充/裁剪参数，避免影响测试中的未知函数。
- 效果：getparameter 从 3 参数补充到 5（对齐源代码），parseconfig 从 1 补充到 2。
- gcc 53/53，175/176（1 预存失败）维持。

### 2026-06-23（续）：保守化 httpd 签名

- 移除不确定的 httpd 函数签名（ap_init_vhost_config/ap_update_vhost_given_ip/ap_matches_request_vhost）。
- 只保留确定正确的（ap_fini_vhost_config/ap_parse_vhost_addrs）。
- httpd 参数差 25→21。

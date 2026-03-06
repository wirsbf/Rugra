# `utils.rs` API Reference (通用工具函数库)

**源代码路径**: `src/utils.rs`（内部模块，非 `pub`）

## 模块说明 (Module Doc)

收集了反编译器全局可复用的底层工具函数，按子模块分组。

---

## 子模块 (Sub-modules)

### `pub mod bits` (位操作工具)

*   `extract(value, start, length) -> u64`: 提取指定位范围。
*   `insert(value, start, length, bits) -> u64`: 设置指定位范围。
*   `sign_extend(value, bits) -> i64`: 有符号扩展。
*   `popcount(value) -> u32` / `leading_zeros(...)` / `trailing_zeros(...)`: 位统计。
*   `is_power_of_two(...)` / `next_power_of_two(...)`: 2 幂判定。

### `pub mod format` (字符串格式化工具)

*   `hex_bytes(bytes: &[u8]) -> String`: 如 `"de ad be ef"`。
*   `format_address(addr, width) -> String`: 带填充的十六进制地址。
*   `escape_c_string(s) -> String`: C 语言字符串转义 (`\n`, `\"`, `\\` 等)。
*   `make_c_identifier(s) -> String`: 将任意字符串转为合法 C 标识符。

### `pub mod graph` (图论算法工具)

*   `compute_dominators<T>(entry, successors) -> HashMap<T, T>`: 迭代式支配树计算，返回即时支配者映射。
*   `topological_sort<T>(nodes, edges) -> Option<Vec<T>>`: DAG 拓扑排序（含环检测）。

### `pub mod memory` (内存/字节工具)

*   `read_u64(bytes, offset, size, little_endian) -> Result<u64>`: 按指定字节序从字节切片读取整数。
*   `align_up(value, alignment)` / `align_down(...)` / `is_aligned(...)`: 地址对齐操作。

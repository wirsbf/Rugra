# `address.rs` API Reference (系统寻址元基元)

**源代码路径**: `src/address.rs`

## 模块说明 (Module Doc)

这是所有内存、寄存器及操作指令定位定位的核心底层表示。它提供了在任何（甚至是完全虚拟或基于寄存器窗口偏移的）`AddressSpace` 中精确定位到一个字节序列的基础设施。
这里完全照搬对齐了 Ghidra 的 `address.hh`，提供了 `Address`, `SeqNum` 以及 `Range` 这三个逆向工程中的基石型时空位控组件。

---

## 导出的公共 API (Public API)

### `pub struct Address(u64)` (内存地址类型)

表示目标二进制切片内的一个虚拟内存地址（在内部被抹平升格为安全的、可包裹绝大部分寻址空间的 64 位无符号长整型）。

*   `pub const fn new(addr: u64) -> Self` / `pub const fn as_u64(&self) -> u64`: 原生类型的双向包装。
*   `pub fn offset(&self, offset: i64) -> Self`: 核心的内存滑动计算函数，提供带符号步进能力的地址偏移叠加。
*   `pub fn is_null(&self) -> bool` / `pub fn is_aligned(&self, alignment: u64) -> bool`: 给调度和分析阶段提供指针检验和按页对齐检验的支持。
*   `pub fn next(&self) -> Self` / `pub fn prev(&self) -> Self`: 前进/后退一字节。

*(注：系统中的 `Address` 大多数场景下并不特指“真·物理内存”。比如当位于 `Register` 空间时，一个 `Address(8)` 可能仅代表了相对于整个寄存器栈组基址向前便宜 8 字节处的某个 CPU 控制单元！)*

---

### `pub struct SeqNum` (时空执行标记码)

由于把一句粗大的机器码汇编指令翻译推展到 P-code 时，会爆炸产生一连串的 SSA 微操作指令序列。此结构唯一地标定了这些同一次呼吸下的微指令的逻辑发生时序。这就是 **Seq**uence **Num**ber。

*   **`pub addr: Address`**: 标示产生此序列的宏观母汇编指令原始内存坐落点。
*   **`pub order: u32`**: （微指令发射序）在这个原始机码内部，它是第几个被发配执行的。

这不仅是溯源报错追踪用的“黑匣子记录仪”，更是 `PcodeOpBank` 里全局按执行流流淌排序、判断先后覆盖关系的主键！

---

### 区间与大范围封控管辖组 (Range System)

处理变量作用域生命跨段查询与重影区覆盖检验。

*   **`pub struct Range`**: 一个拥有闭合边界区间（`first` 与 `last` 均为 `Address`）的微小跨度区段。
    *   `pub fn overlaps(&self, other: &Range) -> bool` / `pub fn is_adjacent(&self, other: &Range) -> bool`: 在判断控制块是否被撕裂/接续重组时提供重并判定。
*   **`pub struct RangeProperties`**: 提供附加在这个管控地域上的特殊功能魔数（如该区间属于特定的 ELF Section 或具备安全控制块等）。

#### `pub struct RangeList`

一段巨大的非连接跨度集合记录册（内部是由 `Vec<Range>` 组合）。Ghidra 极重度依赖该类通过合并 (Merge/Insert) 来追踪某变量的覆盖作用范围 (Liveness Scope)。
*   `pub fn insert_range(&mut self, new_range: Range)`: （**核心方法**）在推入跨度时内部引擎会**自动融合平滑掉所有发生交叠、首尾串联相邻的小范围**，确保记录册内始终维系最少数量的高效离散跨越图景。

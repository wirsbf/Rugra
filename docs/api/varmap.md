# `varmap.rs` API Reference

**状态**: 骨架已实现（L2），集成待完成
**源代码路径**: `src/varmap.rs`

## 模块说明

Ghidra `varmap.cc` (1620行) 的 Rust 移植。负责局部变量的栈帧重构和映射。

## 导出的公共 API

### `pub struct RangeHint`
栈地址空间上的类型化范围提示。对应 Ghidra RangeHint。
- `start: u64` — 起始偏移
- `size: i32` — 字节大小
- `sstart: i64` — 有符号起始偏移（用于比较）
- `dtype: Option<Arc<Datatype>>` — 数据类型
- `flags: u32` — 标志（TYPE_LOCK, COPY_CONSTANT, UNALIASED, MAPPED）
- `range_type: RangeType` — Fixed/Open/Endpoint

#### RangeHint 方法（2026-06-26 完整对齐 Ghidra varmap.cc）
以下方法现已 **1:1 对齐 Ghidra**（此前为简化版，已替换）：

- `is_const_absorbable(&self, b)` — `RangeHint::isConstAbsorbable` (varmap.cc:30)
- `reconcile(&self, b)` — `RangeHint::reconcile` (varmap.cc:62)，含 `get_sub_type` 对齐遍历
- `contain(&self, b)` — `RangeHint::contain` (varmap.cc:109)
- `preferred(&self, b, reconcile)` — `RangeHint::preferred` (varmap.cc:126)
- `absorb(&mut self, b)` — `RangeHint::absorb` (varmap.cc:217)
- `merge_with(&mut self, b)` — `RangeHint::merge` (varmap.cc:259)，三态 resType（0/1/2）
- `compare(a, b)` — `RangeHint::compare` (varmap.cc:321)，排序：offset→size小优先→rangeType→flags→highind
- `attempt_join(&mut self, b)` — `RangeHint::attemptJoin` (varmap.cc:170)，数组元素吸收

### `pub struct AliasChecker`
栈指针别名分析器。对应 Ghidra AliasChecker。
**2026-06-26 完整对齐**（此前为简化版，仅扫描 STORE）：
- `pub aliases: Vec<u64>` — 排序的别名偏移（varmap.cc `alias`）
- `pub add_base: Vec<AddBase>` — 加法基根（base + index）
- `gather_internal(&mut self, fd)` — `AliasChecker::gatherInternal` (varmap.cc:660)
- `gather_additive_base(&mut self, startvn)` — `AliasChecker::gatherAdditiveBase` (varmap.cc:741)，递归 BFS 追踪 INT_ADD/INT_SUB/PTRADD/PTRSUB/SEGMENTOP/COPY 后继
- `has_local_alias(&self, vn)` — `AliasChecker::hasLocalAlias` (varmap.cc:711)
- `derive_boundaries(&mut self, local_boundary)` — `AliasChecker::deriveBoundaries`

辅助函数：
- `fn gather_offset(vn)` — `AliasChecker::gatherOffset` (varmap.cc:817)，递归求和常量偏移（COPY/ADD/SUB/PTRADD/SEGMENTOP），末尾按 size 掩码（calc_mask）
- `fn find_spacebase_input(fd)` — `Funcdata::findSpacebaseInput`，Rugra 中 RSP = Register@0x20 size8 无 def 的输入 varnode

### `pub struct MapState`
范围提示收集器和重构器。对应 Ghidra MapState。
**2026-06-26 完整对齐**（此前为简化版）：
- `new_with_default(local_start, local_end, default_type)` — 带 getBase(1,TYPE_UNKNOWN) 默认类型
- `add_range(start, dtype, flags, rt, high_ind)` — `MapState::addRange` (varmap.cc:896)，size<=0/越界时丢弃，无类型时回退默认
- `add_fixed_type(start, dtype, flags)` — `MapState::addFixedType` (varmap.cc:926)
- `gather_varnodes(fd)` — `MapState::gatherVarnodes` (varmap.cc:1124)，逐 op-code 分支（INDIRECT/MULTIEQUAL/COPY/默认），含 same-storage 去重与 `is_read_active`
- `gather_open(fd, checker)` — `MapState::gatherOpen` (varmap.cc:1211)，对每个 AddBase 根：指针→pointee，数组→base，index 在则 minItems=3
- `is_read_active(vn)` — `MapState::isReadActive` (varmap.cc:1088)，过滤纯 same-storage INDIRECT/MULTIEQUAL
- `initialize()` — `MapState::initialize` (varmap.cc:1063)，加端点 + 排序
- `gather_spacebase(fd)` — **Rugra 专有**：Rugra 的 x86 lift 不产 Stack varnode，故扫描 LOAD/STORE 的地址，若为 RSP 派生（含 frame_base 链 `INT_ADD(INT_SUB(RSP,fs),off)`），则在对应栈偏移合成 fixed RangeHint。对应 Ghidra 的 Stack-spacebase 解析（`ActionSpacebase`）。
  - **2026-06-29 续**：Stack INDIRECT varnode 现在产生了（heritage discover+guard），但 gather_varnodes 对 same-addr INDIRECT 跳过（对齐 varmap.cc:1145-1151），不产生 RangeHint。Stack symbol 仍由 gather_spacebase 提供。这是正确的——Ghidra 的 Stack symbol 也来自 gatherOpen + rename 后的 def-use 链，而非 gather_varnodes 直接。

### `pub struct LocalSymbol`
重构后的局部变量符号。
- `name: String` — 变量名
- `start: u64` — 栈偏移
- `size: i32` — 大小
- `dtype: Option<Arc<Datatype>>` — 类型
- `unaliased: bool` — 是否无别名（可安全合并）
- `is_param: bool` — 是否为函数参数

### `pub struct ScopeLocal`
局部变量作用域。对应 Ghidra ScopeLocal。`#[derive(Debug, Clone)]`（2026-06-26：
Clone 用于 printc 从 `fd.scope` 复用）。
**2026-06-26 完整对齐**：
- `restructure_varnode(fd)` — 主入口：`ScopeLocal::restructureVarnode` (varmap.cc:1256)，编排 gather_varnodes→gather_internal→gather_open→restructure→mark_unaliased→fake_input_symbols
- `restructure(state)` — `ScopeLocal::restructure` (varmap.cc:1294)，相交→merge_with，不相交→attempt_join/adjust_fit/create_entry
- `adjust_fit(a)` — `ScopeLocal::adjustFit` (varmap.cc:587)，typelock/size0 拒绝 + 符号重叠收缩
- `create_entry(hint)` — `ScopeLocal::createEntry` (varmap.cc:617)
- `build_variable_name(offset)` — `ScopeLocal::buildVariableName` (varmap.cc:548)，Stack[X|Y]_hex 命名
- `mark_unaliased(aliases)` — `ScopeLocal::markUnaliased` (varmap.cc:1332)，含 0xffff 距离启发式（alias_block_level 待接入）
- `fake_input_symbols(fd)` — `ScopeLocal::fakeInputSymbols` (varmap.cc:1392)，扫描栈空间输入 varnode 并合并相邻
- `find_symbol(offset)` — 按偏移查找重构后的符号

## 当前限制

varmap 算法层（RangeHint/AliasChecker/MapState/ScopeLocal）已 1:1 对齐 Ghidra。
尚未完成：
- **集成到 printc.rs**：变量命名仍用启发式 get_stack_variable_name，未走 ScopeLocal 符号查找
- alias_block_level 配置（影响 markUnaliased 的 struct/array 阻断）
- LoadGuard/StoreGuard 在 gatherOpen 中的 addGuard 路径（待 LoadGuard 接入 Funcdata 栈空间）
- TYPE_PARTIALSTRUCT/PARTIALUNION 在 addFixedType 的处理（Rugra 无此元类型）

测试：varmap::tests 17 个（compare/contain/reconcile/preferred/merge/absorb/const_absorbable/build_name/mark_unaliased/restructure）。

### 2026-06-27（会话3 续）：MapState::hint_count（诊断）

- `MapState::hint_count() -> usize` — 诊断辅助：返回已收集的 RangeHint 数量。用于核实 gather_spacebase 的实际产出（发现多数函数返回 0，定位 G3 阻塞根因）。

### 2026-06-27（会话3 G3 深水区诊断）：uVar 碎片根因实证定位

通过 `examples/diag_stack.rs` 实证诊断 curl 函数的 P-code，确认 uVar 碎片的**两个根因**：

**根因 A：def 链断链（主要）**
`inject_raw_ops` 为每个 op 的 input 创建**全新的** varnode（`create_with_space`），而非复用产出该地址的 op 的 output varnode。例如 myprogress 的 `STORE@0x34f0` 地址是 `INT_ADD(COPY(INT_SUB(RSP,0x258)), 0x248)`，但 STORE 的 input varnode 是新对象（`Unique:0x1018`），其 def=None——与产出它的 INT_ADD 的 output 是不同 Arc。

`resolve_rsp_offset` 已正确处理 COPY/INT_ADD/INT_SUB 递归，但因 def 链断裂，递归到 def=None 就终止。

**根因 B：参数指针基址（次要）**
my_fwrite 的 `LOAD@0x3475` 是 `INT_ADD(param_4=Register:0x8, 8)`——参数指针解引用，正确地**不应**被当作栈访问。这类"碎片"其实是参数访问。

**为何不能简单复用 varnode**：尝试在 inject 里 `find_by_loc` 复用同 (size,offset) 的 varnode，导致 7 个 SSA 测试失败——Rugra 的 SSA 基于 Arc identity 区分定义点，合并对象破坏了 SSA 语义。正确方案需重新设计 def 链建立（heritage 后统一），非 inject 时合并。

**剩余工作**：重新设计 inject/heritage 的 def 链建立，使 LOAD/STORE 的地址 varnode 能追溯到产出它的 op（保留 SSA 独立性的同时建立 use-def）。这是 G3 的核心阻塞。

诊断工具 `examples/diag_stack.rs` 保留，可打印任意函数的 LOAD/STORE def 链 + scope symbol 数。

### 2026-06-27（会话3 G3 续2）：resolve_rsp_offset_via_bank 重新启用 — spacebase 解析恢复

- `resolve_rsp_offset_via_bank(addr, fd)` — 只读空间回查：当 addr varnode 的 def 链断裂（inject 创建独立 def-less 输入 varnode），在 vbank 中查找同 (space, offset) 且有 def 的 varnode，通过它解析到 RSP 派生偏移。**不修改任何 varnode**（保持 SSA identity），作用域仅限 varmap 的 gather_spacebase。

**关键决策**：此前全局 def-linking（inject Phase 4）虽正确解析栈符号（helpf 10 个），但扰动 typeop 推断（struct 指针类型泄漏到 switch/算术上下文）。via_bank 只读法**不扰动 typeop/copyprop**，避免回归。

**验证效果**：helpf 的栈符号解析 StackX 使用 5→9（scope 10 符号中 9 个被引用）。配合 printc scope 声明增强（声明所有 scope 符号），输出 24/24 + 29/29 全绿。

**uVar 碎片**：spacebase 修复的是*栈变量*恢复，而 uVar_N 是 SSA 中间临时碎片（main 69 个），属 printc 表达式内联问题（独立子系统）。

### 2026-06-29：ScopeLocal::mark_not_mapped + has_overlap
- `mark_not_mapped(offset, size, parameter)` — 忠实移植 Ghidra `ScopeLocal::markNotMapped`（varmap.cc:510-546）。从符号列表移除与范围重叠的符号。用于 ActionRestrictLocal 防止特定栈位置（保存的寄存器、调用参数）被当作局部变量。
- `has_overlap(offset, size)` — 检查范围是否与任何符号重叠。

### 2026-07-01：query_by_addr
- `ScopeLocal::query_by_addr(offset, size) -> Option<(&LocalSymbol, i32)>` — 查栈范围匹配符号，返回符号+偏移（partial read）。
<!-- annotation-pass: 2026-07-04 -->

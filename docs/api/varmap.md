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

### `pub struct LocalSymbol`
重构后的局部变量符号。
- `name: String` — 变量名
- `start: u64` — 栈偏移
- `size: i32` — 大小
- `dtype: Option<Arc<Datatype>>` — 类型
- `unaliased: bool` — 是否无别名（可安全合并）
- `is_param: bool` — 是否为函数参数

### `pub struct ScopeLocal`
局部变量作用域。对应 Ghidra ScopeLocal。
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

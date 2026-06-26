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

### `pub struct AliasChecker`
栈指针别名分析器。对应 Ghidra AliasChecker。
- `gather(&mut self, fd: &Funcdata)` — 从函数收集别名信息
- `get_aliases(&self) -> &[u64]` — 获取已排序的别名偏移列表

### `pub struct MapState`
范围提示收集器和重构器。对应 Ghidra MapState。
- `gather_varnodes(&mut self, fd: &Funcdata)` — 从栈 varnode 收集类型信息
- `initialize(&mut self) -> bool` — 排序并添加端点

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
- `restructure_varnode(&mut self, fd: &Funcdata)` — 主入口：重构栈帧
- `find_symbol(&self, offset: u64) -> Option<&LocalSymbol>` — 按偏移查找符号

## 当前限制

模块已实现但尚未集成到 printc.rs/codegen。变量命名仍使用 printc.rs 中的启发式命名。

# `cover.rs` API Reference

**状态**: 接口描述可用；Ghidra 12.0.4 对齐级别 L2
**源代码路径**: `src/cover.rs`

> Null/End/Input/Op endpoint 身份、`start>stop` 回绕 cover、CFG 前驱递归、
> dirty rebuild 与 PcodeOpSet/HighIntersectTest 尚未对齐。

## 模块说明 (Module Doc)

Liveness cover for varnodes

Corresponds to Ghidra's `cover.hh`

## 导出的公共 API (Public API)

### `pub struct CoverBlock`

Range of P-code ops within a single basic block where a varnode is alive

Corresponds to Ghidra's `CoverBlock` class

### `pub fn new() -> Self`

Create an empty cover block

### `pub fn clear(&mut self)`

Clear the cover block

### `pub fn set_begin(&mut self, s: u32)`

Set the start of liveness

### `pub fn set_end(&mut self, e: u32)`

Set the end of liveness

### `pub fn empty(&self) -> bool`

Check if the cover block is empty

### `pub fn contain(&self, point: u32) -> bool`

Check if the cover block contains a specific point

### `pub fn merge(&mut self, other: &CoverBlock)`

Merge another cover block into this one

### `pub fn intersect(&mut self, other: &CoverBlock)`

Intersect another cover block with this one

### `pub struct Cover`

Full liveness cover of a varnode across multiple blocks

Corresponds to Ghidra's `Cover` class

### `pub fn new() -> Self`

Create a new empty cover

### `pub fn clear(&mut self)`

Clear the cover

### `pub fn add_def_point(&mut self, block_idx: i32, point: u32)`

Add a definition point to the cover

### `pub fn add_ref_point(&mut self, block_idx: i32, point: u32)`

Add a reference point to the cover

### `pub fn contain(&self, block_idx: i32, point: u32) -> bool`

Check if the cover contains a point within a block

### `pub fn merge(&mut self, other: &Cover)`

Merge another cover into this one

### `pub fn intersect(&mut self, other: &Cover)`

Intersect another cover with this one


### 2026-07-04：新增 CoverBlock::boundary + Cover::contain_varnode_def_at
- `CoverBlock::boundary(point)`（对齐 cover.cc:129-142）：返回 0/1/2（非边界/tail/defining point）。
- `Cover::contain_varnode_def_at(is_input, block, order)`（对齐 cover.cc:441-462）：返回 0/1/2/3（未包含/内部/定义边界/tail边界）。供 eliminate_intersect 使用。

### 2026-07-04（续）：新增 intersect_char（非破坏性相交特征）
- `CoverBlock::intersect_char(op2)`（对齐 cover.cc:59）：返回 0/1/2（无/边界/区间相交）。
- `Cover::intersect_char(op2)`（对齐 cover.cc:269）：遍历两个 cover 的 block map，对共同 block 调 CoverBlock::intersect_char。返回 0/1/2。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-11：ANN-E 注释溯源

本轮只补函数来源标注，不改变运行时行为。源码 oracle 固定为 Ghidra
12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`：

- `PcodeOpSetImpl::populate` 与 `affects_test` 映射到 `cover.hh` 中的两个
  pure-virtual 方法。
- `Cover::{block_index_of_op, order_of_op, predecessors_of}` 是 Rust
  所有权/锁释放适配；Ghidra 在对应调用点直接解引用 `PcodeOp*` 和
  `FlowBlock*`，没有独立函数。
- `PcodeOpSet` 的 `Debug`、四个只读访问器，以及临时 `NoOpOwner` 的两个
  trait 方法属于 Rust 可见性、快照或借用检查胶水，不计作 Ghidra 函数映射。

这些标注不提升模块对齐级别；文件头列出的 endpoint 身份、回绕 cover、CFG
递归和 PcodeOpSet 交集缺口仍然存在。

### 2026-08-15：`COVER-REBUILD-SELFLOCK-0001` root-identity 重建

生产路径曾出现永久自锁：`Merge::update_high_cover` 持 root Varnode 写锁时，
`Cover::rebuild` 再对同一 Arc 取读锁。现按锁定 `cover.cc:477-496` /
`varnode.cc:233-241` 改为显式共享 root identity：

- `Cover::rebuild(root: &Arc<RwLock<Varnode>>)` 签名改为共享句柄；worklist
  语义不变（root + implied outputs，`addRefPoint` 恒以 root 为身份）。
- `add_ref_point_full(op_arc, root)` 在持有 op 读锁的窗口内用
  `Arc::ptr_eq` 快照全部 MULTIEQUAL 匹配槽（Ghidra `ref->getIn(j)==vn` 的
  指针恒等），随后释放块读锁再递归，不再自创 dedup。
- `add_def_point_full(def, is_input)` 接收定义 op 与 input 标志快照。
- 空块分支显式 `set_begin(0)` 物化 Ghidra nullptr start 的可比值（Ghidra
  `setEnd(ref)` 不触碰 start；投影一致，见 cover.hh:75-91）。
- `rebuild_from_root_snapshot` 是锁释放适配（RUGRA-GLUE）：updateCover 持
  root 写锁时先快照 def/is_input/descend/is_implied，rebuild 全程不再锁
  root；op 输出恰为 root 时用快照的 `root_is_implied` 判定，避免写锁重入。

已知残差：order-only `CoverBlock` 无法恢复 addRefPoint "旧 stop" 的
MULTIEQUAL-tip 判别（保守放行 MULTIEQUAL 递归）；INDIRECT 的
`getOpFromConst` 目标 order 仍回退自身 order。`COVER-REBUILD-SELFLOCK-0001`
fixture（8 case 合成图，含 slot2 self-reference、双槽读、implied 链、
setAll 前驱填充、no-cover-object dirty 清除）负责该投影的行为门禁。

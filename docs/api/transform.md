# `transform.rs` API Reference

**源代码路径**: `src/transform.rs`
**Ghidra 对应**: `transform.hh` / `transform.cc` (1023行)
**状态**: 📋 L1→🔧 L2（LanedRegister/LaneDescription/TransformVar/TransformOp 已实现，TransformManager 待补）

## 模块说明

大规模数据流变换基础设施。对应 Ghidra 的 `transform.hh`。
用于 lane splitting（将大寄存器操作分解为小的逻辑通道）。

## 导出的公共 API

### `pub struct LanedRegister`
描述寄存器存储位置及其可分割的 lane 尺寸。
- `with_sizes(sz, mask)` / `add_lane_size(size)` / `allowed_lane(size)` / `lane_sizes()`

### `pub struct LaneDescription`
大 Varnode 内的逻辑 lane 布局。
- `uniform(orig_size, sz)` — 均匀分割
- `two_lane(orig_size, lo, hi)` — 两 lane
- `get_num_lanes()` / `get_size(i)` / `get_position(i)`

### `pub enum TransformVarType`
替换 Varnode 的类型（Piece/Preexisting/NormalTemp/PieceTemp/Constant/ConstantIop）。

### `pub struct TransformVar`
变换后的 Varnode 占位符。new_preexisting/new_unique/new_constant/new_piece 构造方法。

### `pub struct TransformOp`
变换后的 PcodeOp 占位符。new(num_params, opc) 构造。

测试：transform::tests 3 个（LanedRegister/LaneDescription uniform/LaneDescription two_lane）。

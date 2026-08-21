# `transform.rs` API Reference

**源代码路径**: `src/transform.rs`
**Ghidra 对应**: `transform.hh` / `transform.cc` (767 行)
**状态**: 🔧 L2 — `TransformManager` 五阶段与主要 API 已实现；本轮 PHI 插入
目标投影为 `MATCH`，但模块仍有已登记 `UNTESTED`/实现残差，不能宣称 L3。

## 模块说明

大规模数据流变换基础设施。对应 Ghidra 的 `transform.hh` / `transform.cc`。
用于 lane splitting（将大寄存器操作分解为小的逻辑通道）和 Dolphin 变换。

## Rust 适配设计

Ghidra 使用原始 `TransformVar*` / `TransformOp*` 指针指向 `TransformManager`
拥有的 `list<TransformVar>` / `list<TransformOp>`。Rugra 采用 arena 风格 ID 索引：
`TransformManager` 拥有 `Vec<TransformVar>` 和 `Vec<TransformOp>`，引用使用稳定
的 `usize` 索引。Split 数组（Ghidra 的 `new TransformVar[n]`）存储为连续的 run，
其起始索引记录在 `piece_map` 中。

## 导出的公共 API

### `LanedRegister` (transform.hh:93)
描述寄存器存储位置及其可分割的 lane 尺寸。
- `with_sizes(sz, mask)` / `default()`
- `add_lane_size(size)` / `allowed_lane(size)` / `lane_sizes()`
- `parse_sizes(register_size, lane_sizes)` — 解析逗号分隔的尺寸列表 (transform.cc:300)
- `get_whole_size()` / `get_size_bit_mask()`

### `LaneDescription` (transform.hh:132)
大 Varnode 内的逻辑 lane 布局。
- `uniform(orig_size, sz)` — 均匀分割 (transform.cc:35)
- `two_lane(orig_size, lo, hi)` — 两 lane (transform.cc:53)
- `subset(lsb_offset, size)` — 裁剪到子范围 (transform.cc:72)
- `get_boundary(byte_pos)` — 字节位置→lane 索引（二分搜索）(transform.cc:100)
- `restriction(num, skip, pos, size) -> Option<(num, skip)>` — 截断检查 (transform.cc:133)
- `extension(num, skip, pos, size) -> Option<(num, skip)>` — 扩展检查 (transform.cc:158)
- `get_num_lanes()` / `get_size(i)` / `get_position(i)` / `get_whole_size()`

### `TransformVarType` (transform.hh:36)
枚举：Piece(1)/Preexisting(2)/NormalTemp(3)/PieceTemp(4)/Constant(5)/ConstantIop(6)。

### `transform_var_flags` (transform.hh:45)
常量：`SPLIT_TERMINATOR`(1) / `INPUT_DUPLICATE`(2)。

### `TransformVar` (transform.hh:34)
变换后的 Varnode 占位符。
- `initialize(type, vn, bits, bytes, value)` — 原始初始化 (transform.hh:203)
- `create_replacement(fd, def_op)` — 创建实际 Varnode (transform.cc:175)
- 字段：`vn` / `replacement` / `var_type` / `flags` / `byte_size` / `bit_size` /
  `val` / `def`

### `transform_op_special` (transform.hh:70)
常量：`OP_REPLACEMENT`(1) / `OP_PREEXISTING`(2) / `INDIRECT_CREATION`(4) /
`INDIRECT_CREATION_POSSIBLE_OUT`(8)。

### `TransformOp` (transform.hh:63)
变换后的 PcodeOp 占位符。
- `attempt_insertion(fd, ops)` — follow 已落块后完成延迟插入；`MULTIEQUAL`
  使用 `op_insert_begin`，其他 opcode 使用 `op_insert_before` (transform.cc:254)
- `inherit_indirect(ind_op)` — 继承 INDIRECT 标记 (transform.cc:273)
- 字段：`op` / `replacement` / `opc` / `special` / `output` / `input` / `follow`

### `TransformManager` (transform.hh:156)
orchestrates 变换生命周期。
- `new()` / `default()` / `init(fd)`
- `preserve_address(vn, bit_size, lsb_offset)` — 是否保留地址 (transform.cc:348)
- `clear_varnode_marks()` — 清除所有占位符 Varnode 的 mark (transform.cc:356)

**占位符创建**（transform.cc:370-575）：
- `new_preexisting_varnode(vn)` / `new_unique(size)` / `new_constant(size, lsb, val)`
- `new_iop(vn)` / `new_piece(vn, bit_size, lsb)`
- `new_split(vn, description)` / `new_split_subset(vn, desc, num, start)`
- `new_op_replace(num, opc, replace)` / `new_op(num, opc, follow)`
- `new_preexisting_op(num, opc, original)`

**占位符查找**（transform.cc:581-649）：
- `get_preexisting_varnode(vn)` / `get_piece(vn, bit_size, lsb)`
- `get_split(vn, desc)` / `get_split_subset(vn, desc, num, start)`

**输入/输出设置**（transform.hh:219-253）：
- `op_set_input(rop, rvn, slot)` / `op_set_output(rop, rvn)`
- `preexisting_guard(slot, rvn)` — 是否应创建 preexisting op

**apply 生命周期**（transform.cc:651-765）：
- `apply(fd)` — 完整应用变换（createOps→createVarnodes→removeOld→
  transformInputVarnodes→placeInputs）
- 私有：`create_op_replacement(op_idx)` / `create_ops()` / `create_varnodes(input_list)`
  / `remove_old()` / `transform_input_varnodes(input_list)` / `place_inputs()`

## 已知限制
- `transferVarnodeProperties`（transform.cc:208）尚未实现 — Rugra 的 Varnode 未暴露
  完整的属性转移 API。
- `markIndirectCreation` 尚未完整接入；`inherit_indirect` 仍保守地假设
  possible-out。`opInsertBegin` 已由 Funcdata 暴露并用于 PHI 插入。
- ~~`deleteVarnode` / `setInputVarnode` 未暴露~~ — 2026-08-15
  （VARNODE-INPLACE-MUTATION-SITES-0001）已接入：`transform_input_varnodes` 对旧
  输入走 `fd.delete_varnode`（cc:734-735，funcdata.hh:294），新输入走
  `fd.set_input_varnode`（cc:736，funcdata_varnode.cc:340-373 → `VarnodeBank::setInput`
  varnode.cc:1358 身份删除+INPUT 重键），canonical 返回值存回 `replacement` 供
  placeInputs 接线；不再原地 set_flags(INPUT) 突变树驻留 varnode。
- `ConstantIop` 类型使用常量 fallback（Rugra 无 iop space）。
- `inherit_indirect` 的 indirect-zero 检查保守地假设 possible-out。

## 测试
20 个单元测试覆盖 LanedRegister（basic/parse_sizes）、LaneDescription（uniform/
two_lane/get_boundary/subset/restriction/extension）、TransformVar（initialize）、
TransformManager（preexisting/unique/constant/constant-shift/split/op-replace/
op-set-input-output/preexisting-guard/constant-getpiece）。

### 2026-07-01（续）：TransformManager::apply 确认完整
TransformManager::apply（transform.cc:756-765）：create_ops→create_varnodes→remove_old→place_inputs→transform_input_varnodes。SplitFlow 委托此方法。

### 2026-08-21：TRANSFORM-MULTIEQUAL-INSERT-0001

`TransformOp::createReplacement` 的 immediate 分支和 `attemptInsertion` 的 follow
分支现在都保留锁定 Ghidra 的 opcode 特判：新 `MULTIEQUAL` 总是通过
`Funcdata::op_insert_begin` 插到基本块开头，其他新 op 仍紧邻原 op/follow 之前。
连续创建两个 PHI 时，第二个创建的 op 因再次插到 block begin 而排在第一个之前；
COPY 等非 PHI 保持创建顺序。对应单测同时覆盖 immediate/follow 两条路径及
PHI/non-PHI 四种组合；锁定 12.0.4 fixture 对比完整 op/varnode identity、
SeqNum time/order、def-use、块内顺序和 bank 计数。

证据状态严格区分为：`projection_status=MATCH`、`overall_status=UNTESTED`。
所有未覆盖项统一绑定 `TRANSFORM-MULTIEQUAL-INSERT-RESIDUAL-0001`：

- `op_preexisting` 的 opcode/input resize 与 nullable-slot 路径；
- 多层 follow 链仍未落块时的 retry；
- INDIRECT `inheritIndirect` / `specialHandling`；
- missing-parent、畸形 placeholder 和错误注入路径；
- `createReplacement` 的 `output == nullptr` 分支；
- SeqNum midpoint 不足、触发 `BlockBasic::setOrder` 整块重排的插入边界。

fixture metadata 使用 schema 2：每个 coverage 项都包含 `{status, covers,
residual_todo_ids}`，顶层 residual union 与逐项 union 由 runner fail-closed 核对。
<!-- annotation-pass: 2026-07-04 -->

# `dynamic.rs` API Reference

**源代码路径**: `src/dynamic.rs`
**Ghidra 对应**: `dynamic.hh` / `dynamic.cc` (773行)
**当前规模**: 1264 行 (HEAD 391 行 → +873 行)

## 模块说明

动态哈希：为 Varnode 和 PcodeOp 生成内容寻址哈希，跨编译保持稳定。
用于 equate/重命名标注、跨编译变量识别、调试标注。

DynamicHash 在目标周围构建局部子图，对 opcode 结构 + 地址进行哈希，
生成稳定标识符。Ghidra 用它把符号/注解锚定到具体的 SSA 变量。

## 常量与函数

### `const TRANSTABLE: [u32; 75]`
Ghidra `DynamicHash::transtable` (dynamic.cc:24-63) 的逐元素移植。
opcode 索引到哈希翻译值的映射表，将变体合并到同一哈希值：
- `INT_SUB` / `PTRADD` / `PTRSUB` → `INT_ADD` (索引 19)
- `INT_NOTEQUAL` → `INT_EQUAL` (索引 11)
- `INT_LEFT` → `INT_MULT` (索引 32)
- `FLOAT_SUB` → `FLOAT_ADD` (索引 47)
- `CAST` (64) / 未用槽 (45) → `0` (跳过)

以 `OpCode as usize` 索引。Rust `#[repr(i32)]` enum 与 Ghidra C++ enum
数值完全一致（值 45 两边都跳过，故 FLOAT_NAN==46）。const 上下文中
逐元素初始化，无运行时开销。

### `fn translate_opcode(opc: OpCode) -> u32`
`TRANSTABLE[opc]` 的薄封装（RUGRA-GLUE：边界检查胶水）。零=跳过。

## `struct ToOpEdge`
从 Varnode 到 PcodeOp 的边 (dynamic.hh:32)。`slot == -1` 表示 op 输出。
- `new(op, slot)` — 构造 (dynamic.hh:36)
- `get_op()` / `get_slot()` — 访问器 (dynamic.hh:37-38)
- `compare(other)` — 排序：SeqNum.addr → SeqNum.order → slot (dynamic.cc:69-81)
- `hash_into(reg)` — CRC 折叠：slot + 翻译后 opcode + 每字节地址 (dynamic.cc:92-104)

## `struct DynamicHash`
哈希引擎 (dynamic.hh:62)。

### 子图构建（私有）
- `build_vn_up(vn)` — 向上到定义 op，穿越 CAST 跳过 op (dynamic.cc:109-120)
- `build_vn_down(vn)` — 向下到读取 op，穿越 CAST，按 compare 排序 (dynamic.cc:125-148)
- `build_op_up(op)` / `build_op_down(op)` — 暂存输入/输出 Varnode (dynamic.cc:152-167)
- `gather_unmarked_vn()` / `gather_unmarked_op()` — 标记并入子图 (dynamic.cc:170-191)

### 哈希计算（公共）
- `calc_hash_vn(root, method)` — Varnode 根哈希 (dynamic.cc:268-316)。method 0=立即读写, 1=多一层输入, 2=多一层输出, 3=双向
- `calc_hash_op(op, slot, method)` — PcodeOp+slot 哈希 (dynamic.cc:202-255)。method 4=仅op, 5=输入, 6=输出
- `piece_together_hash(root, method)` — 组装最终 64 位哈希 (dynamic.cc:323-381)。CRC 种子 `0x3ba0fe06`

### 唯一化与查找（公共）
- `unique_hash_vn(root, fd)` — 选最小冲突的 method (0..3) (dynamic.cc:424-477)
- `unique_hash_op(op, slot, fd)` — 选最小冲突的 method (4..6) (dynamic.cc:485-548)
- `find_varnode(fd, addr, h)` — 按地址+哈希反查 Varnode (dynamic.cc:561-580)
- `find_op(fd, addr, h)` — 按地址+哈希反查 PcodeOp (dynamic.cc:593-615)
- `move_off_skip(op, slot)` — 穿越 CAST 等跳过 op (dynamic.cc:389-407)
- `dedup_varnodes(varlist)` — 去重保序 (dynamic.cc:619-634)
- `gather_first_level_vars(varlist, fd, addr, h)` — 收集 addr 处直接挂接的 Varnode (dynamic.cc:645-685)
- `gather_ops_at_address(op_list, fd, addr)` — 收集 addr 处所有活 op (dynamic.cc:692-702)

### 哈希解码静态方法（dynamic.cc:707-771）
64 位哈希位布局：
```
bit 48   : is_not_attached
bits 44-47: method (4 bits)
bits 37-43: translated opcode (7 bits)
bits 32-36: slot (5 bits; 31 = -1 = output)
bits 0-31 : 32-bit CRC neighborhood hash
bits 49-51: position (collision list 内位置)
bits 52-54: total (碰撞总数，编码值 = 实际 - 1)
```
- `get_slot_from_hash(h)` — 返回 i32；31→-1 (dynamic.cc:707)
- `get_method_from_hash(h)` — bits 44-47 (dynamic.cc:719)
- `get_opcode_from_hash(h)` — bits 37-43 (dynamic.cc:728)
- `get_position_from_hash(h)` — bits 49-51 (dynamic.cc:737)
- `get_total_from_hash(h)` — bits 52-54，+1 (dynamic.cc:746)
- `get_is_not_attached(h)` — bit 48 (dynamic.cc:755)
- `clear_total_position(&mut h)` — 清 bits 49-54 (dynamic.cc:764)
- `get_comparable(h)` — 取低 32 位用于比较 (dynamic.hh:103)

## 2026-07-22 移植状态（完整移植）

**19 个单元测试**，覆盖：translate_opcode 变体合并、ToOpEdge compare/hash、
哈希解码全字段往返、calc_hash_vn/op、稳定性、gather_ops_at_address、
dedup_varnodes、move_off_skip（含穿越 CAST）、find_varnode 往返。

已移植全部 dynamic.cc 关键方法：transtable、ToOpEdge compare/hash、
buildVn{Up,Down}、buildOp{Up,Down}、gather{UnmarkedVn,UnmarkedOp}、
calcHash（两重载）、pieceTogetherHash、moveOffSkip、dedupVarnodes、
uniqueHash（两重载）、findVarnode、findOp、gatherFirstLevelVars、
gatherOpsAtAddress、所有哈希解码静态方法。

**关键修正**（相对旧 391 行版本）：
- `translate_opcode` 由 match 改为 `TRANSTABLE` const 数组索引，正确合并 ADD/SUB/LEFT/PTRADD/PTRSUB/FLOAT_SUB 等变体（旧版全部映射到自身，导致哈希不收敛）
- 哈希位布局对齐 Ghidra（method 在 bits 44-47 而非 32-37；opcode 在 bits 37-43 而非 38-43；新增 attached 位 48）
- CRC 种子由 `0xffffffff` 改为 `0x3ba0fe06`（dynamic.cc:337）
- `piece_together_hash` 实现 attached-op 查找逻辑（旧版缺失）
- 新增 14 个方法（uniqueHash/findVarnode/findOp/gatherFirstLevelVars/gatherOpsAtAddress/moveOffSkip/dedupVarnodes 等）

**编译验证**：`cargo check --lib` 对 `src/dynamic.rs` 报 0 错误 0 警告。
（工作树其他文件 variable.rs/unionresolve.rs/database.rs/merge.rs 等存在预先
存在的编译错误，非本移植引入，按约束仅修改 dynamic.rs + 本文档。）
<!-- annotation-pass: 2026-07-22 -->

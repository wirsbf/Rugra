# 工程日志：栈帧分析模型 + SSA-aware 条件解析

**日期**: 2026-05-21  
**范围**: `rugra/src/printc.rs`  
**测试**: 168 passed ✅

## 目标

用户需求：
1. `RSP + 0x38` 等栈偏移 → 栈帧分析模型
2. `uVar99`/`uVar156` 仍作为条件出现 → SSA-aware 引用追踪
3. `uVar107 = RSP - 0x228` → 转为栈帧基址

## 实现概要

### 1. 栈帧检测

- 新增 `stack_frame_size: u64` 字段
- 在 `doc_function` 中扫描所有 block ops，检测 `INT_SUB(RSP, const)` 模式
- RSP 识别为 Register offset 0x20, size 8

### 2. 栈变量命名

- 新增 `get_stack_variable_name()` helper
- **Case 1**: `INT_ADD(RSP, const)` → `local_{frame_size - offset}`
  - `RSP + 0x38` (frame=0x228) → `&local_1f0`
  - `RSP + 0x34` → `&local_1f4`
- **Case 2**: `INT_ADD(frame_base, const)` → 通过 `stack_frame_base_key` 匹配
  - `uVar107 + 0x218` → `local_10` (因为 uVar107 = RSP - 0x228, +0x218 = RSP - 0x10)
  - `uVar107 + 0x48` → `local_1e0`
- 集成到三处：
  - `emit_inline_expr` (CALL 参数等表达式上下文)
  - `op_binary` (独立赋值语句)
  - `op_store` (STORE 目标地址)

### 3. 栈帧基址消除

- 新增 `is_stack_frame_setup()` helper
- 在 `emit_block_ops` 和 `op_binary` 中跳过 `INT_SUB(RSP, frame_size)` ops
- 效果：`uVar107 = RSP - 0x228` 完全消除

### 4. comparison_def_map

- 新增 `comparison_def_map: HashMap<(Space, u64), Arc<PcodeOp>>`
- 仅存储比较和布尔 ops (INT_EQUAL, INT_LESS, BOOL_OR 等)
- 使用 "first one wins" 策略，不被后续非比较 ops 覆盖
- 作为 `emit_condition` 的最终 fallback

### 5. do-while 条件修复

- `BlockType::DoWhile` 的条件从 `push_varnode` 改为 `emit_condition`
- `while (uVar99)` → `while (uVar194 == 0)`

### 6. block-level def_map 扩展

- `def_map` 原来只从 `fd.obank.alivelist` 构建
- 现在也从 block-level ops 构建（许多比较/布尔 ops 仅存在于 blocks 中）

### 7. emit_block_condition 增强

- 扫描 block 的 ops 找到与 CBRANCH 条件匹配的比较 op
- 将匹配的比较 op 的 Arc 插入 `def_map`，供 `emit_condition` 使用

## 效果

| 变化 | 前 | 后 |
|------|----|----|
| 栈帧 | `uVar107 = RSP - 0x228` | (消除) |
| 函数参数 | `curl_version(RSP + 0x38)` | `curl_version(&local_1f0)` |
| 栈存储 | `*(RSP + 0x18) = lVar_b0` | `local_210 = lVar_b0` |
| 帧偏移 | `*(uVar107 + 0x218) = uVar110` | `local_10 = uVar110` |
| do-while | `while (uVar99)` | `while (uVar194 == 0)` |
| 声明数 | 8 个 | 7 个 |

## 遗留问题

- `if (uVar99)`, `if (uVar156)`: CBRANCH 条件 varnode 的 Arc 与比较 op 输出的 Arc 不是同一对象，且跨块存在 value_def_map 碰撞。需要完整 SSA use-def chain。
- `uVar_a0`: Unique 空间变量，需追踪到源定义。
- 栈变量类型推断：`local_1f0` 等目前无类型声明。

## 新增 PrintC 字段

```rust
comparison_def_map: HashMap<(AddressSpace, u64), Arc<RwLock<PcodeOp>>>
stack_frame_size: u64
stack_frame_base_key: Option<(AddressSpace, u64)>
```

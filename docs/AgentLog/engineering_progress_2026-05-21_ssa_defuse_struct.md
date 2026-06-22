# Engineering Log: SSA Def-Use Chain + Struct Aggregation (2026-05-21)

## 目标

完成 SSA def-use chain 在 PrintC 中的完整集成，并在此基础上实现栈帧结构体字段聚合。

## 问题分析

### Problem 1: `if (uVar99)` / `if (uVar156)` 未解析

**原因追踪**:
- 初始假设：`emit_condition` 的 SSA 策略未命中 → 错误
- 实际原因：`if (uVar99)` 来自一个**完全不同的代码路径**
- 在 `emit_block_structured` 中的 "legacy inline if/else" 分支（line 455），直接使用 `push_varnode` 输出 CBRANCH 条件，**完全绕过了 `emit_condition`**
- 通过在所有 `if (` 发射点添加 `eprintln` 追踪，逐步排除 `emit_condition` fallback、`op_cbranch`、`emit_block_condition`，最终定位到 line 463

**修复**: 将 legacy if/else 路径改为使用 `emit_block_condition(block_arc)` — 与 BlockIf 路径一致

### Problem 2: `argc <= 1` 退化为 `uVar99 || uVar100`

**原因**: 修复 Problem 1 后，`emit_condition` 的 SSA Strategy 0 找到了 MULTIEQUAL (phi) → trace → BOOL_OR 的全局 def chain，跳过了 block-local 的 `try_fold_bool_comparison` 

**修复**: 在 `emit_condition` Case 2 处，当 def_op 是 BOOL_OR/BOOL_AND 时：
1. 先调用 `try_fold_bool_comparison` 尝试折叠
2. 若折叠成功，直接返回（`argc <= 1`）
3. 若折叠失败，对每个操作数递归调用 `emit_condition`

### Problem 3: Struct Detection

**方法**: 检测 `INT_ADD(RSP, const)` 模式，其输出通过 COPY 传递到 Register 空间（函数参数传递模式）。

**初始失败**: 使用 `Varnode.descend` 检测 CALL 使用 → 空列表（Heritage SSA renaming 创建新 varnode）

**修复**: 改为扫描同基本块的后续 ops：
1. COPY 传播到 Register = 函数参数
2. 直接被 CALL 使用

## 代码变更

### `printc.rs`

1. **StackStruct 模型**: 新增结构体定义（name, base_offset, size, fields）
2. **SSA def-use chain**: `get_defining_op` 作为 Strategy 0 集成到 `emit_condition`
3. **Legacy if/else 修复**: 使用 `emit_block_condition` 替代 `push_varnode`
4. **BOOL_OR/BOOL_AND 递归**: 操作数通过 `emit_condition` 递归解析
5. **Struct 检测 pass**: 在 `doc_function` 中扫描所有块检测 struct 基址
6. **Struct 字段解析**: `get_stack_variable_name` 优先匹配 struct 范围

## 效果对比

| 改进前 | 改进后 |
|--------|--------|
| `if (uVar99)` | `if (uVar194 == 0)` |
| `if (uVar156)` | `if (uVar194 != 0)` |
| `if (uVar122)` (regression) | `if (argc <= 1)` (restored) |
| `&local_1f0` | `&config` |
| `curl_version(&local_1f0)` | `curl_version(&config)` |

## 验证

- 168 单元测试通过
- `cargo run --example curl_decompile` 输出干净，无 debug 输出

## 遗留问题

- `local_1f4` 未被聚合到 config 结构体（4 字节标量，struct 检测阈值 < 8 跳过）
- STORE/LOAD 的 `[rsp+48h]` 类型偏移未被 `all_stack_offsets` 收集
- 变量声明中仍有 `uVar109`, `uVar110` 等未消除的中间变量
`, "Description": "Engineering log for SSA def-use chain and struct aggregation."

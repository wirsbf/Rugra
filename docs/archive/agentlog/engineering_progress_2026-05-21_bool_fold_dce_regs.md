# Engineering Progress: Boolean Fold + Cross-Block DCE + Register Elimination

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 20:42
- **核心意图**: 布尔表达式简化、跨块 DCE、寄存器名消除、CALL 参数深度解析
- **触及模块**: `src/printc.rs`

---

## 代码变更

### 1. 布尔表达式简化 (Boolean Comparison Folding)
- **新增方法**: `try_fold_bool_comparison(&mut self, def_op: &PcodeOp) -> bool`
- 检测 `BOOL_OR(INT_EQUAL(A,B), INT_LESS(A,B))` / `INT_SLESS` 模式
- 使用 pointer-based `def_map` 精确匹配定义 op（避免 value_def_map 的 offset 碰撞）
- 折叠为 `A <= B`，标记子比较 ops 为 `inlined_ops`
- 在 `emit_inline_expr` 和 `op_binary` 两处调用

### 2. 跨基本块死代码消除 (Cross-Block DCE)
- **新增字段**: `global_used_outputs: HashSet<usize>`
- 在 `doc_function` 中扫描 ALL blocks + alivelist，收集所有 input varnode Arc 指针
- `emit_block_ops` 将 `global_used_outputs` 合并到局部 `used_outputs`
- RIP-relative INT_ADD 在 `emit_block_ops` 级别直接跳过（不进入 `doc_statement`）
- 消除 `uVar106 = config`, `uVar108 = stdin`, `uVar113 = stdout` 等

### 3. 寄存器名消除 (Register Name Elimination)
- **新增方法**: `is_raw_register_name(name: &str) -> bool`
- 在 Priority 1 (HighVariable) 名称检查中，将 x86-64 寄存器名转换为 Ghidra 风格局部变量名
- `lVar` (long/8 bytes), `iVar` (int/4 bytes), `sVar` (short/2 bytes), `bVar` (byte/1 byte)
- RSP/ESP 和 RBP/EBP 保留（栈/帧指针）
- 同步更新 `get_varnode_display_name` 和 Priority 2 fallback

### 4. CALL 参数深度解析 (Deep CALL Arg Resolution)
- op_call 中 COPY 源增加二次查找：
  - 查 `value_def_map` 和 `inline_candidates` 找源的定义 op
  - RIP-relative 定义 → 直接输出符号名
  - 其他定义 → 内联表达式
  - Fallback → push 原始 COPY 源
- 非 COPY ops 也增加 RIP-relative 检查

---

## 效果对比（从初始到最终）

| 指标 | 初始 | 本轮后 |
|------|------|--------|
| 变量声明 | 75 个 | 8 个 |
| 代码行数 | ~93 行 | ~48 行 |
| 常量显示 | `uVar58` | `1` |
| 布尔比较 | `uVar99 || uVar100` | `argc <= 1` |
| 寄存器名 | `R14`, `EAX` | `lVar_b0`, `iVar_0` |
| 符号折叠 | `uVar106 = config` | (已消除) |
| CALL 参数 | `uVar193` | `RSP + 0x38` |

## 测试
- **全部 168 测试通过，0 失败**

## 仍可改进
- `uVar_a0` 等 Unique 空间变量可追溯到源
- `uVar99`/`uVar156` 在其他块引用但无声明
- Stack offset 可转为 stack frame 模型
- `while (uVar99)` 中 uVar99 应解析为 `argc <= 1`

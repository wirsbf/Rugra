# Engineering Progress: Constant Folding + DCE + Parameter Naming

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 19:40
- **核心意图**: 常量折叠、扩展 DCE、argc/argv 参数映射
- **触及模块**: `src/printc.rs`

---

## 代码变更

### 1. 常量折叠 (Const Space HighVariable Bypass)
- 在 `push_varnode` 中，对 Const 空间 varnode 跳过 HighVariable 命名
- 常量直接显示为数值：`uVar58` → `1`，`uVar104` → `0x228`

### 2. Priority 1.5: Def Chain Resolution
- 对 uVarN 命名的 Register/Unique varnode，追踪 value_def_map 定义链
- Case A: COPY(Const) → 发射常量或符号名
- Case B: COPY(Unique) → 追踪 Unique 定义 → RIP 折叠或内联
- Case C: 直接 INT_ADD(RIP, x) → 折叠为符号

### 3. is_lhs Guard
- 新增 `is_lhs: bool` 字段
- 所有 output push_varnode 调用前设置 `is_lhs = true`
- Priority 1.5 跳过 `is_lhs == true`
- 防止 `uVar106 = config` 变成 `config = config`

### 4. argc/argv 参数映射
- main 函数自动将 RDI(0x38) → `argc`，RSI(0x30) → `argv`
- `EDI == 1` → `argc == 1`

### 5. 扩展 Dead Code Elimination
- 从仅跳过比较/布尔 ops 扩展到所有纯计算 ops
- 新增：算术、位运算、移位、扩展/截断、LOAD、COPY
- 消除 16 行死赋值（R13+8, RAX*8, *RBX, RSP+0x60 等）

### 6. 变量声明裁剪
- uVar 名称从 output 端不再触发声明
- 只有作为 input 使用的 uVar 才会被声明

---

## 效果对比

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| 变量声明 | 75 个 | 17 个 |
| 代码行数 | ~93 行 | ~62 行 |
| 常量 | `uVar58` | `1` |
| 参数 | `EDI` | `argc` |
| 符号 | `RIP + config` | `config` |
| 死代码 | 16 行 | 0 行 |

## 测试
- **全部 168 测试通过，0 失败**

## 仍待优化
- `uVar193` 应解析为 `config`（多跳 COPY chain）
- `R13`, `R15`, `RAX` 等寄存器名仍出现
- `uVar99 || uVar100` 应简化为 `argc <= 1`
- 跨基本块的死代码消除

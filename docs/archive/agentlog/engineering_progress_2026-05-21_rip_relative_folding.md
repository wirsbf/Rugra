# Engineering Progress: RIP-Relative Folding & Variable Cleanup

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 19:09
- **核心意图**: RIP-relative 地址折叠 + 帧寄存器声明清理
- **触及模块**: `src/printc.rs`, `src/opcodes.rs`

---

## 1. 代码变更

### RIP-relative 地址折叠
- **新增辅助方法**: `get_rip_relative_operand()` — 检测 `INT_ADD(RIP, x)` 或 `INT_ADD(x, RIP)` 模式
- **三处修改**:
  - `op_binary`: 顶层语句 `uVar = RIP + config` → `uVar = config`
  - `emit_inline_expr`: 内联表达式 `(RIP + sym)` → `sym`
  - `op_store`: 存储地址 `*(RIP + config)` → `*config`

### 变量声明清理
- 排除 RIP (0x200)、RSP (0x20)、RBP (0x28) 从变量声明
- 效果：真实 curl 输出减少了 4 个无意义声明

---

## 2. 真实 curl 输出改进

```diff
- uVar106 = RIP + config;        + uVar106 = config;
- uVar108 = RIP + stdin;         + uVar108 = stdin;
- *(RIP + config) = uVar23;      + *config = uVar23;
- uVar117 = RIP + "curl/7.1..";  + uVar117 = "curl/7.1..";
```

---

## 3. 测试
- **全部 168 测试通过，0 失败**

## 4. 设定的优化计划 (定时调度)
- P0: RIP-relative 折叠 ✅ 已完成
- P1: 变量声明精简（dead variable elimination）
- P2: CALL 参数正确附加
- P3: 常量折叠增强

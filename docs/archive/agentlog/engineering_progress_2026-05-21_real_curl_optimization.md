# Engineering Progress: Real Curl Decompilation Optimization (P0-P2)

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 19:15
- **核心意图**: 优化真实 curl 二进制反编译输出（RIP 折叠、变量清理、CALL 参数）
- **触及模块**: `src/printc.rs`

---

## 1. 代码变更

### P0: RIP-relative 地址折叠
- 新增 `get_rip_relative_operand()` — 检测 `INT_ADD(RIP, x)` 模式
- 在 `op_binary`, `emit_inline_expr`, `op_store` 三处添加 RIP 折叠
- 效果：`RIP + config` → `config`，`*(RIP + sym)` → `*sym`

### P1: 变量声明精简
- Register 空间变量全部排除（不再声明 `RAX`, `RDI` 等）
- Ram/Const 空间变量排除（不再声明 `config`, `stdin` 等全局符号）
- 变量声明数量：75 → 35

### P2: CALL 参数解析
- `op_call` 新增 Register 参数 def chain 追踪
- Register-space COPY ops 纳入 `value_def_map`
- 效果：`curl_version(RDI)` → `curl_version(uVar193)`

---

## 2. 输出演变对比

```diff
修复前:
-  long RIP;
-  long RSP;
-  int EAX;
-  int config;
-  int stdin;
-  (75 个变量)
-  uVar106 = RIP + config;
-  curl_version(RDI);

修复后:
+  (35 个变量)
+  uVar106 = config;
+  curl_version(uVar193);
```

---

## 3. 测试
- **全部 168 测试通过，0 失败**

## 4. 仍待优化
- `uVar193` 应解析为 `config`（需要深层 COPY chain 解析）
- 进一步减少变量声明（消除仅使用一次的 Unique 中间变量）
- `R12`, `R13` 等仍出现在函数体中

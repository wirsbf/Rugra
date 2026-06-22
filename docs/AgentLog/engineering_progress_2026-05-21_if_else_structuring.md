# Engineering Progress: If-Else Structuring & Decompilation Quality

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 18:59
- **核心意图**: 修复 if-else 结构化、参数名传播优先级、block terminator 定义
- **触及模块**: `src/funcdata.rs`, `src/printc.rs`, `src/opcodes.rs`, `src/blockaction.rs`, `src/action.rs`

---

## 1. 代码变更

### 参数名优先级提升
- **位置**: `src/printc.rs` `get_varnode_display_name` + `push_varnode`
- 在 HighVariable 名称检查之前添加 `param_names` 查找
- 效果：`ESI` → `param_2`

### CALL 从 block terminator 移除
- **位置**: `src/opcodes.rs` `is_block_terminator`
- 移除 `CPUI_CALL` 和 `CPUI_CALLIND`
- 效果：CALL 不再切割 basic block，CFG 从 5 块减少为 4 块

### if-else diamond 结构化
- **位置**: `src/blockaction.rs` + `src/printc.rs`
- Diamond 模式已正确检测：`cond=B0, then=B2, else=B1, merge=B3`
- 发现 `branch_type=3 (GOTO)` 导致 skip_terminal 失败
- 修复：skip_terminal 改为无条件跳过所有 branch ops
- 修复：BlockIf body 使用 `emit_block_ops(body, true)` 跳过尾部 BRANCH

### E2E 测试重构
- **位置**: `src/funcdata.rs` `test_realistic_curl_function`
- 重构为 14-op、4-block diamond CFG
- 所有 BRANCH 目标地址正确计算

---

## 2. 输出演变

```diff
修复前:
-long curl_easy_setopt() {
-  int ESI;
-  ...
-  goto LAB_4050c0;
-  ...

修复后:
+long curl_easy_setopt(long param_1, int param_2, long param_3) {
+  ...
+  uVar6 = (long)param_2;
+  if (uVar6 == uVar12) {
+    *(uVar5 + uVar4) = uVar7;
+  } else {
+    curl_set_error();
+  }
+  return RAX;
+}
```

---

## 3. 测试
- **全部 168 测试通过，0 失败**

## 4. 待解决
- 常量 0x2712 丢失（变成 uVar12）
- CALL 参数附加
- 冗余变量声明

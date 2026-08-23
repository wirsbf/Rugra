# Engineering Progress: Parameter Name Propagation

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 12:22
- **核心意图**: 让 PrintC 在表达式中使用参数名（param_1）而非寄存器名（RDI），并从变量声明中移除已在函数签名中声明的参数
- **触及模块**: `src/printc.rs`, `docs/TODO_BOARD.md`

---

## 1. 代码变更

### PrintC 参数名映射
- **新字段**: `param_names: HashMap<u64, String>` — 寄存器偏移 → 参数名
- **填充时机**: `doc_function` 开始时从 `fd.funcp.parameters` 遍历填充
- **使用位置**:
  - `push_varnode`：Register 空间 varnode 优先查 `param_names`，若匹配则使用参数名，否则回退到寄存器名
  - `get_varnode_display_name`：同样优先查 `param_names`
  - `is_declarable`：跳过 `param_` 前缀的变量名（但保留 `param_stack_`）

### 效果
```diff
 // Before:
-void curl_easy_setopt() {
-  long RDI;
-  long RSI;
-  RAX = RDI + RSI;

 // After:
+long curl_easy_setopt(long param_1, long param_2) {
+  RAX = param_1 + param_2;
```

---

## 2. 测试

- 新增 `test_param_name_resolution`：验证 `push_varnode` 在有参数映射时输出 `param_1` 而非 `RDI`
- **全部 167 测试通过，0 失败，0 警告**

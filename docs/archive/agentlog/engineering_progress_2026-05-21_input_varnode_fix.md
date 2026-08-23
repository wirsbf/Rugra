# Engineering Progress: INPUT Varnode Fix + Curl E2E Demo

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 15:10
- **核心意图**: 修复 inject_raw_ops 的 INPUT 标记缺失 + 端到端 curl 函数反编译演示
- **触及模块**: `src/funcdata.rs`, `src/action.rs`, `docs/TODO_BOARD.md`

---

## 1. 代码变更

### inject_raw_ops Phase 3 (新增)
- **位置**: `src/funcdata.rs` L211-L245
- 新增逻辑：收集所有 output 定义的 Register offset → 扫描所有 input 中 Register varnode → 若 offset 不在 defined 集合中，标记为 INPUT
- 效果：函数入口处读取的 RDI/RSI/RDX 等寄存器自动标记为 INPUT，被 ActionInferParams 识别为参数

### Pipeline 重排序
- **位置**: `src/action.rs`
- `ActionInferParams` 从 `ActionTypeInfer` 之后移至 `ActionHeritage` 之后、`ActionCopyPropagate` 之前
- 原因：CopyPropagate 会将 Register varnode 替换为 Unique varnode，导致 InferParams 无法找到参数寄存器

### apply_all 方法 (新增)
- **位置**: `src/action.rs` L105-L113
- 公共方法 `ActionDatabase::apply_all(&self, fd) -> Result<i32>` 便于外部使用

### E2E 测试 (新增)
- **位置**: `src/funcdata.rs` `test_realistic_curl_function`
- 模拟 curl_easy_setopt: 3 参数、CBRANCH 条件、CALL、STORE、RETURN
- 运行完整 pipeline 并打印输出

---

## 2. 输出对比

```diff
-long curl_easy_setopt()
+long curl_easy_setopt(long param_1, int param_2, long param_3)
```

---

## 3. 测试
- **全部 168 测试通过，0 失败，0 警告**

# Engineering Progress: Function Signature Recovery (ActionInferParams)

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 01:37
- **核心意图**: 实现函数参数检测与返回类型推断，将反编译输出的函数头部从硬编码改为数据驱动
- **触及模块**: `src/coreaction.rs`, `src/funcdata.rs`, `src/printc.rs`, `src/action.rs`, `docs/TODO_BOARD.md`

---

## 1. 代码变更与迭代

### ActionInferParams (新增)
- **位置**: `src/coreaction.rs` `ActionInferParams`
- **参数检测**: 扫描 `obank.alivelist` 中所有 op 的输入 varnodes，识别标记为 INPUT 且位于 SysV AMD64 ABI 参数寄存器（RDI→RSI→RDX→RCX→R8→R9）的 varnodes。按 ABI 顺序排序后，构建连续的 `ProtoParameter` 列表（在第一个 gap 处停止）。
- **返回类型推断**: 扫描 `CPUI_RETURN` ops，检查 `input[1]` 是否为 RAX（offset 0x00）。若是，从 varnode 的 `v_type`（如果经过类型推断）或按 size 推断的默认类型作为函数返回类型。仅在当前返回类型为 `void` 时更新。

### Funcdata.funcp (新增字段)
- **位置**: `src/funcdata.rs`
- 新增 `funcp: FuncProto` 字段，初始化为 `void funcname()`。
- `ActionInferParams` 填充此字段，`PrintC::doc_function` 消费此字段。

### PrintC 函数头部升级
- **位置**: `src/printc.rs` lines 1117-1146
- `main` 函数保持特殊处理：`int main(int argc, char **argv)`
- 其他函数：从 `fd.funcp.return_type` 取返回类型名，从 `fd.funcp.parameters` 遍历参数，发射 `type param_1, type param_2, ...`

### Pipeline 注册
- **位置**: `src/action.rs`
- `ActionInferParams` 注册在 `ActionTypeInfer` 之后、`ActionBlockStructure` 之前，确保参数类型可以受益于推断引擎的结果。

---

## 2. 测试结果

- 新增 `test_infer_params_and_return_type`：验证 2 个 ABI 参数（RDI、RSI）检测 + RAX 返回类型推断
- **全部 166 测试通过，0 失败，0 警告**

---

## 3. 下一步

- 探索结构体（Struct）成员和偏移量的类型传播恢复方案
- 推进函数级快照对齐验证
- 数组索引表示法：`*(ptr + offset)` → `ptr[idx]`

## analysis/type_infer.rs

ActionTypePropagate 的实现，包含两个阶段：

### Phase 1-4: 结构体指针检测
保守地标记 varnode 为 `_struct *`（基于 >=2 个不同小偏移的 INT_ADD→LOAD/STORE 模式）。通过 COPY 链传播。

### Phase 5: LOAD 输出类型推断（2026-06-28 新增）
`propagate_load_output_types(fd)`——忠实移植 Ghidra `TypeOp::propagateFromPointer`（typeop.cc:206）。

当 LOAD 的地址输入是指针类型 `Pointer(ptr_to=T)`，且 T 的 size 匹配 LOAD 输出 size 时，将输出 varnode 的类型设为 T（元素类型），而非指针。同时通过 COPY 链追溯原始指针类型。更新 vn.v_type 和 high.v_type。

**效果**：修复 `piVar92 = *(int*)piVar91` 被错误标记为指针的根因——LOAD 结果应是 int（元素类型），不是指针。

**限制**：当前为单 pass。完整效果需要多轮迭代传播（Ghidra 的 ActionInferTypes 循环到收敛），未来工作。

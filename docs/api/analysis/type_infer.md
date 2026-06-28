## analysis/type_infer.rs

ActionTypePropagate 实现：多轮迭代类型传播 + 结构体指针检测 + LOAD 输出推断。

### 执行顺序
1. Phase 1-4: 结构体指针检测（标记 `_struct*`）
2. Phase 5: LOAD 输出推断（单 pass）
3. Phase 6: 迭代类型传播（7轮到收敛）

### 迭代类型传播规则
`propagate_one_round(fd) -> bool`——每轮处理 propagateType：
- **COPY**：传递输入类型到输出
- **LOAD**：元素类型推断（force_override=true，可覆盖错误指针标记）
- **INT_ZEXT/INT_SEXT**：指针 widening
- **INT_ADD**：ptr+const→ptr（propagateAddPointer cc:1268）
- **INT_SUB**：ptr-const→ptr

收敛判定：只有类型**名称**实际变化才算 changed（防止 Arc identity 振荡）。

### 已知限制
piVar92=*(int*)(piVar89+0x128) 仍显示 int* —— printc 的 pointer_type_for（pointer_varnodes 注册表）在 var_prefix 中优先于 type_infer 的 v_type。消除 reconcile 需调整 printc 的类型优先级。

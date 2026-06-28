## analysis/type_infer.rs

ActionTypePropagate：多轮迭代类型传播 + 结构体指针检测 + LOAD 输出推断。

### 执行顺序
1. Phase 1-4: 结构体指针检测
2. Phase 5: LOAD 输出推断（单 pass）
3. Phase 6: 迭代类型传播（7轮到收敛）

### 迭代传播规则
COPY/LOAD(force_override)/INT_ZEXT/INT_SEXT/INT_ADD/INT_SUB。

### void 指针推断（2026-06-28）
当指针的 ptr_to size==0（void/unknown struct），从 LOAD 输出 size 推断元素类型（4→int, 8→long）。

### 已知限制
piVar92=*(int*)(piVar89+0x128) 仍显示 int* —— 变量名在声明阶段生成，使用不同的类型查找路径。

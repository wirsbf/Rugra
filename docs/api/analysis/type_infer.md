## analysis/type_infer.rs

ActionTypePropagate 实现：多轮迭代类型传播 + 结构体指针检测 + LOAD 输出推断。

### 多轮迭代类型传播
`propagate_one_round(fd) -> bool`——忠实移植 Ghidra ActionInferTypes::apply（coreaction.cc:5374-5416）。最多 7 轮迭代到收敛。

每轮的 propagateType 规则：
- **COPY**：传递输入类型到输出（cc:411）
- **LOAD**：从指针地址推断元素类型（propagateFromPointer cc:206）
- **INT_ZEXT/INT_SEXT**：通过 widening 传播指针类型
- **INT_ADD**（2026-06-28 新增）：指针算术传播（propagateAddPointer cc:1268）。ptr+const→输出继承指针类型；ptr+INT_MULT(var,const)→数组索引传播；ptr+ptr→不传播
- **INT_SUB**（2026-06-28 新增）：ptr-const→输出继承指针类型

更新 vn.v_type 和 high.v_type。

### Phase 1-4: 结构体指针检测
保守标记 `_struct *`（>=2 个不同小偏移）。

### Phase 5: LOAD 输出类型推断
单 pass LOAD 元素类型推断。

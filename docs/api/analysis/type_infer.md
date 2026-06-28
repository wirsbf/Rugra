## analysis/type_infer.rs

ActionTypePropagate 实现，包含多轮迭代类型传播 + 结构体指针检测 + LOAD 输出推断。

### 多轮迭代类型传播（2026-06-28 新增）
`propagate_one_round(fd) -> bool`——忠实移植 Ghidra ActionInferTypes::apply（coreaction.cc:5374-5416）的核心循环。最多 7 轮迭代到收敛。

每轮处理所有 op 的 propagateType 规则：
- **COPY**：传递输入类型到输出（TypeOpCopy::propagateType cc:411）
- **LOAD**：从指针地址推断元素类型（propagateFromPointer cc:206）
- **INT_ZEXT/INT_SEXT**：通过 widening 传播指针类型

更新 vn.v_type 和 high.v_type。只升级 Unknown→known 或同 metatype 变更。

**限制**：INT_ADD 指针算术传播（propagateAddIn2Out cc:1215）未实现——需要 TypeFactory downChain 支持。这是 piVar92 仍显示为指针的原因（INT_ADD 输出的指针类型未传播）。

### Phase 1-4: 结构体指针检测
保守地标记 varnode 为 `_struct *`（基于 >=2 个不同小偏移的 INT_ADD→LOAD/STORE 模式）。

### Phase 5: LOAD 输出类型推断
`propagate_load_output_types(fd)`——单 pass 的 LOAD 元素类型推断，通过 COPY 链追溯。

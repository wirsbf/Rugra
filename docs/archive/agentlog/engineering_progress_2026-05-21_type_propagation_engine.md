# Engineering Progress: Iterative Type Propagation Engine & Verification

## 会话元信息 (Session Meta)
- **日期时间**: 2026-05-21 01:05
- **核心意图**: 重构类型推断算法（ActionTypeInfer）为基于固定点迭代的数据流传播模型，修复 `test_type_propagation` 单元测试中的类型断言失败。
- **触及模块**: `src/coreaction.rs`, `src/funcdata.rs`

---

## 1. 代码变更与迭代 (Progress & Code Changes)
- **多趟迭代数据流传播**: 重构了 [src/coreaction.rs](file:///d:/ghidra/rugra/src/coreaction.rs) 中的 `ActionTypeInfer::apply`。限制了直接给所有变量硬编码推导 size 默认类型的单趟粗暴做法，将其重构为迭代收敛的指针强类型传播，最大迭代次数上限设为 100 次（检测无状态变动后提前 break 收敛）。
- **五大推断与传播规则实现**:
  1. **Opcode 驱动基础规则 (Rule 1)**: 用于推导比较（`CPUI_INT_EQUAL`等）与逻辑/布尔运算输出为 `bool`。
  2. **COPY 传播规则 (Rule 2)**: 保证强类型（如指针类型）能沿 COPY 语义前向、后向双向流动。
  3. **指针算术规则 (Rule 3)**: 重构对 `CPUI_INT_ADD` / `CPUI_INT_SUB` 的推导，支持从基址指针（Pointer）传播到算术偏移输出，并智能处理反向传播（若输出是已知 Pointer，推断基址也是 Pointer）。
  4. **Phi 节点 (Rule 4)**: 实现对 `CPUI_MULTIEQUAL` 的多输入与输出类型一致性强制合并流动。
  5. **内存解引用规则 (Rule 5)**: 对 `CPUI_LOAD` 与 `CPUI_STORE` 实现解引用关系推导。若地址是 `T *`，LOAD 目标即为 `T`，若 LOAD 目标是 `T`，反向推断地址是 `T *`；对 STORE 也对称处理。
- **后置兜底推断 (Post-pass Fallback)**: 在所有强类型固定点迭代流传播完毕后，对剩余所有仍无任何类型的 Varnode 运行后置 size 匹配，根据 size 兜底赋予整型（`byte` / `short` / `int` / `long`）。
- **测试框架更新**: 重构并修复了 [src/funcdata.rs](file:///d:/ghidra/rugra/src/funcdata.rs) 中的 `test_type_propagation`。由于 `inject_raw_ops` 注入裸 Pcode 序列时在 SSA renaming 前未进行变量去重，测试中通过前端手工合并数据流中同名变量（ deduplicate/link ）来连接 SSA 链路，并直接断言 PcodeOps 关键结点的 inputs / outputs 类型。

---

## 2. 架构推进与一致性审计 (Architecture & Alignment Audit)
- **单元测试验证**:
  - `test_type_propagation` 单元测试在强类型双向传播与 fallback 下完美运行通过。
  - 项目全局 163 个单元测试全部通过。
- **与 Ghidra 对齐情况**:
  - 该迭代固定点数据流模型与 Ghidra 的 ActionTypeInfer 处理机制高度契合。实现了由粗糙的一阶段 size 判断向多阶段指针/复合类型流动的重大升级，极大提升了对反编译 C 源码类型恢复的准确度。

---

## 3. 下一步干涉计划 (Next Steps / Blockers)
- 结合类型恢复引擎开始在高层 C 代码发射（PrintC）中处理必要的类型转换（Type Casts）打印逻辑。
- 探索结构体（Struct）成员和偏移量的类型传播恢复方案。

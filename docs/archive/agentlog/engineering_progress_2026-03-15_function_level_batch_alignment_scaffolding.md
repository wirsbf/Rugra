# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-15  
**核心意图 / Core Intent:** 为 Rugra 建立“函数级批量语义对齐”所需的第一版语义快照骨架，使后续能够按函数而不是单条指令批量对比 Rugra 与 Ghidra 的语义实现。  
**触及模块 / Touched Modules:** `src/align/function_snapshot.rs`、`src/align/mod.rs`、`src/lib.rs`

---

## 1. 代码变更与迭代 (Progress & Code Changes)

本次会话不再继续围绕单条 `mov` / `add` 指令做局部打补丁式推进，而是按新的工程目标转向：

> 先搭建**函数级批量语义对齐基础设施**，让 Rugra 能够把单个函数导出成结构化语义快照，后续再与 Ghidra 对应函数做批量比较。

这一步的意义在于，把“对齐”从零散的样本测试，升级成未来可扩展的**函数级对齐工作流骨架**。

### 1.1 新增函数级语义快照模块

本次新增：

- `src/align/function_snapshot.rs`

该模块当前承担的不是“验证已经完成”的职责，而是定义未来批量对齐所需的**统一数据结构与导出入口**。

核心新增类型包括：

- `FunctionSemanticSnapshot`
- `FunctionIdentitySnapshot`
- `FunctionSummarySnapshot`
- `PcodeSnapshot`
- `PcodeOpSnapshot`
- `CfgSnapshot`
- `BasicBlockSnapshot`
- `SsaSnapshot`
- `SsaVarnodeSnapshot`
- `VarnodeSnapshot`
- `SnapshotSemanticLayer`
- `FunctionSemanticMismatch`
- `FunctionSemanticCompareResult`
- `BatchSemanticCompareReport`

这些结构的共同目标是：

1. 让 Rugra 侧先能稳定导出单函数语义摘要
2. 为未来 Ghidra 侧导出建立对接格式
3. 为未来批量 compare / report / mismatch triage 提供统一承载体

### 1.2 实现 `Funcdata -> FunctionSemanticSnapshot` 导出入口

本次已实现：

- `FunctionSemanticSnapshot::from_funcdata(&Funcdata)`

该入口会从当前 `Funcdata` 中提取三层核心语义：

#### A. P-code 层

当前会导出：

- 每条 op 的 `SeqNum`
- opcode
- output
- inputs

这意味着未来函数级比对不再只能停留在“有几条 op”，而是可以进一步比较：

- op 顺序
- opcode 序列
- 输入输出形态
- 同一机器指令下多条 op 的组织方式

#### B. CFG 层

当前会导出：

- basic block index
- block start address
- block 内 op 序列号
- successors
- predecessors

这为未来批量分析如下问题提供基础：

- block 数量是否一致
- block 边关系是否一致
- block 起始点是否一致
- 某个函数究竟是在 P-code 层还是 CFG 层开始偏离

#### C. SSA / varnode 层

当前会导出：

- varnode 的 `space / offset / size`
- version
- 是否 input
- 是否 written
- defining op
- uses

这意味着未来函数级对齐不再只能说“SSA 好像不太对”，而可以按函数明确地比较：

- version 分配
- defining op 分布
- use 链摘要
- 某些变量节点的 input / written 角色差异

### 1.3 增加批量 compare 结果骨架

本次还加入了两层结果结构：

- `FunctionSemanticCompareResult`
- `BatchSemanticCompareReport`

它们目前主要提供：

- 单函数 matched / mismatched 结果承载
- mismatch 列表
- 批量函数统计
- 按 semantic layer 聚合 mismatch 的基础接口

换句话说，即使当前还没有真正接上 Ghidra 侧导出，Rugra 这边已经开始具备了未来批量结果汇总所需的形状。

### 1.4 接入对齐模块与库入口

为了让新模块能进入当前主线结构，本次还同步修改了：

- `src/align/mod.rs`
- `src/lib.rs`

当前状态为：

- `align::function_snapshot` 已进入 `align` 子模块体系
- 主库入口已经回到更合理的模块暴露状态
- 没有把该模块伪装成“已经完成函数对齐”的高层产品接口

### 1.5 修复新模块与当前真实 API 的适配问题

在落地新模块过程中，本次还针对当前仓库真实结构做了适配修正，包括：

- 使用当前 `FlowBlock` 接口收集 block 输入/输出边，而不是假设存在不存在的 helper API
- 使用当前 `VarnodeBank` 的 `begin_loc()` / `begin_def()` 迭代路径，而不是假设存在统一 `varnode_list`
- 调整排序与去重逻辑，避免依赖当前工程里没有实现 `Ord` 的类型
- 统一从现有 `Funcdata / Block / Varnode / PcodeOp` 真实接口提取信息，保证骨架建立在当前可见代码之上

这些修正的价值在于：

> 新增骨架并不是“想象中的未来架构”，而是**基于当前仓库真实可编译主线**落地的。

---

## 2. 架构推进与一致性审计 (Architecture & Alignment Audit)

### 2.1 为什么本次从“单指令对拍”转向“函数级骨架”

前序会话已经反复暴露出一个核心问题：

- 单指令样本有价值
- 但如果参考侧还不是独立 Ghidra 结构化结果
- 那么继续在极小样本上死抠，很容易陷入：
  - 自比较
  - 假差异
  - 口径错位
  - 结果不可推广

因此本次工作明确转向：

- 先搭起函数级语义导出骨架
- 让对齐目标从“某条 op 看起来像不像”
- 升级成“整个函数在 P-code / CFG / SSA 层如何被摘要和比较”

这一步更符合你当前提出的工程方向：

> 批量按函数对齐 Ghidra，而不是无限停留在单条指令上。

### 2.2 当前这一步真正解决了什么

本次并没有解决以下事情：

- 没有证明 Rugra 当前与 Ghidra 函数级一致
- 没有完成 Ghidra 侧函数语义导出
- 没有建立真实双边批量 compare
- 没有形成完整的批量函数对齐闭环

但本次已经真正解决了一个关键前置问题：

> **Rugra 侧现在开始有“函数级统一语义快照格式”了。**

这是后续一切批量函数对齐工作的前提。

如果没有这一步，后续每次谈“批量对齐函数”都会重新陷入：

- 到底导出什么
- 到底怎么比
- 到底哪些层算 mismatch
- 到底怎么做批量统计

现在这些最基础的问题已经有了第一版工程答案。

### 2.3 当前可确认的事实

本次会话后，可以确认以下事实：

- 仓库中已新增函数级语义快照模块 `src/align/function_snapshot.rs`
- Rugra 侧已经可以从 `Funcdata` 导出函数级语义快照
- 快照当前覆盖：
  - function metadata
  - P-code
  - CFG
  - SSA / varnode 摘要
- 已存在批量比较结果结构骨架
- 新模块已完成最基础的编译与测试落地
- 当前模块是“批量对齐基础设施”，不是“已完成函数级对齐”的证明

### 2.4 当前仍然不能宣称的内容

本次会话后，以下内容仍然不能写成已完成事实：

- 不能宣称 Rugra 已实现函数级批量对齐 Ghidra
- 不能宣称每个函数的语义实现已经与 Ghidra 一样
- 不能宣称当前函数级快照已经与 Ghidra 侧存在稳定一一映射
- 不能宣称当前已具备真实、完整、可规模化运行的 Rugra ↔ Ghidra 批量 compare 流程
- 不能宣称 `function_snapshot.rs` 本身就是验证证据

---

## 3. 测试与验证情况 (Verification & Execution)

### 3.1 本次新增模块的基础测试

本次模块内已落下基础测试，用于验证：

#### A. `test_snapshot_from_funcdata_basic`
验证最小 `Funcdata` 能被导出为：

- 合法的 `FunctionSemanticSnapshot`
- 正确的 schema version
- 正确的 function identity
- 正确的 P-code / CFG / SSA 基础摘要

#### B. `test_batch_report_counts`
验证批量结果对象能正确汇总：

- total functions
- matched functions
- mismatched functions
- match rate

### 3.2 当前可确认的运行结论

按本次会话中的实际编译与测试推进，可以确认：

- `function_snapshot` 模块在当前主线下已能通过其基础测试
- 至少说明：
  - Rugra 侧函数快照骨架已落地
  - 批量报告骨架已具备最小可运行性

### 3.3 这些测试不代表什么

这些测试**不代表**：

- Ghidra 对齐已经完成
- 快照语义已经与 Ghidra 完全一致
- 当前批量 compare 已经具备真实参考侧
- 函数级 parity 已经建立

它们只代表：

- Rugra 侧的函数级批量对齐基础设施，已经从“设计想法”推进成“可编译、可测试的代码骨架”

---

## 4. 证据来源 (Evidence Sources)

本次日志结论主要依据以下可见证据：

### 源码证据

- `src/align/function_snapshot.rs`
  - 新增函数级语义快照结构
  - `FunctionSemanticSnapshot::from_funcdata(...)`
  - 批量 compare 结果结构
  - 基础测试
- `src/align/mod.rs`
  - 新模块纳入 `align` 主线
- `src/lib.rs`
  - 主库入口对模块暴露的调整

### 编译 / 测试证据

- 围绕 `function_snapshot` 相关测试的编译与执行结果
- 可确认最小模块测试已能通过

### 工程上下文证据

- 前序最小样本对拍记录已经暴露：
  - 单指令路线不足以直接支撑“函数级语义一致”
  - 因此需要更高层的函数级语义摘要骨架

---

## 5. 当前判断 (Current Assessment)

### 5.1 本次已经达成的推进

本次已经达成：

- 从“单指令局部验证”正式向“函数级批量对齐基础设施”转向
- Rugra 侧已具备第一版函数级语义快照格式
- P-code / CFG / SSA 三层已进入统一导出结构
- 批量 compare 结果结构已具备第一版骨架
- 新模块已在当前主线下完成基础测试落地

### 5.2 本次尚未达成的目标

本次尚未达成：

- Ghidra 侧函数级语义快照导出
- Rugra ↔ Ghidra 的真实函数级比较器
- 面向一批真实函数的批量运行器
- 可归档的批量函数差异报告
- “每个函数语义实现一样”的真实验证证据

---

## 6. 下一步干涉计划 (Next Steps / Blockers)

### 6.1 下一步最高优先级

现在最值得直接推进的，是把当前骨架补成**可批量跑的 Rugra 侧入口**。建议顺序如下：

1. 为 `function_snapshot` 增加更明确的导出入口
   - 例如导出单函数 JSON
   - 或构造一批函数 snapshot 的 runner
2. 设计 Ghidra 侧对应的函数语义导出格式
   - 保持字段尽量对齐当前 Rugra snapshot
3. 定义第一版函数级 compare 规则
   - 哪些字段必须严格一致
   - 哪些字段暂时只做摘要比较
   - 哪些层先比较，哪些层后比较

### 6.2 第二优先级

在有了单函数与批量导出骨架后，下一步应补：

- 真实样本函数集
- 批量 compare runner
- mismatch 分类策略

也就是让后续能输出类似：

- 哪些函数在 P-code 层失败
- 哪些函数在 CFG 层失败
- 哪些函数在 SSA 层失败
- 哪些函数只在高层摘要上失败

### 6.3 与当前最小样本工作的关系

前序的最小样本工作并没有失效，但它们现在更应该被定位成：

- **局部验证探针**
- 而不是未来批量函数对齐的最终形态

后续更合理的关系是：

- 单指令样本：用于定位底层 lifting / op 级问题
- 函数级 snapshot：用于批量对齐与批量归因
- 两者相互补充，而不是互相替代

### 6.4 当前主要阻塞点

当前最主要的阻塞点包括：

- 还没有 Ghidra 侧对应 snapshot 导出
- 还没有真实的函数级 compare 逻辑
- 还没有批量 runner
- 还没有首批函数语义对齐报告模板

---

## 7. 本次会话结论 (Session Conclusion)

一句话总结本次工作：

> 本次会话已把 Rugra 的对齐工作从“单指令局部验证”推进到“函数级批量语义对齐骨架”阶段：  
> 新增了 `function_snapshot.rs`，使 Rugra 侧已经能够按函数导出 P-code / CFG / SSA 三层语义快照，为后续真正按函数批量对齐 Ghidra 奠定了第一版结构基础。
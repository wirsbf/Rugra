# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-15  
**核心意图 / Core Intent:** 在 `function_snapshot` 语义快照骨架之上，继续推进 Rugra 侧的**函数级批量 compare runner**，让函数快照不再只是“可导出”，而开始具备“可比较、可批量汇总、可记录缺失项”的最小执行能力。  
**触及模块 / Touched Modules:** `src/align/function_snapshot.rs`、`docs/api/align/function_snapshot.md`、`docs/TODO_BOARD.md`

---

## 1. 本次推进摘要 (What advanced this session)

本次工作没有去宣称“函数级 Rugra ↔ Ghidra 对齐已完成”，而是继续沿着上次建立的 `function_snapshot.rs` 骨架往前推进了一层：

> 从“能导出 Rugra 侧函数语义快照”，推进到“能对两侧快照做最小批量比较并形成结果报告”。

换句话说，这次的核心价值不是新增更多快照字段，而是让已有快照开始进入**真正可消费的 compare / report 流程**。

本次推进后，`function_snapshot` 模块新增了以下能力：

1. **单函数快照 compare 入口**
2. **按函数入口地址配对的批量 compare runner**
3. **缺失 Rugra / 缺失 reference 函数快照的差异记录**
4. **覆盖 compare runner 的基础测试**

这使得当前模块从：

- 结构定义层
- Rugra 侧导出层

进一步变成了：

- **Rugra 侧导出 + 最小批量 compare 执行层**

---

## 2. 代码层推进 (Code Changes)

### 2.1 为单函数比较补正式入口

本次在 `FunctionSemanticCompareResult` 上补充了：

- `compare(rugra: &FunctionSemanticSnapshot, reference: &FunctionSemanticSnapshot) -> Self`

并在模块级补充了更直接的公开辅助入口：

- `compare_function_snapshots(...)`

这一步的意义是把“两个函数快照怎么比”从调用方散落逻辑，收敛成模块内统一规则。

当前比较逻辑仍然是**第一版粗粒度 compare**，主要对以下层进行判定：

- `schema_version`
- `function` 元信息
- `summary`
- `pcode`
- `cfg`
- `ssa`

如果这些层中有任一层不同，就会生成 `FunctionSemanticMismatch`，并带上：

- `function_entry`
- `function_name`
- `layer`
- `code`
- `details`

这意味着当前已经可以按函数输出类似下面这种分层结果：

- `Function` 层 mismatch
- `Pcode` 层 mismatch
- `Cfg` 层 mismatch
- `Ssa` 层 mismatch

虽然现在的 `details` 仍然偏摘要化，但相比“只有一个 bool”已经前进了一大步。

---

### 2.2 为批量 compare 增加 runner

本次新增了模块级批量入口：

- `compare_snapshot_batches(...) -> BatchSemanticCompareReport`

这是本次最核心的推进点。

当前 runner 的行为是：

1. 把 Rugra 侧函数快照按 `function.entry` 建索引
2. 把 reference 侧函数快照按 `function.entry` 建索引
3. 取两边 entry 的并集
4. 逐 entry 做以下三类处理：
   - 两边都存在：执行 `compare_function_snapshots(...)`
   - 只有 Rugra 存在：生成 `missing_reference_function`
   - 只有 reference 存在：生成 `missing_rugra_function`
5. 把所有逐函数结果汇总为 `BatchSemanticCompareReport`

这一步的工程意义非常直接：

> `function_snapshot.rs` 终于不只是“未来某天可比”，而是已经具备了“今天就能把两批快照拉进来并出报告”的最小 runner。

---

### 2.3 把“缺失函数”纳入正式差异模型

在批量 compare 里，最常见的一类现实问题不是“函数内容有差异”，而是：

- 一边有这个函数
- 另一边根本没有导出到

如果这种情况不进入正式 mismatch 结构，批量 compare 结果就会非常失真。

因此本次明确把这两类情况纳入 `FunctionSemanticMismatch`：

- `missing_reference_function`
- `missing_rugra_function`

并统一归到：

- `SnapshotSemanticLayer::Function`

这样一来，当前批量报告已经可以明确区分：

- “函数找到了，但语义层不同”
- “函数本身在另一侧就没出现”

这对后续接真实 Ghidra 侧导出非常重要，因为第一轮真实对接几乎必然会遇到大量“配对不上”的函数。

---

### 2.4 增加 compare runner 相关测试

为了避免这次推进只停留在结构层，本次补了几类最小测试：

#### A. `test_compare_function_snapshots_match`
验证相同快照进行 compare 时会得到：

- `matched = true`
- `mismatches.is_empty()`

#### B. `test_compare_function_snapshots_detects_layered_mismatches`
验证当 `schema / function / pcode / cfg / ssa` 都存在差异时，结果中能正确出现对应层级的 mismatch。

#### C. `test_compare_snapshot_batches_reports_missing_entries`
验证当一边只有 Rugra 快照、另一边只有 reference 快照时，batch runner 会正确报告：

- `missing_reference_function`
- `missing_rugra_function`

这些测试的价值在于，它们证明了本次新增的 compare runner 不是空壳，而是已经具备最小可执行性。

---

## 3. 当前 compare 规则的真实边界 (Current Comparison Boundary)

本次虽然已经把 compare runner 补上，但必须明确当前规则仍然是**第一版粗粒度 compare**。

### 3.1 当前已经做到的
当前已经能够：

- 按函数入口地址配对快照
- 比较函数元信息
- 比较 summary
- 比较整个 `pcode` 快照对象
- 比较整个 `cfg` 快照对象
- 比较整个 `ssa` 快照对象
- 把差异按层归类
- 对缺失函数做批量记录
- 输出统一的 `BatchSemanticCompareReport`

### 3.2 当前还没做到的
当前还没有做到：

- P-code 层逐 op 精细差异定位
- CFG 层逐 block / edge 细粒度差异归因
- SSA 层逐 varnode / version / def-use 的细粒度 mismatch 归因
- 名称别名、排序抖动、临时 unique 等“可容忍差异”的策略化处理
- Ghidra 侧真实导出接入
- 大规模 corpus 批跑验证

因此当前最准确的描述是：

> Rugra 已具备函数快照的最小 compare runner，但这仍是**第一版批量比对基础设施**，不是成熟的函数语义 parity 系统。

---

## 4. 为什么这一步重要 (Why this matters)

上一阶段完成的是：

- `Funcdata -> FunctionSemanticSnapshot`
- JSON 导入导出
- 批量报告骨架

但如果没有 compare runner，模块始终还停留在：

- “数据格式已经有了”
- “以后可以拿来比”

这次推进的关键意义在于把它变成：

- “现在就可以实际比较两批快照并出报告”

这带来几个立刻可见的收益：

### 4.1 为 Ghidra 侧接入预留了稳定落点
后续只要 Ghidra 侧能导出兼容快照，当前 Rugra 侧已经有：

- 配对逻辑
- 比较入口
- 报告对象
- 缺失项处理

无需再从零搭 compare 框架。

### 4.2 为工程日志和 TODO 提供可执行对象
后续不再只能写：

- “需要做函数级对齐”

而可以写成更可执行的任务：

- 细化 `compare_snapshot_batches(...)` 的层内差异粒度
- 为 P-code 层补逐 op mismatch
- 为 CFG 层补 block-level mismatch
- 为 SSA 层补 version / defining_op / uses 的分项 compare

### 4.3 为批量报告建立真实入口
`BatchSemanticCompareReport` 现在不再只是一个“理论上会被使用的结构”，而已经有了明确生产路径。

---

## 5. 与 `add rax, 1` 最小失败样本的关系

本次工作没有直接修复：

- `add rax, 1` 中参考 opcode 来源错误
- unique 临时值输入的比较策略

这些问题仍然是当前最小 P-code 对拍链路上的真实阻塞点。

但本次函数级 compare runner 的推进，与那个最小失败样本并不冲突，反而形成了两个互补层级：

### 局部层
继续用 `mov` / `add` / `sub` 这类最小样本做：

- lifting 粒度问题定位
- opcode / varnode / unique 输入问题定位

### 函数层
用 `function_snapshot` compare runner 做：

- 批量函数级摘要比较
- 差异按层归因
- 缺失函数统计
- 后续 Ghidra 导出接入

这意味着当前工程不再只押注在某一条局部路径上，而是同时推进：

- **局部语义问题定位**
- **函数级批量对齐框架**

---

## 6. 文档同步情况 (Documentation Sync)

根据仓库要求，本次代码推进同步更新了相关文档：

### 6.1 `docs/api/align/function_snapshot.md`
已补充说明：

- 新增 `compare_function_snapshots(...)`
- 新增 `compare_snapshot_batches(...)`
- 模块已经从“快照导出层”推进到“快照导出 + 最小 compare runner”

并明确强调：

- 当前 compare runner 仍然是 Rugra 侧基础设施
- 这不是对真实 Ghidra parity 的证明
- 后续仍需 Ghidra 侧导出接入与差异粒度细化

### 6.2 `docs/TODO_BOARD.md`
已把函数级快照相关任务状态从：

- “下一步补批量 runner”

推进为：

- 已补单函数 compare 入口
- 已补按 entry 配对的 batch compare runner
- 已补缺失 Rugra / reference 快照的批量差异记录
- 下一步继续细化各语义层 mismatch 粒度

这样看板已经能正确反映当前进展，而不是继续停留在上一次状态。

---

## 7. 当前可确认的事实 (Verified Current State)

本次会话后，可以基于当前代码状态确认以下事实：

- `src/align/function_snapshot.rs` 已具备单函数 compare 入口
- 已具备按函数入口地址配对的批量 compare runner
- 已具备缺失 reference / 缺失 Rugra 快照的差异记录
- compare 结果仍统一落入 `FunctionSemanticCompareResult` 与 `BatchSemanticCompareReport`
- 模块内已补对应基础测试
- 文档与 TODO 已同步更新

这些都属于**当前仓库可见代码与测试层面可支撑的事实**。

---

## 8. 当前仍然不能宣称的内容 (What still must not be claimed)

本次推进后，以下内容仍然不能写成既成事实：

- 不能宣称 Rugra 已完成函数级批量对齐 Ghidra
- 不能宣称当前 compare runner 已具备生产级差异分析能力
- 不能宣称当前 `FunctionSemanticSnapshot` 已和 Ghidra 导出格式稳定一一对应
- 不能宣称当前 batch compare 结果已经代表真实 Ghidra 对拍结论
- 不能宣称函数级语义 parity 已经建立

最准确的说法仍然应该是：

> Rugra 已经拥有**函数级语义快照 + 最小批量 compare runner** 的基础设施，但真实 Rugra ↔ Ghidra 批量语义对拍仍需 Ghidra 侧导出接入与 compare 粒度继续细化。

---

## 9. 下一步最合理的工程方向 (Next Recommended Steps)

基于本次推进，后续最自然的下一步是：

### 9.1 继续细化 compare 规则
优先把当前粗粒度 mismatch 细化成更可排障的层内差异：

- P-code：逐 op / seq / opcode / input / output
- CFG：逐 block / edge / start / op membership
- SSA：逐 varnode / version / defining_op / uses

### 9.2 设计 Ghidra 侧快照导出约定
既然 Rugra 侧 runner 已有，下一层就应明确：

- Ghidra 侧 schema 对应关系
- 字段命名与兼容策略
- 如何处理唯一空间、版本、块索引、函数命名差异

### 9.3 把 compare runner 接入批量导入导出流程
让使用路径从“库内 helper”进一步推进到：

- 读取 Rugra 快照 JSON
- 读取 reference 快照 JSON
- 生成 `BatchSemanticCompareReport`
- 输出 JSON 报告

### 9.4 并行继续保留 `add rax, 1` 失败样本
函数级批量框架继续推进的同时，局部最小失败样本仍然非常重要，尤其是：

- 参考 opcode 来源错误
- unique 输入 compare 策略

这两个问题仍然是局部语义对拍链路的直接阻塞点。

---

## 10. 本次会话结论 (Session Conclusion)

本次推进最准确的一句话总结是：

> Rugra 已经把 `function_snapshot` 从“函数级语义快照导出骨架”推进成“函数级语义快照导出 + 最小批量 compare runner”的基础设施模块，并开始具备按函数入口配对、生成批量比较报告、记录缺失函数差异的实际能力。

这一步没有完成 Ghidra 对齐本身，但它把后续真正的函数级批量对齐所需要的**执行框架地基**又往前推进了一层。
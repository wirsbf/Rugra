# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-15  
**核心意图 / Core Intent:** 将最小样本 `mov rbx, rax` 的 P-code 验证从“框架级真实运行记录”推进到“带结构化本地比较与真实输入传递的局部验证记录”。  
**触及模块 / Touched Modules:** `src/align/runtime_verify.rs`

---

## 1. 代码变更与迭代 (Progress & Code Changes)

本次会话聚焦于上一条最小样本记录留下的直接缺口：`verify_pcode_generation(...)` 虽然已经能够真实执行，但仍然存在“比较参数不完整、结果总是返回 `Match`”的问题。

### 1.1 修正 P-code 比较入口的输入传递

此前 `verify_pcode_generation(...)` 在调用比较入口时，虽然已经改为传入真实 opcode 和真实 output，但 input 仍然只传入：

- `input_count`
- `null inputs pointer`

这意味着比较层即使知道“有几个输入”，也拿不到输入 varnode 的真实内容。

本次修改后，`verify_pcode_generation(...)` 已为每个 Rugra `PcodeOp` 显式构造完整的输入列表：

- `space_id`
- `offset`
- `size`

并将其作为 `VarnodeFFI` 数组传入比较入口。这样，最小样本 `mov rbx, rax` 的单输入寄存器 `rax` 不再只是“数量正确”，而是具备了真实的结构化输入数据。

### 1.2 在运行时验证层补入结构化本地比较

此前该函数主要依赖比较入口的副作用日志，自己并不真正消费结构化比较结果，因此行为上仍然更接近：

- 调用比较入口
- 打印日志
- 最后直接返回 `VerifyResult::Match`

本次修改后，`runtime_verify.rs` 额外引入了 `align::pcodeop::verify_operation(...)`，在 Rugra 本地侧对每条 op 做结构化核对，检查内容包括：

1. opcode
2. SeqNum / 地址
3. 输入个数
4. 输入 varnode 明细
5. 输出 varnode 明细

虽然这里使用的“参考侧数据”仍是当前传入比较层的局部结构，而不是真正来自 Ghidra 的独立结构化返回值，但它至少把验证逻辑从“纯 stdout 副作用”推进到了“可生成结构化布尔判定”。

### 1.3 `verify_pcode_generation(...)` 不再无条件返回 `Match`

本次会话前的关键问题之一是：

- 即使比较入口打印出 mismatch
- `verify_pcode_generation(...)` 仍然固定返回 `VerifyResult::Match`

这会让调用方把“框架被触发”和“验证真的通过”混淆在一起。

本次修改后，该函数会：

- 在 op 数量不一致时直接返回 `VerifyResult::Mismatch(...)`
- 在逐 op 的结构化核对发现失败时收集 mismatch 详情
- 只有当所有 op 的结构化核对都通过时，才返回 `VerifyResult::Match`

也就是说，返回值现在已经具备了最基本的“受比较结果影响”的语义，不再只是占位流程。

### 1.4 mismatch 记录开始进入统一收集路径

本次修改还把逐 op 的结构化失败纳入了既有的 `MismatchRecord` 记录体系。  
当局部 op 校验失败时，会记录：

- `test_name`
- `address`
- Rugra 摘要
- 参考摘要
- details

这使得后续 `generate_report()`、统计信息和进一步样本扩展时，可以复用统一的 mismatch 聚合路径，而不再只依赖控制台日志。

---

## 2. 最小样本推进结果 (Minimal Sample Advancement)

### 2.1 本次推进针对的样本

- **样本 ID**：`PCode-Min-001`
- **目标指令**：`mov rbx, rax`
- **机器码**：`48 89 c3`
- **起始地址**：`0x1000`

### 2.2 本次推进前的状态

上一轮已经确认：

- 该样本可以完成反汇编
- `X86Lifter::lift(...)` 可生成单条 `CPUI_COPY`
- `Funcdata::inject_raw_ops(...)` 可完成注入
- `verify_pcode_generation(...)` 可真实执行
- 比较入口可被触发

但当时仍有明显局限：

1. input 明细没有真正传入比较层
2. 比较结果主要体现为 stdout 日志
3. `verify_pcode_generation(...)` 固定返回 `Match`

### 2.3 本次推进后的状态

本次会话后，可以更准确地描述当前状态为：

- `mov rbx, rax` 的最小验证路径已经具备：
  - 真实 opcode
  - 真实 output varnode
  - 真实 input varnode 列表
- 本地验证逻辑已可执行结构化逐项核对
- `VerifyResult` 已开始受局部结构化比较结果影响
- mismatch 已可进入统一记录路径

因此，这条样本已经从：

- **框架级真实运行记录**

推进到：

- **带结构化本地比较语义的局部验证记录**

---

## 3. 架构推进与一致性审计 (Architecture & Alignment Audit)

### 3.1 本次工作的实际价值

本次工作的价值不在于宣称“`mov rbx, rax` 已与 Ghidra 严格一致”，而在于修复了验证层里最误导人的一段行为：

- 之前的函数会在发生差异时仍然报告 `Match`
- 现在返回值至少开始和结构化比较结果挂钩

这是一次重要的语义校正。  
它让最小样本验证从“看起来像验证系统”更接近“开始真正承担验证职责”。

### 3.2 当前可以确认的事实

本次会话后，可以确认：

- `verify_pcode_generation(...)` 现在会构造真实输入 varnode 列表
- 比较入口调用时不再只传入 `input_count`
- 本地侧已接入 `verify_operation(...)` 进行结构化 op 校验
- P-code mismatch 已开始影响 `VerifyResult`
- mismatch 已纳入统一记录路径

### 3.3 当前仍然不能宣称的内容

即使完成了以上改进，当前仍然**不能**把该样本写成“已通过真正的 Ghidra 局部对拍”，原因包括：

1. 当前结构化核对所使用的参考数据，仍然不是 Ghidra 侧独立返回的结构化结果
2. 比较入口本身仍更偏向日志输出，而非返回可消费的结构化比较对象
3. 现阶段的“结构化比较”更准确地说是：
   - Rugra 本地结构化验证能力增强
   - 而不是完整双边结构化对拍完成

因此目前最准确的口径应是：

> `mov rbx, rax` 已从“带真实运行记录的最小样本”进一步推进为“带真实输入传递与结构化本地比较的局部验证样本”，  
> 但尚未形成真正由 Ghidra 侧独立参考数据驱动的完整局部 parity 结论。

### 3.4 文档同步确认

按仓库规范，只要代码和验证语义发生变化，就不能把收尾留到后续。  
本条日志用于明确记录：

- 本次具体修了什么
- 修到了哪一层
- 还没修到哪一层
- 下次应该从哪里继续推进

避免后续会话把“已开始结构化比较”误写成“已完成 Ghidra 对拍闭环”。

---

## 4. 证据来源 (Evidence Sources)

本次日志结论依据当前可见修改意图与上一轮样本上下文整理，核心证据应回链到以下位置：

### 源码证据
- `src/align/runtime_verify.rs`
  - `verify_pcode_generation(...)`
  - `MismatchRecord`
  - `VerifyResult`
- `src/align/pcodeop.rs`
  - `verify_operation(...)`
- `src/ffi.rs`
  - `VarnodeFFI`
  - `rugra_compare_pcode(...)`

### 样本上下文证据
- 第一条最小样本：`mov rbx, rax`
- 原始字节：`48 89 c3`
- 入口链路：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`

### 前序记录证据
- `docs/AgentLog/engineering_progress_2026-03-15_minimal_mov_pcode_sample.md`

---

## 5. 当前判断 (Current Assessment)

### 5.1 本次已经达成的推进

本次已经完成以下关键升级：

- 从“只传 input_count”升级到“传真实 input varnode 列表”
- 从“比较层只打日志”升级到“本地侧有结构化 op 校验”
- 从“无条件返回 `Match`”升级到“返回值受 mismatch 影响”
- 从“差异主要停留在 stdout”升级到“差异可进入统一记录体系”

### 5.2 本次仍未完成的部分

本次没有解决的关键问题仍然包括：

- 比较入口仍缺少真正可消费的结构化返回结果
- 当前参考侧数据还不是 Ghidra 独立返回的真实结构化 op
- 还没有形成“比较层 -> VerifyResult -> 统一差异报告”的完整双边闭环
- 该样本尚未被提升为“真正的 Ghidra 局部对拍通过记录”

---

## 6. 下一步干涉计划 (Next Steps / Blockers)

### 6.1 下一步最高优先级

接下来最直接的工程切入点是：

1. 让比较入口不再只打印日志，而是返回结构化比较状态
2. 让 `verify_pcode_generation(...)` 消费来自参考侧的独立结果，而不是只基于本地构造数据
3. 将 mismatch 分类进一步细化为：
   - opcode mismatch
   - seq mismatch
   - output mismatch
   - input count mismatch
   - input field mismatch

### 6.2 第二优先级

在 `mov rbx, rax` 这条样本基础上，继续扩展第二批样本：

- `add rax, 1`
- `sub rax, 8`

重点验证：

- 常量输入
- 算术 opcode
- 输入顺序
- 输出回写

### 6.3 文档侧待跟进

后续若继续推进这条最小样本，应同步更新：

- `docs/TODO_BOARD.md`
- `docs/VERIFICATION_GUIDE.md`
- 必要时更新更高层的 `ALIGNMENT_PROGRESS.md`

前提是新的结论必须由真实运行和可复核证据支撑，不能把“结构化本地比较已存在”扩大表述成“已完成 Ghidra 对拍闭环”。

---
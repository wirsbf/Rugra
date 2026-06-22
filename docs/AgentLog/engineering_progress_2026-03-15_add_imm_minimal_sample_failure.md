# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-15  
**核心意图 / Core Intent:** 为第二条最小 P-code 样本 `add rax, 1` 建立首条真实失败记录，明确当前最小局部验证未通过的具体现象、边界与下一步修复方向。  
**触及模块 / Touched Modules:** `src/funcdata.rs`、`src/disasm/x86_64.rs`、`src/disasm/x86_lift.rs`、`src/align/runtime_verify.rs`、`src/ffi.rs`

---

## 1. 代码变更与迭代 (Progress & Code Changes)

本次会话延续前一条 `mov rbx, rax` 最小样本之后的推进路径，把第二条优先样本切换到：

- `add rax, 1`

目标不是一次性完成 Ghidra parity，而是先把这条样本从“计划中的模板项”推进成：

- 已有最小测试
- 已能真实执行
- 已能暴露当前局部比较错位
- 已能为后续修复提供明确切入点

### 1.1 新增最小样本测试

在 `src/funcdata.rs` 的测试模块中新增了：

- `test_add_rax_imm_minimal_alignment_path`

该测试围绕机器码：

- `48 83 c0 01`

验证如下最小链路：

1. 反汇编得到单条 `add`
2. 通过 `X86Lifter::lift(...)` 生成 raw P-code
3. 检查 raw P-code 的 opcode、输入、输出
4. 注入 `Funcdata::inject_raw_ops(...)`
5. 调用 `RuntimeVerifier::verify_pcode_generation(...)`
6. 观察最小样本在当前局部验证链路中的真实结果

### 1.2 当前 Rugra 侧 lifting 结果

按当前可见实现，这条样本在 Rugra 侧被提升为两条 op：

1. `CPUI_INT_ADD`
2. `CPUI_COPY`

这意味着当前 `add rax, 1` 并不是直接被表示为“写回同一寄存器的一条 op”，而是先计算到临时值，再拷回寄存器。

### 1.3 本次测试中已确认的 raw 断言

本次测试围绕以下事实建立了断言：

- 指令文本包含 `rax`
- 指令文本包含立即数 `1`
- `raw_ops.len() == 2`

第一条 raw op：
- opcode = `CPUI_INT_ADD`
- output:
  - `space = Unique`
  - `size = 8`
- inputs:
  - input0:
    - `space = Register`
    - `offset = 0x00`
    - `size = 8`
  - input1:
    - `space = Const`
    - `offset = 0x01`
    - `size = 1`

第二条 raw op：
- opcode = `CPUI_COPY`
- output:
  - `space = Register`
  - `offset = 0x00`
  - `size = 8`
- input0:
  - `space = Unique`
  - `offset = 与第一条 op 的 output offset 相同`
  - `size = 8`

### 1.4 注入后函数级状态

注入 `Funcdata` 后，本次样本可确认：

- `fd.obank.alivelist.len() == 2`
- `fd.bblocks.get_size() == 1`

这说明从 raw P-code 到函数级 op / block 的最小注入链路是可执行的。

---

## 2. 实际运行结果 (Actual Execution Result)

### 2.1 本次执行命令

本次围绕新增样本实际运行了对应测试，目标是拿到第一条真实失败记录，而不是停留在静态推断。

### 2.2 最终结果

当前该测试并未通过，而是形成了明确的失败样本记录。

测试输出中可确认的关键现象包括：

- 进入了实际测试执行
- 触发了当前 P-code 比较入口
- 结果为 `FAILED`

### 2.3 当前已观测到的差异日志

本次失败过程中，日志出现了两类具有直接价值的差异信号：

#### A. Opcode mismatch
出现日志：

- `[RUGRA DIFF] 0x1000: Opcode mismatch. Ghidra Op: 4, Rugra has 1 ops here`

这表明在当前第一条 op 的比较过程中，比较入口拿到的“参考 opcode”与 Rugra 当前地址下的 op 组织方式之间仍然存在错位。

#### B. 输入 varnode 比较失败
出现日志：

- `[RUGRA DIFF] 0x1010: Input mismatch at index 0. Rugra: 0x1000:8, Ghidra space: 3, offset: 0x1000, size: 8`

这说明第二条 op（当前为 `COPY`）的输入比较中，unique / 临时值相关的 varnode 组织与当前比较口径之间仍不一致。

### 2.4 测试断言失败点

当前测试最终在：

- `assert!(matches!(result, VerifyResult::Match));`

处失败。

这意味着本次工作并没有把 `add rax, 1` 推进成“局部最小验证通过”，但已经成功把它推进成：

- 可执行
- 可复现
- 可定位差异类别

的真实失败记录。

---

## 3. 架构推进与一致性审计 (Architecture & Alignment Audit)

### 3.1 本次工作的实际价值

这次工作的价值不在于“证明 add 已对齐”，而在于把第二条最小样本从抽象计划推进成了真实故障记录。

相比只写 TODO 或只做静态推断，现在已经能明确确认：

- `add rax, 1` 的最小测试已经存在
- 它能完整跑到 `runtime_verify`
- 它会触发 FFI 比较入口
- 当前失败不是模糊的“哪里不对”，而是已有明确差异信号：
  - opcode 错位
  - unique 输入比较错位

这对下一轮修复非常关键，因为它意味着后续不必再花时间确认“样本能不能跑”，而是可以直接进入“为什么失败”的分析阶段。

### 3.2 当前可以确认的事实

本次会话后，可以确认：

- `48 83 c0 01` 能被反汇编为 `add rax, 1`
- `X86Lifter::lift(...)` 当前会为其生成 `INT_ADD + COPY`
- `inject_raw_ops(...)` 能接受该样本
- `verify_pcode_generation(...)` 会真实执行并返回 mismatch
- FFI 比较入口会输出明确差异日志
- 当前 `add rax, 1` 仍未通过最小局部验证

### 3.3 当前仍然不能宣称的内容

本次会话后，以下内容仍然不能写成既成事实：

- 不能宣称 `add rax, 1` 已完成局部对拍通过
- 不能宣称当前 `INT_ADD + COPY` 组织已经与 Ghidra 一致
- 不能宣称 unique 临时值比较口径已经正确
- 不能宣称当前 opcode 参考值已与真实 Ghidra 侧逐字段参考完全对齐

### 3.4 当前更准确的状态描述

当前最准确的结论应是：

> `add rax, 1` 已从“待实现样本”推进成“第二条真实失败最小样本记录”，  
> 当前已能稳定暴露 opcode 与 unique 输入比较错位，但尚未通过局部结构化验证。

---

## 4. 差异初步分析 (Initial Difference Analysis)

### 4.1 Opcode mismatch 的可能含义

日志中出现：

- `Ghidra Op: 4`

而当前样本预期中的第一条主要运算 op 应更接近：

- `CPUI_INT_ADD`

这说明当前比较口径中，至少存在以下一种或多种问题：

1. 传入比较入口的“参考 opcode”并不是真实 Ghidra 独立结果
2. 当前 op 地址与参考 op 地址的对齐方式存在偏移
3. 当前将一条机器指令提升成多条 P-code 后，比较入口对“同一地址下多条 op”的匹配策略仍不充分

### 4.2 Unique 输入比较失败的可能含义

第二条日志指向：

- `0x1010`
- input index 0
- unique / 临时值相关 mismatch

这通常意味着以下问题之一：

1. unique 空间 ID 映射口径与比较层仍不一致
2. 临时值地址 / 偏移的比较方式仍不适合直接用作 parity 依据
3. 当前 `INT_ADD -> COPY` 的两步组织与参考侧的 op 组织粒度不同
4. 当前第二条 op 的输入在比较层中被当作“需严格逐字段相等”的对象，但实际上 unique 可能需要特殊放宽或归一化策略

### 4.3 为什么这条失败记录有价值

这类失败记录的价值在于，它已经把问题从宽泛范围缩小到了非常具体的两个点：

- op 匹配策略
- unique 输入比较策略

后续修复时，不需要再回到整个端到端链路做大范围排查。

---

## 5. 证据来源 (Evidence Sources)

本次日志结论主要依据以下可见证据：

### 源码证据
- `src/funcdata.rs`
  - 新增测试：`test_add_rax_imm_minimal_alignment_path`
- `src/disasm/x86_64.rs`
  - x86-64 反汇编入口
- `src/disasm/x86_lift.rs`
  - `add` 指令当前 lifting 路径
- `src/align/runtime_verify.rs`
  - `verify_pcode_generation(...)`
- `src/ffi.rs`
  - `rugra_compare_pcode(...)`

### 样本证据
- 样本机器码：
  - `48 83 c0 01`
- 目标指令：
  - `add rax, 1`

### 运行结果证据
- 测试结果：
  - `test funcdata::tests::test_add_rax_imm_minimal_alignment_path ... FAILED`
- 差异日志：
  - `Opcode mismatch. Ghidra Op: 4`
  - `Input mismatch at index 0 ...`

---

## 6. 当前判断 (Current Assessment)

### 6.1 本次已经达成的推进

本次已经达成：

- 第二条最小样本正式落地
- 样本已具备真实测试入口
- 样本已形成真实失败记录
- 已能观测 opcode 错位
- 已能观测 unique 输入比较错位

### 6.2 本次尚未达成的目标

本次尚未达成：

- `add rax, 1` 局部最小验证通过
- 当前样本的 compare 口径稳定
- current op / reference op 的可靠映射
- unique 输入的合理归一化比较

---

## 7. 下一步干涉计划 (Next Steps / Blockers)

### 7.1 下一步最高优先级

围绕 `add rax, 1`，下一步最值得直接推进的是：

1. 重新检查 `verify_pcode_generation(...)` 对多 op 同地址样本的比较策略
2. 检查 `opcode` 参考值在当前最小样本中的来源与传递口径
3. 对 unique 输入比较增加更合适的归一化或放宽策略
4. 把该样本先推进到：
   - “局部结构化比较可通过”
   - 再谈真实 Ghidra 独立参考接入

### 7.2 第二优先级

在 `add rax, 1` 稳定后，继续推进第三条样本：

- `sub rax, 8`

这样可以尽快确认：

- 算术 opcode 的共性问题
- 立即数输入组织是否一致
- `INT_SUB` 是否暴露相同类型错位

### 7.3 文档侧待跟进

后续若继续推进该样本，应同步更新：

- `docs/TODO_BOARD.md`
- `docs/VERIFICATION_GUIDE.md`
- 必要时更新更高层的 `ALIGNMENT_PROGRESS.md`

前提仍然是：

- 只能基于真实可复核结果更新
- 不能把“失败样本已存在”夸大成“局部对拍已完成”

---

## 8. 本次会话结论 (Session Conclusion)

一句话总结本次工作：

> 本次会话把 `add rax, 1` 从第二条计划中的最小样本，推进成了第二条真实失败记录：  
> 样本已能稳定执行到局部验证链路，并暴露出 opcode 与 unique 输入比较错位，为下一轮有针对性的修复提供了明确切入点。
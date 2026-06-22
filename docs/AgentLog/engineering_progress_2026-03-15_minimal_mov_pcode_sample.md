# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-15  
**核心意图 / Core Intent:** 落地第一条最小 P-code 样本 `mov rbx, rax`，把“样本草案”推进成可执行、可复现、可记录的真实局部验证记录。  
**触及模块 / Touched Modules:** `src/funcdata.rs`、`src/disasm/mod.rs`、`src/disasm/x86_64.rs`、`src/disasm/x86_lift.rs`、`src/align/runtime_verify.rs`、`src/ffi.rs`

---

## 1. 代码变更与迭代 (Progress & Code Changes)

本次会话的目标不是扩展新功能，而是验证前一轮已经明确的最小对齐闭环是否真的能落地到一条**真实测试样本**。

### 1.1 新增最小样本测试

在 `src/funcdata.rs` 的测试模块中新增了一条围绕 `mov rbx, rax` 的最小路径测试，覆盖以下链路：

1. 使用机器码 `48 89 c3`
2. 反汇编得到单条 `Instruction`
3. 通过 `X86Lifter::lift(...)` 生成 `PcodeOpRaw`
4. 校验 raw P-code 的 opcode、输入、输出
5. 注入 `Funcdata::inject_raw_ops(...)`
6. 调用 `RuntimeVerifier::verify_pcode_generation(...)`
7. 通过当前 FFI 比较入口观察实际行为

### 1.2 本次样本验证的具体断言

本次测试围绕以下事实建立断言：

- 原始字节：`48 89 c3`
- 反汇编语义：`mov rbx, rax`
- raw p-code 数量：`1`
- raw opcode：`CPUI_COPY`
- 输出 varnode：
  - space = `Register`
  - offset = `0x18`（`rbx`）
  - size = `8`
- 输入 varnode：
  - 数量 = `1`
  - space = `Register`
  - offset = `0x00`（`rax`）
  - size = `8`
- 注入后 `Funcdata`：
  - op 数量 = `1`
  - basic block 数量 = `1`

### 1.3 实际编译与执行结果

本次新增测试已完成一次真实编译与执行。结果为：

- 测试名称：`test_mov_reg_reg_minimal_alignment_path`
- 执行状态：`ok`
- 测试数量：`running 1 test`
- 最终结果：`1 passed; 0 failed`

这说明：
- 从机器码到 raw P-code 的最小路径可以实际运行
- `inject_raw_ops(...)` 与当前最小样本兼容
- 当前运行时验证入口至少已经可以承载一条真实样本

### 1.4 本次遇到的小修正

在第一次编译时，测试里对 `raw.output()` 的借用方式触发了生命周期错误。随后改为先绑定临时值，再取 `as_ref()`，问题即消除。

这类修正不涉及语义变化，只是为让测试能够稳定编译。

---

## 2. 最小样本运行记录 (Minimal Sample Record)

### 样本标识
- `PCode-Min-001`
- `mov_reg_reg`

### 目标层级
- `Level 2：运行时局部对拍（当前为框架级入口验证）`

### 目标指令
- `mov rbx, rax`

### 原始字节
- `48 89 c3`

### Rugra 侧入口
- `src/disasm/x86_64.rs`
- `src/disasm/mod.rs`
- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`
- `src/align/runtime_verify.rs`

### 参考侧入口 / 对比方式
- `src/ffi.rs`
- 当前通过 `set_current_program(...)` + `rugra_compare_pcode(...)` 走现有比较入口

### Rugra 结果摘要
- 反汇编：
  - 识别出单条 `mov`
  - 文本中包含 `rbx` 与 `rax`
- lifting：
  - 生成 `1` 条 `CPUI_COPY`
- raw output：
  - `rbx`
- raw input：
  - `rax`
- inject 后：
  - `1` 条正式 op
  - `1` 个 basic block

### 实际运行时比较输出
本次测试执行时，控制台出现如下差异提示：

- `[RUGRA DIFF] 0x1000: Opcode mismatch. Ghidra Op: 0, Rugra has 1 ops here`

### 当前结论
该结果**不表示** `mov rbx, rax` 的 lifting 本身失败，而是表明：

1. 当前最小样本链路已经真实跑通
2. 当前 `verify_pcode_generation(...)` 仍然是**框架级比较**
3. 它传给 `rugra_compare_pcode(...)` 的参考 opcode 仍为占位值 `0`
4. 因此当前比较入口会输出“opcode mismatch”日志
5. 但测试仍返回 `VerifyResult::Match`

换句话说：

> 本次已拿到第一条“真实执行记录”，  
> 但当前结果证明的是“最小链路可执行”，还不是“已完成有效逐字段对拍”。

---

## 3. 架构推进与一致性审计 (Architecture & Alignment Audit)

### 3.1 本次对齐推进的实际价值

本次工作的价值不在于“证明已经和 Ghidra 一致”，而在于首次把此前文档中的最小样本方案，推进成了**真实、可执行、可复现的测试记录**。

这意味着项目从：

- 只有链路分析
- 只有样本模板
- 只有入口判断

推进到了：

- 已有真实样本
- 已能执行
- 已能看到框架级差异输出
- 已能明确下一步该修哪里

### 3.2 当前能确认的事实

本次会话后，可以确认以下事实：

- `mov rbx, rax` 这条样本在当前代码中可成功反汇编
- `X86Lifter::lift(...)` 能为其生成单条 `CPUI_COPY`
- 输入输出寄存器映射在该样本上与预期一致
- `Funcdata::inject_raw_ops(...)` 能接受这条样本并生成函数级 op / block
- `RuntimeVerifier::verify_pcode_generation(...)` 已可用于真实测试流程
- `ffi::rugra_compare_pcode(...)` 确实被触发，且会输出差异日志

### 3.3 当前仍不能宣称的内容

本次会话后，以下内容仍然**不能**写成已完成事实：

- 不能宣称 `mov rbx, rax` 已完成与 Ghidra 的严格逐字段对拍
- 不能宣称 `verify_pcode_generation(...)` 已具备完整 opcode / output / input 明细比较
- 不能宣称当前 FFI 比较已经形成稳定、可靠、可统计的局部验证体系
- 不能宣称最小 P-code 对拍已经真正闭环完成

### 3.4 文档同步确认

本次会话的主要代码变更是新增最小样本测试，因此按仓库约定，需要同步留下工程日志与后续待办更新口径。

本条日志即用于记录本次会话的真实结果与边界，避免下次会话把“测试已存在”误写成“对拍已完成”。

---

## 4. 证据来源 (Evidence Sources)

本次日志结论主要依据以下可见证据：

### 源码证据
- `src/funcdata.rs`
  - 新增最小样本测试
  - `inject_raw_ops(...)` 注入路径
- `src/disasm/mod.rs`
  - `Instruction` / `Operand` 结构
- `src/disasm/x86_64.rs`
  - x86-64 反汇编入口
- `src/disasm/x86_lift.rs`
  - `mov` 对应 `CPUI_COPY` lifting 分支
- `src/align/runtime_verify.rs`
  - `verify_pcode_generation(...)`
- `src/ffi.rs`
  - `set_current_program(...)`
  - `rugra_compare_pcode(...)`

### 测试证据
- `cargo test --manifest-path rugra/Cargo.toml mov_reg_reg_minimal_alignment_path --lib -- --nocapture`
- 实际结果：
  - `running 1 test`
  - `test funcdata::tests::test_mov_reg_reg_minimal_alignment_path ... ok`

### 运行输出证据
- 实际日志：
  - `[RUGRA DIFF] 0x1000: Opcode mismatch. Ghidra Op: 0, Rugra has 1 ops here`

---

## 5. 当前判断 (Current Assessment)

### 5.1 这条样本达成了什么
本次已经达成：

- 第一条最小样本真实执行
- 第一条最小样本真实记录
- 第一条最小样本真实差异输出

这是“恢复最小 P-code 对拍工作”的一个实质性起点。

### 5.2 这条样本还没达成什么
本次尚未达成：

- 有效 Ghidra opcode 传入
- output / input 的参考侧逐字段比较
- 有意义的 `MismatchRecord` 分层归档
- 从“入口可跑”升级到“比较结果可信”

因此目前最准确的表述应是：

> `mov rbx, rax` 已从“模板化记录草案”推进为“第一条真实可执行最小样本”，  
> 但当前运行时比较仍停留在框架级入口验证，而非完整局部对拍。

---

## 6. 下一步干涉计划 (Next Steps / Blockers)

### 6.1 下一步最高优先级
围绕这条样本，下一步最值得立即推进的是：

1. 修正 `verify_pcode_generation(...)` 中传给 `rugra_compare_pcode(...)` 的占位参数
2. 至少把当前 Rugra op 的真实 opcode 传入比较层
3. 把“总是返回 `VerifyResult::Match`”的框架逻辑改成基于实际比较结果返回
4. 让这条样本真正区分：
   - `入口跑通`
   - `比较有效`
   - `发现差异`
   - `无差异`

### 6.2 第二优先级
在 `mov rbx, rax` 之后，继续推进第二批最小样本：

- `add rax, 1`
- `sub rax, 8`

目标是验证：
- 算术类 opcode 路径
- 常量输入组织
- 输入顺序与输出回写

### 6.3 文档侧待跟进
后续应同步补到相关状态文档中的内容包括：

- `docs/TODO_BOARD.md`
  - 把 `mov rbx, rax` 从“待补真实记录”推进到“已有第一条真实记录，仍待提升比较粒度”
- `docs/VERIFICATION_GUIDE.md`
  - 明确记录当前最小样本已能执行，但比较仍是框架级
- 如后续形成更多真实样本，再视情况补入：
  - `ALIGNMENT_PROGRESS.md`

---

## 7. 会话结论 (Session Conclusion)

本次会话最重要的成果不是“对齐完成”，而是：

> **第一条最小 P-code 样本 `mov rbx, rax` 已经完成真实测试落地。**

其当前状态应准确表述为：

- 样本已存在
- 测试已执行
- lifting 结果与注入路径已可验证
- 运行时比较入口已触发
- 但比较参数仍带占位值，尚未形成可信的逐字段对拍

这为下一轮会话提供了非常明确的切入点：

> 不再需要继续讨论“从哪里开始”，  
> 下一轮可以直接从 `verify_pcode_generation(...)` 的比较参数与返回语义开始修正。
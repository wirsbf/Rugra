# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-15  
**核心意图 / Core Intent:** 将最小 P-code 对拍链路中的 FFI 比较入口从“仅打印差异日志”推进到“返回结构化比较状态”，为 `runtime_verify` 消费真实比较结果打下基础。  
**触及模块 / Touched Modules:** `src/ffi.rs`、`src/align/runtime_verify.rs`

---

## 1. 代码变更与迭代 (Progress & Code Changes)

本次会话围绕上一轮已经明确的直接缺口继续推进：  
虽然 `mov rbx, rax` 的最小样本已经能够完成真实执行，并且 `runtime_verify` 已开始做结构化本地比较，但 FFI 比较入口本身仍然主要表现为：

- 接收参数
- 打印 `[RUGRA DIFF] ...`
- 不向调用方返回可消费的结构化结果

这意味着 `runtime_verify` 虽然“调用了比较层”，但还不能真正基于 FFI 返回值来区分：

- match
- opcode mismatch
- output mismatch
- input count mismatch
- input mismatch
- missing op

本次工作的核心，就是把这条返回路径补出来。

### 1.1 在 `ffi.rs` 中新增结构化比较结果类型

本次在 FFI 层引入了新的结构化返回对象与状态码，核心包括：

- `PcodeCompareResultFFI`
- `PCODE_COMPARE_MATCH`
- `PCODE_COMPARE_OPCODE_MISMATCH`
- `PCODE_COMPARE_OUTPUT_MISMATCH`
- `PCODE_COMPARE_INPUT_COUNT_MISMATCH`
- `PCODE_COMPARE_INPUT_MISMATCH`
- `PCODE_COMPARE_MISSING_RUGRA_OP`

这一步的意义是：  
FFI 比较入口不再只能通过 stdout 暗示发生了什么，而是开始能显式告诉上层“哪一类比较失败了”。

### 1.2 修改 `rugra_compare_pcode(...)` 的返回语义

此前 `rugra_compare_pcode(...)` 的主要行为是：

- 查找当前地址上的 Rugra op
- 尝试根据 opcode 找到匹配项
- 打印 output / input count / opcode 等差异
- 直接结束

本次修改后，该函数开始返回 `PcodeCompareResultFFI`，并在不同分支上返回明确状态：

#### A. Rugra 侧缺失 op
当当前地址找不到任何 Rugra op 时，返回：

- `PCODE_COMPARE_MISSING_RUGRA_OP`

#### B. Opcode 不匹配
当同地址下存在 op，但找不到 opcode 对应的匹配项时，返回：

- `PCODE_COMPARE_OPCODE_MISMATCH`

#### C. Output 不匹配
当输出存在性、空间、偏移或大小不一致时，返回：

- `PCODE_COMPARE_OUTPUT_MISMATCH`

#### D. Input count 不匹配
当输入数量不一致时，返回：

- `PCODE_COMPARE_INPUT_COUNT_MISMATCH`

#### E. Input 明细不匹配
当某个输入在：

- space
- offset
- size

上与参考侧不同，返回：

- `PCODE_COMPARE_INPUT_MISMATCH`

#### F. 全部匹配
当 opcode、output、input count、input 明细都一致时，返回：

- `PCODE_COMPARE_MATCH`

### 1.3 FFI 层开始真正消费 input 列表

此前虽然上层已经开始传入真实 input 列表，但 `ffi.rs` 侧仍没有真正解引用并逐项比较这些输入。  
本次会话中，FFI 比较逻辑开始：

1. 将 `inputs + input_count` 解释为输入数组
2. 逐项取出参考输入
3. 与 Rugra 当前 op 的对应输入逐项比对：
   - `space_id`
   - `offset`
   - `size`

这意味着“输入已传下去”和“输入真的参与比较”这两件事，现在终于同时成立。

### 1.4 `runtime_verify.rs` 开始消费 FFI 返回状态

在 `runtime_verify.rs` 中，本次会话同步完成了调用侧升级：

- `verify_pcode_generation(...)` 不再只是调用 FFI 比较入口后忽略其结果
- 现在会接收 `PcodeCompareResultFFI`
- 并通过状态码判断 FFI 比较是否成功

同时新增了状态描述函数，用于把 FFI 状态码映射为可读字符串，例如：

- `match`
- `opcode mismatch`
- `output mismatch`
- `input count mismatch`
- `input mismatch`
- `missing Rugra op`

这样，`MismatchRecord` 与 `VerifyResult::Mismatch(...)` 中已经能开始携带 FFI 比较层面的结构化差异语义，而不只是依赖终端日志。

### 1.5 `verify_pcode_generation(...)` 的 mismatch 语义继续收敛

在这次修改前，`runtime_verify` 的 mismatch 主要来自：

- op 数量差异
- 本地 `verify_operation(...)` 结果

本次修改后，判断条件扩大为：

- 本地结构化校验失败  
或
- FFI 结构化比较返回非 `MATCH`

这意味着调用方现在已经可以开始得到一种更接近真实验证链路的结果：

> 不是“我调用过比较入口所以大概没问题”，  
> 而是“比较入口明确告诉我它属于哪一类失败”。

---

## 2. 最小样本推进结果 (Minimal Sample Advancement)

### 2.1 本次推进针对的样本上下文

本次工作仍然服务于当前第一条最小样本：

- **样本 ID**：`PCode-Min-001`
- **目标指令**：`mov rbx, rax`
- **机器码**：`48 89 c3`
- **起始地址**：`0x1000`

### 2.2 本次推进前的状态

推进前，该样本已经具备：

- 可反汇编
- 可 lifting 为 `CPUI_COPY`
- 可注入 `Funcdata`
- 可调用 `verify_pcode_generation(...)`
- 可把真实 opcode / output / input 传给比较层
- `verify_pcode_generation(...)` 不再无条件返回 `Match`

但当时仍存在关键缺口：

- FFI 比较入口本身仍然不返回结构化结果
- `runtime_verify` 仍无法真正消费 FFI 比较层的差异分类
- mismatch 仍然部分依赖 stdout 侧现象

### 2.3 本次推进后的状态

本次会话后，这条样本的验证链路已经进一步升级为：

- 上层可传入真实 opcode / output / input
- FFI 层可逐项比较 output 与 input
- FFI 层可返回结构化比较状态
- `runtime_verify` 可消费该状态并形成 mismatch 记录
- `VerifyResult` 与 `MismatchRecord` 现在都开始具备“来自 FFI 比较层的分类信息”

因此，这条样本已经从：

- **带结构化本地比较的局部验证记录**

进一步推进到：

- **带结构化 FFI 比较返回路径的局部验证记录**

---

## 3. 架构推进与一致性审计 (Architecture & Alignment Audit)

### 3.1 本次工作的真实价值

本次修改最重要的价值，不是“证明已经与 Ghidra 一致”，而是把验证链路中的一个关键假闭环改成了真链路：

之前：

- 比较入口会跑
- 会打印
- 但调用方拿不到真正的比较状态

现在：

- 比较入口会跑
- 会打印
- 还会返回结构化状态
- 上层开始把这个状态纳入 mismatch 判定

这是一次验证链路语义上的实质性收敛。

### 3.2 当前可以确认的事实

本次会话后，可以确认以下事实：

- `rugra_compare_pcode(...)` 已不再只是 stdout side-effect
- FFI 比较入口已拥有结构化返回值
- 该返回值已区分至少 6 类状态
- FFI 层已经真正逐项比较 input 列表
- `verify_pcode_generation(...)` 已开始消费 FFI 结果
- mismatch 详情开始包含 FFI 状态说明

### 3.3 当前仍然不能宣称的内容

即使完成了这一步，当前仍然**不能**把该样本写成“完整 Ghidra 局部对拍闭环已完成”，原因包括：

1. 当前传入 FFI 的“参考侧数据”仍然不是来自稳定 Ghidra 侧独立回传的完整结构化结果
2. 当前链路更准确地说是：
   - Rugra 侧本地构造参考数据
   - FFI 比较入口结构化消费这些数据
3. 还没有形成真正的“双边独立来源数据 + 统一差异报告”闭环
4. 当前结果更像：
   - 比较基础设施显著增强
   - 而不是 parity 已被证明

因此目前最准确的口径应是：

> `mov rbx, rax` 的最小验证样本已经拥有结构化 FFI 比较返回路径，  
> 但当前仍未形成由真实 Ghidra 独立参考数据驱动的完整局部 parity 结论。

### 3.4 文档同步确认

按照仓库规则，只要验证语义和调用链路发生变化，就必须同步记录。  
本条日志用于明确说明：

- FFI 比较层本次增加了什么
- `runtime_verify` 现在消费到了什么
- 结果能说明什么
- 结果还不能说明什么

避免后续会话把“FFI 已有结构化返回”误写成“已完成 Ghidra 逐字段对拍闭环”。

---

## 4. 证据来源 (Evidence Sources)

本次日志结论主要依据以下代码与上下文：

### 源码证据
- `src/ffi.rs`
  - `PcodeCompareResultFFI`
  - `rugra_compare_pcode(...)`
  - `VarnodeFFI`
- `src/align/runtime_verify.rs`
  - `verify_pcode_generation(...)`
  - FFI 状态消费逻辑
  - `MismatchRecord`
- `src/align/pcodeop.rs`
  - `verify_operation(...)`

### 样本上下文证据
- 当前第一条最小样本：`mov rbx, rax`
- 机器码：`48 89 c3`
- 链路：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`

### 前序记录证据
- `docs/AgentLog/engineering_progress_2026-03-15_minimal_mov_pcode_sample.md`
- `docs/AgentLog/engineering_progress_2026-03-15_structured_mov_pcode_verification.md`

---

## 5. 当前判断 (Current Assessment)

### 5.1 本次已经达成的推进

本次已完成的关键升级包括：

- FFI 比较入口新增结构化返回对象
- FFI 层开始逐项比较 input 明细
- FFI 层开始区分 opcode / output / input count / input / missing op 等差异类型
- `runtime_verify` 开始消费 FFI 比较返回值
- mismatch 详情开始带有 FFI 状态语义

### 5.2 本次仍未完成的部分

本次没有解决的问题仍然包括：

- 参考侧数据仍未真正来自独立 Ghidra 结构化回传
- FFI 状态虽然已结构化，但还没有更丰富的差异载荷
- 仍缺少“参考侧真实字段值 -> 统一报告对象”的完整双边记录
- 还没有扩展到第二批样本：
  - `add rax, 1`
  - `sub rax, 8`

---

## 6. 下一步干涉计划 (Next Steps / Blockers)

### 6.1 下一步最高优先级

接下来最直接的工程切入点是：

1. 让参考侧数据真正来自独立 Ghidra 返回，而不是仅由 Rugra 当前侧构造
2. 让 FFI 结构化返回不仅包含状态码，还能携带更具体的 mismatch payload
3. 让 `runtime_verify` 直接基于这些 payload 生成更细粒度的 `MismatchRecord`

### 6.2 第二优先级

在 `mov rbx, rax` 基础上继续推进：

- `add rax, 1`
- `sub rax, 8`

重点验证：

- 常量输入组织
- 算术 opcode
- 输入顺序
- output 回写

### 6.3 文档侧待跟进

若后续继续推进，应同步更新：

- `docs/TODO_BOARD.md`
- `docs/VERIFICATION_GUIDE.md`
- 必要时更新 `ALIGNMENT_PROGRESS.md`

前提仍然是：  
只能基于真实可复核结果更新，不能把“FFI 已结构化返回”夸大成“已完成 Ghidra parity”。

---

## 7. 本次会话结论 (Session Conclusion)

一句话总结本次工作：

> 本次会话把最小 P-code 样本验证链路中的 FFI 比较入口，从“仅打印差异”推进成了“可返回结构化比较状态并被 `runtime_verify` 消费”的形式，使 Rugra 的局部 P-code 验证开始具备真正的返回路径语义，但当前仍未达到由独立 Ghidra 参考数据驱动的完整局部对拍闭环。
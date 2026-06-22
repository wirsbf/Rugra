# Rugra-Ghidra Alignment Verification Progress

本文档用于追踪 **Rugra 与 Ghidra 在核心对象、算法行为与端到端输出上的对齐状态**。  
其核心目标是：**把“已完成静态结构对齐”与“尚未验证运行时一致性”严格区分开来**，避免把未验证能力误写成既成事实。

> **重要声明**
>
> 1. 当前仓库中，**静态结构对齐**与**运行时一致性验证**是两个不同层次。
> 2. “字段、枚举、接口形态相似” **不等于** “算法行为与 Ghidra 完全一致”。
> 3. 除非存在明确的运行时对拍证据，否则**不得**声称：
>    - 与 Ghidra `100%` 一致
>    - SSA 版本分配已完全对齐
>    - CFG / P-code / 最终 C 输出已完成等价验证
> 4. 本文档只记录**当前可由仓库内容合理支撑的结论**。
> 5. 本文档中的高风险结论，后续应尽量附带**证据来源**，至少能回链到以下之一：
>    - 相关源码文件
>    - 测试或测试入口
>    - 示例程序
>    - 验证框架入口
>    - 差异报告或实验记录
> 6. 如果某项结论当前**没有明确证据来源**，应按“待验证”“未证实”或“仅有框架基础”表述，而不是写成既成事实。

---

## 0. 证据来源记录规则

为降低状态文档再次失真的风险，后续维护本文档时，建议对关键对齐结论显式补充“证据来源”。

### 0.1 适用范围
以下内容属于高风险结论，应优先补证据来源：

- 某模块“已完成静态结构对齐”
- 某行为“已具备运行时验证入口”
- 某项对拍“已通过”
- 某项差异“已定位/已修复”
- 某层级“已形成闭环”
- 任何接近“与 Ghidra 一致”或“已验证”的表述

### 0.2 可接受的证据类型
证据来源至少应能指向以下之一：

- **源码证据**：例如 `src/align/address.rs`、`src/align/runtime_verify.rs`
- **测试证据**：例如单元测试、集成测试、可执行验证入口
- **示例证据**：例如 `examples/` 下可复现样例
- **文档证据**：例如验证说明、实验记录、差异归档
- **结果证据**：例如对拍报告、 mismatch 记录、统计输出

### 0.3 推荐写法
后续在正文中，建议采用类似格式：

- `证据来源：src/align/address.rs，相关测试入口`
- `证据来源：src/align/runtime_verify.rs，docs/VERIFICATION_GUIDE.md`
- `证据来源：当前仓库可见源码结构；尚无稳定运行结果`

### 0.4 无证据时的写法
如果当前没有足够证据，应使用以下保守口径：

- `已具备工程基础`
- `已存在框架入口`
- `待运行时对拍验证`
- `当前仓库信息不足以证实`
- `尚不能确认`

而不应直接写成：

- `已完成`
- `已一致`
- `已保障`
- `已闭环`

---

## 1. 当前结论摘要

### 已确认
- `src/align/` 下已经建立了一批 **静态对齐辅助模块与验证代码**
  - 证据来源：`src/align/`
- 若干核心对象已有：
  - 字段级/结构级映射
  - 基础验证函数
  - 单元测试或静态检查入口
  - 证据来源：`src/align/address.rs`、`src/align/varnode.rs`、`src/align/pcodeop.rs`、`src/align/datatype.rs`、`src/align/range.rs`
- 仓库内存在 `runtime_verify.rs`，说明项目已经开始建设**运行时对拍框架**
  - 证据来源：`src/align/runtime_verify.rs`

### 尚不能确认
- 尚**不能确认** Rugra 当前运行时行为与 Ghidra 完全一致
- 尚**不能确认** SSA 版本分配算法已完成 1:1 对拍
- 尚**不能确认** P-code 生成序列已与 Ghidra 完整比对
- 尚**不能确认** CFG 结构恢复已完成逐函数等价验证
- 尚**不能确认** 最终 C 风格输出在真实样本上达到稳定语义等价

---

## 2. 对齐层次定义

为避免文档失真，今后所有“对齐”结论都必须落在以下层级之一。

### Level A: 静态结构对齐
指数据结构、字段、枚举值、API 形态、基本语义约定与 Ghidra 概念相近。

**可宣称内容**
- 某类对象已完成字段映射
- 某枚举 / opcode 表已完成静态映射
- 某验证函数 / 基础测试已经存在

**不可宣称内容**
- 算法行为一致
- 输出结果一致
- 运行时 parity 已建立

---

### Level B: 运行时局部对拍
指某个具体行为已通过运行时比对验证，例如：
- 常量求值
- 单条指令 P-code 生成
- 指定函数 SSA 重命名
- CFG 基本块划分

**可宣称内容**
- 某个验证点已可执行
- 某项行为在若干样本上通过
- 某项行为仍存在差异

**不可宣称内容**
- 整体系统已完全一致
- 全模块都已验证

---

### Level C: 端到端语义验证
指在真实二进制样本上，对完整流程进行对比，包括：
- lifting
- SSA
- CFG
- 类型传播
- 输出结构

**可宣称内容**
- 某样本、某函数、某架构下通过端到端验证
- 语义等价达到某一明确范围

**不可宣称内容**
- 只凭少量样本就宣称“全面完成”

---

## 3. 总体进度总览

| 维度 | 当前状态 | 说明 |
|------|----------|------|
| 静态结构对齐 | 部分完成 | 已有多个 `align` 模块与基础验证逻辑 |
| 运行时
验证框架 | 已起步 | `runtime_verify.rs` 已存在，但不等于验证工作
已完成 |
| 运行时局部对拍 | 未充分证实 | 现有仓库信息不足以支撑“已全面通过”
 |
| 端到端 parity | 未证实 | 不能宣称
已和 Ghidra 完全一致 |
| 一致性总保证 | 不成立 |
 当前只能说“在推进对齐中” |

---

## 4. 已有静态结构对齐项

以下内容表示：**仓库内存在对应的静态对齐
实现或验证意图**。  
这部分结论
只代表 **Level A: 静态结构对齐**。

### 4.1 Core Infrastructure

#### `Address` / `SeqNum`
- 对应文件
：`src/align/address.rs
`
- 当前状态：**已建立静态对齐**
- 证据来源：
  - `src/align/address.rs`
- 可确认内容：
  - 地址空间 / 偏移 / 顺序信息等核心概念
已建模
  - 存在验证函数与测试意图
- 运行时结论：
  - **未证明** 与 Ghidra 在所有调用场景下行为完全一致

####
 #### `Range` / `RangeList`
 - 对应文件：`src/align/range.rs
 `
 - 当前状态：**已建立静态对齐**
 - 证据来源：
   - `src/align/range.rs`
 - 可确认内容：
   - 范围表示、包含关系、合并逻辑已有实现基础
 - 运行时结论：
   - **未
 完成** 大规模运行时 parity 证明

---

### 4.2 Syntax / IR Core

#### `Varnode`
- 对应文件：`src/align/varnode.rs`
- 当前状态：**已建立静态对齐**
- 证据来源：
  - `src/align/varnode.rs`
- 可确认内容：
  - 空间、偏移、大小、版本等基础字段已纳入对齐语境
- 运行时结论：
  - **不能据此推出** SSA 版本分配行为已与 Ghidra 一致

#### `PcodeOp` / `PcodeOperation`
- 对应文件：`src/align/pcodeop.rs`
- 当前状态：**已建立静态对齐**
- 证据来源：
  - `src/align/pcodeop.rs`
- 可确认内容：
  - opcode 映射、输入输出、序号等基础形态已有映射基础
- 运行时结论：
  - **不能据此推出** Rugra 生成的 P-code 序列已逐指令与 Ghidra 一致

#### `PcodeOpRaw`
- 对应文件：`src
/pcoderaw.rs` 与相关对齐
文档
- 当前状态：**具备对齐基础**
- 证据来源：
  - `src/pcoderaw.rs`
  - `docs/api/pcoderaw.md`
- 运行时结论：
  - 是否与真实 lifting 流程完全一致，**仍需单独验证**

---

### 4.3 Type System

#### `DataType`
- 对应文件：`src
/align/datatype.rs`
- 当前状态：**已建立静态对齐**
- 证据来源：
  - `src/align/datatype.rs`
- 可确认内容：
  - 基本类型、元类型、结构布局等已有映射基础
- 运行时结论：
  - **不代表** 类型传播、推导、约束求解结果已与 Ghidra 对齐

---

### 4.4 Heritage / SSA / Control Flow / Actions

以下模块在仓库中已经
存在对齐实现或命名映射基础，但默认只按
“静态对齐 / 工程接轨”计算
：

- `src/align/heritage.rs`
- `src/align/block.rs`
- `src/align/action.rs`

**当前可确认**
- 已开始对
  Ghidra 核心概念进行 Rust 映射
- 已具备继续做运行时验证的结构基础
- 证据来源：
  - `src/align/heritage.rs`
  - `src/align/block.rs`
  - `src/align/action.rs`

**当前不可确认**
- `heritage()`、`placeMultiequals()`、`rename()` 已与 Ghidra 行为严格对拍

- `calcDominance()`、循环识别、块划分结果已运行时等价
- Action / Rule 的执行顺序
、副作用与最终
结果已完全一致

### 4.4.1 Cover-based HighVariable Merging（2026-06-21 新增）

- 对应文件：`src/merge.rs`、`src/cover.rs`、`src/action.rs`
- 当前状态：**Level A 静态结构对齐 + Level B 局部运行时行为**
- 证据来源：
  - `src/merge.rs::Merge::merge_by_cover` 实现 Ghidra `Merge::mergeByCopy` 的等价语义（仅处理 CPUI_COPY 对，要求 cover 在 COPY 点之外不相交）
  - `src/cover.rs::Cover::intersects_except_at` 是 COPY 合并安全谓词，对应 Ghidra 在 `merge.cc` 中排除合并点的处理
  - `src/action.rs::ActionDatabase::set_default_actions` 已修正流水线顺序：`ActionMergeType` 现位于 `ActionCopyPropagate` 之前（与 Ghidra 一致）
  - 单元测试：`src/cover.rs::tests`（+5 测试，覆盖 disjoint / overlapping / multi-block / 非变异性谓词）
  - curl 反编译样本：`uVar` 引用 129 → 72（-44%）
- 当前限制：
  - Cover 仅按 def/use 块计算，未做 CFG 传递性扩展（Ghidra 会填充中间存活块）
  - 仅实现 `mergeByCopy`，未实现 `mergeAdjacent` / `mergeMultiEntry` / `mergeMarker` / `mergeByDatatype`（仍为桩函数）
  - 未做与 Ghidra 的逐函数 SSA/Cover 对拍，因此**不可宣称**与 Ghidra 完全一致

---

## 5. 运行时验证框架状态

### `src/align
/runtime_verify.rs`
当前
可以合理得出的结论是：

- 项目**已经开始搭建**运行时验证框架
- 其中包含：
  - 验证结果类型
  - 统计信息
  - 差异记录
  - 若干验证入口
- 这说明项目方向明确：希望从“静态像”推进到“行为像”
- 证据来源：
  - `src/align/runtime_verify.rs`
  - `docs/VERIFICATION_GUIDE.md`

### 但必须明确区分
**框架存在 ≠ 验证已完成**

当前不能直接
从框架代码的存在，推出
以下结论：

- 所有 FFI 依赖都已配置完成
- 所有验证入口都已接入稳定的 Ghidra 运行环境
- 所有验证测试都已在真实样本上通过
- 已经形成可靠的自动化 regression parity 体系

---

## 6. 关键未验证项

以下是当前最重要、但仍不能被写成“已完成”的内容。

### 6.1 P-code 生成一致性
**问题**  
Rugra 的 lifting / raw op 注入 / P-code 组织流程，
是否与 Ghidra 对同一条指令生成完全一致，仍需逐点验证。

**尚未可宣称**
- opcode 顺序完全一致
- unique 空间分配策略一致
- 临时 varnode 组织完全一致

- 指令边界上的 P-code 数量完全一致

**结论**
- 当前状态应写为：**待运行时对拍验证**

---

### 6.
2 SSA
 版本
分配一致性
**问题**  
SSA 版本号、Phi 放置、rename 顺序，是反编译正确性的关键环节。

**静态对齐不能替代的原因**
- 即使 `Varnode` 有 `version` 字段
- 即使 `Heritage` 结构已存在
- 也不代表实际 rename 过程与 Ghidra 完全一致

**当前结论**
- 只能写为：**尚未完成可信的运行时 parity 证明**
- 若未做逐函数对拍，严禁写成“已保障一致性”

---

### 6.3 CFG / Dominance / Loop Recovery
**问题**
- 基本块划分
- 前驱后继边
- 支配树
- 回边 / 循环识别

这些都必须通过真实函数进行比对，不能仅凭实现名称或 API 相似度判断。

**当前结论**
- 只能写为：**已有实现基础，运行时一致性待验证**

---

### 6.4 类型传播与高级语义恢复
**问题**
- 类型传播是算法层结果，不是静态结构映射
- 结构体恢复、指针语义、调用约定恢复，均需要样本验证

**当前结论**
- 不能写成“已与 Ghidra 对齐”
- 只能写为：**具备工程实现基础，语义 parity 待实证**

---

### 6.5 最终 C 输出一致性
**问题**
即便前端 lifting 类似，最终输出仍会受到：
- CFG structuring
- 变量合并
- 类型命名
-
 表达式规约
- PrintC 策略

等多因素影响。

**当前结论**
- 当前仓库信息不足以支撑“最终输出与 Ghidra 一致”
- 只能写为：**存在
输出能力 / 正在改进质量，未完成系统级对拍证明**

---

## 7. 当前
推荐用语

今后所有文档中，建议只使用下列可信表述。

### 可以使用
- “已完成静态结构对齐”
- “已建立运行时验证框架”
- “已具备对拍入口 / 验证基础设施”
- “某模块正在推进 Ghid
ra 语义对齐”
- “运行时 parity 尚待验证”
- “当前结论基于仓库可见代码
与文档”

### 不应使用
- “已保障一致性”
- “已与 Ghidra 完全一致”
-
 “SSA 已 100% 对齐”
- “端到端验证
已完成”  
  除非有明确样本、命令、结果、记录支撑

---

## 8. 状态表（按可信度重写）

### 8.1 静态结构对
齐状态

| 模块 / 能力 | 状态 | 说明 |
|-------------|------|------|
| Address / SeqNum | 已建立静态对齐 |
 字段与基础验证存在 |
| Varnode | 已建立静态对齐 | 结构级映射存在 |
| PcodeOp | 已建立静态对齐 | opcode / IO 形态有映射基础 |
| DataType | 已建立静态对齐 | 基本类型与布局语义已有映射 |
| Range / RangeList | 已建立静态对齐 | 范围类逻辑已有基础 |
| Heritage / Block / Action 对齐模块 | 部分建立 | 有工程接轨基础，但不能等同算法 parity |

---

### 8.2 运行时验证状态

| 验证项 | 当前状态 | 说明 |
|
--------|----------|------|
| 常量求值
对拍 | 框架已起步，结果未充分证实 | 不能视为稳定完成 |
| P-code 生成对拍 | 待证实 | 需要真实指令级比对 |
| SSA 版本对拍 | 待
证实 | 关键高风险项 |
| CFG 结构对拍 | 待证实 | 需要基本块、
边、支配关系对比 |
| 端到端 C 输出对拍 | 待证实 | 不能用文档描述替代实验结果 |

---

### 8.3 综合
判断

| 维度 | 结论 |
|------|------|
| 是否已完成静态基础对齐工作 | 是
，已完成一部分 |
| 是否已完成可靠的运行时 parity 证明 | 否 |
| 是否可以宣称与 Ghidra 完全一致 | 否 |
| 当前最准确表述 | 正在从“结构对齐”推进到“行为对齐” |

---

## 9. 下一阶段工作重点

### P0：把“能验证”变成“已验证”
优先事项：

1. 补齐并稳定运行时验证环境
2. 对以下项目建立可重复执行的比对流程：
   - 常量求值
   - 单指令 P-code
   - 单函数 SSA
   - 单函数 CFG
3. 明确记录：
   - 测试样本
   - 命令
   - 结果
   - 差异类型

---

### P0.5：推荐的最小 Ghidra 对齐恢复切入路径
在当前仓库状态下，最适合恢复 Ghidra 对齐工作的方式，不是直接追求端到端大闭环，而是先走**最小、可复现、可局部比对**的路径。

#### 推荐切入顺序
1. **单指令 / 小型指令序列的 P-code 对拍**
2. **小函数级 SSA 版本对拍**
3. **小函数级 CFG 结构对拍**
4. **最后再扩大到样本级输出观察**

#### 为什么先从 P-code 局部对拍开始
按当前仓库可见代码结构判断，以下链路已经具备最小切入基础：

- `src/disasm/x86_lift.rs`
- `src/pcoderaw.rs`
- `src/funcdata.rs`
- `src/align/runtime_verify.rs`
- `src/ffi.rs`

这说明当前最有希望先形成闭环的是：

**指令解码 → raw p-code → 注入 `Funcdata` → 局部比较**

而不是：

**完整用户入口 → 全函数恢复 → 最终 C 输出全面对拍**

#### 推荐的第一批最小验证对象
建议先选择：

- 简单 `mov`
- 简单 `add/sub`
- 简单移位 / 位运算
- 简单条件跳转
- 无复杂调用约定的小函数片段

原因是这些目标：

- 更容易稳定复现
- 更容易定位差异到底发生在 lifting、raw p-code 还是注入阶段
- 更适合把“框架存在”推进成“已有首批真实可比较结果”

#### 第一批最小 P-code 对拍样本（建议按优先级推进）
下面给出一组更具体的第一批样本建议，优先选择那些**当前 `x86_lift.rs` 已明显覆盖、且经过 `inject_raw_ops(...)` 后结构容易观察**的指令或短序列。

##### Sample A：寄存器到寄存器复制
- 代表指令：`mov rbx, rax`
- 优先级：最高
- 目的：
  - 验证寄存器操作数解析
  - 验证 `COPY` raw op 生成
  - 验证输出 varnode / 输入 varnode 的基本组织
- 预期关注点：
  - 是否生成单条 `CPUI_COPY`
  - 输入/输出寄存器映射是否稳定
  - 注入后 op 数量是否与预期一致
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/pcoderaw.rs`
  - `src/funcdata.rs`

##### Sample B：寄存器加立即数
- 代表指令：`add rax, 1`
- 优先级：最高
- 目的：
  - 验证二元算术 raw op 生成
  - 验证立即数是否进入 `Const` 空间
  - 验证 `INT_ADD` 组织是否稳定
- 预期关注点：
  - 是否生成 `CPUI_INT_ADD`
  - 常量输入的 offset / size 是否合理
  - 输出是否正确回写目标寄存器
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/opcodes.rs`
  - `src/funcdata.rs`

##### Sample C：寄存器减立即数
- 代表指令：`sub rax, 8`
- 优先级：高
- 目的：
  - 验证 `CPUI_INT_SUB` 生成
  - 与 `add` 配对，确认同类二元算术路径一致性
- 预期关注点：
  - opcode 是否正确
  - 输入顺序是否稳定
  - 注入后是否仍保持单条核心算术 op
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/opcodes.rs`

##### Sample D：位运算
- 代表指令：
  - `and rax, rbx`
  - `or rax, rbx`
  - `xor rax, rbx`
- 优先级：高
- 目的：
  - 验证多个常见逻辑 opcode 的映射
  - 确认不同 mnemonic 是否稳定映射到对应 `OpCode`
- 预期关注点：
  - `CPUI_INT_AND` / `CPUI_INT_OR` / `CPUI_INT_XOR`
  - 输入输出组织方式是否与 `add/sub` 路径一致
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/opcodes.rs`

##### Sample E：位移
- 代表指令：
  - `shl rax, 1`
  - `shr rax, 1`
  - `sar rax, 1`
- 优先级：高
- 目的：
  - 验证 shift 类指令到 `INT_LEFT` / `INT_RIGHT` / `INT_SRIGHT` 的映射
  - 观察立即数位移是否稳定落到常量输入
- 预期关注点：
  - opcode 映射是否准确
  - 立即数输入大小是否合理
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/opcodes.rs`

##### Sample F：内存加载
- 代表指令：`mov rax, [rbx]`
- 优先级：中高
- 目的：
  - 验证 memory operand 解析
  - 验证地址计算 + `LOAD` 生成
- 预期关注点：
  - 是否先生成地址相关 `INT_ADD/INT_MULT`（如适用）
  - 是否生成 `CPUI_LOAD`
  - RAM space id 是否按当前实现写入输入槽
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/pcoderaw.rs`

##### Sample G：内存写入
- 代表指令：`mov [rbx], rax`
- 优先级：中高
- 目的：
  - 验证 store 路径
  - 确认 `emit_store(...)` 的 raw op 组织
- 预期关注点：
  - 是否生成 `CPUI_STORE`
  - 地址输入、值输入是否顺序稳定
  - `Funcdata::inject_raw_ops(...)` 后的块内 op 序列是否可预测
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`

##### Sample H：简单条件跳转
- 代表指令：`je label` / `jne label`
- 优先级：中
- 目的：
  - 验证控制流终结符是否进入 `is_block_terminator()` 路径
  - 验证 block 边界构建的最小行为
- 预期关注点：
  - 是否出现 `CPUI_CBRANCH`
  - `inject_raw_ops(...)` 后 basic block 是否正确切分
- 证据来源：
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/opcodes.rs`

##### Sample I：短指令序列
- 代表序列：
  - `mov rax, rbx`
  - `add rax, 1`
  - `sub rax, 2`
- 优先级：中
- 目的：
  - 在不引入 CFG / SSA 复杂度的前提下，验证多条连续 raw op 注入后的顺序稳定性
- 预期关注点：
  - `PcodeOpRaw` 顺序
  - `PcodeOpBank` 中的创建顺序
  - 同一 basic block 内 op 序列是否与输入一致
- 证据来源：
  - `src/pcoderaw.rs`
  - `src/funcdata.rs`

#### 当前不建议作为第一恢复目标的方向
在没有局部闭环前，不建议直接把主要精力放在：

- 大样本最终 C 输出对拍
- 复杂控制流结构化质量对比
- “是否已经接近 Ghidra UI 输出风格”这类主观评估
- 重新把 CLI 当成当前主入口

#### 当前恢复对齐工作的判断标准
基于当前文档与代码状态，更合理的恢复标准是：

- 文档基线已基本稳定
- 高风险主线 API 文档已完成大部分状态标注
- 历史高风险日志已开始补复核提示
- 状态类文档已开始要求证据来源
- 因此可以恢复**小步、证据驱动、局部闭环优先**的 Ghidra 对齐工作

换句话说：

> 当前已经可以开始继续去对齐 Ghidra，  
> 但应从“最小 P-code 局部对拍闭环”恢复，而不是直接跳回“大范围端到端完成度推进”。

#### 后续记录要求
当后续开始按这一路径恢复对齐推进时，建议每一轮至少记录：

- 目标指令或目标函数
- Rugra 侧入口文件
- Ghidra 侧参考入口或比较方式
- 当前比较层级（P-code / SSA / CFG / 输出）
- 已知差异
- 下一步打算消除的最小偏差

---

### P1：建立样本级证据
至少应针对真实样本建立记录，例如：
- 小型 ELF 样本
- 控制流复杂样本
- 含调用与栈变量样本
- 较大的真实程序片段

每次验证结果都应写入：
- 通过范围
- 未通过范围
- 是否语义等价
- 是否只是命名/格式差异

---

### P2：把结论回写到文档系统
所有对齐进度更新都应同步影响：
- `CURRENT_STATUS.md`
- `GAP_ANALYSIS.md`
- `docs/VERIFICATION_GUIDE.md`
- `docs/PROJECT_STRUCTURE.md`
- `docs/AgentLog/`

避免再次出现：
- 框架存在就写成“已完成”
- 静态对齐写成“运行时一致”
- 少量样本成功写成“全面完成”

---

## 10. 文档维护规则

今后更新本文件时，必须遵循以下规则：

1. **每一项结论都必须标明层级**
   - 静态结构对齐
   - 运行时局部对拍
   - 端到端验证

2. **没有实验记录，不写完成**
   - 尤其是 SSA / CFG / P-code / 输出一致性

3. **不要用勾选框制造“已完成错觉”**
   - 如果只是“有实现”或“有入口”，应写成：
     - 已实现框架
     - 待验证
     - 部分验证

4. **出现差异时要记录差异，不要抹平**
   - 对齐工作的价值在于发现差异，而不是掩盖差异

---

## 11
. 当前一句话结论

**Rugra 当前已经具备一批面向 Ghidra 的静态对齐基础与运行时验证框架雏形，但尚不能根据现有仓库信息宣称已完成运行时 parity 或
端到端一致性；最准确的状态是：结构
对齐在推进，行为对齐仍待系统验证。**

## 12. Ghidra 参考输出语义对比（2026-06-23）

本节记录首次使用可运行 Ghidra（11.3.2 headless）对 curl 二进制生成参考反编译输出，并与 Rugra 输出做逐函数语义对比的结果。

### 证据来源
- Ghidra 参考输出：`tools/ghidra_decompile_all.py` 脚本运行 `ghidra_11.3.2` headless 生成
- Rugra 输出：`examples/curl_decompile` + `examples/httpd_decompile`
- gcc 语法通过率：53/53（100%）— 但这只是语法合法性，不等于语义等价

### 系统性语义差距（按优先级）

#### 差距 1：参数类型恢复缺失（最高优先级）
- Ghidra：`int my_fwrite(void *buffer, size_t size, size_t nmemb, FILE *stream)`
- Rugra：`int my_fwrite(long param_1, long param_2, long param_3, long param_4)`
- 根因：ActionInferParams 只按 size 给 scalar 类型，不传播指针/结构体类型

#### 差距 2：结构体字段访问未恢复
- Ghidra：`stream->_IO_read_ptr`、`config->url`
- Rugra：`*(long *)(piVar_18 + 0x8)`
- 根因：无结构体布局恢复（Ghidra 用 FILE/Configurable 等已知类型）

#### 差距 3：控制流分支丢失
- Ghidra SetHTTPrequest：`if ((*store != UNSPEC) && (*store != req)) { return SetHTTPrequest(...); }`
- Rugra：只输出 `if (iVar10 == 0) {...}`，丢失 `&&` 分支和 tail call
- 根因：blockaction.rs 控制流结构化不完整，未处理 CBRANCH 级联到 tail call

#### 差距 4：返回值推断缺失
- Ghidra：`return -1;` / `return 0;`
- Rugra：`return;`（void）
- 根因：未从 RETURN op 的输入推断返回值

#### 差距 5：变量名传播缺失
- Ghidra：`__s, config, glob, pOVar15`
- Rugra：`lVar_0, piVar_18, struct1`
- 根因：无类型库/调试符号集成

### 结论
gcc 语法 100% 是必要条件但非充分条件。语义对齐 Ghidra 需要前端架构改进（类型传播、结构体恢复、控制流结构化），是 `GAP_ANALYSIS.md` 列出的长期工作。

### 量化对比基线（2026-06-23）

首次与可运行 Ghidra 11.3.2 的量化语义对比：

| 维度 | curl | httpd |
|------|------|-------|
| 控制流结构差（if/while/for/switch 计数） | 160 | 168 |
| 返回值差 | 34 | 45 |
| 参数数差 | 13 | 17 |
| gcc 语法通过率 | 53/53 (100%) | 53/53 (100%) |

控制流差距是最大问题（160-168），源于 blockaction.rs 的区域化结构分析不完整。Ghidra 的 ActionBlockStructure 恢复完整 if-else/switch/loop 嵌套，而 Rugra 只做基础检测。

**后续改进路线（按 ROI 排序）**：
1. 控制流结构化（移植 Ghidra blockaction.cc 的区域分析）— 最大差距
2. 返回值推断（已部分修复，继续覆盖 RETURN 前的非 RAX 写入）
3. 参数类型传播（LOAD/STORE 地址反推指针类型）
4. 结构体字段恢复（从指针偏移 + 类型库）
5. 变量名传播（从符号表/类型库）

### 控制流差距根因分析（2026-06-23 深入）

对 getparameter.constprop.0（121 个基本块，Rugra 4 if vs Ghidra 42 if）的深入分析：

**根因**：Rugra 的 `collapse_all`（blockaction.rs）在 121 块上运行后，**块数不变（仍 121）**——没有任何规则匹配。

**Ghidra blockaction.cc 的结构化流程**：
1. `orderLoopBodies` — 循环识别 + 排序
2. `collapseConditions` — `ruleBlockOr`（&&/|| 短路折叠）
3. `collapseInternal` — 反复执行 10+ 规则直到收敛：
   - `ruleBlockGoto` / `ruleBlockCat` / `ruleBlockProperIf` / `ruleBlockIfElse`
   - `ruleBlockWhileDo` / `ruleBlockDoWhile` / `ruleBlockInfLoop`
   - `ruleBlockSwitch` / `ruleCaseFallthru`

**Rugra 当前的 collapse_all**：
- `collapse_loops` — 基础循环检测（自然循环 + CBRANCH latch）
- `collapse_conditions` — 只做简单 Triangle（if-then）和 Diamond（if-then-else），要求 size_in==1 && size_out==1
- `collapse_switches` — BRANCHIND switch 检测
- `collapse_bool_conditions` — &&/|| 折叠

**缺失**：
1. **多轮迭代直到收敛**（Ghidra 反复跑直到 change==false；Rugra 只跑 3 轮固定）
2. **ruleBlockProperIf 通用化**（Rugra 的 Triangle 条件太严格）
3. **ruleBlockIfElse**（完整 if-else 结构化）
4. **ruleBlockWhileDo/DoWhile 的完整实现**
5. **ruleCaseFallthru**（switch case fallthrough 处理）

**改进路线**：移植 Ghidra 的 collapseInternal 到 Rugra blockaction.rs，实现 10+ 规则的多轮迭代。这是缩小控制流差距（128/119）的唯一途径。

**尝试过的 printc 层修复**（递归 Basic 块后继）失败了——破坏 switch 结构（case label 出现在 switch 体外）。控制流结构化必须在 blockaction 层完成，不能在 printc 层 ad-hoc 处理。

### 最终控制流差距状态（2026-06-23 会话结束）

interleaved 规则框架已实现但对复杂 CFG 无额外改善。控制流差距：

| 函数 | Rugra if | Ghidra if | 差距 | 根因 |
|------|----------|-----------|------|------|
| getparameter | 4 | 42 | 38 | 121 块 0 个被结构化 |
| glob_word | 1 | 7 | 6 | 循环+条件嵌套缺失 |
| glob_set | 3 | 7 | 4 | 多入口合并点 |
| main | 28 | 65 | 37 | 复杂 switch/if 嵌套 |

**需要移植的 Ghidra 规则**（按优先级）：
1. `ruleBlockGoto` — 标记不可归约块为 goto（让其它规则能继续）
2. `ruleBlockCat` 链式扩展 — 沿 size_in==1 链合并多个顺序块
3. 循环-条件嵌套 — 先识别循环，在循环体内做条件折叠
4. `ruleCaseFallthru` — switch case fallthrough 处理

这些需要 FlowBlock trait 扩展（支配树、回边、goto 标记接口），是多会话架构工作。

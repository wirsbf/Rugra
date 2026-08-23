# 工程进度日志 (Engineering Progress Log)

**日期 / Date:** 2026-03-15 02:35  
**摘要 / Topic:** Documentation Index Completion, API Status Label Rollout & Historical Log Review Policy  
**关联任务 / Related Tasks:** `docs/TODO_BOARD.md` 中关于文档去失真、总索引建设、API 文档状态标签统一、历史日志复核与状态口径统一的高优先级任务

## 🔄 会话续记：当前主线 API 状态标签补齐 (Current-Mainline API Label Rollout)

在上一轮完成 API 文档状态标签规则建立之后，本轮继续沿着“**先标可信度，再继续审计内容**”的思路推进，把一批仍缺少显式标签、但已经过源码核对的当前主线 API 文档补上统一状态标记。

本轮处理的重点不是重写整批 API 文档主体，而是：

1. **对照当前 `src/` 实际文件再次核实文档对应关系**
2. **为当前主线 API 页补上显式 `已核对（当前有效）` 状态**
3. **缩小“README 已定义标签体系，但单页尚未完全落地”的缺口**
4. **为后续全面 API 审计建立更清晰的已完成边界**

本轮确认并补齐状态标签的当前主线文档包括：

- `docs/api/coreaction.md`
- `docs/api/ruleaction.md`
- `docs/api/blockaction.md`
- `docs/api/fspec.md`
- `docs/api/typeop.md`
- `docs/api/merge.md`
- `docs/api/cover.md`
- `docs/api/space.md`
- `docs/api/address.md`
- `docs/api/opcodes.md`

这些页面现在都显式标记为：

- `已核对（当前有效）`

这一步的价值在于：

- 让读者不再需要从上下文猜测这些页面是否已经过当前源码核实
- 让 `docs/api/README.md` 中的标签体系开始真正落到单页
- 让后续会话更容易区分：
  - 已核对的当前主线页面
  - 尚未补标签的页面
  - 已降级为历史说明的旧架构页面

### 本轮工作特点

与上一轮“高风险主线文档重写 + 旧目录降级”相比，这一轮更偏向**标签落地与边界收口**，具体体现为：

- 不夸大为“API 审计已完成”
- 不把“补状态标签”写成“所有内容都已深度重写”
- 仅把已经重新对照源码的页面标成 `已核对（当前有效）`
- 继续保持“文档可信度标签 ≠ 模块完成度 ≠ 行为验证结论”的口径

### 对 TODO 看板的影响

这一轮进展直接推动了 `docs/TODO_BOARD.md` 中以下方向：

- “按新标签体系逐页补齐状态标记”
- “API 文档状态标签已覆盖主要高风险页面”

但当前仍不能把 API 审计整体标记为完成，因为还有以下事项未收口：

- 仍有部分当前主线 API 页面尚未补齐显式标签
- 仍需建立“主线文档清单 / 历史文档清单”两份更清晰的索引视图
- 历史 `AgentLog` 的复核提示策略虽然已建立口径，但尚未系统回填
- “所有高风险结论都能回链到代码或测试依据”这一目标仍未完全达成

### 本轮后的下一步建议

建议下一轮优先继续以下工作：

1. 继续给剩余当前主线 API 页面补齐显式状态标签
2. 将“已核对（当前有效）/ 历史遗留（仅供参考）”整理成更明确的双清单索引
3. 开始把历史日志复核提示策略逐步回填到更多旧 `AgentLog`
4. 在标签覆盖率进一步稳定后，再继续推进更细粒度的 API 内容核对与证据回链

## 🔄 会话续记：API 标签扫尾与对齐文档覆盖扩展

在继续推进单页状态标签落地时，本轮又完成了一次面向当前主线 API 文档的“扫尾补标”，目标是把此前遗漏的辅助主线页和 `align/` 子目录也纳入统一标签体系。

### 本轮新增补齐的页面

本轮继续显式补上 `已核对（当前有效）` 的页面包括：

- `docs/api/error.md`
- `docs/api/ffi.md`
- `docs/api/disasm/x86_64.md`
- `docs/api/disasm/x86_lift.md`
- `docs/api/align/mod.md`
- `docs/api/align/action.md`
- `docs/api/align/address.md`
- `docs/api/align/block.md`
- `docs/api/align/datatype.md`
- `docs/api/align/heritage.md`
- `docs/api/align/pcodeop.md`
- `docs/api/align/range.md`
- `docs/api/align/varnode.md`

此外，还顺手修正了一处已有文档的小问题：

- `docs/api/printc.md` 中重复出现的状态行已清理

### 这轮补齐的意义

这一步带来的实际收益主要有三点：

1. **把状态标签从“核心主线对象页”继续扩展到“辅助主线页 + 对齐验证页”**
2. **让 `align/` 子目录不再游离于标签体系之外**
3. **进一步缩小“规则已写入 README、但单页覆盖率还不够”的缺口**

经过这一轮补齐后，当前 API 文档体系中，围绕以下方向的主线页已经基本都进入了显式状态标签管理：

- 核心对象层
- Action / Rule / Block 相关层
- Binary / Disasm 输入层
- PrintC 输出层
- FFI / Error 辅助层
- Alignment 验证层

### 当前判断

到这一轮为止，`docs/api/` 中“当前主线高风险页面”的状态标签覆盖率已经明显提高，后续工作重点可以逐步从：

- “先补状态标签”

过渡到：

- “建立主线文档清单 / 历史文档清单双索引”
- “为状态类文档增加证据来源回链”
- “继续扩展历史日志复核提示覆盖”

### 下一步建议

建议下一轮优先转向以下事项：

1. 继续排查是否还有零散当前主线 API 页面未显式标注状态
2. 建立 `docs/api/` 的“当前主线文档清单”与“历史文档清单”双索引视图
3. 继续把历史 `AgentLog` 的复核提示扩展到更多旧日志
4. 为 `CURRENT_STATUS.md`、`ALIGNMENT_PROGRESS.md`、`VERIFICATION_GUIDE.md` 建立证据来源回链规则

## 🔄 会话续记：API 双索引视图推进 (API Dual-Index View Progress)

在主线 API 文档状态标签覆盖率明显提升之后，下一阶段的重点已经不再只是“给单页补标签”，而是让整个 `docs/api/` 目录具备更清晰的**索引可导航性**。

本轮推进的核心目标是把 `docs/api/README.md` 从：

- 只有状态标签规则
- 只有按源码模块大类分组的阅读入口

进一步推进到：

- 能明确区分**当前主线文档**
- 能明确区分**历史遗留文档**
- 能让后续会话快速知道“优先看哪里，哪些不要误当现状”

### 为什么要建立双索引视图

在前几轮清理之后，`docs/api/` 已经出现了两类性质完全不同的文档：

#### 1. 当前主线文档
这些页面已经基本对照当前 `src/` 结构核实，适合作为当前参考入口，例如：

- `lib.md`
- `funcdata.md`
- `op.md`
- `varnode.md`
- `block.md`
- `heritage.md`
- `action.md`
- `coreaction.md`
- `ruleaction.md`
- `blockaction.md`
- `pcoderaw.md`
- `binary/mod.md`
- `disasm/mod.md`
- `printc.md`
- `align/runtime_verify.md`
- 以及最近补齐标签的一批 `align/`、`ffi`、`error`、`disasm` 页面

#### 2. 历史遗留文档
这些页面虽然仍有参考价值，但主要作用是解释旧架构、旧分层或项目演化历史，例如：

- `analysis/`
- `pcode/`
- `codegen/`
- `translator/`
- 以及这些目录下的旧子页

如果没有双索引视图，后续读者仍容易出现两种误判：

- 把旧页误当成当前主线入口
- 不知道哪些当前页已经过核实、哪些历史页只是参考材料

### 双索引视图的直接价值

建立“当前主线文档清单 / 历史文档清单”后，`docs/api/README.md` 将更容易承担以下职责：

1. **告诉读者应该先读哪些页面**
2. **明确哪些页面不能直接当作当前事实**
3. **减少后续会话在旧目录中迷路**
4. **把状态标签体系从“单页级”推进到“目录入口级”**
5. **为后续继续做 API 全量审计提供稳定导航基线**

### 与前几轮工作的衔接关系

这一轮工作并不是替代前面的状态标签补齐，而是建立在前面工作的基础上：

- 前几轮先修主线高风险页
- 然后给主线页补状态标签
- 再给 `align/`、`ffi`、`error`、`disasm` 等辅助页补标签
- 现在才有条件把这些成果整理成**目录级导航结构**

换句话说：

> 没有前面的状态标签落地，双索引视图就会缺少可信分类依据；  
> 有了前面的标签落地，双索引视图才真正具备可维护价值。

### 这轮推进后的下一步建议

建议后续继续按以下顺序推进：

1. 在 `docs/api/README.md` 中落地“当前主线文档清单 / 历史文档清单”
2. 继续排查剩余低风险 API 页面是否仍有漏标状态
3. 在双索引稳定后，再补“证据来源回链”规则
4. 最后再继续扩展历史 `AgentLog` 复核提示覆盖范围

## 🔄 会话续记：最小 P-code 对齐闭环重入分析 (Minimal P-code Alignment Re-entry Analysis)

在文档基线、主线/历史双索引以及状态标签覆盖率基本稳定之后，本轮开始为**重新恢复 Ghidra 对齐工作**做一次最小切入点分析。  
目标不是马上宣称“重新全面开工”，而是先明确：

- 当前代码里哪条链路最适合先恢复
- 哪条链路最小、最容易形成证据闭环
- 哪条链路最不依赖 CLI、最终输出质量和大样本环境

### 第一批最小 P-code 对拍记录模板（草案）

为了避免后续对拍记录再次出现“只写结论、不写输入、不写差异层级”的问题，本轮进一步补出一份**最小 P-code 对拍记录模板**草案。  
这份模板的目标不是替代正式测试框架，而是给下一批工程记录、实验记录和差异归档一个统一的最小结构。

建议后续每条最小对拍记录至少包含以下字段：

1. **样本标识**
   - 例如：`pcode_min_001_mov_reg_reg`
2. **目标层级**
   - `P-code`
   - 若后续扩展，再写 `SSA` / `CFG`
3. **目标指令或指令序列**
   - 例如：`mov rbx, rax`
   - 或：
     - `mov rax, rbx`
     - `add rax, 1`
4. **原始字节**
   - 例如：十六进制机器码字节序列
5. **Rugra 侧入口**
   - `disasm`
   - `x86_lift`
   - `pcoderaw`
   - `Funcdata::inject_raw_ops(...)`
   - `verify_pcode_generation(...)`
6. **参考侧入口 / 对比方式**
   - 当前若仍依赖 FFI 入口，应明确写出是通过何种参考路径进行比较
7. **Rugra 结果摘要**
   - raw op 数量
   - opcode 序列
   - 输入输出组织摘要
8. **参考结果摘要**
   - 当前若尚拿不到完整细节，也应至少记录“计数 / opcode / 可见比较结果”
9. **差异分类**
   - `无差异`
   - `opcode 差异`
   - `输入顺序差异`
   - `输出 varnode 差异`
   - `计数差异`
   - `框架已运行但比较粒度不足`
10. **当前结论**
   - `已可运行`
   - `已可比较`
   - `已发现差异`
   - `当前仍未形成有效比较`
11. **证据来源**
   - 相关源码文件
   - 样本记录
   - 对应日志条目
12. **下一步最小动作**
   - 例如：补齐 opcode 逐项比较
   - 例如：把当前样本从计数比较推进到输入输出逐字段比较

### 三条首批样本记录草案

下面给出三条建议最先使用的模板化样本草案。

#### 样本草案 A：`mov reg, reg`
- **样本标识**：`pcode_min_001_mov_reg_reg`
- **目标层级**：`P-code`
- **目标指令**：`mov rbx, rax`
- **原始字节**：待补充
- **Rugra 侧入口**：
  - `src/disasm/mod.rs`
  - `src/disasm/x86_lift.rs`
  - `src/pcoderaw.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
- **参考侧入口 / 对比方式**：
  - `src/ffi.rs`
  - 当前以局部 P-code 比较入口为准
- **Rugra 结果摘要（预期）**：
  - 生成单条 `CPUI_COPY`
  - 输入为寄存器 varnode
  - 输出为寄存器 varnode
- **差异分类（初始预设）**：
  - 优先检查：`opcode` / `输入输出寄存器映射`
- **当前结论**：
  - 最适合作为第一条最小闭环样本
- **证据来源**：
  - `src/disasm/x86_lift.rs`
  - `src/pcoderaw.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`
- **下一步最小动作**：
  - 补入真实机器码
  - 跑通从 `Instruction` 到 `verify_pcode_generation(...)` 的最短链路

#### 样本草案 B：`add reg, imm`
- **样本标识**：`pcode_min_002_add_reg_imm`
- **目标层级**：`P-code`
- **目标指令**：`add rax, 1`
- **原始字节**：待补充
- **Rugra 结果摘要（预期）**：
  - 生成 `CPUI_INT_ADD`
  - 其中一个输入应为 `AddressSpace::Const`
- **差异分类（初始预设）**：
  - `opcode 差异`
  - `常量输入组织差异`
  - `输入顺序差异`
- **当前结论**：
  - 适合作为第一条算术类样本
- **证据来源**：
  - `src/disasm/x86_lift.rs`
  - `src/opcodes.rs`
  - `src/pcoderaw.rs`
  - `src/funcdata.rs`
- **下一步最小动作**：
  - 确认立即数 size / offset 的实际组织
  - 记录注入后 op 数量与输入槽摘要

#### 样本草案 C：`sub reg, imm`
- **样本标识**：`pcode_min_003_sub_reg_imm`
- **目标层级**：`P-code`
- **目标指令**：`sub rax, 8`
- **原始字节**：待补充
- **Rugra 结果摘要（预期）**：
  - 生成 `CPUI_INT_SUB`
  - 与 `add` 类路径基本对称
- **差异分类（初始预设）**：
  - `opcode 差异`
  - `立即数组织差异`
  - `输出回写差异`
- **当前结论**：
  - 适合作为与 `add` 配套的第二个算术样本
- **证据来源**：
  - `src/disasm/x86_lift.rs`
  - `src/opcodes.rs`
  - `src/funcdata.rs`
- **下一步最小动作**：
  - 和 `add` 样本放在同一批次比较，确认算术路径是否稳定

### 为什么先出模板而不是先下结论
在当前阶段，先补模板的价值比先写“已通过/已失败”更高，因为当前最缺的不是“再多一句判断”，而是：

- 统一记录格式
- 统一差异分类语言
- 统一证据来源写法
- 统一下一步动作表达方式

这能直接降低下一阶段真正恢复 P-code 对拍时的记录混乱度。


### 第一批最小 P-code 对拍样本规划（首轮建议）

结合当前仓库里已经可见的 `Instruction` / `Operand` 结构、`X86Lifter::lift(...)`、`PcodeOpRaw`、`Funcdata::inject_raw_ops(...)` 以及 `verify_pcode_generation(...)` / `rugra_compare_pcode(...)` 入口，当前更适合先固定一批**单条指令或极短指令序列**样本，而不是先追求复杂函数。

建议首轮样本按以下优先级推进：

1. **`mov reg, reg`**
   - 例如：`mov rbx, rax`
   - 价值：
     - 最容易观察 `COPY`
     - 不涉及内存寻址
     - 输入输出都落在寄存器空间，便于先验证 register → raw p-code → injected op 的最短路径

2. **`add reg, imm` / `sub reg, imm`**
   - 例如：`add rax, 1`、`sub rbx, 2`
   - 价值：
     - 覆盖 `INT_ADD` / `INT_SUB`
     - 可以观察常量输入在 `AddressSpace::Const` 下的组织方式
     - 比 `mov` 只多一层算术语义，仍然容易定位偏差

3. **`and/or/xor reg, reg|imm`**
   - 例如：`and rax, rbx`、`xor rcx, 0xff`
   - 价值：
     - 覆盖位运算路径
     - 可验证 opcode 映射和输入顺序
     - 仍然不依赖复杂内存语义

4. **`shl/shr/sar reg, imm`**
   - 例如：`shl rax, 1`、`sar rdx, 2`
   - 价值：
     - 覆盖移位类 opcode
     - 可验证 `INT_LEFT` / `INT_RIGHT` / `INT_SRIGHT`
     - 适合观察立即数处理是否稳定

5. **简单条件跳转前的极短序列**
   - 例如：先构造寄存器值，再接一个简单条件跳转
   - 价值：
     - 用于后续过渡到 `CBRANCH`
     - 但不建议作为第一优先级，在基础算术/复制路径没有稳定前不应先做

### 第一条最小可执行样本说明：`mov rbx, rax`

在现有样本规划中，`mov rbx, rax` 仍然是最适合作为**第一条真正落地执行**的最小对拍样本。  
原因很简单：

- 语义最单纯
- 不涉及内存地址计算
- 不涉及 CFG
- 不涉及 SSA
- 不依赖调用约定
- 最容易把“入口存在”推进成“已有一条真实记录”

#### 当前建议的最小执行链路
针对这条样本，推荐按如下顺序推进：

1. 准备最小机器码字节
2. 通过反汇编层拿到 `Instruction`
3. 用 `X86Lifter::lift(...)` 生成 `PcodeOpRaw`
4. 用 `Funcdata::inject_raw_ops(...)` 注入正式 op / varnode
5. 调用 `verify_pcode_generation(...)`
6. 观察 `rugra_compare_pcode(...)` 是否至少完成入口级比较与差异记录

#### 当前应优先记录的字段
对于第一条样本，建议至少先把以下字段补成真实记录：

- 样本 ID
- 原始字节
- 指令文本
- `Instruction` 摘要
- `PcodeOpRaw` 数量
- `PcodeOpRaw` opcode 摘要
- 注入后 op 数量
- 当前比较入口是否真正被调用
- 当前得到的是：
  - match
  - mismatch
  - 还是只有“入口跑通但比较粒度不足”
- 下一步最小修复动作

#### 当前最可能优先观察的差异
这条样本首轮不应该奢望一次性证明“完全一致”，而应优先回答：

1. 是否真的生成了单条核心 `CPUI_COPY`
2. 输入寄存器是否稳定映射为 `rax`
3. 输出寄存器是否稳定映射为 `rbx`
4. `Funcdata::inject_raw_ops(...)` 后是否没有引入多余噪声 op
5. FFI 比较入口是否已经开始使用当前注入的程序状态

#### 当前最小成功标准
对这条第一样本，当前最小成功标准建议定义为：

> 不是“已经与 Ghidra 完全一致”，  
> 而是“已经能稳定走完整条最小链路，并形成一条可复现、可记录、可继续定位差异的真实样本记录”。

只要这一点成立，后续 `add rax, 1`、`sub rax, 8` 的推进难度就会显著下降。

#### 当前下一步建议
围绕这条样本，后续最值得立即推进的是：

- 补入真实机器码与地址
- 记录第一次真实 `Instruction -> PcodeOpRaw -> injected ops` 结果
- 明确 `verify_pcode_generation(...)` 当前到底比较到了哪一层
- 如果只完成了计数级比较，就把“比较粒度不足”本身记录为当前结果，而不是继续空泛写成“待验证”

#### 当前第一版真实样本草案（基于可见代码）
在当前无法直接执行样本、也无法补入真实运行结果的前提下，先给出一版**基于当前仓库可见代码**能够成立的最小真实草案。  
这不是运行结果，而是把“待填写”项尽量压缩到最少的预填版本，便于下一轮直接落真实记录。

- **样本 ID**：`PCode-Min-001`
- **目标层级**：`P-code`
- **目标指令**：`mov rbx, rax`
- **原始字节**：`48 89 c3`
- **预期汇编文本**：`mov rbx, rax`
- **当前执行入口链路**：
  - `src/disasm/mod.rs`
    - `Instruction`
    - `Operand`
  - `src/disasm/x86_lift.rs`
    - `X86Lifter::lift(...)`
  - `src/pcoderaw.rs`
    - `PcodeOpRaw`
    - `VarnodeRaw`
  - `src/funcdata.rs`
    - `Funcdata::inject_raw_ops(...)`
  - `src/align/runtime_verify.rs`
    - `verify_pcode_generation(...)`
  - `src/ffi.rs`
    - `rugra_compare_pcode(...)`
- **当前根据源码可确认的事实**：
  1. `disasm` 层已经存在 `Instruction` / `Operand` 结构，足以承载单条 `mov` 指令
  2. `X86Lifter::lift(...)` 对 `mov` 分支已有显式处理
  3. 对于寄存器到寄存器的 `mov`，当前路径应优先走：
     - 解析源操作数
     - 解析目标操作数
     - 生成一条 `CPUI_COPY`
  4. `Funcdata::inject_raw_ops(...)` 已存在，并且当前仓库中可见测试已覆盖 simple raw op 注入路径
  5. `verify_pcode_generation(...)` 当前至少具备：
     - op 数量比较
     - mismatch 记录入口
  6. `rugra_compare_pcode(...)` 已存在，但当前更应把它视为“入口已具备”，而不是“已形成完整逐字段比较”
- **当前最合理的预期结果摘要**：
  - `Instruction`：应能表示为 `mov rbx, rax`
  - `raw p-code`：应至少包含一条核心 `CPUI_COPY`
  - `inject_raw_ops(...)` 之后：应至少存在一条与该复制语义对应的正式 op
  - `verify_pcode_generation(...)`：当前最现实目标是得到“可比较 / 可 mismatch 记录”的结果，而不是直接假设完全一致
- **当前差异分类预设**：
  - `尚未真实执行`
  - `入口已存在`
  - `比较粒度可能不足`
- **证据来源**：
  - `src/disasm/mod.rs`
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/pcoderaw.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`
  - `src/funcdata.rs` 中与 `inject_raw_ops(...)` 相关的现有测试
- **当前结论**：
  - `mov rbx, rax` 已经是一个足够具体、足够小、且当前代码路径清楚的第一批最小对拍样本
  - 下一轮只要补上真实运行结果，就可以从“样本草案”升级为“第一条真实局部对拍记录”
- **下一步最小动作**：
  1. 把该样本真正跑过 `Instruction -> X86Lifter::lift(...)`
  2. 记录真实 raw op 数量与 opcode
  3. 记录 `inject_raw_ops(...)` 后的实际 op 数量
  4. 记录 `verify_pcode_generation(...)` 返回的是：
     - `Match`
     - `Mismatch`
     - 还是目前只有入口级行为
  5. 若失败，优先定位失败层级，不直接上升为“Ghidra 对齐整体失败”

### 当前不建议作为第一批样本的对象

首轮不建议优先选择以下类型：

- 带复杂内存寻址的 `mov [base + index*scale + disp], reg`
- 带调用约定影响的 `call`
- 复杂比较链与长分支序列
- 需要同时观察 SSA、CFG、输出层的函数级样本
- 大型真实二进制片段

原因很简单：这些对象会把 lifting、注入、CFG、SSA、输出层问题混在一起，首轮不利于快速形成“最小差异可定位闭环”。

### 当前代码层面的最小执行路径建议

按当前可见实现，更合理的第一条实操路径应是：

1. 构造一条最小 x86-64 指令字节序列
2. 通过反汇编层得到 `Instruction`
3. 用 `X86Lifter::lift(...)` 生成 `Vec<PcodeOpRaw>`
4. 用 `Funcdata::inject_raw_ops(...)` 注入正式 op / varnode / block 容器
5. 调用 `verify_pcode_generation(...)` 做局部比较
6. 通过 `rugra_compare_pcode(...)` 记录差异或确认当前只是计数/入口级比较

### 当前最可能卡住的点（首轮预判）

首轮最可能遇到的问题包括：

1. **`verify_pcode_generation(...)` 目前更接近“入口存在 + 基础计数比较”**
   - 当前实现里真正传给 FFI 比较的内容仍较简化
   - 说明首轮闭环可能先做到“能跑通入口 + 能记录 mismatch”，而不是立刻得到高质量逐字段比较

2. **`rugra_compare_pcode(...)` 需要 `CURRENT_PROGRAM` 已正确准备**
   - 如果没有先把 `Funcdata` 正确放入比较上下文，FFI 侧比较入口不会产生有效结果

3. **opcode 映射与 lifter 输出是否完全对齐仍待验证**
   - 这正是首轮样本的主要目的之一
   - 因此不应假设首批样本天然会通过

4. **内存型 operand 应延后**
   - 当前 `x86_lift.rs` 对内存地址计算会额外发出 `INT_ADD` / `INT_MULT` / `LOAD` / `STORE`
   - 这会显著增加首轮差异定位难度

### 当前最值得先实现的“第一批闭环目标”

如果把恢复 Ghidra 对齐工作的第一步压缩成一句话，那最合理的目标应是：

> 先让 `mov reg, reg` 与 `add/sub reg, imm` 这类最小样本，能够稳定走完  
> `Instruction -> PcodeOpRaw -> Funcdata injected ops -> verify_pcode_generation()`  
> 这条链路，并能输出有意义的通过/失败记录。

只要这个目标达成，项目就不再只是“有框架”，而是开始拥有**第一批真实可复现的 P-code 局部对拍证据**。

### 为什么优先选择最小 P-code 闭环
从当前仓库状态看，若直接从“端到端输出”或“大样本最终 C 结果”恢复对齐，会同时受到太多因素影响：

- lifting 语义
- raw p-code 组织
- `Funcdata` 注入
- SSA
- CFG
- 变量合并
- 类型传播
- `PrintC` 输出策略

这会导致一旦出现偏差，很难快速定位问题属于哪一层。  
因此，更合理的恢复方式是先选择一条**局部、可控、可证据回链**的最小闭环。

当前最适合的切入点是：

> **单条指令 / 小型指令序列的 P-code 局部对拍**

### 当前代码里已经具备的最小闭环基础
按当前仓库可见源码，最适合组成这条最小闭环的入口包括：

1. `src/disasm/x86_lift.rs`
   - 负责把 x86-64 指令提升为 `PcodeOpRaw`
2. `src/pcoderaw.rs`
   - 负责承载 raw p-code 表示
3. `src/funcdata.rs`
   - 提供 `inject_raw_ops(...)`，把 raw p-code 转成正式函数级图结构
4. `src/align/runtime_verify.rs`
   - 已存在 `verify_pcode_generation(...)` 等运行时验证入口
5. `src/ffi.rs`
   - 已存在 `rugra_compare_pcode(...)` 与 opcode 映射等 FFI 比较基础

这说明当前并不是“还没有入口”，而是：

- 入口已经存在
- 框架已经存在
- 但还缺一条**明确、聚焦、真正被拿来反复执行的最小对拍闭环**

### 为什么这条链路比其它切入点更合适
相比先做 SSA / CFG / 最终输出，这条最小 P-code 对拍链路有几个优势：

#### 1. 责任边界更清晰
它主要关注：

- 指令提升结果
- raw op 数量
- opcode 序列
- 输入输出组织

问题更容易定位到 lifting / raw p-code / 注入层，而不会立刻混入输出层噪声。

#### 2. 对样本规模要求更低
它不需要先准备复杂真实程序或完整 CLI 流程。  
单条指令、小函数、固定样本都可以作为起点。

#### 3. 更容易形成“第一批可信证据”
相比“最终结果看起来更像 C”，单条指令或小型序列的 P-code 对拍更容易写出：

- 输入是什么
- Rugra 产出什么
- 参考实现产出什么
- 差异在哪
- 是否通过

这更适合作为下一阶段的第一批证据链。

### 当前恢复对齐工作的判断
结合本轮前后的文档治理结果，现在对“什么时候可以开始继续对齐 Ghidra”的更准确回答是：

- **现在已经可以开始恢复**
- 但应采用“文档基线已基本稳定 + 从最小可验证闭环开始”的方式恢复
- 不建议一上来就恢复“大样本最终输出质量追平”这类高耦合目标

更具体地说，当前最合理的恢复路径应是：

1. 先固定一批最小 x86-64 指令样本
2. 对这些样本建立 raw p-code / `Funcdata` 注入后的局部比较
3. 通过 `runtime_verify.rs` 与 `ffi.rs` 的现有入口，逐步把 P-code 局部对拍真正跑起来
4. 等第一批局部对拍结果稳定后，再扩展到 SSA / CFG
5. 最后再回到最终输出质量比较

### 这轮分析的结论
本轮最重要的结论不是“对齐已经恢复”，而是：

> **当前最适合恢复 Ghidra 对齐推进的切入点，已经可以明确锁定为“最小 P-code 局部对拍闭环”。**

这条链路当前已经具备代码级基础，接下来最值得做的不是继续泛泛讨论“还差很多”，而是：

- 固定最小样本
- 明确对拍对象
- 开始让 `verify_pcode_generation(...)` 一类入口承载真实、可复现的比较任务

## 🔄 会话续记：证据来源回链规则推进 (Evidence-Source Policy Rollout)

在主线文档与历史文档的边界逐渐清晰之后，下一步需要解决的问题已经不再只是“这份文档是不是失真”，而是：

> **文档里的关键判断，能不能回指到具体证据。**

这一轮推进的目标，是把“状态类文档应该基于可核实证据写作”从口头原则，进一步推进为可执行的文档治理规则。

### 为什么必须引入证据来源回链

前几轮文档修复虽然已经大幅降低了夸大表述，但如果缺少“证据来源”约束，状态类文档仍然容易出现以下问题：

- 把模块存在写成能力完成
- 把框架存在写成验证完成
- 把局部样例写成整体结论
- 把阶段性工程判断写成长期稳定事实

这些问题最容易出现在以下文档里：

- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- `docs/VERIFICATION_GUIDE.md`

因为这些文档天然带有“总结现状”“判断完成度”“描述验证状态”的性质，一旦没有证据锚点，就最容易重新滑回失真口径。

### 证据来源规则准备覆盖的内容

这一轮计划推进的“证据来源回链”规则，核心是要求高风险结论尽量能回指到以下一种或多种可见依据：

1. **源码文件**
   - 例如某模块真实存在于 `src/` 下
   - 某公共接口真实出现在 `lib.rs` 或对应模块中

2. **测试**
   - 例如某能力已有单元测试或集成测试覆盖
   - 某对齐子模块已有测试入口

3. **示例**
   - 例如 `examples/` 中已有可运行或至少可审阅的入口
   - 但必须明确“示例存在”不等于“能力稳定”

4. **验证框架或验证记录**
   - 例如 `runtime_verify.rs` 中确有某类验证入口
   - 但必须区分“框架存在”和“结果已完成”

5. **实验记录 / 工程日志**
   - 例如某结论只在某次会话或实验里出现过
   - 则应明确这是阶段性记录，而不是当前总保证

### 这轮推进的直接价值

如果这套规则真正落到状态类文档里，会带来几个直接收益：

- **降低状态文档再次失真的概率**
- **让“已实现 / 部分实现 / 待验证”更有依据**
- **让后续继续恢复 Ghidra 对齐工作时，优先级判断更稳**
- **让历史日志、当前状态、API 文档三者之间形成更清晰的证据链**

换句话说，这一步不是纯文档形式优化，而是在给后续重新转回“对齐 Ghidra”的工程工作做地基加固。

### 与恢复 Ghidra 对齐推进的关系

你问“什么时候可以开始继续去对齐 Ghidra”，按当前进度，更准确的判断应当是：

- **现在已经可以开始逐步恢复对齐工作**
- 但更适合采用“文档基线已基本稳定 + 按证据驱动的小步对齐”方式恢复
- 不建议回到“状态口径还没稳、验证边界还混乱时就大规模推进对齐”的做法

也就是说，恢复对齐工作的前提不再是“文档 100% 完美”，而是至少满足以下条件：

1. 主线文档与历史文档边界基本清楚
2. 高风险 API 页面已有显式状态标签
3. 历史高风险日志已开始补复核提示
4. 状态类文档开始引入证据来源约束

按当前这几轮推进结果，前 3 项已经基本具备，第 4 项正是现在要补的内容。  
因此，**在这一轮证据来源规则落地之后，就可以更有把握地恢复对齐 Ghidra 的下一批实质性工作**。

### 下一步建议

建议紧接着做以下动作：

1. 先在：
   - `CURRENT_STATUS.md`
   - `ALIGNMENT_PROGRESS.md`
   - `docs/VERIFICATION_GUIDE.md`
   中加入“证据来源 / Evidence Sources”规则或说明段落
2. 然后把 TODO 看板中“状态类文档增加证据来源要求”推进为进行中
3. 再恢复更聚焦的对齐工作，例如：
   - P-code 局部对拍
   - SSA 版本对拍
   - CFG 结构对拍

这样可以保证下一阶段重新回到对齐工作时，不会重新把“阶段性观察”写成“已完成事实”。


## 📝 代码变更与文档迭代 (Progress & Documentation Changes)

本次会话继续围绕“**先修正文档失真，再推进后续工程判断**”这一原则推进，重点完成了以下几类工作：

1. **补全 `docs/` 总索引**
2. **完成高风险 API 文档第一轮清扫与重写**
3. **把旧 `analysis/`、`pcode/`、`translator/` 子页系统性降级为历史说明**
4. **在 `docs/api/` 中正式建立统一的状态标签规则**
5. **形成历史 `AgentLog` 的复核提示策略草案**

这次工作的核心目标不是增加新功能，而是让 Rugra 的文档系统进一步达到以下状态：

- 可以导航
- 可以区分“当前主线”和“历史遗留”
- 可以区分“接口存在”和“能力已验证”
- 可以让后续会话少走弯路，避免继续围绕旧架构误判当前工程状态
- 可以为后续历史日志复核、验证证据沉淀和状态文档回链建立统一口径

---

### 1. 完成 `docs/` 总索引建设

本次新增：

- `docs/README.md`

该文件现在作为 `rugra/docs/` 目录的统一入口，明确说明了：

#### 1.1 文档系统的阅读顺序
建立了从“项目定位 → 项目结构 → 当前状态 → 验证口径 → API 文档 → 会话日志/实验/方法”的推荐阅读路径，具体引导顺序为：

1. `README.md`
2. `AGENTS.md`
3.
 `docs/PROJECT_STRUCTURE.md`
4. `CURRENT_STATUS.md`
5. `GAP_ANALYSIS.md`
6. `ALIGNMENT_PROGRESS.md`
7. `docs/TODO_BOARD.md`
8. `docs/VERIFICATION_GUIDE.md`
9. `docs/data_contract.md`
10. `docs/api/`
11. `docs/AgentLog/`
12. 其他专题目录

#### 1.2 `docs/` 各目录职责边界
为以下目录建立了清晰定位：

- `docs/api/`
- `docs/AgentLog/`
- `docs/alignment_docs/`
- `docs/workflow/`
- `docs/decisions/`
- `docs/experiments/`
- `docs/method/`
- `docs/branches/`
- `docs/src_ref/`

并明确区分了：

- 总控事实文档
- 专题解释文档
- 过程记录文档

#### 1.3 文档可信度边界
在总索引中明确写入以下原则：

- 以 `src/` 真实代码为准
- 目标态不能写成现状
- 静态结构对齐不能写成运行时一致
- 文档索引必须能回答“代码在哪”“文档在哪”
- 如果文档冲突，应优先修正文档，而不是继续沿用旧说法

这一步的意义在于：**文档系统终于有了统一入口，不再要求后续会话靠零散文档自己摸索结构。**

---

### 2. 完成高风险 API 文档第一轮清扫

本次重点清理的是最容易误导后续会话、最容易把旧架构写成现状的 API 文档入口。

#### 2.1 重写 `docs/api/lib.md`
修复前的主要问题：

- 继续把被注释掉的旧版 `Decompiler` 写成当前公开 API
- 继续沿用旧版“Binary → P-code IR → Analysis → AST → C Code”的完整分层图，和当前 `src/lib.rs` 的实际导出结构不一致
- 继续把 `analysis` / `pcode` / `codegen` 写成当前主导模块
- 混入旧示例代码，容易让人误以为当前高层 facade API 仍可直接使用

修复后的新口径：

- 明确按当前 `src/lib.rs` 的实际 `pub mod` 和 `pub use` 重写
- 重新列出真实公开模块：
  - `address`
  - `space`
  - `varnode`
  - `op`
  - `opcodes`
  - `typeop`
  - `heritage`
  - `fspec`
  - `block`
  - `funcdata`
  - `pcoderaw`
  - `type_system`
  - `prettyprint`
  - `printlanguage`
  - `printc`
  - `action`
  - `coreaction`
  - `ruleaction`
  - `cover`
  - `variable`
  - `merge`
  - `blockaction`
  - `binary`
  - `disasm`
  - `ffi`
  - `align`
- 重新整理真实重导出项：
  - `Error`, `Result`
  - `Address`, `SeqNum`, `Range`, `RangeList`, `RangeProperties`
  - `BlockBasic`, `BlockRef`, `BlockEdge`
  - `Funcdata`
  - `FuncProto`, `ProtoParameter`
  - `AddressSpace`
  - `OpCode`
  - `Architecture`
  - `Datatype`, `TypeMetatype`
  - `VERSION`
- 明确指出：旧版 `Decompiler` 仅能被视为**历史设计痕迹**，当前不是正式公开 API

#### 2.2 重写 `docs/api/funcdata.md`
修复后明确：

- `Funcdata` 是当前 Rugra 的**函数级分析核心上下文**
- 它是当前主链路中的核心工作台：
  - raw p-code 注入落点
  - block / CFG 构建承载体
  - heritage / SSA / ActionDatabase 的主要操作对象
  - 输出层读取的主要函数级数据源
- 把 `inject_raw_ops(...)` 明确写成：
  - “从 raw p-code 进入正式函数级图结构的桥”

#### 2.3 重写 `docs/api/op.md`
修复后明确：

- `op.rs` 是当前 **P-code 操作层** 的核心模块
- `PcodeOp` 是正式 IR 操作节点，不是最终源码语句
- `PcodeOpBank` 是统一管理操作对象的“bank / 仓库”
- 所有 flags 被重新按语义分组解释，不再只是机械罗列

#### 2.4 重写 `docs/api/varnode.md`
修复后明确：

- `Varnode` 是当前 Rugra 的**storage-node / 数据节点模型**
- 它不是最终高层源码变量，而是：
  - 某个地址空间里的值节点
  - `PcodeOp` 的输入/输出载体
  - SSA、类型、命名恢复的附着点
- 明确指出：
  - `unique` 节点通常是内部临时值
  - 有 `version()` 不代表 SSA 已完成验证
  - 不能脱离 `AddressSpace` 去理解 `offset`

#### 2.5 重写 `docs/api/printc.md`
修复后明确：

- `PrintC` 是当前 **C-like 输出层** 的关键实现
- 它负责组织输出文本，而不是替代前序分析
- 它不能被写成“输出质量已经成熟”的证据
- 它和 `PrintLanguage`、`Funcdata`、`Heritage`、`Action` 的关系已经被写清

#### 2.6 重写 `docs/api/align/runtime_verify.md`
修复后明确：

- `runtime_verify.rs` 当前是：
  - **运行时验证基础设施**
  - **框架早期实现**
  - **对拍体系入口层**
- 不能因此推出：
  - FFI 已稳定打通
  - 全量对拍已完成
  - SSA / CFG / P-code 已验证一致
  - 端到端输出等价已成立

---

### 3. 将旧目录索引和旧子页系统性降级为“历史 / 待复核说明”

为了避免后续会话继续把旧目录当当前主线，我把以下几类文档统一降级：

#### 3.1 旧目录索引页
- `docs/api/analysis/mod.md`
- `docs/api/pcode/mod.md`
- `docs/api/codegen/mod.md`
- `docs/api/translator/mod.md`

这些页现在都明确成：

- 旧架构入口
- 只能作为历史设计参考
- 当前主线应优先看：
  - `Funcdata`
  - `PcodeOp`
  - `Varnode`
  - `BlockBasic`
  - `Heritage`
  - `ActionDatabase`
  - `PrintC`

#### 3.2 旧 `analysis/` 子页
本轮已系统降级的旧 `analysis/` 页面包括：

- `docs/api
/analysis/calls.md`
- `docs/api/analysis/dataflow.md`
- `docs/api/analysis/high_variable.md`
- `docs/api/analysis/liveness.md`
- `docs/api/analysis/optimization.md`
- `docs/api/analysis/ssa.md`
- `docs/api/analysis/type_inference.md`
- `docs/api/analysis/type_propagation.md`
- `docs/api/analysis/variables.md`
- `docs/api/analysis/api/mod.md`
- `docs/api/analysis/rules/mod.md`
- `docs/api/analysis/rules/algebra.md`
- `docs/api/analysis/rules/constants.md`
- `docs/api/analysis/rules/dataflow.md`

这些文档现在统一采用以下思路：

- 明确它们属于旧版 `analysis/` 分层
- 强调这些主题本身依然重要，但**旧文档不等于当前实现**
- 不再允许从旧文档直接推导：
  - 当前主线仍按旧目录组织
  - 当前能力已成熟
  - 当前行为已验证
  - 当前结果已与 Ghidra 一致
- 每一页都补了：
  - 当前阅读姿势
  - 更接近当前主线的替代阅读入口
  - 推荐状态标签
  - 如果未来要恢复为“当前有效文档”，需要核对哪些问题

#### 3.3 旧 `pcode/` 与 `translator/` 子页
本轮已统一降级的页面包括：

- `docs/api/pcode/program.md`
- `docs/api/translator/x86_64.md`
- `docs/api/translator/registers.md`

这些页面现在已经统一为：

- 历史 `Program` 架构说明
- 历史 x86-64 翻译层说明
- 历史寄存器映射层说明

并且明确指出：

- 当前主线已经更接近围绕 `Funcdata`、`PcodeOpRaw`、`PcodeOp`、`Varnode`、`Heritage`、`ActionDatabase`、`PrintC` 组织
- 这些旧页现在只能帮助理解项目演化历史
- 不能再作为当前 lifting / IR / 变量恢复 / 输出质量判断的事实依据

---

### 4. 正式建立 API 文档状态标签规则

本轮对 `docs/api/README.md` 做了重要补充，正式加入统一状态标签体系：

- `已核对（当前有效）`
- `部分有效（需对照源码）`
- `历史遗留（仅供参考）`
- `明显过期（待重写）`

并明确说明：

- 状态标签描述的是**文档可信度**
- 不是模块完成度
- 不是行为验证结论
- 不是与 Ghidra 一致性的证明

这一步让后续继续清理 API 文档时，有了统一的状态分类语言，不再需要每轮重新发明一套描述方式。

---

### 5. 当前主线 API 文档开始补统一状态标签格式

在建立状态标签规则之后，本轮也开始把它落实到当前主线 API 文档头部。  
已开始统一补齐到以下页面：

- `docs/api/lib.md`
- `docs/api/funcdata.md`
- `docs/api/op.md`
- `docs/api/varnode.md`
- `docs/api/block.md`
- `docs/api/heritage.md`
- `docs/api/action.md`
- `docs/api/pcoderaw.md`
- `docs/api/binary/mod.md`
- `docs/api/disasm/mod.md`
- `docs/api/printc.md`
- `docs/api/align/runtime_verify.md`
- `docs/api/bin/rugra.md`

这些页面现在开始统一显式写出类似：

- **状态**: 已核对（当前有效）
- **可信度**: 高 / 或相应说明
- **适用范围 / 可信边界**

这一步的意义在于：

- 主线文档不仅内容可信，状态也开始标准化
- 读者不需要再猜“这页是不是已经校过”
- 后续继续做全量 API 审计时，有了统一模板可复制

---

### 6. 历史 `AgentLog` 复核提示策略（草案）

在审阅历史日志时，可以明显看出部分早期日志存在以下风险：

- 使用了阶段性乐观表述
- 把阶段成果写得接近“已完成事实”
- 使用了与当前代码现状不完全一致的旧分层术语
- 某些日志中的完成判断缺少现在意义上的证据回链

为此，本轮形成了一个**历史日志复核提示策略草案**，后续建议采用以下方式处理旧日志：

####
 6.1 复核提示适用范围
对下列类型的历史日志，应考虑增加提示：

- 明显围绕旧架构写作
- 声称“已完成 / 已对齐 / 已打通”但与当前文档基线冲突
- 缺少清晰代码、测试、样本或验证回链
- 容易被后续会话误当成“当前事实”的日志

#### 6.2 推荐提示口径
建议统一追加类似说明：

- “按当时记录，现已纳入历史上下文，具体结论需结合当前代码与总控文档复核”
- “本日志反映当时阶段判断，不直接等同于当前工程现状”
- “若与 `CURRENT_STATUS.md`、`ALIGNMENT_PROGRESS.md` 或当前源码冲突，以当前文档和代码为准”

#### 6.3 处理原则
- **不直接篡改历史过程记录**
- **只追加复核说明**
- **把日志从“当前事实来源”降级为“历史过程记录”**
- **让总控文档继续承担“当前状态事实源”的角色**

这项策略本轮先形成规则，不立即大批改旧日志；后续可按风险优先级逐步执行。

---

## 🔐 架构推进与一致性审计 (Architecture & Alignment Audit)

### 本次文档同步范围
在上一轮基础上，本轮继续新增或重写了以下文件：

- `docs/api/analysis/api/mod.md`
- `docs/api/analysis/rules/mod.md`
- `docs/api/analysis/rules/algebra.md`
- `docs/api/analysis/rules/constants.md`
- `docs/api/analysis/rules/dataflow.md`
- `docs/api/README.md`
- `docs/TODO_BOARD.md`
- 本会话日志文件本身

并继续对主线 API 文档的状态标签格式进行统一化修订，包括：

- `docs/api/lib.md`
- `docs/api/funcdata.md`
- `docs/api/op.md`
- `docs/api/varnode.md`
- `docs/api/block.md`
- `docs/api/heritage.md`
- `docs/api/action.md`
- `docs/api/pcoderaw.md`
- `docs/api/binary/mod.md`
- `docs/api/disasm/mod.md`
- `docs/api/printc.md`
- `docs/api/align/runtime_verify.md`
- `docs/api/bin/rugra.md`

### 本次进一步达成的一致性收敛
本轮继续让以下文档群的口径保持一致：

- `README.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- `docs/VERIFICATION_GUIDE.md`
- `docs/api/README.md`
- 本轮重写的主线 API 文档
- 本轮降级的历史子页文档
- 历史日志复核策略草案

进一步统一到的基线包括：

1. 当前主线围绕 `Funcdata`、`PcodeOp`、`Varnode`、`BlockBasic`、`Heritage`、`ActionDatabase`、`PrintC`
2. 旧 `analysis/`、`pcode/Program`、`codegen/`、`translator/` 分层属于历史说明
3. 旧子页不再被允许继续冒充“当前能力说明”
4. API 文档开始采用统一的“可信度状态标签”概念
5. 历史 `AgentLog` 未来将不再被默认视为“当前事实源”，而会逐步补充复核提示

### 对后续工程推进的实际意义
这一轮最大的价值在于：**文档系统开始从“修正文案”进入“建立长期治理规则”阶段**。  
主要收益包括：

- **旧 `analysis/` 目录已基本系统性降级**，后续误判风险进一步下降
- **状态标签体系已经建立并开始落地**，后续主线文档可信度更可视化
- **历史日志复核策略已经形成**，后续可以逐步把高风险旧日志纳入治理
- **总控文档 / 主线文档 / 历史页 / 日志页之间的边界越来越清晰**

---

## ⏭️ 下一步干涉计划 (Next Steps / Blockers)

### 下一步优先任务
接下来建议按以下顺序继续推进：

1. **继续把状态标签格式补到剩余主线 API 文档**
   - 例如：
     - `coreaction.md`
     - `ruleaction.md`
     - `blockaction.md`
     - `fspec.md`
     - `typeop.md`
     - `merge.md`
     - `cover.md`
     - `space.md`
     - `address.md`
     - `opcodes.md`
   - 目标是让主线页在形式上也完全统一

2. **开始按风险优先级处理历史 `AgentLog`**
   - 优先看：
     - `engineering_progress_2026-03-07_api_docs_completion.md`
     - `engineering_progress_2026-03-08_zero_codegen_pipeline_resolved.md`
     - `engineering_progress_2026-03-08_output_refinement_and_quality.md`
   - 为其追加“按当时记录，需结合当前文档复核”的提示性说明

3. **为状态类总控文档增加“证据来源”回链规则**
   - 让后续 `CURRENT_STATUS.md`、`ALIGNMENT_PROGRESS.md`、`VERIFICATION_GUIDE.md` 的关键结论更明确地回链到：
     - 代码文件
     - 测试
     - 示例
     - 实验记录
     - 差异报告

4. **在文档基线更稳定后，再恢复更细粒度的验证证据链整理**
   - 包括：
     - P-code 对拍
     - SSA 对拍
     - CFG 对拍
     - 输出对比实验

### 当前仍然存在的阻塞点
- 主线 API 文档的状态标签仍未完全铺开到全部页面
- 历史 `AgentLog` 还没有真正逐篇追加复核提示
- 运行时验证链路仍停留在“框架清晰、证据不足”的状态
- “所有高风险结论都能回链到代码或测试依据”这一目标还未完全达成

### 给下一次会话的直接切入点
建议下一次会话从下面顺序继续：

1. 继续补主线 API 文档状态标签
2. 开始给高风险历史 `AgentLog` 追加复核提示
3. 再回头清剩余未统一状态的 API 页面
4. 最后开始设计“证据来源回链”模板

---

## 📌 本次会话结论 (Session Conclusion)

本次会话继续推进了 Rugra 文档修复工作的治理层建设：

- 早前阶段解决“总控文档失真”
- 之后阶段解决“API 文档入口失真”
- 本轮进一步推进“旧子页系统降级 + API 状态标签统一 + 历史日志复核策略建立”
- 并开始把文档治理成果转化为**恢复 Ghidra 对齐工作的最小切入点分析**

本次最重要的成果是：

1. **`analysis/api/` 与 `analysis/rules/` 旧子目录已继续系统性降级为历史说明**
2. **API 文档状态标签规则已经正式写入 `docs/api/README.md`**
3. **当前主线关键 API 文档已经开始统一补状态标签**
4. **历史 `AgentLog` 的复核提示策略已经形成草案**
5. **文档系统已经从“救火式修文档”进入“建立长期治理规则”阶段**
6. **后续恢复 Ghidra 对齐工作的前置条件已经基本具备，当前差的主要是“证据来源回链”这一步**
7. **当前最适合恢复的实质性对齐切入点，已经明确为“最小 P-code 局部对拍闭环”**
8. **第一批最小对拍样本记录模板已经形成，并已给出 `mov` / `add` / `sub` 三条模板化草案**
9. **第一条最小可执行样本已进一步收敛到 `mov rbx, rax`，并明确了最小执行链路、最小成功标准与首批真实记录字段**
10. **已开始为 `mov rbx, rax` 设计首条真实运行记录填写清单，用于把首批局部对拍从“样本草案”推进到“可落记录”**
11. **第一批最小对拍样本规划已经能够聚焦到 `mov`、`add/sub`、位运算与移位这类低耦合指令级对象**

一句话总结：

> 本次会话把 Rugra 的文档治理往前又推了一层：不仅继续清理了旧分析子目录、建立了 API 状态标签规则和历史日志复核策略草案，还进一步明确了状态类文档的证据来源回链要求，锁定了恢复 Ghidra 对齐工作的最小 P-code 闭环切入点，补出了第一批最小对拍样本记录模板，并把第一条可执行样本进一步收敛到 `mov rbx, rax`，同时开始为其补真实运行记录填写清单，从而为下一阶段重新回到实质性对齐工作创造了更稳定的文档基线。

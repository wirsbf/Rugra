# `action.rs` API Reference

**源代码路径**: `src/action.rs`

## 文档状态

- **状态**: 已核对（当前有效，2026-07-02）——mainloop repeatapply 仍未启用（overflow 根因见 action.rs:806 注释，CFT 树遍历迁移后重新评估）
- **文档目标**: 说明 Rugra 当前 `Action` / `Rule` 分析流水线的职责、边界与公开接口
- **可信边界**: 本文档描述的是当前源码可见的 **Action / Rule 管线抽象**，不是对“所有规则都已实现”或“与 Ghidra 行为已完全一致”的证明
- **阅读建议**: 建议结合以下文档一起阅读：
  - `lib.md`
  - `funcdata.md`
  - `op.md`
  - `heritage.md`
  - `coreaction.md`
  - `ruleaction.md`
  - `../data_contract.md`
  - `../../VERIFICATION_GUIDE.md`

---

## 模块定位

`action.rs` 是 Rugra 当前分析流水线中的**动作调度层与规则抽象层**。  
它的核心作用不是直接表示指令或变量，而是定义：

1. 什么是一个“高层分析动作”（`Action`）
2. 什么是一个“局部变换规则”（`Rule`）
3. 如何把多个动作组织成组（`ActionGroup`）
4. 如何把动作注册、查找并形成默认分析流水线（`ActionDatabase`）

从当前主线架构来看，它处于如下位置：

```text
raw semantics / PcodeOp / Varnode / Funcdata
  -> Heritage / block-level preparation
  -> Action / Rule pipeline
  -> additional simplification / normalization / recovery
  -> PrintLanguage / PrintC
```

也就是说：

- `Action` / `Rule` 主要消费 `Funcdata` 及其内部图结构
- 它们对 IR 做分析、规范化、简化、命名或恢复相关处理
- 它们属于“过程层 / 调度层”，不是底层数据模型本身

---

## 设计意图

Rugra 当前的 `action` 层明显受 Ghidra 反编译器中 `Action` / `Rule` 体系启发。  
这一层的价值在于：把复杂的分析流程拆分成可组合、可替换、可局部扩展的步骤。

### 为什么要有 `Action`
如果把所有分析逻辑都堆在一个“大函数”里，会带来这些问题：

- 难以调试
- 难以插拔
- 难以控制执行顺序
- 难以局部替换或扩展
- 难以和 Ghidra 的分阶段流水线建立语义映射

因此，`Action` 的引入让 Rugra 可以：

- 用多个分析阶段组织函数处理流程
- 明确哪些步骤是“管线级动作”
- 为未来对齐和实验提供更清晰的插入点

### 为什么要有 `Rule`
相比 `Action`，`Rule` 更偏向于：

- 局部
- 小规模
- 面向某类操作码
- 以模式匹配和重写为主

它适合处理：

- 小型简化
- 局部等价变换
- 常量传播相关重写
- 某些规范化步骤

---

## 当前职责边界

为了避免文档继续失真，这里明确 `action.rs` 当前**应负责**和**不应负责**的内容。

### 应负责
- 定义 Action 抽象
- 定义 Rule 抽象
- 组织 ActionGroup
- 管理 ActionDatabase
- 提供默认动作流水线入口
- 为后续分析和变换建立统一执行框架

### 不应负责
- 直接定义底层 IR 节点（这是 `op.rs` / `varnode.rs` 的职责）
- 直接定义 SSA 数据结构（这是 `heritage.rs` 的重点）
- 直接负责最终 C 文本输出（这是 `printlanguage.rs` / `printc.rs` 的职责）
- 单独证明所有分析步骤都已完整落地
- 单独证明当前动作序列已与 Ghidra 完全一致

---

## 与其他模块的关系

### 与 `Funcdata`
`Action` / `Rule` 体系最主要的工作对象通常是 `Funcdata`。  
也就是说，这一层不是围绕裸 `PcodeOp` 序列孤立运作，而是围绕**函数级分析上下文**来工作。

### 与 `heritage.rs`
`heritage` 更偏向 SSA / heritage 构建与相关准备。  
`action` 层则更像是在这些基础上组织进一步的分析与变换。

### 与 `coreaction.rs`
`coreaction.rs` 更可能承载一批“核心动作实现”。  
`action.rs` 则更偏向定义抽象和调度骨架。

### 与 `ruleaction.rs`
`ruleaction.rs` 更可能承载规则型动作或规则应用实现。  
`action.rs` 则是这套体系的上层抽象入口。

### 与 `printlanguage.rs` / `printc.rs`
`Action` / `Rule` 的目标之一，是让函数级语义在进入打印层前尽量变得：

- 更稳定
- 更规范
- 更适合恢复
- 更适合输出

但打印本身不属于 `action.rs` 的职责。

---

## 导出的公共 API

---

## `pub trait Action`

`Action` 是当前 Rugra 中“高层分析动作”的基础抽象。

### 角色
它表示一个**面向函数级上下文的分析或变换步骤**。  
一个 `Action` 通常不是只改一条操作，而是代表一个更完整的阶段，例如：

- 命名恢复相关动作
- DCE 相关动作
- copy merge 相关动作
- 某类规范化过程
- 一组规则的应用包装

### 当前应如何理解
你可以把 `Action` 理解为：

> “对 `Funcdata` 做一次有明确目的的阶段性处理。”

而不是：

> “任意一条局部 rewrite 规则。”

### 设计意义
有了 `Action` trait 之后，Rugra 可以：

- 把分析阶段模块化
- 让不同动作可注册、可替换
- 通过名字或顺序组织完整流水线
- 更接近 Ghidra 的动作数据库设计思路

### 文档边界
`Action` trait 的存在说明**动作调度框架已存在**，但不等于：

- 所有动作都已实现
- 所有动作都已稳定
- 当前默认动作集就是最优或最终版本
- 已与 Ghidra 当前版本动作序列完全一致

---

## `pub trait Rule`

`Rule` 是当前 Rugra 中“局部变换规则”的基础抽象。

### 角色
它通常表示一个更小粒度的规则，往往针对：

- 某类 `OpCode`
- 某种局部图模式
- 某种可证明安全的局部重写
- 某种局部简化或规范化

### 与 `Action` 的区别
可以粗略理解为：

- `Action`：较高层、阶段性、面向整体函数上下文
- `Rule`：较低层、局部性、偏模式匹配和局部重写

### 当前典型用途
规则系统适合承载以下内容：

- 算术简化
- 常量折叠相关变换
- 某些无意义中间节点消除
- 局部逻辑规约
- 为打印层准备更简洁 IR

### 当前文档边界
`Rule` trait 的存在不应被写成：

- 所有规则都已完备
- 规则库已经非常丰富
- 当前局部优化已足以达到成熟反编译器质量
- 规则执行结果已全部通过行为级对拍

---

## `pub struct ActionGroup`

`ActionGroup` 用于把多个 `Action` 组织成一个逻辑组。

### 角色
它的作用是把若干动作聚合在一起，以便：

- 按组执行
- 形成阶段性动作集合
- 让某类动作可以统一编排
- 方便默认流水线装配

### 适合理解为
你可以把它理解为：

> “一组按逻辑归类的分析动作容器。”

而不是：

> “全局唯一调度器”。

### 使用价值
当动作数量变多时，直接平铺会带来管理困难。  
`ActionGroup` 可以帮助：

- 明确某几步属于同一个阶段
- 做更清晰的流程分组
- 为默认动作集构建提供中间组织层

---

### `pub fn new(name: &str) -> Self`

创建一个新的动作组。

#### 参数
- `name`: 动作组名称

#### 作用
为一组相关
动作建立一个具名容器。

#### 典型用途
- 构造某个分析阶段的动作组
- 在默认流水线中按名字组织动作阶段
- 在调试时更方便识别当前执行的动作组

---

### `pub fn add_action(&mut self, action: Box<dyn Action>)`

向动作组中添加一个动作。

#### 参数
- `action`: 一个实现了 `Action` 的动作对象

#### 作用
把某个动作注册到当前组中，以便后续统一执行。

#### 说明
这说明当前动作体系采用的是：

- 动态分发
- trait object
- 运行时组合

这种设计更适合做：

- 插拔
- 实验
- 分阶段装配
- 与不同动作实现解耦

---

## `pub struct ActionDatabase`

`ActionDatabase` 是当前 Rugra 动作体系中最关键的管理对象之一。

### 角色
它负责统一管理已注册动作，并提供默认分析动作集的构建和访问入口。

从概念上可以把它理解为：

> “整个函数级动作流水线的注册表 / 调度入口 / 默认动作集容器。”

### 典型职责
- 注册动作
- 按名称查找动作
- 建立默认动作集
- 为高层分析流程提供统一入口

### 当前在架构中的意义
`ActionDatabase` 的存在非常重要，因为它意味着 Rugra 当前不再把分析阶段写成“硬编码大流程”，而是在向：

- 可注册
- 可组合
- 可扩展
- 可对齐
- 可阶段化

的动作数据库设计靠拢。

### 但要注意
`ActionDatabase` 的存在不等于：

- 默认动作链已经全部成熟
- 当前动作顺序已经稳定到可视作最终答案
- 所有动作都已经高质量实现
- 已经完成与 Ghidra 动作库的逐项等价验证

---

### `pub fn new() -> Self`

创建一个新的动作数据库。

#### 作用
初始化一个空的 `ActionDatabase`。

#### 典型用途
- 测试中手动装配动作集
- 构建自定义动作管线
- 从零注册动作后再执行

---

### `pub fn register_action(&mut self, action: Box<dyn Action>)`

向数据库中注册一个动作。

#### 参数
- `action`: 一个实现了 `Action` 的动作对象

#### 作用
把动作放入数据库中，供后续查找或执行。

#### 设计意义
这说明动作系统不是硬编码绑定的，而是允许：

- 动态装配
- 试验性添加
- 定制动作集
- 分场景选择动作链

---

### `pub fn get_action(&self, name: &str) -> Option<&dyn Action>`

按名称获取动作。

#### 参数
- `name`: 动作名称

#### 返回
- 找到时返回对应动作的只读引用
- 未找到时返回 `None`

#### 作用
提供按名字访问动作的能力，便于：

- 调试
- 检查默认动作集
- 做定向调用或验证
- 构建更复杂的调度逻辑

#### 注意事项
按名称查找动作本身很有用，但名称存在不代表：
- 动作一定已经在当前主线中执行
- 动作一定已经稳定可用
- 同名动作的行为已经最终定型

---

### `pub fn set_default_actions(&mut self)`

建立默认动作集。

### 作用
向当前 `ActionDatabase` 中填充默认分析动作集合。

### 当前意义
这是当前动作系统中最重要的“默认流水线入口”之一。  
它体现了项目已经开始把“函数分析阶段”收敛成一套默认动作顺序。

### 更准确的理解
当前应把它理解为：

> “为当前 Rugra 架构建立一套默认动作装配方案。”

而不是：

> “已经完成、不可更改、与 Ghidra 全等的最终动作链。”

### 为什么这个接口重要
因为它直接影响：

- 哪些分析步骤默认会运行
- 顺序如何组织
- 是否更容易得到可打印的 IR
- 后续输出质量的基础状态

---

## 动作执行结果常量

本模块公开了一组整型常量，用于表达动作执行后的结果状态。

### `pub const NO_CHANGE: i32 = 0`
表示本次动作执行后**没有产生变化**。

#### 典型语义
- 当前动作检查过了，但无需修改
- 对当前函数上下文没有带来有效变换
- 可用于调度器判断是否继续推进某些迭代逻辑

---

### `pub const CHANGE: i32 = 1`
表示本次动作执行后**产生了变化**。

#### 典型语义
- IR 被改写
- 节点状态发生变化
- 某些结构被重建或清理
- 后续阶段可能需要重新评估某些条件

---

### `pub const RESTART: i32 = 2`
表示本次动作执行后需要**
重新开始某类流程**。

#### 典型语义
这通常用于更复杂的调度场景，例如：

- 某些变换改变了前提条件
- 需要重新扫描规则
- 需要重新执行某些阶段
- 当前迭代已不适合继续沿用原状态推进

### 说明
`RESTART` 的存在说明动作调度并不总是线性的。  
某些动作可能会让整个局部分析状态发生较大变化，从而需要重新进入某一轮流程。

---

## 当前主线中如何理解 Action / Rule 流水线

结合当前架构，`Action` / `Rule` 流水线更适合被理解为：

```text
Funcdata ready
  -> default actions prepared in ActionDatabase
  -> actions run in configured sequence
  -> some actions may apply local rules
  -> IR becomes more stable / simpler / more printable
  -> output stage consumes the result
```

也就是说：

- `Funcdata` 提供上下文
- `ActionDatabase` 提供组织方式
- `Action` 提供阶段性处理
- `Rule` 提供局部改写
- `PrintC` 等输出层消费最终结果

---

## 当前应避免的误解

### 1. 有 `ActionDatabase` 不等于默认动作链已经最终成熟
这
只能说明当前项目已经有了“动作数据库式”组织结构。

### 2. 有 `Rule` trait 不等于局部规则库已经完备
规则库是否足够丰富、是否覆盖关键模式，要看具体实现与测试。

### 3. 动作存在不等于行为已验证
即使某个动作已注册，也不能自动推出：
- 它已通过运行时对拍
- 它与 Ghidra 行为一致
- 它不会引入输出回归

### 4. 调度层不等于结果质量本身
动作体系是“过程组织层”，不是最终输出质量的唯一决定因素。

---

## 与 `coreaction.rs` / `ruleaction.rs` 的分工建议

虽然真正实现细节应以源码为准，但从文档层面建议这样理解：

- `action.rs`
  - 定义抽象
  - 定义数据库
  - 定义动作组和执行结果常量
- `coreaction.rs`
  - 承载较核心、较大粒度的动作实现
- `ruleaction.rs`
  - 承载基于规则的局部重写实现

这种理解方式更符合当前主线的职责划分，也比旧式笼统描述更不容易误导。

---

## 推荐联动阅读

若你正在理解当前 Rugra 的动作管线，建议继续阅读：

1. `funcdata.md`
2. `op.md`
3. `varnode.md`
4. `heritage.md`
5. `coreaction.md`
6. `ruleaction.md`
7. `blockaction.md`
8. `printc.md`
9. `../VERIFICATION_GUIDE.md`

---

## 文档维护建议

后续若继续维护 `action.rs` 的 API 文档，建议同步关注以下变化：

- `Action` / `Rule` trait 的签名是否变化
- `ActionGroup` 是否新增执行逻辑
- `ActionDatabase` 是否新增默认构建入口
- 默认动作集是否发生结构变化
- 动作执行状态常量是否扩展
- `coreaction` / `ruleaction` 的分工是否调整

同时应避免再次把以下内容写成既成事实：

- “默认动作集已经完全成熟”
- “当前动作顺序已经与 Ghidra 一致”
- “规则系统已经足以覆盖所有关键优化”
- “动作数据库存在就说明分析流水线已稳定收敛”

---

## 一句话总结

`action.rs` 是 Rugra 当前 **Action / Rule 分析流水线的抽象与调度入口**：它定义了什么是动作、什么是规则、如何把动作组织成组、如何通过数据库建立默认分析管线。它是当前主线架构中非常关键的过程组织层，但不应被文档夸大成“所有分析能力已成熟”或“与 Ghidra 动作体系已完全一致”的证明。
### 2026-06-24：ActionTypePropagate 集成

- ActionTypePropagate 在 ActionCopyPropagate 之后运行，保守标记 struct pointer varnode。

### 2026-06-27（会话2）：ActionConditionalExe 接入主管线

- `ActionConditionalExe`（crate::condexe）注册在 `decompile` group 的 `ActionDeadCode` 之后、`ActionBlockStructure` 之前，对应 Ghidra coreaction.cc:5675 mainloop 顺序。条件执行消除（condexe.cc:712）在结构化前折叠冗余 CBRANCH 汇合。

### 2026-07-02：ActionInferTypes 接入 mainloop（对齐 coreaction.cc:5508）

- `ActionInferTypes`（coreaction.cc:5508 "typerecovery"）现注册在 mainloop 的 `ActionRestructureVarnode` 之后、`ActionConditionalExe` 之前，faithful to Ghidra 注册顺序。此前它**只有实现没有注册**，导致类型恢复从不执行，所有 Unique varnode 的 `vn.v_type = None`，`printc::maybe_apply_type_prefix` 无法升级前缀。
- 效果（curl）：uVarN 453→0（全部升级为 lVar/iVar/sVar/bVar 等类型前缀），lVar_etc 346→474（接近 Ghidra 481）。pcVar_etc 81（Ghidra 246）—— 指针类型恢复仍弱，是类型系统下一步。
- 自限 7 轮（coreaction.cc:5411 `local_count >= 7` 停止），无收敛警告，957/957 测试通过。
- 依赖 `ActionStartTypes`（build_full_pipeline_actions，coreaction.cc:5687）先 `set_type_recovery_started()`，否则 InferTypes 立即 NO_CHANGE。

### 2026-06-27（会话3 续）：ActionRestructureVarnode 接入主管线

- `ActionRestructureVarnode`（coreaction.cc:5505 "localrecovery"）现注册在 `decompile` group 的 `ActionDeadCode` 之后、`ActionConditionalExe` 之前。此前它**未接入**，导致 `fd.scope` 永远为 None，printc 的 `get_stack_variable_name` 永远找不到栈变量名 → uVar 碎片。接入后 scope 被构建，local_ 统计从 81→78（curl）。**G3 剩余**：多数函数 gather_spacebase 收集到 0 hints，根因是栈访问用 RBP/param 指针而非 RSP 直派，需扩展 spacebase 基址识别 + 修复 SSA def 断链。

### 2026-06-29：ActionMarkType 移到 dead-code 之后（对齐 Ghidra 管线顺序）

- `ActionMergeType` 此前注册在 `CopyPropagate` **之前**（action.rs 416），违反 Ghidra 顺序（coreaction.cc:5682 deadcode → 5718-5729 merge 阶段）。后果：merge 在 copy-prop/dead-code 删除 op 之前建立 `high.instances`，之后这些 instances 永不更新（copy-prop/dead-code 不清理），printc 拿到陈旧 instances → 自建 4 套 map 重建 def 关系。
- 现顺序：`CopyPropagate → TypePropagate → CallParams → RestrictLocal → DeadCode → ActionMergeType → MarkExplicit → MarkImplied → RestructureVarnode`。MarkExplicit/MarkImplied 在 MergeType 之后（Ghidra 的 MergeRequired 在 MarkImplied 前建 high，Rugra 的 merge_all 合并了 MergeRequired+MergeType，故 MarkImplied 跟在 merge_all 后）。配合 `Merge::is_live_varnode`（merge.rs）跳过死 varnode，`high.instances` 现反映 dead-code 后的 varnode 集，成为 printc 可信的权威来源。这是 P0 "声明却未赋值" 症状的根因修复（详见 `docs/alignment_docs/P0_DEF_CHAIN_DIAGNOSIS_2026-06-29.md`）。
- **implied 机制接入**（2026-06-29）：MarkImplied 用 checkImpliedCover（cover 相交）标记 implied varnode；printc 的 emit_block_ops 跳过 implied-output 的 op（对齐 printc.cc:2704），push_varnode 对 implied varnode 递归 inline 其 def 表达式（recurse 等价）。这是 Ghidra 控制内联的权威机制，替代 printc 自造的 4 套 map。
- curl 审计保持 24/24；`debug_my_fwrite` 中间变量（如 `piVar1`/`lVar3`）被正确内联。已知调优项：部分函数有重复变量声明（块内 shadow，gcc 允许但影响可读性）。

### 2026-06-29：ActionFuncLink 接入主管线（在 ActionHeritage 之前）

- `ActionFuncLink` 注册在 decompile_group 的 `ActionStart` 之后、`ActionHeritage` **之前**（对齐 Ghidra coreaction.cc:5484 FuncLink → 5492 Heritage）。它在 ActionFuncLink::apply 里调 `ensure_callspecs`（对齐 FlowInfo::setupCallSpecs flow.cc:680）扫描所有 alive CALL op 建立 FuncCallSpecs，存入 fd.callspecs，再对每个调 funcLinkInput/funcLinkOutput。此前 callspecs 仅测试填充。funcLink 的 locked 路径（opInsertInput/newVarnode/newVarnodeOut）仍 deferred。

- **移除 ActionCallParams**（2026-06-29 完整移植）：CALL 参数现由 ActionFuncLink::funcLinkInput 建立（opInsertInput + newVarnode），对齐 Ghidra coreaction.cc:1474。ActionCallParams（lifter 挂寄存器 + trim 的简化方案）已移除。

### 2026-06-27（会话3 续）：ActionPool — Rule 调度器接入主管线（G6 核心补全）

**系统性架构补全**：Rugra 此前 ~90 个 Rule 全部实现了 `apply_op` 但**均未接入主管线**——无 Ghidra ActionPool 式的 Rule 遍历调度。本次补全：

- 新增 `ActionPool` struct（对应 Ghidra `ActionPool`，action.hh:262）：持有 `Vec<Box<dyn Rule>>` + `per_op: HashMap<OpCode, Vec<usize>>` 索引。`add_rule` 注册 Rule 并按 opcode 建索引；`apply` 遍历所有 live op，按 opcode 匹配 Rule，循环至固定点（对应 Ghidra rule_repeatapply）。
- `build_simplify_pool()` 注册 **112 个简化 Rule**（2026-06-29 实测：`grep -cE 'pool\.add_rule'` = 105）。**镜像 Ghidra `oppool1` 精确顺序**（coreaction.cc:5511-5649）：每行标注 Ghidra 源码行号，未移植的 Rule 以 `skip` 注释标注。**2026-06-29 新增**：RuleSubCommute（5577）、RuleFloatSign（5619）、RuleSLess2Zero（5558）。
- **`build_cleanup_pool()`**（对齐 Ghidra `actcleanup` coreaction.cc:5694-5710）：独立池，含 `RuleMultNegOne`/`Rule2Comp2Sub` + **`RuleStringCopy`/`RuleStringStore`（constseq，coreaction.cc:5709-5710）**。constseq 模块此前代码完整但从未接入主管线（死代码），现已接入。**在 simplify 池之后跑**（阶段分隔）。这解决了一个收敛 bug：RuleMultNegOne（`x*-1→INT_2COMP`）若与 Rule2Comp2Mult（`INT_2COMP→x*-1`，oppool1 内）同池会无限 ping-pong；Ghidra 靠阶段分隔（主池先收敛、cleanup 池再跑一次）避免循环，Rugra 现忠实移植此机制。constseq 的 transform 阶段（替换为 CALLOTHER）仍待 userop 基础设施。
- RuleEarlyRemoval(5512) **已重新启用**（保守版）：补齐 Ghidra 6 守卫中的 is_call/is_indirect_source/is_auto_live/空间门（ruleaction.cc:30-40）。因 Rugra 的 descend 追踪有缺口（多处直接 push inrefs 绕过 op_set_input），当前空间门只允许 CONSTANT 输出删除（无条件安全）。REGISTER/UNIQUE 删除待 descend 追踪完整 + INDIRECT_SOURCE 设置 + doesDeadcode 移植后放开。
- 接入 `set_default_actions`：`ActionStart` → `ActionHeritage` → **`ActionSpacebase`** → `ActionStackPtrFlow` → `ActionSimplify` → `build_simplify_pool()` → `build_cleanup_pool()` → ... → `ActionCallParams` → **`ActionRestrictLocal`**（2026-06-29 新增）→ `ActionDeadCode` → ...

**验证（2026-06-28 量化核实）**：`ActionPool::apply` 增加可选 per-Rule 触发计数（环境变量 `RUGRA_RULE_STATS=1` 开启，默认关闭，不影响行为）。实测 `RUGRA_RULE_STATS=1 cargo run --example curl_decompile`：curl 24 函数反编译中 Rule 池触发 **515 次简化**，涉及 **21 个不同 Rule**（propagate_copy 244 / and_mask 43 / sub2_add 40 / less2_zero 39 / or_consume 29 / collapse_constants 23 / add_mult_collapse 20 / mult_neg_one 18 / 2comp2sub 18 / bool_negate 11 / ...）。**此前声称"实际反编译不触发任何 Rule 简化"为过期误判，已作废。** 776/776 测试通过，curl 24/24 + httpd 29/29 gcc 审计，0 goto。

**注意**：**2026-06-29 ActionSpacebase 接入后，uVar 碎片 149→0**（此前的说明"uVar 碎片数未变 149"已过时）。spacebase 标记让 varmap/printc 正确识别 RSP 为栈空间指针，消除了变量恢复层的 def 断链问题。

### 2026-06-27（会话3 G5）：结构清理 Action 未接入说明

ActionDeterminedBranch/ActionUnreachable/ActionDoNothing/ActionRedundBranch 的 apply() 已完整移植（coreaction.cc:3457-3528），但**未接入 set_default_actions**。set_default_actions 中有 NOTE 说明：Ghidra 在 selectGoto→collapseInternal 循环内运行这些清理 Action，structurer 围绕块删除设计；Rugra 的 staged-phase structurer 依赖这些块，接入导致回归。完整接入需 staged→collapseInternal 架构迁移（G4 可选优化）。apply() 逻辑已就绪。
### 2026-06-27（续）：ActionStackPtrFlow 接入管线（Heritage 后）
- set_default_actions 在 ActionHeritage 后接入 ActionStackPtrFlow（对齐 Ghidra actstackstall, coreaction.cc:5656）。

### 2026-07-01：oppool1/cleanup pool 大批补缺 Rule 注册接入

`build_simplify_pool`（oppool1）按 Ghidra coreaction.cc:5511-5649 顺序补齐此前 skip 的注册槽：
- 5517 RulePullsubIndirect、5551 RuleIndirectCollapse、5565 RuleTransformCpool、5606 RuleSwitchSingle
- 5621-5628 subvar 族（RuleSubvarAnd/Subpiece/SplitFlow/SubvarCompZero/Shift/Zext/Sext，来自 subflow.rs）
  - 例外：5624 RulePtrFlow 仍未移植（ruleaction.cc:9177，重）
- 5629-5641：RuleNegateNegate/ConditionalMove/FuncPtrEncoding/IgnoreNan/Unsigned2Float/Int2FloatCollapse/PtraddUndo/PtrsubUndo/Segment/PiecePathology
  - 例外：5631 RuleOrPredicate 存于 condexe.rs 但非 Rule trait impl，暂 skip
- 5633 RuleSubfloatConvert（subflow.rs）、5634 RuleFloatCast（从 local-extras 移至 Ghidra 正确槽位）
- 5643-5646 RuleDoubleLoad/Store/In/Out（来自 double_precis.rs）

`build_cleanup_pool`（actcleanup）补齐 coreaction.cc:5696-5708：
- 5697 RuleAddUnsigned、5700 RuleSubRight、5701 RuleFloatSignCleanup、5702 RuleExpandLoad、
  5703 RulePtrsubCharConstant、5704 RuleExtensionPush、5705 RulePieceStructure、
  5706-5708 RuleSplitCopy/Load/Store（来自 subflow.rs）
  - 例外：5699 RuleDumptyHumpLate 仍未移植（subflow.cc:3012）

lib.rs 新增 `pub mod double_precis`。RuleFloatCast 从 local-extras 移除（避免与 5634 重复注册）。

验证：832/832 测试，curl 24/24 无回归。

### 2026-07-01（重大）：管线架构改造 — perform 调度引擎 + 嵌套树结构
- **perform 状态机**：移植 Ghidra action.cc:298-362。`Action::perform(&mut self, fd, &mut ActionState)` 驱动 repeatapply/onceperfunc 语义。ActionState 持有 status/count/flags 字段。
- **Action trait 改 `&mut self`**：apply/reset 签名变更，全仓连锁修改（coreaction.rs/blockaction.rs/condexe.rs/funcdata.rs/examples/bin）。
- **ActionGroup 改 perform 驱动**：apply 调子 Action 的 perform（而非直接 apply），支持状态续传。
- **ActionPool 单遍化**：移除内部 repeat loop，由父级 perform 的 rule_repeatapply 驱动。补 opcode 变化检测（action.cc:862-867）。
- **ActionRestartGroup 新建**：移植 action.cc:554-583。universal 根容器，支持 restart pending → clearAnalysis → 重跑。
- **Funcdata +restart_pending + has_restart_pending/set_restart_pending + is_jumptable_recovery_on**。
- **set_default_actions 重构为嵌套树**：universal(ActionRestartGroup) → fullloop(ActionGroup) → mainloop(ActionGroup) → stackstall(ActionGroup) → oppool1(ActionPool)。
- **TODO**：fullloop/mainloop/stackstall 暂不设 RULE_REPEATAPPLY（Rugra 自造 Action 非幂等，重复会导致死循环）。待自造 Action 幂等化或替换为 Ghidra 机制后启用。
- **apply_all 改 perform 驱动**：每个函数先 reset，再 perform。

### 2026-07-01（续）：perform count 修复 + stackstall repeatapply 启用
- perform count 累加 bug 修复：count/count_tests 只在循环外清零/递增一次（对齐 action.cc:298-362）。
- ActionRestartGroup apply 返回值修复：只在 res<0（断点）时早返回。
- stackstall 启用 RULE_REPEATAPPLY（唯一子节点 simplify pool 可收敛）。
- mainloop/fullloop 暂不启用（非幂等子 Action 导致死循环）。

### 2026-07-01（续 2）：接入 22 个 pipeline Action

### 2026-07-01（续 3）：oppool2 接入 + build_full_pipeline_actions 更新
- build_oppool2() 新增，注册进 mainloop（stackstall 之后，coreaction.cc:5662）。
- build_full_pipeline_actions 新增 ActionStartTypes/AssignHigh/DominantCopy/CopyMarker。

### 2026-07-01（续 4）：注册 3 条缺失 Rule
RulePtrFlow(oppool1:5624) + RuleOrPredicate(oppool1:5631) + RuleDumptyHumpLate(cleanup:5699) 全部注册。

### 2026-07-01（续 5）：mainloop repeatapply 调查结果
mainloop RULE_REPEATAPPLY 测试：导致无限循环。根因：build_full_pipeline_actions 的 22 个 Action 中某些（ActionDirectWrite/ActiveParam 等）每次 apply 都报告变化。启用需要逐个验证这些 Action 的幂等性。暂不启用，标注 TODO。

### 2026-07-01（续 6）：perform loop cap + mainloop repeatapply 调查（栈溢出）
perform 加 100 次迭代安全阀（防止非幂等 Action 死循环）。mainloop RULE_REPEATAPPLY 测试：simplifypool 达到 cap 后 mainloop repeatapply 导致栈溢出（复杂函数）。结论：启用需要所有 22 个 extra Action 真正幂等（第二次 apply 返回 0 无副作用）。当前不启用。DoNothing/RedundBranch 接入测试：破坏 16 个结构化测试预期（splice 改变 bblocks），回退。

### 2026-07-01（续 7）：perform cap=3 + mainloop repeatapply 根因分析
cap 从 100→10→3。mainloop repeatapply 根因：ActionGroup.perform 在嵌套树中递归调用子 Action perform（5 层 × repeatapply 迭代），每个 RwLock guard ~2KB 栈，3³=27 层嵌套 perform 超过 Windows 8MB 栈。修复需重写 ActionGroup.perform 为迭代（非递归）或增大栈。cap=3 保留作为 ActionPool 叶子级安全阀。

### 2026-07-01（续 8）：256MB 线程栈 + mainloop repeatapply 深度根因
curl_decompile 改用 256MB 线程栈（防嵌套 perform 递归溢出）。mainloop repeatapply 在 256MB 栈下仍溢出→根因不是栈大小，而是 **pipeline 非收敛**：repeatapply 导致 Rule 在每轮创建新 op，alivelist 无限增长，ActionPool apply 的 clone(alivelist) 消耗全部内存。这是 pipeline 正确性问题（某些 Rule/Action 每轮产生新 op 而非收敛到不动点），需要逐个验证哪个 Rule/Action 不收敛。暂不启用 mainloop repeatapply。

### 2026-07-01（续 9）：迭代式 ActionGroup.apply（消除 perform 递归）
ActionGroup::apply 改为：对有 repeatapply flag 的子 Action 调 perform（如 ActionPool），对没有的调 apply（如中间 ActionGroup）。这消除了 perform→apply→child.perform→child.apply 的递归链——只有叶子级 repeatapply Action（ActionPool）使用 perform，中间 ActionGroup 用 apply + 父级 perform 循环。

mainloop repeatapply 仍不启用：即使迭代式 apply + 256MB 栈仍溢出。根因是 Rule apply_op 内部的深层 RwLock guard 链（Rule 接收 &Arc<RwLock<PcodeOp>>，apply_op 内部可能持有嵌套 read/write guard）。修复需重构 Rule apply_op 避免 nested lock，或用非递归 pipeline executor。

### 2026-07-01（续 10）：迭代式 ActionGroup.perform + mainloop repeatapply 最终根因
ActionGroup.perform 重写为迭代式：循环调 self.apply()，不递归进默认 perform。cap=1+mainloop repeatapply→24/24 通过；cap=2→glob_range 栈溢出。

### 2026-07-02：移除 perform/ActionGroup 迭代上限（R73 对齐 Ghidra，输出中性）
- **变更**：`Action::perform` 删除 `if iterations > 1 { break; }`（action.rs:90-92），`ActionGroup::perform` 删除 `if iterations > 2 { break; }`（action.rs:270）。两者改为纯 `lcount >= count` 终止（与 Ghidra action.cc:298-362 的无界 do-while 一致）。
- **动机**：audit R73。原上限是续 7/10 时期防 glob_range 栈溢出/死循环的安全阀；但续 9（迭代式 ActionGroup.apply）+ 续 10（迭代式 perform）已修复溢出根因（递归 perform→apply→child.perform 链），该上限已是冗余技术债，且静默禁用了 repeatapply 收敛（如 `V^V→0` 折叠后传播到 RETURN 的多轮简化）。
- **验证（2026-07-02 19:50 实测）**：
  - `cargo test --lib` 961/961 通过，零回归零挂起。
  - curl_decompile 连跑 3 次：rc=0，1281 行，glob_range 函数体完整（1266 字符，以 `}` 收尾），**无栈溢出**。
  - func_gap_audit（vs tests/golden/ghidra_curl.c）：0 EXACT / 24 DIFF — 与移除前**完全一致**（输出中性）。即此改动既未引入回归也未带来改善，但消除了收敛性阻塞，为后续 Rule 多轮简化生效扫清障碍。
- **诚实声明**：本次改动对 curl 当前输出**无可见影响**（return-V^V 等缺陷未变）。其根因经诊断（RUGRA_DBG_XOR）证实不在迭代上限，而在更深处（main_init 的 `iVar1^iVar1` 中 iVar1 为未初始化 varnode，由 printc 返回值启发式合成，非真实 `xor eax,eax`）。单指令 `xor eax,eax` 提升测试（test_xor_eax_eax_input_identity）证明 lifter 的 varnode 身份 dedup 正确（ptreq=true），故 main_init 缺陷需在返回值恢复层（ActionReturnRecovery）继续追查。

**最终根因**：mainloop repeatapply 重新运行 ActionHeritage（有深层递归 rename 逻辑 visit_rename_impl）。glob_range 有 17 bblocks，Heritage 的递归重命名在多轮 repeatapply 下累积递归深度，即使 256MB 栈也溢出。修复需要让 Heritage 的 rename 迭代化（非递归），或接受 Rugra 的 Actions 有内部循环不需要外部 repeatapply。

### 2026-07-01（续 11）：mainloop repeatapply 仍阻塞（迭代 Heritage 后 cap=1 仍溢出）

### 2026-07-01（续 12）：mainloop repeatapply 最终根因确认
通过加 `[STEP]` 日志定位：栈溢出发生在 `[STEP] glob_range action done` **之后**——即 pipeline 已完成，溢出在 `printer.doc_function()` 期间。这证明根因不是 pipeline 执行时的栈深度，而是 **sblocks 与 bblocks 不同步**：
1. mainloop repeatapply 第 1 轮：ActionBlockStructure 构建 sblocks
2. mainloop repeatapply 第 2 轮：其他 Action（Heritage/Simplify/CopyPropagate）改变 bblocks（新 op/varnode）
3. ActionBlockStructure 检查 `sblocks.get_size() != 0` → 跳过（不重建 sblocks）
4. sblocks 此时与 bblocks 不一致
5. printc 的 `emit_block_structured` 递归遍历 sblocks → 结构不匹配 → 无限递归 → 栈溢出

修复需要：sblocks 失效机制（bblocks 变化时清除 sblocks 让 ActionBlockStructure 重建）或将结构化 Action 移出 repeatapply 循环。这是架构级改进。

### 2026-07-01（续 13）：sblocks 失效 + printc 递归溢出
ActionBlockStructure: +last_op_count，op count 变化时 clear sblocks 重建。mainloop repeatapply 仍不启用：sblocks 重建后 printc emit_block_structured 在新结构上递归溢出。修复需迭代化 printc。

### 2026-07-01（续 14）：printc depth guard + mainloop repeatapply 最终状态
printc emit_block_structured +thread_local depth guard（>200 回退）。sblocks 失效重建保留。mainloop repeatapply 测试：depth guard+rebuild 仍溢出（200层×栈帧>256MB）。不启用。

### 2026-07-01（续 15）：mainloop repeatapply 栈帧分析
根因=emit_block_structured match 栈帧巨大（所有 arm 局部变量同帧）。depth=50+256MB 仍溢出。修复需拆分 per-arm helpers 或完全迭代化。

### 2026-07-01（续 16）：per-arm printc helpers + mainloop repeatapply 最终诊断（无限递归）
printc emit_block_structured 拆分 7 个 per-arm helpers。mainloop repeatapply 测试 depth 20-200+256MB：全部溢出。最终诊断=不是栈帧大小而是 sblocks 重建后的真正无限递归。

### cleanup pool 加 RuleTrivialArith（2026-07-03）
- 在 `build_cleanup_pool` 末尾注册 `RuleTrivialArith`。Ghidra mainloop（coreaction.cc:5503）repeatapply `actprop`（含 RuleTrivialArith）会重简化新创建的 op；Rugra 的 simplifypool 在 stackstall 里只跑一次，mainloop 后期（type-recovery / copy-prop / structuring）创建的 trivially-foldable op（self-XOR x^x→0 等）无法被再简化。cleanup pool 在管线最末运行（universal post-fullloop，coreaction.cc:5694），补这一刀捕获后期 op。Rugra-local 决策（Ghidra 靠 mainloop repeatapply 达同等效果），注释说明。

### 启用 ActionSetCasts（2026-07-03 续）
- `set_default_actions` 里 ActionSetCasts 之前被注释掉（注释说"需要 ActionInferTypes 先跑"）。ActionInferTypes 已在 mainloop（line 864）跑，所以条件满足。
- 按 Ghidra 顺序（coreaction.cc:5735：MarkImplied → NameVars → SetCasts → FinalStructure）在 ActionMarkImplied 后、ActionNormalizeBranches 前启用。
- 当前 castInput 只覆盖 integer binary/unary 路径（PTRADD/PTRSUB/resolveUnion/castOutput 待补），所以对当前输出影响小（类型系统还太松，cast 机会少），但这是把 SetCasts 接入主管线的正确步骤，后续补全 castInput 范围后会逐步产生 cast。

### ActionAssignHigh 注册澄清（2026-07-03 续）
- set_default_actions 里移除了重复的 ActionAssignHigh 注册——它已在 build_full_pipeline_actions（coreaction.rs:7084）注册，RULE_ONCEPERFUNC 保证幂等，无需在 universal 层重复。

### ActionOutputPrototype + ActionInputPrototype 接入主管线（2026-07-03 续）
- 两个 Action 之前已实现（coreaction.rs:4180/4254）但未在 set_default_actions 注册。
- 按 Ghidra 顺序（coreaction.cc:5730-5731）在 MarkImplied 后、SetCasts 前注册。
  - ActionOutputPrototype：从 RETURN ops 推导返回类型（已由 ActionReturnRecovery 挂载返回值）。
  - ActionInputPrototype：从 input varnodes 推导参数个数/类型（已由 ActionInferParams 做初步检测）。

### 主管线全量审计 + 注册（2026-07-03 续）
- 审计了 Ghidra universalAction（coreaction.cc:5462-5738）的全部 72 个 Action，对比 Rugra 注册情况。
- 发现 24 个 Ghidra Action 有 struct 定义但未注册。
- **安全注册**了无害的：ActionPrototypeWarnings（:5737）。
- **禁用**了导致回归的（注释说明原因）：ActionConstbase/ExtraPopSetup/Unreachable/RedundBranch/DeterminedBranch/NodeJoin/ConditionalConst/LikelyTrash/DoNothing/ReturnSplit/MappedLocalSync/StartCleanUp/PreferComplement/StructureTransform/MarkIndirectOnly/MapGlobals/DynamicSymbols/Stop。
  - 这些 Action 的 apply() 有副作用（删 op/块），实现不够成熟，启用后导致函数体丢失（24→14 函数）。
  - 需要逐个对照 Ghidra 源码验证其 apply 逻辑后才能安全启用。
- curl gcc 24/24（保持），0 defects，956/956 测试。

### ActionUnreachable 入口检测修复 + 禁用诊断（2026-07-03 续）
- 修了 `remove_unreachable_blocks` 的入口检测：之前只查 `ENTRY_POINT` flag（从不设），改为查 `size_in()==0`（对齐 Ghidra block.hh:325）。
- 但诊断发现根因：bblocks CFG 构建不完整（跳转表/间接分支边缺失），BFS 误判可达块。ActionUnreachable 保持禁用，注释说明根因 + 修复路径。

### ActionUnreachable 深度诊断结果（2026-07-03 续 2）
- 入口检测修复正确（size_in()==0），保守门禁（>=5 且 >5%）通过单元测试。
- 但即使移除 1 块也破坏函数体（myprogress 24→18 函数）→ 根因是 block 移除逻辑（branchRemove + blockRemove + structure_reset）不对齐 Ghidra。
- ActionUnreachable 保持禁用。修复路径：①CFG 边完整化（BRANCHIND）②block 移除逻辑对齐 Ghidra funcdata_block.cc。

### ActionUnreachable 根因更正（2026-07-03 续 3）
- **更正**：curl 的 24 个函数中 **0 个 BRANCHIND op**（之前误诊为 BRANCHIND 边缺失）。CFG 边对 BRANCH/CBRANCH 基本完整（仅 3 个目标因地址对齐偏移 3 字节未解析，不影响块可达性）。
- **真根因**：Rugra 的块移除（remove_block_arc/remove_edge_blocks）**不修补数据流**。Ghidra 的 `blockRemoveInternal`（funcdata_block.cc:255-335）移除 MULTIEQUAL 输入、修补后代 Varnode、处理搁浅引用。Rugra 只删 CFG 边和块 → 留下悬空 phi-node 和断裂数据流 → 函数体损坏。
- **修复路径**：移植 Ghidra `blockRemoveInternal`（含 MULTIEQUAL 调整 + descendantsOutside 检查）。

### ActionUnreachable op-destruction + 仍禁用（2026-07-03 续 4）
- remove_unreachable_blocks 新增 op 销毁（mark_dead）——正确的前提，但不够。
- 仍需 MULTIEQUAL phi 修补（funcdata_block.cc:278-294 的 opRemoveInput+opZeroMulti）。
- ActionUnreachable 保持禁用，注释更新。

### ActionUnreachable descendantsOutside（2026-07-03 续 5）
- remove_unreachable_blocks 的 Phase 2 改进：descendantsOutside 检查（只销毁无外部后代的 op）。对齐 Ghidra funcdata_block.cc:312。
- ActionUnreachable 仍禁用：根因是 pipeline 顺序——Action 在 mainloop 最开始运行时 bblocks 可能不完整。

### ActionUnreachable 安全启用（2026-07-03 续 6）★
- **将 ActionUnreachable 移到 ActionBlockStructure 之后**——解决了 pipeline 顺序问题。
- 根因：Rugra 的 bblocks CFG 在 mainloop 最开始（heritage 之前）不完整（sblocks 还没建），在此阶段移除块破坏后续阶段。移到 BlockStructure 后，CFG 完整，只有真不可达块被移除。
- Ghidra 在 :5490（更早）运行此 Action，但 Ghidra 的 CFG 在反汇编阶段就已完整。Rugra 需要在 BlockStructure 后才能保证 CFG 完整。
- **curl gcc 24/24（确定，3/3 runs），0 defects，956/956 测试**。

### 批量启用 13 个 Actions（2026-07-03 续 7）★
- 通过逐个二分测试，安全启用了 13 个之前禁用的 Actions：
  - **Stubs (安全 no-op)**: Constbase, ConditionalConst, MappedLocalSync, StartCleanUp, PreferComplement, StructureTransform, MapGlobals, DynamicSymbols, Stop
  - **Has-logic (验证安全)**: ExtraPopSetup, DeterminedBranch, LikelyTrash, DoNothing, MarkIndirectOnly
- **禁用 (1个有破坏性)**: RedundBranch — spliceBlockBasic 破坏输出（my_get_token gcc fail）
- **仍禁用 (2个 stub)**: NodeJoin, ReturnSplit — 留作占位
- 主管线覆盖率从 68/85 → **81/85 = 95%**（仅 RedundBranch/NodeJoin/ReturnSplit 3 个禁用 + ActionUnreachable 已启用）

### RedundBranch spliceBlockBasic op-moving（2026-07-03 续 8）
- spliceBlockBasic 修了 op-moving（ops 从 out_block 移到 bb），但还差 setOrder（seq_num 重置）。
- RedundBranch 保持禁用，注释说明剩余缺口（BlockBasic::set_order 未实现）。

### RedundBranch 启用（2026-07-03 续 10）
- spliceBlockBasic 现在忠实对齐 `BlockGraph::spliceBlock`（block.cc:1597-1620）：moveOutEdge 循环 + flags 合并（f_unstructured_targ/f_entry_point/f_switch_out）。
- ActionRedundBranch 重新接入主管线（action.rs:881，coreaction.cc:5658）。
- 验证：curl 24/24 反编译，23/24 gcc 审计通过。唯一失败 `file2string_part_0` 的 `goto ;` 是**预先存在的**结构化 bug（branch op 的 in(0) 缺失），与 RedundBranch 无关——禁用时同样失败。见续 11。
- 主管线覆盖率 81/85 → **82/85**（仅 NodeJoin/ReturnSplit 2 个 stub 禁用）。

### BlockBasic::set_order + RedundBranch（2026-07-03 续 9）
- 新增 BlockBasic::set_order（block.rs:451）——重置 seq_num.order（Ghidra block.cc:2638）。
- spliceBlockBasic 调用 set_order。但 RedundBranch 仍禁用：goto 目标引用未更新。

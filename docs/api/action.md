# `action.rs` API Reference

**源代码路径**: `src/action.rs`

## 文档状态

- **状态**: 已核对（当前有效）
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

### 2026-06-27（会话3 续）：ActionRestructureVarnode 接入主管线

- `ActionRestructureVarnode`（coreaction.cc:5505 "localrecovery"）现注册在 `decompile` group 的 `ActionDeadCode` 之后、`ActionConditionalExe` 之前。此前它**未接入**，导致 `fd.scope` 永远为 None，printc 的 `get_stack_variable_name` 永远找不到栈变量名 → uVar 碎片。接入后 scope 被构建，local_ 统计从 81→78（curl）。**G3 剩余**：多数函数 gather_spacebase 收集到 0 hints，根因是栈访问用 RBP/param 指针而非 RSP 直派，需扩展 spacebase 基址识别 + 修复 SSA def 断链。

### 2026-06-29：ActionMarkType 移到 dead-code 之后（对齐 Ghidra 管线顺序）

- `ActionMergeType` 此前注册在 `CopyPropagate` **之前**（action.rs 416），违反 Ghidra 顺序（coreaction.cc:5682 deadcode → 5718-5729 merge 阶段）。后果：merge 在 copy-prop/dead-code 删除 op 之前建立 `high.instances`，之后这些 instances 永不更新（copy-prop/dead-code 不清理），printc 拿到陈旧 instances → 自建 4 套 map 重建 def 关系。
- 现顺序：`CopyPropagate → TypePropagate → CallParams → RestrictLocal → DeadCode → ActionMergeType → MarkExplicit → MarkImplied → RestructureVarnode`。MarkExplicit/MarkImplied 在 MergeType 之后（Ghidra 的 MergeRequired 在 MarkImplied 前建 high，Rugra 的 merge_all 合并了 MergeRequired+MergeType，故 MarkImplied 跟在 merge_all 后）。配合 `Merge::is_live_varnode`（merge.rs）跳过死 varnode，`high.instances` 现反映 dead-code 后的 varnode 集，成为 printc 可信的权威来源。这是 P0 "声明却未赋值" 症状的根因修复（详见 `docs/alignment_docs/P0_DEF_CHAIN_DIAGNOSIS_2026-06-29.md`）。
- **implied 机制接入**（2026-06-29）：MarkImplied 用 checkImpliedCover（cover 相交）标记 implied varnode；printc 的 emit_block_ops 跳过 implied-output 的 op（对齐 printc.cc:2704），push_varnode 对 implied varnode 递归 inline 其 def 表达式（recurse 等价）。这是 Ghidra 控制内联的权威机制，替代 printc 自造的 4 套 map。
- curl 审计保持 24/24；`debug_my_fwrite` 中间变量（如 `piVar1`/`lVar3`）被正确内联。已知调优项：部分函数有重复变量声明（块内 shadow，gcc 允许但影响可读性）。

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

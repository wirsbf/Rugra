# `heritage.rs` API Reference

**源代码路径**: `src/heritage.rs`

## 文档状态

- **状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——canonical `Heritage::heritage` 没有生产调用且会重入写锁；主管线改走未建 dominator 的 direct phi/rename 两遍。pass、def-use、IOP、block membership、refinement 与 guard 闭包均不等价，正式行为门禁为 `NO_ORACLE`。详见 `docs/alignment_audit/CONTROL_OUTPUT_PIPELINES_2026-08-11.md`。
- **文档目标**: 说明 Rugra 当前 `heritage.rs` 在 SSA 构造与相关中间状态管理中的职责、边界与公开接口
- **可信边界**: 本文档围绕“当前架构中的 SSA / Heritage 责任分工”进行说明，不把“结构存在”写成“已完成与 Ghidra 的运行时一致性验证”
- **阅读建议**: 请结合以下模块一起理解：
  - `src/funcdata.rs`
  - `src/op.rs`
  - `src/varnode.rs`
  - `src/block.rs`
  - `src/action.rs`
  - `docs/data_contract.md`
  - `ALIGNMENT_PROGRESS.md`
  - `docs/VERIFICATION_GUIDE.md`

> 重要提醒：  
> `heritage.rs` 对应的是 Rugra 当前 SSA / heritage 相关核心层之一。  
> 结构存在不等于生产接线正确；修复前不得把 direct 算法单测当作 Ghidra 运行时 1:1 对拍。

---

## 模块定位

`heritage.rs` 是 Rugra 当前反编译主线中，负责 **SSA 构造、变量版本传播、Phi / MULTIEQUAL 放置及其辅助状态管理** 的关键模块。

从整体链路看，它大致处在这样的位置：

```text
raw p-code / injected ops
  -> Funcdata
  -> block / CFG
  -> Heritage
  -> SSA versioning / multiequals
  -> Action / Rule passes
  -> PrintLanguage / PrintC
```

换句话说，`heritage.rs` 主要解决的问题是：

1. 如何在函数级图结构上构造 SSA 形式
2. 如何为值节点分配和传播版本
3. 如何在控制流汇合点插入 `MULTIEQUAL` / Phi 风格节点
4. 如何维护与 SSA 过程相关的辅助索引、优先队列与状态记录

它**不应**被理解为：

- 最终代码生成层
- 最终类型恢复层
- 最终变量命名层
- 与 Ghidra 行为已完成对拍的证明模块

---

## “Heritage” 在当前工程中的含义

“Heritage” 在这里更接近 Ghidra 反编译器语义中的 heritage 过程，核心关注点是：

- 某个存储位置上的值如何随着控制流传播
- 某个 `Varnode` 在不同定义点之间如何形成版本序列
- 汇合控制流下，哪些位置需要插入合流节点
- 后续规则系统和输出层如何依赖这种 SSA 形态

因此，它不是一个抽象的“优化器”，而更像：

> **负责把函数级 IR 变成更适合数据流分析和高层恢复的 SSA 语义骨架的层。**

---

## 当前模块的责任边界

为了避免文档继续失真，下面明确 `heritage.rs` 当前应负责和不应负责的内容。

### 应负责

- 组织 SSA 构造流程
- 跟踪地址空间上的 heritage 状态
- 处理版本传播相关辅助结构
- 决定何时放置 `MULTIEQUAL`
- 进行 SSA rename 相关工作
- 维护与 heritage 过程有关的中间状态

### 不应负责

- 单独证明 SSA 已和 Ghidra 完全一致
- 单独恢复最终源码变量名
- 单独恢复最终高级类型
- 单独负责最终控制流结构化输出
- 把尚未验证的版本分配写成“已保证一致”

---

## 与其他模块的关系

### 与 `Funcdata`
`Funcdata` 是函数级分析上下文。  
`Heritage` 运行在 `Funcdata` 所承载的操作图、值节点和 block 信息之上。

可以把关系理解为：

- `Funcdata`: “函数级总容器
”
- `Heritage`: “在这个容器上进行 SSA 组织与版本传播的过程控制器”

### 与 `Varnode`
`Varnode` 是 SSA 的直接承载体之一。  
版本号、定义/使用关系、空间位置语义，都会在 heritage 过程中被使用和强化。

### 与 `PcodeOp`
`PcodeOp` 是操作节点。  
`MULTIEQUAL` 放置、rename 传播、def-use 组织，都离不开对操作节点的遍历和改写。

### 与 `BlockBasic` / CFG
SSA 不是孤立构造的，它依赖控制流结构。  
因此：

- block 划分
- 前驱后继
- 支配关系
- 合流位置

都会直接影响 heritage 过程。

### 与 `ActionDatabase`
Heritage 通常是后续高层规则与优化动作的前置基础之一。  
如果 SSA 形态不稳定，后续 Action / Rule 的推断和简化效果也会受到影响。

---

## 公开 API 说明

以下内容围绕当前可见公开接口展开，并重点解释它们在“SSA / Heritage 责任链”中的角色。

---

## `pub struct LocationMap`

### 作用
`LocationMap` 用于按地址位置记录与 heritage 过程相关的信息映射。

### 语义
从当前命名和职责来看，它更接近：

> “按 Address 维度记录某类尺寸 / pass / heritage 状态信息的辅助映射结构”

### 为什么需要它
在 SSA / heritage 过程中，经常需要回答类似问题：

- 某个位置之前已经在哪一轮处理过？
- 某个地址对应的 heritage pass 信息是什么？
- 某个存储位置是否已经被纳入当前阶段处理？

`LocationMap` 正是这类“位置级辅助索引”的容器。

### 当前边界
它是 SSA 构造过程中的工具对象，不应被当成最终用户可见语义，也不应写成“高层变量映射”。

---

## `pub struct SizePass`

### 作用
`SizePass` 是与“大小 + pass 信息”相关的辅助记录结构。

### 当前理解
它更适合作为 `LocationMap` 内部所依赖的记录单元，负责描述：

- 某个地址位置相关的大小信息
- heritage 过程中的 pass 状态

### 注意事项
当前文档不应夸大它的角色。  
更保守的表述是：

- 它是 heritage 过程中的辅助状态结构
- 它服务于位置索引和阶段控制
- 它不是最终 SSA 结果对象

---

## `pub fn new() -> Self`
适用于 `LocationMap` / `PriorityQueue` / `HeritageInfo` / `Heritage` 等结构的构造接口时，统一理解为：

- 创建一个空的、尚未承载 heritage 状态的新实例
- 作为后续分析过程的起点
- 不代表该对象一创建就处于“分析已完成”状态

---

## `pub fn add(&mut self, addr: Address, size: i32, pass: i32)`

### 所属
`LocationMap`

### 作用
向位置映射中登记一条与 heritage 相关的位置信息记录。

### 参数
- `addr`: 目标地址
- `size`: 关联尺寸
- `pass`: 关联处理轮次

### 语义
该接口更适合被理解为：

> “把某个地址位置在当前 heritage 流程中的元信息写入位置映射表中”

### 使用价值
这类接口通常有助于：

- 避免重复处理
- 查询某位置的历史处理信息
- 为多轮 heritage / SSA 过程提供追踪依据

---

## `pub fn find_pass(&self, addr: Address) -> i32`

### 所属
`LocationMap`

### 作用
查询某个地址对应的 heritage pass 信息。

### 典型用途
- 判断某个位置此前是否已被处理
- 决定当前阶段是否需要重复进入某个空间或地址位置
- 给调试或日志输出提供处理轮次依据

### 当前边界
返回值有助于控制流程，但不应被误写为“证明某位置 SSA 已正确完成”的最终证据。

---

## `pub fn clear(&mut self)`

### 所属
`LocationMap` / `Heritage`

### 作用
清空当前记录或重置 heritage 状态。

### 语义
这类 `clear()` 应统一理解为：

- 清除当前对象中的 heritage 过程状态
- 便于重新分析、重跑或测试复位
- 不是“回退整个工程状态”的万能接口

### 注意
在 `Heritage` 语境下，`clear()` 更偏向于“重置 heritage 过程内部状态”，而不是删除所有函数级 IR。

---

## `pub struct PriorityQueue`

### 作用
用于 heritage 过程中按优先级组织 block 的辅助队列。

### 语义
这是一个服务于 SSA / heritage 流程的调度结构。  
从命名和公开方法看，它主要用于：

- 插入 block
- 依据深度或优先级组织处理顺序
- 在 heritage 过程中抽取下一待处理块

### 为什么会有它
Heritage 过程往往并不是简单线性扫描，而是要考虑：

- CFG 深度
- 支配关系
- 处理顺序
- 汇合点传播

因此需要优先队列这类结构帮助决定处理顺序。

---

## `pub fn reset(&mut self, maxdepth: usize)`

### 所属
`PriorityQueue`

### 作用
重置优先队列状态，并按给定深度边界重新初始化。

### 适用场景
- 每轮 heritage 前初始化
- 重新构造调度环境
- 在测试中清空并重新配置队列状态

---

## `pub fn insert(&mut self, bl: Arc<RwLock<BlockBasic>>, depth: i32)`

### 所属
`PriorityQueue`

### 作用
把某个基本块按深度信息插入调度队列。

### 参数
- `bl`: 目标基本块
- `depth`: 与处理优先级有关的深度信息

### 设计意义
说明 heritage 并不是“按文件顺序处理块”，而是需要按图结构组织处理顺序。

---

## `pub fn extract(&mut self) -> Option<Arc<RwLock<BlockBasic>>>`

### 所属
`PriorityQueue`

### 作用
从优先队列中取出下一个待处理 block。

### 返回
- `Some(block)`: 取到下一个块
- `None`: 当前队列已空

### 用途
这是 heritage 过程中“驱动下一步处理”的关键接口之一。

---

## `pub fn empty(&self) -> bool`

### 所属
`PriorityQueue`

### 作用
判断队列是否已空。

### 用途
用于控制 heritage 处理循环是否结束。

---

## `pub struct HeritageInfo`

### 作用
表示某个地址空间上的 heritage 状态信息。

### 当前理解
它更适合被解释为：

> “针对单个 AddressSpace 的 heritage/SSA 处理上下文记录”

### 为什么按空间区分
这是很重要的设计点。  
因为不同地址空间上的值传播语义并不完全相同，例如：

- register
- ram
- stack
- unique
- const

在 heritage 过程中，按空间维护状态有助于：

- 避免混淆不同空间上的传播逻辑
- 更细粒度地控制版本化
- 让后续对齐 Ghidra 时更容易保持语义分层

---

## `pub fn new(space: AddressSpace) -> Self`

### 所属
`HeritageInfo`

### 作用
为指定地址空间创建一份 heritage 状态记录。

### 参数
- `space`: 目标地址空间

### 设计意义
说明 heritage 过程不是完全“无差别地处理所有值”，而是会显式关注不同空间的传播上下文。

---

## `pub struct LoadGuard`

### 作用
用于处理 `LOAD` / `STORE` 相关保护状态的辅助记录。

### 当前理解
它更适合作为：

- SSA / heritage 过程中处理内存相关操作的保护/跟踪结构
- 防止某些加载与存储语义在分析过程中被错误折叠或重复传播的辅助机制

### 文档边界
当前不应把它写成完整内存模型，只应描述为：

- 与内存读写保护有关的辅助记录
- 服务于 heritage 过程中的特殊场景

---

## `pub struct Heritage`

### 作用
这是 `heritage.rs` 中的主控制对象，负责组织 SSA / heritage 的整体过程。

### 当前定位
`Heritage` 更适合被理解为：

> “在单函数上下文上执行 SSA 组织、合流节点放置和 rename 的过程控制器”

### 典型职责
从当前公开接口来看，它至少会承担：

- 启动 heritage 主流程
- 放置 `MULTIEQUAL`
- 执行 rename
- 提供更直接、避免额外锁冲突的
变体接口
- 维护内部 pass 状态

### 当前不要夸大的地方
`Heritage` 的存在和接口完整度，不能直接推出：

- SSA 与 Ghidra 已行为一致
- 所有边界控制流已验证通过
- 所有 Phi 放置策略都已完成运行时对拍

它说明的是：**架构上已经明确把 SSA / heritage 当成正式主线能力来建设**。

---

## `pub fn heritage(&mut self)`

### 作用
启动 heritage 主流程。

### 语义
这是当前 `Heritage` 控制器的核心入口之一，负责推动 SSA / heritage 相关处理整体执行。

### 当前应如何理解
这个方法更接近：

- “进入 SSA / heritage 主过程”
- “协调 block、varnode、位置映射与中间状态”
- “为后续分析整理更稳定的数据流骨架”

而不是：

- “调用一次就自动完成全部高层恢复”

---

## `pub fn place_multiequals(&mut self)`

### 作用
插入 `MULTIEQUAL` 节点。

### 语义
这是 Phi / 合流节点放置的核心接口之一。

### 为什么重要
在控制流汇合点，如果多个定义路径在同一位置合流，就需要引入类似 Phi 的机制。  
在 Rugra 当前实现中，这类节点以 `MULTIEQUAL` 形式体现。

### 当前应如何表述
这说明当前 SSA 主线已经考虑并实现了合流节点放置机制。  
但这**不等于**：

- 放置位置已经和 Ghidra 运行时逐点一致
- 所有复杂 CFG 都已完成验证
- 多空间、多层嵌套流图下都已行为稳定

---

## `pub fn place_multiequals_direct(`

### 作用
以更直接的方式插入 `MULTIEQUAL`，并显式传入所需 bank 引用。

### 设计意义
从接口命名和描述看，它的意义主要在于：

- 避免额外锁层级带来的冲突
- 让 heritage 过程在共享对象图上更稳定地操作
- 适配当前工程使用共享读写容器的架构方式

### 当前理解
这是一个更偏工程安全性与可执行性优化的变体接口，说明项目在 heritage 过程中已经开始关注：

- 图对象共享引用
- 死锁风险
- 直接操作 bank 的性能/稳定性问题

---

## `pub fn rename(&mut self)`

###
 作用
执行 SSA rename。

### 语义
这是 heritage 过程中的另一个核心环节，用于：

- 传播版本信息
- 为值节点建立 SSA 版本序列
- 让 def-use 更明确

### 为什么重要
没有 rename，仅有原始节点和合流节点还不足以形成可用的 SSA 形式。

### 当前边界
这类接口的存在说明项目已经正式建模 SSA rename 过程；  
但不能把它直接写成：

- “版本号分配已证明与 Ghidra 完全一致”
- “rename 行为已经过完整对拍”

---

## `pub fn rename_direct(&mut self, vbank: &mut VarnodeBank, bblocks: &crate::block::BlockGraph)`

### 作用
以更直接的方式执行 rename，并显式使用 bank 与 block graph。

### 设计意义
这通常意味着：

- 当前实现中已有更强调工程稳定性的 rename 路径
- 共享对象图上的锁和引用关系是实际问题
- heritage 模块已经不只是概念实现，而是开始面向实际执行问题做接口分化

### 使用价值
相比间接依赖上下文，这类接口更利于：

- 测试
- 避免死锁
- 控制底层 bank 访问顺序
- 与当前图模型更紧密集成

### 2026-07-05 对齐修正（visit_rename_direct 三个 load-bearing 语义）

`visit_rename_direct` 此前声称对齐 Ghidra `renameRecurse`（heritage.cc:2480-2563），但漏掉了 3 个决定性语义：

1. **empty-stack input promotion**（cc:2500-2503 / cc:2541-2544）—— 当 varstack 为空时，Ghidra 创建新 varnode 并 `setInputVarnode` 提升为函数输入。Rugra 此前静默跳过 → 自由读未被替换 → SSA 不完整。现移植：通过 `VarnodeBank::set_input_varnode`（对齐 `Funcdata::setInputVarnode` cc:340-373）。

2. **INDIRECT same-time stack-deepening**（cc:2507-2518）—— 当栈顶 vnnew 是 INDIRECT 写且其 iop-const input(1) 指向当前 op 时，Ghidra 认为 "INDIRECT 和它的 op 同时发生"，深入栈一层（`stack[size-2]`）。Rugra 此前完全缺失 → 栈指针 INDIRECT 配对的 op 拿到错误的 SSA 名。现已按 cc:2509 比对 iop 偏移与当前 op 指针。

3. **deleteVarnode of consumed frees**（cc:2520-2521 / cc:2549-2550）—— 替换后若 `vnin->hasNoDescend()` 则 `fd->deleteVarnode(vnin)`。Rugra 此前从不删除 → 死 varnode 留在 loc_tree 污染后续 pass。现通过 `VarnodeBank::destroy_varnode` 移植。

同时修正 `rename_direct` 开头的 marker：原来只对 `!is_heritage_known()` 的 varnode 设 `activeHeritage`（即只标 free，跳过 written），但 Ghidra `guard()`（cc:1175/1182）对 **read+write** 两个 list 都设。written varnode 漏标导致 rename 的 `if (!vnout->isActiveHeritage()) continue;`（cc:2527）跳过 push → stack 空 → empty-stack promotion 触发 → set_input_varnode 把多分支 input 去重成同一个 → diamond merge 丢失分支独立性。现按 Ghidra 语义对非常量/非 annotation 的所有 varnode（含 written）设 activeHeritage。

---

## `pub fn get_pass(&self) -> i32`

### 作用
返回当前 heritage 过程的 pass 信息。

### 用途
可用于：

- 调试
- 日志输出
- 判断 heritage 推进轮次
- 分析阶段状态检查

### 边界
pass 计数只代表处理轮次，不等于质量保证。

---

## 常量标志位

### `pub const BOUNDARY_NODE: u32 = 1 << 0`
表示边界节点相关标志。

### `pub const MARK_NODE: u32 = 1 << 1`
表示标记节点相关状态。

### `pub const MERGED_NODE: u32 = 1 << 2`
表示已合并节点相关状态。

### 当前理解
这些常量说明 heritage 过程中还需要对节点做状态分类，例如：

- 是否是边界引入节点
- 是否已被 heritage 标记
- 是否已经参与合并过程

这再次说明 heritage 过程不是简单一次遍历，而是一个带有中间状态管理的多阶段处理过程。

---

## `pub struct StackNode`

### 作用
表示 SSA rename 栈中的节点。

### 语义
在 SSA rename 中，通常需要维护某种“当前定义栈”或“版本栈”来跟踪不同路径下的值版本。  
`StackNode` 就是服务于这种过程的辅助结构。

### 当前应如何理解
把它理解为：

- rename 过程中的内部工作单元
- 服务于版本传播和回溯
- 为递归或图遍历中的 SSA 状态跟踪提供支撑

而不是最终暴露给用户的高层数据结构。

---

## 当前应如何看待 `heritage.rs`

如果你正在理解当前 Rugra 主线，可以把 `heritage.rs` 概括为：

> **负责把函数级 IR 推进到更稳定 SSA 形态的核心模块。**

它的重要性体现在：

- 是后续 Action / Rule 的基础
- 是变量恢复和高层语义整理的重要前提
- 是对齐 Ghidra 时必须重点关注的行为层模块之一

但它当前的存在**不应被直接夸大为**：

- SSA 质量已成熟
- SSA 与 Ghidra 已完成运行时一致
- Heritage 全路径已被实证验证

---

## 推荐联动阅读

建议按以下顺序继续理解：

1. `funcdata.md`
2. `varnode.md`
3. `op.md`
4. `block.md`
5. `heritage.md`
6. `action.md`
7. `printlanguage.md`
8. `printc.md`
9. `../data_contract.md`
10. `../../ALIGNMENT_PROGRESS.md`

---

## 维护注意事项

后续维护本文档时，应特别注意以下几点：

### 1. 不要把概念对齐写成行为对齐
即使名称和对象组织对应 Ghidra，也不能直接写成“已完全一致”。

### 2. 不要把 `place_multiequals` / `rename` 的存在写成验证完成
这些接口说明能力方向存在，不等于对拍闭环已完成。

### 3. 如果共享引用模型变化，要同步更新本文
尤其是：
- direct 变体接口
- bank 访问方式
- queue / state 管理方式
- pass 统计方式

### 4. 如果未来加入更明确的测试证据，应同步补到状态文档
但 API 文档本身不替代验证报告。

---

## 一句话总结

`heritage.rs` 是 Rugra 当前 **SSA 构造与 heritage 过程控制** 的核心模块：它负责
组织版本传播、合流节点放置、rename 及相关辅助状态管理，为后续数据流分析、变量恢复和输出层提供更稳定的函数级语义骨架。

## 2026-06-29：discover_and_guard_stack_stores_fd（heritage.cc:985 + 1539）

- 新增 `Heritage::discover_and_guard_stack_stores_fd(fd: &mut Funcdata)`——对齐 Ghidra 的 `discoverIndexedStackPointers` + `guardStores`。从 RSP input 前向 descend 追踪 INT_ADD/INT_SUB/COPY 链，对到达的 STORE 算 stack offset，调 `new_indirect_op` 建 Stack 空间 INDIRECT。
- 接入 `ActionHeritage::apply`（coreaction.rs），在 place_multiequals/rename 之前跑。
- 前置依赖：varnode 去重（find_or_create_input_space）修复 descend 碎片化后，RSP input 有 64 个 descendants。
- 当前局限：written varnode（如 INT_ADD output）未去重，BFS 从 RSP 到 INT_ADD output 后，output 的 descend 不含 STORE（STORE 用独立副本）——待 inject_raw_ops 连接 op 图修复。

### 2026-06-29（续）：rename isHeritageKnown 检查 + 两 pass heritage

- **rename 跳过 heritage-known varnode**（对齐 heritage.cc:2496 `isHeritageKnown`）：input 重写只替换 free varnode（非 input/written/constant），跳过已 SSA 解析的。此前 Rugra rename 无条件替换所有 input，会错误 re-rename。这是 written varnode dedup 的前提。
- **两 pass heritage**：ActionHeritage::apply 跑两遍 place+rename。Pass 1 连接 op 图（rename 重写 STORE input 引用 INT_ADD output），Pass 2 的 discover 在连接后的图上发现 stack STOREs。对齐 Ghidra 多 pass heritage。
- **varnode 去重仍限 free/input**：written varnode 去重需要 loc_tree 排序按 input/written/free 分类（VarnodeCompareLocDef），是更深的重构。
- **VarnodeCompareLocDef 排序已对齐**（2026-06-29 续）：loc_tree 排序键改为 `(address_space, loc, size, input/written/free, def SeqNum or createIndex)`，对齐 Ghidra VarnodeCompareLocDef（varnode.cc:34-52）。input 同位置返回 Equal；written 按 def SeqNum 区分；free 按 createIndex 区分。
- **INSERT/activeHeritage flag 对齐**（2026-06-29 续 2）：rename 使用 `is_heritage_known()`（检查 INSERT flag，对齐 varnode.hh:298）+ `is_active_heritage()`（addl_flags，对齐 varnode.hh:115）。rename_direct 对所有 free varnode 设 activeHeritage（对齐 guard heritage.cc:1175/1182）。create 不设 INSERT（对齐 varnode.cc:1250）；set_def/set_input 设 INSERT（对齐 createDef/makeInput→xref）。
### 2026-07-01：LoadGuard methods + Heritage get_store/load_guard
- `LoadGuard::is_guarded(space, offset)`（heritage.cc:819-826）— 范围检查 space+minimum/maximum。
- `LoadGuard::get_minimum/get_maximum/get_op`（heritage.hh:164-165/161）。
- `Heritage::get_store_guard(op)/get_load_guard(op)`（heritage.hh:337-338）— 线性扫描 guard Vec。

### 2026-07-01（续）：LoadGuard/StoreGuard 填充逻辑
guard_stores（heritage.cc:1539+927）：扫描 spacebase-marked stack STORE，创建 StoreGuard 记录，去重。
guard_loads（heritage.cc:1571+910）：同理 LOAD，含 stale-record 清理。
guard_calls/guard_returns：stub（需 FuncCallSpecs effect characterization）。
guard_all：调用全部 4 个阶段。
establish_range/finalize_range：stub（需 ValueSetRead 求解器）。
LoadGuard::set/new_unanalyzed/Default/space_highest。3 新测试验证填充。

### 2026-07-01（续 2）：block-not-found 优雅降级
place_multiequal_direct 的 block 查找从 .expect 改为优雅 return。

### 2026-07-01（续 3）：visit_rename 迭代化（消除递归栈深度）
visit_rename_impl 从递归改为迭代式（显式 work stack + Enter/Leave 状态）。work stack 有 100000 上限防循环。消除 dominator-tree 递归深度。但 mainloop repeatapply 仍栈溢出（即使 cap=1+迭代 Heritage），根因待进一步调查。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-11：ANN-F provenance 分类（无行为变更）

`guard_calls_range_with_space` 不是 Ghidra 的独立 overload。锁定 oracle 只有
`Heritage::guardCalls(uint4, const Address &, int4, vector<Varnode *> &)`
(`heritage.cc:1443-1527`)，其中 address-space 身份由 `Address` 自身携带。Rugra
当前 `Address` 只有数值 offset，因此该 helper 额外传递 `AddressSpace`，属于
临时参数适配层；由 `ADDRESS-0001` / `HERITAGE-0001` 跟踪并在 space-aware
`Address` 与 canonical Heritage 接线完成后移除。本轮只补 `RUGRA-GLUE`
provenance，不改变 guard 行为或对齐状态。
 

### 2026-07-05: HeritageInfo + dead-code 时序对齐 Ghidra cc:180/2793/2843
- `HeritageInfo::new` 全字段对齐:delay/deadcodedelay 从 `AddressSpace::get_delay()` 读(Stack=1,其他=0);deadremoved=0(was -1);loadGuardSearch=false(was true,反义);hasCallPlaceholders=is_stack。
- `AddressSpace::get_delay/get_deadcode_delay/is_heritaged` 新增(space.hh)。
- `Heritage::build_info_list`(cc:2664)/`get_info`(hh:257)新增。
- `num_heritage_passes`(cc:2793): `pass - delay` (was `pass`)。
- `dead_removal_allowed`(cc:2843): `pass > deadcodedelay` (was const true)。
- `seen_dead_code`(cc:2805): 设 deadremoved=1 (was no-op)。
- `set/get_dead_code_delay`(cc:2829/2817): 读写 infolist (was no-op/const 2)。
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

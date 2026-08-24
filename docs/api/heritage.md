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

## `pub fn heritage(&mut self, fd: &mut Funcdata)`

### 作用
执行一个规范 heritage 单 pass（对齐 `Heritage::heritage`，
heritage.cc:2663-2758）。

### 语义（HERITAGE-OWNERSHIP-0001 重写）
签名从无参（内部 `Weak<RwLock<Funcdata>>` 升级取锁）改为显式
`&mut Funcdata`。单 pass 序列 1:1 对应锁定 oracle：

1. `maxdepth == -1` 时重建增广支配树（cc:2676-2677；Rugra 先
   `build_dom_tree` 再 `build_adt`，对齐上游 structureReset）；
2. `process_joins`（cc:2679）；
3. pass 0：同一个局部 `PreferSplitManager` init+split（cc:2680-2683）；
4. per-space 循环（cc:2684-2748）：delay 门控、
   `clear_stack_placeholders`、有序 Varnode 扫描喂持久
   `globaldisjoint` + 本 pass `disjoint`（prev 0/1/2 分类、
   warning 分支）；`discoverIndexedStackPointers` 为已登记缺口
   （HERITAGE-CALLGUARD-0001），故 `reprocessFreeStores` 不触发；
5. `place_multiequals(fd)`（cc:2749）；
6. `rename(fd)`（cc:2750，末尾 `disjoint.clear()` 对齐 cc:2592）；
7. `analyze_new_load_guards` + `handle_new_load_copies(fd)`
   （cc:2753-2754）；
8. pass 0：同一个 manager 上 `split_additional`（cc:2755-2756）；
9. `pass += 1` 恰好一次（cc:2757）。

与 oracle 一致：**不** 内部构建 infolist（`buildInfoList` 属于
`startProcessing`，funcdata.cc:166），也**不**运行 DeadCode /
不设 `pass >= 2` 早退 —— 重复调度属于 Action 执行器。

### 持久状态
`Heritage` 对象跨 pass 持久：`pass`、`maxdepth`、`globaldisjoint`、
per-space `HeritageInfo`（delay/deadcodedelay/loadGuardSearch/
hasCallPlaceholders）、load/store guards。`Funcdata::op_heritage`
用 `mem::take` 暂移整个对象、跑完一个 pass、原样回写，持久状态因此
跨调用保留且无锁路径。

### 构造与清零
`Heritage::new` / `Heritage::clear` 均置 `maxdepth = -1`
（heritage.cc:218-224 / 2882），这是首次 pass 重建 ADT 的哨兵。

---

## `pub fn build_adt(&mut self, fd: &Funcdata)`

### 作用
构建增广支配树（对齐 `Heritage::buildADT`，heritage.cc:2316-2385）。

### 语义（HERITAGE-OWNERSHIP-0001 重写）
显式 `&Funcdata`（只读），不再升级 `Weak`。步骤逐行对齐：
domchild 由 `immed_dom` 按列表序组装（无 idom 的块进 `size` 死桶，
block.cc:2036-2051）；`buildDomDepth` 根深度 1、子 = 父+1、尾部哨兵
`depth[size]=0`（block.cc:2056-2075）；up-edge 判定 `u != immed_dom(v)`
（指针同一性 → 块索引）；bottom-up a[]/z[] 与 boundary 标记、
`z[0] = -1`、top-down 传播、`k = z[k]` 的 augment 构造。

---

## `pub fn place_multiequals(&mut self, fd: &mut Funcdata)`

### 作用
按锁定 oracle `Heritage::placeMultiequals`（heritage.cc:2599-2645）逐段
消费当前 `disjoint` TaskList：每段 `collect` 分类 NEW/OLD（cc:2609）、
`size > 4 && max < size` 时走 `refinement` 细分并重 collect 第一片
（cc:2610-2616）、无读且无写/输入或内部空间/旧段跳过（cc:2619-2625）、
`removeRevisitedMarkers`（cc:2626-2627）、`guard_input`（cc:2628）、
`guard`（cc:2629，addIndirects 取 `new_addresses()`）、`calc_multiequals`
吃 collect 的 write varnode 列表（cc:2630/2439），随后对 `merge` 里每个
块用 `Funcdata::new_op(sizeIn, block.start)` + `create_def_with_space` 输出
（active-heritage）+ 每 slot 一个 fresh free 输入 + `op_insert_begin` 落在
块首（cc:2631-2642）。

### 语义
2026-08-15（HERITAGE-ADT-RENAME-0001）起该函数不再以
`(space, address)` 分组整个 bank，改按 TaskList 顺序消费；四个输出向量在
循环外声明、由每次 `collect` 清空复用（cc:2603-2609）；`MemRange` 的
`clear_property(new_addresses)` 突变经 clone/写回镜像 cc:334 的就地突变。
块首插入序即创建序的倒序（MULTIEQUAL 的 opInsertBegin 落 index 0），
`tests/oracle/heritage_adt_rename_1204` 三案例（diamond/oldmark/two-join
`seq=6,3`）对锁定 oracle 逐字节 MATCH。

### 残差（如实登记）
- `collect` 现为探针驱动的 loc_tree 活窗口（本空间限定；历史全 bank 偏移扫描已废），
  跨空间偏移碰撞会误分类——`HERITAGE-DRIVER-SWITCH-0001` 硬前置。
- 2026-08-17（HERITAGE-COLLECT-WRAPAROUND-0001）起 collect 已镜像 oracle 的
  endaddr 回绕钳位（heritage.cc:317-320）：`endaddr = wrapOffset(addr+size)` 落到
  start 之下时，窗口终点不用 beginLoc(endaddr)（会立刻截断成空窗口），而是钳到
  `endLoc(space, getHighest())` —— 从 start 扫到本空间末尾（首个异空间成员终止，
  无偏移上界）。Rugra 空间均为 8 字节寻址（`space_highest` 约定），u64 wrapping add
  即 oracle 算术。生产可达性：仅当 MemRange 跨越空间顶端（offset 0xffffffffffffffff
  且 size>1 的 varnode 进入 disjoint cover）触发，真实 loader 不产出 —— 预存非 r2
  引入。单点 fixture `tests/oracle/heritage_collect_wraparound_1204` 三案例（回绕
  跨顶 SUBPIECE 链接 / 同形非回绕对照 / 回绕恰顶字节直连）与锁定 oracle 逐字节
  MATCH；去掉钳位后 fixture 的 free_with_reader 断言即失败（判别力实证）。
- refinement/guardInput concat/removeRevisitedMarkers 已按 oracle 调用
  形状接线，但 fixture 未触发（UNTESTED）。

---

## `pub fn place_multiequals_direct(`

### 作用
以更直接的方式插入 `MULTIEQUAL`，并显式传入所需 bank 引用。

### 设计意义
从接口命名和描述看，它的意义主要在于：

- 避免额外锁层级带来的冲突
- 让 heritage 过程在共享对象图上更稳定地操作
- 适配当前工程使用共享读写容器的架构方式

### 确定性（RUN-NONDETERM 最小修，2026-08-15）
dominance frontier 是 `HashSet<i32>`（std SipHash 每进程随机种子）；
直接迭代会使 MULTIEQUAL 创建序逐进程随机 → 输出漂移。迭代前先
`sort_unstable()` 按块索引定序（/tmp 因果验证 20/20 全语料字节一致）。
canonical 路径不走 dom_frontier——merge 块由深度序 PriorityQueue +
有序 augment 推导（calcMultiequals cc:2448-2463 / visitIncr cc:2394-2428，
非块索引序，`seq=6,3` witness 可区分）；生产切换归
`HERITAGE-DRIVER-SWITCH-0001`。

---

## `pub fn rename(&mut self)`

###
 作用
执行 SSA rename。

### 语义
2026-08-15（HERITAGE-ADT-RENAME-0001）起该函数是
`Heritage::rename`（heritage.cc:2587-2593）的忠实移植入口：新建
VariableStack，**仅从 block 0** 起调 `rename_recurse`，随后
`disjoint.clear()`。`rename_recurse`（cc:2479-2562，迭代化
Enter/Leave 工作栈镜像"先子树后弹栈"的递归序）逐块：

- 单趟按执行序遍历 op（cc:2489）——MULTIEQUAL 只跳过读替换内层
  循环（cc:2491），其输出仍在**自身 op 位置**走公共写压栈尾
  （cc:2523-2529），不再有独立的 phi 预处理趟；
- 读槽升序（cc:2493）：heritage-known 跳过（cc:2495）、非 active
  free 跳过且不清标（cc:2496）、消费时清 active（cc:2497）、空栈
  input 提升（cc:2499-2502）、INDIRECT same-time 深栈
  （cc:2507-2516）、经 `Funcdata::op_set_input` 替换（cc:2518）、
  consumed free 删除（cc:2519-2520）；
- 后继循环（cc:2531-2552）：出边升序、精确 reverse slot、只扫后继
  **前导** MULTIEQUAL 组（cc:2536 break）；phi 输入只查
  `isHeritageKnown`（cc:2538——phi 环上已写的 loop-carried 输入保持
  原样，即 old-marker skip），无 active 检查/清除；
- domchild 序递归、writelist 按遇到序在全部子树后弹（cc:2553-2561）。

`tests/oracle/heritage_adt_rename_1204` 三案例（含 oldmark 环）对该路径
逐字节 MATCH。生产 direct 路径的差异（全入口块、预置 input 栈、
v_type 拷贝、宽泛 active 标记）仍留在 `rename_direct`，切换归
`HERITAGE-DRIVER-SWITCH-0001`。

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

`visit_rename_direct` 此前声称对齐 Ghidra `renameRecurse`（heritage.cc:2479-2562），但漏掉了 3 个决定性语义：

1. **empty-stack input promotion**（cc:2499-2502 / cc:2540-2543）—— 当 varstack 为空时，Ghidra 创建新 varnode 并 `setInputVarnode` 提升为函数输入。Rugra 此前静默跳过 → 自由读未被替换 → SSA 不完整。现移植：通过 `VarnodeBank::set_input_varnode`（对齐 `Funcdata::setInputVarnode` cc:340-373）。

2. **INDIRECT same-time stack-deepening**（cc:2507-2516）—— 当栈顶 vnnew 是 INDIRECT 写且其 iop-const input(1) 指向当前 op 时，Ghidra 认为 "INDIRECT 和它的 op 同时发生"，深入栈一层（`stack[size-2]`）。Rugra 此前完全缺失 → 栈指针 INDIRECT 配对的 op 拿到错误的 SSA 名。现已按 cc:2508 比对 iop 偏移与当前 op 指针。

3. **deleteVarnode of consumed frees**（cc:2519-2520 / cc:2548-2549）—— 替换后若 `vnin->hasNoDescend()` 则 `fd->deleteVarnode(vnin)`。Rugra 此前从不删除 → 死 varnode 留在 loc_tree 污染后续 pass。现由该 exact guard 调 `VarnodeBank::destroy_varnode_prevalidated`；debug build 重新断言 no-def/no-descendant 与 bank ownership，public integrated 错误没有被吞掉。

2026-08-13 `VARNODE-INIT-0001` caller closure：生产 direct 路径的 `insert_multiequal_direct` 为 fresh bank-owned 输出调用 `set_def_prevalidated`，并把 xref 返回的 canonical Arc 写入 MULTIEQUAL output；每个 fresh placeholder 也像 locked `heritage.cc:2638-2639` 的 `opSetInput` 一样建立一条 descendant。`renameRecurse` 的普通 op 与 successor MULTIEQUAL 两条替换路径都先从旧 Varnode 精确擦除一个 descendant，再向 canonical 新值添加一条，并保留 same-Arc early return；删除仅发生在 locked `heritage.cc:2519/2548 hasNoDescend()` 守卫内。Rust graph tests 覆盖普通 free replacement 后旧值退 bank、两 predecessor 的 phi placeholder 逐槽退 bank，以及 same-Arc 不增边/不删除；这些是 Rust-only 生命周期回归，不是同输入 Ghidra 差分，故 `visit_rename_direct` caller graph 仍为 `UNTESTED`，Heritage 整体仍无逐函数 oracle。低层 erase/add/slot 迁移另由 Varnode/combine oracle 覆盖。legacy `place_multiequals` 尚未统一到这条 setDef 路径，仍归 `HERITAGE-OWNERSHIP-0001`/后续 driver 闭包。该原子只修所触及 direct 路径的引用/输出身份和 destroy 先验，不提升 Heritage 模块整体级别。

同时修正 `rename_direct` 开头的 marker：原来只对 `!is_heritage_known()` 的 varnode 设 `activeHeritage`（即只标 free，跳过 written），但 Ghidra `guard()`（cc:1174/1181）对 **read+write** 两个 list 都设。written varnode 漏标导致 rename 的 `if (!vnout->isActiveHeritage()) continue;`（cc:2526）跳过 push → stack 空 → empty-stack promotion 触发 → set_input_varnode 把多分支 input 去重成同一个 → diamond merge 丢失分支独立性。现按 Ghidra 语义对非常量/非 annotation 的所有 varnode（含 written）设 activeHeritage。

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

## 2026-08-16：HERITAGE-DRIVER-SWITCH-0001 —— 生产路径切 canonical 单 pass + LocationMap 空间键

- **`ActionHeritage::apply` 切换**（coreaction.rs，逐字对齐 coreaction.hh:289）：`{ fd.op_heritage(); Ok(0) }`。删除 pass>=2 guard、global_struct_ptrs v_type 预戳、direct 双 pass、内嵌 ActionDeadCode 夹层与 discover_and_guard_stack_stores_fd 调用。收敛性验证：curl 124/124 processed、`multiple descendants` WARN 351（=HEAD 基线，FLAGFREE 审计的 44 在 HEAD 不可复现，两态均为 351）、"not settling" 5（=基线，type-propagation 家族）、3× 输出 sha 一致。
- **LocationMap 空间键**（heritage.hh:48 `map<Address,SizePass>`，Address 含 space；`Address::overlap` 跨空间恒 -1）：`themap` 键从裸 offset 改为 `(AddressSpace, Address)`，`add/find_pass/entry_containing` 只在本空间子区间找候选——跨空间同 offset 碰撞不再误分类 NEW/OLD（126b56f 复核硬前置）。新增看门狗测试 `test_location_map_cross_space_keys_are_disjoint`。
- **normalize_read_size 修复**（heritage.cc:383-401）：此前直接 `newop.output = Some(vn)` 绕过 `Funcdata::op_set_output`，被归一的 varnode `def` 从未置位、永远 FREE，驱动器每 pass 重新归一、每 pass 新建 SUBPIECE——canonical 切换后实测 main 800+ mainloop 迭代/WARN 21630 的 ping-pong 根因。现走 `op_set_output`（装 def + def_tree）+ cc:398 `set_write_mask`（驱动器 cc:2706 跳过）。
- **collect 活窗口（复核 M1 修正，2026-08-16 r2；heritage.cc:323-325）**：collect 每 range 用合成探针 varnode（size 0，同 offset 排最前）构造 `loc_tree.range(probe..)`——字面 beginLoc(addr) 语义的**活迭代器**，只走本空间窗口成员（O(log V + hits)），兼修跨空间同 offset 误收。**活性是承载语义的**：refinement（cc:1902-1906）在本 placeMultiequals 行进中创建 pieces，oracle 的 cc:2615 re-collect 与后续各 piece 的 collect 都必须看到；早先的入口冻结快照实现把 pieces 对整个 pass 隐藏、下一 pass 该范围已成 OLD（addIndirects=false）→ INDIRECT 永不补建（x86-64 部分寄存器写高频触发 `size>4 && max<size`）。fixture case E（switch_refinement_recollect）锁定：冻结实现下该 case `free_with_reader=0` 断言失败（判别力实证），live 实现下与 oracle 逐字节一致（`phi.PIECE(R54:4:I,R50:4:W+INT_SUB)`）。
- **direct 族移出生产路径**：`place_multiequals_direct`/`rename_direct`/`insert_multiequal_direct`/`run_heritage_direct` 仅剩 example 侧 throwaway-Funcdata 参数估计与 crate 内测试调用；无调用者的 `insert_multiequal`（fd 适配壳）删除。`insert_multiequal_direct` 的 phi 尺寸回退（`.unwrap_or(4)`）随之不再有生产可达路径。
- **E2E 残差**（如实登记，绑定后继）：(1) 生产 callspec 无 model（FUNCPROTO-MODEL-BIND-0001/CSPEC-TEXT-INGEST-0001）→ `FuncCallSpecs::has_effect` 恒 UnknownEffect（fspec.rs 保守分支）→ canonical guardCalls 每 call×range 建 INDIRECT（main pass 0 = 13,462 INDIRECT + 4,098 phi，ops 674→22,186、vns 8K→68K）；(2) varnode bank descend 列表 O(n) `has_no_descend`（Weak upgrade 逐元素）× 共享 free varnode → pass 0 rename 30s。两因叠加 8 函数超 example 的 10s worker 预算（decompiled 76→68），skeleton diff 于 11 个文本变化函数 +1..+277（defects=0 不变）。

## 2026-06-29：discover_and_guard_stack_stores_fd（heritage.cc:985 + 1539）

- 新增 `Heritage::discover_and_guard_stack_stores_fd(fd: &mut Funcdata)`——对齐 Ghidra 的 `discoverIndexedStackPointers` + `guardStores`。从 RSP input 前向 descend 追踪 INT_ADD/INT_SUB/COPY 链，对到达的 STORE 算 stack offset，调 `new_indirect_op` 建 Stack 空间 INDIRECT。（2026-08-16 起移出生产路径，仅 reprocess_free_stores 近似与测试调用。）
- 前置依赖：varnode 去重（find_or_create_input_space）修复 descend 碎片化后，RSP input 有 64 个 descendants。
- 当前局限：written varnode（如 INT_ADD output）未去重，BFS 从 RSP 到 INT_ADD output 后，output 的 descend 不含 STORE（STORE 用独立副本）——待 inject_raw_ops 连接 op 图修复。

### 2026-06-29（续）：rename isHeritageKnown 检查 + 两 pass heritage

- **rename 跳过 heritage-known varnode**（对齐 heritage.cc:2495 `isHeritageKnown`）：input 重写只替换 free varnode（非 input/written/constant），跳过已 SSA 解析的。此前 Rugra rename 无条件替换所有 input，会错误 re-rename。这是 written varnode dedup 的前提。
- **两 pass heritage**：ActionHeritage::apply 跑两遍 place+rename。Pass 1 连接 op 图（rename 重写 STORE input 引用 INT_ADD output），Pass 2 的 discover 在连接后的图上发现 stack STOREs。对齐 Ghidra 多 pass heritage。
- **varnode 去重仍限 free/input**：written varnode 去重需要 loc_tree 排序按 input/written/free 分类（VarnodeCompareLocDef），是更深的重构。
- **VarnodeCompareLocDef 排序已对齐**（2026-06-29 续）：loc_tree 排序键改为 `(address_space, loc, size, input/written/free, def SeqNum or createIndex)`，对齐 Ghidra VarnodeCompareLocDef（varnode.cc:34-52）。input 同位置返回 Equal；written 按 def SeqNum 区分；free 按 createIndex 区分。
- **INSERT/activeHeritage flag 对齐**（2026-06-29 续 2）：rename 使用 `is_heritage_known()`（检查 INSERT flag，对齐 varnode.hh:298）+ `is_active_heritage()`（addl_flags，对齐 varnode.hh:115）。rename_direct 对所有 free varnode 设 activeHeritage（对齐 guard heritage.cc:1174/1181）。create 不设 INSERT（对齐 varnode.cc:1250）；set_def/set_input 设 INSERT（对齐 createDef/makeInput→xref）。
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

### 2026-08-15: HERITAGE-CALLGUARD-0001 — 规范 guardCalls + 驱动器接线

- `Heritage::guard_calls(fd, fl, space, addr, size, write)`（heritage.cc:1443-1527）
  1:1 移植：callspec 顺序循环、assignment 跳过（cc:1453-1456）、Stack spacebase
  偏移翻译（cc:1457-1466，`OFFSET_UNKNOWN` → `tryregister=false`）、
  `has_effect` 查询、output-active/stack-output-lock 双分支（cc:1469-1494，
  autoKilledByCall 升级 + `try_output_overlap_guard`/`try_output_stack_guard`）、
  input-active 双分支（cc:1495-1509，contains_justified 注册 trial 并
  `op_insert_input`、contained_by → `guard_call_overlapping_input`）、三态
  INDIRECT 创建（unknown/return_address → `new_indirect_op` + holdind/return
  标志；killedbycall → `new_indirect_creation_in_space`）。旧的
  `guard_calls_range`/`guard_calls_range_with_space` stub（按指令地址找 call、
  丢输出效果、只处理 unknown_effect）已删除。
- `guard_range` 接入 per-space `AddressSpace` 参数（Ghidra 的 `Address` 自带
  space 身份；`ADDRESS-0001` 移除该参数后删除）。`place_multiequals` 按
  `MemRange::new_addresses()` 门控执行 guard fan-out（cc:2608-2629 的
  addIndirects 半边；collect/refinement/guardInput 仍归
  HERITAGE-ADT-RENAME-0001）。`guard_returns` 死 stub 删除（需
  FuncProto::activeoutput，归 PARAM-BIND 家族）。
- `MemRange`/`TaskList::add` 增加 `space` 字段/参数（Ghidra MemRange 的
  space-carrying Address 的显式镜像）。
- `guard_call_overlapping_input`/`try_output_overlap_guard`/`guard_output_overlap`/
  `try_output_stack_guard` 改为 per-callspec 签名（fc + caller/callee 双地址），
  `guard_output_overlap` 用 `new_indirect_creation_in_space`（cc:1253 真正用
  creation 而非 indirect op）。
- `guard_stores_range`/`guard_loads_range` 忠实化：STORE 空间匹配（range space
  或其 container + usesSpacebasePtr，cc:1551-1552）、`indirect_store` flag 由
  调用方传入、fl/addrtied 早退（cc:1576）。
- `reprocess_free_stores`（cc:1111-1141）：改为 `previous_op_in_block` 反向
  遍历 + `get_op_from_const` IOP 别名校验 + `op_clear_spacebase_ptr` +
  `op_destroy`（原实现按 bank 顺序收集 prev 列表，非连续组语义）。
- **Bug 修复（本 fixture 发现）**：`LocationMap::add`（heritage.cc:34-71）在
  查询地址与既有 key 精确相等且前一 key 不重叠时，把该 entry 走了 merge
  循环（返回 1=partial）而非 contained 检查（应返回 2）。这使第二趟
  heritage 把已覆盖 range 重新标 NEW，guard 重复创建。修复后
  driver_pass_gating 第二趟 0 新 INDIRECT 与 oracle 一致。
- 锁定 oracle fixture `tests/oracle/heritage_callguard_1204`（7 case 双侧逐
  字节 MATCH，GetStr 形态 2 calls × 10 ranges = 20 INDIRECT 全对象投影）。
- 残差：ScopeLocal queryProperties 的 fl（addrtied → ADDRFORCE）未建模
  （fixture 投影中 `af` 双侧省略）；reprocessFreeStores 的
  discoverIndexedStackPointers 触发链与生产 Action 切换归后续任务。

### 2026-08-15: HERITAGE-ADT-RENAME-0001 — canonical placeMultiequals/rename 消费 disjoint

- `place_multiequals`（heritage.cc:2599-2645）改为逐段消费 `disjoint`
  TaskList：collect →（>4B 且 max<size 时）refinement → 无读跳过规则
  （cc:2619-2625，含 IPTR_INTERNAL/oldAddresses）→ removeRevisitedMarkers
  → guardInput → guard（`new_addresses()` 门控）→ calcMultiequals →
  块首 MULTIEQUAL 插入。旧的"全 bank (space,address) 分组 + bank 近似插入"
  删除；phi 经 `fd.new_op(sizeIn, block.start)` +
  `create_def_with_space`/`set_varnode_properties`（newVarnodeOut 的
  space-carrying 镜像）+ `op_set_input` + `op_insert_begin` 创建，无条件
  dominator 重建也一并删除（cc:2599 无 buildADT/buildDomTree 调用，
  dominator 状态由 driver 的 maxdepth==-1 分支供给）。
- `calc_multiequals`（cc:2439-2466）签名改为吃 write **varnode** 列表，
  块索引从 `write[i]->def->parent` 派生（cc:2449）。
- `collect`（cc:307-347）改为 MemRange 引用形式：write-mask 跳过
  （cc:326，`Varnode::is_write_mask` 已存在）、marker/return-COPY 旧
  heritage 证据（cc:329）、`clear_property(NEW_ADDRESSES)`（cc:334）。
- 新增 `refinement`（cc:1890-1940）orchestrator：size+1 fencepost、
  边界→分区尺寸转换、`remove13_refinement` 按 cc:1857-1880 重写、
  tasklist 就地 splice + globaldisjoint 逐片 add（原 pass 号）。
- `refine_read/refine_write/refine_input`（cc:1772/1806/1836）重写为
  oracle 调用形状：concatPieces/splitPieces + totalReplace +
  deleteVarnode；refineInput 不再凭空 setFlags(INPUT)（消除
  VARNODE-INPLACE-MUTATION-SITES-0001 登记的 heritage.rs 突变点）。
- `concat_pieces`/`split_pieces` 的 null-insertop 分支对齐 cc:516-519/
  578-581（start block begin + 函数地址，无 entry 标志时如 Ghidra
  getStartNode 抛错路径降级为 stderr 警告）；splitPieces 的 Some 分支
  改为插在写 op **之后**（++insertiter）。
- **机制 C 复核返工（2026-08-16，M1-M5）**：concatPieces/splitPieces 的
  插入改为**元素锚**——cc:516-518/582-587 的 insertiter 是进入循环前捕获的
  固定元素（原首 op X / write 之后的元素 Y），cc:546/602 每片插在该元素
  **之前**，片序=创建序 [P1..Pn,X] / [W,S1..Sn,Y]；首轮交付的固定数值
  索引（每轮 index 0 / write_pos+1）会把组反转成 use-before-def 块内序，
  已由 `adt_refine_order` 案例的 block-order 投影钉死（runner 断言
  `b1=PIECE,PIECE,PIECE,r` 与 `wa,SUBPIECE,SUBPIECE`）。refineRead 非自由
  路径按 cc:1786 改为 panic（保留 "Refining non-free varnode" 原文）。
  二轮复核（M5a/b）修正：warning 文本为 printRaw 原形——`0x` + 按
  2*addrsize 零填充、高位缩短规则（>>32==0→4B / >>48==0→6B）、**无空间名**
  （space.cc:206-221），如 `0x00000070`；removeRevisitedMarkers 的重插位置
  改为**元素锚**——在 opUninsert 之前于移除前列表解析锚（dead/不可解析
  target→INDIRECT 自身后继 cc:268-269；alive target→target 后继
  cc:270-272；MULTIEQUAL→组后首个非 ME cc:275-280），uninsert 后
  `op_insert_before(op, anchor)`、锚为尾时追加——数值索引在移除后列表上
  平移一位且块尾越界 panic（`adt_revisit_positions` 案例钉死
  [a2,S,f2]/[a3,S]/[m2,S,x] 三形态）。附带修复 refine_read 把
  lone_descend 内联进 if-let 条件导致的同线程 RwLock 死锁（读守卫跨块
  存活 × op_set_input 对同一 varnode 取写锁）。
- `rename`/`rename_recurse`（cc:2587-2593/2479-2562）：canonical rename
  不再走 `rename_direct`——block 0 唯一根、单趟 op 序、精确
  `op_set_input`、phi 输入 old-marker skip、无预置 input 栈、无
  v_type 拷贝、无宽泛 active 标记；直接路径保持不变（生产用）。
- RUN-NONDETERM 最小修：`place_multiequals_direct` 的 dom_frontier
  `HashSet` 迭代前 `sort_unstable()`（详见上文该函数小节）。
- 锁定 oracle fixture `tests/oracle/heritage_adt_rename_1204`（3 case
  双侧逐字节 MATCH，含 merge 序 witness `seq=6,3` 与 ownership 波受限
  phi_cycle 案例的完整投影）。残差：collect 全 bank 偏移窗口
  （跨空间碰撞，DRIVER-SWITCH 硬前置）、refinement/guardInput concat/
  removeRevisitedMarkers 分支 UNTESTED。


## 测试区维护（2026-08-17）

`test_op_heritage_leaves_deadcode_to_the_action_executor` 的 harness 修正
（VARNODE-ADDDESCEND-THROW-0001 前置件，最后一个 WARN 源）：原 harness 把同一
free varnode 对象同时交给 b0 的 d1 读与 b1 的 r1 读（free-with-2-readers）。
Ghidra 的 PcodeEmitFd::dump 对每个输入引用独立调 newVarnode（funcdata.cc:905），
同一寄存器两处读=两个分立 free varnode（loc-tree 以 createIndex 区分，
VarnodeCompareLocDef），单对象双读者会触发 addDescend throw（varnode.cc:336）。
修法=分立 per-read free 实例（不走 set_input：保持 free 才能保留 heritage 的
read 工作负载——INPUT 会置 insert 使 isHeritageKnown 跳过该读）；两实例仍在
Register@0x30 同一 loc，collect 按地址窗口照常收作 read，断言（alive 计数差、
pass==3）零变化，生产代码未动。
<!-- annotation-pass: 2026-08-17 -->

## ParamActive 地址空间传递（2026-08-24）

`guard_calls`、`guard_call_overlapping_input` 和
`try_output_overlap_guard` 对 trial 的查询与注册均显式携带当前 heritage
range 的 `AddressSpace`。这对应 Ghidra `transAddr`/`truncAddr` 保留
`AddrSpace *` 的语义，防止不同空间中 offset 相同的 trial 被误判为同一项；
trial 大小、注册时机、callspec 遍历顺序与既有分支均未改变。

## force_restructure（block_domroot_1204，2026-08-19）

**`Heritage::force_restructure`** — `heritage.hh:333`
`void forceRestructure(void) { maxdepth = -1; }` 的一行移植。闭环：
`heritage()` 入口 `maxdepth==-1` → `build_dom_tree + build_adt`
（对应 heritage.cc:2676-2677 增广支配树重建），调用点为
`Funcdata::structure_reset` 尾部（funcdata_block.cc:730）。对齐证据：
block_domroot_1204 权威 runner MATCH + 机制 C 复核 APPROVE（2026-08-19）。

## CALLSPEC-IDENTITY-D0 guard/placeholder owner 接线（2026-08-24）

- callspec 现由 `Arc<RwLock<FuncCallSpecs>>` 稳定拥有；active-input/output trial
  查询在 read guard 内产生布尔快照，注册则使用独立 write guard，不把内部引用
  带出锁域，也不改变既有 callspec 顺序、trial 大小或注册时机。
- `clear_stack_placeholders` 克隆的是 owner `Arc` 列表，而不是把 qlst 按值
  `take` 出再放回。每个 callspec 通过自身的 exact op `Weak` 找 CALL/CALLIND，
  随后在同一 owner 上执行 `abort_spacebase_relative`；相同指令地址的两个 op
  不会互相冒充，且操作期间 qlst/annotation 的身份保持稳定。
- 这是 D0 所有权适配，不批准 Heritage 其余分支。总体仍为 `MISMATCH`：
  `AddressSpace::Iop` 暂代专用 `IPTR_FSPEC`
  （`TYPEOP-FSPEC-SPACE-0001`），TypeOp getter、PrintC、StringManager 与既有
  heritage/callspec 残差均未接通，模块状态不提升。
- `call_op_indirect_effect` 仍未消费已经可用的 exact owner 与
  `has_effect_translate`：CALL/CALLIND 继续保守返回 true，CALLOTHER/NEW 也尚未
  恢复 oracle 的 false 分支。源码审计已确认该缺口，但没有同输入双侧 fixture，
  所以证据状态为 `UNTESTED`，绑定 `CALLSPEC-0001`；本 D0 不把它虚升为行为
  `MATCH`，也不在 identity/lifecycle 租约内扩写 Heritage 算法。

## HERITAGE-GUARD-NORMALIZE-0001 — guard/return 归一化切片（2026-08-24）

`Heritage::guard` 的 addIndirects 半边（heritage.cc:1188-1198）与
normalizeWriteSize/callOpIndirectEffect 的 1:1 移植：

- **`guard_query_properties`**（database.cc:1263 `Scope::queryProperties`，
  guard cc:1191 空 usepoint 调用形态）：最小包含符号 → getAllFlags
  （mapped|addrtied(无 usepoint)|typelock|namelock|nolocalalias）；在
  local_range 内 → mapped|addrtied；否则 → Architecture::symboltab 的
  flagbase（persist 等属性带）。残余：Ghidra 的 stackContainer 会继续走到
  父（global）scope，Rugra ScopeLocal 无父链，global 符号不可见（管线内
  stack/register 路径不依赖）；`fd.scope` 为空时属性查询走 arch flagbase。
- **`guard_range`**：fl 改为真实查询（原硬编码 0）；调用顺序
  guardCalls → **guardReturns**（新接入）→ `high_ptr_possible` 门控
  guardStores/guardLoads（cc:1194，原无条件调用）；write 表项由
  `normalize_write_size` 的返回值替换（cc:1180 `*iter = vn =`，原丢弃）。
- **`guard_returns`**（heritage.cc:1652-1692，新移植）：activeoutput 半边 ——
  `characterize_as_output` 分 contained_by（→ guardReturnsOverlapping）、
  其余 containment（registerTrial + 每个 live 非 halt RETURN 追加全范围新
  input，cc:1663-1673）；persist 半边 —— 每个 **live RETURN（含 halt，
  cc:1678-1680 无 halt 检查）** 前插 return-copy COPY（out addrForce+
  activeHeritage，op 带 `PcodeOp::return_copy`，cc:1681-1690）。coreaction
  侧 ANN-F 默认模型输出 seed（coreaction.rs）不在本租约内，待 PARAM-BIND
  家族收敛时统一去重。
- **`guard_returns_overlapping`**（heritage.cc:1609-1638，新移植）：
  `get_biggest_contained_output` → 截断 trial 注册（BE 偏移从高位重算，
  cc:1620-1622）+ 每个 live 非 halt RETURN 前 SUBPIECE(#offset) 截断
  （cc:1628-1636），常量 4 字节（cc:1632）。
- **`normalize_write_size`**（heritage.cc:416-494，完全重写）：most/least
  两片 CALL 分支（`call_op_indirect_effect` 真 → `new_indirect_creation`；
  假 → 全范围 free read 的 SUBPIECE，常量宽度 = `space.addr_size()`）；
  midvn PIECE(vn, leastvn)（BE 输出地址取 vn 原地址，cc:472-475）；bigout
  PIECE(mostvn, midvn)（插在 midvn def 之后，cc:489）；原 vn `set_write_mask`
  （cc:493）；返回 bigout。旧实现的三处结构性错误（不回写替换、PIECE 用
  全范围新建 free varnode 当输入、new_op(3) 元数）全部消除。
- **`call_op_indirect_effect`**（heritage.cc:358-370，极性修复）：
  CALL/CALLIND → `get_call_specs_of_op` exact owner + `has_effect_translate
  != Unaffected`（无 spec → true）；**CALLOTHER/NEW → false**（原恒 true，
  两分支极性均错）。D0 时登记的 `CALLSPEC-0001` UNTESTED 缺口就此闭合并由
  heritage_guard_normalize_1204 双侧 fixture 提供证据。
- RETURN 遍历顺序 = `obank.returnlist` 创建序（Ghidra `beginOp(CPUI_RETURN)`
  的插入序镜像）；halt 判定 = `HALT|BADINSTRUCTION|UNIMPLEMENTED|NORETURN|
  MISSING`（op.hh:171）。
- fixture：`tests/oracle/heritage_guard_normalize_1204.{cc,rs}` +
  `tools/run_heritage_guard_normalize_oracle.sh`（锁定 oracle e40ed130 双侧
  执行、字节级 stdout diff）。covered projections = MATCH（六 case）；
  模块整体仍 MISMATCH：loadGuard COPY 插入、indexed/ValueSet、join、
  removeRevisitedMarkers COPY 形态等未做切片按 TODO 登记（load/join/indexed
  归 HERITAGE-CALLGUARD/PROCESSJOINS 家族）。

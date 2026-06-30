# `varnode.rs` API Reference

**源代码路径**: `src/varnode.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **可信度**: 高
- **文档定位**: 当前源码的接口解释层
- **可信边界**: 以 `src/varnode.rs` 实际代码为准
- **注意**: 本文描述的是 Rugra 当前的 **storage-node / IR data node** 模型，不等同于“与 Ghidra 运行时行为已完全一致”的证明

---

## 模块说明

`varnode.rs` 定义了 Rugra 中最核心的数据节点类型之一：`Varnode`。

在当前实现里，`Varnode` 的职责可以概括为：

1. 表示一个**具备地址空间、偏移和大小**的数据存储单元
2. 作为 P-code / IR 中操作数和结果值的基础承载对象
3. 为后续的：
   - def-use 关系
   - SSA 版本标记
   - 类型传播
   - 变量恢复
   - 输出打印
   提供统一的数据节点模型

它对应的是一种**存储节点 / 数据节点模型**，而不是高层变量本身。  
也就是说：

- `Varnode` 更接近“某个位置上的值”
- 而不是“用户源码里最终看到的那个逻辑变量名”

---

## 设计定位：当前的 storage-node 模型

在当前 Rugra 架构里，`Varnode` 主要围绕以下三个维度组织：

### 1. 位置语义
一个 `Varnode` 首先要能说明"它在哪"：

- 属于哪个 `AddressSpace`
- 偏移是多少
- 占多少字节

这使它可以表示：

- 寄存器值
- RAM 中的值
- 栈槽中的值
- 内部临时值（如 `unique` 空间）
- 常量值（通过特定空间或构造方式表达）

**loc_tree 排序键**（2026-06-29）：`VarnodeLocRef::Ord` 按 `(address_space, loc, size, input/written/free 分类, def SeqNum or create_index)` 排序——对齐 Ghidra `VarnodeCompareLocDef`（varnode.cc:34-52）。关键：input varnode 同位置返回 Equal（同一个对象）；written 按 def SeqNum 区分；free 按 createIndex 区分。这让 Stack 空间 varnode 不与其他空间混淆，且 xref 去重能正确工作。新增 `VarnodeBank::iter_space(space)` 方法按空间遍历 varnode。

**varnode 去重（find_or_create_input_space）**（2026-06-29）：新增 `VarnodeBank::find_or_create_input_space(size, space, offset)`——查找已有的同 (space, offset, size) 的 free/input varnode（不含 written），复用它；没有则创建。对齐 Ghidra `Funcdata::newVarnode`（funcdata_varnode.cc:148）——建 free varnode，由 rename 连接到 written。修复了 descend 链碎片化（RSP input 从 1 个 descend 变 64 个）。

**INSERT/activeHeritage flag 模型**（2026-06-29 续）：对齐 Ghidra varnode flag 语义。`VarnodeBank::create` 不设 INSERT（对齐 varnode.cc:1250，free varnode 无 INSERT → `isHeritageKnown` false → rename 处理）。`set_def`/`set_input` 设 INSERT（对齐 createDef/makeInput→xref）。新增 `addl_flags` 模块（ACTIVE_HERITAGE=0x01 等，对齐 varnode.hh:115）。`is_heritage_known()` 检查 `flags & (INSERT|CONSTANT|ANNOTATION)`（对齐 varnode.hh:298）。`set_active_heritage()`/`is_active_heritage()` 访问器。

### 2. 数据流节点语义
`Varnode` 是 `PcodeOp` 的输入或输出节点，因此它天然处于数据流图中：

- 可以被某个操作定义
- 可以被后续多个操作使用
- 可以在分析阶段携带更多附加状态

### 3. 分析附着点
随着分析推进，`Varnode` 还可能承担：

- SSA 版本标记
- flags 状态
- 输入/写入/常量等标签
- 类型与命名恢复的挂载点

因此，`Varnode` 不是一个单纯的“地址 + 大小”元组，而是**可参与整个函数级分析流程的数据节点对象**。

---

## 与其他核心对象的关系

`Varnode` 在当前架构中通常与以下对象强关联：

### 与 `Address`
`Address` 负责表达“位置”的统一语义。  
`Varnode` 通过 `Address` 或 `AddressSpace + offset` 来定位自己。

### 与 `AddressSpace`
`AddressSpace` 决定一个 `Varnode` 属于：

- 寄存器空间
- 内存空间
- 常量空间
- 栈空间
- unique 临时空间
- 其他内部空间

### 与 `PcodeOp`
`Varnode` 是 `PcodeOp` 的输入与输出载体：

- 输入 `Varnode` 表示操作读取哪些值
- 输出 `Varnode` 表示操作定义了什么值

### 与 `Funcdata`
在函数级分析上下文中，`Varnode` 一般不是孤立存在的，而是被组织到 `Funcdata` 的内部图结构中。

### 与变量恢复 / 类型系统
`Varnode` 不是最终高层变量，但它是：

- 变量合并的候选单元
- 类型传播的附着点
- 打印层恢复更高层表示的基础

---

## 常量标志位（Flags）

本模块公开了一组 `u32` 位标志，用来描述 `Varnode` 的状态或性质。

这些标志大体可分为几类：

### 基础身份类
- `CONSTANT`
- `INPUT`
- `WRITTEN`

用于区分：
- 是否是常量
- 是否是输入值
- 是否已被某个操作写入

### 命名 / 类型 /绑定类
- `TYPELOCK`
- `NAMELOCK`
- `ADDRTIED`
- `MAPPED`

用于表达某些语义是否已固定，或是否与特定地址绑定。

### 存储属性类
- `READONLY`
- `VOLATIL`
- `PERSIST`
- `SPACEBASE`
- `RETURN_ADDRESS`

用于表达该节点的存储属性或在调用语义中的特殊角色。

### 间接 / 辅助分析类
- `INDIRECTONLY`
- `INDIRECT_CREATION`
- `INDIRECTSTORAGE`
- `INCIDENTAL_COPY`
- `AUTOLIVE_HOLD`

这类标志主要服务于分析过程和中间状态管理。

### 覆盖 / 精度 / 原型相关类
- `COVERDIRTY`
- `PRECISLO`
- `PRECISHI`
- `HIDDENRETPARM`
- `PROTO_PARTIAL`

这类状态更接近高级分析或恢复阶段使用的辅助标签。

> 注意：  
> 这些 flag 的存在，说明 `Varnode` 不只是一个静态数据结构，而是一个会随着分析过程逐步积累状态的节点对象。

---

## 导出的公共 API

## `pub struct Varnode`

### 语义

`Varnode` 是 Rugra 当前 IR 中的基础存储节点，表示：

- 一个有位置的数据单元
- 一个数据流节点
- 一个可被分析和打印流程继续加工的载体

### 当前模型下应如何理解

请把它理解为：

> “某个地址空间里的某个值节点”

而不是：

> “已经恢复完成的源码变量”

---

## 构造函数

### `pub fn new(size: usize, loc: Address) -> Self`

创建一个新的 `Varnode`。

### 作用
- 直接用现成的 `Address` 构造节点
- 适合已经有统一地址对象的场景

### 参数
- `size`: 节点大小（字节）
- `loc`: 节点位置

### 返回
- 一个新的 `Varnode`

### 说明
文档中提到它带有某种向后兼容语义，但在理解上应以“使用已有地址对象构造存储节点”为主。

---

### `pub fn new_with_space(size: usize, space: AddressSpace, offset: u64) -> Self`

使用显式地址空间和偏移构造 `Varnode`。

### 作用
- 当调用方还没有完整 `Address`，但已知空间和偏移时使用
- 是当前 storage-node 模型里更直观的构造方式之一

### 参数
- `size`: 节点大小
- `space`: 地址空间
- `offset`: 空间内偏移

### 返回
- 一个新的 `Varnode`

---

### `pub fn new_constant(val: u64, size: usize) -> Self`

构造常量 `Varnode`。

### 作用
用于把立即数、字面值等表示成 IR 数据节点。

### 参数
- `val`: 常量值
- `size`: 字节大小

### 返回
- 表示常量的 `Varnode`

### 说明
常量在数据流中仍然以节点存在，因此它依然遵守 `Varnode` 统一接口。

---

### `pub fn new_register(offset: u64, size: usize) -> Self`

构造寄存器空间中的 `Varnode`。

### 作用
表示寄存器上的值。

### 参数
- `offset`: 寄存器空间偏移
- `size`: 节点大小

---

### `pub fn new_ram(offset: u64, size: usize) -> Self`

构造 RAM 空间中的 `Varnode`。

### 作用
表示普通内存中的值。

---

### `pub fn new_stack(offset: u64, size: usize) -> Self`

构造栈相关 `Varnode`。

### 作用
用于表示栈槽、局部变量候选位置等。

### 说明
这很重要，因为后续变量恢复往往会从栈空间节点出发。

---

### `pub fn new_unique(offset: u64, size: usize) -> Self`

构造 unique 空间中的 `Varnode`。

### 作用
表示内部临时值、提升阶段或中间运算阶段产生的临时节点。

### 说明
这类节点通常不是最终用户想看到的源码变量，而是中间 IR 的内部载体。

---

## 位置与空间访问接口

### `pub fn get_addr(&self) -> &Address`

返回节点的完整地址对象。

### 用途
- 获取统一位置表示
- 用于排序、显示、关联其他图节点

---

### `pub fn get_space(&self) -> AddressSpace`

返回节点所属的地址空间。

### 用途
判断当前节点属于：
- register
- ram
- stack
- unique
- const
- 其他空间

---

### `pub fn get_offset(&self) -> u64`

返回节点的偏移。

### 说明
偏移的意义依赖于 `AddressSpace`。  
不能脱离空间单独解释。

---

### `pub fn offset(&self) -> u64`

返回偏移。

### 说明
这是较短形式的访问接口，与 `get_offset()` 属于相同语义层。

---

### `pub fn space(&self) -> AddressSpace`

返回地址空间。

### 说明
这是较短形式的访问接口，与 `get_space()` 属于相同语义层。

---

### `pub fn get_val(&self) -> u64`

返回底层值语义。

### 说明
这个接口通常更适用于：
- 常量节点
- 或某些将节点值视作原始整数的场景

使用时应注意：
- 它不自动等价于“高层可直接显示的值”
- 在不同空间中的语义并不相同

---

### `pub fn constant_value(&self) -> Option<u64>`

若该节点是常量，则返回其常量值。

### 返回
- `Some(value)`: 当前节点可被解释为常量
- `None`: 当前节点不是常量

### 作用
这是判断“这个节点是否可当立即数使用”的更安全方式。

---

## 大小与版本接口

### `pub fn size(&self) -> usize`

返回节点大小。

---

### `pub fn get_size(&self) -> usize`

返回节点大小。

### 说明
与 `size()` 语义相同，属于不同风格的访问接口。

---

### `pub fn version(&self) -> usize`

返回节点的版本号。

### 作用
用于表达 SSA 相关版本信息。

### 重要说明
这里“有 version 字段/接口”并不等于：
- SSA 行为已经与 Ghidra 完全一致
- 版本分配已完成运行时对拍

它只说明当前 `Varnode` 模型已为 SSA 版本信息预留了表达位点。

---

### `pub fn with_version(self, _version: usize) -> Self`

返回一个携带指定版本信息的新节点。

### 作用
用于构造或传播带版本号的节点表示。

### 说明
这是 storage-node 模型向 SSA 语义扩展的入口之一。

---

### `pub fn get_create_index(&self) -> u32`

返回创建索引。

### 用途
通常用于：
- 稳定排序
- 调试
- 追踪节点创建先后关系

---

## 判定接口

### `pub fn is_unique(&self) -> bool`

判断该节点是否位于 unique 空间。

### 典型意义
表示内部临时值。

---

### `pub fn is_register(&self) -> bool`

判断该节点是否位于寄存器空间。

---

### `pub fn is_constant(&self) -> bool`

判断该节点是否为常量节点。

---

### `pub fn is_input(&self) -> bool`

判断该节点是否被标记为输入节点。

### 典型场景
- 函数输入
- 初始状态值
- 某些未在本函数内定义的入口值

---

### `pub fn is_written(&self) -> bool`

判断该节点是否已被某个操作写入。

---

### `pub fn is_free(&self) -> bool`

判断该节点是否处于未绑定/自由状态。

### 说明
这通常更偏向内部状态管理，而不是最终用户语义。

---

## 状态修改接口

### `pub fn set_flags(&mut self, f: u32)`

为节点添加一个或多个 flag。

### 参数
- `f`: 位标志集合

### 用途
- 在分析过程中标记节点状态
- 更新输入/写入/绑定/恢复相关标签

---

### `pub fn clear_flags(&mut self, f: u32)`

清除一个或多个 flag。

### 参数
- `f`: 要清除的位标志集合

### 用途
- 撤销中间状态
- 调整分析流程中的节点属性

---

## 包装类型

### `pub struct VarnodeLocRef(pub Arc<RwLock<Varnode>>)` 

### 作用
位置排序或位置相关集合操作的包装器。

### 说明
当前实现使用共享所有权和读写锁包装 `Varnode`，说明：
- 节点会在多个分析阶段共享
- 节点状态可能被逐步更新
- 需要面向图结构和并发/共享访问设计

> 注意：旧文档里若还写着 `Rc<RefCell<Varnode>>` 一类表述，应视为历史遗留描述，不应再作为当前实现结论。

---

### `pub struct VarnodeDefRef(pub Arc<RwLock<Varnode>>)` 

### 作用
定义点相关的包装器。

### 典型用途
- 按定义关系组织节点
- 在 def-use 或 SSA 相关集合中使用

---

## 当前文档应如何使用

建议你把 `varnode.rs` 看作以下问题的入口：

1. **一个值节点如何定位？**  
   看：
   - `Address`
   - `AddressSpace`
   - `get_addr()`
   - `get_space()`
   - `get_offset()`

2. **一个值节点如何区分常量、寄存器、栈槽、临时值？**  
   看：
   - `new_constant()`
   - `new_register()`
   - `new_stack()`
   - `new_unique()`
   - `is_constant()`
   - `is_register()`
   - `is_unique()`

3. **一个值节点如何进入 SSA / 分析流程？**  
   看：
   - `version()`
   - `with_version()`
   - flags
   - `Funcdata`
   - `PcodeOp`

4. **一个值节点如何被更高层恢复成变量或打印结果？**  
   看：
   - `variable.rs`
   - `heritage.rs`
   - `printlanguage.rs`
   - `printc.rs`

---

## 已知边界与风险提示

### 1. `Varnode` 不是最终源码变量
不要把它直接理解为用户看到的 `local_10`、`param_1` 这类逻辑变量。

### 2. 有版本字段不代表 SSA 已完全验证
`version()` 的存在，只能说明当前模型支持 SSA 表达，不代表当前 SSA 行为已经完成运行时等价验证。

### 3. 空间语义非常重要
同一个偏移在不同 `AddressSpace` 下不是同一个东西。  
任何脱离空间理解 `Varnode` 的做法都会导致语义偏差。

### 4. `unique` 节点通常是内部临时值
它们对分析非常重要，但通常不是最终输出中希望直接暴露给用户的高层变量。

---

## 推荐联动阅读

如果你正在理解 `Varnode`，建议继续阅读：

- `address.md`
- `space.md`
- `op.md`
- `pcoderaw.md`
- `funcdata.md`
- `heritage.md`
- `printc.md`
- `../data_contract.md`

---

## 一句话总结

`Varnode` 是 Rugra 当前 storage-node 模型中的基础数据节点：  
它统一承载“位置 + 大小 + 节点状态 + 分析附着点”这几类信息，是从原始 P-code、函数级图模型、SSA 分析到最终打印输出之间最重要的底层数据载体之一。
## 2026-06-26：Ghidra-faithful flag 访问器（varnode.hh:235-330）

新增与 Ghidra 一致的 Varnode flag 访问/设置方法，解锁 coreaction Action
（ActionMarkExplicit/MarkImplied/RestrictLocal 等）：

- `is_mark/set_mark/clear_mark` (varnode.hh:263,303,304)
- `is_implied/set_implied/clear_implied` (varnode.hh:235,309,310)
- `is_explicit/set_explicit/clear_explicit` (varnode.hh:236,311,312)
- `is_direct_write/set_direct_write/clear_direct_write` (varnode.hh:247,305,306)
- `is_addr_tied`（addrtied|insert 同置，varnode.hh:250）
- `is_persist` (246), `is_unaffected/set_unaffected` (255,167)
- `is_illegal_input`（input 置而 directwrite 清，varnode.hh:240）

测试：varnode::tests 4 个新增（mark、explicit/implied、addr_tied 双标志、illegal_input）。

## 2026-06-26（续）：get_nz_mask

- `get_nz_mask(&self) -> u64`（varnode.hh:231）：非零掩码。Ghidra 由 Heritage/Cover 维护；
  Rugra 当前保守近似（常量=值，其他=calc_mask(size)）。解锁 RuleSlessToLess 等 NZM 相关 Rule。

## 2026-06-26（续）：lone_descend / has_no_descend

- `lone_descend(&self) -> Option<Arc<RwLock<PcodeOp>>>` — `Varnode::loneDescend`：返回唯一后代 op（无或多个则 None）。
- `has_no_descend(&self) -> bool` — `Varnode::hasNoDescend`：无后代读取。
解锁 RuleDoubleShift/RuleSubZext/RuleXorCollapse 等独占使用检查。

## 2026-06-26（续）：consume/nzm 访问器

- `get_consume() -> u64` / `set_consume(val)`（varnode.hh:205-206）：dead-code 维护的 consumed 位掩码。
- `get_nzm() -> u64` / `set_nzm(val)`：Heritage 维护的 nzm 字段原始访问。
解锁 RuleOrConsume/RuleAndMask 等依赖 consume 的 Rule。

## 2026-06-26（续）：is_boolean_value

- `is_boolean_value(use_annotation) -> bool`（varnode.cc:942）：判断 varnode 是否为已知布尔值（由 calculated_bool 标志的 op 定义）。解锁 RuleBooleanNegate/RuleLogic2Bool。

## 2026-06-27：def / descend / flag 访问器（L3 基础设施）

新增 def-chain 遍历所需访问器，解锁 jumptable/ruleaction/condexe 等模块的深度遍历：

- `get_def() -> Option<Arc<RwLock<PcodeOp>>>`（varnode.hh:213）：升级内部 Weak→Arc，返回定义此 varnode 的 PcodeOp。
- `is_read_only() -> bool`（varnode.hh:243）：是否来自只读内存空间。
- `is_annotation() -> bool`（varnode.hh:237）：是否为反编译器插入的注解 varnode。
- `is_spacebase() -> bool`：是否为 spacebase 指针 varnode。
- `is_persist_global() -> bool`：是否为持久化（全局）varnode。
- `descend_iter() -> impl Iterator<Item = Arc<RwLock<PcodeOp>>>`（varnode.hh:219-220）：遍历活跃的后继 op（beginDescend/endDescend）。
- `count_descends() -> usize`：活跃后继计数。
- `add_descend(&Arc<RwLock<PcodeOp>>)`（varnode.hh:295）：添加后继引用。
- `is_bool_output_def() -> bool`：定义 op 是否有布尔输出（getDef()->isBoolOutput）。

### 2026-06-27（会话2 续）：is_constant_extended（解锁 RuleDivOpt）

- `is_constant_extended() -> Option<(u64, u64)>` — `Varnode::isConstantExtended`（varnode.cc:799-840）：检测扩展常量，返回 128 位值 (lo, hi)。普通常量返回 (offset, 0)；INT_ZEXT/INT_SEXT/PIECE 链递归解析。被 RuleDivOpt::findForm 用于处理超过 64 位的乘法常量（除法乘法编码 c 可能 > 2^64）。

### 2026-06-27（会话3 G3 诊断）：find_by_loc

- `VarnodeBank::find_by_loc(size, loc) -> Option<Arc<Varnode>>` — 空间查找辅助：扫描 loc_tree 找任意 (size, loc) 匹配的 varnode（忽略 create_index），返回 create_index 最大者。用于 G3 诊断时桥接断链的 use-def（实验性，当前未被主管线调用）。
### 2026-06-27（续）：is_auto_live（解锁 RuleEarlyRemoval）
- @is_auto_live() -> bool@ 对齐 @Varnode::isAutoLive@（varnode.hh）：保守返回 false（AUTOLIVE_HOLD 设置机制未移植，无 varnode 被标记）。is_indirect_source 才是空 varnode 的真修复。

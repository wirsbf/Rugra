# `op.rs` API Reference

**源代码路径**: `src/op.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **文档目标**: 解释 Rugra 当前 `PcodeOp` 相关结构、标志位和操作银行的职责
- **可信边界**: 本文以当前 `src/op.rs` 所体现的 **P-code 操作结构建模** 为核心，不再沿用旧式“完整旧架构已稳定可用”的写法
- **阅读方式**: 请结合以下文件一起看：
  - `src/op.rs`
  - `src/opcodes.rs`
  - `src/varnode.rs`
  - `src/address.rs`
  - `src/funcdata.rs`
  - `docs/data_contract.md`

> 若本文与源码不一致，应以当前源码为准，并优先修正文档。

---

## 模块定位

`op.rs` 是 Rugra 当前 **P-code 操作层** 的核心模块之一，主要负责：

1. 定义单条 P-code 操作的结构表示：`PcodeOp`
2. 定义与操作状态相关的一组位标志（flags）
3. 提供操作引用包装类型：`PcodeOpRef`
4. 提供操作片段/拼接分析辅助结构：`PieceNode`
5. 提供操作容器：`PcodeOpBank`

它在整体链路中的位置大致是：

- `pcoderaw.rs` 表示更原始的、接近 lifting 输出的操作
- `op.rs` 表示进入图结构后的正式操作对象
- `funcdata.rs` 将这些对象组织到单函数分析上下文中
- `heritage.rs`、`action.rs`、`ruleaction.rs` 等在此基础上做 SSA、重写和分析
- `printlanguage.rs` / `printc.rs` 最终消费这些结构并生成文本输出

---

## 与 Ghidra 的关系

本文档中涉及的核心类型主要对应 Ghidra 的：

- `op.hh`
- `PcodeOp`
- `PcodeOpBank`
- 若干与操作属性相关的 flag 语义

但需要明确：

- **结构命名接近 Ghidra，不等于运行时行为已经与 Ghidra 完全一致**
- 本模块当前应被理解为 **Rugra 的现行操作层建模基础**
- 与 Ghidra 的“行为级一致性”仍需依赖单独的验证与对拍文档，而不是由 API 文档直接证明

---

## 核心设计思路

`op.rs` 的关注点不是“如何直接生成 C 代码”，而是如何为函数级分析提供一个可变换、可追踪、可链接的操作图层。

它解决的问题包括：

- 一条 P-code 操作如何保存 opcode、输入、输出、时序信息
- 如何标记这条操作是否为：
  - 分支
  - 调用
  - 已死亡
  - 布尔输出
  - 不可折叠
  - 间接来源
  - 非打印节点
- 如何将操作对象放进容器统一管理
- 如何在重写、DCE、SSA、结构恢复过程中追踪这些对象

---

## 公共 API 总览

当前本文重点覆盖以下公共项：

- `TypeOp`
- 一组公开的操作标志常量
- `IopSpace`
- `PcodeOp`
- `PcodeOpRef`
- `PieceNode`
- `PcodeOpBank`

---

## 1. `TypeOp`

### `pub struct TypeOp`

`TypeOp` 是与操作类型语义相关的结构体。

### 当前文档口径

从当前模块职责来看，`TypeOp` 更适合被理解为：

- 操作语义分类/行为支持的基础类型
- 与 opcode 的高级语义或类别信息有关
- 为更高层的分析或规则处理提供辅助

### 说明

由于当前公开文档中缺少更详细的源码注释，本文不把它夸大描述为完整稳定的“行为数据库”或“完全对齐 Ghidra 的语义工厂”。

更保守的理解是：

- 它属于操作语义层的一部分
- 它可能参与操作类别、属性或行为推断
- 具体字段和使用方式应以 `src/op.rs` 实现为准

---

## 2. 操作标志位常量（flags）

`op.rs` 公开了一大组 `u32` 标志位常量，用于描述一条 `PcodeOp` 的属性状态。

这些常量本质上属于：

- **位掩码（bit flags）**
- **操作元信息**
- **规则系统和打印系统的判定依据**

### 标志位的作用

这些标志不是“单独的业务对象”，而是用来回答类似问题：

- 这条操作是不是分支？
- 这条操作是不是调用？
- 这条操作是不是已经被标记为 dead？
- 这条操作是否有布尔输出？
- 这条操作是不是不可折叠？
- 这条操作是不是特殊控制流节点？
- 这条操作是不是仅用于内部分析、不应出现在最终打印中？

### 当前公开常量

- `STARTBASIC`
- `BRANCH`
- `CALL`
- `RETURNS`
- `NOCOLLAPSE`
- `DEAD`
- `MARKER`
- `BOOLOUTPUT`
- `BOOLEAN_FLIP`
- `FALLTHRU_TRUE`
- `INDIRECT_SOURCE`
- `CODEREF`
- `STARTMARK`
- `MARK`
- `COMMUTATIVE`
- `UNARY`
- `BINARY`
- `SPECIAL`
- `TERNARY`
- `RETURN_COPY`
- `NONPRINTING`
- `HALT`
- `BADINSTRUCTION`
- `UNIMPLEMENTED`
- `NORETURN`
- `MISSING`
- `SPACEBASE_PTR`
- `INDIRECT_CREATION`
- `CALCULATED_BOOL`
- `HAS_CALLSPEC`
- `PTRFLOW`
- `INDIRECT_STORE`

---

### 标志位分组理解

虽然源码里这些是平铺的常量，但在阅读时可以按语义粗分：

#### A. 控制流相关
- `STARTBASIC`
- `BRANCH`
- `CALL`
- `RETURNS`
- `HALT`
- `NORETURN`
- `FALLTHRU_TRUE`

这类标志帮助回答：

- 是否会切分基本块
- 是否影响 CFG 边
- 是否代表函数调用/返回语义
- 是否是停止点

#### B. 生命周期与状态相关
- `DEAD`
- `MARKER`
- `MARK`
- `MISSING`
- `UNIMPLEMENTED`
- `BADINSTRUCTION`

这类标志帮助规则系统和错误处理识别：

- 节点是否还活着
- 节点是否为内部标记用途
- 节点是否由坏指令或未实现语义产生

#### C. 运算性质相关
- `COMMUTATIVE`
- `UNARY`
- `BINARY`
- `TERNARY`
- `SPECIAL`
- `BOOLOUTPUT`
- `BOOLEAN_FLIP`
- `CALCULATED_BOOL`

这类标志更偏操作语义，用于：

- 简化匹配
- 规则分类
- 打印与表达式生成
- 条件逻辑推断

#### D. 间接/内存/调用语义相关
- `INDIRECT_SOURCE`
- `INDIRECT_CREATION`
- `INDIRECT_STORE`
- `HAS_CALLSPEC`
- `SPACEBASE_PTR`
- `PTRFLOW`
- `RETURN_COPY`
- `CODEREF`

这类标志常用于更高层分析，例如：

- 间接引用
- 指针流
- 调用语义
- 返回值复制
- 地址/代码引用识别

#### E. 输出与显示控制相关
- `NONPRINTING`
- `NOCOLLAPSE`

这类标志偏向表示层或规则约束层，帮助决定：

- 某些节点是否适合进入最终文本输出
- 某些节点是否可以被折叠、合并或简化

---

## 3. `IopSpace`

### `pub struct IopSpace`

`IopSpace` 对应 Ghidra 中 `op.hh` 的相关概念。

它更适合被理解为：

- 与 P-code 操作引用或内部操作空间有关的辅助结构
- 为某些特殊操作节点或间接操作标识提供命名/空间支撑

### `pub const NAME: &'static str = "iop"`

这是 `IopSpace` 暴露的名称常量。

### 语义理解

`"iop"` 一般可理解为：

- internal op / indirect op 之类的内部命名空间
- 用来给某类“不是普通 RAM / register / unique”的操作相关对象提供可识别标签

### 注意事项

在当前文档层面，不应把 `IopSpace` 夸大解释为完整独立的“通用地址空间体系”或“最终用户可感知空间”。

它更像：

- 内部语义工具
- 用于支持 IR / op 级建模
- 不直接面向最终 C 代码使用者

---

## 4. `PcodeOp`

### `pub struct PcodeOp`

`PcodeOp` 是本模块最核心的类型，表示 **一条正式进入 Rugra IR 图结构的 P-code 操作**。

它承担的核心职责包括：

- 保存该操作的 `OpCode`
- 保存该操作的输入列表
- 保存可选输出
- 保存操作时序锚点 `SeqNum`
- 保存与标志位相关的状态
- 为后续：
  - SSA
  - def-use
  - DCE
  - 规则重写
  - CFG/结构化打印
  提供操作级访问入口

### 核心语义

可以把 `PcodeOp` 理解为：

> “图中的一条带有输入、输出、时序和语义类别的操作节点。”

它不是：

- 原始 lifting 结果本身（那更接近 `PcodeOpRaw`）
- 最终高层 AST 节点
- 直接面向用户的 C 代码语句

它是 Rugra 当前反编译分析主链路中的 **正式 IR 操作节点**。

---

### `pub fn new(start: SeqNum, opcode: OpCode) -> Self`

创建新的 `PcodeOp`。

#### 参数
- `start`: 该操作的时序/地址锚点
- `opcode`: 操作码

#### 返回
- 一个新的 `PcodeOp`

#### 作用
这是最基础的构造入口，用于在图中创建一条操作记录。

#### 约束理解
新建后的 `PcodeOp` 一般还需要进一步补充：

- 输入
- 输出
- 标志状态
- 图中链接关系

因此它是“节点创建起点”，不是“完整操作生命周期的终点”。

---

### `pub fn get_opcode(&self) -> OpCode`

获取当前操作的操作码。

#### 用途
常用于：

- 分析分支
- 规则匹配
- 打印阶段判断
- 分类判断（算术、控制流、调用、比较等）

---

### `pub fn get_addr(&self) -> Address`

获取该操作关联的地址。

#### 语义
这是从操作的时序锚点中提取出的地址语义，用于：

- 调试
- 查找
- 报错定位
- CFG / block 相关逻辑

#### 注意
这里的地址是 IR 操作关联的地址锚点，不应简单理解为“源码行号”或“最终语句地址”。

---

### `pub fn get_seq_num(&self) -> &SeqNum`

获取该操作的完整序号对象。

#### 用途
比 `get_addr()` 更完整，因为 `SeqNum` 通常还包含：

- 地址
- 顺序
- 时间/局部序

这对同一机器指令展开出多条 P-code 时尤其重要。

---

### `pub fn num_input(&self) -> usize`

返回输入数量。

#### 用途
常用于：

- 操作分类
- 规则匹配
- 防御式遍历
- 打印表达式时检查输入是否合法

---

### `pub fn get_in(&self, slot: usize) -> Option<&Arc<RwLock<Varnode>>>`

获取指定输入槽位的输入 `Varnode`。

#### 参数
- `slot`: 输入位置索引

#### 返回
- 对应输入 varnode 的只读引用包装，若不存在则返回 `None`

#### 说明
之所以返回带锁的共享引用，说明当前 Rugra 的操作对象与 varnode 对象是图式共享结构，而不是简单值复制。

---

### `pub fn get_out(&self) -> Option<&Arc<RwLock<Varnode>>>`

获取输出 `Varnode`。

#### 返回
- 若该操作有输出，则返回输出节点
- 否则返回 `None`

#### 说明
不是所有操作都有输出，例如某些控制流类操作就可能没有普通意义上的输出 varnode。

---

### `pub fn is_dead(&self) -> bool`

判断该操作是否被标记为 dead。

#### 语义
通常用于：

- 死代码消除
- 清理阶段
- 打印过滤
- 规则跳过

#### 注意
“dead” 是操作生命周期状态，不等于对象已经物理销毁。

---

### `pub fn is_call(&self) -> bool`

判断该操作是否具有调用语义。

#### 用途
可用于：

- 调用恢复
- 参数与返回值分析
- 打印阶段生成调用表达式

---

### `pub fn is_branch(&self) -> bool`

判断该操作是否具有分支语义。

#### 用途
可用于：

- 基本块切分
- CFG 边构建
- 结构化控制流恢复

---

## 5. `PcodeOpRef`

### `pub struct PcodeOpRef(pub Arc<RwLock<PcodeOp>>)`

这是对 `Arc<RwLock<PcodeOp>>` 的包装类型。

### 作用

它的主要作用是：

- 让 `PcodeOp` 的共享引用更方便进入集合或银行结构
- 统一操作对象在容器层的引用形式
- 避免在上层接口中到处直接暴露底层锁包装类型

### 为什么需要包装

因为当前 Rugra 的 IR 不是简单的树或线性列表，而是带有共享引用关系的图结构。  
`PcodeOpRef` 让以下事情更容易处理：

- 存入 bank
- 在多个分析阶段共享同一节点
- 做标记、销毁、替换时保留同一对象身份

---

## 6. `PieceNode`

### `pub struct PieceNode`

`PieceNode` 对应 Ghidra `op.hh` 中的相关结构，用于表示与“piece / 拼接 / 分片”语义有关的节点。

### 适合理解为

- 某种与操作局部片段有关的辅助结构
- 为分析复合数据拼接关系提供支持
- 在处理子片段、piece 合成、偏移等场景下使用

### 当前不要夸大理解的部分

在当前文档层面，不应把它描述成一个“完整的结构化表达式系统”或“通用 AST 片段节点”。

更保守的说法是：

- 它是 P-code 操作分析中的辅助节点
- 它与某个 `PcodeOp` 的弱引用、输入槽位和偏移量有关
- 它主要服务于内部 IR 级处理，而不是直接服务于最终 C 输出

---

### `pub fn new(op: Weak<RwLock<PcodeOp>>, slot: i32, offset: i32) -> Self`

创建新的 `PieceNode`。

#### 参数
- `op`: 关联的操作弱引用
- `slot`: 所关联的输入槽位
- `offset`: 类型或片段偏移

---

### `pub fn is_leaf(&self) -> bool`

判断当前片段节点是否为叶子节点。

#### 用途
适合用于：

- 片段树/分解结构遍历
- 判断是否还能继续展开
- 递归处理终止条件

---

### `pub fn get_type_offset(&self) -> i32`

获取类型偏移量。

### `pub fn get_slot(&self) -> i32`

获取关联输入槽位。

这两个接口都属于 `PieceNode` 的基础查询接口，用于在片段分析中定位当前节点的上下文。

---

## 7. `PcodeOpBank`

### `pub struct PcodeOpBank`

`PcodeOpBank` 是当前 Rugra 中 **统一管理 P-code 操作对象的容器**。

你可以把它理解为：

> “函数级 P-code 操作节点的银行/仓库/统一管理器”。

它通常承担：

- 创建操作
- 保存操作
- 查询操作
- 标记操作状态
- 修改 opcode
- 清理 dead 操作
- 销毁指定操作

在 Rugra 当前架构里，它通常会与以下对象协作：

- `Funcdata`
- `VarnodeBank`（若在其他模块中定义）
- `BlockBasic`
- `ActionDatabase`

---

### `pub fn new() -> Self`

创建空的 `PcodeOpBank`。

---

### `pub fn create(&mut self, opcode: OpCode, num_inputs: usize, addr: Address) -> PcodeOpRef`

创建一条新的操作并加入 bank。

#### 参数
- `opcode`: 操作码
- `num_inputs`: 输入数量
- `addr`: 操作关联地址

#### 返回
- 新建操作的引用包装 `PcodeOpRef`

#### 作用
这是 bank 层的统一创建入口，适合保证：

- 操作统一纳管
- 节点身份稳定
- 后续查找、标记和销毁一致

#### 说明
与 `PcodeOp::new` 相比，这个入口更偏“容器负责的创建与注册”。

---

### `pub fn mark_alive(&mut self, op: PcodeOpRef)`

将操作标记为活跃。

#### 用途
适用于：

- 恢复被误判的节点
- 重写后重新启用节点
- 生命周期管理

---

### `pub fn mark_dead(&mut self, op: PcodeOpRef)`

将操作标记为死亡。

#### 用途
适用于：

- DCE
- 重写中替换旧节点
- 延迟清理策略

#### 注意
被标记 dead 不等于立刻从 bank 中物理移除。

---

### `pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode)`

修改某条操作的 opcode。

#### 用途
可用于：

- 规则重写
- 语义规范化
- 将某类操作替换为更简化的形式

#### 风险
修改 opcode 必须保证：

- 输入/输出数量仍然语义合理
- 不会破坏下游打印或分析假设
- 图仍保持自洽

---

### `pub fn destroy_dead(&mut self)`

销毁所有已经被标记为 dead 的操作。

#### 作用
这是延迟清理机制的重要部分。

#### 典型使用方式
常见流程是：

1. 先 `mark_dead`
2. 后统一 `destroy_dead`

这种方式比“见一个删一个”更安全，因为它允许规则系统先完成批量重写，再统一收尾。

---

### `pub fn destroy(&mut self, op: PcodeOpRef)`

销毁指定操作。

#### 说明
与 `destroy_dead` 相比，这是更直接的单节点销毁入口。

#### 注意
调用前通常需要确保：

- 引用关系可安全解除
- 不会留下悬空输入/输出链接
- 上层图与 bank 状态保持一致

---

### `pub fn find_op(&self, seq: &SeqNum) -> Option<PcodeOpRef>`

按 `SeqNum` 查找操作。

#### 参数
- `seq`: 目标操作的时序锚点

#### 返回
- 找到则返回 `Some(PcodeOpRef)`
- 否则返回 `None`

#### 作用
这是调试、对齐、验证、图遍历时非常关键的查找入口。

---

## 8. 当前模块在主流程中的作用

`op.rs` 当前可以被放在以下主链路中理解：

```text
PcodeOpRaw
  ↓
注入 Funcdata
  ↓
创建/组织 PcodeOp 与 Varnode
  ↓
由 PcodeOpBank 管理操作节点
  ↓
被 CFG / SSA / Action / Rule / Print 层消费
```

也就是说，本模块不负责：

- 直接从二进制解码机器码
- 直接输出最终 C 源码
- 单独完成 SSA
- 单独完成变量恢复

它负责的是：

- 把“操作”这件事稳定地建模出来
- 让后续所有分析和打印都有统一的操作节点可用

---

## 9. 当前文档边界与风险提醒

在使用 `op.rs` API 时，请特别注意以下几点：

### 9.1 不要把结构存在等同于能力完成
例如：

- 有 `PcodeOp`
- 有 `PcodeOpBank`
- 有大量 flags

并不自动代表：

- 所有优化规则都已完善
- 所有 opcode 都已完整消费
- 与 Ghidra 行为已经完全一致

---

### 9.2 不要把 `PcodeOp` 当成最终高层语句
`PcodeOp` 是 IR 节点，不是最终用户看到的高级 C 语句。

---

### 9.3 修改 opcode 或标志位时要同步考虑图一致性
任何对 `PcodeOp` 的重写都可能影响：

- Varnode 连接
- CFG 切分
- SSA 语义
- 打印行为
- DCE 与清理阶段

---

### 9.4 `PcodeOpBank` 是统一真相源之一
如果某操作已经由 bank 管理，就不应在其他地方偷偷维护一套脱离 bank 的“影子节点集”。

---

## 10. 推荐联动阅读

想继续理解本模块，建议接着看：

1. `opcodes.md`
   - 看 opcode 语义分类

2. `varnode.md`
   - 看操作的输入输出节点如何表示

3. `pcoderaw.md`
   - 看原始操作如何进入正式图结构

4. `funcdata.md`
   - 看操作如何进入单函数上下文

5. `heritage.md`
   - 看这些操作如何进入 SSA / heritage 相关过程

6. `printlanguage.md` / `printc.md`
   - 看这些操作如何最终参与文本输出

---

## 11. 一句话总结

`op.rs` 是 Rugra 当前 P-code 操作层的核心建模模块：它定义了**操作节点是什么、如何被标记、如何被引用、如何被统一管理**，并为后续的 SSA、规则重写、控制流分析和打印输出提供操作级基础设施。
## 2026-06-26：is_calculated_bool

- `is_calculated_bool()` — `PcodeOp::isCalculatedBool`（op.hh:211）：检查 CALCULATED_BOOL|BOOLOUTPUT 标志。解锁 RuleBooleanNegate/RuleLogic2Bool。

## 2026-06-27：is_marker / is_bool_output

- `is_marker() -> bool`（op.hh:185）：检查 MARKER 标志（MULTIEQUAL/INDIRECT）。解锁 JumpBasic::is_prune。
- `is_bool_output() -> bool`（op.hh:190）：检查 BOOLOUTPUT 标志。解锁 Varnode::is_bool_output_def。

## 2026-06-29：uses_spacebase_ptr / mark_spacebase_ptr（op.hh:432 + funcdata.hh:487）

- `uses_spacebase_ptr() -> bool`（对齐 `PcodeOp::usesSpacebasePtr`）：检查 SPACEBASE_PTR 标志。heritage 的 discoverIndexedStackPointers 给 stack-pointer-relative STORE 打此 flag，guardStores 据此决定是否建 Stack 空间 INDIRECT。
- `mark_spacebase_ptr(&mut self)`（对齐 `Funcdata::opMarkSpacebasePtr`）：设置 SPACEBASE_PTR 标志。

## 2026-06-27（续）：CSE 方法

- `get_eval_type() -> u32` — `PcodeOp::getEvalType`（op.hh:169）：返回 unary/binary/special/ternary 标志位。
- `get_cse_hash() -> u64` — `PcodeOp::getCseHash`（op.cc:130-147）：计算公共子表达式检测哈希。非 unary/binary 或 COPY 返回 0。
- `is_cse_match(other) -> bool` — `PcodeOp::isCseMatch`（op.cc:153-171）：完整 CSE 匹配测试（相同 opcode + 大小 + 输入）。

### 2026-06-27（会话2）：is_boolean_flip（解锁 condexe）

- `is_boolean_flip() -> bool` — `PcodeOp::isBooleanFlip`（op.hh:210）：CBRANCH 的布尔语义是否翻转。当为 true 时，CBRANCH 在输入为 TRUE 时走 fallthru 边（FALSE 时跳转）。condexe 的 verifySameCondition + is_true_out_to 用此适配 Rugra 边顺序。

### 2026-06-27（会话2 续）：compare_order（解锁 RuleOrPredicate）

- `compare_order(bop) -> i32` — `PcodeOp::compareOrder`（op.cc:778-790）：比较两个 op 的控制流顺序。同块比较 SeqNum.order；不同块用 find_common_block 找 LCA，LCA 是本块则在前（-1），是 bop 块则在后（1），否则无序（0）。RuleOrPredicate 用此决定 branch0/branch1 谁在后以定位 finalBlock。
### 2026-06-27（续）：is_indirect_source（解锁 RuleEarlyRemoval）
- @is_indirect_source() -> bool@ 对齐 @PcodeOp::isIndirectSource@（op.hh:180）：读 INDIRECT_SOURCE 标志（op 的输出喂给 CPUI_INDIRECT 追踪内存副作用）。RuleEarlyRemoval 不得删此类 op。注：SET 路径未移植，当前总 false。

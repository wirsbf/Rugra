# `block.rs` API Reference

**源代码路径**: `src/block.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **文档目标**: 说明 Rugra 当前控制流块模型、CFG 相关对象和结构化块表示
- **可信边界**: 本文档描述的是当前 `block.rs` 在工程中的职责与公开接口角色，不代表“控制流恢复已经与 Ghidra 完全一致”
- **阅读建议**: 建议与以下文档配合阅读：
  - `funcdata.md`
  - `op.md`
  - `varnode.md`
  - `heritage.md`
  - `printc.md`
  - `../data_contract.md`

---

## 模块定位

`block.rs` 是 Rugra 当前**控制流块模型与块图组织层**的核心模块之一。  
它的主要职责是：

1. 定义基本块及其共同抽象
2. 定义块之间的连接关系
3. 提供控制流图容器
4. 提供若干结构化块类型，用于把低层 CFG 逐步表达成更接近高级语言控制结构的形式

从整体链路看，它位于大致如下位置：

```text
raw ops / PcodeOp
  -> Funcdata
  -> BlockBasic / BlockGraph
  -> dominance / loop / structure-related processing
  -> structured blocks (if / while / list / goto ...)
  -> PrintLanguage / PrintC
```

因此，`block.rs` 更适合被理解为：

- **函数级控制流组织层**
- **从操作节点走向结构化输出的中间桥梁**
- **SSA、循环分析、结构恢复和打印层的重要依赖**

而不是：

- 反汇编层
- 类型恢复层
- 最终输出层
- 当前已完成全部控制流恢复证明的证据

---

## 与 Ghidra 的关系

本模块中的主要概念明显参考了 Ghidra 的 `block.hh`，包括：

- `FlowBlock`
- `BlockBasic`
- `BlockGraph`
- `BlockIf`
- `BlockWhileDo`
- `BlockDoWhile`
- `BlockList`
- `BlockGoto`
- `BlockCopy`

但需要明确：

- **命名与对象分层对齐，不等于行为已经完全对齐**
- 本模块当前更能证明“架构方向与对象模型接近 Ghidra”
- 不能仅因为这些对象存在，就宣称：
  - CFG 已全面恢复正确
  - dominance / frontier 已全面验证一致
  - loop structuring 已全部成熟
  - 最终控制流输出已与 Ghidra 等价

---

## 当前设计思路

`block.rs` 主要解决两个层次的问题。

### 第一层：低层控制流组织
围绕基本块和边关系，回答：

- 一组 `PcodeOp` 如何按控制流边界切成 block
- block 之间如何建立前驱/后继关系
- 如何在图层表达 dominance、RPO、loop 等分析基础

### 第二层：高层结构块表达
围绕结构化块对象，回答：

- 某段图能否被表达为 `if`
- 某段图能否被表达为 `while-do`
- 某段线性块能否被表达为 `BlockList`
- 某段无法自然结构化的图是否应退化为 `goto`

这说明 `block.rs` 并不只是“保存基本块列表”的地方，它还是：

- CFG 分析基础设施
- 结构恢复过渡层
- 打印层语句组织的重要语义来源

---

## 公共 API 总览

本文重点覆盖以下公开项：

- `BlockType`
- 一组 block 标志常量
- `FlowBlock`
- `BlockBasic`
- `BlockEdge`
- `BlockRef`
- `BlockGraph`
- `BlockCopy`
- `BlockGoto`
- `BlockIf`
- `BlockWhileDo`
- `BlockDoWhile`
- `BlockList`
- `BlockSwitch`

---

## 1. `BlockType`

### `pub enum BlockType`

用于标识控制流块的类型。

## 角色

`BlockType` 是块层分类的基础枚举，用于说明一个 block 当前属于哪类结构。  
它的作用通常包括：

- 区分基础块与结构化块
- 让打印层和结构恢复阶段按类型分支处理
- 作为调试和图遍历时的快速分类依据

## 当前应如何理解

它更适合作为：

- **控制流块类别标签**

而不是：

- 高级语言语法本身
- 最终代码生成的直接替代物

也就是说，`BlockType` 用来表达“当前块是什么类型”，但不等于最终一定能生成完全理想的高级语言结构。

---

## 2. 控制流块标志位常量

本模块公开了一组 `u32` 标志位，用于表示块对象的状态或属性。

### 当前公开常量

- `TERMINAL`
- `GOTO_TERMINAL`
- `RETURN_TERMINAL`
- `ENTRY_POINT`
- `DEAD`
- `MARK`

### 这些标志的作用

它们主要用来回答类似问题：

- 这个 block 是否为终结块
- 它是不是通过 `goto` 终结
- 它是不是 `return` 终结
- 它是不是函数入口块
- 它是不是已经被标记为 dead
- 它是不是被分析流程临时标记过

### 推荐理解方式

#### A. 终结性质相关
- `TERMINAL`
- `GOTO_TERMINAL`
- `RETURN_TERMINAL`

这些标志主要帮助判断 block 的控制流结束方式。

#### B. 生命周期与入口相关
- `ENTRY_POINT`
- `DEAD`

这些标志主要描述 block 的角色和生命周期状态。

#### C. 临时分析标记
- `MARK`

通常用于分析过程中的临时标识，而不是最终用户语义。

### 注意事项

这些标志存在，只说明 block 层已经有较细的状态语义。  
它们不等于：

- CFG 已完全正确
- 所有 block 分类都已完成验证
- 结构恢复已成熟稳定

---

## 3. `FlowBlock`

### `pub trait FlowBlock: std::fmt::Debug + Send + Sync`

所有块类型的共同抽象接口。

## 角色

`FlowBlock` 是 block 体系中的统一抽象层，用于把以下对象纳入同一控制流块体系：

- 基本块
- 图块
- 条件块
- 循环块
- 顺序块
- goto 块
- copy 块
- 其他结构化块

## 设计意义

有了 `FlowBlock`，上层逻辑可以：

- 用统一引用类型持有不同 block
- 在图结构中混合使用基础块与结构化块
- 让结构化恢复不是“重建另一套完全独立的树”，而是继续使用统一块抽象

这使 `block.rs` 更接近 Ghidra 风格的“块也是对象、图也是块、结构块也是块”的设计方式。

## 当前边界

`FlowBlock` 的存在说明架构设计成熟度较高，但不自动证明：

- 所有块类型都已完整实现
- 所有结构化块都已进入主线
- 结构恢复行为已经与 Ghidra 一致

---

## 4. `BlockBasic`

### `pub struct BlockBasic`

表示一个基本块。

## 角色

`BlockBasic` 是当前控制流层最基础、最重要的块类型之一。  
它通常表示一段：

- 顺序执行
- 中间不被控制流切断
- 由若干 `PcodeOp` 组成
- 以控制流终结点结束或自然落空结束

的基础块。

## 当前应如何理解

`BlockBasic` 是：

- CFG 的基本单位
- dominance、frontier、loop 分析的对象
- 结构化恢复进一步聚合的基础积木
- 输出层组织语句时的重要局部语义块

它不是：

- 最终高级语言块
- 直接等同于源码中的一个语句块
- 完整的函数表示

---

### `pub fn new(index: i32, start_addr: Address) -> Self`

创建一个新的基本块。

#### 参数
- `index`: 块索引
- `start_addr`: 块起始地址

#### 作用
建立一个新的基础块对象，作为后续装载 `PcodeOp` 和连接 CFG 的起点。

#### 说明
这个构造函数只建立“块壳”，并不自动填充：

- 操作序列
- 前驱/后继关系
- dominance 信息
- loop 信息

---

### `pub fn add_op(&mut self, op: PcodeOpRef)`

向块尾部追加一条操作。

#### 作用
把 `PcodeOp` 纳入当前基本块中。

#### 语义
说明 `BlockBasic` 当前承担了“有序操作容器”的职责。

#### 注意
操作加入 block 后，调用方仍需保证：

- 顺序是正确的
- 这条 op 属于该 block
- 与 CFG 终结语义不冲突

---

### `pub fn last_op(&self) -> Option<PcodeOpRef>`

获取块中的最后一条操作。

#### 作用
常用于：

- 判断块的终结指令语义
- CFG 边推断
- 结构恢复分析
- 打印阶段决定语句收尾

---

### `pub fn first_op(&self) -> Option<PcodeOpRef>`

获取块中的第一条操作。

#### 作用
常用于：

- 块调试输出
- 起始语义识别
- 块级遍历和打印准备

---

## 5. `BlockEdge`

### `pub struct BlockEdge`

表示控制流图中的一条边。

## 角色

`BlockEdge` 用于表达 block 与 block 之间的连接关系，是 CFG 的基本组成单元之一。

## 当前应如何理解

它承担的是：

- 图连接信息
- 前驱/后继关系组织
- loop 边 / 正常边 / 反向索引等图层辅助信息

它不是：

- 高级语言中的 `if` / `while` 语法对象
- 最终输出结构本身

---

### `pub fn new(point: Arc<RwLock<dyn FlowBlock + Send + Sync>>, reverse_index: i32) -> Self`

创建一条新的边记录。

#### 参数
- `point`: 边所连接到的 block
- `reverse_index`: 反向索引或与边组织相关的辅助位置编号

#### 作用
建立块间关系的一个边对象，供图结构维护使用。

---

## 6. `BlockRef`

### `pub struct BlockRef(pub Arc<RwLock<dyn FlowBlock + Send + Sync>>)`

块对象的统一引用包装。

## 角色

`BlockRef` 的意义类似于 `PcodeOpRef`：

- 为不同类型的块提供统一引用包装
- 方便进入集合、图结构和容器
- 让调用方不用到处显式操作底层共享锁类型

## 使用价值

它体现出当前 block 体系并不是简单的值复制模型，而是：

- 共享对象
- 可被图结构和分析流程共同持有
- 可能在多个阶段被读取或改写

---

## 7. `BlockGraph`

### `pub struct BlockGraph`

表示一个块图，同时自身也作为一种块存在。

## 角色

`BlockGraph` 是当前 CFG 组织层的核心容器。  
它的重要性在于：

- 它不只是“块列表”
- 它还包含块间连接
- 它可以作为更高一级结构块继续参与控制流建模

这种“图也是块”的设计，是理解 Rugra 当前 block 架构的关键。

## 它通常承担的职责

- 保存 block 集合
- 保存 block 之间的边关系
- 提供 dominance 分析入口
- 提供 RPO 计算入口
- 提供 loop 计算和结构恢复相关入口
- 作为结构化控制流分析的基础容器

---

### `pub fn
 new() -> Self`

创建一个空的块图。

---

### `pub fn add_block(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>)`

将一个块加入图中。

#### 作用
把基础块或结构化块纳入当前图容器管理。

---

### `pub fn get_size(&self) -> usize`

返回图中块的数量。

---

### `pub fn get_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>`

按索引获取图中的块。

---

### `pub fn clear(&mut self)`

清空图内容。

#### 作用
用于重置或重新构建图结构。

---

### `pub fn add_edge(`

为图添加一条边。

#### 作用
建立块与块之间的连接关系。

#### 说明
这是 CFG 构建的核心接口之一，但具体的边类型语义仍要结合终结操作和控制流分析来理解。

---

### `pub fn build_dom_tree(&mut self)`

构建支配树。

#### 作用
为后续以下阶段提供基础：

- dominance 分析
- frontier 计算
- SSA Phi 放置
- loop 结构判断
- 结构恢复

#### 当前边界
该函数的存在说明图层已具备 dominance 分析入口，  
但不能仅凭文档存在就宣称 dominance 行为已与 Ghidra 完全对齐。

---

### `pub fn build_dom_depth(&mut self)`

基于支配树构建深度信息。

#### 作用
为后续遍历、优先级和结构恢复提供辅助层级信息。

---

### `pub fn build_dom_subtree(&mut self)`

构建支配子树关系。

#### 作用
使支配树不仅可作为父子关系，也可更方便用于后续子树级分析。

---

### `pub fn calc_dom_frontier(&mut self)`

计算支配边界（dominance frontier）。

#### 作用
这是 SSA、Phi 节点放置等分析的重要基础。

#### 重要性
这意味着 `block.rs` 不只是控制流展示层，还直接和 SSA 构造有耦合。

---

### `pub fn calc_rpo(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>`

计算反向后序（RPO）。

#### 作用
RPO 常用于：

- CFG 遍历
- 数据流分析
- dominance 算法
- 结构恢复顺序控制

---

### `pub fn structure_loops(&mut self) -> bool`

执行循环结构化。

#### 作用
尝试把图中的循环组织成更接近高级控制流的结构。

#### 返回
- 通常表示是否成功完成某种结构化步骤

#### 注意
存在这个接口，并不意味着所有循环都已经能被稳定、正确、高质量地恢复成高级结构。

---

### `pub fn add_loop_edge(`

添加循环边。

#### 作用
用于在 loop 分析或 loop structuring 过程中记录或构建循环相关边关系。

---

### `pub fn calc_loop(&mut self)`

计算图中的循环。

#### 作用
识别和组织 loop 相关结构，为后续：

- `while`
- `do-while`
- 更高级 loop 恢复

提供基础。

---

## 8. 结构化块类型

除了基础块和块图，本模块还定义了一组更高层的结构化块类型。  
这些类型的意义在于：把“原始 CFG”逐步表达成更接近高级语言控制结构的对象。

---

## `pub struct BlockCopy`

表示另一个块的复制或包装结构。

### 作用
通常用于：

- 保留结构变换中的映射关系
- 对某个块做结构化包装
- 在图转换时临时或辅助性复用已有块语义

### 注意
这类对象通常更偏内部结构组织工具，不应直接当成最终用户语义节点。

---

## `pub struct BlockGoto`

表示 `goto` 结构。

### 作用
当某段控制流不能自然表达成更高级结构时，`BlockGoto` 提供一种显式跳转表达方式。

### 设计意义
它很重要，因为真实反编译器不能假设所有 CFG 都能完美结构化。  
因此：

- `goto` 不是失败的标志
- 而是“在语义保真优先”原则下的保守表达方式

---

## `pub struct BlockIf`

表示结构化 `if` / `if-else` 块。

### 作用
用于把某段条件控制流表达成更高级的分支结构。

### 当前语义
它通常包含：

- 条件块
- true 分支
- 可选 false 分支

### 重要边界
`BlockIf` 的存在说明结构恢复层正在把图表达成高级控制流，  
但并不自动说明：

- 所有分支都能恢复成漂亮的 `if`
- 所有条件都已正确折叠
- 输出已经与成熟反编译器等价

---

## `pub struct BlockWhileDo`

表示 `while-do` 结构化循环块。

### 作用
用于把某类 loop 结构表达成 `while` 风格控制流。

### 当前语义
通常包含：

- 循环头 / 条件块
- 循环体

---

## `pub struct BlockDoWhile`

表示 `do-while` 结构。

### 作用
用于表达先执行后判断的循环模式。

---

## `pub struct BlockList`

表示线性顺序执行的一组块。

### 作用
把若干按顺序执行、无复杂分支打断的块组合成一个更高层的顺序块。

### 设计意义
这使打印层更容易把图结构转换成顺序语句块，而不是裸 CFG 节点遍历。

---

### `pub fn new(index: i32, children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>) -> Self`

创建一个新的顺序块。

#### 参数
- `index`: 块索引

- `children`: 顺序子块列表

#### 作用
把一组按顺序执行的块包装为单个 `BlockList`。

---

## `pub struct BlockSwitch`

表示 `switch-case` 结构化选择块。

### 作用
用于把多路分支（通常是间接跳转或跳转表）表达为高级 `switch-case` 结构。

### 当前语义
通常包含：
- `control`: 包含 `BRANCHIND` 的控制块
- `cases`: 对应的 case 体分支块列表
- `case_values`: 与 cases 对应的常量匹配值（例如 `case 0:`, `case 1:`）
- `default_case`: 可选的 `default` 分支块
- `index_varnode`: 可选的控制 switch 索引的变量

---

## 当前模块的核心价值

从当前架构看，`block.rs` 的价值主要在于：

1. **为函数级控制流提供统一对象模型**
2. **为 dominance、frontier、loop 等分析提供基础结构**
3. **为结构化恢复提供逐层提升的块表示**
4. **为 `PrintLanguage` / `PrintC` 提供更接近高级语句组织的输入**

换句话说，它是：

- CFG 层
- SSA 辅助层
- 结构恢复层
- 输出准备层

共同依赖的重要中间支柱。

---

## 当前风险与边界提示

### 1. 块对象存在不等于结构恢复成熟
有 `BlockIf`、`BlockWhileDo`、`BlockDoWhile` 不等于所有真实程序都能稳定恢复为高级结构。

### 2. dominance 接口存在不等于行为已验证一致
有 `build_dom_tree()`、`calc_dom_frontier()` 不等于已与 Ghidra 一致。

### 3. `goto` 是保守表达，不是错误
当无法自然结构化时，`BlockGoto` 是合理结果，而不是单纯失败。

### 4. `BlockGraph` 是主真相源之一
如果控制流
图已经进入 `BlockGraph`，不应在其它层偷偷维护一套脱离图的平行控制流结构。

---

## 推荐联动阅读

建议接着阅读：

1. `op.md`
2. `varnode.md`
3. `funcdata.md`
4. `heritage.md`
5. `action.md`
6. `printlanguage.md`
7. `printc.md`
8. `../data_contract.md`

---

## 一句话总结

`block.rs` 是 Rugra 当前**控制流块模型与结构化块表示层**的核心模块：它既负责基本块和 CFG 的组织，也为 dominance、loop 分析和更高层的 `if/while/list/goto` 结构表达提供对象基础，是从底层操作图走向可打印控制流结构的关键桥梁。
### 2026-06-23（续）：F_SWITCH_DISPATCH 边标记

- `edge_flags` 新增 `F_SWITCH_DISPATCH` 用于标记 switch dispatch 边。

### 2026-06-23（续）：CASE_BODY flag

- `block_flags` 新增 `CASE_BODY`，标记 cascade switch 的 case body 块。供 blockaction/printc 层检测。

### 2026-06-23（续）：CASE_BODY flag

- `block_flags::CASE_BODY` 标记 cascade switch case body。

### 2026-06-23（续）：effective_size_out + GOTO_EDGE flags

- FlowBlock 新增 `effective_size_out()`/`effective_get_out()`，排除 goto 标记边。
- block_flags 新增 `GOTO_EDGE_0`/`GOTO_EDGE_1`。

### 2026-06-25：is_consumed() + 对齐 Ghidra collapseInternal

- FlowBlock::is_consumed() — DEAD flag 检查，对齐 Ghidra sizeIn==0&&sizeOut==0。
- interleaved 循环跳过 consumed 块。
- gcc 53/53，175/176 测试。getparameter 5 if，控制流差 174。

### 2026-06-25：BlockBasic size_in/out 返回 0 当 consumed

- BlockBasic::size_in/size_out 在 DEAD flag 设置时返回 0。
- 对齐 Ghidra collapseInternal 的 sizeIn==0&&sizeOut==0 检查。
- curl 24/24 OK，httpd 12/29（大量函数因 consumed 块边清零导致变量声明遗漏）。
- 175/176 测试。

### 2026-06-25：过滤 DEAD 边的 size_in/out

- BlockBasic::size_in/out 过滤来自 DEAD 块的边（对齐 Ghidra identifyInternal）。
- get_in/get_out 也过滤 DEAD 边。
- 效果：后继块的 effective size_in 减少，使 proper_if 能匹配。
- 175/176 测试（预存失败）。

### 2026-06-25：回退到简单 DEAD size_in/out

- 移除动态过滤（死锁/性能问题）。
- BlockBasic size_in/out 在 DEAD 时返回 0。
- gcc 53/53，175/176 测试。getparameter 5 if。

### 2026-06-25：set_flags 清空 edges（实验）

### 2026-06-25：block.rs 恢复最佳状态

### 2026-06-25：FlowBlock as_any_mut + BlockBasic 边操作

### 2026-06-27（会话2）：边操作原语（解锁 condexe）

为支撑 condexe 核心图重写（condexe.cc:712），BlockBasic 新增忠实于 Ghidra block.cc 的边操作：
- `get_out_rev_index(slot) -> i32` / `get_in_rev_index(slot) -> i32` — `FlowBlock::getOutRevIndex/getInRevIndex`（block.cc）：返回反向边索引。
- `half_delete_in_edge(slot)` / `half_delete_out_edge(slot)` — `FlowBlock::halfDeleteInEdge/halfDeleteOutEdge`（block.cc:140/149）：只删除边的本端，并修正剩余边的反向索引。
- `replace_edges_thru(in_slot, out_slot)` — `FlowBlock::replaceEdgesThru`（block.cc:198-216）：移除本块的入/出边，但在入块与出块间建立直连边，保留槽位。condexe 的 `removeFromFlowSplit` 核心。

BlockGraph 新增：
- `remove_block_arc(bl)` — `BlockGraph::removeBlock`（block.cc:1517）：先断开所有入/出边，再从 blocks 列表移除（不 drop Arc）。
- `remove_edge_blocks(src, dst)` — `BlockGraph::removeEdge`：对称删除 src→dst 边的两端。

### 2026-06-27（会话2 续）：find_common_block（解锁 RuleOrPredicate）

- `BlockGraph::find_common_block(bl1, bl2) -> Option<BlockArc>` — `FlowBlock::findCommonBlock`（block.cc:736-795）：支配者树最近公共祖先（标准等深上溯算法，等价 Ghidra mark 版）。被 `PcodeOp::compareOrder` 用于判定不同块内两 op 的控制流顺序。

### 2026-06-27（会话3 G4）：FlowBlock 标记原语 + edge flags（解锁 LoopBody）

为支撑 Ghidra LoopBody 算法（blockaction.cc:46-490），新增忠实于 Ghidra block.hh 的标记原语：

**block_flags**：复用现有 `MARK`（f_mark）。
**edge_flags 新增**：
- `F_LOOP_EXIT_EDGE`（Ghidra f_loop_exit_edge）— LoopBody::setExitMarks 标记
- `F_BACK_EDGE`（Ghidra f_back_edge）— 可归约图的回边
- `F_IRREDUCIBLE_EDGE`（Ghidra f_irreducible）— 结构化器引入的不可归约边
- **修正 bug**：`F_GOTO_EDGE` 原为 1<<1（与 F_CONTINUE_EDGE 重复），改为 1<<2
- **2026-06-28 新增 spanning-tree 边分类**（对齐 Ghidra block.hh:108-118）：`F_TREE_EDGE`(1<<7)/`F_FORWARD_EDGE`(1<<8)/`F_CROSS_EDGE`(1<<9)/`F_LOOP_EDGE`(1<<10) + `SPANNING_MASK`。由 `CollapseStructure::find_spanning_tree`（DFS）标记，`order_loop_bodies` 读 `F_BACK_EDGE` 检测循环。

**FlowBlock trait 新增方法（2026-06-28）**（对齐 Ghidra block.hh:288/331）：
- `set_out_edge_flag(slot, flag)` — 对第 slot 条出边 OR-set 边 flag（Ghidra setOutEdgeFlag）。默认实现用 `as_any_mut` downcast 到 `BlockBasic`/`BlockGraph` 的 `outgoing` 字段。
- `clear_edge_flags(mask)` — 清除所有出边的 mask 位（Ghidra clearEdgeFlags）。
- `is_back_edge_out(slot)` — 第 slot 条出边是否为回边（Ghidra isBackEdgeOut）。

**BlockBasic 新字段**：`visit_count: i32`（Ghidra getVisitCount/setVisitCount）。

**FlowBlock trait 新增方法**（默认 no-op，BlockBasic 覆盖）：
- `is_mark`/`set_mark`/`clear_mark`（block.hh:286-288）
- `get_visit_count`/`set_visit_count`（block.hh visit count）
- `is_goto_in(i)`/`is_goto_out(i)`（block.hh:346-347）——**2026-06-29 修复**：`BlockBasic::is_goto_out` 此前只查边级 `F_GOTO_EDGE`，但 TraceDAG 把 goto 标在 block 级 `GOTO_EDGE_0/1` 上。修复后同时查边级和 block 级标志，使 ruleBlockWhileDo 能正确识别 break 边。
- `set_loop_exit(i)`/`clear_loop_exit(i)`（block.hh:294-295）
- `remove_in_edge_from(exclude_indices)`（block.cc:1469 忠实移植）——从块的 incoming 列表中移除 index 匹配的前驱边。对应 Ghidra `BlockGraph::removeEdge(begin, end)`，是 newBlockGoto/newBlockIfGoto "消费" goto 边的机制（使 goto 源对 target 的 sizeIn 不可见）。2026-06-29 新增，当前未被调用（ruleBlockGoto 消费实验因 Rugra 非对称边追踪导致图损坏，已回退；保留为未来对称边图工作的基础设施）。

### 2026-06-29：BlockIf goto_target 字段（newBlockIfGoto 风格，block.cc:1799）
- BlockIf 新增 `goto_target: Option<Arc<...>>` 字段。当 Some 时，表示 if-goto 块（`if (cond) goto target;`），body 保持外部（非嵌入）。忠实 Ghidra BlockIf::gototarget（block.hh:660）。
- 所有 7 个 BlockIf 构建点已更新（goto_target: None 为默认）。

### 2026-06-29（续）：remove_in_edge_from 自环死锁修复
- `remove_in_edge_from` 的 retain 闭包中 `e.point.read()` 改为 `try_read()`。此前若 `e.point == self`（自环边），在持有自身 write lock 时 read 会永久死锁（ap_count_dirs 挂起根因）。try_read 失败时保留边（安全默认）。

### 2026-06-29（续 2）：VarnodeBank::find_input
- `find_input(size, loc)` — 忠实移植 `VarnodeBank::findInput`（varnode.hh）。查找指定 size+address 的 INPUT varnode。用于 ActionRestrictLocal + AncestorRealistic。

### 2026-07-01：CBRANCH 出边 + 支配查询（解锁 RuleConditionalMove/Int2FloatCollapse/IgnoreNan）
- `FlowBlock::dominates(other)`（block.cc:386-395）— 沿 immed_dom 链上溯判断支配。
- `FlowBlock::get_true_out(cbranch)/get_false_out(cbranch)`（block.hh:299-300）— 按 BOOLEAN_FLIP 重映射 CBRANCH 真/假出边（Rugra out[0]=taken,out[1]=fallthru；flip 时翻转）。
- `FlowBlock::get_in_rev_index(slot)` trait 方法（block.hh:308）— 入边的反向索引。
- `find_condition(bl1,edge1,bl2,edge2)` 自由函数（block.cc:839-858）— 返回支配两路径的 CBRANCH 块 + slot1。解锁 RuleInt2FloatCollapse 核心。

### 2026-07-01（续 2）：is_entry_point + get_start_block
- `FlowBlock::is_entry_point()`（block.hh:325）— ENTRY_POINT flag 检查，trait default。
- `BlockGraph::get_start_block()`（block.cc:1649-1655）— 第一个 entry point 块。

### 2026-07-01（续 2）：build_dom_tree reindex
build_dom_tree 开头 reindex 所有块到向量位置（防止 dead-flow 删块后索引越界）。

### 2026-07-01（续 3）：BlockWhileDo +for_init/for_iter

### 2026-07-01（续 4）：JOINED_BLOCK flag + create_new_block
block_flags: +JOINED_BLOCK (1<<9, block.hh:97)。Funcdata: +create_new_block。

### set_order（2026-07-03 续）
- 新增 `BlockBasic::set_order`：重置块内所有 op 的 SeqNum::order，均匀分布。对齐 Ghidra block.cc:2638-2651。用于 spliceBlockBasic 后。

### SWITCH_OUT / UNSTRUCTURED_TARG flags（2026-07-03 续 7）
- `block_flags` 新增 `SWITCH_OUT`（1<<10）和 `UNSTRUCTURED_TARG`（1<<11）。
- 对齐 Ghidra `f_switch_out`（block.hh:92）/`f_unstructured_targ`（block.hh:93）。
- **位值偏离技术债**：Ghidra 用 0x10/0x20，但 Rugra 早期把 0x10/0x20 分配给了 DEAD/MARK。本次用新位 1<<10/1<<11，**语义对齐，位值待统一重排**。
- 用于 `splice_block_basic` 的 flags 合并（block.cc:1609-1619）：splice 后 `bl->flags = (bl & (unstructured_targ|entry_point)) | (outbl & switch_out)`。

### 2026-07-04（续）：find_common_block_n + get_stop_addr
- `BlockGraph::find_common_block_n(block_set)`（对齐 block.cc:796）：N-way 支配树 LCA，用 HashSet 模拟 mark。供 build_dominant_copy 使用。
- `BlockBasic::get_stop_addr()`（近似 block.cc:2328 getStop）：用最后 op 地址近似块的结束地址（无 cover 系统）。

### 2026-07-04：block_flags 位值完整对齐 Ghidra block.hh:88-105
- 所有 Ghidra 共享 flags 用精确位值：SWITCH_OUT=0x10, UNSTRUCTURED_TARG=0x20, MARK=0x80, ENTRY_POINT=0x200, DEAD=0x4000, JOINED_BLOCK=0x20000。
- Rugra 独有 flags 移到 0x80000+（避免与 Ghidra 未来 flags 冲突）：RETURN_TERMINAL=0x80000, CASE_BODY=0x100000, GOTO_EDGE_0=0x200000, GOTO_EDGE_1=0x400000。
- 删除死代码 TERMINAL/GOTO_TERMINAL（从未被读取）。
- 验证：所有 flag 访问通过命名的 `block_flags::*` 常量（无原始十六进制掩码），所以位值变更不影响任何调用点语义。952/952 测试通过，curl 无回归。

### 2026-07-04（续）：移植 block-graph 重写方法
- `set_default_switch(pos)`（block.cc:318）：标记出边为 switch 默认边（设 F_DEFAULTSWITCH_EDGE）。
- 新增 `edge_flags::F_DEFAULTSWITCH_EDGE = 1<<7`（Ghidra f_defaultswitch_edge=4，Rugra 用新位避免与 F_GOTO_EDGE 冲突）。

### 2026-07-04（续 2）：新增 DUPLICATE_BLOCK flag
- `block_flags::DUPLICATE_BLOCK = 0x40000`（f_duplicate_block, block.hh:106）。nodeSplit 创建的重复块。
<!-- annotation-pass: 2026-07-04 -->
 

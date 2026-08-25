# `block.rs` API Reference

**源代码路径**: `src/block.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **Ghidra 12.0.4 对齐级别**: L2；edge flags、双向 reverse-index、parent、RPO/loop/dominator 与 marshal 均有已复现反例
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

`start_addr` 同时是存量直接读取者的兼容镜像。`FlowInfo::split_basic`
完成分块时会通过 `set_initial_range` 安装闭区间；区间的两端是完整
`Address`，因此不会丢失 address-space 身份。与 Ghidra `setInitialRange`
一样，结束端取 `beg` 的空间和 `end` 的 offset。

`set_initial_range` 本体是 `pub`（原为 `pub(crate)`，BLOCK-STOPADDR-
FIXTURE-REGRESSION-0001 放宽）。Ghidra 侧 `setInitialRange` 为 private +
`friend class Funcdata`（block.hh:462/467），公开构造路径是
`Funcdata::setBasicBlockRange(bb, beg, end)`（funcdata.hh:556，内联转发）。
Rugra 直接在 `BlockBasic` 上暴露 `pub`，使 crate 外的 oracle fixture
能构造同等的合法块状态（锁定 C++ fixture 经 `#define private public`
走 `fd.setBasicBlockRange`）。生产语义不变；无 range 时的回退仍见下条。

### `pub fn get_stop_addr(&self) -> Address`

返回初始指令覆盖范围的最后一个地址，对应 `BlockBasic::getStop`
(`block.cc:2328-2335`)。这个值来自 `set_initial_range` 记录的结束端，
不再用块内最后一条 op 的地址近似。尚未安装初始范围的存量
Rust 块仍回退到构造时的 `start_addr`；Ghidra 原生构造器不接受
这个兼容参数（Ghidra 在 cover 为空时返回 invalid `Address()`，
该差异归 `BLOCKBASIC-COVER-0001`；Ghidra 没有任何“末条 op 地址”
回退，因此 0d2252d 移除旧近似是对的，手工构造块必须显式安装
cover 才是合法状态）。

本轮只闭合 `setInitialRange` 建立的单范围。`copyRange`/`mergeRange`、
多不相连范围下的 `contains`/`getEntryAddr`与 RangeList marshal 仍归
`BLOCKBASIC-COVER-0001`，不由该字段的存在推断已完成。

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

### `pub fn structure_loops(&mut self, rootlist: &mut Vec<...>) -> anyhow::Result<()>`

执行循环结构化（`BlockGraph::structureLoops`，block.cc:2194-2215）。

#### 作用
`do { findSpanningTree; findIrreducible; needrebuild 时清生成树 label 并重跑 } while(needrebuild)`，
最后 `irreduciblecount > 0` 时调用 `calc_loop`。产出 RPO 成员列表、边分类与
rootlist（含不可归约边标记）。

#### 返回
- `Ok(())`；`find_spanning_tree` 两遍后仍有 extraroots 时返回 LowlevelError 等价错误。

#### 注意
`irreduciblecount > 0` 时调用完整实现的 `calc_loop`（BLOCK-CALCLOOP-0001，
oracle fixture `block_calcloop_1204` MATCH）：DFS 环检测补标 f_loop_edge。

---

### `pub fn find_irreducible(&self, preorder: &[...], irreduciblecount: &mut i32) -> bool`

识别不可归约边（`BlockGraph::findIrreducible`，block.cc:1147-1199）。

#### 作用
反向前序遍历 `preorder`；对每个回边入点 x，用 FIND(y)=`copymap` 种子
reachunder 集，BFS 中区间测试 `[visitcount, visitcount+numdesc)` 之外的 y'
标记边为 `f_irreducible`（唯一写者），树边触发 needrebuild，非树边清除
cross/forward 旧分类；末尾把集合坍缩为 x（清 mark、copymap 指向 x）。

#### 返回
- `needrebuild`：存在不可归约的树边时需要重建生成树（见下方暴力证据）。

---

### `pub fn add_loop_edge(&mut self, begin: &Arc<...>, outindex: usize)`

标记既有出边为 loop 边（`BlockGraph::addLoopEdge`，block.cc:1451-1464）。

#### 作用
把 `begin` 的第 `outindex` 条**既有**出边标记为 `f_loop_edge`（cc:1463 经
`setOutEdgeFlag`，两侧 halves 同写：out 边 + 目标块的镜像 in 边，block.cc:240-246）。
Ghidra 按 out-index（而非目标块身份）定位边——同一目标的多条平行出边必须可区分
（cc:1459-1462 注释）。`#ifdef BLOCKCONSISTENT_DEBUG` 的 parent 检查在 oracle
release 构建中编译掉。

---

### `pub fn calc_loop(&mut self)`

DFS 环检测补标 loop 边（`BlockGraph::calcLoop`，block.cc:2104-2147）。

#### 作用
从 `blocks[0]`（cc:2118 `list.front()`）起做显式栈 DFS，按出边槽序访问
（cc:2130 先递增 per-path-level 游标再用槽位）。`f_mark`=已访问、
`f_mark2`=在当前 DFS 路径上（cc:2120）：

- 出边指向仍带 `f_mark2` 的块 → 成环 → `add_loop_edge(bl, i)` 标
  `f_loop_edge`（cc:2133-2137，oracle 的 throw 被注释掉——不可归约 failsafe）；
- 出边已带 `f_loop_edge` → 跳过（cc:2131 `isLoopOut`，重跑时视早前环断边不存在）;
- 已访问但已弹栈（f_mark 置、f_mark2 清）→ 截断搜索（cc:2138 else）；
- 新块 → 置 `f_mark|f_mark2` 入栈（cc:2138-2142）。

弹栈只清 `f_mark2`（cc:2124-2128）；栈空后按 list 序清所有块的
`f_mark|f_mark2`（cc:2145-2146）。在 structureLoops 中仅当
`irreduciblecount > 0` 时运行（cc:2211-2214）。

#### 对齐证据
oracle fixture `tests/oracle/block_calcloop_1204`（BLOCK-CALCLOOP-0001）：
7 用例（可归约回边/嵌套循环/自环/双跑 isLoopOut 跳过/截断/不可归约
end-to-end/structureReset 链含支配树）双侧投影 byte-MATCH。

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

### 2026-07-16：B4 INTERIOR_GOTOOUT/GOTOIN flags + set_goto_branch 完整化

- block_flags 新增 `INTERIOR_GOTOOUT`（0x400, block.hh:97）+ `INTERIOR_GOTOIN`（0x800, block.hh:98），匹配 Ghidra 位值。
- `set_goto_branch(bl, j)` 对齐 Ghidra `FlowBlock::setGotoBranch`（block.cc:305-314）**三件事**：edge flag + source `INTERIOR_GOTOOUT` + target `INTERIOR_GOTOIN`。此前只设 source 的 GOTO_EDGE，target 侧 `is_interior_goto_target` 失效。
- `is_interior_goto_target` 先查 `INTERIOR_GOTOIN`（Ghidra 模型），回退 in-edge 扫描。
- 新增 `has_interior_goto`（block.hh:324）查 `INTERIOR_GOTOOUT`。

### 2026-07-16：B3 BlockInfLoop struct

- 新增 `BlockInfLoop` struct（对齐 Ghidra `BlockInfLoop` block.hh:735）：包装单 body 块（自循环），incoming/outgoing/parent/flags。`get_type()` 返回 `BlockType::InfLoop`，`get_ops`/`get_start_addr` 委托 body。
- printc `emit_structured_infloop` 输出 `do { <body> } while(true);`（对齐 emitBlockInfLoop printc.cc:3097）。

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

### 2026-08-23：halfDelete reciprocal reverse-index 修复

- `BlockBasic::half_delete_in_edge` 对应 locked Ghidra
  `FlowBlock::halfDeleteInEdge`（`block.cc:100-112`）：从删除槽开始逐项左移
  `incoming`，保留 surviving 本地 half-edge 的 `reverse_index` 与 label，并把每条
  surviving source 的 `outgoing[reverse_index].reverse_index` 逐次减一。
- `BlockBasic::half_delete_out_edge` 对应
  `FlowBlock::halfDeleteOutEdge`（`block.cc:115-127`）：对 `outgoing` 做同序滑动，
  并更新每条 surviving target 的 `incoming[reverse_index].reverse_index`。删除的
  另一半按 half-delete 契约暂时保留，由 `removeInEdge/removeOutEdge` 等调用者删除。
- Rust trait-object 边端点可能是任一持有边表的结构化块；内部胶水覆盖这些具体类型。
  自环在当前 per-`Funcdata` 单线程图改写中复用已持有的 `&mut BlockBasic`，避免二次
  获取同一 `RwLock`。
- `BLOCK-HALFDELETE-REVIDX-0001` 的 locked 12.0.4 双侧 fixture 逐槽观察所有块的
  `peer/reverse_index/label`，覆盖非末槽入/出删除、连续删除、PHI 输入槽映射、
  self/parallel 边、双向有序边，以及 single/last-slot 合法边界。空表或越界 slot
  在 Ghidra 函数中没有定义的异常分支，不作为可比较输入。

### 2026-06-27（会话2）：边操作原语（解锁 condexe）

为支撑 condexe 核心图重写（condexe.cc:712），BlockBasic 新增忠实于 Ghidra block.cc 的边操作：
- `get_out_rev_index(slot) -> i32` / `get_in_rev_index(slot) -> i32` — `FlowBlock::getOutRevIndex/getInRevIndex`（block.cc）：返回反向边索引。
- `half_delete_in_edge(slot)` / `half_delete_out_edge(slot)` — `FlowBlock::halfDeleteInEdge/halfDeleteOutEdge`（block.cc:100/115）：只删除指定 half-edge；本地 surviving edge 依序左移，对端 surviving half-edge 的 reciprocal reverse index 随槽位更新。
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
- `clear_out_edge_flag(slot, flag)` — 清除第 slot 条出边的 flag 位（Ghidra clearOutEdgeFlag block.hh:289，set_out_edge_flag 的配对）。**2026-07-16 B5 新增**，供 LoopBody::clearExitMarks。
- `BlockWhileDo.overflow_syntax`（bool，对齐 hasOverflowSyntax block.hh:692）—— **2026-07-16 P7 新增**：条件块 isComplex 时设 true，printc 发射 while(true)+if(cond)break 形式（emitBlockWhileDo cc:3017-3044）。
- `get_flip_path()`（block.hh:297）—— **2026-07-16 新增**：检查 FLIP_PATH flag，供 jumptable checkUnrolledGuard 使用。
- `restricted_by_conditional(cond)`（block.cc:405-425）—— **2026-07-16 新增**：检查块是否完全被条件块 cond 支配（所有路径经 cond 的边到达）。供 ActionConditionalConst apply()。
- `BlockBasic::lift_verify_unroll(var_array, slot)`（block.cc:2802）—— **2026-07-16 新增**：静态方法，验证 varArray 中所有 varnode 由相同 opcode + 匹配常量操作数定义，然后按 slot 展开。供 checkUnrolledGuard。
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
- `FlowBlock::get_true_out(cbranch)/get_false_out(cbranch)`（block.hh:299-300）— **2026-08-23 CONDEXE-TRUEOUT-0002 修正为纯位置语义**：`get_false_out()=out[0]`、`get_true_out()=out[1]`，与 Ghidra 逐字一致，**不读 BOOLEAN_FLIP**。Rugra 流构造（flow.rs:920-928，同 flow.cc:960-967）先压 fallthru 再压 branch，因此 out[0]=false 路径、out[1]=true 路径，与 Ghidra 布局相同；negateCondition（block.cc:2351）翻转 flip 同时交换两条出边以维持该不变量。BOOLEAN_FLIP 只在显式调用点消费（condexe.cc:612、expression.cc:227-230、ruleaction.cc:8981/9428、coreaction.cc:4538、double.cc:922）。`cbranch` 形参已废弃（纯位置实现忽略之），仅为带租约消费文件（ruleaction.rs）保持签名兼容，租约释放后应移除。
- `FlowBlock::swap_edges()`（block.cc:218-233）— **2026-08-23 补齐 cc:225-228**：交换 out[0]/out[1] 后，按交换后槽位回写目标块入边的 reverse_index（此前缺失，negateCondition 后 get_in_rev_index 会过期）。
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

### 2026-07-04（续）：find_common_block_n + get_stop_addr（历史状态）
- `BlockGraph::find_common_block_n(block_set)`（对齐 block.cc:796）：N-way 支配树 LCA，用 HashSet 模拟 mark。供 build_dominant_copy 使用。
- 当时 `BlockBasic::get_stop_addr()` 用最后 op 地址近似块结束。
  2026-08-24 的 `FLOW-TRUNCATED-0001` 切片 B 已用完整 `Address`
  初始范围取代该近似；本条仅保留为历史记录。

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

### 2026-07-22：移植 block.cc Block 子类型 inherent impls（B5 对齐）

完整对齐 Ghidra `block.cc` 中 BlockCopy / BlockGoto / BlockIf / BlockWhileDo /
BlockDoWhile / BlockInfLoop / BlockList / BlockCondition / BlockSwitch 子类型的
虚方法（printHeader / markUnstructured / scopeBreak / nextFlowAfter /
markLabelBumpUp / negateCondition / flipInPlaceTest / flipInPlaceExecute /
getExitLeaf / lastOp / encodeHeader 等）。Rugra 因 struct-with-specific-fields
布局无法直接复用 Ghidra 的 BlockGraph 子类模型，改为 inherent impl 辅助方法
（返回 `String` / `Option` / 索引），由调用方在 downcast 后使用。

**新增模块级常量：**
- `block_flags::LABEL_BUMPUP = 0x1000`（f_label_bumpup, block.hh:99）。
- `block_flags::DONOTHING_LOOP = 0x2000`（f_donothing_loop, block.hh:100）。
- `block_flags::WHILEDO_OVERFLOW = 0x8000`（f_whiledo_overflow, block.hh:102）。
- `goto_type` 模块：`GOTO_GOTO=1` / `BREAK_GOTO=2` / `CONTINUE_GOTO=4`
  （block.hh:89-91，对应 f_goto_goto/f_break_goto/f_continue_goto）。

**新增 FlowBlock trait 方法（默认实现）：**
- `scope_break_trait(cur_exit, cur_loop_exit)`（block.hh:266 FlowBlock::scopeBreak）。
- `get_exit_leaf_trait() -> Option<...>`（FlowBlock::getExitLeaf）。
- `flip_in_place_test() -> i32`（FlowBlock::flipInPlaceTest，默认 2=不可翻转）。
- `flip_in_place_execute()`（FlowBlock::flipInPlaceExecute）。
- `last_op() -> Option<PcodeOpRef>`（FlowBlock::lastOp，默认 None）。

**新增 inherent impl 方法（每个对应 Ghidra block.cc 中的虚方法重写）：**

- **BlockCopy**（block.cc:2835-2854）：`print_header` / `print_tree` /
  `encode_header`。
- **BlockGoto**（block.cc:2856-2903）：新增 `goto_type: u32` 字段；
  `get_goto_target` / `get_goto_type` / `mark_unstructured_target` /
  `scope_break_goto_type` / `goto_prints` / `print_header` /
  `next_flow_after_index`。
- **BlockIf**（block.cc:3067-3135）：新增 `goto_type: u32` 字段；
  `set_goto_target` / `get_goto_target` / `get_goto_type` /
  `mark_unstructured_target` / `scope_break_goto_type` / `print_header` /
  `get_exit_leaf` / `last_op` / `next_flow_after_parent` / `prefer_complement`
  （cc:3093-3109，翻转 CBRANCH 并交换 if_body/else_body）。
- **BlockWhileDo**（block.cc:3316-3351）：`get_initialize_op` /
  `get_iterate_op` / `has_overflow_syntax` / `set_overflow_syntax` /
  `mark_label_bump_up` / `scope_break_children` / `print_header` /
  `next_flow_after`。
- **BlockDoWhile**（block.cc:3426-3452）：`mark_label_bump_up` /
  `scope_break_body` / `print_header` / `next_flow_after`。
- **BlockInfLoop**（block.cc:3454-3483）：`mark_label_bump_up` /
  `scope_break_body` / `print_header` / `next_flow_after`。
- **BlockList**（block.cc:2953-2988）：`get_exit_leaf` / `last_op` /
  `negate_condition` / `get_split_point` / `print_header` / `outgoing_swap`。
- **BlockCondition**（block.cc:2990-3065）：`get_opcode` / `is_split_point` /
  `is_complex` / `last_op` / `negate_condition`（分布 NOT 到两个子条件并
  切换 AND<->OR）/ `scope_break_children` / `print_header` /
  `next_flow_after` / `encode_header` / `flip_in_place_execute`。
- **BlockSwitch**（block.cc:3596-3661）：`get_switch_block` /
  `get_num_case_blocks` / `get_case_block` / `get_num_labels` / `get_label` /
  `is_default_case` / `is_exit` / `mark_unstructured_targets` /
  `scope_break_break_cases` / `print_header` / `next_flow_after` /
  `get_switch_varnode`。

**调用点更新（blockaction.rs）：**
- 3 个 `BlockIf` 构造点（blockaction.rs:3128/3163/3630）+ 1 个 `BlockGoto`
  构造点（blockaction.rs:3715）添加 `goto_type: GOTO_GOTO` 字段
  （由并发会话在 commit 4b5584f 中完成）。

**scope_break 接入主管线（block.rs / blockaction.rs）：**
- 新增 `BlockGraph::scope_break(cur_exit, cur_loop_exit)`（block.cc:1270-1288
  `BlockGraph::scopeBreak`）：按顺序遍历 `blocks`，对每个子块调用
  `scope_break_trait(ind, cur_loop_exit)`，其中 `ind` 是下一个兄弟块的
  index（最后一个子块继承传入的 `cur_exit`）。这是 `ActionFinalStructure::apply`
  的入口（blockaction.cc:2193 `graph.scopeBreak(-1,-1)`）。
- `FlowBlock::scope_break_trait` 在 7 个结构化子类型中重写，dispatch 到
  已有的 inherent 辅助方法（之前定义但从未被调用，导致所有 BlockGoto/BlockIf
  保留默认 `GOTO_GOTO`，emit 阶段打印 `goto code_r0x...;`）：
  - `BlockGoto` → `scope_break_goto_type`（block.cc:2866）
  - `BlockIf` → `scope_break_goto_type`（block.cc:3075）
  - `BlockWhileDo` → `scope_break_children`（block.cc:3324）
  - `BlockDoWhile` → `scope_break_body`（block.cc:3434）
  - `BlockInfLoop` → `scope_break_body`（block.cc:3462）
  - `BlockCondition` → `scope_break_children`（block.cc:3034）
  - `BlockSwitch` → `scope_break_break_cases`（block.cc:3613）
  - `BlockList` → 内联 `BlockGraph::scopeBreak` 遍历（Ghidra 中 BlockList
    继承 BlockGraph，不重写 scopeBreak）
- `ActionFinalStructure::apply`（blockaction.rs）在标记 BRANCH/CBRANCH
  之前调用 `fd.sblocks.scope_break(-1, -1)`，把目标 == 内层循环 exit 的
  goto 重分类为 `BREAK_GOTO`，emit 阶段打印 `break;` 而非 `goto code_r0x...;`。

**验证：** `cargo check` 通过（block.rs / blockaction.rs / coreaction.rs 零错误；
剩余 4 个 E0308 错误位于 printc.rs / typefactory.rs，属其他并发会话的进行中工作）。
每个移植方法上方均有 `// Ghidra: block.cc:<行号> <函数名>` 注释；Rust 粘合代码
标记为 `// RUGRA-GLUE: <reason>`。
 
 
 
 

### 2026-08-15：公共 BlockGraph::find_spanning_tree（BLOCK-INDEX-ASSIGN-0001）

Ghidra `FlowBlock::index` 生产唯一赋值点的 1:1 移植：`BlockGraph::findSpanningTree`
（block.cc:1009-1136，Tarjan 生成树 + 反向后序）。此前 Rugra 侧只有
blockaction.rs 的私有 `find_spanning_tree`（位置索引域、HashMap 局部状态、
不写 `FlowBlock.index`）——本次新增**公共**方法，全副作用对齐：

- `BlockGraph::find_spanning_tree(&mut self, preorder, rootlist) -> anyhow::Result<()>`
  （block.cc:1009）。副作用：
  - 每个成员块 `index = -1`、`visitcount = -1`、`copymap = self`（cc:1023-1030/1118-1123）；
  - 每遍开始 `clear_edge_flags_all()` = `clearEdgeFlags(~((uint4)0))`（cc:1045），
    清空所有成员块入/出边两侧的全部 label 位；
  - DFS 出边分类 tree / back|loop / forward / cross（cc:1093-1105），出边与
    镜像入边两侧同时 OR-set（Ghidra setOutEdgeFlag block.cc:240-246）；
  - `numdesc` 在发现时置 1、子树弹栈时向上累加（cc:1073/1084/1098）；
  - `rpostcount` 自 n 递减后赋 `index`（cc:1080-1082）；
  - 结束 `list = rpostorder`：成员列表本身重排为反向后序（cc:1135）；
  - `preorder` 输出前序、`rootlist` 为 in/out 参数（尾交换使 orighead 最后访问
    →RPO 最前，cc:1031-1035/1129-1133；两遍 repeat + extraroots 提升与
    rootlist 换位 cc:1041-1127；repeat==1 仍发现 extraroots 时返回
    LowlevelError 等价的 anyhow 错误，cc:1110-1111）。

**支撑原语（均为 trait 默认实现或自由函数）：**
- `set_in_edge_flag(slot, flag)` — setOutEdgeFlag 的镜像入边半边（block.cc:245）。
- `set_out_edge_flag_mirrored(cur, i, lab)`（自由函数，pub）— 完整 Ghidra
  setOutEdgeFlag（block.cc:240-246）：出边 + 目标块镜像入边；自环边（目标即
  本块）在单一把锁内同时写两侧，避免对调用方已持有的写锁重入死锁。
- `is_irreducible_out(i)`（block.hh:332）— DFS 跳过不可归约出边判定
  （cc:1089；注意 cc:1045 的全清使外部预置 label 不存活，跳过分支对外部
  预置不可达——与锁定 oracle 行为一致）。
- `get_copy_map`/`set_copy_map`（block.hh:163 + 私有 copymap 字段 block.hh:123）。
- `get_num_desc`/`set_num_desc`（私有 numdesc 字段 block.hh:126；未发现时 -1
  对应 C++ 未初始化值）。
- `BlockBasic`/`BlockGraph` 新字段 `copy_map: Option<Weak<...>>`、`num_desc: i32`。

**对齐证据：** `tools/run_block_index_assign_oracle.sh` 权威差分（锁定 oracle
e40ed130 重建 + pinned base + overlay src/block.rs），8 case 逐字节一致
（空图早退/单块/单入口 DAG + 状态污染复位/多入口 rootlist 交换/无根假定
首块 + 回环/不可达分量两遍 extraroots/stale-root 机制 + 自环/irreducible 与
goto 预置 label 全清）。blockaction.rs 私有变体保留未接线（接线需统一
index 域并重过差分门禁，注释已注明）。

## 支配树重建域（block_domroot_1204，2026-08-19）

**`BlockGraph::structure_loops(&mut rootlist)`** — `block.cc:2194-2215`
`BlockGraph::structureLoops(vector<FlowBlock*> &rootlist)` 的完整移植：
`do { find_spanning_tree; find_irreducible; needrebuild 时
clear_edge_flags_mask(SPANNING_MASK) + 清 preorder/rootlist 重跑 } while
(needrebuild)`，`irreduciblecount > 0` 时调用 `calc_loop`（登记 stub，见
下方 BLOCK-FINDIRREDUCIBLE-0001 节残差）。`findIrreducible`（cc:1147）已
随本 wave 移植；`calcLoop`（cc:2104）为剩余残差。

**`BlockGraph::calc_forward_dominator(&rootlist)`**（及预留
`calc_forward_dominator_on`）— `block.cc:1954-2032`
`calcForwardDominator` 的 CHK 迭代支配树：prefill `dom[root]=VRoot`、
postorder 降序主循环（排除 root 槽位）、first-processed-pred 按 in-edge 序、
无前驱 idom 置 null。多根图虚拟根（createVirtualRoot/excise，cc:1970-2029）
以 `Dom::VRoot`（dom_index=0，复刻 FlowBlock ctor `index=0` 别名语义，
cc:61-69）建模——finger 走入 VRoot 时落到 rpo[0] 的 postorder 槽
（cross-root merge 得 idom=rpo[0]），excise 后入口块 immed_dom=null。

**`compute_spanning_rpo`** — RUGRA-GLUE：block.cc:1009-1136 的无副作用
RPO 视图（不重排成员列表），供 fixture 观察使用。

**对齐证据：** `tools/run_block_domroot_1204_oracle.sh` 权威差分（锁定
oracle e40ed130 导出重建 libdecomp.a + 不可变 fd runner + fixture 哈希
pin），四 case 双侧逐字节 MATCH（stdout_sha256=080948a5…）：A 尾部孤儿
rootlist swap / B 入口回环 / C 多根 cross-merge VRoot 别名 / D 单根基线。
复核：机制 C 独立 APPROVE（2026-08-19，含四类语义逐项）。

## 不可归约边标记域（block_findirreducible_1204，2026-08-23）

### 2026-08-23：BlockGraph::find_irreducible + structure_loops 完整重建环（BLOCK-FINDIRREDUCIBLE-0001）

Ghidra `f_irreducible` 唯一写者的 1:1 移植：
`BlockGraph::findIrreducible`（block.cc:1147-1199，Tarjan 可归约性测试），
并把 `structure_loops` 从"仅可归约路径"升级为完整
`structureLoops`（block.cc:2194-2215）重建环。

**`BlockGraph::find_irreducible(&self, preorder, irreduciblecount) -> bool`**
（block.cc:1147）逐语句对齐：
- 反向前序遍历 `preorder`（cc:1152-1155 `xi` 自尾部递减）——每个循环体先于
  包围它的循环头被坍缩；
- 对每个 x 的**回边入**（cc:1157-1158 isBackEdgeIn）：源 y 的 `FIND(y)` =
  `copymap` 一步读种子进 reachunder 集并置 mark（cc:1161-1162，无去重——
  平行边会双重种子/双倍计数）；自环 y==x 跳过（cc:1160）；
- reachunder BFS（cc:1164-1189）：跳过已标不可归约的入边（cc:1170）；
  对 y' = FIND(y) 做区间测试——y' 落在 x 的前序区间
  `[visitcount, visitcount+numdesc)` **之外**（cc:1174：严格在 x 之前，或
  达/超过子树末端）即不可归约：`irreduciblecount` 累计（cc:1176，跨
  structureLoops 重建累计）、y 的 `getInRevIndex(i)` 出边槽 + 镜像入边半边
  OR-set `f_irreducible`（cc:1177-1178）、树边 → needrebuild（cc:1179-1180）、
  非树边仅清 cross|forward 旧分类（cc:1182）；否则未标记且 ≠x 的 y' 入集
  （cc:1184-1187）；
- 末尾整集坍缩为 x：清 mark、成员 `copymap` 指向 x（cc:1191-1195）——
  即 FIND 并查集的 union 步，后续顶点经 `y->copymap` 读到（cc:1161/1173）。

**`BlockGraph::structure_loops`** 升级为完整 do-while：`find_spanning_tree`
→ `find_irreducible` → needrebuild 时 `clear_edge_flags_mask(SPANNING_MASK)`
（cc:2206，保 f_irreducible）+ 清 preorder/rootlist 重跑；收敛后
`irreduciblecount > 0` 调 `calc_loop`（完整实现见下方 BLOCK-CALCLOOP-0001
节）。注意
`find_spanning_tree` 每遍开头的 `clearEdgeFlags(~0)`（cc:1045）会把上一遍
findIrreducible 标的 f_irreducible 也清掉——重建遍的收敛依赖 cc:1135
`list = rpostorder` 重排改变下一遍根扫描顺序，与 oracle 一致。

**支撑原语（本次新增，均为 trait 默认实现或自由函数）：**
- `is_tree_edge_in(i)`（block.hh:329）/ `is_back_edge_in(i)`（block.hh:330）/
  `is_irreducible_in(i)`（block.hh:333）— 入边半边谓词（get_in 读 flags，
  与既有 `is_loop_in`/`is_irreducible_out` 同模式）。
- `clear_in_edge_flag(slot, flag)` — clearOutEdgeFlag 的镜像入边半边
  （block.cc:254）。
- `clear_out_edge_flag_mirrored(cur, i, lab)`（自由函数，pub）— 完整
  Ghidra clearOutEdgeFlag（block.cc:250-256）：自环边单锁双写，与
  `set_out_edge_flag_mirrored` 对称。
- `BlockGraph::clear_edge_flags_mask(fl)` — block.cc:966-978 的通用双半边
  mask 清除（`clear_edge_flags_all` 即其 ~0 特例）。
- `find_copy_map(y)`（RUGRA-GLUE）— FIND(y) 的 `copymap` Weak 升级读；
  findSpanningTree 保证 list 内块恒有 copymap（cc:1027/1122），Option 回退
  不可达。

**needrebuild 分支可达性（重要发现）：** 对锁定 oracle 做穷举实验——全部
4 节点有向图 2^16=65536 个（含自环）与全部 5 节点无自环有向图 2^20=1048576
个，`findSpanningTree → findIrreducible` 后 **needrebuild=true 出现 0 次**
（不可归约图分别为 24000/730112 个）。与区间套论证一致：新鲜一致生成树下，
reachunder 成员恒在 x 的 DFS 子树内，其树父不可能既是 x 的真祖先又满足
区间包含。该分支为防御性代码，fixture 投影记 UNTESTED（同 BLOCK-INDEX 对
不可达分支的先例）。

**残差（BLOCK-CALCLOOP-0001 已闭环，更新登记）：**
- ~~`calcLoop`（block.cc:2104-2147）未移植~~ → 2026-08-23 完整移植
  （见下方 BLOCK-CALCLOOP-0001 节 + oracle fixture `block_calcloop_1204`
  全 case MATCH）。
- `EDGEFLAG-BIT7-COLLISION-0001`（预存）：F_TREE_EDGE 与
  F_DEFAULTSWITCH_EDGE 共享 bit 7。本域投影内 bit 7 只可能是 tree
  （wipe-first 后无 default-switch 写者），与 block_index fixture 同一处理；
  重分配需独立任务审计全部使用点。
- ~~生产管线未消费~~ → 2026-08-23 blockaction.rs `order_loop_bodies` 接线
  完整 `structure_loops` 驱动（见 docs/api/blockaction.md）。

**对齐证据：** `tools/run_block_findirreducible_oracle.sh` 权威差分（锁定
oracle e40ed130 导出重建 libdecomp.a + pinned base 296c128 + overlay
src/block.rs/docs，pin-base schema2），7 case 双侧逐字节 MATCH
（stdout_sha256=62c35679…）：可归约菱形零标记 / 自环头排除 / 经典双入口
forward→i 提升 / 平行边双计数 / 嵌套不可归约 FIND 复用 + copymap 坍缩链 /
多根 cross→i 提升 / structureLoops 端到端可归约驱动。投影含
rebuild/cnt、preorder、rootlist、list、每块
index/visitcount/numdesc/mark/copymap、出入边双侧 label 终态。

## calcLoop 环断边补标域（block_calcloop_1204，2026-08-23）

### 2026-08-23：BlockGraph::calc_loop 完整移植（BLOCK-CALCLOOP-0001）

Ghidra `f_loop_edge` 唯一写者链的 1:1 移植：`BlockGraph::calcLoop`
（block.cc:2104-2147）+ 忠实签名的 `BlockGraph::add_loop_edge(begin,
outindex)`（block.cc:1451-1464，替换原先误标 addLoopEdge 的"加新边"死代码
——旧实现语义是 addEdge cc:1439 且无调用者）。

**`BlockGraph::calc_loop(&mut self)`** 逐语句对齐：
- 空图早退（cc:2113）；从 `blocks[0]`（cc:2118 `list.front()`）种子化显式栈
  DFS，置 `f_mark|f_mark2`（cc:2120）；
- per-path-level 游标 `state` **先用后增**（cc:2130 `state.back() += 1` 发生在
  读槽位之后、所有检查之前）——continue 跳过已标边后不会重扫同一槽；
- `is_loop_out(i)` 跳过已带 `f_loop_edge` 的出边（cc:2131）——单次调用内
  同槽不重扫，故仅对**调用前已存在**的 l 标签生效（重跑/stale 场景）；
- 目标带 `f_mark2` → 成环 → `add_loop_edge(&bl, i)`（cc:2133-2137，oracle 的
  LowlevelError throw 被注释掉）；目标带 `f_mark` 无 `f_mark2` → 截断（else
  分支无事发生）；否则新块入栈（cc:2138-2142）；
- 弹栈仅清 `f_mark2`（cc:2125）；栈空后按 list 序对每块清
  `f_mark|f_mark2`（cc:2145-2146）。

**支撑原语（本次新增）：**
- `block_flags::MARK2`（=0x100，block.hh:95 f_mark2）；
- `FlowBlock::clear_flags(f)`（trait 必选方法，block.hh:156 clearFlag
  `flags &= ~fl`；全部 10 个 FlowBlock 实现类落地）。

**生产接线：** `structure_loops` 内 cc:2211-2214 调用点闭环（此前 stub）；
blockaction.rs 侧 `order_loop_bodies` 改调完整 `structure_loops` 驱动
（见 docs/api/blockaction.md BLOCK-CALCLOOP-0001 节）。

**对齐证据：** `tools/run_block_calcloop_1204_oracle.sh` 权威差分（锁定
oracle e40ed130 导出重建 libdecomp.a + pinned base + overlay
src/block.rs+src/blockaction.rs，pin-base schema2），7 case 双侧逐字节
MATCH。投影含 list 序、每块 index/visitcount/numdesc/mark/mark2/copymap/
immed_dom、rootlist + unreachable 判定、出入边双侧 label 终态。直接调用
case 的 desc/copymap 投影为 "-"：oracle FlowBlock 用户构造器（cc:61-69）
不初始化这两个字段（findSpanningTree 才初始化，cc:1025-1027），直接投影
是堆噪声而非算法输出——这一非确定性两侧同因同果，按"不可比即不投影"处
理并在 metadata normalization 登记。

### 2026-08-25：FlowBlock 边 flag 写入 trait 化（selectGoto 非终止修复）
- `FlowBlock::out_edges_mut` / `in_edges_mut`（新 trait 方法）— Ghidra 的 FlowBlock 基类持有
  `outofthis`/`intothis`（block.hh:124-127），对所有子类型生效；Rugra 每个具体类型各存
  `outgoing`/`incoming`，`set_out_edge_flag`/`clear_out_edge_flag`/`clear_edge_flags`/
  `set_in_edge_flag`/`clear_in_edge_flag` 改经这对访问器路由，替换原先只覆盖
  BlockBasic/BlockGraph 的 downcast 链。此前 goto 标记在结构化块（BlockIf/BlockList/
  BlockCondition 等）上被静默丢弃，TraceDAG 反复重提同一边导致 selectGoto 死循环
  （GetStr 家族 >10s 超时根因）。BlockCopy 补空 `incoming`/`outgoing` 字段保持 trait 全。
- `set_out_edge_flag_mirrored` / `clear_out_edge_flag_mirrored` 的 self-edge 分支 — 同步改为
  out_edges_mut/in_edges_mut 访问器（原 downcast 链在结构化块 self-loop 上同样丢标记）。
## isComplex 条件守卫域（RULEBLOCKOR-ISCOOMPLEX-0001，2026-08-25）

`FlowBlock::is_complex`（trait 默认，block.hh:250）从恒 `false` 改为恒
`true`——oracle 基类即 `return true`（非叶/非委托子类一律太复杂，不能当
条件子句）；`BlockBasic::is_complex`（block.cc:2388-2444）全量移植 statement
计数：分支本身（sizeOut>=2 时 statement=1）→ 每 CALL +1（先于输出判空）→
无输出非流断 op（STORE 等）+1 → 有输出计算的保守 calc-explicit 判定
（无 descendant / addr-tied / 被 marker 或块外 op 读 / 引用数 >
max_implied_ref(默认 2, architecture.cc:1420) 任一命中 +1），statement>2
即拒绝折叠。`BlockCopy::is_complex`（block.hh:536）委托
`original.is_complex()`；`BlockCondition::is_complex`（block.hh:635）改为
`first.is_complex()`（原无条件 `true` 是背离 oracle 的占位）。消费方：
blockaction.rs `try_rule_or`（ruleBlockOr blockaction.cc:1342）在折叠
INT_OR/AND 条件前用 `orblock.is_complex()` 守卫——此前恒 false 宽松放行，
导致 my_fwrite 出现 Ghidra 不会做的错误折叠（空体 `if (…||…) {}` 形态）。
注：Ghidra 对 `bl` 自身的 isComplex 检查在 cc:1333-1334 处于注释状态，Rugra
同样不查 `bl` 只查 `orblock`。Rugra 的 BlockBasic 无 arch 回指针，
max_implied_ref 取默认常量 2（与 ActionRestructureVarnode 同一先例）。

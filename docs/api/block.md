# `block.rs` API Reference (基本块与控制流图集)

**源代码路径**: `src/block.rs`

## 模块说明 (Module Doc)

这里定义了从死板线性长阵列到有向分支演变的基石模型：**基本块 (Basic Block)** 及 **结构化流控制图构建网络**。
它完成了控制流指令（从最初仅包含连串打平 Pcode 的切片，演变融合入具备高维语言支配结构（如 IF-DO-WHILE 等AST树层）节点的底层挂载。本模块完整地致信并复刻了 Ghidra 内部的 `block.hh` 类系统族。

---

## 导出的公共 API (Public API)

### 基础结构元类型与枚举

*   **`pub enum BlockType`**: 最核心的类型标记元。指示其作为一个图控节点的类型变通：`Plain`, `Basic`, `Graph`, 甚或已经由结构切分器确立的 `If`、`WhileDo`、`DoWhile`、`Switch` 及 `InfLoop`。
*   **`pub mod block_flags`**: 控制流区块边界标识符：
    *   `TERMINAL` / `GOTO_TERMINAL` / `RETURN_TERMINAL`: 表示它包含或终了于控制权流失边界（跳飞、或函数收尸段）。
    *   `ENTRY_POINT` / `DEAD`: 本函数首个或已经无法被任何边路所触及执行的无效块。

*   **`pub struct BlockEdge`**: 控制分叉的单向带箭连通光缆（从一个 `FlowBlock` 连向另一）。记录这路挂接于母体输出引脚（`reverse_index`）槽位的位置。

---

### `pub trait FlowBlock: std::fmt::Debug + Send + Sync` (控制结点核心虚基元)

多态泛型的核心定义层。无论是最初简朴的“死板单块”或是后续经折叠后长出的“巨大的 If-Else 组嵌套容器块”，它们都被统一视作实现了 `FlowBlock` 特征的图论操作结点！

必须提供的交互能力：
*   图网织机相关: `get_in(&self, slot: usize)`, `get_out`, `add_in_edge`, `add_out_edge`。可以随时查阅该网点的入出分支跨度以及向端点外抛散出几条决策边缘。
*   内在算力查询: `get_ops(&self) -> Vec<PcodeOpRef>` (查阅块内当前承载的所有序列执行微指令), `get_type` 控制结语类别。
*   支配树强行关联: `get_immed_dom`, `get_dom_depth`, `get_dom_children`, `get_dom_frontier`：支配者系统（对于进行 SSA SSA 化构造不可或缺的特质！）。

---

### `pub struct BlockBasic` (基础运行载体块)

最本源最简朴的落脚实物。包含了一排平直不能打断控制流的微操。任何复杂语法树拆到底层树叶一定是一堆 `BlockBasic`！
*   **`pub ops: Vec<PcodeOpRef>`**: 一堆绝不包含 `CBRANCH` 或 `CALL`（除非在最后一句）打断执行的按 `SeqNum` 时间线顺次排列 Pcode 集合。
*   提供诸如 `add_op`, `last_op` 的管理能力以及一套非常完整的基于 `immed_dom` 和 `dom_frontier` 的强缓存。

---

### `pub struct BlockGraph` (流分析统筹与支配引擎主堡)

该子类不仅仅扮演控制流的巨大容器，它也是实现各种图论解算，强绑定支配者层级的计算驱动引擎。（对应原 Ghidra 分析调度中心的 `BlockGraph`）
*   `pub blocks: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>`: 其管理的本层所有图节点集合。

#### 主要计算引擎驱动入口！
这套类包含了极其硬核的图论构造算法包，这些动作是任何反编译器在生成 SSA / 折叠源码**最初的绝对先决步骤**！

*   `pub fn build_dom_tree(&mut self)`
    **(核心中的核心！)**
    调用以彻底计算并更新其名下管理的节点的 Immediate Dominator (直接支配者) 网络。使用的算法在背后高度重构遍历了此流图并计算最近公共祖先来完成建立（详读代码部分使用到的 `intersect` 及基于 RPO (逆后序) 预处理的高效方案）。

*   `pub fn build_dom_depth(&mut self)` / `pub fn build_dom_subtree(&mut self)` 
    建立完整的后备树关系：每个节点的控制树从属从栈底挂载并分配递进深度数值。
*   `pub fn calc_dom_frontier(&mut self)`
    计算支配边界：在 SSA （单静态赋值）转化里，这决定着哪些位置必须插入极其重要的 `OpCode::MULTIEQUAL` ("Phi"节点) 获取分支重聚时的交汇态数据统一！

*   `pub fn calc_rpo(&self) -> Vec<...>`
    (Calculate Reverse Post-Order) 以逆后序遍历深度优先图，保证控制流分析顺着程序线性跑道流向推进的最优扫描图算法底层。

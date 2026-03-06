# `varnode.rs` API Reference (核心数据元节点)

**源代码路径**: `src/varnode.rs`

## 模块说明 (Module Doc)

这是本项目中 P-code 中间表示（IR）的基础承载颗粒。
Varnode 表示 P-code 时空中的一个存储位置及其大小。它可以是寄存器、内存片、或者临时运算的常量与SSA特征变元。此模块在语义级别严格对接并复刻 Ghidra 的 `varnode.hh` 中的 `Varnode` 类。

---

## 导出的公共 API (Public API)

### `pub mod varnode_flags` (Varnode 特征标识位)

这组位掩码用于精确标记变元在流图中的地位，决定其生存法则。绝大部分映射自 Ghidra 的原生特征位：

*   `MARK` / `CONSTANT` / `ANNOTATION`: 常量与标注属性标记。
*   `INPUT` / `WRITTEN`: 表明此变元是一个**基本块级的纯输入参数**还是某个特定 P-code 运算**产出的结果**。如果两者皆否，证明这是一个处于 `Free` 游离态的待回收节点。
*   `TYPELOCK` / `NAMELOCK`: 指示这个变量的类型推断或名字已经被分析器强绑定锁死，后续的 Type Propagation（类型传播扩散）和自动命名 Pass 切勿覆盖它。
*   `EXTERNREF` / `READONLY` / `PERSIST`: 全局与静态数据相关标识。
*   `MAPPED` / `INDIRECT_CREATION`: 跟随函数原型签名或系统外部间接调用的标记。
*   `AUTOLIVE_HOLD` / `INCIDENTAL_COPY`: 在死代码消除与生命周期（Liveness）计算过程中用来豁免特定节点的高级内部使用位。

---

### `pub struct Varnode`

承载 P-code 数据流的基础元数据结构。
由于采用了 `Arc<RwLock<T>>` 架构进行跨引用共享，此内部结构包含大量运行时跟踪组件：

*   **`pub flags: u32`**: 存储上述的 `varnode_flags` 特征位组合。
*   **`pub size: usize`**: 该存储位置/变元占用了多大的字节跨度。
*   **`pub loc: Address`**: 标定这个节点处于哪一个存储空间下的哪个偏移处 (比如在 Registers 空间内偏移 8)。
*   **`pub def: Option<Weak<RwLock<PcodeOp>>>`**: (**关键流关联**) 指明哪一个 `PcodeOp` 运算节点的输出产生了它（单一定义点）。
*   **`pub descend: Vec<Weak<RwLock<PcodeOp>>>`**: (**关键流关联**) 指明目前有哪些其它的 `PcodeOp` 在输入端正在消费这个数据。
*   **`pub high: Option<Arc<RwLock<HighVariable>>>`**: 链接到后期聚合生成的**高级变量对象**（代表 C 语言层面的一个高级聚合变量）。
*   **`pub cover: Option<Box<Cover>>`**: 描述该变量在当前函数指令流跨度内的生存时空区间记录仪。 

#### 核心方法签名与语义

*   `pub fn new(size: usize, loc: Address) -> Self`  
    以给定大小并在某一特定 `Address` (包含 AddressSpace) 处原地凭空制造出一个基础 Varnode。默认初始状态不持有任何关联链接与特殊标志。

*   `pub fn is_unique(&self) -> bool` / `pub fn is_register(&self) -> bool` / `pub fn is_constant(&self) -> bool`  
    快捷判定此 Node 的源宿主所在空间属性：是由 SSA 生成的局域临时变量、真实的 CPU 机架寄存器还是定常数值。

*   `pub fn is_input(&self) -> bool` / `pub fn is_written(&self) -> bool` / `pub fn is_free(&self) -> bool`  
    基于位标志进行快捷的生命特征断言，用以在优化和死代码裁切时筛选变量状态。

*   `pub fn new_constant(val: u64, size: usize) -> Self` / `pub fn new_register(offset: u64, size: usize) -> Self` ...  
    快捷工厂函数，针对特殊的 `Constant`, `Register`, `Ram`, `Unique` 空间生成对应特征的 Node 句柄。

---

### `pub struct VarnodeBank`

变量管理器/银行。类似于 Ghidra 的 `VarnodeBank` 类，在此类容器内注册、销毁并依据多纬度组织存储本函数下的成千上万个微型 Varnode：

*   `pub loc_tree: BTreeSet<VarnodeLocRef>` / `pub def_tree: BTreeSet<VarnodeDefRef>`:  
    同时使用空间位置与定义点序列作为依据的内部排序树（红黑树），提供对特定节点级别的 `O(log N)` 定位查找。

#### 生命周期及操作 API

*   `pub fn create(&mut self, size: usize, loc: Address) -> Arc<RwLock<Varnode>>`  
    正规的 Varnode 登记与请求出口。通过 Bank 创建的新节点会自动被内部记录并分发上全局自增主键 `create_index` 以及并纳入红黑树追踪。
*   `pub fn set_input(&mut self, vn: Arc<RwLock<Varnode>>)` / `pub fn set_def(&mut self, vn: Arc<RwLock<Varnode>>, op: Weak<RwLock<PcodeOp>>)`  
    将注册于树中的变量进行状态切换与依赖更新（如将其定义权指派给某条乘法运算）。在此过程中将发生树脱离再插入与标识更改，从而维护查询树的完全有序平衡！
*   `pub fn clear(&mut self)`  
    抹除当前库中所有的结构引用（用于释放与回滚）。
*   `pub fn make_free(&mut self, vn: &mut Varnode)`  
    将指定游历的节点剥离所有的输入与被写连接，将其降级并标记进入准备剔除的自由态。

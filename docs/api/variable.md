# `variable.rs` API Reference (高阶变量形态层)

**源代码路径**: `src/variable.rs`

## 模块说明 (Module Doc)

对应于 Ghidra 中的 `variable.hh`。
在底层的 P-code 世界线中，同一个 C 语言变量例如 `int i` 在历经一连串的控制流跳跃或重复写入时，会被拆分成几十上百个带有后缀数字版本号的独立（SSA）无名 `Varnode`。
而 **HighVariable（高阶变量）** 则相反：它是一个逻辑层面聚合体（代表原本 C 语言里的那个 `i`），它反向把底下那些在数据流上被证明属于同一个命名的碎片 `Varnode` **收拢统一挂载**！

---

## 导出的公共 API (Public API)

### `pub struct HighVariable` (合一高阶变量)

代表了最终反编译结果代码中将要呈现在你眼前的“那个带名字和类型的本地变量”。
它是通过底层的类型传播（Type Propagation）和符号合并决议所最终产出的高级语言核心资产对象：

*   **`pub name: String`**: 在前端展现的人类可读高层名字 (例如 `uVar1`, `iVar2` 或经过栈重命名的 `local_c`)。
*   **`pub v_type: Arc<Datatype>`**: 该聚合实体统一推断出的数据类型（此类型可能经历多次变种碰撞后最终落锤）。
*   **`pub instances: Vec<Arc<RwLock<Varnode>>>`**: **(核心资产表)** 该集合收录了所有被认为是代表这个高层变量的（散落在各处带有不同版本的）底层 SSA `Varnode`。
*   **`pub id: u64`**: 这个函数的变量记账表内的独占标识。

#### 重要方法

*   `pub fn new(v_type: Arc<Datatype>) -> Self`: 诞生之初必须要有一个锚定的根类型依据。
*   `pub fn get_name(&self) -> &str` / `pub fn set_name(&mut self, name: String)`: 用于分析末端命名引擎 (Name recovery/Demangling) 反复对其调教。
*   `pub fn add_instance(&mut self, vn: Arc<RwLock<Varnode>>)`: 在推演过程中，每当系统确信或者强行并轨发现一个新游荡的微节点与该群集属于同一语义体时，就收入此集中。

---

### `pub mod high_flags` (高级属性强固约束字)

当这批变量在用户修改或者静态扫描分析时，它们的这部分属性将被固化，阻止进一步的优化引擎覆盖它。

*   `NAMELOCK`: 用户的显式重命名已经介入，自动起名规则此后不得干涉和重写它的名称。
*   `TYPELOCK`: 用户手动指定或类型传播引擎已经百分百确信了它的内存布局尺寸结构，后期推导不能覆盖此结果。
*   `ADDRTIED`: （与地址硬绑定）这玩意必须永远留在特定对应的 CPU 物理寄存器或特定栈偏移上活动，绝对禁止在化简时将其升举为一个只活在中间寄存空间中的无主孤魂。

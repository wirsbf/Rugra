# `funcdata.rs` API Reference (函数级总容器)

**源代码路径**: `src/funcdata.rs`

## 模块说明 (Module Doc)

对应 Ghidra `funcdata.hh`。在整个反编译引擎中，`Funcdata` 好比一场行军战役的总参谋部，它**将属于同一个函数的所有分析资产（Varnode 银行、操作库、控制流图、SSA 管理器）统统绑定聚合到一个统一的顶层对象中**。几乎所有的分析 Action 都将其作为唯一入口参数。

---

## 导出的公共 API (Public API)

### `pub struct Funcdata` (函数域总托管器)

*   **`pub name: String`**: 被反编译的目标函数符号名。
*   **`pub baseaddr: Address`**: 函数在二进制中的入口加载基地址。
*   **`pub size: i32`**: 函数体在二进制中占用的原始字节长度。
*   **`pub vbank: VarnodeBank`**: 本函数中所有数据元 (Varnode) 的总注册银行。
*   **`pub obank: PcodeOpBank`**: 本函数中所有执行微操的总操作池。
*   **`pub bblocks: BlockGraph`**: 原始控制流基本块图。
*   **`pub sblocks: BlockGraph`**: 经结构化折叠后的高级控制块图（如 if/while 等）。
*   **`pub heritage: Heritage`**: SSA 构造引擎实例。

#### 核心方法

*   `pub fn new(name: &str, addr: Address, size: i32) -> Self`: 创建函数级容器。所有子系统均置为空初始态。
*   `pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>)`: **必须在 `Arc::new()` 后立即调用**。将自身的弱引用分发给子系统（如 `Heritage`），使其能够反向操作宿主的 vbank/obank。
*   `pub fn clear(&mut self)`: 一键清空所有分析状态（VarnodeBank、PcodeOpBank、BlockGraph、Heritage），用于分析回滚或重新开始。
*   `pub fn num_heritage_passes(&self) -> i32`: 查询 SSA 构造已经完成了多少轮迭代（用于增量分析判定）。

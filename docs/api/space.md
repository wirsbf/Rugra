# `space.rs` API Reference (物理与意象寻址层)

**源代码路径**: `src/space.rs`

## 模块说明 (Module Doc)

该模块是整个逆向分析的“地质地基”。由于处理器具备复杂离散的寄存器插槽、平面主干内存，以及在此架构上特异化模拟产生的各种缓存片段：这些东西对于分析域都是平权的，因此引入 `AddressSpace` 加空间偏移的模型体系。
其在内部设计对齐 Ghidra `space.hh` 中所有空间基数分配规则（Ram, Register, Unique, Const, Stack 等等）。

---

## 导出的公共 API (Public API)

### `pub enum AddressSpace` (存储空间的形态谱系)

描述并界定所寻址的 `Varnode` 的栖身之地模型：
*   **`Ram` (正常内存)**: 平面上连绵不绝的程序代码或静态区内存域地址，所有的 `.text`, `.data` 与动态寻址皆着落于此。
*   **`Register` (CPU寄存器栈)**: 被独立隔离出的超高速存储层。在这里寻找诸如 `EAX`, `RSP` 等的离散数据块。
*   **`Unique` (分析用临时生成间)**: 这是仅存在于 P-code 仿真世界的意象抽屉！用于在剥离复合汇编机器码时（如将一条 `xadd` 化为复数个微操作序列所产生的大量“无处安放又不应当存在”的过程临时桥接点存放空间）。
*   **`Const` (绝对幻相区间)**: 这里没有“物理地址”。存放在这里的东西，其所包含的“Offset”数值**直接等于它自身的被包裹常数值**自身。
*   **`Stack` (运行时栈)**: 专门提供函数调用帧游动的特供存取空间模型，其计算往往是相对于某个不可见栈底动态相连的。
*   **`Join` / `Overlay`**: 虚拟复合的高阶空间，用于把两块（如不同的离散寄存器碎片）当做同一个连串空间来寻址；或在一个区域中虚空盖起另一块镜像以屏蔽原地址碰撞。
*   **`Other(SpaceId)`**: 面向特种稀有微处理器芯片/协处理器的自定义衍生扩展槽口接环。

#### 空间判定与特性查询函数

*   `pub fn space_id(&self) -> SpaceId` / `pub fn from_id(id: SpaceId) -> Self`: 提供和 Ghidra 底层 C 对应的字节序列短 ID (例 `SPACEID_RAM = 0`, `SPACEID_REGISTER = 1`) 的双向匹配铸造。
*   `pub fn is_register(&self) -> bool` / `pub fn is_unique(&self) -> bool` / `pub fn is_const(&self) -> bool` / `pub fn is_ram(&self) -> bool` / `pub fn is_stack(&self) -> bool`  
    用于快速拦截特定属性特性的流分支的判定捷径布尔函数。
*   `pub fn word_size(&self) -> usize` / `pub fn addr_size(&self) -> usize`: 取决于不同的仿真体系和装载要求：定义单步进长度和总偏移极值承载宽度。

---

### 高阶/合成虚拟空间实例结构体群 (Advanced Structural Models)

这部分对于基本平面分析往往透明，但在处理特定架构复杂变量复合折叠，或仿真运行时沙箱建立时非常核心：

*   **`pub struct ConstantSpace`**: 常数专有极简空间模型包裹管理器。
*   **`pub struct UniqueSpace`**: 这个空间维护着一个极速无缝的内部流水线自增池 (`public allocate(&mut self, size: usize) -> u64`)。由于每一条微指令拆解都需要新家，它全权负责把源源不断的新临时地址像挤牙膏一般连贯批发出租。
*   **`pub struct JoinSpace`** & **`pub struct JoinPiece`**:  
    当面对形似“返回一个结构体占据了 `RDX` 和 `RAX` 共同存储拼合的结果”时，系统将通过这套模型注册并缝合碎片跨度（支持把两个相隔十万八千里的不同物理模型 `space:offset:size` 逻辑捏合成一个供上层读取）。
*   **`pub struct OverlaySpace`**: 为存在特种需求的分段覆写与虚模提供底层包装支撑。

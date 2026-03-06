# `pcoderaw.rs` API Reference (未加工微操元)

**源代码路径**: `src/pcoderaw.rs`

## 模块说明 (Module Doc)

本文件对应于 Ghidra 内部的 `pcoderaw.hh`。
此类存在的意义在于：当汇编语言（例如通过 SLEIGH 翻译引擎）刚刚被解析出 P-code 微指令流时，这些操作**尚未被放入函数数据流网络中，也没有被赋予强类型引用智能指针，仅仅是最粗糙的中间码表达**。这种结构体负责承载早期的线性的、易于快速反序列化与缓存的动作数组阶段。只有经历后续建图阶段，它们才会被正式提升转译为 `op.rs` 内的带图论网络状态的 `PcodeOp`。

---

## 导出的公共 API (Public API)

### `pub struct VarnodeRaw` (无引用态变元数据)

处于孵化期的变量载体，只关心纯粹的选址与大小：
*   **`pub space: AddressSpace`**: 存储在哪个模拟层区。
*   **`pub offset: u64`**: 层区内切准偏移。
*   **`pub size: usize`**: 吃多少字节宽度。
*   *方法*: `pub fn to_varnode_data(&self) -> VarnodeData` 用于转换为序列化专用模型快照以供存储传输。

---

### `pub struct PcodeOpRaw` (无关联态操作算子)

此结构没有任何复杂的流图拓扑指针，一切皆为轻量级的标量表达。非常适合用于翻译引擎后端的平面推展！
*   **`opcode: i32`**: （内部持有为 `i32` 原生整形，无缝对接 C 原生 Enum 字面量表映射）代表微操作语义。
*   **`output: Option<VarnodeRaw>`**: 最多持有一个纯元出栈位。
*   **`inputs: Vec<VarnodeRaw>`**: 持有其所需源引流入口位置描述的简单表阵。
*   **`seqnum: Option<SeqNum>`**: （在完全就绪构建时打上的）时间线标识，用以最终追认自己是从哪个原初机码偏移位出生的。

#### 装配操作函数

*   `pub fn add_input(&mut self, varnode: VarnodeRaw)` / `pub fn clear_inputs(&mut self)` 
    模拟压栈或者清扫其依赖的源槽区。
*   `pub fn set_output(&mut self, varnode: VarnodeRaw)`: 将某个位置烙印为写出槽。
*   `pub fn decode(s: &str) -> Option<Self>`: **极其关键的功能集**。它配合对应体系架构下的 SLEIGH 解析器输出物或调试文件，通过解析类似 `"19 -> register:0:4 register:4:4"` 的纯文本文本格式还原出一个未经连接的流网络结构初号机。
*   `pub fn encode(&self) -> String`: 将一个原始微操压化为上面的一行格式化反编译微操打印流序列。

---

### `pub struct PcodeOpRawBuilder` (工厂构造器)

应用常用的流水线组装模式（Builder Pattern）来给 SLEIGH 后端生成大量的翻译组提供连续的链式拼装。这在 Rust 侧大幅减少了临时变量代码的冗余。
*   `builder.output(..).input(..).seq_num(..).build()`: 无缝构造法。

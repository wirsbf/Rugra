# `lib.rs` API Reference

**源代码路径**: `src/lib.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **可信度**: 高
- **适用范围**: 本文档描述的是当前库入口中**实际可见的模块导出与重导出**，以及它们在工程中的作用
- **特别说明**: 旧版 `Decompiler` 相关说明目前只能作为**历史设计痕迹**理解，**不能**再被当成当前稳定可用的主入口 API

---

## 模块说明 (Module Doc)

`lib.rs` 是 `rugra` 的库入口文件，负责：

1. 声明和导出当前主线模块
2. 暴露跨模块共享的基础类型
3. 通过 `pub use` 提供更方便的库级访问路径
4. 作为整个反编译分析框架的公共入口层

从当前代码可见结构来看，`rugra` 的主线已经转向：

- Ghidra 风格核心对象建模
- `Funcdata` 驱动的函数级分析上下文
- `PcodeOp` / `Varnode` / `Address` 等基础 IR 与寻址对象
- `ActionDatabase` 风格的分析/变换流水线
- `PrintLanguage` / `PrintC` 输出链路
- `align/` 下的对齐验证与运行时验证框架

---

## 当前实际导出的模块 (Public Modules)

以下模块在当前 `lib.rs` 中以 `pub mod` 形式公开导出。

### 核心 Ghidra 对齐对象层

- `address`
- `space`
- `varnode`
- `op`
- `opcodes`
- `typeop`
- `heritage`
- `fspec`
- `block`
- `funcdata`
- `pcoderaw`
- `type_system`
- `prettyprint`
- `printlanguage`
- `printc`
- `action`
- `coreaction`
- `ruleaction`
- `cover`
- `variable`
- `merge`
- `blockaction`

### 现存但处于过渡/兼容阶段的模块

- `binary`
- `disasm`
- `ffi`
- `align`

> 注意：这些模块当前确实由 `lib.rs` 公开导出，但其“是否已经完整、稳定、面向最终用户可直接使用”应以对应源码与状态文档为准，不能仅凭导出存在就推断“能力已全部完成”。

---

## 当前实际私有模块 (Private Modules)

以下模块在 `lib.rs` 中作为内部实现使用，并未以 `pub mod` 形式完整暴露：

- `error`
- `types`
- `utils`

不过其中部分内容通过 `pub use` 被重新导出，见下文。

---

## 当前实际重导出 (Re-exports)

`lib.rs` 当前使用 `pub use` 暴露了以下常用类型和结果别名。

### 错误与结果

### `pub use error::{Error, Result};`

为库使用者提供统一的错误类型与结果别名。

**用途**：
- 统一库内部与外部调用的错误返回风格
- 让上层调用者可以直接使用 `rugra::Result`

---

### 地址与范围相关

### `pub use address::{Address, SeqNum, Range, RangeList, RangeProperties};`

导出基础寻址与范围对象。

#### `Address`
用于表示带地址空间语义的地址。

#### `SeqNum`
用于标识操作在地址和顺序上的锚点。

#### `Range`
表示一个地址范围。

#### `RangeList`
表示多个地址范围的集合。

#### `RangeProperties`
与范围属性相关的辅助类型。

**用途**：
- 这些类型贯穿 `Varnode`、`PcodeOp`、CFG、打印与验证等多个阶段
- 是库级最基础的公共类型之一

---

### 控制流图块相关

### `pub use block::{BlockBasic, BlockRef, BlockEdge};`

导出 block 层的核心类型。

#### `BlockBasic`
函数控制流图中的基本块表示。

#### `BlockRef`
对 block 对象的引用包装。

#### `BlockEdge`
块之间的边关系表示。

**用途**：
- CFG 构建
- 支配关系、循环识别等后续分析
- 结构化输出前的控制流组织

---

### 函数级核心对象

### `pub use funcdata::Funcdata;`

导出 `Funcdata` 作为函数级分析上下文的核心入口对象。

**用途**：
- 承载单函数的 IR、block、varnode、操作与分析状态
- 作为后续 Action/Rule/Print 流程的中心对象

**当前定位**：
- 从现有代码结构看，`Funcdata` 是当前主链路中最关键的公共对象之一

---

### 函数原型相关

### `pub use fspec::{FuncProto, ProtoParameter};`

导出函数签名与参数描述相关类型。

#### `FuncProto`
函数原型对象。

#### `ProtoParameter`
函数参数描述对象。

**用途**：
- 函数签名恢复
- 调用约定和参数建模
- 输出层的函数头部生成

---

### 地址空间

### `pub use space::AddressSpace;`

导出地址空间枚举或对应抽象类型。

**用途**：
- 区分 RAM / register / unique / const 等空间
- 驱动 `Varnode` 与打印逻辑的空间语义

---

### P-code 操作码

### `pub use opcodes::OpCode;`

导出 P-code 操作语义枚举。

**用途**：
- 所有规则、分析、打印逻辑的语义分支基础
- 运行时与静态对齐时的重要公共字典

---

### 架构类型

### `pub use types::Architecture;`

导出目标架构类型。

**用途**：
- 标识当前分析对象属于哪种目标架构
- 与反汇编、提升和旧设计中的高层入口有关

**注意**：
- 该类型当前确实是公共导出的一部分
- 但与它一起出现的旧版“高层 Decompiler API”并不是当前稳定主入口

---

### 类型系统相关

### `pub use type_system::{Datatype, TypeMetatype};`

导出统一类型系统中的基础类型。

#### `Datatype`
统一数据类型对象。

#### `TypeMetatype`
类型元类别信息。

**用途**：
- 类型传播
- 类型恢复
- 输出层的类型表达

---

## 当前推荐理解方式

从当前 `lib.rs` 结构看，`rugra` 更适合被理解为：

> 一个以 `Funcdata`、`Varnode`、`PcodeOp`、`ActionDatabase`、`PrintC` 等对象为核心组织方式的反编译分析框架入口

而不是：

> 一个已经稳定暴露“单一高层 `Decompiler` 对象”的成熟终端库 API

---

## `lib.rs` 中关于旧版 `Decompiler` 的说明

当前 `lib.rs` 中保留了一大段被注释掉的旧版 `Decompiler` 设计代码。这部分内容包括：

- `pub struct Decompiler`
- `new`
- `load_binary`
- `decompile_function`
- `get_functions`
- `get_function_name`
- `architecture`
- `clear_cache`
- 以及基于旧 `Program` 架构的内部缓存与生成逻辑

### 这部分应该如何理解

这段内容目前应被视为：

- **历史设计痕迹**
- **旧架构说明**
- **未来可能重建的高层入口参考**
- **迁移期保留的注释代码**

### 不应如何理解

这段内容目前**不应**再被当成：

- 当前有效的公开 API
- 当前稳定可用的主入口
- 当前 README 中可以直接示例调用的正式接口
- 当前已对外承诺的库能力

### 文档处理原则

因此，本文档**不再**把 `Decompiler` 写成“当前公开 API”条目。  
如果后续该类型重新在源码中以真实、未注释、可编译、可测试的形式恢复，再应当重新纳入本文件的公共 API 说明中。

---

## 当前可见的库级使用方式

结合当前 `lib.rs` 的真实导出结构，更接近当前代码状态的库使用思路是：

1. 使用基础对象：
   - `Address`
   - `AddressSpace`
   - `OpCode`
   - `Datatype`
2. 构造或维护函数级上下文：
   - `Funcdata`
3. 在 `Funcdata` 上组织：
   - raw p-code 注入
   - block / SSA / heritage 处理
   - Action/Rule 分析
4. 最终通过：
   - `PrintLanguage`
   - `PrintC`
   输出 C 风格结果

换句话说，当前公共入口更偏向“对象组合式框架”，而不是“单一 facade 式反编译器对象”。

---

## 与当前库入口最相关的模块

如果你从 `lib.rs` 出发继续阅读源码，建议优先关注：

1. `funcdata.rs`
2. `varnode.rs`
3. `op.rs`
4. `opcodes.rs`
5. `address.rs`
6. `block.rs`
7. `heritage.rs`
8. `action.rs`
9. `printlanguage.rs`
10. `printc.rs`

这些模块最能体现当前真实主线。

---

## 文档可信度提示

### 当前可以确认的
- 上文列出的 `pub mod` 与 `pub use` 来自当前 `lib.rs` 的真实可见结构
- `VERSION` 常量当前仍为真实存在的公共导出项
- 注释掉的 `Decompiler` 当前不是有效公共 API

### 当前不能从 `lib.rs` 单独推导出的
- CLI 已完整可用
- 端到端输出已稳定
- 与 Ghidra 已完成运行时一致性验证
- 旧架构示例代码仍适合直接复制使用

这些结论需要结合以下文档一起判断：

- `docs/README.md`
- `docs/PROJECT_STRUCTURE.md`
- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- `docs/VERIFICATION_GUIDE.md`

---

## 当前仍有效的公共常量

### `pub const VERSION: &str = env!("CARGO_PKG_VERSION")`

**说明**：
- 当前库版本字符串
- 直接来自 Cargo 包元信息

**用途**：
- 版本显示
- 调试与元信息输出

---

## 总结

当前 `lib.rs` 的最准确文档结论是：

1. 它是 **Rugra 当前真实公共模块与核心类型的导出入口**
2. 它反映的是 **以 Ghidra 风格对象建模为中心的库结构**
3. 它**不再**支持把旧版注释掉的 `Decompiler` 视为当前主入口
4. 使用 `rugra` 时，应优先从：
   - `Funcdata`
   - `Address`
   - `Varnode`
   - `PcodeOp`
   - `OpCode`
   - `Datatype`
   等当前真实导出对象理解整个框架

如果后续 `lib.rs` 重新恢复高层 facade API，本文档应同步更新；在此之前，任何继续把旧 `Decompiler` 当作当前公开主接口的说明，都应视为过期描述。
### 2026-06-24：analysis 模块

- 新增 `pub mod analysis` 包含 type_infer（保守 ActionTypePropagate）。

### 2026-06-26：新增 tracedag 模块

- 添加 `pub mod tracedag;` — Ghidra TraceDAG (blockaction.cc:499-1014) 的 Rust 移植骨架。
- 追踪控制流图找 likely goto 边，当前已禁用（需完整 BadEdgeScore + visit-count）。

### 2026-06-26：新增 varmap 模块

- 添加 `pub mod varmap;` — Ghidra varmap.cc (1620行) 的 Rust 移植。
- RangeHint + AliasChecker + MapState + ScopeLocal 骨架已实现。
- 尚未集成到 codegen/printc.rs。

## 2026-06-26：新增 expression 模块

- `pub mod expression;` — 对应 `expression.hh`，TermOrder/AdditiveEdge/AddExpression。

## 2026-06-26（续）：新增 condexe 模块

- `pub mod condexe;` — 对应 `condexe.hh`，条件执行简化。ActionConditionalExe 骨架已实现。

## 2026-06-26（续）：新增 transform 模块

- `pub mod transform;` — 对应 `transform.hh`，大规模数据流变换。LanedRegister/LaneDescription/TransformVar/TransformOp 已实现。

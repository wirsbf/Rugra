# `op.rs` API Reference (操作算子对象)

**源代码路径**: `src/op.rs`

## 模块说明 (Module Doc)

此类为抽象表示 P-code IR 层核心操作的集结。它将独立流离的 `Varnode`（参数/变量）以网络边（流依赖）的形式打通构成控制数据流网络。
该模块旨在实现与老版 Ghidra 代码 `op.hh` 中对于 `PcodeOp` 及附属组织形式的一致映射构造。

---

## 导出的公共 API (Public API)

### `pub mod pcodeop_flags` (算子的执行特性标识位)

决定某个特定操作指令的宏观特性与不可剔除性的布尔级组合掩码：
*   **`STARTBASIC`**: 表明这是一块基本块 (Basic Block) 的头领节点指令。
*   **`BRANCH` / `CALL` / `RETURNS`**: 表述此操作会打断线性的自然堕落式执行，并引发控制流越阶跳跃（具有函数层副作用）。
*   **`NOCOLLAPSE` / `DEAD` / `MARKER`**: 优化过程中的生死存亡判定： `DEAD` 表示其结果悬空并已经被死代码擦除引擎确认消灭离线；`NOCOLLAPSE` 意味着其具有特殊意义禁止在代数化简中被压扁折叠。
*   **`COMMUTATIVE` / `UNARY` / `BINARY` / `TERNARY`**: 描述该指令特性的多元组与自交换数学特征（比如 INT_ADD 可安全交换运算两侧）。
*   **`BADINSTRUCTION` / `UNIMPLEMENTED`**: 解析、解码与恢复错误断言位。

---

### `pub struct PcodeOp`

代表数据流网络上的一根功能纤维（一个独立 P-code 中间指令节点）。

*   **`pub opcode: OpCode`**: 核心动作枚举词（挂钩跨全系统的加减跳、比较等行为定性词汇）。
*   **`pub start: SeqNum`**: 此微操源自于原始二进制机码字节流中的具体位置序列坐标。用于查错与追溯映射还原。
*   **`pub parent: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>`**: 向上指引它被编排落户在哪一个图状基本块/容器域中。
*   **`pub output: Option<Arc<RwLock<Varnode>>>`**: 本次执行可能触发覆写的输出结果变元（单端出线）。
*   **`pub inrefs: Vec<Arc<RwLock<Varnode>>>`**: 计算过程必须消耗消费的上游输入变元参宿群（多端入线）。

#### 关联核心查询指引

*   `pub fn get_addr(&self) -> Address` / `pub fn get_seq_num(&self) -> &SeqNum`  
    获取该操作的发源原态机码位置或唯一追溯编号。
*   `pub fn get_in(&self, slot: usize) -> Option<&Arc<RwLock<Varnode>>>` / `pub fn get_out(&self) -> Option<&Arc<RwLock<Varnode>>>`  
    检索该算子的进出口挂载节点（如果它是一个 CALL 或者是 BRANCH，它有可能无输出宿主而返回 None）。
*   `pub fn is_dead(&self) -> bool` / `pub fn is_call(&self) -> bool` / `pub fn is_branch(&self) -> bool`  
    读取内部挂载的掩码标志位，提供面向高级扫描器的特判通道。

---

### `pub struct PcodeOpBank`

操作算子的超级管家。由于 PcodeOp 基于共享智能指针互相关联极深，且常伴随优化插入/剔除等结构突变行为，本类维护着函数级别下的全量生命集。
对应 Ghidra 内用以集中分封管理控制网点的 `PcodeOpBank` 类：

*   `pub optree: BTreeSet<PcodeOpRef>`: 全量基于原始序列坐标点 (`SeqNum`) 的自平衡有序算子集。
*   `pub alivelist: Vec<PcodeOpRef>` / `pub deadlist: Vec<PcodeOpRef>`: 动态维持生与死（如死代码已确认标记移除的）列表供集中批扫消杀。

#### 生命周期及调度 API

*   `pub fn create(&mut self, opcode: OpCode, num_inputs: usize, addr: Address) -> PcodeOpRef`  
    **唯一正确**的新操作创建挂载口。申请配发一个尚未链接孤立的新微指令。在内部其被强制分配递增的安全子序号并默认投入存活树池中！
*   `pub fn mark_alive(&mut self, op: PcodeOpRef)` / `pub fn mark_dead(&mut self, op: PcodeOpRef)`  
    通知管理器调整某个算子实例的“生死簿”户籍位置（将伴随相应的状态掩码位拔插改动）。
*   `pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode)`  
    在不需要打断连接流树的情况下暴力更新一个旧有节点的操作行为类型（如代数折叠发现把 `ADD(a,0)` 优化退化时调用并转变成一枚空转的 `COPY`）。
*   `pub fn destroy_dead(&mut self)` / `pub fn destroy(&mut self, op: PcodeOpRef)`  
    向指定或标记死亡的无根系/无效操作进行抹杀释放。

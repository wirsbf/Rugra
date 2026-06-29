# `funcdata.rs` API Reference

**源代码路径**: `src/funcdata.rs
`

## 文档状态

- **状态**: 已核对（当前有效）
- **可信度**: 高
- **文档用途**: 说明当前 Rugra 中 `Funcdata` 这一“函数级分析容器”的角色、边界与主要公开接口
- **适用范围**: 以当前 `src/funcdata.rs` 所体现的主干架构为准
- **重要说明**: 本文档描述的是**当前函数分析容器**，而不是旧版 `Program` 驱动架构下的函数表示层

---

## 模块定位

`Funcdata` 是 Rugra 当前反编译主链路中的**函数级核心上下文对象**。  
它承担的职责，不是单纯保存“函数名字和地址”，而是把一个函数在分析过程中的核心状态统一收拢到一个容器里，供后续各阶段共享和改写。

在当前工程中，你可以把 `Funcdata` 理解为：

> “单个函数在进入 Rugra 分析管线后，对应的总工作台 / 总上下文 / 总容器”。

它通常位于以下链路的中心：

```text
binary / disasm
  -> raw p-code
  -> Funcdata
  -> block / CFG
  -> heritage / SSA
  -> ActionDatabase
  -> variable / type enrichment
  -> PrintLanguage / PrintC
```

也就是说，`Funcdata` 既是：

- 原始语义注入的落点
- 控制流和数据流分析的承载体
- 后续规则系统（Action / Rule）的操作对象
- 打印输出阶段读取的主要函数级数据源

---

## 与 Ghidra 的关系

本文档中的 `Funcdata` 对应的是 Ghidra 反编译器中的 `Funcdata` 概念。  
这种对应关系主要体现在：

- 它是**单函数**分析的中心对象
- 它把 P-code、Varnode、Block、原型、符号等信息组织到一起
- 它是后续优化、SSA、变量恢复、输出打印的重要入口

但需要注意：

- **概念对应不等于行为已经完全与 Ghidra 一致**
- 当前 Rugra 中的 `Funcdata` 文档只能说明“角色和结构方向”，不能直接推出“运行时表现已与 Ghidra 1:1 对齐”

如果需要判断对齐层级，应同时查看：

- `../ALIGNMENT_PROGRESS.md`
- `../VERIFICATION_GUIDE.md`
- `../data_contract.md`

---

## 当前角色边界

`Funcdata` 当前更适合被理解为以下几类信息的“函数级聚合体”：

### 1. 函数身份信息
例如：

- 函数名
- 入口地址
- 大小或范围信息

### 2. 图与节点容器
例如：

- `PcodeOp` 集合
- `Varnode` 集合
- block / CFG 相关状态

### 3. 分析期辅助信息
例如：

- 符号名映射
- 字符串字面量映射
- heritage / SSA 阶段统计信息
- 与后续输出或恢复有关的中间状态
- **`scope: Option<crate::varmap::ScopeLocal>`**（2026-06-26 新增）：由
  `ActionRestructureVarnode` (coreaction.cc:2274) 构建的局部变量作用域，
  对应 Ghidra `Funcdata::getScopeLocal()`，供 printc 查询栈变量名。

### 4. 规则系统操作对象
`Funcdata` 是 `ActionDatabase` 等分析动作的主要输入对象。  
因此它不只是“静态数据结构”，还是被多轮分析、改写、增强的工作上下文。

---

## 当前设计原则

在当前架构下，`Funcdata` 的设计应遵循以下原则：

### 单函数边界
一个 `Funcdata` 只应对应一个函数。  
它不应混入多个函数的 IR、Block 或 SSA 状态。

### 可逐步构建
`Funcdata` 不要求一创建就具备全部分析信息。  
更合理的流程是：

1. 先建立函数基本身份
2. 再注入 raw p-code
3. 再建立 block / CFG
4. 再进入 heritage / SSA / Action 处理
5. 最后再供打印层读取

### 可持续增强
分析阶段可以不断往 `Funcdata` 中补充信息，但不应在输出层为了“看起来更好”而反过来篡改底层事实。

### 图一致性优先
只要 `Funcdata` 中保存的是图结构、节点引用和 def-use 关系，那么任何修改都必须优先保证：

- 对象引用不悬空
- 节点状态前后一致
- block / op / varnode 之间关系仍可遍历

---

## 公开 API 说明

以下说明围绕当前可见公开接口展开，重点说明“它们在主链路中扮演什么角色”。

---

### `pub struct Funcdata`

函数分析容器。

这是 `funcdata.rs` 中最核心的公开类型，用于表示“一个函数在当前反编译流程中的完整分析上下文”。

从工程视角看，`Funcdata` 通常承载：

- 函数基础元信息
- 原始与正式 IR 之间的桥接结果
- `PcodeOp` / `Varnode` / block 等图对象
- 分析阶段产生的附加信息
- 输出层所需的上下文

从使用方式看，后续许多主流程都围绕 `&mut Funcdata` 展开，因为它是：

- 可被构建的
- 可被改写的
- 可被分析的
- 可被最终打印消费的

---

### `pub fn new(name: &str, addr: Address, size: i32) -> Self`

创建一个新的 `Funcdata` 实例。

#### 语义
这是单个函数分析容器的初始化入口。  
创建时通常只需要最基础的函数身份信息：

- `name`: 函数名
- `addr`: 函数入口地址
- `size`: 函数大小

#### 作用
该方法建立的是“函数分析容器的初始壳”，而不是一个已经完成分析的函数对象。  
调用 `new(...)` 后，通常还需要继续：

- 注入 raw p-code
- 建立 block / CFG
- 补符号和字符串
- 进入 ActionDatabase / heritage 等阶段

#### 适用场景
- 从反汇编或样例程序中开始构造单函数分析对象
- 在测试中创建函数级分析上下文
- 为后续管线准备最小函数容器

#### 注意事项
创建成功不代表：
- 该函数已经可打印
- 该函数已经完成 SSA
- 该函数已经完成变量恢复

它只是主链路的起点。

---

### `pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>)`

设置自身的弱引用。

#### 语义
该方法用于在 `Funcdata` 被包装进共享引用模型后，把“指向自己”的弱引用回填进去。

#### 为什么会有这个接口
当前工程中大量对象采用共享读写容器组织，某些场景下：

- `Funcdata` 内部对象需要回指所属 `Funcdata`
- 或某些图节点/分析过程需要持有函数上下文的弱引用
- 为避免强引用环，需要使用 `Weak<...>`

因此该方法是一个“包装后回填”的初始化步骤。

#### 典型使用顺序
更常见的使用方式不是直接裸建 `Funcdata` 后长期使用，而是：

1. `Funcdata::new(...)`
2. 包装进共享读写容器
3. 调用 `set_self_ref(...)`
4. 再继续进入完整分析流程

#### 注意事项
这是架构层初始化接口，不是面向最终用户的简化 API。  
如果你在更高层封装函数分析入口，通常应由封装层负责调用它，而不是把它暴露成最终用户手工步骤。

---

### `pub fn run_heritage_direct(&mut self)`

安全地执行 SSA (heritage) 构建通道，避免死锁。

#### 语义
该方法是一个便捷且安全的 SSA 构建入口。它会通过 `std::mem::take` 临时剥离必要的组件（如 `VarnodeBank` 和 `PcodeOpBank`），并将其直接传递给底层的 heritage 算法，从而避免底层的 `Heritage` 在重入时尝试通过 `Weak<RwLock<Funcdata>>` 再次获取自身写锁。

#### 作用
在进行函数级分析并需要构造 SSA 时，如果当前上下文已经持有了 `Funcdata` 的可变借用（或 `RwLockWriteGuard`），直接调用 `self.heritage.heritage()` 必然导致死锁。`run_heritage_direct` 就是为了彻底绕过这个问题而提供的官方安全入口。

#### 典型使用场景
- 单元测试或集成测试中执行 SSA 通道
- 后续在单线程 / 顺序分析管道中执行 heritage

#### 注意事项
这是用于替换旧版测试代码中手动调用 `place_multiequals_direct` 和 `rename_direct` 的推荐方式。

---

### `pub fn get_name(&self) -> &str`

获取函数名。

#### 语义
返回当前 `Funcdata` 所代表函数的名称。

#### 作用
这个名称通常用于：

- 调试输出
- 打印阶段生成函数头
- 日志和错误上下文
- 与符号信息对齐

#### 注意事项
函数名可能来自不同来源，例如：

- 输入构造时显式给出
- 符号表
- 后续命名恢复逻辑

因此“有名字”不等于“名字一定可靠到可代表源码原名”。

---

### `pub fn add_symbol(&mut self, addr: u64, name: String)`

注册一个符号名。

#### 语义
把某个虚拟地址与一个符号名称关联起来，保存到当前函数上下文中。

#### 作用
这个接口主要用于把来自二进制元信息、外部符号、函数名或全局对象名等信息挂入 `Funcdata`，便于后续阶段使用。

典型用途包括：

- 调用目标名称恢复
- 全局对象访问命名
- 输出阶段显示更友好的标识符

#### 设计意义
这说明 `Funcdata` 不只是保存函数内部 IR，还保存一部分与该函数分析强相关的“环境级辅助信息”。

---

### `pub fn add_string(&mut self, addr: u64, s: String)`

注册一个字符串字面量。

#### 语义
把某个地址与恢复出的字符串内容关联起来，记录到当前函数上下文。

#### 作用
供后续打印或语义恢复阶段使用，例如：

- 把某个地址常量解释为字符串引用
- 在输出中直接恢复为可读文本
- 辅助判断某些调用语义

#### 典型来源
- `.rodata`
- 已知字符串段
- 预处理扫描结果
- 反汇编阶段识别出的字面量地址

#### 注意事项
字符串映射属于“语义增强信息”，不是底层 IR 的替代品。  
即使记录了字符串，也不应直接覆盖底层地址事实。

---

### `pub fn get_symbol(&self, addr: u64) -> Option<&str>`

按地址查询符号名。

#### 语义
查询某个地址是否已经注册了对应的符号名。

#### 作用
这个查询通常会被：

- 打印层
- 调用恢复逻辑
- 调试输出
- 语义恢复逻辑

用来把“裸地址”提升成更可读的名字。

#### 返回值含义
- `Some(...)`: 当前上下文中已有该地址的符号名
- `None`: 没有已知符号，调用方应保守处理

---

### `pub fn get_string(&self, addr: u64) -> Option<&str>`

按地址查询字符串字面量。

#### 语义
查询某个地址是否已被映射为字符串内容。

#### 作用
供输出层和恢复逻辑将地址常量解释为字符串引用。

#### 返回值含义
- `Some(...)`: 当前上下文已知该地址对应字符串
- `None`: 调用方应继续按普通地址/常量处理

---

### `pub fn get_address(&self) -> &Address`

获取函数基地址。

#### 语义
返回当前 `Funcdata` 所对应函数的起始地址。

#### 作用
这个地址常用于：

- 作为函数身份锚点
- 错误上下文定位
- 图构建起点
- 打印和日志标识
- 与二进制符号表、测试样本、对齐验证数据做关联

#### 注意事项
这里返回的是 `Address`，而不是裸整数，这一点很重要。  
它意味着函数入口定位仍然保留地址空间语义，而不是被降级为普通 `u64`。

---

### `pub fn get_size(&self) -> i32`

获取函数大小。

#### 语义
返回创建 `Funcdata` 时记录的函数大小。

#### 作用
这个值通常可用于：

- 调试信息
- 输出摘要
- 与函数范围相关的扫描边界
- 构造或验证分析上下文

#### 注意事项
在反编译工程中，函数大小常常不是绝对可靠事实。  
因此这个字段更适合作为“当前已知函数范围信息”，而不是绝对真理。

---

### `pub fn inject_raw_ops(&mut self, raw_ops: &[PcodeOpRaw])`

把原始 P-code 序列注入到当前 `Funcdata` 中。

#### 语义
这是当前 `Funcdata` 最关键的桥接方法之一。  
它负责把反汇编 / 提升阶段得到的 `PcodeOpRaw` 序列，转为当前函数容器中的正式图结构。

#### 它在主链路中的位置

```text
disasm / lifting
  -> raw_ops: &[PcodeOpRaw]
  -> Funcdata::inject_raw_ops(...)
  -> PcodeOp / Varnode / block graph 初步建立
```

#### 典型职责
根据当前文档与工程定位，这个方法通常负责：

1. 把每个 `PcodeOpRaw` 转成 `PcodeOp`
2. 为输入输出创建或挂接 `Varnode`
3. 建立基础图关系
4. 识别基本块边界
5. 为后续 block / CFG / heritage / ActionDatabase 提供初始结构

#### 基本块划分（2026-06-28 重大修复）

`build_blocks_from_ops` 现在按 Ghidra 式（BlockGraph::copyBlocks / Funcdata::structureReset）划分基本块，在**两种**点分裂：
1. **terminator 之后**（BRANCH/CBRANCH/BRANCHIND/RETURN）—— 原有逻辑
2. **跳转目标地址处** —— **新增**：收集所有 BRANCH/CBRANCH 的目标地址（input[0] offset），在对应 op 索引处也分裂

此前只做 (1)，导致跳转目标落在块中间时无法解析（CBRANCH target 地址不等于任何块 start_addr），边被静默丢弃。实测 curl main 有 56 个 / 全局 182 个 CBRANCH 目标未匹配，丢失大量回边，while 循环恢复从 ~6 降到 1。

修复后：curl main 块数 102→123，回边检测 3→8（3 个独立循环头：5/7/26，接近 Ghidra 的 6），全局结构化循环 8→17（10 whiledo + 7 dowhile）。736/736 测试通过，curl 24/24 gcc 审计。

**已知影响**：httpd 大函数（如 main 12 循环）goto cascade 轮次增加（40 轮），整体变慢但无正确性回归。性能优化是后续工作。

#### 为什么这个方法重要
如果没有这一步：

- raw p-code 只是“线性原始语义记录”
- 不能方便地进入函数级图分析
- 后续 Action / SSA / 输出层都缺少统一工作对象

因此这一步可以看作：

> 从“原始语义序列”进入“正式函数分析容器”的桥

#### 输入要求
`raw_ops` 应满足最基本的顺序性和语义完整性，例如：

- 操作顺序正确
- 输入输出槽位可解释
- 地址 / 顺序信息可关联
- 不应把缺失支持的语义静默吞掉

#### 调用后预期
调用后，`Funcdata` 应进入“可供进一步分析”的状态，但**不应自动被理解为“全部分析已经完成”**。

更合理的理解是：

- block 初始结构可能已建立
- 正式 `PcodeOp` / `Varnode` 图已建立
- 后续还需要进入 heritage / Action / type / print 等阶段

---

### `pub fn clear(&mut self)`

清空分析状态。

#### 语义
重置当前 `Funcdata` 中已经建立的分析结果或相关状态。

#### 作用
主要用于以下场景：

- 重跑分析流程
- 测试中复位函数容器
- 在局部失败后回退到更干净的状态
- 重新注入或重新构建函数图

#### 注意事项
“清空”并不一定等价于“回到刚创建时的完全裸状态”，具体保留哪些基础信息应以源码实现为准。  
从文档角度应理解为：它用于清理分析期状态，而不是作为输出层接口。

---

### `pub fn num_heritage_passes(&self) -> i32`

获取已经完成的 heritage pass 数量。

#### 语义
返回当前函数在 heritage / SSA 相关处理中已经执行过的轮次数量。

#### 作用
这个接口主要用于：

- 调试 SSA / heritage 过程
- 判断分析推进程度
- 记录某些多轮处理是否发生
- 辅助验证或日志输出

#### 设计含义
它反映出 `Funcdata` 不只是静态容器，还会记录“分析过程中的阶段性状态”。

---

## `Funcdata` 在当前主链路中的推荐理解方式

如果你需要快速把握 `Funcdata` 的工程角色，可以用下面这段话概括：

> `Funcdata` 是 Rugra 当前单函数分析的核心总容器。  
> 它负责承接 raw p-code 注入后的正式 IR、控制流结构、分析状态与附加语义信息，并作为后续 SSA、ActionDatabase、变量恢复、类型传播和打印输出的函数级工作上下文。

---

## 与旧架构的区别

在历史文档里，你可能会看到围绕以下对象组织的旧式描述：

- `Program`
- `analysis/`
- `codegen/`
- 直接 `Decompiler -> analyze -> generate_c_code`

这些叙述在当前工程里已经不再是最准确的主线。

相较之下，当前更贴近现状的主线是：

```text
PcodeOpRaw
  -> Funcdata
  -> PcodeOp / Varnode / Block
  -> Heritage / Actions
  -> PrintLanguage / PrintC
```

因此，`Funcdata` 的 API 文档应以“**当前函数分析容器**”为中心，而不是继续围绕旧版 `Program` 风格容器来写。

---

## 使用建议

如果你准备围绕 `Funcdata` 开发或调试，建议优先联动阅读：

- `address.md`
- `varnode.md`
- `op.md`
- `pcoderaw.md`
- `block.md`
- `heritage.md`
- `action.md`
- `printc.md`
- `../data_contract.md`

推荐顺序：

1. 先理解 `Address`
2. 再理解 `Varnode` / `PcodeOp`
3. 再理解 raw p-code 如何进入 `Funcdata`
4. 再看 `heritage` 和 `ActionDatabase` 如何消费 `Funcdata`
5. 最后看 `PrintC` 如何从函数级上下文输出结果

---

## 文档维护注意事项

后续维护本文时，请特别注意以下几点：

### 1. 不要把 `Funcdata` 写成“完整产品 API”
它是当前核心内部架构对象，更偏工程主链路，而非最终用户直接使用的高层门面。

### 2. 不要把概念对齐写成行为对齐
即使它对应 Ghidra 的 `Funcdata`，也不能直接写成“已与 Ghidra 完全一致”。

### 3. 不要把注入成功写成分析完成
`inject_raw_ops(...)` 打通的是桥接层，不代表最终变量恢复、类型恢复、输出结构化都已完成。

### 4. 如果构造流程变化，要同步更新本文
尤其是以下变化发生时：

- `new(...)` 签名变动
- `inject_raw_ops(...)` 职责变动
- `Funcdata` 不再承担当前这些主干角色
- self reference 或共享容器模型变化
- block / heritage / action 的耦合方式变化

---

## 一句话结论

`Funcdata` 是 Rugra 当前架构里最关键的函数级分析容器之一。  
它不是旧版 `Program` 的简单别名，也不是单纯的数据壳，而是当前反编译主链路中承接 raw p-code、组织图结构、支撑分析动作并服务最终输出的核心上下文对象。
### 2026-06-23（续）：test_bool_condition 搜索 BlockList

- 测试现在搜索 BlockList 内部的 BlockCondition（适配 interleaved cat）。

### 2026-06-23（续）：test_bool_condition 搜索 BlockList

- 测试现在搜索 BlockList 内部的 BlockCondition（适配 interleaved cat）。

## 2026-06-26：Funcdata P-code op 编辑 API（funcdata.hh:281-479）

新增与 Ghidra 一致的 P-code op 构造/编辑方法，解锁 ruleaction/coreaction
中需创建或改写 P-code 的 Rule/Action（此前 Rugra 仅原地改 op 字段，无法
创建新 op）。忠实对应 funcdata.hh：

- `new_op(inputs, pc)` — `Funcdata::newOp` (444)
- `new_unique_out(s, op)` — `Funcdata::newUniqueOut` (281)
- `new_constant(s, val)` — `Funcdata::newConstant` (283)
- `new_unique(s)` — `Funcdata::newUnique` (288)
- `op_set_opcode(op, opc)` — `Funcdata::opSetOpcode` (463)
- `op_set_input(op, vn, slot)` — `Funcdata::opSetInput` (467)，扩展 inrefs、维护 descend
- `op_insert_input(op, vn, slot)` — `Funcdata::opInsertInput` (479)
- `op_remove_input(op, slot)` — `Funcdata::opRemoveInput` (478)
- `op_insert_before(op, follow)` — `Funcdata::opInsertBefore` (454)，alivelist 顺序
- `op_insert_after(op, follow)` — `Funcdata::opInsertAfter` (456)，将 `op` 插入
  `follow` 之后。用于 prefersplit.cc 的 split 变换（在原 op 旁插入新 COPY/LOAD/STORE）

**已知限制**：新建 op 仅进 alivelist，未挂到 BlockBasic.get_ops()（块编辑
infra 仍待补），故影响 emit 顺序的 Rule（需块内插入）目前仅保证数据流正确。

### 2026-06-26（续）：op_swap_input

- `op_swap_input(op, slot1, slot2)` — `Funcdata::opSwapInput`：交换两输入操作数。
  用于 RuleBoolNegate 翻转比较时的换序（如 `!(V < W) => W <= V`）。

### 2026-06-26（续）：op_set_output

- `op_set_output(op, vn)` — `Funcdata::opSetOutput`：设置/替换 op 输出 varnode。
  标记 WRITTEN、设 def 链、清旧输出 def。解锁 RuleSubZext 等。

### 2026-06-26（续）：op_destroy / op_unset_input

- `op_destroy(op)` — `Funcdata::opDestroy`（funcdata_op.cc:203）：销毁未用 op（清输出 def、断所有输入 descend 链、markDead）。
- `op_unset_input(op, slot)` — `Funcdata::opUnsetInput`：断某输入的 descend 链。
解锁 RuleEarlyRemoval。

### 2026-06-27（续）：op_destroy_recursive / total_replace

- `op_destroy_recursive(op)` — `Funcdata::opDestroyRecursive`（funcdata_op.cc:228）：递归销毁 op 及其变为死代码的定义 op（跳过 call/indirect-source）。使用 scratch worklist 避免递归栈溢出。
- `total_replace(vn, newvn)` — `Funcdata::totalReplace`（funcdata_varnode.cc:1474）：将 vn 的所有读取引用替换为 newvn（遍历 descend 链 + op_set_input）。解锁 ActionMultiCse、constseq。

### 2026-06-26（续）：op_unset_output / new_varnode_out

- `op_unset_output(op)` — `Funcdata::opUnsetOutput`：断开 op 输出 def 链。
- `new_varnode_out(size, addr, op)` — `Funcdata::newVarnodeOut`：创建新输出 varnode 并关联 op。
解锁 RuleLeftRight。

### 2026-06-26（续）：replace_lessequal

- `replace_lessequal(op) -> bool` — `Funcdata::replaceLessequal`（funcdata_op.cc:1029）：
  `V <= c => V < c+1`，调整常量±1并改 opcode，带溢出保护。解锁 RuleIntLessEqual。

### 2026-06-26（续）：distribute_int_mult_add

- `distribute_int_mult_add(op) -> bool` — `Funcdata::distributeIntMultAdd`（funcdata_op.cc:1073-1118）：
  `(V + W) * c => V*c + W*c`。将 INT_MULT 系数分配到 INT_ADD 的两个输入。常量输入直接乘出结果；非常量输入创建新 INT_MULT op。解锁 RuleCollectTerms 完整形式。

## 2026-06-27：CFG 重写原语（funcdata_block.cc）

新增控制流图编辑方法，解锁 jumptable.rs 的 foldInGuards/switchOver L3 缺口：

- `push_branch(bb, slot, bbnew) -> Result<(), String>`（funcdata_block.cc:404）：将 CBRANCH 转为 BRANCH（移除条件输入 slot 1），重定向 out-edge 到 BRANCHIND 块。验证源是 CBRANCH（2 out-edges）+ 目标以 BRANCHIND 结尾。
- `force_goto(pcop, pcdest) -> bool`（funcdata_block.cc:752）：遍历所有基本块，找到地址为 pcop 的最后 op，标记其指向 pcdest 的 out-edge 为非结构化 goto。
- `set_goto_branch(bl, j)`：标记 out-edge j 为 goto（设置 GOTO_EDGE_0/1 标志）。
- `move_out_edge(bb, slot, bbnew)`：重定向 out-edge（BlockGraph::moveOutEdge 等价），更新源/旧目标/新目标的 edge 列表 + reverse_index。

## 2026-06-27（续 2）：remove_branch

- `remove_branch(bb, num)`（funcdata_block.cc branchRemoveInternal）：销毁 CBRANCH op（如果 2 out-edges）+ 移除非选中 out-edge + 更新目标块 incoming。解锁 ActionDeterminedBranch。

## 2026-06-27（续 3）：FuncCallSpecs 集成

- `callspecs: Vec<FuncCallSpecs>` — 函数调用规格向量（Ghidra breefcall）。
- `num_calls() -> usize` — 调用点数（funcdata.hh numCalls）。
- `get_call_specs(i) -> Option<&FuncCallSpecs>` — 按索引获取（funcdata.hh getCallSpecs）。
- `get_call_specs_mut(i) -> Option<&mut FuncCallSpecs>` — 可变访问。
- `add_call_specs(fc) -> usize` — 添加调用规格。
- `get_func_proto() -> &FuncProto` / `get_func_proto_mut() -> &mut FuncProto` — 函数原型访问。

### 2026-06-27（续 2）：op_bool_negate

- `op_bool_negate(vn, op, insert_after)` — `Funcdata::opBoolNegate`（funcdata_op.cc:560）：插入 BOOL_NOT（CPUI_BOOL_NEGATE）op 取反 vn，返回输出 varnode。insert_after 控制插入位置。解锁 RuleBooleanUndistribute/RuleBoolZext 等。

### 2026-06-27（续 3）：is_type_recovery_on + flags

- `is_type_recovery_on()` — `Funcdata::isTypeRecoveryOn`（funcdata.hh:150）：检查 TYPE_RECOVERY_ON 标志。
- `set_type_recovery_on(on)` — 启用/禁用类型恢复。
- 新增 `flags: u32` 字段 + `funcdata_flags::TYPE_RECOVERY_ON` 常量。解锁 RuleBoolZext。

### 2026-06-27（续 4）：op_uninsert / op_insert_begin / op_get_slot

- `op_uninsert(op)` — `Funcdata::opUninsert`（funcdata.hh）：从 alivelist 移除 op 但不销毁（用于重新插入）。
- `op_insert_begin(op, bb)` — `Funcdata::opInsertBegin`（funcdata.hh:457）：在块开头插入 op。
- `op_get_slot(op, vn) -> i32` — `PcodeOp::getSlot`：返回 vn 在 op 中的输入槽位（-1 未找到）。

### 2026-06-29：spacebase() + split_uses()（底层阻塞解除）

- `spacebase()` — `Funcdata::spacebase()`（funcdata.cc:230-269）：标记映射到虚拟地址空间的寄存器（栈指针 RSP @ Register@0x20, size 8）为 `SPACEBASE` 标志。对已标记且有多后代的空间基 varnode，调用 `split_uses()` 复制定义 op 使各加法用户独立寻址。**这是 Ghidra 让 varmap/ActionStackPtrFlow 识别 RSP 为栈空间指针的规范机制**——不需要 lifter 发出 Stack-space varnode。接入主管线为 `ActionSpacebase`（coreaction.cc:5506，在 ActionHeritage 之后、infertypes 之前）。
- `split_uses(vn)` — `Funcdata::splitUses`（funcdata_varnode.cc:1540-1567）：若 vn 由 op 定义（如 INT_ADD）且有多个后代，复制定义 op 使每个读取者获得独立输出副本。允许按用户分析（如同一空间基派生指针的不同栈偏移）。
- **验证**：curl uVar 碎片 149→0，httpd uVar→0，while/goto 不变，776/776 测试 + curl 24/24 + httpd 29/29 gcc 审计通过。

### 2026-06-27（续 5）：CSE 基础设施

- `cse_elimination(op1, op2) -> PcodeOpRef` — `Funcdata::cseElimination`（funcdata_op.cc:1358）：消除两个公共子表达式 op 之一（保留序列号较小的），total_replace 输出后销毁重复 op。
- `cse_eliminate_list(list) -> Vec<Varnode>` — `Funcdata::cseEliminateList`（funcdata_op.cc:1420）：对 (hash, op) 列表排序，查找匹配对，消除冗余。解锁 RuleSelectCse + ActionCse。

### 2026-06-27（续 6）：op_flip_condition

- `op_flip_condition(op)` — `Funcdata::opFlipCondition`（funcdata_op.cc）：翻转比较 op 的条件（INT_LESS↔INT_LESSEQUAL 等 via get_booleanflip），交换输入如需，清除 BOOLEAN_FLIP 标志。解锁 RuleCondNegate。

### 2026-06-27（会话2）：CFG 重写原语（解锁 condexe）

为支撑 condexe 核心图重写（condexe.cc:712），Funcdata 新增忠实于 Ghidra funcdata_block.cc 的方法：
- `remove_from_flow_split(bl, swap) -> Result<(), String>` — `Funcdata::removeFromFlowSplit`（funcdata_block.cc:892 + block.cc:1575）：移除一个 2 入/2 出的空块，将每条入边重连到对应的出边。swap=true 时 In(0)->Out(0)/In(1)->Out(1)；否则交叉连接。condexe execute() 用此消除冗余路径汇合。
- `structure_reset()` — `Funcdata::structureReset`（funcdata_block.cc:705）：重算循环结构 + 支配者树 + 清空 sblocks。任何 CFG 变更后调用以保持一致性。

### 2026-06-27（会话3 G3 续）：inject Phase 4 use-def linking（验证有效，暂禁用）

在 inject_raw_ops Phase 3 后验证了一个 Phase 4 use-def 链补全 pass：按线性指令序维护 (space_id, offset)→defining op 映射，为 LOAD/STORE 地址输入补上 def 弱引用（保持 SSA Arc-identity，只填 def-less 链）。**验证有效**：varmap gather_spacebase 解析出 helpf 的 10 个栈符号。

**但与 jumptable/switch 交互**（switch 表本身是 LOAD）导致 main 等函数 switch quantity 回归。为保持默认 24/24+29/29，Phase 4 暂禁用（inject_raw_ops 内详细 NOTE 记录）。重启需 jumptable/typeop 协调。实现可从 git 历史恢复。

### 2026-06-27（会话3 G3 续2）：inject Phase 4 确认禁用

inject Phase 4 全局 def-linking 确认禁用——它正确解析栈符号但扰动 typeop（struct 指针泄漏）。改用 varmap 的只读 `resolve_rsp_offset_via_bank`（作用域仅 spacebase），不扰动 typeop/copyprop。inject_raw_ops Phase 4 NOTE 已更新说明此决策。

### 2026-06-27（会话3 G5）：remove_unreachable_blocks + splice_block_basic

- `remove_unreachable_blocks() -> bool` — `Funcdata::removeUnreachableBlocks`（funcdata_block.cc:347-394）：从入口 BFS 收集可达块，标记不可达块为 dead，移除其出边，再从图移除。用于 ActionUnreachable。
- `splice_block_basic(bb) -> bool` — `Funcdata::spliceBlockBasic`（funcdata_block.cc:919-956）：拼接单出边块到其单后继（销毁 bb 的 branch op，继承后继出边，移除后继）。用于 ActionDoNothing/ActionRedundBranch case 1。

### 2026-06-27（会话3 G5续）：sync_varnodes_with_symbols

- `sync_varnodes_with_symbols(update_datatypes, unmapped_alias_check) -> bool` — `Funcdata::syncVarnodesWithSymbols`（funcdata_varnode.cc:938-989）的忠实适配：遍历 Stack-space varnodes，匹配 ScopeLocal 符号，标记为 mapped（set_direct_write）。ActionRestructureVarnode 现调用它（coreaction.cc:2281）。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29（续 2）：new_extended_constant（funcdata_varnode.cc:462）
- `new_extended_constant(s, lo, hi, before_op)` — 创建可能 >8 字节的常量 Varnode。s≤8 时直接 newConstant；s>8 且 hi==0 时 INT_ZEXT(const)；s>8 且 hi!=0 时 PIECE(hi,lo)。忠实移植 Ghidra `Funcdata::newExtendedConstant`（funcdata_varnode.cc:462-484）。解锁 RuleDivTermAdd。

### 2026-06-29（续 3）：Funcdata.active_output 字段
- 新增 `active_output: Option<ParamActive>` 字段（funcdata.hh）。用于 ActionReturnRecovery 检测函数返回值。当 RETURN op 有 >1 input 时自动创建 active_output。

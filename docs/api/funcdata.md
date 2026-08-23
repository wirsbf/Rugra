# `funcdata.rs` API Reference

**源代码路径**: `src/funcdata.rs`
**2026-07-16**: `link_symbol` + `link_symbol_reference` 已加（funcdata_varnode.cc:1156/1193）。符号链接 + PTRSUB 常量解析。

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

`clear_dead_varnodes` 的 `makeFree` 调用点（2026-08-13，`VARNODE-INIT-0001`）从当前 bank 的 loc-tree snapshot 获取 Arc，因而使用带 debug ownership 断言的 prevalidated remove→mutate→reinsert；随后清 cover，并在同一个 `hasNoDescend` 守卫内删除 free 值。`combine_input_varnodes` 按锁定 `funcdata_varnode.cc:381-454` 在 synthetic LE、register storage、无符号/ProtoModel effect、high-level-off 的合法图上执行：PIECE reader 改成 COPY；其他 reader 在入口块首逆序插入 SUBPIECE，输出保留原 source Address space/offset；`totalReplace` 支持同一 op 的重复输入槽；旧输入 detach 后经 checked `delete_varnode` 删除；最终建立并传播 setInput 返回的 canonical Arc。真实 12.0.4 fixture 观察完整 slots、descendants、bank membership/cardinality、op 顺序与 storage，并覆盖 non-input/non-contiguous 两条异常。big-endian、nullable/missing-entry 图，以及 `newVarnodeOut` 的 local-map/`assignHigh`/lane/ProtoModel property 副作用仍未由该 fixture 证明。

`Funcdata::destroy_varnode` 只把 read edges 从 descendant 索引 detach、清定义输出，再走 prevalidated bank 删除；因为 Rust `Vec<Arc<Varnode>>` 不能表示 Ghidra 的 NULL input slot，`op_unset_input` 后槽中仍保留 stale Arc，直到调用方移除或替换该槽。本函数对 foreign/stale handle 的行为未闭合，不能当成 public checked `destroyVarnode`。相对地，inline `delete_varnode` 返回 `Result<()>` 并直接走 public checked `VarnodeBank::destroy_varnode`；bank API 的 integrated/foreign/stale 错误由 `Result` 表达。Ghidra delete 与外部 Rust Arc 生命周期差异继续归 `VARNODE-0001`。

`set_input`/`set_def` 的 canonical 返回值已贯穿当前生产调用点：`combine_input_varnodes`、INDIRECT 构造、raw P-code 两种注入路径及 Heritage MULTIEQUAL 输出都把 canonical Arc 接到后续 op/output。`inject_raw_ops` Phase 3 在转换前先 snapshot `(opcode, inputs, output)` 并释放 op read guard，避免 xref replacement 回写同 op 时自锁；每个变换后的 slot 在 debug build 验证确实指向返回的 canonical Arc。这里仅证明这些 fresh/bank-owned 内部路径和锁生命周期，不把 raw 注入桥接整体宣称为 Ghidra `PcodeEmitFd::dump` MATCH。

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

#### HERITAGE-OWNERSHIP-0001 变更
`Heritage` 不再保存任何 `Funcdata` 自引用（原 `heritage.fd = Some(self_ref)`
行已删除）。Heritage 的 pass 方法现在显式接收 `&mut Funcdata`，由
`Funcdata::op_heritage` 用 `mem::take` 暂移 Heritage 后单 pass 驱动（对齐
Ghidra 非拥有的 `Heritage::fd` 裸指针语义，且无任何锁重入路径）。
`set_self_ref` 现在只回填 `Funcdata::self_ref` 本身。

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

### `pub fn op_heritage(&mut self)`

执行一整个 heritage pass（对齐 `Funcdata::opHeritage`，funcdata.hh:462）。

#### 语义
Ghidra 侧该函数体即 `{ heritage.heritage(); }` —— 恰好一次
`Heritage::heritage` 调用，单 pass，pass 计数在其最后一行 +1
（heritage.cc:2757）。Rugra 1:1 移植：

1. `std::mem::take(&mut self.heritage)` 暂移持久 Heritage 对象；
2. `heritage.heritage(self)` 在同一个 `&mut Funcdata` 上执行一个
   规范单 pass；
3. 回写同一个 Heritage 状态（pass 计数、持久 `globaldisjoint`、
   per-space HeritageInfo、guards）。

#### 所有权模型（HERITAGE-OWNERSHIP-0001）
旧实现里 `Heritage` 持有 `Weak<RwLock<Funcdata>>`，nominal `heritage()`
先升级并取写锁，嵌套 helper 再取同一写锁 —— 单线程自死锁
（HERITAGE-DRIVER-0001 审计结论）。现在整个 pass 无任何
`Weak` 升级 / 嵌套锁获取；连续多次调用（例如边界测试连续 3 次调用驱动
pass 0→1→2→3）不可能死锁。

#### 注意事项
- 生产管线（`ActionHeritage::apply`）**已切换**到此桥（HERITAGE-DRIVER-SWITCH-0001，
  2026-08-16）：`apply` 逐字对齐 coreaction.hh:289 `{ fd.op_heritage(); Ok(0) }`。
  `run_heritage_direct` / `place_multiequals_direct` 移出生产路径，仅剩 example
  侧 throwaway-Funcdata 参数估计与 crate 内测试调用。
- 与 Ghidra 一致：`Heritage::heritage` 不构建 infolist ——
  `buildInfoList` 属于 `Funcdata::startProcessing`（funcdata.cc:166）。
  未运行 startProcessing 就调用本方法，per-space 阶段对空 infolist
  迭代（零空间），与 oracle 行为一致。

---

### `pub fn run_heritage_direct(&mut self)`

执行**非生产**的 direct SSA pass（`place_multiequals_direct` + `rename_direct`）。

#### 语义
该方法通过 `std::mem::take` 临时剥离 `VarnodeBank` / `PcodeOpBank`，把它们直接传给 direct 系 heritage 算法。

#### HERITAGE-DRIVER-SWITCH-0001 状态（2026-08-16）
Ghidra 没有 `runHeritageDirect` 对应物（此前注释引用的 funcdata.cc:34 实为
`setSelfRef`，属误引，已更正为 RUGRA-GLUE）。自生产路径切换后，本入口
**绕过** canonical `Heritage::heritage`（heritage.cc:2663-2758）的
ADT/guard/refinement 阶段，只服务 example 侧 prototype 估计 helper（在
丢弃型 Funcdata 上）与 crate 内测试；不得在主管线调用。

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

修复后：curl main 块数 102→123，回边检测 3→8（3 个独立循环头：5/7/26，接近 Ghidra 的 6 个），结构化循环数从 8 提升到 17。736/736 测试通过，curl 24/24 gcc 审计。

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

清空与反编译（analysis）关联的全部状态（`Funcdata::clear`，
funcdata.cc:84-112 逐步对齐）。

#### 语义
按 Ghidra 语句顺序执行：

1. `flags &= ~(HIGHLEVEL_ON|BLOCKS_GENERATED|PROCESSING_STARTED|
   TYPE_RECOVERY_START|TYPE_RECOVERY_ON|DOUBLE_PRECIS_ON|RESTART_PENDING)`
   （cc:88-89；七位分析期旗标清零，`BLOCKS_UNREACHABLE`/`PROCESSING_COMPLETE`/
   `JUMPTABLERECOVERY_*` 等保留位不动），并同步复位独立的
   `restart_pending: bool` 镜像。
2. `high_level_index = 0`（cc:91；`clean_up_index`/`cast_phase_index` 无
   Rust 字段，coreaction.rs 标记为忠实 no-op，此处为 no-op）。
3. `min_laned_size` 重新从 Architecture 派生（cc:93，无 lane 记录时为 -1，
   Rust 用 `u32::MAX` 表示同一哨兵）。
4. localmap 建模（cc:95-96）：`scope.symbols.clear()` + 伴生
   `high_symbols`/`symbol_entry_cache` 清空（与 start_processing 相同的
   wholesale-clear 约定），`min_param_offset`/`max_param_offset` 复位
   （varmap.cc:443-444）；typelock 符号存活为已登记 MISMATCH 残差
   （MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001）。
5. `active_output = None`（cc:98 clearActiveOutput）。
6. `funcp.clear_unlocked_output()`（cc:99；fspec.rs 侧为简化版，残差同上）。
7. `union_map.clear()`（cc:100）。
8. `clear_blocks()` → `obank.clear()` → `vbank.clear()`
   （cc:101-103；obank uniqid 归 0，vbank uniqid 归基址、create_index 归 0）。
9. `clear_call_specs()`（cc:104）。
10. `clear_jump_tables()`（cc:105）：override 表调用忠实的
    `JumpTable::clear()`（jumptable.cc:2739-2758，保留
    opaddress/maxaddsub/maxleftright/maxext/collectloads 永久域）后保留，
    非 override 表丢弃。
11. overrides 与 `laned_map` 不清（cc:106 注释；Ghidra 亦无清除调用点）。
12. `heritage.clear()`（cc:107）。
13. `merge_state.clear()`（cc:108 covermerge.clear()）。

#### 作用
主要用于以下场景：

- 重跑分析流程（restart 循环：clear 后 `is_proc_started()==false`，
  startProcessing 可再次进入 —— Ghidra ActionRestartGroup 的前提）
- 测试中复位函数容器
- 在局部失败后回退到更干净的状态
- 重新注入或重新构建函数图

#### 注意事项
“清空”不等于“回到刚创建时的裸状态”：保留域（override JumpTable、
typelock 符号、localoverride、lanedMap、processing_complete 等旗标位）
正是 Ghidra restart 语义的组成部分；两侧差集见
`tools/run_merge_clear_lifecycle_oracle.sh` 的 registered_mismatch_domains。

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

- `new_op(inputs, pc)` — 分配适配层：新 op 初始位于 dead list，直到某个
  `op_insert_*` 将其接入基本块；但底层还不能表达 Ghidra 的 NULL opcode
  与固定数量 nullable input slots，因此完整函数行为仍是 **MISMATCH**。
- `new_op_with_seq(seq)` — 通过 `PcodeOpBank::create_seq` 导入显式 SeqNum；
  `(Address, time)` 保持为不可变 op 身份，并以 `time` 推进 bank 的 uniqid，
  而可变 `order` 只表示接入基本块后的块内位置。该闭包不消除复制语义差异：
  Ghidra `SeqNum` copy constructor 不复制 `order`，Rust 当前 `SeqNum: Copy`
  会复制它，因此直接观察 copied order 仍是 **MISMATCH**，不能由本次
  SeqNum 部分 fixture 推导为完整 copy-constructor `MATCH`。
- `new_unique_out(s, op)` — `Funcdata::newUniqueOut` (281)
- `new_constant(s, val)` — `Funcdata::newConstant` (283)
- `new_unique(s)` — `Funcdata::newUnique` (288)
- `op_set_opcode(op, opc)` — `Funcdata::opSetOpcode` (463)。**2026-07-02**：对齐 `PcodeOp::setOpcode` (op.cc:276) — 清除 opcode 派生 flag 位（CALL/BRANCH/RETURNS/MARKER/CODEREF/...）后按新 OpCode 重设。修复前 CPUI_CALL 的 output 永远不带 CALL flag → ActionMarkExplicit 的 `def->isCall()` 失败 → output 未被 force-explicit → ActionMarkImplied 标 implied → printc 跳过 CALL 语句（curl 丢失约 130 处调用）。
- `op_set_input(op, vn, slot)` — `Funcdata::opSetInput` (467)，扩展 inrefs、维护 descend
- `op_insert_input(op, vn, slot)` — `Funcdata::opInsertInput`（funcdata_op.cc:308-317）：
  扩槽（`PcodeOp::insertInput` op.cc:311-318，`slot` 及之后的旧输入右移一格）后
  **经完整 `op_set_input` 路径**落位——常量去重（cc:108-115）、fresh 空槽跳过
  `opUnsetInput`（cc:118-121 NULL guard）、`addDescend` free 检查 + coverdirty
  （varnode.cc:330-340）。**2026-08-17 收编**（VARNODE-ADDDESCEND-THROW-0001 子项）：
  此前直接 `descend.push` 绕过 opSetInput，是 addDescend 同族最后一个生产者缺口
  （缺 free 检查/coverdirty/常量去重）。Rugra `Vec` 无法物化 Ghidra 的瞬态 NULL
  槽，实现将尾部 split_off 后由 `op_set_input` 追加进新槽（两步间所有 Ghidra 语句
  对 NULL 槽均为 no-op），无需分配可观察的 sentinel Varnode。
- `op_remove_input(op, slot)` — `Funcdata::opRemoveInput`（funcdata_op.cc:291）：先按
  `opUnsetInput` 擦除旧 Varnode 的一个 descendant edge，再从 Rust `Vec` 删除该槽。
- `op_insert_before(op, follow)` — `Funcdata::opInsertBefore`
  (funcdata_op.cc:345)，按 `follow` 的 `BlockBasic.ops` 定位，并把紧邻
  `follow` 的 INDIRECT 组留在原位。
- `op_insert_after(op, follow)` — `Funcdata::opInsertAfter`
  (funcdata_op.cc:373)，按块内顺序插入；非 MULTIEQUAL 会越过块首的
  MULTIEQUAL 组，INDIRECT 的 alive iop 目标会成为实际插入锚点。
- `set_input_varnode(vn)` — `Funcdata::setInputVarnode` (funcdata_varnode.cc:340)：将
  varnode 提升为函数输入（overlap 去重 + `vbank.set_input`）。**2026-07-05 新增**，
  用于 heritage rename 的 empty-stack promotion（heritage.cc:2502/2512）。委托给
  `VarnodeBank::set_input_varnode`；保守子集（省略 ProtoModel 效果属性设置）。
- `delete_varnode(vn) -> Result<()>` — inline `Funcdata::deleteVarnode`
  （funcdata.hh:294）：委托给 checked `VarnodeBank::destroy_varnode` 并传播
  `Deleting integrated varnode`/ownership 错误。用于 heritage rename 替换后的死
  varnode 清理（heritage.cc:2521/2550）。

`op_insert` 的两层状态与 Ghidra 一致：`PcodeOpBank::alivelist` 记录接入
生命周期/接入顺序，`BlockBasic.ops` 记录执行顺序。低层插入同时维护
`PcodeOp.parent`、块内 SeqNum order；插入 BRANCHIND 时设置块的
`SWITCH_OUT`。这两个容器不能互相替代。

兼容边界：部分既有 Rule 单测仍直接构造 parentless flat op bank，违反
Ghidra `opInsertBefore/After/Uninsert` 的基本块前置条件。Rugra 暂时保留
该无块域的旧 alivelist 插入/摘除分支，状态为 **MISMATCH / UNTESTED**；
有真实 `BlockBasic` parent 的有效域走上述原子插入实现，并由锁定 12.0.4
fixture `tests/oracle/op_insert_1204.*` 验证。

相邻但未纳入该 MATCH 的结构缺口：Ghidra `opUnlink/opDestroy` 会把每个
输入槽清成 NULL 而保留槽数。`RULE-MULTICOLLAPSE-0001` 已让 Rugra
`op_destroy` 通过 `destroy_varnode` 真正删除输出 Varnode，并在有 parent 时
执行 markDead + 从 `BlockBasic` 移除；但 `Vec<Arc<Varnode>>` 仍不能表达
nullable slot，只能在按序擦除 descendant 后清空整个 Vec。因此 dead op 的
input-slot 状态仍是 **MISMATCH**，不能由插入或 collapse fixture 推导为完整
`opDestroy` B2 `MATCH`。
同一 OPBANK 缺口也意味着 `new_op(inputs, pc)` 当前 `num_input()==0`，并
预置 COPY opcode/派生 flags；fixture 在插入前立即设置 opcode 和所需输入，
所以本次 `MATCH` 仅证明插入族和 dead/alive 生命周期，不证明完整 newOp。

### 2026-06-26（续）：op_swap_input

- `op_swap_input(op, slot1, slot2)` — `Funcdata::opSwapInput`：交换两输入操作数。
  用于 RuleBoolNegate 翻转比较时的换序（如 `!(V < W) => W <= V`）。

### 2026-06-26（续）：op_set_output

- `op_set_output(op, vn)` — `Funcdata::opSetOutput` (`funcdata_op.cc:70`) ：
  same-Arc output 直接返回；按顺序先将 op 的旧 output 转为 free，再将 `vn`
  从它原来的 defining op 取下，然后调用 `VarnodeBank::set_def` 并消费它
  返回的 canonical Arc。最后应用 Varnode properties 并安装 canonical output，
  避免在 `BTreeSet` 内原位改动 written/def 排序键。

### 2026-06-26（续）：op_destroy / op_unset_input

- `op_destroy(op)` — `Funcdata::opDestroy`（funcdata_op.cc:203）：调用 `destroy_varnode` 删除输出及其 bank identity，按 slot 顺序断开所有输入；有 parent 时 markDead 并从原 `BlockBasic` 删除。（2026-08-23 修正：无 parent 路径也必须 mark_dead——Ghidra 后置条件是 opDestroy 后 op 恒为 dead：Ghidra 中无 parent 的 op 由 `PcodeOpBank::create`（op.cc:946）起始即 dead、在 deadlist，仅 opInsert 的 markAlive（funcdata_op.cc:157）转活；Rugra 的 create 起始即 alive，故无 parent 销毁（未插入 op 或 block Arc 已释放）需显式 mark_dead，否则无输入 alive op 滞留 ActionPool 迭代（processOp isDead 检查 action.cc:830），使读取 getIn(0) 的 Rule（如 RuleSubvarSubpiece subflow.cc:1593）panic——glob_word 修复。）dead op 的 NULL-slot 保留仍受上述 nullable 表示缺口约束。
- `op_unset_input(op, slot)` — `Funcdata::opUnsetInput`：断某输入的 descend 链。
解锁 RuleEarlyRemoval。

### 2026-06-27（续）：op_destroy_recursive / total_replace

- `op_destroy_recursive(op)` — `Funcdata::opDestroyRecursive`（funcdata_op.cc:228）：递归销毁 op 及其变为死代码的定义 op（跳过 call/indirect-source）。使用 scratch worklist 避免递归栈溢出。
- `total_replace(vn, newvn)` — `Funcdata::totalReplace`（funcdata_varnode.cc:1474）：将 vn 的所有读取引用替换为 newvn（遍历 descend 链 + op_set_input）。解锁 ActionMultiCse、constseq。

### 2026-06-26（续）：op_unset_output / new_varnode_out

- `op_unset_output(op)` — `Funcdata::opUnsetOutput` (`funcdata_op.cc:52`) ：先从
  op 取下 output，再通过 `VarnodeBank::makeFree` 将旧 output 从 written/insert
  类转为 bank-owned free Varnode，最后清除 Cover。此顺序保证 bank 的 Loc/Def
  排序键在 flags/def 变化前先移除。当 op 无 output 时不产生任何突变。
- `new_varnode_out(size, addr, op)` — `Funcdata::newVarnodeOut`
  (`funcdata_varnode.cc:104`) ：直接通过 `VarnodeBank::createDef` 以最终
  written/def 键插入 Loc/Def 树，再安装 op output 并应用已有 property
  查询。Rugra 尚未完整表达 Ghidra 的动态 AddressSpace、TypeFactory、
  `assignHigh`、laned-register 和 ScopeLocal property 边效应，这些调用闭包仍为
  **MISMATCH/UNTESTED**。
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
- `set_goto_branch(bl, j)`：标记 out-edge j 为 goto，对齐 Ghidra `FlowBlock::setGotoBranch`（block.cc:305-314）**三件事**：(1) edge flag（BlockBasic 用 GOTO_EDGE_0/1，结构块用 F_GOTO_EDGE），(2) source `INTERIOR_GOTOOUT`（0x400，block.hh:97），(3) target `INTERIOR_GOTOIN`（0x800，block.hh:98）。此前只做 (1)，导致 `is_interior_goto_target` 对 goto 标记的目标块失效。**2026-07-16 B4 修复**。
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

- `op_uninsert(op)` — `Funcdata::opUninsert`（funcdata_op.cc:164）：从
  `BlockBasic.ops` 移除、清 parent，并由 alive list 移到 dead list；输入
  descend 与输出 def 保持不变，因而可以随后重新插入。
- `op_insert_begin(op, bb)` — `Funcdata::opInsertBegin`
  （funcdata_op.cc:413）：MULTIEQUAL 插在绝对块首，其他 op 插在块首
  MULTIEQUAL 组之后。
- `op_get_slot(op, vn) -> i32` — `PcodeOp::getSlot`：返回 vn 在 op 中的输入槽位（-1 未找到）。

### 2026-06-29：spacebase() + split_uses()（底层阻塞解除）

- `spacebase()` — `Funcdata::spacebase()`（funcdata.cc:230-269）：标记映射到虚拟地址空间的寄存器（栈指针 RSP @ Register@0x20, size 8）为 `SPACEBASE` 标志。对已标记且有多后代的空间基 varnode，调用 `split_uses()` 复制定义 op 使各加法用户独立寻址。**这是 Ghidra 让 varmap/ActionStackPtrFlow 识别 RSP 为栈空间指针的规范机制**——不需要 lifter 发出 Stack-space varnode。接入主管线为 `ActionSpacebase`（coreaction.cc:5506，在 ActionHeritage 之后、infertypes 之前）。
- `split_uses(vn)` — `Funcdata::splitUses`（funcdata_varnode.cc:1540-1567）：若 vn 由 op 定义（如 INT_ADD）且有多个后代，复制定义 op 使每个读取者获得独立输出副本。允许按用户分析（如同一空间基派生指针的不同栈偏移）。
- **验证**：curl uVar 碎片 149→0，httpd uVar→0，while/goto 不变，776/776 测试 + curl 24/24 + httpd 29/29 gcc 审计通过。

### 2026-08-15：split_uses 对齐 VarnodeBank 转换（VARNODE-INPLACE-MUTATION-SITES-0001）

- `split_uses(vn)` — `Funcdata::splitUses`（funcdata_varnode.cc:1540-1567）两处对齐修正：
  1. **bank 转换**：新输出 varnode 由 `vbank.create_with_space`（`VarnodeBank::create`，varnode.cc:1250）以最终 (space, loc) 键创建，再经 `op_set_output`（`Funcdata::opSetOutput`，funcdata_op.cc:70-87 → `VarnodeBank::setDef`）完成 WRITTEN 置位与 def 树重键。替换旧的手写 `address_space`/`WRITTEN`/`def` 原地突变（树驻留 key 字段突变会漂移树序、破坏查找语义）。
  2. **循环边界**：Ghidra 迭代器先推进再重写（cc:1551/1563-1564），**每个**原始 descendant 都被重定向到新克隆 op；没有「最后一个读者保留原 op」特例（旧 Rugra `last_idx` break 是移植缺陷）。原 op 留给 dead-code 移除（cc:1566）。
- 验证：HEAD worktree 基线对比证明 5 个失败单测为域外既有（零新增）；E2E curl 124/124；全语料 5 连跑 sha256 一致（03d97945…）；差分 defects=0/numbering=0。

### 2026-06-27（续 5）：CSE 基础设施

- `cse_elimination(op1, op2) -> PcodeOpRef` — `Funcdata::cseElimination`（funcdata_op.cc:1358）：消除两个公共子表达式 op 之一（保留序列号较小的），total_replace 输出后销毁重复 op。
- `cse_eliminate_list(list) -> Vec<Varnode>` — `Funcdata::cseEliminateList`（funcdata_op.cc:1420）：对 (hash, op) 列表排序，查找匹配对，消除冗余。解锁 RuleSelectCse + ActionCse。

### 2026-06-27（续 6）：op_flip_condition

- `op_flip_condition(op)` — `Funcdata::opFlipCondition`（funcdata_op.cc）：翻转比较 op 的条件（INT_LESS↔INT_LESSEQUAL 等 via get_booleanflip），交换输入如需，清除 BOOLEAN_FLIP 标志。解锁 RuleCondNegate。

### 2026-06-27（会话2）：CFG 重写原语（解锁 condexe）

为支撑 condexe 核心图重写（condexe.cc:712），Funcdata 新增忠实于 Ghidra funcdata_block.cc 的方法：
- `remove_from_flow_split(bl, swap) -> Result<(), String>` — `Funcdata::removeFromFlowSplit`（funcdata_block.cc:881-889）+ `BlockGraph::removeFromFlowSplit`（block.cc:1575-1590）：移除一个 2 入/2 出的空块，将每条入边重连到对应的出边。swap=true 时 In(0)->Out(1)/In(1)->Out(0)（交叉）；swap=false 时 In(0)->Out(0)/In(1)->Out(1)（直连）（funcdata_block.cc:880）。序列忠实 block.cc:1584-1589：swap ⇒ `replaceEdgesThru(0,1)`，否则 `replaceEdgesThru(1,1)`，随后 `replaceEdgesThru(0,0)`（swap 经 funcdata_block.cc:886 直传为 flipflow）。condexe execute() 用此消除冗余路径汇合。（2026-08-23 修正：旧实现的 swap 分支序列 (0,0),(0,1) 在第二次调用时越界 panic（block.rs:1613），swap=false 分支误用 flipflow=true 的交叉序列——CONDEXE-CFG-0001。）
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

### 2026-08-15（FUNCDATA-SCOPE-SYNC-0001）：sync_varnodes_with_symbols 忠实移植

旧适配体（两参数全 `_` 忽略、DIRECT_WRITE 代理、从不 updateType、从不设 nolocalalias）被完整移植替换，oracle fixture `tests/oracle/scope_sync_1204`（锁定 12.0.4 oracle，双侧 8 记录逐字节 MATCH）：

- `sync_varnodes_with_symbols(update_datatypes, unmapped_alias_check) -> bool` — `Funcdata::syncVarnodesWithSymbols`（funcdata_varnode.cc:938-989）1:1。按 loc 序遍历 scope 空间 varnode；`findOverlap` 命中符号时 `fl = getAllFlags()`（extraflags=mapped ∪ Symbol flags；`LocalSymbol.usepoint == None` ↔ Ghidra `Scope::addMap` 在 uselimit 为空时设的 addrtied，database.cc:1149-1150；typelock/namelock/nolocalalias=unaliased）；entry.size ≥ vn.size 且 updateDatatypes 时 `getSizedType`（TYPE_UNKNOWN 丢弃，cc:956-960）；entry 更小时仅清 typelock/namelock 位（cc:962-969，nolocalalias 保留）；无符号时 in-scope → `mapped|addrtied`（cc:976）、否则 unmappedAliasCheck 走 `isUnmappedUnaliased`（cc:980）、否则 0。
- `sync_varnodes_with_symbol_set(ordered, index, fl, ct) -> bool`（私有）— per-set 重载 `Funcdata::syncVarnodesWithSymbol(VarnodeLocSet::const_iterator&,uint4,Datatype*)`（funcdata_varnode.cc:1048-1095）1:1：mask 从 `mapped` 起，fl 无 addrtied 时并入 `addrtied|addrforce`（可清不可设），fl 有 nolocalalias 时并入 `nolocalalias|addrforce`（可设不可清），`fl &= mask` 后对同 (space,offset,size) 集内每个非 free varnode 应用；已挂 mapentry 的 varnode 用 `mask & ~mapped` 局部掩码（mapped 位保持不变，cc:1075-1082）；ct 非空时 `updateType`（typelock varnode 不被覆盖），成功时 `high->typeDirty()`；flag 写后 `high->flagsDirty()`（varnode.cc:352-374 副作用，Rugra 的 `Varnode::set_flags` 不含此传播，故在此显式调用）。
- 模块级辅助（funcdata.rs，均带 `// Ghidra:` 注释）：
  - `varnode_use_point_offset` — `Varnode::getUsePoint`（varnode.cc:696-703）。
  - `scope_local_find_overlap`（pub，2026-08-16 SCOPE-FINDOVERLAP-KEY-0001/DYNAMIC-0001 重写）— `ScopeInternal::findOverlap`（database.cc:2392-2404）的 rangemap 分区语义：`find_overlap(point,end)`（rangemap.hh:411-423）`lower_bound(AddrRange(point))` 取与查询相交的最左分区单元，单元内按 `SymbolEntry::getSubsort`（database.cc:97-107，addrtied → 最小 (0,0)，否则首 uselimit range 的 (index,offset)；同二进制代码空间下 index 一致，Rugra 以常量 1 建模）取最小者胜出，等值 subsort 按 Vec 创建序（= std::multiset 等价键插入序）。旧实现"最小 start 真重叠"在互重叠符号上与 oracle 分歧（判别 fixture `tests/oracle/scope_find_overlap_1204`：oracle 答 `narrow` 而旧实现答 `wide`）。动态条目先被过滤（`addDynamicMapInternal` database.cc:1866-1876 只入 dynamicentry 不入 maptable，`LocalSymbol.is_dynamic` 镜像）。辅助 `entry_subsort_key` 为 getSubsort 的 (u8,u64) 键形式。
  - `scope_local_in_scope` — `Scope::inScope`（database.hh:597）→ rangetree 完整覆盖语义；签名保留被基类忽略的 `usepoint` 参数（funcdata_varnode.cc:974 的实参调用形态，SCOPE-USEPOINT-WARNING-0001）。
  - `scope_local_is_unmapped_unaliased` — `ScopeLocal::isUnmappedUnaliased`（varmap.cc:494-502）。
  - `local_symbol_sized_type` + `exact_piece_arc_sub_type` — `SymbolEntry::getSizedType`（database.cc:151-162）+ `TypeFactory::getExactPiece`（type.cc:4090-4117）的 Arc 恒等版本；partial struct/array/enum/union 构造（getTypePartialStruct 族）未移植，返回 None（与 database.rs `SymbolEntry::get_sized_type` 同一残差）。
- 调用闭包：`ActionRestructureVarnode`（coreaction.cc:2281-2282，false/aliasyes，count 累计）与 `ActionMappedLocalSync`（coreaction.cc:2302-2303，true/true，count 累计）。
- 已知残差：① `getExactPiece` 的 partial-struct/array/enum/union 构造缺失（getSizedPiece 返回 None → 不做类型投影）；② Rugra `Varnode::set_flags/clear_flags` 本体不带 flagsDirty 传播（varnode.rs 端预置缺口，本移植在调用点补偿）；③ 未知类型工厂命名 `undefined{size}` vs Ghidra `xunknown{size}`（fixture 层规范化，属 TypeFactory 命名域而非本函数契约）。

### 2026-06-29（续 2）：new_extended_constant（funcdata_varnode.cc:462）
- `new_extended_constant(s, lo, hi, before_op)` — 创建可能 >8 字节的常量 Varnode。s≤8 时直接 newConstant；s>8 且 hi==0 时 INT_ZEXT(const)；s>8 且 hi!=0 时 PIECE(hi,lo)。忠实移植 Ghidra `Funcdata::newExtendedConstant`（funcdata_varnode.cc:462-484）。解锁 RuleDivTermAdd。

### 2026-06-29（续 3）：Funcdata.active_output 字段
- 新增 `active_output: Option<ParamActive>` 字段（funcdata.hh）。用于 ActionReturnRecovery 检测函数返回值。当 RETURN op 有 >1 input 时自动创建 active_output。

### 2026-06-29（续 4）：Funcdata::calc_nz_mask（funcdata_varnode.cc:856-930）【2026-08-23 已重写为 oracle 结构，见文末】
- `calc_nz_mask()` — 计算所有 Varnode 的 non-zero mask（NZM）。遍历 alive ops，根据 opcode 从输入 NZM 推导输出 NZM：COPY/ZEXT 传播、XOR/OR 合并、AND 交集、LEFT/RIGHT 位移、SUBPIECE/PIECE 等。
- 用于 RuleAndMask/RuleOrMask 位优化 + 类型推断变量范围。（初版为简化单遍实现，2026-08-23 按 FUNCDATA-CALCNZM-0001 重写为 oracle 两阶段结构。）

### 2026-06-29（续 5）：find_varnode_input
- `find_varnode_input(size, addr)` — 忠实移植 `Funcdata::findVarnodeInput`（funcdata.hh:324）。查找指定 size+address 的 input varnode。用于 ActionRestrictLocal + AncestorRealistic。

### 2026-06-29（续 6）：Stack 空间 / spacebase 配置字段
- 新增字段（对齐 cspec `<stackpointer>` + Architecture stack 配置）：`stack_space: AddressSpace`（= Stack）、`stack_pointer_space/offset/size`（= Register@0x20 size 8 = x86-64 RSP）、`stack_grows_negative: bool`（= true）。
- Funcdata 不持有 Architecture 引用（L3 缺口），这些字段用 x86-64 默认值初始化，模拟 Ghidra Funcdata 从 Architecture 拿 stack 配置。
- `spacebase()` 改为从这些字段读 stack pointer 位置（不再硬编码 0x20）。

### 2026-06-29（续 7）：new_indirect_op（funcdata_op.cc:683）
- `new_indirect_op(indeffect, stack_offset, sz)` — 忠实移植 `Funcdata::newIndirectOp`。建 `STACK:off = INDIRECT(STACK:off, iop=STORE)`：input[0] + output 在 Stack 空间（stack_offset），input[1] 是引用 causing op 的 iop 常量。op 标记 INDIRECT_STORE，插在 causing op 前。这是 Ghidra 产生 Stack 空间 varnode 的核心机制（guardStores 调用它）。
  - **2026-06-29 续**：input/output 通过 `vbank.set_def` 建（设 INSERT），output 设 `active_heritage`（对齐 guardStores heritage.cc:1554-1556）。

### 2026-06-29（续 8）：inject_raw_ops varnode 去重
- `inject_raw_ops` 创建非 Const input varnode 时，改用 `vbank.find_or_create_input_space(size, space, offset)`（替代 `create_with_space`）。这让同地址的 input varnode 共享身份（对齐 Ghidra xref 去重），descend 累积所有 reader。修复了 descend 链碎片化（RSP input 从 1 个 descend 变 64 个）。

### 2026-07-01：TYPE_RECOVERY_START flag
- `funcdata_flags::TYPE_RECOVERY_START`（funcdata.hh:90）+ `has_type_recovery_started()/set_type_recovery_started()`（funcdata.hh:151）。标记类型恢复已开始，Rule 据此决定 type-based 守卫是否生效。

### 2026-07-01：Architecture 引用 + iop-space varnode + op_undo_ptradd（解锁 cpool/funcptr/iop 依赖 Rule）
- `arch: Option<Arc<Architecture>>` 字段 + `get_arch()/set_arch()`（funcdata.hh:80/144）。Ghidra 在 ctor 从 scope 取 glb；Rugra 用 set_arch 接线。默认 None 保证现有 832 测试不破坏。
- `new_varnode_iop(op)`（funcdata_varnode.cc:176-184）— 在 Iop 空间创建引用 op 的 varnode（Arc::as_ptr 编码）。
- `get_op_from_const(vn)`（op.hh:249）— iop-space varnode 反查回 PcodeOp。
- `op_undo_ptradd(op)`（funcdata_op.cc:579）— PTRADD 撤销为 INT_ADD/INT_MULT。
- `op_mark_cpool_transformed(op)`（funcdata.hh:485）— 标记 cpool 已转换。

### 2026-07-01（续 2）：new_indirect_creation + jump_tables + get_store_guard/load_guard
- `new_indirect_creation(op, addr, sz, possibleout)`（funcdata_op.cc:710-728）— constant 零输入 + indirect_creation flag on op/in/out。
- `jump_tables: Vec<Arc<RwLock<JumpTable>>>` 字段（funcdata.hh:89）。
- `find_jump_table(op)`（funcdata_block.cc:446）+ `remove_jump_table(jt)`（funcdata_block.cc:65）。
- `get_store_guard(op)/get_load_guard(op)`（funcdata.hh:269-270）— 转发到 Heritage。

### 2026-07-01（续 3）：combine_input_varnodes + DOUBLE_PRECIS_ON + new_varnode + warning_header
- `combine_input_varnodes(vn_hi, vn_lo) -> Result<()>`（funcdata_varnode.cc:381-454）—
  校验 input/同空间连续性（按 endian 选择合并地址），PIECE→COPY，非 PIECE reader
  在入口块首造 SUBPIECE，并让新输出保留各 source 的 Address space/offset。锁定
  12.0.4 的 synthetic LE/no-effect fixture 覆盖 register PIECE、重复槽、非 PIECE
  readers、canonical combined input 与两条 LowlevelError；BE Architecture 配置、nullable
  slot、local-map/ProtoModel/high-level/lane 副作用和 raw SeqNum time/order 分离仍是残差。
- `DOUBLE_PRECIS_ON` flag（funcdata.hh:85=0x2000）+ `set_double_precis_recovery`/`is_double_precis_on`。
- `new_varnode(size, addr)`（funcdata.hh:282）— 包装 vbank.create。
- `warning_header(txt)`（funcdata.cc:135-145）— 通过 commentdb 加 WARNINGHEADER 注释。

### 2026-07-01（管线改造）：restart_pending + jumptable_recovery
- `restart_pending: bool` 字段 + `has_restart_pending()/set_restart_pending(bool)` — ActionRestartGroup 的重启信号。
- `is_jumptable_recovery_on() -> bool` — Rugra 无 jumptable 恢复，返回 false（TODO）。

### 2026-07-01（续 4）：create_new_block
create_new_block(): 创建新空 BlockBasic 并加入 bblocks（funcdata_block.cc newBlockBasic）。

### set_high_level + HIGHLEVEL_ON（2026-07-03 续）
- 新增 `Funcdata::set_high_level`（对齐 Ghidra `setHighLevel` funcdata_varnode.cc:595）：设 `HIGHLEVEL_ON` 标志（对齐 `highlevel_on` funcdata.hh:84）+ 遍历 loc_tree 给每个无 high 的 Varnode 分配 HighVariable。幂等。
- 新增 `funcdata_flags::HIGHLEVEL_ON`。

### remove_unreachable_blocks 入口检测修复（2026-07-03 续）
- 修了入口检测 bug：之前只查 `ENTRY_POINT` flag（Rugra CFG 构建从不设此 flag），回退到 block 0。改为查 `size_in()==0`（对齐 Ghidra `isEntryPoint()` block.hh:325）。
- 但发现更深的根因：Rugra 的 bblocks CFG 构建不完整——跳转表/间接分支的边没全连上，导致 BFS 从入口可达的块远少于实际（getparameter: 49/133 块被误判可达，84 块误判不可达）。启用 ActionUnreachable 会删掉大部分函数体。
- ActionUnreachable 保持禁用，注释说明根因（CFG 边不完整）+ 修复路径（CFG 构建需补全跳转表/间接分支边）。

### remove_unreachable_blocks 保守门禁 + 深度诊断（2026-07-03 续 2）
- 加了保守门禁：unreachable >= 5 且 > 5% 时跳过移除（防 CFG 不完整时误删可达块）。
- 诊断：即使只移除 1 个"不可达"块（myprogress: 13 块中 1 块），也破坏了函数体 → block 移除逻辑（branchRemoveInternal/blockRemoveInternal）或 structure_reset 有 bug。
- ActionUnreachable 保持禁用，注释说明：CFG 边不完整 + 块移除逻辑需验证。

### remove_unreachable_blocks op-destruction（2026-07-03 续 3）
- 新增 Phase 2：销毁死块的所有 op（mark_dead），从 obank.alivelist 移除。这是正确移除块的前提（之前 op 留在 alivelist → printc 打印已删块的内容 → 损坏输出）。
- 但 ActionUnreachable 仍禁用：还需要 MULTIEQUAL (phi) 修补（Ghidra blockRemoveInternal :278-294 的 opRemoveInput+opZeroMulti），否则后继块的 phi-node 引用被删块 varnode 变悬空。
- curl gcc 24/24（保持），956/956 测试。

### remove_unreachable_blocks descendantsOutside 检查（2026-07-03 续 4）
- Phase 2 改进：只 mark_dead 没有外部后代的 op（descendantsOutside 检查，对齐 Ghidra funcdata_block.cc:312）。有外部 phi-node 引用的 op 保持 alive（块标 DEAD 但 op 不删）。
- 但 ActionUnreachable 仍禁用：根因更深——Action 在 mainloop 最开始运行，此时 bblocks CFG 可能不完整（sblocks 未建），移除块破坏后续阶段状态。需 pipeline 顺序调整或 CFG 完整化后才能安全启用。

### spliceBlockBasic op-moving 修复（2026-07-03 续 5）
- 修复：spliceBlockBasic 现在把 out_block 的 ops 移到 bb 末尾（对齐 Ghidra funcdata_block.cc:940-947）。之前只重定向 CFG 边，ops 被孤立。
- 还加了 MULTIEQUAL 检查（Ghidra :936 遇 phi 抛异常，Rugra 返回 false）。
- 但仍需 setOrder（:948 重置 seq_num）——Rugra 的 BlockBasic::set_order 未实现。RedundBranch 保持禁用直到 setOrder 完成。

### BlockBasic::set_order + spliceBlockBasic（2026-07-03 续 6）
- 新增 `BlockBasic::set_order`（block.rs）——重置块内所有 op 的 seq_num.order，均匀分布（Ghidra block.cc:2638-2651）。
- spliceBlockBasic 在 op-moving 后调用 set_order（Ghidra funcdata_block.cc:948）。
- 但 RedundBranch 仍禁用：splice 移除块后，引用该块为 goto 目标的 op 留下 `goto ;` 空目标。需更新 goto 引用（重定向到拼接后的块）。

### spliceBlockBasic CFG 对齐（2026-07-03 续 7）
- 重写 `splice_block_basic` 的 CFG 边处理，忠实对齐 `BlockGraph::spliceBlock`（block.cc:1597-1620）。
- 之前：手工 `remove_edge + add_edge` 拼接，丢失 moveOutEdge 的 reverse-index 重定向，且**完全丢弃 flags**。
- 现在：
  - 读取 `fl1 = bl.flags & (UNSTRUCTURED_TARG|ENTRY_POINT)`、`fl2 = outbl.flags & SWITCH_OUT`、`szout = outbl.size_out()`
  - `remove_edge_blocks(bb, out_block)` = `removeOutEdge(0)`（block.cc:1612）
  - `for _ in 0..szout { move_out_edge(&out_block, 0, bb) }` = `moveOutEdge` 循环（block.cc:1614-1616）
  - `remove_block_arc(out_block)` = `removeBlock`（block.cc:1618）
  - `bb.flags = fl1 | fl2` = Ghidra 的 `bl->flags = fl1 | fl2`（block.cc:1619，**直接赋值非 OR**）
- `mergeRange`（funcdata_block.cc:953）暂缺：Rugra 无 Cover 系统，记录为已知基础设施缺口。
- root cause：flags 丢失导致 `f_unstructured_targ` 丢失，printc 无法解析 goto 目标 → `goto ;`。
- Alignment Evidence 见 commit message。

### 2026-07-04（续）：op_insert_end + op_mark_non_printing
- `op_insert_end(op, bb)`（funcdata_op.cc:435）：插到块末尾；若末尾是
  flow-break（BRANCH/RETURN），则插在该终结 op 之前。
- `op_mark_non_printing(op)`（对齐 funcdata.hh:519）：设置 NONPRINTING flag。

### 2026-07-04：移植高优先级缺失 Funcdata op-editing API
- `op_set_all_input(op, vvec)`（funcdata.hh:477）：一次性设置所有输入（先 unset 全部，resize，再逐个 set）。
- `op_mark_calculated_bool(op)`（funcdata.hh:486）：标记布尔输出。
- `op_mark_special_print(op)`（funcdata.hh:483）：标记特殊打印。
- `op_mark_no_collapse(op)`（funcdata.hh:484）：标记不可折叠。
- `op_mark_spacebase_ptr(op)`（funcdata.hh:487）/ `op_clear_spacebase_ptr(op)`（funcdata.hh:488）。
- `mark_indirect_creation(indop, possible_output)`（funcdata.hh:451）：把已存在的 INDIRECT op 标记为 indirect creation。

### 2026-07-04（续 2）：移植 block-graph 重写 API
- `install_switch_defaults`（funcdata_block.cc:688）：遍历 jump_tables，标记每个 switch 块的默认边。
- `remove_do_nothing_block(bb)`（funcdata_block.cc:328）：移除 do-nothing 块（setDead + opDestroy + removeBlock + structureReset）。
- `node_join_create_block(...)`（funcdata_block.cc:790）：创建合并块（newBlockBasic + removeEdge + moveOutEdge + addEdge）。
- 文件级 helper `find_out_index`（对应 FlowBlock::getOutIndex）。

### 2026-07-04（续 3）：移植 nodeSplit + CloneBlockOps
- `node_split(b, inedge)`（funcdata_block.cc:856）：分裂基本块，复制 p-code 到新块。
- `node_split_block_edge`（funcdata_block.cc:835）：创建 DUPLICATE_BLOCK 块，重定向入边。
- `switch_edge(in, outbefore, outafter)`（block.cc:1489）：重定向出边目标。
- `CloneBlockOps` struct（funcdata_block.cc:962-1104）：完整 p-code 克隆逻辑：
  - `build_op_clone`：克隆 op（复制 opcode + flag 子集，跳过 branch）。
  - `build_varnode_output`：克隆输出 varnode（复制 flag 子集）。
  - `clone_block`：遍历 ops 克隆 + patch_inputs。
  - `patch_inputs`：MULTIEQUAL→COPY 转换 + 常量共享 + 克隆映射查找。
- 新增 `block_flags::DUPLICATE_BLOCK`（f_duplicate_block=0x40000）。
### 2026-07-04: Added flow module (FlowInfo reachability tracking)

### 2026-07-04（续 4）：AncestorRealistic + ancestorOpUse + onlyOpUse 移植

**AncestorRealistic**（funcdata.hh:655-724 + funcdata_varnode.cc:1997-2237）：
- `AncestorRealistic` 结构 + `ArState`（op: Arc<RwLock<PcodeOp>>, slot, flags, offset）
- `state_flags` 模块：SEEN_SOLID0/SEEN_SOLID1/SEEN_KILL
- `ar_command` 模块：ENTER_NODE/POP_SUCCESS/POP_SOLID/POP_FAIL/POP_FAILKILL
- `execute(op: &PcodeOpRef, slot, trial: &mut ParamTrial, allow_fail) -> bool`
- `enter_node` — 5 case switch：INDIRECT（isIndirectCreation/isIndirectStore/killedbycall）、SUBPIECE（overlap 检测 + minimal traversal）、COPY（internal/incidental + PIECE-following minimal traversal）、MULTIEQUAL（push + multiDepth++）、PIECE（trial_size 比较 + slot 选择）
- `upon_pop` — MULTIEQUAL 回溯（markSolid/markKill + checkConditionalExe + seenSolid/seenKill 决策树）
- `check_conditional_exe` — parent block size_in==2 + solid slot source size_out==1
- Rust 适配：trial_killed_by_call/trial_size 快照字段 + pending_ind_create_formed/pending_condexe_effect 延迟应用

**ancestorOpUse**（funcdata_varnode.cc:1917-1994）+ **onlyOpUse**（funcdata_varnode.cc:1805-1904）：
- `pub fn ancestor_op_use(has_active_output, maxlevel, vn, op, trial_slot, offset, flags) -> bool`
- 递归 def 链遍历（INDIRECT/MULTIEQUAL/COPY/PIECE/SUBPIECE）+ only_op_use 回调
- `only_op_use` — 前向 descend 迭代器遍历，检测 BRANCH/CBRANCH/BRANCHIND/LOAD/STORE/CALL/CALLIND/INDIRECT/COPY/RETURN
- traverse_flags 模块：ACTIONALT/INDIRECT/INDIRECTALT/LSB_TRUNCATED/CONCAT_HIGH
- checkCallDoubleUse 保守端口（返回 false = 非合法双重使用 → 安全方向）

**新增 PcodeOp mark 访问器**：is_mark/set_mark/clear_mark（op.hh:190/234/235，flags MARK=1<<13）
<!-- annotation-pass: 2026-08-15 -->
<!-- activeparam-port: 1783158350.9624996 -->
 

### 2026-07-05: op_set_input / op_unset_input / total_replace / op_set_all_input 签名改 &mut self
- `op_set_input`(funcdata_op.cc:104): 改 `&mut self`,4 类语义全对齐(early-out / const dedup / opUnsetInput erase_descend / addDescend)。修了 placeholder bug(用 vn 当 resize 占位会触发 early-out)。
- `op_unset_input`(cc:92): erase_descend + clearInput(隐式)。
- `total_replace` / `op_set_all_input`: 改 `&mut self`(Ghidra 是 mutable)。

### 2026-08-11：ANN-E CFG/helper 注释溯源

本轮只补来源标注，不改变运行时行为。源码 oracle 固定为 Ghidra 12.0.4
commit `e40ed13014025f82488b1f8f7bca566894ac376b`。

- `find_in_index` 映射 `block.cc:579 FlowBlock::getInIndex`；Rust 用
  `Option<usize>` 表示 Ghidra 的 `-1` 未找到值。
- `has_no_code` 映射 `funcdata.hh:153 Funcdata::hasNoCode`，但当前 Rust
  仍以空 op-bank 加零 size 近似 Ghidra 的 `no_code` flag，因此该映射仍是
  已知行为缺口，不能据此声明 `MATCH`。
- `block_index_for_op_addr`、`find_jump_table_arc`、`load_fill`、
  `funcp_extrapop`、`userop_type` 是 Rust 的地址查找、Arc 所有权、
  `Result`/`Option` 或缺字段适配器；Ghidra 在 `compareCallspecs`、
  `blockRemoveInternal`、`fillinExtrapop`、`earlyJumpTableFail` 内直接执行
  对应表达式，没有这些独立的 `Funcdata` 函数。

其中 `funcp_extrapop` 恒返 unknown、`userop_type` 的缺表 fallback、以及
`block_index_for_op_addr` 用地址代替 PcodeOp 身份/顺序，都是既有差异；本轮
仅如实分类，未将其伪装为 Ghidra 映射。

## 2026-08-13：`PcodeEmitFd::dump` 输入对象创建语义

`PIPE-REACH-0001` 重新读取锁定 `funcdata.cc:878-910 PcodeEmitFd::dump` 后，修正
`inject_raw_ops_single` 的输入构造：每个 emitted operand 都创建独立 Varnode；常量走
`VarnodeBank::create_constant` 以保留 CONSTANT 状态；BRANCH/CBRANCH/CALL 的第一个
operand 走一字节 code-reference；其他 operand 以 SLEIGH 指定空间创建。每次输入创建后
立即建立 descendant 反向引用。

真实 `GetStr` raw fixture 中，Rugra 因而从旧的 197 个 Varnodes 变为与 Ghidra 相同的
272 个；全部 103 个 op 的地址、数值 opcode、输入数量和输出存在性顺序一致。完整
Varnode 状态仍为 `MISMATCH`：Ghidra 初始 unknown datatype/COVERDIRTY 等状态没有被
Rugra 的当前 VarnodeBank 生命周期复现，CALL 的 Fspec 地址空间也依赖 `ADDR-0001`。
本项不构成 `Funcdata` 模块 L3 证明。
 
 
 
 

## 2026-08-15：`SLEIGH-FLOW-REL-0001` — `inject_raw_ops_single` 忠实 `PcodeEmitFd::dump`

锁定 oracle：Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。本轮
完整重读 `funcdata.cc:878-908 PcodeEmitFd::dump`、`funcdata_varnode.cc:43-233`
（`assignHigh/newConstant/newUniqueOut/newVarnodeOut/newVarnode/newCodeRef`）、
`varnode.cc:1250-1352/1411-1432`（`VarnodeBank::create/xref/createDef/replace`）、
`op.cc:941-1000`（`PcodeOpBank::create/destroy`）后重写
`Funcdata::inject_raw_ops_single`：

1. **输出先行**：有输出的 op 先经 `VarnodeBank::create_def_with_space`
   （=`createDef`：构造 flags + `setDef` 的 `written|coverdirty` + `xref` 的
   `insert`）创建输出 Varnode，再创建输入——与 dump 的
   `newOp → newVarnodeOut → opSetOpcode → inputs` 顺序一致，固定了
   `Varnode::create_index` 与 Ghidra 相同的发射序。
2. **CODEREF 语义**：仅 BRANCH/CBRANCH/CALL（typeop.cc:586/605/663 的 coderef
   opflags；BRANCHIND/CALLIND 无此 flag）的 input(0) 走 `newCodeRef`：
   一字节 annotation Varnode 落在 **SLEIGH 上报的原空间**（`Address(vars[0].space,
   vars[0].offset)`），类型为核心 "code" 类型（`sleigh_arch.cc:233
   setCoreType("code",1,TYPE_CODE,false)`）。因此 CPUID 决策树这类
   `goto <label>` 内部相对分支（slghparse.y:462，const space + j_relative +
   `resolveRelatives` 写回的 masked 偏移）保持 Const 空间；x86 机器
   `jmp/call rel`（ia.sinc:1149-1151 `export *[ram]:$(SIZE) reloc`）保持 Ram
   空间绝对地址。二者不再被互相改写。
3. **其余输入**：逐引用新建 Varnode（常量含内，无位置去重），`addDescend` 按
   slot 顺序追加并置 `coverdirty`，与 `newVarnode→vbank.create` +
   `opSetInput→addDescend` 等价。
4. 新增 `code_ref_datatype()`：构造与 `TypeFactory::getTypeCode`
   （type.cc:3692-3701）观察等价的 `{name:"code", metatype:TYPE_CODE, size:1}`
   值对象（Rugra 未把 TypeFactory 穿入该发射路径）。

真实 `0f a2 c3`（CPUID; RET）门禁结果：Rugra 与锁定 Ghidra capture 逐字节一致
（81 ops / 186 Varnodes / 33 个 Const 空间 relative 分支全部 internal 解析 /
34 blocks / 49 raw+graph edges / visited 2）。这是
`tools/run_sleigh_flow_relative_oracle.sh` 差分门禁的 `funcdata.rs` 侧证据；
Varnode 生命周期其余差异（Fspec 空间、HighVariable 分配等）仍由
`ADDR-0001`/`CALLSPEC-0001` 跟踪，本模块保持 L2/MISMATCH。

### 2026-08-15: totalReplace 快照迭代 + opUnsetInput NULL-slot 语义（FUNC-GLOBRANGE-HANG-0001）

- `total_replace(vn, newvn)`（funcdata_varnode.cc:1474-1487）：从「循环重扫
  descend 直到无 live 条目」改为 Ghidra 的迭代器语义——一次性快照 live
  descendant，逐站点在**应用时**计算首个匹配 slot（getSlot，op.hh:166，
  先前的站点改写后求值），再 `op_set_input`。Ghidra 用 `op = *iter++` 在
  opSetInput 断链前推进迭代器，因此每个原始条目恰好访问一次、到达
  endDescend() 即终止——即使 `newvn == vn` 时 opSetInput 早退（cc:107）留下
  条目也只跑一趟。旧 Rust 重扫循环在 precisely 该情形下永续自旋
  （glob_range(0x4d60) 死锁，A/B 证明：旧实现跑
  `test_total_replace_same_varnode_terminates` 30s 超时被 SIGTERM；新实现
  通过）。死 Weak 条目（Ghidra raw 指针模型不可达）无法访问即跳过；slot
  缺失（Ghidra getSlot→numInput→opSetInput throw）按漂移清理掉 stale 条目。
- `op_unset_input(op, slot)`（funcdata_op.cc:92-99）与 `op_set_input` 第 (3)
  步（cc:120-121）：Ghidra `clearInput`（op.hh:136）原地置 NULL，
  `opDestroy`（funcdata_op.cc:213-215）逐槽 `if (vn != NULL)` 守卫；Rust
  `Vec<Arc>` 不能存 NULL，stale Arc 保留在槽内，改用「op 是否仍在该 vn 的
  descend 列表」作为链路存活性判据——不在则跳过 erase，等价于 Ghidra 的
  NULL-slot no-op。重复 unset（op_unlink → op_destroy 序列，Ghidra 靠 NULL
  槽天然幂等）不再产生 `erase_descend not in descend list` WARN 风暴。
- `destroy_varnode`（funcdata_varnode.cc:277-284）：`op_get_slot` 返回 -1 时
  不再 `as usize`（usize::MAX 静默 no-op，遗留无法匹配的死条目），改为跳过
  ——Ghidra 该点越界写 UB（前置条件违规），Rugra 以保守跳过表达。
- 回归测试：`test_total_replace_same_varnode_terminates`、
  `test_total_replace_skips_dead_weak_entries`、
  `test_unlink_then_destroy_does_not_disturb_other_readers`。
- E2E：curl 全量 24/24 函数完成（glob_range 1.1s、match_url 亦完成），
  `erase_descend` WARN 1454→0；残余 340 条 `free varnode multiple
  descendants` 为揭出的真实 live 不变量违规（UPSTREAM-OUTVN-DEADWIRE-0001
  残余范围）。

### 2026-08-15：`op_heritage` 桥 + `set_self_ref` 收窄（`HERITAGE-OWNERSHIP-0001`）

- 新增 `Funcdata::op_heritage`（funcdata.hh:462 的 1:1 桥）：`mem::take`
  暂移 persistent Heritage → `heritage.heritage(self)` 单 pass（显式
  `&mut Funcdata`，零 Weak 升级、零嵌套锁）→ 原对象回写。连续调用
  pass=0→1→2→3。
- `set_self_ref` 不再回填 `heritage.fd`（该字段已删除）：Heritage 管理器
  不再持有 Funcdata 句柄，消除 HERITAGE-DRIVER-0001 审计认定的写锁
  重入死锁源。
- 证据：`tests/oracle/heritage_ownership_1204.*`（3/3 MATCH，含 phi
  自引用环三连 pass 无死锁）；生产 `ActionHeritage` 未切换（归
  HERITAGE-DRIVER-SWITCH）。

### 2026-08-15：`new_indirect_op` 忠实化 + `new_indirect_creation_in_space`（HERITAGE-CALLGUARD-0001）

- `new_indirect_op(indeffect, space, offset, sz, extra_flags)`（funcdata_op.cc:683-698）
  签名对齐 oracle：输出/输入 varnode 在调用方传入的 `(space, offset)` 而非
  写死 Stack；`extra_flags` 由调用方决定（CALL guard 传 0，STORE guard 传
  `indirect_store`）；input[1] 改用 `new_varnode_iop`（Iop 空间，经
  `get_op_from_const` 可回溯 causing op 别名）替代写死的 Const/annotation
  常量；构造器不再 `set_active_heritage`（Ghidra 的调用方
  guardCalls/guardStores 在构造后设置）。
- `new_indirect_creation_in_space(indeffect, space, offset, sz, possibleout)`
  （funcdata_op.cc:710-728）：输出 varnode 在调用方空间（如 killed-by-call
  的 RAX Register 空间）而非写死 Unique；旧 `new_indirect_creation` 保留为
  Unique 空间委托（ruleaction 的历史调用点行为不变），同样移除构造器内的
  `set_active_heritage`。
- 证据：`tests/oracle/heritage_callguard_1204.*`（锁定 12.0.4 双侧 7 case
  逐字节 MATCH：IOP 别名、parent/位置、in0 形态、out 空间/flags）。


### 2026-08-15：MERGE-PERSISTENT-STATE-0001 — 持久 merge_state 挂载点
- `Funcdata::merge_state: MergePersistentState`（新字段，funcdata.hh:96
  `Merge covermerge` 对应物）：构造器初始化为 default（对应 funcdata.cc:39
  `covermerge(*this)`），merge-family Action 经 merge.rs 的 attach/detach
  往返共享 testCache/copyTrims/存活前提。
- `Funcdata::clear()`：在 heritage.clear() 后追加
  `self.merge_state.clear()`（funcdata.cc:108 `covermerge.clear()` 对齐）。
- `set_high_level()`：每个待分配 High 的 varnode 先
  `if has_cover() { calc_cover() }`（funcdata_varnode.cc:52-53
  setHighLevel→assignHigh 的 calcCover 副作用）。此前缺失该步导致独立
  merge Action（mergerequired/mergecopy/mergeadjacent）在 null-cover 空前提
  下运行。
<!-- annotation-pass: 2026-08-15 -->

### 2026-08-16：`new_indirect_op` 规范构造（`HERITAGE-CALLGUARD-0001`）

`Funcdata::new_indirect_op`（funcdata_op.cc:683-728 对应物）：free-varnode
输入、def 承载输出、Iop alias 往返、调用方旗标、`op_insert_before` 的
INDIRECT 群回跳；构造器不再内置 `set_active_heritage`/硬编码
`INDIRECT_STORE`（对齐 oracle 的调用方语义）。供 canonical guardCalls
接线消费；生产 `ActionHeritage` 双 pass 路径不变。

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`Funcdata::linkSymbol`（funcdata_varnode.cc:1156-1184 对应物）重写为逐行
对齐：proto-partial 走 `link_proto_partial`（`PieceNode::findRoot` 的
op.cc:824-852 多级 PIECE 回溯为 funcdata.rs 模块级 `piece_node_find_root`）；
high 已有 Symbol 时提前返回；`queryProperties(addr,1,usepoint)` 查询重叠
（usepoint 为 def op 地址，input 取函数基址-1，varnode.cc:696-703）；无重
叠且非 persist 时 `localmap->addSymbol("", high->getType(), addr, usepoint)`
——`local_XX` HashMap 自创名删除，golden 的 bVar/pcVar 族由此产生。
`handleSymbolConflict`（:997-1029）与 `buildDynamicSymbol`（:1283-1305）改
走 ScopeLocal 符号模型（varmap.rs），HighVariable→Symbol 关联由
`Funcdata::high_symbols` 侧表建模（variable.rs 不在本租约）。persist 无重
叠仍返回 None。`remapVarnode`/`remapDynamicVarnode` 的 symbol_table 记录
保留（GLUE，待 DB-LOCALSCOPE-MAP-0001 收编）。

### 2026-08-16（复核修正）：`linkSymbol` 链四处对齐收口（`FUNCDATA-LINKSYMBOL-TYPED-0001` 复核）

`piece_node_find_root` 的多 PIECE 平手改用忠实的 `PcodeOp::compare_order`
（op.cc:778-791 执行支配序，原为地址数值比较）；`attach_symbol_to_vn` 不再
手写 flags——经 `Funcdata::symbol_entry_cache`（LocalSymbol→database.rs
`SymbolEntry` 身份稳定桥接，动态项带 hash、静态项带单址 uselimit）调用
`Varnode::set_symbol_entry`（varnode.cc:429-439 的 mapped/namelock 腿）+
忠实 `HighVariable::set_symbol`（variable.cc:245-275 四分支 symboloffset：
整匹配 -1、部分覆盖=overlap 字节偏移），coreaction.cc:2965 的
`getSymbolOffset() < 0` namerec 门因此与 Ghidra 同判；桥接 Symbol 的名字
在命名期后由 ActionNameVars 刷新与 varmap 符号一致。fixture 新增
partial_coverage case：4 字节临时@0x70（def pc=函数基址-1）+ 1 字节
input@0x71 → soff=1、被 namerec 门排除，双侧逐字节一致。

### 2026-08-17：set_arch 绑定 Architecture default model（FUNCPROTO-MODEL-BIND-0001）

- `set_arch` 不再只赋 `arch` 字段——它镜像 Ghidra named ctor 的绑定链
  （funcdata.cc:48 `glb = scope->getArch()` → funcdata.cc:69
  `funcp.setScope(localmap, baseaddr-1)` → fspec.cc:3884
  `if (model == 0) setModel(s->getArch()->defaultfp)`）：当 `funcp` 尚无
  model 时安装 `Architecture::defaultfp` 的共享 Arc。Rugra 的 Funcdata
  构造没有 ctor 期 Scope（FUNCDATA-LOCALSCOPE-OWNERSHIP-0001），set_arch
  即 `glb` 可用时刻。效果：DWARF/PLT locked-prototype overlay 之后不再出现
  非法 `model_locked && !has_model`；callspec 克隆自 fd.funcp 时携带 model，
  `FuncCallSpecs::has_effect` 返回 cspec 声明效果而非保守 UnknownEffect。

### 2026-08-17：op_set_input 常量去重分支补全 copySymbol（VARNODE-COPYSYMBOL-FIELDS-0001）

- `op_set_input`（funcdata_op.cc:104-125）常量单读者去重分支的
  cc:112 `cvn->copySymbol(vn)` 此前只内联拷贝 mapentry，丢失
  `Varnode::copySymbol`（varnode.cc:493-505）的其余簿记：Datatype 指针
  拷贝（cc:496）与 typelock|namelock 位的清空重继承（cc:498-499，
  不含 mapped/insert）。现改为直接调用 `Varnode::copy_symbol`
  （varnode.rs，cc:496-499 字段腿），equate 锁定常量在去重后不再丢
  type/typelock/namelock。
- cc:500-504 的 high 簿记（`high->typeDirty()`；有 mapentry 时
  `high->setSymbol(this)`）按 attach_symbol_to_vn 房式（Varnode 字段腿
  + Funcdata 调用侧 high 腿）接在调用侧，因为 `copy_symbol` 的
  `&mut self` 拿不到 `HighVariable::set_symbol` 所需的 Arc-to-self。
  当前不可达：Rugra `new_constant` 未接 `Funcdata::assignHigh`
  （funcdata_varnode.cc:72 缺口，残差 R1 登记 VARNODE-COPYSYMBOL-FIELDS-0001），
  cvn.high 恒 None；assignHigh 补全后该块即生效。
- oracle fixture `tests/oracle/varnode_copy_symbol_1204.{cc,rs}` +
  `tools/run_varnode_copy_symbol_oracle.sh`（pinned base dce02f7 +
  src/funcdata.rs overlay）：locks_type / no_locks / mapentry_symbol
  （含 mapentry 指针拷贝与 mapped 位不拷贝的判别）/ identity_return
  （cc:107 早退）/ spacebase_exempt（cc:110 豁免）6 行双侧逐字节 MATCH；
  high 块 NO_ORACLE（fixture 不开 highlevel_on，双侧 cvn.high==null）。

## 测试区维护（2026-08-17）

`test_split_uses_duplicates_op` / `test_unlink_then_destroy_does_not_disturb_other_readers`
的 harness 修正（VARNODE-ADDDESCEND-THROW-0001 前置件，同 aa0b6e1 ruleaction/subflow
模式）：被 splitUses 重读（funcdata_varnode.cc:1560 对每个复制 op 重设全部输入）或
被双读者共享的 free 寄存器 varnode 经 `VarnodeBank::set_input`（varnode.cc:1358 setInput
映射）登记为 INPUT，消除 addDescend throw（varnode.cc:336 "Free varnode has multiple
descendants"）会触发的 Ghidra 不可达 harness 态。INPUT 保持 is_written/is_addr_tied
false，split_uses / op_unlink / op_destroy / op_unset_input 无 input-flag 分支，
断言与被测路径零变化；setInput 在唯一 loc 上返回同一 Arc，ptr_eq 断言原样通过。
生产代码未动。

### 2026-08-17（续）：assign_high 双向挂接 + new_* 族十处接线（FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001）

- `assign_high`（funcdata_varnode.cc:48-59）补全 Ghidra `new HighVariable(vn)`
  ctor（variable.cc:220-235）的全部副作用：`add_instance(vn)`（cc:231）、
  `vn.mergegroup = 0; vn.high = high`（cc:232 setHigh(this, numMergeClasses-1)）、
  `vn.getSymbolEntry().is_some()` 时 `set_symbol(vn)`（cc:233-234）。此前只
  返回 HighVariable Arc 由调用者丢弃，vn.high 恒 None。
- newVarnode 族十处调用面接线（全部在 funcdata_varnode.cc，任务清单原写
  funcdata.cc 系笔误，oracle 已核实）：
  | oracle 行 | 函数 | Rugra 接线 |
  |---|---|---|
  | :72 | newConstant | `new_constant` assign_high |
  | :89 | newUnique | `new_unique` assign_high |
  | :110 | newVarnodeOut | `new_varnode_out` assign_high（queryProperties 腿前） |
  | :135 | newUniqueOut | `new_unique_out` assign_high |
  | :157 | newVarnode(s,m,ct) | `new_varnode` assign_high |
  | :182 | newVarnodeIop | `new_varnode_iop` assign_high（annotation no-op 腿） |
  | :196 | newVarnodeSpace | 已有调用，本次随 assign_high 补全而生效 |
  | :212 | newVarnodeCallSpecs | 已有（annotation no-op） |
  | :231 | newCodeRef | 已有（annotation no-op） |
  | :604 | setHighLevel | `set_high_level` 重写为经 assign_high 单一真源 |
- `Funcdata` 新增 `high_level_index: u32` 字段（funcdata.hh:76）；
  `set_high_level` 补 cc:600 `high_level_index = vbank.get_create_index()` 与
  annotation 拒绝门（iop/fspec/coderef varnode 不挂 high，cc:54 guard）。
  merge.rs `wire_unique_high` house pattern 自动退化为 no-op（early return）。
- 上节 "当前不可达：cvn.high 恒 None" 已失效——highlevel_on 置位后
  `op_set_input` 去重副本的 cc:500-504 high 腿可达，
  VARNODE-COPYSYMBOL-FIELDS-0001 残差 R1 关闭（fixture dedup_high 观察）。
- oracle fixture `tests/oracle/funcdata_assign_high_1204.{cc,rs,metadata.json}` +
  `tools/run_funcdata_assign_high_oracle.sh`：20 行双侧逐字节 MATCH，覆盖
  highlevel 门（off 2 行）/ setHighLevel 扫掠（7 行：flag、index、const/written
  +cover/input/iop、instances 形状、幂等）/ on 态十处族（7 行）/ opSetInput
  dedup high 腿（R1 关闭观察）/ copySymbol typedirty 重臂 + symbol guard。
  Ghidra 12.0.4 `Varnode::getHigh()` 在 high==NULL 时 throw
  LowlevelError("Requesting non-existent high-level")（varnode.cc:92），
  fixture 两侧都读裸字段（C++ `->high` / Rust `high: Option`）对齐观察通道。
  E2E：curl + httpd stdout 与接线前零差异（Matched 123 不降、defects=0、
  numbering=0）。
<!-- annotation-pass: 2026-08-17 -->


## structure_reset 支配树重置链（block_domroot_1204，2026-08-19）

**`Funcdata::structure_reset`** — `funcdata_block.cc:704-731`
`structureReset` 的语句级镜像：清 `blocks_unreachable` →
`bblocks.structureLoops(rootlist)` → `bblocks.calcForwardDominator(rootlist)`
→ `rootlist.len()>1` 置 unreachable → 死 jumptable 消灭循环（jumpvec 保序、
`warning_header` 先于 drop、isDead 经 PcodeOp 读锁）→ `sblocks.clear()` →
`heritage.force_restructure()`。RUGRA-GLUE 尾部补
`build_dom_depth/build_dom_subtree/calc_dom_frontier` 缓存刷新（Ghidra 的
dom depth 是 Heritage::buildADT 局部计算 heritage.cc:2338，Rugra 为
per-block 缓存；不触碰 oracle 可观测状态）。LowlevelError 通道按项目既有
策略映射为 panic（与 `Varnode::add_descend` 同款，per-function worker 隔离）。

**`funcdata_flags::BLOCKS_UNREACHABLE`**（bit 6 重映射，Ghidra
`blocks_unreachable` = funcdata.hh:60 = 0x4；flags 无序列化出口，按名访问
无外部可观测差异）与 **`has_unreachable_blocks`**（funcdata.hh:149）。

**对齐证据：** `tools/run_block_domroot_1204_oracle.sh` MATCH（见
docs/api/block.md 同节）；机制 C 独立复核 APPROVE。残差：死 jumptable 的
`get_indirect_op()==None` 输入域 UNTESTED（Ghidra 无条件解引用=null 即 UB，
Rugra 防御性视为 alive，生产不可达已注释）。

## laned-map 生命周期（LANEDIVIDE-INFRA-0001）


- `check_for_laned_register`（funcdata_varnode.cc:298-309 镜像）/
  `set_laned_reg_generated`（funcdata.hh:155，minLanedSize=1000000 哨兵）/
  `lane_accesses`（beginLaneAccess/endLaneAccess 镜像）/
  `clear_laned_access_map`（funcdata.hh:399）—— Funcdata 侧 typed ordered
  lanedMap 生命周期，键序为 `VarnodeData::operator<`（pcoderaw.hh:67：space
  index → offset → size 降序）。四个 `newUnique`/`newUniqueOut`/
  `newVarnode`/`newVarnodeOut` call site（funcdata_varnode.cc:90/112/136/159）
  均接 `s >= minLanedSize` 门;`clear()`（funcdata.cc:93）重置 minLanedSize 但
  不清 lanedMap（与 oracle 一致）。
- 对拍：`tools/run_lanedivide_infra_oracle.sh` MATCH（miss/hit、排序、
  setLanedRegGenerated 抑制、clear 保留 + gate 重置、clearLanedAccessMap
  逐字节一致）；残差 LANEDIVIDE-INFRA-RESIDUAL-0001（见
  tests/oracle/lanedivide_infra_1204.metadata.json）。

## 2026-08-23：MERGE-CLEAR-LIFECYCLE-0001 — clear 持久状态生命周期对拍

- `Funcdata::clear()`（funcdata.cc:84-112）从 8 步补齐为 13 步全量对齐：
  新增 7 位分析旗标掩码复位（含 `restart_pending` bool 镜像）、
  `high_level_index=0`、localmap 建模（symbols+high_symbols+
  symbol_entry_cache+param window 标量）、`active_output=None`、
  `funcp.clear_unlocked_output()`、`clear_call_specs()`、`clear_jump_tables()`，
  并把执行顺序排成 Ghidra 语句序。
- `clear_jump_tables()`（funcdata_block.cc:43-60）：override 表由"替换为新空表"
  改为调用忠实的 `JumpTable::clear()`（jumptable.rs 既有实现，
  jumptable.cc:2739-2758），保留 maxaddsub/maxleftright/maxext/collectloads/
  opaddress 永久域；此前 fresh-replacement 会丢永久域（MISMATCH 修复）。
- 观察投影（`tools/run_merge_clear_lifecycle_oracle.sh`，
  pin-base 2f9725f + funcdata.rs/merge.rs 双 overlay，schema2）：
  构造带全部持久域的 Funcdata，双侧观察 clear 前后 6 行 stdout。
  结果 `covered_projection=4/6 projection_status=MATCH overall_status=MISMATCH`；
  两行登记 MISMATCH：`localmap_typelock_survival`（Ghidra 保留
  typelock+namelock 符号，Rugra wholesale-clear 丢弃——需 varmap.rs 侧
  忠实 clearUnlocked）、`funcproto_unlocked_output`（fspec.rs 简化版不清
  returnBytesConsumed——需 fspec.rs 侧补齐）。残差统一登记
  MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001（含 4 项 UNTESTED：window range
  重派生、clean_up/cast_phase index、merge 通道生产路径填充、
  localoverride 持久性投影）。
- 既有测试影响：`funcdata::` 42 通过、2 失败
  （test_infer_params_and_return_type / test_type_propagation）为 base
  2f9725f 上即失败的预存在残差（已用 base 文件复跑验证），与本改动无关。
<!-- annotation-pass: 2026-08-23 -->

## 极性重断言（2026-08-23，root，CONDEXE-TRUEOUT-0002 跟进）

`test_bool_condition_folding_and_pattern` 按 Ghidra 纯位置极性（block.hh:299-300，out[1]=true）重断言：双 CBRANCH 的 **false** 边合流 → `BlockCondition(Or)`（block.cc:1785）；旧 And 断言编码的是翻转前反极性。

## calcNZMask 对齐重写（2026-08-23，FUNCDATA-CALCNZM-0001）

### Funcdata::calc_nz_mask（funcdata_varnode.cc:856-926）— oracle 两阶段结构
- **Phase 1（cc:859-902）**：显式 DFS opstack 按 alive 顺序遍历。遍历到 unwritten 输入时初始化：常量 → `nzm = offset`（cc:889-890）；非常量 → `nzm = calc_mask(size)`（cc:892）；spacebase 输入额外 `&= ~0xff`（视为对齐，cc:893-894）。op 弹栈时 `outvn->nzm = getNZMaskLocal(true)`（cc:874），MULTIEQUAL 的 looping 输入边被 `isLoopIn(slot)` 裁剪（cc:882-885）。Varnode 构造初值：常量=offset、其余 ~0（varnode.cc:597/601/605）。
- **Phase 2（cc:904-925）**：清 mark，把所有 MULTIEQUAL 压入 worklist；反复用 `getNZMaskLocal(false)`（不裁剪 loop 边）重算，nzm 变化时把该输出的全部 descend 压回 worklist，直至不动点。
- 旧实现（简化单遍 + 内联 switch）已删除；旧 switch 中 INT_NEGATE/INT_2COMP 分支是自创语义（oracle 落 `default:` → fullmask），已随重写移除。

### Funcdata::pcode_op_nz_mask_local → PcodeOp::get_nz_mask_local（op.cc:547，FUNCDATA-CALCNZM-0002 合并）
- **完整 oracle switch（op.cc:547-771）已迁至 `PcodeOp::get_nz_mask_local`（src/op.rs）**：比较/布尔 → 1；COPY/ZEXT 传播；SEXT sign_extend；XOR/OR/AND；LEFT/RIGHT（含 >8 字节扩展精度分支 cc:612-630）；SRIGHT（符号位已知 0 分支 cc:639-644）；**INT_DIV**（cc:648-659，coveringmask(val) >> mostsigbit_set(常量分母)——sc6 y/64 根因修复）；INT_REM（cc:660-663）；POPCOUNT/LZCOUNT（cc:664-672）；SUBPIECE（含扩展精度 cc:673-692）；PIECE（cc:693-698）；INT_MULT（cc:699-731）；INT_ADD（进位 cc:732-739）；MULTIEQUAL（cliploop 裁剪 cc:740-757）；CALL/CALLIND/CPOOLREF isCalculatedBool→1（cc:758-765）；default→fullmask。
- **输入 NZM 读取直接访问存储字段 `nzm`**（oracle varnode.hh:231 `getNZMask() { return nzm; }`）。Rugra 的 `Varnode::get_nz_mask()`（varnode.rs）是 calcNZMask 接线前的保守近似（常量→offset、其余→calc_mask），不能用于传播——残差 TODO FUNCDATA-CALCNZM-0003。
- funcdata.rs 内的暂存副本 `Funcdata::pcode_op_nz_mask_local` 已删除（值等价迁移）；`calc_nz_mask` 的 phase-1（cc:874）与 phase-2（cc:919）调用点直接调用 `PcodeOp::get_nz_mask_local`。原 funcdata.rs 侧 RUGRA-GLUE（op.rs 租约限制）随之解除，TODO FUNCDATA-CALCNZM-0002 的 op.rs divergent 旧版（忽略 cliploop、缺 DIV/REM/POPCOUNT/LZCOUNT/MULT/CALL 臂、输入 mask 走保守近似）已被完整 switch 替换。
- 原始 `>>`/`<<` 位点（oracle 未加保护处）用 `wrapping_shr/wrapping_shl` 镜像 x86-64 移位计数掩码语义；oracle 经 `pcode_right/pcode_left`（address.hh:505-517）保护的位点按其语义（sa>=64 → 0）。

### 主管线接线核实（FUNCDATA-CALCNZM-0001）
- oracle 的 calcNZMask 唯一生产调用点是 `ActionNonzeroMask::apply`（coreaction.hh:300），注册于 universal mainloop 的 `ActionSpacebase` 之后、`ActionInferTypes` 之前（coreaction.cc:5506-5508）。`newUniqueOut` 等 funcdata_varnode.cc 构造函数 **不** 触发 calcNZMask。
- Rugra 侧对应注册已存在：src/action.rs:1196（`add!(mainloop, "analysis", ActionNonzeroMask)`，"analysis" 在默认 decompile grouplist 内），无需新增接线。
- 功能证据：新增单测 `test_nonzeromask_pipeline_wiring`（funcdata.rs）——`u1=EDI&0x3f0; u2=u1/3; STORE` 走完整 `decompile` root 后，INT_DIV 输出 nzm == 0x1ff（coveringmask(0x3f0)=0x3ff >> mostsigbit_set(3)=1），未接线时写 unique 保持构造初值 ~0 不可能得到该值。


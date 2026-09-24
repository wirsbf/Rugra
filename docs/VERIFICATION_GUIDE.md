# Rugra-Ghid
ra 验证指南

> **
状态声明**：截至当前仓库可见代码与文档状态，
Rugra 的验证体系仍处于
**未完成**阶段。  
> 已经具备一部分静态对齐测试与运行时验证框架代码，但**不能据
此宣称**已经完成了与 Ghidra 的端到端一致性验证，也**不能宣称**当前输出与 Ghidra 100% 等价。

本文档用于说明：

1. 当前已经具备哪些验证能力
2. 哪些关键验证
仍未真正落地
3. 如何区分“静态对齐”与“运行时
对拍”
4. 当前阶段建议采用什么验证路径
5.
 5. 阅读和更新本文件时应避免哪些失真表述
 6. 如何为验证类结论补充证据来源

> 机器门禁入口与本文件较早的历史说明并存时，以
> `tests/oracle/fixture_registry.json`、`tools/select_fixtures.py` 和生成式
> `docs/alignment_audit/FUNCTION_LEDGER.json` 为准。未登记 fixture 的源码改动不是
> “无需测试”，而是 coverage gap。

### 差分诊断工具链后续计划（2026-08-14）

详细实施方案见
[`docs/alignment_audit/DIFFERENTIAL_ALIGNMENT_TOOLING_PLAN_2026-08-14.md`](alignment_audit/DIFFERENTIAL_ALIGNMENT_TOOLING_PLAN_2026-08-14.md)。
计划已拆入 `docs/TODO_BOARD.md` 的稳定 ID。下图表示硬依赖；互不相连的分支可以并行，
不是一条强制串行链：

```text
稳定函数 ID → registry/schema → metadata 四态迁移 → strict gate/CI → 函数 evidence
cache hardening ───────────────┐
registry/schema ───────────────┴→ 标准 oracle result
标准 oracle result + strict gate/CI → runner 全量迁移
标准 oracle result → IR invariant → Action/Rule trace → hang triage
函数 evidence + oracle result → P-code/CFG DSL → fuzz → reducer → corpus promotion
reducer hardening ────────────────────────────────────────┘

既有 `PIPE-TREE-0001` 是 Action trace 的已满足前置，`RUNTIME-TIMEOUT-0001` 是 hang triage
的已满足前置；精确 DAG 以计划文档和 TODO 行为准。
```

审计基线显示工作树可见 32 套 metadata/runner，但正式 registry 只登记 12 套；现有
`stage_diff.py` 主要定位到阶段 hash，现有 `reduce_fixture.py` 也只做删除式 JSON/hex ddmin。
因此近期优先目标是统一事实源并自动定位首个错误 mutation，而不是直接扩大完整二进制 fuzz。
顶层 fixture 状态继续严格采用 B2 的 `MATCH/MISMATCH/NO_ORACLE/UNTESTED`；局部已匹配部分
只能记为 observation 级证据，不能以 `PARTIAL_MATCH` 冒充新的顶层状态。迁移旧
`PARTIAL_MATCH` 时必须逐 fixture 判定：已有双侧差异记 `MISMATCH`，双侧已测部分相等但
覆盖不完整记 `UNTESTED`，缺少合法同输入双侧 oracle 记 `NO_ORACLE`；不得一刀切。

### 机器化四级入口（2026-08-12）

日常验证统一通过以下入口，避免每次人工拼接一整套命令：

```bash
python3 tools/rugra_gate.py edit
python3 tools/rugra_gate.py commit --staged
python3 tools/rugra_gate.py wave
python3 tools/rugra_gate.py nightly
```

`edit` 只做秒级反馈；`commit` 增加全静态检查、生成账本检查和受影响的真实 oracle
fixture；`wave` 运行全部 fixture、全目标测试和 curl/httpd 回归；`nightly` 再加入
fresh-target canonical release 构建。每一级都可用 `--report` 保存结构化 JSON。

门禁不会因 selector 未找到 fixture 而静默跳过：`commit` 以上层级对 coverage gap
返回 2。`--dry-run` 可审计将执行的命令，但不能作为通过证据。

昂贵 fixture 和 pipeline stage 可通过 `tools/oracle_cache.py` 内容寻址复用。cache key
必须包含锁定 commit、architecture、compiler spec、analysis options、输入、runner 和
两侧 comparand 的真实 hash；cache hit 仍重新验证 provenance 和 artifact hash。缓存只减少
重复编译/执行，不改变 `MATCH/MISMATCH/NO_ORACLE/UNTESTED` 的判定，也不能补齐未覆盖分支。

端到端输出不同时，先用 `tools/stage_diff.py snapshot` 保存两侧同一输入的有序阶段 artifact，
再用 `compare` 定位第一个差异。原始 stage hash 是诊断索引，不是行为证明；只有该阶段完整
观察结果及其所有状态突变同输入零差异时，映射函数才可记 `MATCH`。

`GetStr` 已有历史六层 fixture，但截至 2026-08-14 **不能作为当前源码可直接运行的证据**。
metadata 固定的 Rust comparand SHA 为 `bfcadc80…`，当前文件为 `8e74e438…`，因此以下命令会在
provenance 预检阶段 fail-closed，而不是产出当前诊断：

```bash
tools/run_getstr_pipeline_oracle.sh
```

历史结果写入 `result/pipeline_snapshots/getstr/`：`ghidra/`、`rugra/` 和
`rugra-repeat/` 分别保存 raw P-code、CFG、Heritage/SSA、完整 Action IR、结构树和 C 文本；
`comparison.json` 保存每层首个 JSON 路径差异，`README.md` 给出紧凑摘要，`ghidra.c`、
`rugra.c` 与 `rugra-repeat.c` 可阅读。历史报告为 `MISMATCH`，不是 golden；它曾记录两侧
103 ops / 272 Varnodes / 6 CFG blocks，但审计确认旧 runner 实际没有比较其声明中的
`has_output`，并且 `zip` 未检查尾部长度，因此这些字段不能继续作为完整同输出证明。

历史 raw 层也不是 `MATCH`：第一个 op-storage 差异位于 direct CALL，Ghidra 用动态 Fspec
space index 5，Rugra 因固定 `AddressSpace` 模型只能用 synthetic Iop index 7；第一个
Varnode-state 差异是 Ghidra 已附 unknown datatype/COVERDIRTY，而 Rugra 尚未附这些状态。
此外 Ghidra 侧实际载入完整 gcc cspec，而当前 Rust companion 没有消费同一 cspec；新的
`00_effective_configuration` preflight 在这一差异关闭前必须报告 `NO_ORACLE`，不得继续解释
后续 IR 差异。`ORACLE-RESULT-0001` 将拆分 `--verify-recorded`、`--diagnose-current` 和审核后的
`--accept`，在该任务完成前不要把旧 runner 的失败描述成“最新反编译结果”。

历史 fixture 使用 release profile。debug Action 路径会暴露
`VARMAP-GATHEROFFSET-0001` 与 `RULE-COLLECTTERMS-0001` 两个核心无符号边界缺陷；因为它们
尚未完成独立核心复核，本 snapshot 不把 release 成功冒充对应分支 `MATCH`。

Ghidra 的 Heritage 快照来自真实 `decompile` Action 在 `paramdouble` 前的 breakpoint；Rugra
目前只能直接重放 `ActionHeritage`，所以该层明确是 `NO_ORACLE` 诊断边界。只有补齐同一
Action-tree 观察点并在完整状态上零差异，才能将该层改记 `MATCH`。

首差异定位后，可用 `tools/reduce_fixture.py` 缩减输入。predicate 必须运行真实两侧 fixture，
并以结构化 `predicate_signature` 区分同一故障、不同故障、非法 candidate 与 harness error；
不能只看 exit code，也不得把手写 expected 当 oracle。reducer trace 是诊断证据，最终最小 case
仍须补齐 commit/arch/cspec/options/input 指纹并进入 B2 runner。

---

## 1
. 验证目标

Rugra 的验证工作不是单一测试，而是分层目标：

- **结构层验证**：核心数据结构是否与 Ghidra 的概念模型基本对齐
- **算法层验证**：P-code、SSA、CFG、类型传播等核心算法行为是否一致
- **输出层验证**：最终伪 C 输出在语义上是否接近或等价
- **回归层验证**：修改后是否破坏现有行为

当前项目**已在结构层迈出了一部分**，但**算法层与输出层仍未完成**。

---

## 2. 当前可确认的真实状态

结合当前代码与文档，项目验证现状应按以下方式理解。

### 2.1 已具备的部分

#### A. 静态对齐测试存在
`src/align/` 下已经存在若干面向 Ghidra 核心概念的对齐模块，例如：

- `address.rs`
- `varnode.rs`
- `pcodeop.rs`
- `datatype.rs`
- `range.rs`
- `heritage.rs`
- `block.rs`
- `action.rs`

这些模块说明项目已经围绕 Ghidra 的概念模型开展了映射与验证工作。

#### B. 运行时验证框架代码存在
`src/align/runtime_verify.rs` 已经存在，说明项目已经开始设计运行时比对框架，框架中可见的目标包括：

- 常量求值比对
- P-code 生成比对
- SSA 版本验证
- CFG 结构验证
- 差异记录与统计

但这只能说明“**框架方向存在**”，**不能直接等价于验证已经完成**。  
按当前最近一次最小样本推进记录看，`mov rbx, rax` 这条样本已经从“框架级真实运行记录”进一步推进到：比较入口能够接收 **真实 opcode、真实 output、真实 input 列表**，并由 `verify_pcode_generation(...)` 基于结构化本地比较结果返回 `Match` 或 `Mismatch(...)`，不再无条件返回 `Match`。  
进一步地，当前比较入口也已经不再只是 stdout 日志副作用：`rugra_compare_pcode(...)` 现在会返回结构化比较状态，调用侧可以区分 `match`、`opcode mismatch`、`output mismatch`、`input count mismatch`、`input mismatch`、`missing Rugra op` 等结果类型。

#### C. FFI 相关代码存在
仓库中存在 `src/ffi.rs`，且运行时验证框架中引用了 FFI 接口。这说明项目确实计划走“Rust 实现 ↔ Ghidra/相关原生能力”的跨边界验证路线。

---

### 2.2 明确未完成的部分

以下事项目前**不能**视为已完成：

#### A. 不能确认运行时对拍已经全面打通
虽然有 `runtime_verify.rs`，但从可见代码来看，若干逻辑仍处于框架、占位、简化比较或待环境集成状态，不能视为“已稳定可用的完整运行时验证体系”。

#### B. 不能确认 Ghidra FFI 集成已经形成稳定工作流
当前仓库有相关接口与文档描述，但不能据此断言：

- 已完成全部链接配置
- 已在本地/CI 中稳定运行
- 已有大规模真实样本验证结果
- 已得到可靠的一致性统计

#### C. 不能确认 SSA / CFG / P-code 已与 Ghidra 严格一致
这些是反编译器的核心语义层。  
除非存在真实运行结果、稳定测试样本和明确统计，否则不能写成“已保障一致性”。

#### D. 不能确认端到端输出验证已完成
当前不能把“能够生成某些 C 风格输出”表述为：

- 已完成与 Ghidra 输出对比
- 已经语义等价
- 已达到 1:1 对齐
- 已达到生产级完全可信

---

## 3. 验证层级划分

为了避免文档失真，项目中的“验证”应严格分层描述。

### Level 1：静态结构对齐
目标：验证 Rust 中的数据结构、字段语义、基本行为与 Ghidra 概念模型相近。

典型对象：

- `Address`
- `SeqNum`
- `Varnode`
- `PcodeOp`
- `DataType`
- `Range`
- `RangeList`

这一层能说明：

- 模型命名和字段组织较接近
- 某些基础行为有单元测试覆盖
- 为后续算法对齐提供了基础

这一层**不能说明**：

- 算法行为已一致
- 反编译输出已一致
- 整体系统已经通过对拍

---

### Level 2：运行时局部对拍
目标：在受控输入下，对某一局部行为做比较。

可能包括：

- 常量折叠结果
- 单条指令的 P-code 序列
- 单个函数的 SSA 版本分配
- 单个函数的基本块划分

这一层如果未来真正落地，才有资格讨论：

- 哪些局部行为一致
- 哪些局部行为存在偏差
- 差异集中在哪个算法阶段

当前这一层已经不再只是纯占位框架：至少在第一条最小样本 `mov rbx, rax` 上，Rugra 侧已经能够把真实的 opcode / output / input 元数据送入比较层，比较入口也已经能够返回结构化状态码，随后再由 `verify_pcode_generation(...)` 汇总为 `VerifyResult`。  
但这一层**仍然不能被表述为已完成**，因为当前比较虽然已经具备“结构化返回路径”，参考数据仍主要来自 Rugra 侧本地构造与当前程序态，并不等价于“已接入稳定、完整、可信的 Ghidra 参考侧逐字段结果”。

---

### Level 3：端到端语义验证
目标：针对真实二进制，比较整个函数或程序的反编译结果。

可能比较内容：

- 控制流结构是否接近
- 调用参数与返回值恢复是否接近
- 变量恢复是否合理
- 伪 C 代码语义是否等价

这一层是最难的，也最接近用户真实感知质量。  
**当前不能宣称这一层已经完成。**

---

### Level 4：持续回归验证
目标：每次改动后快速发现回归。

理想形态包括：

- `cargo test`
- 指定模块测试
- 对齐模块测试
- 示例样本回归
- 未来可能加入的 FFI/样本级验证

这一层是项目走向稳定工程化的关键，但当前仍应视为**持续建设中**。

#### Level 4 已落地资产：投影 fixture 银行（2026-09-25 扩至 71 条）

`tests/fixtures/projections/` 固化了 71 个函数的锁 oracle / Rugra 双侧
stage projection（v1.2），每函数一个目录（oracle.projection +
rugra.projection + manifest.toml，记录 oracle commit e40ed130、capture
命令、日期、sha256 pin 与验证状态）。门禁入口：

```bash
tools/verify_projection_bank.sh        # 全部条目；sha256 完整性 + run_stage_bisect --v1 全 MATCH 才退出 0
```

当前条目：next_url / match_url / parseconfig.constprop.0 / myprogress /
getparameter.constprop.0 / glob_set / glob_word / file2string.part.0 /
my_get_token / glob_range（前 10 条逐 lane 入库），HARVEST 级联收割
批 15 条：main_free / main_init / SetHTTPrequest.part.0 / SetHTTPrequest /
glob_url / frame_dummy / __do_global_dtors_aux / _init / _fini /
__libc_csu_fini / __libc_csu_init / deregister_tm_clones /
register_tm_clones / GetStr / my_fwrite，helpf（PM-HF），以及 ADDRARM2
（2026-09-25）经 oracle harness **地址-only 臂**收割的 PLT-thunk 全量
45 条（PLT0 + .plt.got + 43 个 .plt.sec 桩，runner 函数名位置传 `-`，
fixture 按控制台 `load <addr>` 语义在入口注册函数；全部首验即 MATCH；
首分歧残差与地址臂机制见银行 README）。结构、重捕获 recipe 与新增条目
流程见 `tests/fixtures/projections/README.md`。

---

## 4. 当前建议采用的验证策略

在运行时对拍尚未完全落地前，建议使用“**保守、分层、可复现**”的验证路线。

### 第一步：先保证普通 Rust 测试可运行
优先确保基础测试不退化：

```text
cargo test
```

如果某次改动只影响某个局部模块，应优先运行该模块相关测试。

---

### 第二步：运行对齐相关测试
针对 `align` 相关模块运行聚焦测试，确认结构层行为未退化。

可按实际测试命名运行类似：

```text
cargo test --lib align::
```

或更细粒度地针对具体子模块执行。

> 注意：是否能够直接使用某条命令，取决于当前工程内测试命名、feature 和平台环境。  
> 文档中不应把“可能可运行”写成“已经稳定跑通”。

---

### 第三步：检查运行时验证框架是否仍可编译
当修改了 `src/align/runtime_verify.rs`、`src/ffi.rs` 或对齐模块时，至少应确认：

- 代码仍然可编译
- 接口没有失配
- 没有因为签名变更导致框架彻底失效

如果运行时验证尚未可执行，也应至少保持“框架不被进一步破坏”。

---

### 第四步：先用最小样本维持局部验证链路

在端到端样本恢复之前，建议优先维护“单条指令 / 小型指令序列”的最小验证记录，例如：

- `mov rbx, rax`
- `add rax, 1`
- `sub rax, 8`

这类样本的价值在于：

- 可以稳定复现输入字节与预期 lifting 结果
- 可以把问题限定在 `disasm -> x86_lift -> pcoderaw -> funcdata -> runtime_verify -> ffi` 的最小链路
- 可以更清楚地区分：
  - 入口是否可执行
  - 比较参数是否真实
  - 结果是否被结构化回传
  - 当前差异究竟来自 Rugra 侧实现，还是参考侧数据仍未真正接入

> 这类最小样本属于 **Level 2：运行时局部对拍** 的基础建设。  
> 即使某条样本通过，也**不能**直接外推出“更大范围样本已完成一致性验证”。

---

### 第五步：针对示例和样本做人工审阅
对于当前阶段，人工审阅仍然重要。可结合：

- `examples/`
- 反编译输出样本
- `CURRENT_STATUS.md`
- `GAP_ANALYSIS.md`

重点确认：

- 输出是否明显退化
- 控制流是否出现明显错误
- 是否引入新的无意义变量碎片
- 是否出现明显错误的调用恢复

这类检查属于“人工质量审阅”，**不能冒充自动一致性验证**。

---

## 4.1 第一条最小 P-code 样本记录：`mov rbx, rax`

为了把“最小 P-code 对拍重入计划”从草案推进到真实记录，当前已经补入第一条最小样本的可执行记录口径。

### 样本信息

- **样本 ID**：`PCode-Min-001`
- **目标层级**：`Level 2：运行时局部对拍`
- **机器码**：`48 89 c3`
- **汇编文本**：`mov rbx, rax`
- **Rugra 入口链路**：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`

  ### 当前可确认的真实结果

  基于当前仓库中的最小测试链路，这条样本已经能够完成以下步骤：

  1. 反汇编得到单条 `mov rbx, rax`
  2. `X86Lifter` 生成 1 条 raw P-code
  3. 该 raw P-code 的 opcode 为 `CPUI_COPY`
  4. 输出 varnode 为寄存器空间 `rbx`
     - offset: `0x18`
     - size: `8`
  5. 输入 varnode 为寄存器空间 `rax`
     - offset: `0x00`
     - size: `8`
  6. `Funcdata::inject_raw_ops(...)` 后：
     - op 数量为 `1`
     - basic block 数量为 `1`
  7. `verify_pcode_generation(...)` 在给定 `ghidra_op_count = 1` 时返回 `Match`

  ### 当前仍需明确区分的限制

这条记录**不能**被解读为“已经与 Ghidra 完整对齐”，但它也已经不再停留在最早的纯占位比较阶段。当前更准确的边界是：

- 当前不再只是 op 数量比较，比较入口已能消费：
  - opcode
  - output varnode
  - input varnode 列表
- 当前比较入口已能返回结构化状态，而不只是打印日志
- 当前 `verify_pcode_generation(...)` 已会消费该结构化状态，并据此生成 `Match` / `Mismatch(...)`

但以下限制仍然存在：

- 当前参考信息仍主要来自 Rugra 侧本地构造，而不是 Ghidra 独立返回的结构化结果
- 当前还没有形成“Ghidra 参考侧结果 -> 结构化返回 -> 统一差异报告”的完整双边闭环
- 当前仍不能把最小样本的本地结构化通过，外推出更大范围的真实 parity 结论

因此，这条样本当前更准确的结论是：

> **Rugra 已经具备第一条最小 `mov reg, reg` 样本的本地可执行验证记录，**
> **并已具备结构化 FFI 比较返回路径，**
> **但目前仍处于“局部结构化验证已建立、真实 Ghidra 侧独立参考尚未完整接入”的阶段。**

### 当前差异分类

建议把这条样本当前归类为：

- `已可运行`
- `已形成真实记录`
- `比较入口已触发`
- `已具备结构化 FFI 返回路径`
- `尚未形成真实 Ghidra 侧逐字段对拍`

### 证据来源

- 代码入口：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`
- 当前最小样本测试：
  - `src/funcdata.rs` 中新增的 `test_mov_reg_reg_minimal_alignment_path`
- 本地测试现象：
  - 测试通过
  - 同时输出一条比较入口日志，表明当前 FFI 比较仍在使用占位参考信息

### 下一步最小动作

围绕这条样本，后续最优先的动作应是：

1. 让比较入口返回的不只是状态码，还能携带更细粒度的结构化差异信息
2. 让 `verify_pcode_generation(...)` 消费来自参考侧的独立结果，而不是主要依赖 Rugra 本地构造数据
3. 将当前“已具备结构化返回路径”的状态，推进到真正的双边逐字段比较
4. 在完成后，再复制同样流程到：
   - `add rax, 1`
   - `sub rax, 8`

---

## 4.2 第二条最小 P-code 样本记录：`add rax, 1`

在继续推进最小 P-code 对拍重入计划时，当前已经补入第二条样本 `add rax, 1` 的失败记录。  
这条记录的价值不在于“验证通过”，而在于它第一次把算术类 opcode 的最小链路差异明确暴露出来。

### 样本信息

- **样本 ID**：`PCode-Min-002`
- **目标层级**：`Level 2：运行时局部对拍`
- **机器码**：`48 83 c0 01`
- **汇编文本**：`add rax, 1`
- **Rugra 入口链路**：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`

### 当前可确认的真实结果

基于当前仓库中的最小测试链路，这条样本已经能够完成以下步骤：

1. 反汇编得到单条 `add rax, 1`
2. `X86Lifter` 当前为其生成 `2` 条 raw P-code
3. 第一条 raw P-code 为：
   - opcode = `CPUI_INT_ADD`
   - output = unique 临时 varnode
   - inputs = `rax` 与常量 `1`
4. 第二条 raw P-code 为：
   - opcode = `CPUI_COPY`
   - output = `rax`
   - input = 上一步的 unique 临时 varnode
5. `Funcdata::inject_raw_ops(...)` 后：
   - op 数量为 `2`
   - basic block 数量为 `1`

### 当前失败现象

这条样本当前**尚未通过**最小局部验证。  
按最近一次测试记录，运行时日志中已经出现了两类明确差异：

1. 第一条 op 地址处出现 opcode mismatch：
   - `Opcode mismatch. Ghidra Op: 4`
2. 第二条 op 地址处出现输入比较失败：
   - `Input mismatch at index 0`
   - 当前日志中表现为 unique 输入在空间/偏移比较上与参考侧口径未对齐

对应地，最小测试当前返回失败，而不是 `VerifyResult::Match`。

### 当前最准确的结论

这条样本当前应被描述为：

- `已可运行`
- `已形成失败记录`
- `已暴露算术类 opcode 路径中的局部比较错位`
- `尚未形成局部对拍通过记录`

换句话说：

> `add rax, 1` 已从“计划样本”推进为“真实失败样本记录”，  
> 但当前结果表明 Rugra 侧 lifting 产物、FFI 比较口径或参考数据组织之间仍存在错位，尚不能写成局部 parity 已建立。

### 当前差异分类

建议把这条样本当前归类为：

- `已可运行`
- `已形成真实失败记录`
- `算术类 opcode 已进入最小验证范围`
- `当前存在 opcode 比较错位`
- `当前存在 unique 输入比较错位`
- `尚未形成真实 Ghidra 侧逐字段对拍通过结果`

### 证据来源

- 代码入口：
  - `src/disasm/x86_64.rs`
  - `src/disasm/x86_lift.rs`
  - `src/funcdata.rs`
  - `src/align/runtime_verify.rs`
  - `src/ffi.rs`
- 当前最小样本测试：
  - `src/funcdata.rs` 中新增的 `test_add_rax_imm_minimal_alignment_path`
- 本地测试现象：
  - `Opcode mismatch. Ghidra Op: 4`
  - `Input mismatch at index 0`
  - 最终测试失败

### 下一步最小动作

围绕这条样本，后续最优先的动作应是：

1. 先确认当前 `add rax, 1` 的两条 op 是否就是 Rugra 侧期望的最小表示
2. 继续检查 opcode 比较错位为何表现为 `Ghidra Op: 4`
3. 继续检查 unique 输入在 FFI 比较中的空间 ID / 偏移口径
4. 先把该样本从“失败记录”推进到“局部结构化比较可通过”
5. 再继续推进：
   - `sub rax, 8`

---

## 5. 验证结论的证据来源规则

为了避免把“计划中”“框架存在”“局部观察”写成既成事实，后续更新本文件时，所有高风险验证结论都应尽量附带**证据来源**。  
这里的“证据来源”不是要求写成长篇证明，而是要求让读者能够追溯：

- 该结论依据了哪类文件或结果
- 该结论属于结构层、局部运行时对拍，还是端到端观察
- 该结论是“已验证”“待验证”还是“仅有框架/入口”

### 5.1 哪些结论必须补证据来源
以下类型的表述，后续都应尽量补充证据来源说明：

- “某验证已完成”
- “某行为已与 Ghidra 一致”
- “某项运行时对拍已通过”
- “某条最小样本已形成真实记录”
- “某条样本只达到框架级比较”
- “某个输出质量已提升”
- “某项 FFI 验证已打通”
- “某项差异已定位/已消除”
- “某命令可以稳定复现某结果”

如果暂时无法给出证据来源，应该降级表述为：

- “当前仓库可见代码表明……”
- “已存在相关框架/入口，但尚待实测……”
- “按现有文档与代码判断……”
- “尚缺可复现的运行结果支撑……”

### 5.2 可接受的证据来源类型
可作为验证结论依据的材料包括：

- **源码文件**
  - 例如 `src/align/runtime_verify.rs`
  - 例如 `src/ffi.rs`
  - 例如 `src/align/*.rs`
- **测试**
  - 单元测试
  - 集成测试
  - `cargo test` 的可复现结果
- **示例 / 样本**
  - `examples/` 下的样本运行
  - 指定真实二进制样本的实验记录
- **文档化实验记录**
  - `docs/archive/agentlog/`
  - `docs/experiments/`
  - 未来的差异报告或验证记录
- **人工审阅结果**
  - 仅可用于说明“观察到某现象”
  - 不应冒充自动化运行时一致性验证

### 5.3 推荐写法
后续若需要在本文件中写入验证结论，建议尽量采用类似格式：

- **结论**：当前已存在 SSA 运行时验证框架入口  
  **证据来源**：`src/align/runtime_verify.rs`、`src/ffi.rs`

- **结论**：当前仅能确认静态结构对齐已建立，尚不能确认运行时一致  
  **证据来源**：`src/align/address.rs`、`src/align/varnode.rs`、`ALIGNMENT_PROGRESS.md`

- **结论**：某示例输出在人工审阅下看起来更接近 C 风格  
  **证据来源**：`examples/` 运行结果、对应会话日志、人工审阅记录  
  **说明**：这不等于已完成端到端语义等价验证

### 5.4 不可接受的写法
以下写法在没有明确证据来源时应避免：

- “已经完全验证”
- “已经 100% 一致”
- “所有对拍都已通过”
- “输出已经达到 Ghidra 水平”
- “FFI 已稳定打通”
- “验证体系已完成闭环”

除非同时能指出：

- 对应代码入口
- 可执行路径
- 样本或测试结果
- 差异是否仍存在

### 5.5 最低要求
即使不补完整的“证据来源”小节，后续至少也应做到：

1. 能指出相关代码文件  
2. 能说明属于哪个验证层级  
3. 能明确是“框架存在”还是“结果已验证”  
4. 能区分自动验证与人工观察

---

## 6. `runtime_verify.rs` 应如何被正确描述

当前对 `src/align/runtime_verify.rs` 的正确表述应是：

> 它是一个**运行时验证框架草案/早期实现**，用于承载 Rugra 与外部参考实现之间的行为比对逻辑。  
> 它表明项目正在建设运行时一致性验证能力，并且现在已经具备“比较入口返回结构化状态 -> 调用侧消费状态 -> 统一映射到 `VerifyResult`”这一基础返回路径，  
> 但**并不代表所有验证路径都已打通，也不代表这些验证已被持续执行**。

换句话说，它可以被描述为：

- 已存在的验证基础设施
- 正在建设的比对框架
- 已开始具备结构化返回路径的局部验证入口
- 后续对拍工作的入口

但**不应被描述为**：

- 已完成的完整验证系统
- 已证明一致性的证据本身
- 已投入稳定生产使用的验证平台

---

## 6. 当前文档允许使用的表述

为了修复文档失真，后续文档和日志请尽量使用下面这类表述。

### 推荐表述
- “已实现静态结构对齐的部分测试”
- “已建立运行时验证框架”
- “尚未完成 Ghidra FFI 的稳定集成验证”
- “当前不能宣称与 Ghidra 100% 一致”
- “已具备对拍方向，但仍缺少稳定的端到端结果”
- “按当前仓库可见状态，运行时一致性仍待验证”

### 禁止或不推荐表述
- “已保障一致性”
- “与 Ghidra 完全一致”
- “运行时验证已完成”
- “端到端输出已完成对拍”
- “SSA 已确认 100% 一致”
- “所有验证能力已具备并可稳定运行”

---

## 7. 已知风险区域

在没有完整运行时验证前，以下区域都应被视为高风险区。

### 7.1 P-code 生成
风险点：

- 单条指令的 P-code 序列可能与 Ghidra 不同
- 临时变量 / unique 空间策略可能不同
- 部分架构语义边界条件可能未覆盖

### 7.2 SSA 构建
风险点：

- Phi 节点放置位置
- 变量重命名顺序
- 版本号分配
- 某些边界控制流下的合流处理

这是高优先级风险，因为一旦偏离，会影响后续大量分析结果。

### 7.3 CFG 结构恢复
风险点：

- 基本块划分
- 边关系
- 支配关系
- 循环识别

CFG 偏差会进一步放大到 SSA、变量恢复与控制流结构化。

### 7.4 类型传播与变量恢复
风险点：

- 类型传播方向不稳定
- 对调用约定的理解不充分
- 栈变量/寄存器变量恢复策略偏差
- 高层变量合并不足

### 7.5 最终输出层
风险点：

- 结构化程度不足
- 命名质量不稳定
- 局部语义正确但全局可读性差
- 与 Ghidra 输出风格差异很大

---

## 8. 推荐的近期验证里程碑

为了让验证体系真正走向可信，建议近期按以下顺序推进。

### Milestone 1：清理文档失真
先统一修正文档中的夸大结论，确保所有地方都承认：

- 运行时验证未完成
- 端到端一致性未证明
- 当前结论以真实代码和测试为准

### Milestone 2：固定一组最小验证样本
选择少量、稳定、可重复的目标：

- 简单算术函数
- 分支函数
- 循环函数
- 简单调用函数

针对这些样本建立最小对拍集合。

### Milestone 3：让运行时验证至少覆盖一个真实闭环
先打通一个最小闭环，例如：

- 常量求值对拍  
或
- 单条指令 P-code 对拍  
或
- 小函数 SSA 对拍

当前最小 `mov rbx, rax` 样本已经把闭环推进到“结构化 FFI 返回路径已建立”的阶段；后续真正要补齐的，是让该返回路径接入独立参考侧数据，并沉淀出可复核的差异分类。  
同时，`add rax, 1` 已经进入“真实失败样本记录”阶段，这说明最小闭环不再只是停留在单一 `mov` 指令，而是已经开始暴露算术类 opcode 的实际差异点。  
只要有一个闭环真实跑通，就比泛泛而谈“全部都在做”更可信。

### Milestone 4：沉淀差异报告格式
当出现不一致时，需要明确记录：

- 测试对象
- 地址/函数
- Rugra 输出
- 参考输出
- 差异类别
- 初步原因判断

### Milestone 5：再谈端到端样本验证
在局部行为没有验证清楚前，不应过早把主要精力放在“大样本最终输出比较”上。

---

## 9. 与其他文档的关系

本文件应与以下文档保持一致：

- `CURRENT_STATUS.md`
- `ALIGNMENT_PROGRESS.md`
- `GAP_ANALYSIS.md`
- `docs/TODO_BOARD.md`
- `docs/PROJECT_STRUCTURE.md`

同步原则：

- 如果本文件说“运行时验证未完成”，其他总控文档不能再写“已保障一致性”
- 如果本文件说“CLI 当前不可作为稳定对拍入口”，其他文档不能把 CLI 写成完整可用产品
- 如果本文件说“端到端对拍未完成”，状态文档不能写成“已完成 Ghidra 质量对齐”

---

## 10. 当前结论

截至当前仓库可见状态，Rugra 的验证工作应当被准确描述为：

- **静态对齐：已有一部分基础**
- **运行时验证：已有框架，但未完成**
- **FFI 对拍：有方向与接口，但未形成可信闭环**
- **端到端一致性：尚未证明**
- **最终质量结论：应保持审慎，不可夸大**

因此，当前最准确的总述是：

> Rugra 已经开始建设面向 Ghidra 的多层验证体系，但现阶段仍处于“结构层已有进展、运行时与端到端层面尚未完成”的状态。任何关于“已完全对齐”或“已保障一致性”的表述都应视为失真，后续文档与日志应统一回到这一真实基线之上。

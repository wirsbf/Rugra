# 增强轨总体架构（ENHANCED_TRACK_ARCH_2026-09-26）

> 日期 2026-09-26 | 车道 ENHARCH（docs-only 设计票，worktree enharch，零 src 零 tools）
> 任务：把四份研究合成一张图纸——增强轨（Phase 4）总体架构，含用户提出的 PRINTIR 第二输出面设计。
>
> **输入研究**（本文所有结论性引用的出处锚点，标注约定 `[DECBENCH §x]` / `[RELIT §x]` / `[PCODEIR §x]` / `[LEDGER 波次账本]` / `[ROADMAP §x]`）：
> ① `/dev/shm/rugra-reports/LANE_DECBENCH_2026-09-26.md`（参赛协议/差距/Stage 0-4）
> ② `/dev/shm/rugra-reports/LANE_RELIT_2026-09-26.md`（杠杆地图/首推三件）
> ③ `/dev/shm/rugra-reports/LANE_PCODEIR_2026-09-26.md`（三可偷件/两裁决）
> ④ `.slim/deepwork/stage-bisect-e2e.md` 尾部（IR 收敛纲领/PRINTIR 构想/双脸架构讨论）+ `docs/alignment_docs/RUGRA_MASTER_ROADMAP_2026-09-26.md`
>
> **地位**：本文件是增强轨的**架构图纸**（非状态账本）。组件状态以 `docs/TODO_BOARD.md` 增强轨票池为准；模块对齐状态以 `ALIGNMENT_ROADMAP.md` 为准；跨 wave 排程以总路线图为纲、本文件 §六为其 Phase 4 展开层。
>
> **增强域纪律声明**（随 SAILR-PORT 立项先例，[LEDGER 2026-09-26]）：增强轨组件**没有锁定 oracle 对照物**——Ghidra 12.0.4 是我们默认脸的 oracle，不是增强脸的天花板。增强层代码的注解走 `// ENHANCEMENT: <来源引用>`（SAILR/angr/Patchestry/Ghidrall/TRex 等），**不适用** `// Ghidra:` 对齐纪律；票面显式声明 ENHANCEMENT 域。默认脸（主管线）的一切对齐铁律不变。

---

## 〇、执行摘要（一张图）

**第一性原理**：反编译质量 = 重建表示向语义 IR 的收敛度。Rugra 有两张脸、两个 oracle：
**默认脸**收敛于锁定 oracle（Ghidra 12.0.4，逐函数字节恒等，canon/fixture 门禁锁定）；
**增强脸**收敛于源码语义结构（超越 Ghidra 位置，以 DecBench 三指标 + 行为门禁度量）。
两脸共用同一套反编译器基座与恢复层，增强组件全部走可配置路径（env 门控 + 独立发射面 + 末端逐函数择优），默认脸代码路径零改动。

**组件总账**（§三有逐件输入输出与依赖序）：

| ID | 组件 | 角色 | 状态 | 工作量级 |
|---|---|---|---|---|
| C1 | IRFIX-CONTRACT-0001 | 统一输入契约（printc 前 IR 的序列化投影，Patchestry schema 适配） | 设计（本文件 §二） | 小–中（emitter 已有 80% 字段） |
| C2 | SAILR-PHASE2-SEAM-0001 | SAILR 结构化层（GED 主杠杆，kuna 同族 28.45→39.05） | **在飞**（SAILR-PORT Phase 1） | Phase 1 2-4 车道日；全链 10-20 车道日 [LEDGER] |
| C3 | GEP-RECON-0001 | GEP 重建层（Ghidrall 单 struct 帧形态参照） | 设计（未来件） | 中 |
| C4 | IRCONV-PASSMENU-0001 | SSA 规范化 pass（LLVM pass 菜单映射，option-gated） | 设计（清单已就绪 [PCODEIR §四-④]） | 每 pass 小；菜单零成本 |
| C5 | PRINTIR-RENDERER-0001 | .ll 文本渲染器（用户构想落地，第二输出面） | 设计（本文件 §四） | 中（一次性 emitter） |
| C6 | BEHAVIOR-SIDECAR-0001 | Pcode2C 确定性行为差分 sidecar（三重门禁行为验收层） | 设计 | 中 |
| C7a | STRIDE-SIDECAR-0001 | STRIDE n-gram 类型/命名 sidecar（ML 层最小管道） | 设计（未来件） | 小 [RELIT §三] |
| C7b | TRex-TYPE-SOCKET-0001 | TRex 式确定性类型重构插座（type_match 主杠杆） | 设计（未来件，artifact 深挖前置） | 中–大 |
| C8 | ERASE-DEINLINE-0001 | 反内联 outlining（O2/O2noinline 切片新杠杆） | 设计（未来件） | 中–高 |
| C9 | SEL-TRIPLEGATE-0001 | 三重门禁 best-of-N 选择器（Union>41.06 胜负手） | 设计 | 中 |

**排程主线**（§六）：MB18 落地 → {M1 契约 emitter ∥ M2 Stage 0 runner（DECBENCH WP1，独立车道）} → M3 SAILR Phase 2 缝 + 增强脸首跑（最低组件集）→ M4 PRINTIR v1 → M5 三重门禁选择器闭环（本地记分板）→ M6 类型层（STRIDE→TRex）→ M7 Stage 4 冲榜（rugra-enhanced Union>41.06 且 type_match>7.56）。

---

## 一、第一性原理与双脸纪律

### 1.1 质量 = 收敛度：两个 oracle 的分层

反编译的输出质量不是绝对属性，而是**重建表示与语义 IR 之间的距离**。距离的度量物（oracle）决定了一切工程纪律：

- **默认脸的 oracle = 锁定 Ghidra 12.0.4（commit e40ed130）**。收敛判据已机制化：五语料 canon 差分（curl 200/0/0、httpd 229/0/0 [MB17 集成态；sleighp3 换装 +82 行归因在 MB18 处理]）、五面镜面棘轮、391 项 B2 fixture bank、逐函数 stage 对拍（next_url/match_url/getparameter 全函数 MATCH 族 [LEDGER]）。这条收敛线 = 总路线图 Phase 0，**与 DecBench GED 分数同一条战线**（逐函数≈Ghidra 的收敛度直接兑换 GED perfect [DECBENCH §2.5]）。
- **增强脸的 oracle = 源码语义结构**。锁定 Ghidra 自身在 DecBench 上只有 Union 32.26 / GED 28.45 / type_match 7.56 / byte_match 4.52 [DECBENCH §1.6，snapshot 2026-09-23T19:00]——**71.5% 的函数连 Ghidra 都不结构完美**。增强脸的收敛判据是外部度量：GED（Joern CFG 同构）、type_match（DWARF 三段对应）、byte_match（重编译归一化汇编 diff）、以及行为等价（Decompile-Diverge 式同输入比对 [RELIT §E]）。

**推论**：默认脸收敛是增强脸的地基而非竞争对手。Ghidra 残差（我们逐函数对拍钉出的每个分歧）在 GED 口径下同样是分数损失；增强轨的每个组件都在默认脸无法到达的位置工作——SAILR 处理 Ghidra 结构化的 irreducible 回退盲区，类型层处理 Ghidra type_match 7.56% 的天花板，选择器处理"单一确定性管线永远无法逐函数最优"的组合问题。

### 1.2 边界定义：什么属于哪张脸

| 维度 | 默认脸 | 增强脸 |
|---|---|---|
| 代码路径 | 主管线（SLEIGH→pcode→SSA/Heritage→结构化→varmap→printc） | 管线之上的**纯增量层**：新模块（src/sailr/ 模式）+ 发射面 + 选择器 |
| oracle | 锁定 Ghidra 12.0.4，逐函数同输入同输出（铁律 2.1） | 源码语义（DecBench 指标 + 行为门禁），无 Ghidra 义务 |
| 注解纪律 | `// Ghidra: file:line fn`（机制 E 强制） | `// ENHANCEMENT: <SAILR/angr/Patchestry/Ghidrall/TRex 引用>`（SAILR-PORT 先例 [LEDGER]） |
| 门禁 | canon 差分/镜面棘轮/B2 bank/stage 对拍 | 三重门禁选择器（§三 C9）+ DecBench 本地记分板 + 行为 sidecar |
| 开关 | 常开（无开关即正典） | **env 门控默认关**（存在性开关，MIRROR 先例形态 [LEDGER F-4]） |
| 输出面 | printc 的 C 文本（canon 口径） | 增强候选 C 文本 + .ll 第二输出面（PRINTIR）+ 双列记分（rugra-default / rugra-enhanced） |

### 1.3 互不污染机制（五条，全部有先例承载）

1. **env 门控默认关**：增强组件的调用点一律由环境变量存在性开关守卫（`RUGRA_ENHANCED=1` 族，模式复用 `RUGRA_MIRROR`/`RUGRA_GEN_MIRROR` 的存在性开关语义 [LEDGER CR-TRIGFACE F-4 / VERIFICATION_GUIDE 规程]）。canon 门禁运行前显式 unset 全部增强变量（同 MIRROR 三变量卫生规程）。
2. **纯增量写域**：增强层新代码只允许新模块 + examples 发射驱动 + 管线**末端挂钩**（post-recovery 的观察/变换/发射），默认路径的函数行为零变化；每次增强合并后 canon 双语料 + 镜面五面 + bank 全绿为验收（与 SLEIGH 换装合并同款纪律 [LEDGER MB17]）。
3. **恢复层 100% 复用**：增强脸不重建恢复层——SSA/Heritage/结构化/varmap 全部来自默认脸的完成态（printc 前的 IR 即增强脸输入面，[PCODEIR §三] 校验结论：我们的输入比 Ghidrall 的切点还靠后一层，其调用约定/栈恢复我们已由 fspec/varmap 域完成对齐）。这条同时是效率纪律（不重复实现）与隔离纪律（增强层永远看不到未收敛的中间态）。
4. **逐函数择优兜底**：选择器（C9）按函数在默认候选与 N 个增强候选间挑选；默认候选永远在场且恒为 oracle 字节恒等输出——**增强层最坏情况的回退 = 默认脸**，不存在"增强层故障拖垮整体"的通道。这与总路线图 Phase 4 的"默认路径永远 oracle 字节恒等，增强按函数择优"判据 [ROADMAP §Phase 4] 一致。
5. **记分双列**：对外与内部评估一律 rugra-default + rugra-enhanced 双列 [DECBENCH §五 Stage 4]——默认列的对齐叙事（逐函数 vs Ghidra diff=0 自证 [DECBENCH §四-2]）与增强列的分数叙事永不混算，防止增强收益污染对齐声明。

### 1.4 为什么双脸而不是单脸加参数

Ghidra 的 Options 体系证明"单脸加参数"最终会遇到参数间耦合（kuna 的 aggressive 脸要 21 个 option override 才稳定复现 [DECBENCH §1.7]）。我们的双脸把耦合面收敛到三个位置：输入契约（C1，统一投影）、发射面（printc/printir 并行渲染器）、选择器（C9，唯一决策点）。中间的一切增强 pass 都是契约到契约的纯函数，可独立 fixture 化、独立差分、独立回退。

---

## 二、统一输入契约（C1 · IRFIX-CONTRACT-0001）

> 可偷件① [PCODEIR §四-①]：Patchestry JSON schema → 我们高层 pcode 的序列化契约。
> 设计裁决 [PCODEIR §六-1]：SAILR/TRex/STRIDE/行为 harness 全部吃同一契约，避免每个增强件各自发明导出。
> 边界 [PCODEIR §四-① 注意]：作为既有投影格式的**增强面**而非替代——身份键协议（oracle commit/指纹）必须保留。

### 2.1 切点与形态

**切点 = printc 前的 IR 完成态**（SSA 完成 + varmap 完成 + 结构化完成、发射前）。该切点有两个独立先例背书：Ghidrall 的 "Decompilation Data Structures"（反编译器内部数据结构、伪 C 发射前的状态）与 Patchestry 的 DecompInterface simplificationStyle="decompile" + PcodeOpAST 选的是**同一个切点** [PCODEIR §〇-3/§一]。我们的切点比两者都靠后（他们还要自己做调用约定修复与栈恢复，我们的 fspec/varmap 域已完成 [PCODEIR §二-b]）——**站在两个先例的肩上且起点更高**。

**载体 = 既有 stage 投影格式（v1.2.2）的增强面**：
- 底层语法与身份键沿用 `STAGE_BISECT_SPEC_1204.md`（META 身份键五要素：oracle_commit/arch/cspec/analysis_options/binary_sha256+func_entry/load_mode/producer/unique_base；op-line `<addr:time> <OPC> d= out= in=`；vn 描述符 c:/n:/u:/s:/f:/o:）。drillfmt/drillobserve emitter 基建已有该格式 80% 字段 [PCODEIR §四-①]。
- 增强面新增 Patchestry 式**结构元数据块**（§2.2），补齐 switch/branch/DECLARE 三族。

**关键差异（我们比 Patchestry 强的两处，契约须如实表达而非抹平）**：
1. **我们保留 SSA**：Patchestry 在序列化器里做 de-SSA 挖矿（MULTIEQUAL/COPY/INDIRECT 坍缩回命名变量 [PCODEIR §一-B]）；我们的契约**原样携带 MULTIEQUAL**（phi 语义显式），消费端（SAILR/TRex/printir）自行决定是否坍缩。理由：SSA 零重建是三个先行工作都做不到的位置 [PCODEIR §两裁决-2]，契约层面保留它让增强层免费获得最强形态；坍缩是单向门，保留是双向门。
2. **我们的 SeqNum 双段 (addr,time) 是原生正典**（address.cc:32-38 语义，stage 投影 v1.1 已钉死），比 Patchestry 的 `ram:ADDR:N:1` 单段引用多一个时间维度——消费端引用 op 时直接用投影既有语法。

### 2.2 字段设计（Patchestry schema 适配 + 字段缺口清单）

以 Patchestry fixture 亲解剖的字段表 [PCODEIR §一-B JSON schema 节] 为蓝本，逐族对照：

| 字段族 | Patchestry 形态 | 我们的适配 | 缺口/差异处理 |
|---|---|---|---|
| 顶层 | `{architecture, id, format, functions(按地址键), globals, types}` | 沿用 + META 身份键五要素入 header（Patchestry 无身份键——**它不需要对拍，我们需要**；v1.2.2 已有） | 无缺口 |
| 函数 | `{name, is_intrinsic, type{return,parameter_types→类型表}, basic_blocks(键 ram:ADDR:N:basic), entry_block}` | 同构；name 取 varmap 完成态符号 | is_intrinsic 语义对齐我们的 intrinsic 通道（小） |
| 块 | `{operations(pN→op), **ordered_operations(显式序)**}` | **已有**（op-line 的 beginAll/optree 迭代序即显式序，两侧同源已核实 [SPEC v1.1]） | 无缺口 |
| 值引用 | 定义点 SeqNum（`ram:0800f28a:66:1`） | **已有**（`addr:time` 双段） | 格式差异：单段 vs 双段，消费端 adapter 一行 |
| op | `{mnemonic, type, size, inputs:[{type,kind,operation/…}]}`，kind ∈ parameter/constant/temporary/local/global/function | inputs kind 枚举照搬（消费端分派键）；mnemonic=get_opname 74 名表（v1.2.1 闭集 [LEDGER]） | 无缺口（v1.2.1 勘误的四槽 quirk 直发已在 punch list 落地） |
| CBRANCH | `taken_block/not_taken_block` | **新增**（块 ID 对引用，投影格式此前无需块级控制流） | 缺口①：块出边表 |
| switch 三路 | `switch_input/switch_cases/fallback` 元数据；三路恢复=JumpTable 权威→symbol/INT_EQUAL 启发→失败诚实省略 [PCODEIR §一-B] | **新增**：switch_cases 元数据块（来源=我们 jumptable.rs 权威结果 + SwitchNorm 形态；第三路"失败省略"语义照搬——契约如实省略，让消费端兜底，交叉验证策略 [PCODEIR §四-⑥]） | 缺口②：switch 元数据发射 |
| 伪指令族 | `DECLARE_PARAMETER/DECLARE_LOCAL/DECLARE_TEMPORARY + ADDRESS_OF + LZCOUNT/TAIL_CALL` | **新增**：DECLARE_* 族从 varmap 完成态投影（参数/局部/临时三分类我们有权威数据）；ADDRESS_OF 由 PTRSUB/PTRADD 语义承载（P-code 无取址 op 是 Ghidra 的表示事实，Patchestry 自加伪指令解决消费端歧义——同款处理） | 缺口③：DECLARE 投影器 |
| CALL | `target{function 地址, is_variadic, is_noreturn} + has_return_value` | **已有 90%**（fspec 域 FuncCallSpecs 完成态即数据源；CALLSPEC/FUNCProto 域已对齐） | 缺口④：序列化字段补齐（小） |
| 类型表 | `{name, size, kind=integer/undefined/composite/enum}` | 沿用；composite/enum 从 type_system 完成态投影 | 无缺口（datatype print_raw 域已有 fixture） |
| SSA（差异面） | 无（已 de-SSA） | **我们保留 MULTIEQUAL 原样**（§2.1） | 非缺口，是增强 |
| 帧表示 | LocalSymbolMap（命名局部） | 见 C3（GEP 层的帧 overlay 是契约的可选附加块） | 缺口⑤：帧 overlay 块（随 C3 设计，v1 可缺省） |

**缺口总账**：五处（①块出边表 ②switch 元数据 ③DECLARE 投影器 ④CALL 字段补齐 ⑤帧 overlay 可选块），全部是投影 emitter 侧的增量发射，无引擎改动。估 1-2 车道周（emitter 模式、身份键、op-line 序全部现成）。

### 2.3 三消费者共用协议

```
默认脸管线完成态（printc 前 IR）
        │ env 门控发射（RUGRA_IRFIX=1 族）
        ▼
┌─ IRFIX 投影（JSON/文本双形态，同一数据源）─┐
│  header: v1.2.2 身份键 + format=irfix-1   │
│  ops: op-line 族（含 MULTIEQUAL 原样）     │
│  增强块: 块出边/switch/DECLARE/CALL/类型表 │
└──┬──────────────┬──────────────┬─────────┘
   │              │              │
 SAILR 层       TRex/STRIDE    行为 harness /
（结构化变体）  （类型 overlay） PRINTIR（.ll 发射）
```

- **双形态**：文本形态（stage 投影同族，diff 友好，供 fixture/差分）+ JSON 形态（结构化消费，SAILR/TRex 的机器接口）。同一 emitter 一次遍历双写，禁止双实现。
- **fixture 纪律**：投影本身可双侧化（oracle harness 侧同切点导出=未来 TRex 层的行为对照面；但**增强层组件的验收不依赖 oracle 对照**——它们以 DecBench 记分板与门禁为准，ENHANCEMENT 域）。契约版本化 `format=irfix-1`，字段变更走版本号，消费端 fail-close。
- **与 Stage 0 的关系**：契约不是 DecBench 参赛前置（GED/byte_match 只吃 C 文本 [DECBENCH §2.2]），它是增强组件的内部接口——排程上与 Stage 0 runner 并行不阻塞。

---

## 三、分层组件图（输入/输出/依赖序/工作量）

### 3.1 总图（依赖序从下往上）

```
L4 末端决策   ┌────────────────────────────────────────────┐
              │ C9 三重门禁 best-of-N 选择器                 │
              │ in: {默认候选} ∪ {N 个增强候选}（各=完整 C 文本+IR投影）
              │    + 门禁器（汇编 diff / arity / SMT 调用序列 / 行为差分）
              │ out: 逐函数择优结果（默认脸恒为可用回退）      │
              └───────────────▲────────────────────────────┘
                              │ 候选供给
L3 增强变换   ┌───────────────┴────────────────────────────┐
              │ C2 SAILR 结构化（GED）  C3 GEP 重建（帧形态）│
              │ C4 SSA 规范化 pass 菜单（option-gated 变体） │
              │ C7 类型层（STRIDE→TRex 插座） C8 ERASE 反内联│
              │ in/out: 契约→契约（纯函数式变换，逐件独立 fixture）│
              └───────────────▲────────────────────────────┘
                              │
L2 接口       ┌───────────────┴────────────────────────────┐
              │ C1 IRFIX 统一输入契约（§二）                  │
              │ C5 PRINTIR .ll 渲染器（第二输出面，§四）       │
              └───────────────▲────────────────────────────┘
                              │ printc 前 IR 完成态（恢复层 100% 复用）
L1 基座       ┌───────────────┴────────────────────────────┐
              │ 默认脸主管线（冻结：canon/镜面/bank/stage 门禁）│
              │ + C6 BEHAVIOR-SIDECAR（raw pcode 直达，旁路） │
              └────────────────────────────────────────────┘
```

依赖序：L1 全部现成 → C1/C5/C6 可并行开工（C6 只依赖 raw pcode，连 C1 都不需要）→ C2（Phase 1 在飞）缝接 C1 → C3/C4/C7/C8 依次上插座 → C9 收口。**关键路径 = C1 → C2 缝 → C9**（增强脸首跑的最小组件集，§6.2）。

### 3.2 逐组件规格

**C2 · SAILR 结构化层（SAILR-PHASE2-SEAM-0001，在飞）**
- **语义源**：angr 原版 SAILR（学术+实证最强：kuna 实测同族增益 GED 28.45→39.05 [DECBENCH §1.6/RELIT §2.1]）；**参照实现**：kuna p7_regions（Rust 9 文件 7.3K 行）；**设计输入**：Behner SoK（Euro S&P'25）选型判据 + SAILR"合法 goto"原则 [RELIT §一-A]。
- **输入**：C1 契约（结构化完成态的块/出边/switch 元数据——SAILR 的 RegionIdentifier 消费 CFG 图）。
- **输出**：结构化变体候选（增强脸 C 文本之一）。三档 option-gated：reducible 恒等 / irreducible 回退增强 / edge 排序 [ROADMAP §Phase 4]。
- **Phase 2 缝设计**（本票核心）：SAILR 的图模型（angr CFG/Region 图抽象）与我们 Funcdata/BlockGraph 的适配缝——**这是本组件最大未知数**（§七）。缝的原则：SAILR 层吃契约投影、产契约投影（或直接产结构化块树），不回写默认脸的 Block 结构；Phase 1 已按"新模块纯加法"落地 src/sailr/（零管线接入）[LEDGER SAILR-PORT]。
- **量级**：Phase 1 2-4 车道日（在飞）；全链 10-20 车道日出可跑增强脸 [LEDGER]。

**C3 · GEP 重建层（GEP-RECON-0001，未来件）**
- **参照形态**：Ghidrall 单 struct 栈策略——一个 LLVM struct（padding 填缝保持相对索引）+ GEP 字段访问；**文献唯一有 A/B 实测排序的选项**：单 struct+GEP 86.08% > 朴素 per-var alloca 83.16% > 字节数组 82.99% [PCODEIR §四-②]。
- **正典路径不动声明**：默认脸维持 Ghidra 原生 varmap（RangeHint 域，对齐铁律）；单 struct 仅作为**增强脸/LLVM 发射脸的帧表示**与类型层 overlay 落点 [PCODEIR §四-② 边界]。
- **输入**：C1 契约（含 DECLARE_LOCAL 族）+ varmap RangeHint 数据（只读）。
- **输出**：帧 overlay 块（契约 §2.2 缺口⑤）——栈/帧对象表示为 struct+字段引用；.ll 发射与 TRex 类型替换共用的落点形态。
- **量级**：中。触发时机：C5 PRINTIR 需要帧表示时（.ll 中地址逃逸的局部必须 alloca/struct 化）或 TRex 层进场时——两者谁先到谁触发。

**C4 · SSA 规范化 pass 菜单（IRCONV-PASSMENU-0001）**
- **菜单（零成本清单，已由 PCODEIR §四-④ 给出映射）**：mem2reg↔SSA 规范化（我们已有 heritage SSA，此 pass 在增强脸用于"坍缩-再规整"的变体生成）/ SROA↔栈槽去物化（restart 语义已做 [GENWIRE 证据]）/ SCCP↔常量传播 / instcombine↔表达式规范化 / GVN↔公共子表达式 / ADCE↔死代码。
- **纪律**：**不引入 LLVM 依赖**——按 pass 语义逐个映射到我们自有 IR 变换 [PCODEIR §五-3]；每个增强 pass 标注"对应 LLVM pass + 在我们 IR 上的等价变换 + option-gated 开关" [PCODEIR §六-4]。
- **输入/输出**：契约→契约；每个 pass 独立开关，组合即 best-of-N 的候选变体生成器（与 dewolf congruence/pointer-transform 作候选变体的思路同位 [RELIT §2.1 候选③]，但注意 dewolf 自己 GED 3.65% 的反证——这些 pass **只做候选不做主张**，成败由 C9 门禁裁决）。
- **量级**：菜单登记零成本；每 pass 实现小；Ghidrall 实证"内存形态+O 级链可达 86% 功能保持"是收益上限参照 [PCODEIR §二-c]。

**C7a · STRIDE n-gram sidecar（STRIDE-SIDECAR-0001，未来件）**
- ML 类型/命名层的**最小可行起步**：n-gram 纯文本匹配预测变量名+类型，开源、无 GPU、与 DIRTY 竞争力但开销小两个数量级 [RELIT §一-B]。先把管道/验证/门禁打通，为 DRAGON/TyGr 置换留插座 [RELIT §三-3]。
- 输入：C1 契约（变量类型/用法上下文的文本面）+ 语料库（ExeBench/Debian 包源 [RELIT §一-D]）；输出：类型/命名 overlay 候选（经 C9 门禁后才生效）。
- 量级：小（1-2 周，数据库构建+匹配器 [RELIT §三]）。

**C7b · TRex 类型插座（TRex-TYPE-SOCKET-0001，未来件，深挖前置）**
- **RELIT 首推①**：演绎式（deductive）类型重构，行为捕获型类型，123/125 二进制胜 Ghidra（论文自报）、artifact 三徽章（Available/Functional/Reproduced）[RELIT §一-B]。type_match 全场洼地（binja 8.83 > ghidra 7.56 > kuna 6.91，LLM 榜首 9.27 已证上限）[RELIT §2.2]；kuna roadmap #261 零 ML/推断计划=护城河③ [RELIT §2.2/Academic]。
- **插座设计**：本票只建插座不建引擎——C1 契约的类型表/变量面 + overlay 应用通道（类型替换经**重编译验证**才生效 [ROADMAP §Phase 4 类型层 gated+重编译验证]）+ B2 式 fixture 承接位。引擎本体（artifact 深挖→移植形态裁决→实现）是独立后续票；确定性演绎与我们的门禁哲学同构（无幻觉、可差分、可进 fixture [RELIT §三-1]）。
- **前置**：TRex artifact 深挖（实现语言/输入格式/依赖——RELIT 与 PCODEIR 均标"需深挖"，诚实边界见 §七）。
- 量级：插座小；引擎中–大。

**C8 · ERASE 反内联（ERASE-DEINLINE-0001，未来件）**
- RELIT 新发现的 O2 杠杆（ACADEMIC_SURVEY 遗漏）：识别内联进调用者体的库函数体并恢复为函数调用（de-inlining/outlining）——DecBench 的 O2/O2-noinline 切片正是内联重灾区，源码有调用、内联后消失，恢复调用=结构向源码靠拢 [RELIT §一-A/§2.1 候选①]。
- **落地次序**：规则半边先行（DREAM++ outlining / FuncRE 规则版——无 LLM），LLM+符号执行半边只做增强轨可选 pass 且永远过 C9 门禁 [RELIT §一-A DREAM++ 行]；先在 O2-noinline 切片试点 [RELIT §一-A ERASE 行]。
- 输入：C1 契约 + 库函数签名台账（我们 LibcSignatureTable/IMPORTSIG 通道天然汇流 [PCODEIR §四-⑤]）；输出：调用边界恢复变体（best-of-N 候选之一）。
- 量级：中–高；GED 收益是机理推论非论文实测（诚实边界 §七）。

---

## 四、PRINTIR 渲染器设计（C5 · PRINTIR-RENDERER-0001，用户构想落地）

> 构想出处 [LEDGER 2026-09-26]：用户提出 LLVM/GCC IR 作为反编译**第二输出面**；用途五件（分析生态直通车/IR 级差分面对齐仪器/机器消费面/语义验证闭环/重优化闭环）；实现形态=printc 旁加 printir 渲染器（恢复层 100% 复用）；设计票排 PCODEIR 精读交付后——即本节。

### 4.1 形态裁决：.ll 文本导出（MLIR 降为备选）

- **主形态 = LLVM .ll 文本**。依据 [PCODEIR §五-3 重估结论]：①MLIR 负先例——Patchestry（该方向经费最充足的团队，ToB+ARPA-H）的 pcode MLIR 方言是遗迹（~20% op 覆盖、无类型安全、无 lowering、仅自引用），生产路径改押 ClangIR；②Rust 侧无生产级 MLIR 绑定（melior 不足以承载方言开发），进程内 MLIR 需 C++ FFI+LLVM 构建链，与纯 Rust 构建链方向冲突；③"若增强轨需要 LLVM 生态消费者，最便宜路径=从高层 pcode 直接发 .ll 文本——绕过方言开发与 FFI，一次性 emitter 工作量"。
- **发射规范现成**：Ghidrall 映射表 3.3.1/4.3.1 即逐 op 发射规范（COPY/LOAD/STORE/BRANCH/CBRANCH/CALL/RETURN/INT_*→icmp/PTRSUB→gep 等）[PCODEIR §一-A2/§五-3]。
- **备选保留**：若未来出现 .ll 表达不了的语义（MULTIEQUAL 显式化等），先发 LLVM dialect 文本，自定义方言只在"LLVM dialect 表达不了"时再议 [PCODEIR §五-3]。GCC IR（GIMPLE/RTL）不排期——LLVM 生态（opt/llvm-diff/KLEE/SeaHorn）消费者覆盖我们的五件用途，双基座无增量收益。

### 4.2 我们与 Ghidrall 的关键差异：SSA 直发

Ghidrall 发射**内存形态** IR（寄存器=全局变量、局部=alloca、输出零 phi），把 SSA 构造甩给 LLVM mem2reg [PCODEIR §两裁决-2]。我们的 heritage SSA 严格更强——**printir 直发 SSA 形态**：
- MULTIEQUAL → `phi` 指令（显式）；
- 寄存器值流 → SSA 值（无全局变量仿真）；
- flags 已被反编译器消化，不存在 [PCODEIR §一-A2]——无需 Ghidra-to-LLVM 的 i1 全局 flags 那套机器仿真；
- CALL 带真参数（我们 fspec 域调用约定完成态；Ghidrall 要自己修复）[PCODEIR §二-a]。
- 地址逃逸/聚合局部 → alloca；**帧表示采用 C3 单 struct 形态**（Ghidrall (b) 实测最优）——这是 C3 的第一触发方。
- 收益：省掉消费端 mem2reg 依赖（.ll 直接可被 opt -verify/llvm-diff 消费）；SSA 形态是"重建表示向语义 IR 收敛"的直接读数（§4.4 用途①）。
- 风险对冲：SSA 直发是设计判断（无先例——三个先行工作全部发内存形态 [PCODEIR §两裁决-2]），故保留 `--emit-ir=mem` 内存形态档位作为兼容备选（Ghidrall 形态，照抄其映射表），消费者假设由验收用例裁决（§七）。

### 4.3 渲染器架构（与 printc 并行）

```
printc 前 IR 完成态（同一对象，零拷贝遍历）
   ├── printc 渲染器（既有）──→ C 文本（默认脸输出面）
   └── printir 渲染器（新） ──→ .ll 文本（第二输出面）
                └── env/CLI 门控（RUGRA_PRINTIR=1 / --emit-ir=ssa|mem）
```

- **平行渲染器**：与 printc 同级的**只读遍历器**（恢复层 100% 复用 [LEDGER 构想]）；不吃 printc 的 RPN/表达式栈（.ll 不需要表达式线性化，直接按 op 语义发射）。
- **吃统一输入契约**：printir 的数据面=C1 契约（§二）——渲染器=契约消费端之一，与 SAILR/TRex 同一接口。这样"增强脸变体的 .ll"与"默认脸的 .ll"天然同构可比（用途①③的机制基础）。
- **发射单元**：函数级（对齐 printc 的 doc_function 文档契约 [HERMITICITY 证据：printc.cc:2641-2676 docFunction 自包含]）；模块级串联（globals/类型表→LLVM 全局/类型定义）。
- **代码位置**：`src/printir.rs`（新模块，纯加法）+ examples 驱动接线；注解走 `// ENHANCEMENT:`（LLVM 语义引用 + Ghidrall 映射表引用）——**printir 无 Ghidra 对照物**（oracle 不发射 .ll），ENHANCEMENT 域。
- **验收形态**：①`opt -verify` 通过率（语法/类型合法性）；②canon 语料 .ll 快照 fixture（确定性：三跑字节恒等）；③SSA 形态与内存形态双档发射的语义一致性抽验（SSA→opt -mem2reg→ 与 mem 档等价）。

### 4.4 三用途优先级（排它性排序）

1. **IR 级差分对拍仪器（最高优先）**——增强轨的观察面刚需：增强 pass（C4）/SAILR 变体（C2）在 C 文本上的 diff 噪音大（printc 线性化放大微小 IR 差异），.ll 是结构化、机器可解析、逐值可寻址的差分面（llvm-diff/逐指令比对）；同时是 A/B 门禁（默认脸 config 变体的中性验证）与 mine/triage 闭环（kuna decbench-loop 方法论 [DECBENCH §1.7] 移植）的仪器。**对拍的两个臂**：Rugra 自身跨 config/跨 pass 变体（主用）；oracle 无 .ll（Ghidra 不发射 IR），跨侧 IR 对拍不是用途（诚实边界——"IR 级差分面对齐仪器"的'对齐'指我们两脸/两配置间的 IR 级收敛测量，非与 Ghidra 对拍）。
2. **机器消费面（次优先）**——SAILR/TRex/STRIDE/harness 的第二接口（JSON 契约为主、.ll 为 LLVM 生态入口）；未来语义验证闭环（KLEE/SeaHorn 类 [PCODEIR §一-B Patchestry 验证配套]）与重优化闭环（opt 链上跑 pass 菜单的等价性参照——注意我们的 pass 实现在自有 IR 上，.ll 是**参照面**不是执行面）。
3. **DecBench IR 侧车（第三优先）**——DecBench 只吃 C 文本 [DECBENCH §2.2]，.ll 不参与得分；作为**自证材料**（对齐自证报告的 IR 级附录：逐函数 .ll 证明结构保真的机读形态）与残差 triage 的钻头（GED 失分函数的 .ll 级归因，比 C 文本 diff 精确到值）。

---

## 五、Pcode2C 确定性行为 sidecar（C6 · BEHAVIOR-SIDECAR-0001）

> 可偷件③ [PCODEIR §四-③]：同一函数发两版 C——我们的反编译 C + pcode2c 式逐字 C，同 harness 同输入跑，diff 行为。
> 承载需求 [RELIT §2.3 强化②]：行为差分验收=Decompile-Diverge（arXiv 2609.05370）的教训落地——LLM 精修把 Ghidra 可编译率 75→90% 的同时行为保持 74→62% [RELIT §〇-3/§E]，**可编译性不是语义门禁**；三重门禁选择器需要行为验收层。

### 5.1 形态（Pcode2C 解释器特化，照抄可偷）

- `CPUState{reg[], unique[], ram[], pc}` 字节数组；每个 pcode op=一个 helper 宏调用（`COPY(dst,8,src,8)` / `INT_LESS(reg+0x200 /*CF*/,1,…)`）；varnode=数组内指针；**控制流=`for(;;) switch(state->pc)` 每指令地址一个 case**；flags=1 字节寄存器 varnode 无特判；常量=复合字面量取址 [PCODEIR §一-C]。
- **非目标声明**（照抄其定位）：逐字 C **不是反编译**（"resulting C has a direct mapping to the original assembly"）——它是行为基准，不进任何输出脸。
- **确定性三件**：非 LLM、可 CI、每次同输出 [PCODEIR §四-③]——与 Decompile-Diverge 的 LLM driver 合成路线相比，便宜、可复现、可进回归。

### 5.2 接线点（raw pcode 原生可得）

**SLEIGH 全 Rust 化已完成**（Phase 0 借用验证→Phase 1 编译器→Phase 2 运行时→Phase 3 iced 退役 [LEDGER]）——raw pcode（逐指令低层 pcode）从锁定 .sla 原生解码，op-for-op 36 面 698,605 decodes / 5.55M p-code ops 零分歧实证 [LEDGER SLEIGHP2]。sidecar 的输入=该 raw pcode 流（**旁路恢复层**：与 C1 契约无关——行为基准必须锚定在指令语义层，不经过任何恢复/变换，这正是它作为"地面真值"的资格）。

```
二进制 ──SLEIGH──→ raw pcode ──C6 逐字发射──→ 基准 C ─┐
                                                        ├─ 同 harness 同输入 ─→ 行为 diff（门禁裁决）
反编译 C 文本（默认或增强候选）── gcc 编译 ────────────┘
```

### 5.3 门禁角色与语料

- **角色**：C9 三重门禁的第三道（行为验收层）+ 增强组件（C4 pass/C2 变体/C7 类型 overlay/C8 outlining）的语义回归信号。CBMC 有界（unwind）性质决定它是**回归信号不是完备证明**——按其博客哲学用作"fuzz+BMC 双通道"进 CI 而非终审 [PCODEIR §四-③ 注意]。
- **harness 语料来源**（优先序）：①DecompileBench（ACL'25）OSS-Fuzz 语料自带 fuzzing harness=现成弹药 [RELIT §一-D]；②Cao et al. Dsmith 内嵌 checksum 的免重编译符号比对（ARM/PE byte_match abstain 切片的兜底同源 [RELIT §一-D]）；③自建最小 harness（每函数从 .ll/C 签名合成 driver——Decompile-Diverge 方法论 [RELIT §E]）。
- **量级**：中（emitter=helper 宏表+逐 op 展开，我们 op 语义表/opbehavior 域全在；harness 管道=编译执行比对三步）。

---

## 六、排程与里程碑

### 6.1 与 Stage 0 的汇合（外部参照系先行）

Stage 0（DECBENCH WP1+WP3：runner CLI + 本地 decbench + sailr x86-64 O0 首跑 + `-d rugra -d ghidra` 双列自证报告）已排在 MB18 后（examples/bin 域被 dualsleigh 待并持有 [LEDGER DECBENCH/WP1]）。**汇合关系**：
- Stage 0 是增强轨的**记分板与残差池**（GED 失分函数→mine/triage→增强组件的靶点清单；WP4 对拍改进闭环 [DECBENCH §三]）——增强组件的收益裁决全部在 Stage 0 的本地跑分台上进行。
- Stage 0 不依赖增强轨任何组件（GED/byte_match 只吃 C 文本 [DECBENCH §2.2]）；增强轨 M1（契约）也不依赖 Stage 0——**两线并行，在 M3（增强脸首跑）汇合**（SAILR 调参阶段与 Stage 0 汇合 [LEDGER SAILR-PORT 排程]）。

### 6.2 增强脸首跑的最低组件集

**{C1 契约 v1（可减配：块出边+DECLARE 两族先行）+ C2 SAILR Phase 2 缝 + env 门控双脸发射}**——不含 C3/C4/C5/C6/C7/C8。判据：canon 语料上 `RUGRA_ENHANCED=1` 产出结构化变体 C 文本、`unset` 后字节恒等回归默认脸、DecBench runner 本地记分板双列（rugra-default/rugra-enhanced）出数。此后每加一个增强组件=多一类候选，选择器（C9）就绪前以"人工比对+记分板差分"过渡。

### 6.3 里程碑表（与总路线图 Phase 4 判据挂钩 [ROADMAP]）

| 里程碑 | 内容 | 前置 | 量级 |
|---|---|---|---|
| M1 | C1 契约 v1：emitter 增强块（五缺口）+ 双形态 + irfix-1 版本化 | MB18 释放 emitter 域 | 1-2 车道周 |
| M2 | Stage 0（DECBENCH 车道独立线）：runner+本地首跑+自证报告 | MB18 | 独立（DECBENCH WP 表 [DECBENCH §三]） |
| M3 | 增强脸首跑：SAILR Phase 2 缝 + 双脸发射 + 记分板双列 | M1+SAILR Phase 1 交付 | 10-20 车道日全链 [LEDGER] |
| M4 | C5 PRINTIR v1：.ll SSA 直发 + verify/确定性/双档验收 | M1（帧 overlay 需 C3 时顺延该档） | 中 |
| M5 | C9 选择器 v1 + C6 sidecar v1：三重门禁（汇编 diff+arity+行为）闭环，本地记分板 best-of-N 出数 | M3+M2（择优需跑分台 [DECBENCH §三 WP8]） | 中 |
| M6 | 类型层：C7a STRIDE 管道 →（深挖裁决后）C7b TRex 引擎 | M1；TRex artifact 深挖前置 | 小→中–大 |
| M7 | Stage 4 冲榜：rugra-enhanced Union>41.06 且 type_match>7.56 | M5+M6（+O2 语料扩面=Stage 1 [DECBENCH §五]） | — |

**Union>41.06 的组合路径**（[RELIT §2.4] 总账的组件化展开）：逐函数≈Ghidra（Phase 0，~32% 档）→ +SAILR 三档（C2，kuna 同族实证 28.45→39.05 空间）→ +类型层（C7，打 kuna 6.91 绝对洼地；type_match>7.56 判据 [ROADMAP]）→ +三重门禁选择器（C9，byte_match 闭环打 kuna roadmap 16.4 空窗）→ **Union>41.06**。反面锚点：LLM 榜一 codex byte_match 15.08 断层第一但 GED 23.98、Union 仅 26.49——**单指标突进换不来 Union，只有门禁化组合杠杆能赢** [RELIT §2.4/DECBENCH §1.6]；D-LiFT 有 Basque 参与=kuna 可能跟进 SMT 信号，**窗口期真实、动作要快** [RELIT §2.3]。

---

## 七、风险与诚实边界（设计判断 vs 先例背书，逐组件）

| 组件 | 有先例背书（证据锚点） | 设计判断/未知数（需验证） |
|---|---|---|
| C1 契约 | Patchestry schema 经 104 CVE/固件 fixture 磨过 [PCODEIR §一-B]；我们 stage 投影 v1.2.2 emitter 80% 字段已有 [PCODEIR §四-①]；切点双先例（Ghidrall/Patchestry 独立同选）[PCODEIR §〇-3] | 我们保留 SSA 与 Patchestry de-SSA 的消费端适配面（SAILR 的 RegionIdentifier 吃坍缩图——适配层语义需 fixture）；irfix-1 字段演进策略；文本/JSON 双形态的一致性维护成本 |
| C2 SAILR | kuna 实测同族增益 28.45→39.05 [DECBENCH §1.6]；angr 原版开源语义源+kuna p7_regions Rust 参照 [LEDGER]；SoK 选型判据 [RELIT §一-A] | **angr 图模型适配**（CFG/Region 抽象 vs 我们 Funcdata/BlockGraph——Phase 2 缝的核心未知）；三档参数在我们语料的落点；enhanced 候选的 GED 收益是 kuna 侧证据的迁移推论，非我们实测（首跑前无自有数据） |
| C3 GEP | Ghidrall 三策略 A/B 实测排序（86.08/83.16/82.99，97 程序×三优化级）[PCODEIR §一-A2] | 我们的 varmap 已恢复相对索引的场景比例高于 Ghidrall 输入（其输入=Ghidra 裂解后），**GEP 层在我们语料的收益可能显著小于文献值**——触发即测，不预支收益 |
| C4 pass 菜单 | pass 语义公开稳定；Ghidrall 实证内存形态+O 链 86% 功能保持 [PCODEIR §二-c] | 每 pass 在我们 IR 上的等价变换需逐个 fixture；**Ghidra 主管线已跑过语义等价 Rules**（RuleConstant/RuleDistribute 等），增强 pass 的净增量上限未知；dewolf GED 3.65% 反证候选化必要性 [RELIT §2.1] |
| C5 PRINTIR | .ll 标准格式消费者多；Ghidrall 映射表=现成发射规范 [PCODEIR §五-3]；MLIR 负先例裁决 [PCODEIR §五] | **SSA 直发无先例**（三先行工作全发内存形态 [PCODEIR §两裁决-2]）——phi 携带、类型最小化策略是本设计自担判断，留 mem 档对冲；第一用户价值排序（差分仪器优先）是排程判断非实证 |
| C6 sidecar | Pcode2C 博客形态完整可照抄 [PCODEIR §一-C]；raw pcode 零分歧（36 面 698,605 decodes）[LEDGER]；Decompile-Diverge 方法论一手 [RELIT §E] | **行为 harness 语料规模**（OSS-Fuzz 语料覆盖我们语料的比例未知；自建 driver 合成的成本）；CBMC 有界=回归信号非证明 [PCODEIR §四-③]；C 执行环境噪音（未定义行为/优化副作用）的归因纪律 |
| C7a STRIDE | 开源/无 GPU/与 DIRTY 竞争力（自报）[RELIT §一-B] | 训练库在我们变量面上的命中率；XTRIDE 部署性证据可参照但代码需深挖 [RELIT] |
| C7b TRex | 123/125 胜 Ghidra（论文自报）+ artifact 三徽章 [RELIT §一-B]；kuna 无计划=护城河 [RELIT §2.2] | **artifact 内部形态未深挖**（实现语言/输入格式/依赖/移植形态——RELIT 与 PCODEIR 均标需深挖）；"123/125"是其语料口径，我们语料收益未知；论文自报未复现 [RELIT §四-6] |
| C8 ERASE | O2 内联重灾区机理成立（源码有调用→结构同构）；kuna #261 自认无 outlining 支持 [RELIT §2.1] | **GED 收益是推论非论文实测**（论文面向可读性 [RELIT §一-A]）；LLM+符号执行依赖→规则半边（DREAM++/FuncRE）的独立收益未知；O2noinline 试点先行是风险对冲设计 |
| C9 选择器 | Decompile-Diverge 反面教材一手（75→90 build 同时 74→62 matched）[RELIT §E]；D-LiFT SMT 信号 [RELIT §2.3]；kuna 16.4 空窗 [RELIT §2.3]；BED'18/Decomperson'22 哲学锚点 [RELIT §一-F] | SMT 调用序列比对的工程化成本（约束求解器引入方式——同"不引入 LLVM 依赖"纪律须裁决求解器依赖）；三 gate 的 false-positive 率（错杀默认脸等价候选=白丢分）；DecBench 归一化规则抄本的保真度 [DECBENCH §1.3] |

**全局风险**：①增强合并对默认脸的回归——由 §1.3 五条机制+canon/镜面/bank 全绿验收对冲；②DecBench 语料演进（96,103/770/41 为 2026-09-23 快照，引用须带 snapshot 日期 [DECBENCH §1.2]）；③首跑子集口径（ARM cps 9 项目零供给，首跑明确声明子集、全量等 WP7 [DECBENCH §四]）；④增强轨不改变对齐优先级——Phase 0 残差收敛与 GED 分数同战线 [DECBENCH §2.5]，两线是同一战场的两个纵深。

---

## 八、与四份研究的结论零矛盾自检

| 研究结论 | 本架构的承接方式 |
|---|---|
| [DECBENCH §四-2] 逐函数≈Ghidra 只到 ~32% 档，+8.8pp 必须靠增强轨 | §1.1 两 oracle 分层；§6.3 组合路径以 32% 为起点 |
| [DECBENCH §五] Stage 4 双列（default+enhanced）冲 Union>41.06 | §1.3 机制 5 双列纪律；§6.3 M7 |
| [RELIT §三-1] 首推① TRex 确定性类型层 | C7b 插座+深挖前置（确定性契合门禁哲学） |
| [RELIT §三-2] 首推② 三重门禁选择器=Union 超 41.06 唯一组合路径 | C9 + §6.3 组合路径 + Decompile-Diverge 教训入 C6 角色 |
| [RELIT §三-3] 首推③ STRIDE n-gram sidecar 起步 | C7a（先通管道再换强模型） |
| [RELIT §一-A] ERASE=O2 新杠杆/规则优先 LLM 兜底 | C8 落地次序照抄 |
| [RELIT §2.1] SAILR 三档已有（kuna 实证） | C2 主杠杆地位+Phase 1 在飞 |
| [PCODEIR §四-①] 契约=投影格式增强面而非替代 | §2.1 载体裁决+身份键保留 |
| [PCODEIR §四-②] 单 struct=GEP 参照形态/正典路径不动 | C3 双声明 |
| [PCODEIR §四-③] pcode2c=非 LLM 行为 oracle/进 CI 非终审 | §5.3 角色边界 |
| [PCODEIR §四-④] pass 菜单映射/不引入 LLVM 依赖 | C4 纪律 |
| [PCODEIR §五] MLIR 降级为 .ll 文本导出 | §4.1 主形态裁决 |
| [PCODEIR §六] 六条设计修订（输入面/帧/验证/pass 表/无 MLIR/.ll 唯一生态接口） | 逐条对应 C1/C3/C6/C4/§4.1/§4.4-② |
| [LEDGER] PRINTIR 构想五用途+printc 旁渲染器+恢复层复用 | §4.3/§4.4（五用途收敛为三优先级：差分仪器/机器消费/侧车——语义验证与重优化闭环归入机器消费面的未来子项，不丢失） |
| [LEDGER] SAILR-PORT 双脸缝/ENHANCEMENT 域/RUGRA-GLUE 形态 | §开头域声明+C2 Phase 2 缝 |
| [ROADMAP §Phase 4] best-of-N+SAILR 三档+ML 层判据 | C9/C2/C7 全对应，判据原样引用 |

---

## 九、票池指针

增强轨票池已登记 `docs/TODO_BOARD.md`（本 commit 同步）：每组件一票——IRFIX-CONTRACT-0001 / SAILR-PHASE2-SEAM-0001 / IRCONV-PASSMENU-0001 / GEP-RECON-0001 / PRINTIR-RENDERER-0001 / BEHAVIOR-SIDECAR-0001 / SEL-TRIPLEGATE-0001 / STRIDE-SIDECAR-0001 / TRex-TYPE-SOCKET-0001 / ERASE-DEINLINE-0001（共 10 票，全部 ENHANCEMENT 域声明）。排程裁决与认领归 root（MB18 后按 §6 里程碑派发）。

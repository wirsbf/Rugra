# LANE HHMIRROR — ".hh 镜像分层"解环方案压测终判

> 归档注记: 来源车道 HHMIRROR（架构压测,只读分析,零 src 改动）· 2026-09-26 · 本件为 .hh 镜像分层方案（A2）压测终判的权威记录;蓝图 A2 修订节以其为准。

> 车道: HHMIRROR（只读压测，零 src 改动）· 日期: 2026-09-26
> 被测方案: root 提出的".hh 镜像分层"（卫星 struct 定义下沉类型层叶子模块 + 算法 impl 浮顶，
> 利用"Rust 固有 impl 在 crate 内可放任意模块"作为 .hh/.cc 分离的原生等价物）。
> 对照物: `wt/cratesplit:docs/alignment_docs/CRATESPLIT_MIGRATION_BLUEPRINT_2026-09-26.md` §1.6
> 12 边表 + §5.4 C0-C5；`/dev/shm/rugra-reports/LANE_KUNACRATES_2026-09-26.md` §4.3-4.5。
> 诚实纪律: 终判只基于本车道亲自核实的边、字段与 trait 签名（逐行 grep + 机器测绘三轮迭代），
> 不采信 root 推理。工具脚本存档 `/dev/shm/hhmirror_tmp/type_deps3.py`（内存盘，关键结论全内嵌正文）。

---

## 0. 摘要（一句话终判）

**FEASIBLE-WITH-CONDITIONS**。方案的旗舰机制**真实成立**——funcdata 的五个卫星
（heritage/merge/dynamic/unionresolve/override）的 struct 定义逐字段核验**确实干净**
（不引用 Funcdata/Architecture），"types 下沉 + impl 浮顶"确实斩断 funcdata↔卫星环，
12 条蓝图环边中 10 条可由此消解。但方案的强主张"**Rust 模块图可镜像 .hh 图 23 层无环**"
被**证伪**：.hh include 图的无环是 C++ **前置声明机制的红利**，不是类型层序的真实无环
——type.hh(L5) 字段持 `Architecture*`(L15 上行 10 层)与 `FuncProto*`(L12 上行 7 层)，
action.hh(L14) 虚方法签名持 `Funcdata&`(L16)，jumptable.hh(L12) 持 `recoverModel(Funcdata*)`，
options.hh(L0-3) 持 `ArchOption::apply(Architecture*)`。Rust 无前置声明，这些 oracle 本体边
全部物化为完整类型依赖，与 Funcdata/Architecture 的字段持有互锁成 **24 模块 types 层核心 SCC**
（生产代码、字段+被持有 trait 签名粒度实测）。纯移动的天花板 = "74 个 solo 模块严格分层
+ 1 个 ~15-24 模块冻结核心 SCC + 环棘轮"，**不是 23 层无环**。要逼近真无环需 4 项 trait 反转
（Action/Rule/ArchOption/JumpModel，kuna EngineTranslate 同款）+ 1 项 GLUE 修复 + 若干字段重构
——全部是语义改动（B2 门禁），与"零语义改动"承诺矛盾。

---

## 1. 压测方法与口径（三轮迭代，防假阳性）

types 层（"必须下沉"层）的精确定义，是本压测的核心方法论：

- **必须下沉项**：被 Funcdata/Architecture 字段闭包**持有**的 struct/enum 定义（字段/变体），
  以及被该闭包 struct 以 `dyn Trait`/`Box<dyn Trait>` 持有的 **trait 定义**（其方法签名随之沉）。
- **可浮动项**（上行引用无害）：impl 块、自由函数、**无人持有**的 trait（如 Decoder/Encoder/
  TypeOp——仅以 `&mut dyn` 出现在方法参数）、**无人持有**的分析器 struct（ScoreUnionFields/
  ConditionalExecution/FlowInfo/EmulateFunction/TransformManager/PreferSplit 管理器）、类型别名。
- **生产/测试切割**：每文件在首个顶层 `#[cfg(test)]` 处截断（v1 曾把 heritage.rs 测试内
  `struct OwnershipGraph { fd: Funcdata }` 误计为生产边，已修正）。
- **导入解析**：`use crate::X::{...}` 裸名解析（v2 修复 `re.M` 缺失 bug 后 PcodeOp.output→
  Varnode 等边才可见）；模块名归一（`type_system::datatype` → `type_system`，与
  `crate::type_system::` 引用口径一致，v3 修复幻影节点）。

最终工具 `type_deps3.py` 输出：生产 types 图 SCC、Funcdata 字段闭包（36 模块）、逐边证据行。

---

## 2. 12 条环边逐边终判表

| # | 环边 | Rust 边精确形态（亲核） | .hh 层序证据（亲核） | 分类 | 处置 |
|---|---|---|---|---|---|
| E1 | typeop→printlanguage | typeop.rs:9 `use printlanguage`；引用全部在 **TypeOp trait 签名**（`push(&mut dyn PrintLanguage)` 族）与 impl；**TypeOpManager（typeop.rs:3918，持 `Vec<Box<dyn TypeOp>>`）无任何生产持有者**（仅 typeop.rs 内部+测试）→ typeop 整体浮动 | typeop.hh:25 include printlanguage.hh（L9→L7 下行合法） | **(a) 可解——浮动变体** | typeop 不下沉、整体浮顶；边消解 |
| E2 | typeop→printc | typeop.rs:65 `as_printc_mut` Any-downcast 为**自由函数**（impl 层） | 无此边（printc.hh L8 在 typeop L9 之下，include 不存在；printc.cc:16-17 才 include funcdata.hh） | (a) 可解 | 随 impl 浮动消解 |
| E3 | varnode→funcdata | varnode.rs:2588 `get_use_point(&self, fd: &Funcdata)`——**方法签名**，Varnode 字段零 Funcdata（亲核 :504-570） | varnode.hh:214 `getUsePoint(const Funcdata&)`；varnode.hh:31 `class Funcdata;` 前置声明 | (a) 可解 | impl 浮动消解（蓝图 C3 无需执行） |
| E4 | block→funcdata | block.rs:4040 `finalize_printing_graph(fd)` 等 5+ 自由函数收 `&mut Funcdata`；**FlowBlock trait 签名亲核为零 Funcdata**（Rust 已把 Ghidra block.hh:242/257/262 的 `Funcdata&` 虚方法改组为自由函数——trait 内 awk 全扫仅 1 处注释命中） | block.cc:18 include funcdata.hh（.cc 叶子）；block.hh 无 Funcdata 签名（仅 :462 friend） | (a) 可解 | 自由函数浮动消解 |
| E5 | address→varnode | address.rs:2010 `functional_equality`（**level-0 简版副本**）vs expression.rs:732 正主（全级）；10 处调用全在 ruleaction.rs（:3525/:3625-3626/:3722-3723/:17238-17267） | expression.cc:520-526 唯一正主；address.hh 无对应 | **(b) 伪影确认** | C1 维持：删副本改调正主（蓝图定性正确） |
| E6 | typeop→op | TypeOp trait 签名收 `&PcodeOp`；**Rust PcodeOp.opcode 是 OpCode 枚举（op.rs:317），Ghidra 的 `TypeOp* opcode` 字段（op.hh:122）在 Rust 已消除**（op.rs:17 stub） | op.hh:21 include typeop.hh 单向；typeop.hh 前置声明 PcodeOp | (a) 可解 | 随 typeop 浮动消解；Rust 侧该边在 types 层本就不存在 |
| E7 | op↔varnode、op↔block | **互持字段**：op.rs:322-323 `output/inrefs: Arc<RwLock<Varnode>>` ↔ varnode.rs:520/528 `def/descend: Weak<PcodeOp>`；op.rs:321 `parent: Weak<RwLock<dyn FlowBlock>>` ↔ block.rs:2133 `ops: Vec<PcodeOpRef>`；另 varnode.rs:522 `high: Arc<HighVariable>` ↔ variable.rs `instance: Vec<Arc<Varnode>>` | op.hh **不 include** varnode.hh/block.hh（仅 :21 typeop.hh）；varnode.hh:31 前置声明族承载全部互指——.hh include 图根本看不见这些边 | **(c) 真互持** | 纯移动不可消；合并节点 {varnode,op,variable,block} |
| E8 | marshal→space | marshal.rs:2153 `trait Decoder` 的 `read_space/write_space` 签名收 `&crate::space::{AddrSpace,SpaceRegistry}`（:2146/:2217/:2362 等 12 处） | marshal.hh:83 `class AddrSpace;` 前置声明 + :262 `virtual AddrSpace *readSpace`——**fwd-decl 物化，非伪影**（蓝图"待核验伪影"定性修正）；space.hh:22-23 反向单向 | (a) 可解——**浮动变体** | Decoder/Encoder trait **无人以字段持有**（全库仅 `&mut dyn Decoder` 方法参数，亲核 grep）→ trait 浮动，marshal types（AttributeId/ElementId）干净下沉，边消解，无需 C4 |
| E9 | funcdata↔卫星全层 | Funcdata 字段持完整类型（funcdata.rs:76-82 vbank/obank/bblocks、:137 scope、:169 callspecs、:182 arch、:195 jump_tables、:498 heritage、:508 merge_state、:616-617 union_map、:635 localoverride）= funcdata.hh:22-27 include 面同构；**反向边全部在 impl 签名**（heritage.rs:7、merge.rs:7 的 `use crate::funcdata` 仅出现在方法体） | funcdata.hh:22-27 include architecture/override/heritage/merge/dynamic/unionresolve（L16 枢纽）；卫星 .hh 全部前置声明 Funcdata（heritage.hh:112、merge.hh:43、dynamic.hh 经 varnode.hh:31、unionresolve.cc:187 派生、override.hh 签名） | **(a) 可解——旗舰机制成立** | 见 §3 逐卫星字段核验 |
| E10 | varmap→heritage、fspec→varmap、fspec→heritage | varmap.rs:1630 `add_guard(&crate::heritage::LoadGuard)`（签名）；fspec.rs:3512 `check_input_trial_use(..., &crate::varmap::AliasChecker)`（签名）；fspec.rs:3354 `Heritage::apply_new_varnode_flags` 调用（方法体） | varmap.hh:130 `class LoadGuard;` 前置声明；fspec.hh:1093 `class AliasChecker;`；fspec.cc:17 include funcdata.hh（.cc 叶子） | (a) 可解 | 全部 impl 级浮动消解（蓝图 C5 无需执行） |
| E11 | action→analysis | action.rs:2648 `crate::analysis::type_infer::propagate_types(fd)` 在 `impl Action for ActionTypePropagate` 内（:2645） | action.hh 纯基类；universalaction 才是注册点 | (a) 可解 | impl 浮动消解（蓝图 C0 无需执行）。**但真阻断边在此暴露，见 E13/E14** |
| E12 | drillfmt↔drillobserve | drillobserve.rs:92/159/191→drillfmt、drillfmt.rs:192→drillobserve 均为 impl 级调用；drillfmt.rs:41 `DrillFmt{arch}` 持 Architecture | 无对应（RUGRA-GLUE 观测件） | (a) 可解 + **1 处 GLUE 阻断** | 双件浮顶消解；**但 action.rs:341 `crate::drillobserve::activate()` 位于 Action trait 默认方法体（:309 perform，:93 trait）内**——默认体随 trait 下沉 → drillobserve→arch 被拖入。Ghidra OPACTION_DEBUG 是 `#ifdef`（action.hh 无此引用）。修法：调用移出默认体或 cfg 门控（小 GLUE 改造，非纯移动） |

### 压测中发现的蓝图未列真阻断边（E13-E16，全部 (c) 类）

| # | 边 | Rust 形态（亲核） | Ghidra 侧（亲核） |
|---|---|---|---|
| E13 | **Action/Rule trait 签名→funcdata** | action.rs:100 `fn apply(&mut self, fd: &mut Funcdata)`、:495 `fn apply_op(..., fd: &mut Funcdata)`；trait 被 ActionDatabase/ActionPool 以 `Box<dyn Action>`/`Box<dyn Rule>` 持有 ← Architecture.allacts（arch.rs）← Funcdata.arch（funcdata.rs:182） | action.hh:102/120 `perform(Funcdata&)`/`reset(Funcdata&)`；Funcdata 前置声明经 include 闭包传递可见：action.hh→block.hh→jumptable.hh→emulateutil.hh→op.hh→typeop.hh→variable.hh→**varnode.hh:31** |
| E14 | **ArchOption trait 签名→arch** | options.rs:51 `fn apply(&self, arch: &mut Architecture, ...)`；trait 被 OptionDatabase 以 `dyn ArchOption` 持有 ← Architecture.options_db | options.hh:27 `class Architecture;` 前置声明；options.hh 在 .hh 图 L0-3（上行 12 层！） |
| E15 | **JumpModel trait 签名→funcdata** | jumptable.rs:1518-1520 `fn recover_model(&mut self, fd: &crate::funcdata::Funcdata, ...)`（同族 build_addresses/fold_in_*/sanity_check 共 7 签名）；trait 被 JumpTable 以 `Box<dyn JumpModel>` 持有 ← Funcdata.jump_tables（funcdata.rs:195） | jumptable.hh:249-260 `virtual bool recoverModel(Funcdata *fd)=0` 等纯虚签名（L12→L16 上行 4 层，fwd decl 承载） |
| E16 | **type_system 反转环 ×2** | ① datatype.rs:4328 `TypeSpacebase.fd: Option<Arc<RwLock<crate::varmap::ScopeLocal>>>` + varmap.rs:2499 `ScopeLocal.arch_lookup: Option<Arc<crate::arch::Architecture>>` + arch `Architecture.types: Arc<RwLock<TypeFactory>>` = **字段级 3-环** {type_system→varmap→arch→type_system}；② datatype.rs:3697 `TypeCode.proto: Option<Arc<FuncProto>>`（type_system→fspec）+ fspec.rs:2773 `FuncCallSpecs.proto_model: Option<ProtoModel>`（fspec→type_system）= **字段级 2-环** | type.hh:725 `Architecture *glb`（L5→L15 上行 10 层）、:696 `FuncProto *proto`（L5→L12 上行 7 层）、:155-158 前置声明块；database.hh:473/917 `Architecture *glb`；type.hh **只 include address.hh**（:22）——include 图完全无环，类型引用图环靠 fwd decl 隐形 |

另：varnode.rs:532 `call_spec: Option<Weak<RwLock<crate::fspec::FuncCallSpecs>>>` 是 **RUGRA-GLUE 偏离**
（Ghidra 把 FuncCallSpecs* 编码在 IPTR_FSPEC 地址整数里，fspec.hh:1733 `getFspecFromConst` 直接
指针转型；Rust 注释自证"cannot safely encode...so the FSPEC annotation carries a typed Weak handle"）。
该字段把 varnode 钉在 fspec 之上（.hh 序 varnode L7 < fspec L12 的**倒置**），并入核心 SCC。

---

## 3. 逐卫星字段核验（root 方案旗舰问题的直接回答）

| 卫星 | struct 定义字段（亲核） | 引用 Funcdata/上层类型？ | 可下沉？ |
|---|---|---|---|
| heritage | Heritage（heritage.rs:681-706）：LocationMap/TaskList/Vec<Vec<i32>>/PriorityQueue/Vec<HeritageInfo>/Vec<LoadGuard>/Vec<Weak<PcodeOp>>；HeritageInfo（:383）：AddressSpace+原生；LoadGuard：op/space/原生 | **无**（Ghidra `Funcdata *fd` 字段已被 RUGRA-GLUE 线程化，:682-689 注释自证；27 处 crate::fspec 全在方法体） | ✅ 可沉到 funcdata 之下 |
| merge | Merge（merge.rs:1010-1032）：u32/HashSet<usize>/Vec<PcodeOpRef>/MergeTypeIntersectCache/attach_depth；MergePersistentState（:767）：test_cache/copy_trims/live_set/proto_partial | **无**（Ghidra `Funcdata &data` 字段经 attach/detach 挂载消除，:1064/:1085） | ✅ 可沉 |
| dynamic | DynamicHash（dynamic.rs:208-218）：usize×3/Vec<Arc<PcodeOp>>/Vec<Arc<Varnode>>/Vec<ToOpEdge>/Address/u64 | **无**（7 处 Funcdata 全在签名 unique_hash_vn 等） | ✅ 可沉 |
| override | Override（override_rs.rs:85-100）：BTreeMap<Address,...>×4/Vec<i32>/Vec<Address> | **无**（1 处 Funcdata 在签名） | ✅ 可沉 |
| unionresolve | ResolvedUnion（:52-58）：Arc<Datatype>×2/i32/bool；ResolveEdge：干净。**但 ScoreUnionFields（:351-365）`pub fd: Option<&'t crate::funcdata::Funcdata>` 是字段** | ResolvedUnion 无；ScoreUnionFields **有**（RUGRA-GLUE：Ghidra 无此字段，从 `op->getParent()->getFuncdata()` 派生，unionresolve.cc:187/207——Rust PcodeOp 无 Funcdata 回指针故穿参） | ⚠️ 拆分处理：ResolvedUnion/ResolveEdge 下沉；ScoreUnionFields 是**无人持有的栈上分析器**（全库无字段持有）→ 浮顶，边消解 |

**结论：root 的旗舰机制对 5 卫星中 4.5 个成立**（unionresolve 需"分析器浮顶"细化规则，
该规则与 .hh/.cc 分离精神一致——ScoreUnionFields 在 Rust 中住 .cc 等价层）。

---

## 4. 方案前提逐项判真伪

### (a) "Rust 固有 impl 可在 crate 内任意模块" — **TRUE，带 1 个隐藏约束**

- 语言层确认：固有 impl 与 trait impl（trait 与 type 均 local，孤儿规则满足）可在同 crate
  任意模块放置；方法解析、UFCS、路径均与 impl 位置无关。泛型 impl/关联类型无位置约束。
- **隐藏约束 = 可见性**：私有字段仅在定义模块及其后代可见。impl 移到兄弟模块后**无法访问
  私有字段**——Merge（5 个私有字段）、DynamicHash（8 个私有字段）、Varnode（self_ref 私有）、
  PcodeOpBank 等全部受影响 → 必须升 `pub(crate)`/`pub(super)`。这是**编译期可见性放宽**，
  零运行时行为变化，但**不是纯移动**，且与蓝图 Phase A"保 pub(crate) 可见性"的承诺面冲突
  （Phase A 用 `#[path]` 不动文件内容；A2 必须改字段可见性，54 处 pub(crate) 审计面扩大）。

### (b) "类型下沉=纯移动零语义改动" — **对旗舰案例 TRUE，对全局 FALSE**

- 旗舰案例（§3）：TRUE，卫星 types 干净，移动即断环。
- 全局：FALSE——E7/E13-E16 的互持字段与 trait 签名**不可动**；可见性放宽是必要伴随（见 (a)）；
  E12 的 Action 默认体 GLUE 修复是必要伴随。
- 派生宏：卫星 struct 全部 std/serde 派生（Debug/Clone/Serialize 等），随定义移动，无 crate
  内自定义派生依赖 ✅。递归类型定义：BlockBasic.parent:Weak<BlockGraph>、Varnode.self_ref
  等全部同模块内自引用，随文件整体移动 ✅。初始化顺序：Rust 无 C++ 静态序问题，struct 移动
  不影响 ✅。测试路径：模块名保留（types 模块沿用 `crate::heritage` 名，impl 放新模块如
  `crate::heritage_impl`），`use crate::heritage::Heritage` 零搅动，方法调用解析 crate 全局 ✅。

### (c) "// Ghidra: 注解随代码走" — **TRUE（亲核检查器逻辑）**

- check_ghidra_annotations.py:123 `os.walk(SRC_DIR)` 递归覆盖 src/ 全部子目录与新文件；
  :44 `GHIDRA_RE = //\s*Ghidra:` 匹配 fn 上方注释块（:131-146 `_has_alignment_marker`）。
  注解锚定 Ghidra file:line，代码跨文件移动不破坏锚。
- check_ghidra_refs.py 校验引用指向 ghidra/ 树真实行，与 src 路径无关。
  蓝图⑯"8526 处注解是路径搅动下最大稳定资产"结论**维持并加强**。

### (d) "重钉级联与 Phase A 同预算" — **同窗一次覆盖 TRUE；分窗则双倍**

- 36 个 tree pin 钉 src/ 整树 git tree hash：A+A2 合并执行只失效一次、重钉一次 ✅。
- 28 个 overlay runner：**改写而非改名**——A2 把 heritage.rs 拆为两文件后，overlay 路径集合
  （如 `"src/heritage.rs"`）与 metadata comparand（文件 sha256 表）都要按新文件清单重建
  （overlay 语义是"钉死基座 + 覆盖候选文件"，候选文件拆分后必须整组覆盖）。比 Phase A 的
  sed 路径改名**更重**，但同属一个级联窗口（2-3 车道日，4-5 并行）。
- **裁决建议**：A2 若采纳，必须与 Phase A 同窗执行（合并 10-12 车道日总盘）；A2 后置 =
  第二次全量级联 +2-3 日，且 36 pin 二次失效。

---

## 5. 决定性实测：types 层 SCC（生产代码、字段+被持有 trait 签名粒度）

```
=== SINK-GRAPH SCCs (size>1) ===
[action, arch, block, cover, cpool, database, drillobserve, fspec, funcdata,
 heritage, jumptable, merge, op, options, pcodeinject, pcodeparse, prefersplit,
 transform, type_system, unionresolve, userop, variable, varmap, varnode]   ← 24 模块
=== solo: 74/98 ===
```

- Funcdata 字段闭包（必须沉到 funcdata 之下）= 36 模块；其中 24 个互锁成 SCC。
- **SCC 的最小阻断边集**（§2 E7/E13-E16 + E12-GLUE）：去掉全部阻断边后仍剩
  ~15 模块核心（{varnode,op,variable,block,fspec,type_system,varmap,arch,database,
  userop,cpool,jumptable,pcodeinject,pcodeparse,cover}——由互持字段对与反转环锁死）。
- **每条阻断边都是 Ghidra 前置声明承载的 oracle 本体边**（type.hh:155-158、varnode.hh:31、
  action.hh 经 varnode.hh:31 传递、options.hh:27、jumptable.hh:249-260、database.hh:473/917、
  op.hh:65 friend）。.hh include 图 226 文件零环 23 层（蓝图实测维持）——但 **.hh 类型引用图
  在完整类型意义上同样有环**，C++ 指针/引用/声明不需要完整类型，环对编译器隐形。

**对 root 核心观察的修正**：".hh 无环靠类型沉底、代码浮顶"的归因不完整。.hh 无环的第一
功臣是**前置声明**（指针字段/虚签名可引用任意层类型）；.cc 浮顶是第二功臣。Rust 能原生复刻
后者（impl 浮动——本压测证实有效，SCC[60]→24），不能复刻前者（→ 剩余 24 模块核心 SCC）。

---

## 6. 与 kuna substrate 半成品的对照（压测核心问题）

**问题**：kuna 沉了 varnode/op/block/funcdata* 进 substrate/ 但 substrate 仍上行引用
（funcdata.rs:94 use crate::fspec 等，KUNACRATES §4.3 实测）——他们止步处，我们能否真完备？
还是他们止步因为有我们没看到的硬阻碍？

**回答**：**他们止步不是因为硬阻碍，是因为无此目标**——kuna 的文件夹是纯导航性分类
（"taxonomy, not the schedule"），单 crate 内互环对他们是零成本事实，从未设定无环执法目标。
他们的 EngineTranslate trait 反转（§4.4）服务于 **crate 边界**（frontend 拆出），不是 crate
内分层。因此 kuna 止步**不构成**对本方案的反证。

但本压测独立发现了 kuna 从未面对的真阻碍面：**被持有 trait 的签名环**（Action/Rule/
ArchOption/JumpModel——kuna 的 action/rule 注册面同样会有，只是他们不执法无环所以看不见）
与**互持字段环**（op↔varnode↔block——Ghidra 本体，kuna §4.3 的"忠实边"清单正是这些）。
我们的方案在他们止步处**不能完备到零环**——天花板是 24 模块（纯移动）→ ~15 模块
（+4 trait 反转 +1 GLUE 修复，每项 B2 门禁语义改动）→ 更小（+字段重构：call_spec 侧表化、
TypeSpacebase/TypeCode/ScopeLocal 重构——发散性重构，kuna 同款"丢 C++ 类形状"成本）。
kuna 的 EngineTranslate 先例背书 4 项 trait 反转的**手法可行性**，但每项在我方门禁下
（B2 逐函数 fixture + canon cmp + runner 重钉）是 0.5-1.5 日/项的语义工程，非纯移动。

---

## 7. 终判：FEASIBLE-WITH-CONDITIONS

### 7.1 成立部分（方案的真实价值）

1. **旗舰机制成立**：卫星 types 下沉 + impl 浮顶，funcdata↔卫星环确实可断（§3 逐字段核验）。
2. **12 边中 10 边消解**（E1-E6/E8/E10/E11/E12 主体），蓝图 C0/C2/C3/C4/C5 五项破环程序
   在 A2 框架下**自动完成或不再需要**（impl 浮动取代签名移居/trait 分发/调用反转），
   仅 C1（E5 伪影）维持。
3. **环棘轮可执法**：冻结 24 模块核心 SCC 成员 + 断言"无新增跨 SCC 边、solo 模块间无新环"
   进 CI（机制 F 同款检查进版本化门禁）。这是独立于分层深度的防回归资产。
4. **oracle 导航 1:1**：74 个 solo 模块可按 .hh 层序严格分层（8-10 个层组），核心 SCC
   单列一个"core"层组，Ghidra file↔Rust 模块映射账本不受影响（注解/refs 检查器亲核通过）。

### 7.2 条件（不满足则降级为 REJECT 的部分）

1. **目标表述必须改写**："镜像 .hh 图 23 层无环" → "**压缩无环图 + 一个冻结核心 SCC
   （~15-24 模块）+ 环棘轮**"。宣称零环 = 宣称错误，机制 D 红线。
2. **"纯移动零语义改动"必须改写** → "纯移动 + 可见性放宽（pub(crate) 面）+ 1 处 GLUE 修复
   （drillobserve 移出 Action 默认体）"。两者零行为变化但非零 diff。
3. **必须与 Phase A 同窗执行**（runner 级联一次付清）；后置 = 双倍级联。
4. **4 项 trait 反转（E13/E14/E15）默认不排期**：每项是 B2 门禁语义改动（Action/Rule/
   ArchOption/JumpModel 签名收窄或经参数 trait），收益 = SCC 24→~15，不改变"核心 SCC 存在"
   的事实。登记为蓝图 C 程序扩展票（C6-C8），触发判据同 §4.4。

### 7.3 A2 执行设计草图（Phase A 升级版）

```
目录形态（Phase A 组目录 + 组内 types/impl 两分；模块名全保留）：
src/
  foundation/          L0-3   opcodes crc32 error rangemap types space marshal compression sleigh_ffi
  pcode/               L4-13  address pcoderaw cover varnode op variable block jumptable
                              dynamic transform(LanedRegister) prefersplit(Record) unify ...
  types-db/            L5-12  type_system(整目录) database cpool comment stringmanage userop
  arch-hub/            L10-15 varmap(ScopeLocal/RangeHint/MapState) fspec options context
                              loadimage pcodeinject pcodeparse arch action(ActionDatabase/trait)
  funcdata-hub/        L14-16 heritage merge override_rs unionresolve funcdata
  impls/               浮顶层  全部算法 impl + 自由函数 + 无人持有 trait(TypeOp/Decoder/
                              JumpValues 除外——被持有者随宿主) + 分析器 struct
  core-scc.freeze      24 模块冻结清单（棘轮断言输入）
  print/ frontend/ align/ analysis/ ...（同 Phase A 组，均 solo 可分层）
层组压缩为 ~9 组（不追 23 层字面）；每组内文件保持 Ghidra 1:1 文件名锚。
```

| 步 | 内容 | 验收门禁 | 估 |
|---|---|---|---|
| A2.0 | 预检：SCC 冻结清单落档 + 54 处 pub(crate) 与私有字段可见性审计表 + runner 级联名单冻结 | 审计表全绿 | 0.5 日 |
| A2.1 | 卫星先行：heritage/merge/dynamic/unionresolve/override 五件拆 types/impl（ScoreUnionFields 浮顶） | canon 字节恒等（curl/httpd 双 profile）+ cargo test 基线逐名同 + annotations/refs 绿 | 1 日 |
| A2.2 | pcode IR 组 + types-db 组拆分（E7 互持组整体下沉，接受合并节点） | 同上 | 1-1.5 日 |
| A2.3 | arch-hub/funcdata-hub 拆分 + E12 GLUE 修复（activate 移出默认体） | 同上 + Action 域 fixture | 1 日 |
| A2.4 | trait 归位：typeop/Decoder/Encoder/未持有 trait 浮顶；drill 双件浮顶 | 同上 | 0.5 日 |
| A2.5 | 棘轮工具：types-SCC 断言器进 CI（复跑 type_deps3 逻辑 + 冻结清单 diff） | 断言器自测 + CI 绿 | 0.5 日 |
| A2.6 | runner 级联：36 tree pin 重钉 + 28 overlay 集重建 + 逐个重跑绿 | 全 runner 绿 | 2-3 日 |

**工期**：A2 增量 ≈ **6-8 车道日**；与 Phase A 合并同窗总盘 ≈ **10-12 车道日**
（Phase A 原 6-8 日中 A1-A8 的移动步骤与 A2.1-A2.4 合并执行，省重复门禁）。
串行约束不变（lib.rs 共享写点）；A2.6 可并行派发。

### 7.4 与蓝图 C 程序的关系修订

| 蓝图票 | A2 框架下的命运 |
|---|---|
| C0 (E11 action→analysis) | **自动完成**（impl 浮动），无需执行 |
| C1 (E5 错置副本) | **维持**（唯一仍需的 C 票，0.5 日） |
| C2 (E2/E6 typeop→printc) | **自动完成**（typeop 整体浮动） |
| C3 (E3/E4 签名移居) | **不再需要**（impl 浮动取代） |
| C4 (E8 marshal→space) | **不再需要**（Decoder/Encoder trait 浮动；定性从"伪影"修正为 fwd-decl 物化） |
| C5 (E10 反向边) | **自动完成**（全部 impl 级） |
| 新增 C6-C8 | Action/Rule、ArchOption、JumpModel trait 反转（可选，B2 门禁，SCC 24→~15） |

---

## 8. 诚实纪律裁决（总）

本压测**证实**了 root 方案的机制核心（impl 浮动 = .cc 浮顶的 Rust 原生等价物，旗舰案例
funcdata↔卫星环可断、10/12 边消解、五项蓝图 C 票作废），**证伪**了其强主张（"23 层无环
零语义"——.hh 无环的第一功臣是前置声明而非分层，Rust 物化 fwd-decl 边后核心 SCC 24 模块
不可消）。方案的正确打开方式是降格目标表述 + 接受冻结核心 SCC + 执法环棘轮 + 与 Phase A
同窗执行。4 项 trait 反转是唯一的"更无环"路径，属语义工程，默认不排期，与 kuna 先例
（EngineTranslate）手法同款、成本异构（我方 B2 门禁 + 永久 oracle 义务）。

## 9. 复现口径

- types 图工具：`/dev/shm/hhmirror_tmp/type_deps3.py`（生产切割 + 导入解析 + dyn-trait
  持有判定 + Tarjan SCC；v1/v2 迭代 bug 与修复已记录于 §1）。
- 关键 grep 事实（防内存盘丢失，全部已内嵌正文）：funcdata.hh:22-27、heritage.hh:23/:112-113、
  merge.hh:22-23/:43/:53/:84/:119、dynamic.hh:23、unionresolve.hh:19、override.hh:22、
  varmap.hh:22/:130、fspec.hh:22-23/:1093/:1626、block.hh:22/:242/:257/:262/:462-473、
  jumptable.hh:22-24/:109-110/:249-260、action.hh:52/:102/:120、options.hh:27、type.hh:22/
  :155-158/:696/:725、op.hh:21/:65/:122、varnode.hh:31/:143-150/:214、database.hh:33/:473/:917、
  architecture.hh:21-35、space.hh:22-23、marshal.hh:19-20/:83/:262、pcoderaw.hh:35、
  expression.cc:520、fspec.hh:1733、unionresolve.cc:187/207、
  funcdata.rs:76-82/:137/:169/:182/:195/:498/:508/:616-617/:635、heritage.rs:7/:383/:681-706、
  merge.rs:7/:1010/:1064/:1085、dynamic.rs:208、override_rs.rs:85、unionresolve.rs:52/:362、
  varnode.rs:520/:522/:528/:532/:2588、op.rs:17/:317/:321-323、block.rs:2133/:4040/:8608、
  jumptable.rs:1500/:1518/:5335、action.rs:93/:100/:309/:341/:489/:495/:2645-2648、
  options.rs:43/:51、marshal.rs:2153、typeop.rs:8-9/:65/:3918、address.rs:2010、
  expression.rs:732、datatype.rs:3694-3697/:4314/:4328、fspec.rs:2773/:3512、varmap.rs:1630/:2499、
  transform.rs:643、prefersplit.rs:22-32/:124-125、drillfmt.rs:41、drillobserve.rs:92。

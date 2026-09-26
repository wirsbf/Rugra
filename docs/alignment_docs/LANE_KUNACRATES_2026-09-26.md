# LANE KUNACRATES — kuna 全 workspace crate 架构实测 + Rugra CRATESPLIT 蓝图对照

> **归档注记（2026-09-26,Lane TODO-BOOK）**: 本报告归档自内存盘
> `/dev/shm/rugra-reports/LANE_KUNACRATES_2026-09-26.md`（来源车道 KUNACRATES,2026-09-26
> 交付,纯调研零 src 改动;内存盘易失,本件为 docs/alignment_docs/ 持久化归档,
> 除本注记外与源文件逐字节一致）。

> 车道: KUNACRATES（纯调研，零 src 改动）· 日期: 2026-09-26
> 取材: github.com/Noelo-Lab/kuna HEAD 浅克隆（--depth 1），只读参考，收尾已删。
> 对照物: `wt/cratesplit:docs/alignment_docs/CRATESPLIT_MIGRATION_BLUEPRINT_2026-09-26.md`
> （基=master a6becff6；SCC[60]/foundation 9/sleigh-ffi 1/upper 25 三线切割）。
> 诚实纪律: kuna 切法是**存在性证明**不是正确性证明——采纳与否以我方门禁约束
> （canon 字节恒等 / 233 runner 重钉成本 / 逐函数 oracle 对齐纪律）为裁决标准。

---

## 0. 摘要（一句话版）

**kuna 对 SCC 互环的答案 = 不破环：整个反编译器核心（469 文件 / 32.9 万行）是单一
crate `kuna-decomp`，内部用"阶段文件夹 + glob 再导出保平铺模块名"做纯导航性分组；
实测其 p0-p9 概念文件夹之间依然大量互环——即使按概念管线重排整个代码库，模块依赖
图也无环不可得。这独立证实了我们蓝图"core 60 整体单 crate"的裁决。** 同时发现两条
必须修订蓝图的事实：①蓝图基点不含 C++ FFI 退役 commit，sleigh-ffi 切割线已过时；
②kuna 的 foundation 切割比我们深（address/pcoderaw/context/translate-trait 下沉成功），
证明 SCC 下沿还有收缩空间，但收益有限且每步触发我方 runner 重钉级联。

---

## 1. kuna 是什么（背景校准）

- kuna = Ghidra C++ 反编译器的 Rust 移植起家（2026-06-05 vendor 锁定 C++ 树 ~196K LOC
  为 oracle），移植完成后**删除了 C++ 树**（2026-06-20），此后按自身 phase 模型
  （P0-P9，Ghidra/angr/Reko 三家研究推导）大幅发散：angr SAILR 结构化、RegionIdentifier、
  ~75 个 settable options、自有 kuna_* 阶段/规则族。
- 移植方法论与我方高度同构：91 port items + 91 对抗 verify items（blob sha 钉死）、
  wave gate W0-W11、porter/verifier 分离（verifier 只拿 C++ 源+diff+门禁输出，不采信
  porter 推理，每 verdict ≥3 个对抗测试）、单调性强制（675 datatest 断言只增不减）、
  losses 账本 ~250 条、移植中发现 Ghidra 上游 6 个潜伏 bug。全程 ~2 周 LLM 时间 / ~$8k。
- **关键差异**：他们的 oracle 纪律是**移植期**的（port 完即删树，改跑冻结 baseline.json）；
  我方是**永久**的（锁定 oracle e40ed130 永不删，逐函数账本 9494 分母）。因此他们的
  crate 边界不承担 oracle-facing 稳定性义务，我方承担——这决定了哪些先例可采纳。

## 2. workspace 全测绘（12 crate）

workspace 根在 `decompiler/Cargo.toml`（members = `crates/*` glob，与我方同款）。
Cargo.lock 61 crate（12 内部 + 49 外部）。规模实测（src 行数含 doc 注释；test 列为
crate 内测试行数）：

| crate | 定位（lib.rs 自述） | 文件 | 行数 | test 行 | 对应 Ghidra .cc |
|---|---|---|---|---|---|
| **kuna-base** | foundation：地址/空间/XML+marshal/raw p-code/压缩 | 14 | 15,143 | 3,639 | types.h/error.hh/xml.y/marshal/space/address/pcoderaw/globalcontext/partmap/rangemap/compression/crc32/filemanage + translate/loadimage **as traits** |
| **kuna-num** | 数值语义：多精度/IEEE 浮点仿真/CircleRange | 6 | 4,845 | 2,066 | multiprecision/float/double + rangeutil 的 CircleRange 半 + **opcodes/pcoderaw/opbehavior** |
| **kuna-sleigh** | SLEIGH .sla 读取 + 指令解码运行时（纯 Rust，无 C++） | 21 | 33,421 | 5,932 | slaformat/context/slghsymbol/slghpattern/slghpatexpress/semantics/sleighbase/sleigh + translate/loadimage/memstate/emulate traits |
| **kuna-slacomp** | SLEIGH 编译器（.slaspec→.sla，sleigh_opt 替代） | 8 | 10,385 | 1,605 | slghscan.l/slghparse.y/pcodecompile/slgh_compile（**复用** kuna-sleigh 的消费侧类型，不重复移植） |
| **kuna-decomp** | **反编译器核心：DECCORE 全量 + kuna 阶段模型** | **469** | **329,146** | 54,996 | varnode/op/block/funcdata*/type*/fspec/database/heritage/merge/dynamic/jumptable/flow/ruleaction/coreaction/blockaction/subflow/transform/condexe/paramid/varmap/print*/universalaction + kuna_* 发散件 |
| **kuna-analysis** | 程序预备 loader+analyzer 层（Ghidra "Run Analysis" Java 层对应物） | 142 | 71,790 | 408 | 无 .cc 对应（Ghidra Java 分析器族：demangle/DWARF/PDB/strings/FID/RTTI/…，loader/ + analyzers/ 每 pass 一模块） |
| **kuna-console** | 控制台前端（decomp_dbg bin） | 30 | 29,998 | 29,983 | console.cc/ifacedecomp.cc/iface.cc（含 kassert/phase/quality 控制台面） |
| **kuna-ghidra** | ghidra-mode 进程前端（Ghidra GUI 的 `decompile` bin 对应物） | 8 | 4,129 | 5,937 | ghidra_process.cc/ghidra_arch.cc |
| **kuna-harness** | dev-only 差分测试辅助（Rust vs C++ oracle） | 7 | 3,674 | 1,998 | test.cc/test.hh/testfunction.cc（C++ 测试框架 1:1 移植）+ liftdiff/corpus 自研 |
| **kuna-lift-diff** | lift 差分自测薄 bin（委托 kuna-harness） | 1 | 71 | 0 | — |
| **kuna-cli** | 用户面 `kuna` bin（decompile/test/catalog/specs） | 26 | 23,450 | 18,070 | —（原 Python 四入口的 Rust 重写） |
| **kuna-wasm** | wasm32-wasip1 浏览器前端（native 输出=parity oracle） | 5 | 2,110 | 0 | — |

**反编译器核心（action/varmap/block/printc/ruleaction/heritage）全部在 kuna-decomp 单
crate 内**，无一拆出。kuna-decomp 内部布局（lib.rs 自述"phase-aligned"）：

```
substrate/   共享 IR 与容器（varnode/op/block/funcdata*/dtype/context/expression/transform）  20 文件 45,657 行
p0_knowledge/  符号 DB/options/overrides/阶段注册表                                          29 文件 16,483 行
p1_partition/  架构/loader 绑定                                                              11 文件  2,766 行
p2_lift/       flow/jumptable/注入/CFG                                                      71 文件 30,788 行
p3_dataflow/   SSA/heritage/化简规则池（ruleaction_1..8 按规则族拆）                         50 文件 49,354 行
p4_calls/      fspec/调用点/原型恢复                                                        71 文件 33,183 行
p5_types/      类型系统+推断（typeop.rs 在此；dtype.rs 在 substrate）                        53 文件 38,622 行
p6_variables/  HighVariable/merge/栈布局（cover/dynamic/varmap 域）                          43 文件 26,996 行
p7_regions/    angr RegionIdentifier 移植                                                    9 文件  7,298 行
p8_structure/  结构化引擎（blockaction + SAILR 族）                                         23 文件 14,787 行
p9_emit/       PrintC/cast/comment/命名/render                                              63 文件 39,771 行
infra/         编排与框架（action/universalaction/architecture/capability/engine_translate） 25 文件 23,357 行
```

文件名层面：funcdata 按方面拆 12 文件（其中 funcdata{,_block,_op,_varnode}.rs 四件是
**Ghidra 12.0.4 oracle 本体文件族的忠实 1:1**——oracle 确有 funcdata_block.cc/
funcdata_op.cc/funcdata_varnode.cc；encode/printraw/merge/facing/callsite/union/
resolveflow/spacebase 八件是 kuna 自创切分）；coreaction 按阶段拆 7 文件
（early/protos/infertypes/casts/render/cleanup/stackptr，kuna 自创）；ruleaction 按规则
族拆 8 文件（kuna 自创）+ kuna_* 发散规则 ~60+ 件散在各阶段文件夹。

## 3. crate 依赖 DAG（从各 Cargo.toml 提取）

```
外部: thiserror flate2 │ smallvec slotmap │ object cpp_demangle rustc-demangle msvc-demangler gimli pdb │ regex syn

kuna-base ──← kuna-num ──← kuna-sleigh ──← kuna-slacomp        (SLEIGH 编译器: 复用 runtime 类型)
    │            │            │        └← kuna-decomp          (核心)
    │            │            │             ├──← kuna-analysis   (loader/analyzer 层)
    │            │            │             ├──← kuna-ghidra     (ghidra-mode 前端; dev-dep: console+analysis)
    │            │            │             └──← kuna-console ──← kuna-harness ──← kuna-lift-diff
    │            │            │                     │       └──← kuna-cli (另依赖 analysis/decomp/base/sleigh)
    │            │            │                     └──← kuna-wasm (另依赖 analysis/decomp/base)
```

- 层序：L0 base → L1 num → L2 sleigh/slacomp → L3 **decomp** → L4 analysis/ghidra →
  L5 console → L6 harness/lift-diff/cli/wasm。**零环**（cargo 图天然无环）。
- 依赖方向纪律与我方蓝图 §5.1 同构：下层永不依赖上层；唯一"近环"用 **dev-dependency**
  消解（kuna-ghidra 的测试 harness 需要 console，dev-dep 不传播）。
- 二进制放置遵循防环规则（Cargo.toml 注释明文）：`decomp_test_dbg` bin 放 kuna-harness
  而非 kuna-console——"kuna-harness depends on kuna-console (the reverse would be a
  dependency cycle)"；`kuna-lift-diff` 是纯薄壳，逻辑全在 kuna-harness::corpus。

## 4. SCC 处理手法（核心问题的答案）

### 4.1 答案：单 crate，不破环

kuna 从未把 SCC 拆成多 crate。反编译器核心整体 = kuna-decomp 一件（469 文件）。
他们连"试拆"的痕迹都没有——移植期就是 6-crate 形态（base/num/sleigh/decomp/console/
harness），核心从头到尾一件。**切割线只切在 SCC 下沿（base/num/sleigh）与上沿
（analysis/console/cli/ghidra/wasm/harness）**，与我方蓝图三条线同构。

### 4.2 内部机制：阶段文件夹 + glob 再导出（= 我方 Phase A 的同族手法）

```rust
// kuna-decomp/src/lib.rs
mod substrate;  mod p0_knowledge;  ...  mod p9_emit;  mod infra;
pub use substrate::*;  pub use p0_knowledge::*;  ...  pub use infra::*;
```

- 文件夹是**纯导航性分类**（"The folders are a taxonomy, not the schedule"——执行序
  是 infra/universalaction.rs 的声明式 SchedNode 树）；
- 模块名**保持平铺**（`kuna_decomp::flow`），下游（console/cli/analysis）全部用平铺
  路径消费，零路径搅动；
- 与我方 Phase A `#[path]` 手法的差异：他们用 `mod X; pub use X::*` 两跳（文件夹 mod
  是中间层），我方 `#[path]` 一跳直达且**保 pub(crate) 可见性**（glob 再导出会丢
  pub(crate) 项——我方蓝图 §2.2 已论证，kuna 侧 pub(crate) 用量低故无痛：实测
  funcdata.rs 42 处/op.rs 3 处/architecture.rs 2 处）。
- **存在性证明价值**：该机制在 469 文件 / 32.9 万行规模上运行无碍——我方 Phase A
  （97 文件 / 31.3 万行）规模更小，机制风险进一步收敛。

### 4.3 决定性实测：概念分层也无法让依赖图无环

对 kuna-decomp 469 文件提取 `use crate::X` 边并按顶层文件夹归约（脚本实测），
**文件夹间互环大量存在**：

| 环族 | 实测边（引用计数） |
|---|---|
| infra ↔ 各阶段 | infra→substrate 40, infra→p0/p2/p3/p4/p6/p8/p9 = 6/9/1/4/1/1/3；反向 p0→infra 2, p1→infra 6, p2→infra 9, p3→infra 26, p4→infra 6, p5→infra 12, p6→infra 6, p7→infra 6, p8→infra 12, p9→infra 7 |
| substrate ↔ 各阶段 | substrate→p0 5, →p2 6, →p4 2, →p5 5, →p6 4, →p8 2, →p9 2, →infra 1（**共享 IR 上行引用各阶段**）；各阶段→substrate 40-156 不等 |
| 阶段 ↔ 阶段 | p2↔p5（3/1）, p3↔p4（3/1）, p4→p9（1）, p9→p3/p5/p6（1/4/2）, p8→p7（4）, p0→p2（1）, p5→p2（1）, p9→p2（1） |

抽查上行边定性（防脚本假阳性，逐条看源）：

- `substrate/funcdata.rs:94 use crate::fspec` —— 忠实：oracle funcdata.hh:22-27
  include architecture/override/heritage/merge/dynamic/unionresolve（Funcdata 枢纽本体）；
- `substrate/funcdata_block.rs:2479,2533,2661 use crate::jumptable::RecoveryMode` ——
  忠实：block.hh:22 include jumptable.hh（我方蓝图 E 边同款）；
- `substrate/funcdata_printraw.rs:28 use crate::typeop` —— 忠实（printraw 走 TypeOp 表）；
- `substrate/funcdata_op.rs:2321 use crate::overrides` —— 忠实（override.hh）。

**结论**：kuna 团队用三家（Ghidra/angr/Reko）研究推导的概念管线模型重排了整个核心的
磁盘布局，p0-p9 文件夹在概念上是严格有序的——但模块依赖图**依然互环**，环边就是
Ghidra 的忠实边（funcdata 枢纽、block→jumptable、typeop↔print）。这比我方"SCC[60]
是前置声明物化代价"的论证更强：**连概念层重排都不能消环，环是领域本体的**。
我方蓝图"core 60 整体单 crate、内部目录分组仅导航用"的裁决获独立第三方证实。

### 4.4 trait 反转实例（他们真正破过的环）

- **EngineTranslate**（kuna-decomp/src/infra/engine_translate.rs）："Architecture owns
  its disassembly engine behind a `Box<dyn EngineTranslate>` trait object rather than
  a concrete Sleigh … the ghidra translator lives in the downstream kuna-ghidra crate,
  **so an enum variant would be a dependency cycle, but a trait object owned here is
  not**"。core 持 trait，下游 frontend crate 实现——教科书式 trait 反转。
- trait 栈分层清晰：RegisterLookup（kuna-base/space.rs:294）→ LoadImage/PcodeEmit/
  Translate: RegisterLookup（kuna-sleigh）→ EngineTranslate: Translate（kuna-decomp）。
  Ghidra 的 translate.hh 在 include 图 L6，他们把**接口**下沉到 base/sleigh、实现留
  高层——"接口低放 + 实现高放"是绕开 include 层序的手法。
- 我方对应物：蓝图 §5.4-C0（action→analysis 注册点经 trait 反转）与未来 frontend
  拆出（B4+）同款手法，获先例背书。

### 4.5 foundation 切割比我们深（SCC 下沿收缩先例）

kuna-base/kuna-num 把我方 SCC[60] 内的几个模块**成功下沉**：

| 模块 | 我方蓝图位置 | kuna 位置 | 他们能下沉的原因 |
|---|---|---|---|
| address | SCC[60]（E5：address.rs:2010 错置 functional_equality 副本→varnode） | kuna-base | 无 E5 伪影（干净移植） |
| pcoderaw | SCC[60]（pcode 组） | kuna-num | 纯数据（raw varnode/op prior to Funcdata ownership），无上行边 |
| context/globalcontext | SCC[60] | kuna-sleigh | 上下文数据库与 SLEIGH 绑定 |
| translate/loadimage | SCC[60] | kuna-sleigh（trait）| **接口下沉**：Translate/LoadImage 定义为 trait，实现在上层 |
| opcodes | foundation 9 | kuna-num | 同层，仅归组不同 |
| float_emulate | SCC[60] | kuna-num | 纯算术，Ghidra float.hh 本就在 include 图 L0-3 |

含义：我方 SCC[60] 中 **address（修 E5 后）/pcoderaw/float_emulate/translate-trait 化**
有下沉先例。但注意：①收益有限（60→~55，funcdata/heritage/varmap/merge/blockaction 等
真枢纽永不可拆——kuna 同样没拆）；②每一步都是语义改动（非纯移动），触发我方
B2 逐函数门禁 + runner 重钉级联；③kuna 的 translate-trait 化是**发散性重构**（他们
不再保 C++ 类形状），我方若做必须以行为等价证明为门禁。

## 5. pub API 形态

- **门面策略**：无独立门面 crate。kuna-decomp lib.rs 即门面（12 个 `pub use <folder>::*`
  glob 再导出），全部模块平铺在 crate 根。下游一律 `kuna_decomp::<module>::<Item>`
  平铺路径消费（实测 kuna-console/src/project.rs：`kuna_decomp::funcdata::Funcdata`、
  `kuna_decomp::decompile_drive::…`、`kuna_decomp::kuna_protoorder::…`）。
- **可见性**：crate 边界即 API 纪律（跨 crate 必须 pub）；crate 内 pub(crate) 用量低。
  我方蓝图 B0"54 处 pub(crate) 审计"在他们无对应需求——他们从第一天就是多 crate，
  可见性天然收敛；我方是先单 crate 后拆，审计不可省。
- **examples**：几乎无（仅 kuna-cli/examples/docs_standalone.rs 一件，且用
  `#[path = "../src/docs.rs"]` 复用源码——`#[path]` 手法的又一生产先例）。他们的
  "examples"角色由 CLI 子命令 + tests 承担。我方 28 个 examples/~600 深层引用是
  我方独有约束（公共 API 冻结面），门面再导出方案不受 kuna 先例影响。
- **测试组织**（四层）：
  1. 单元：`foo.rs` + 同名兄弟目录 `foo/tests.rs`（crate 级约定）——kuna-decomp src
     内 168 个 tests.rs / 58,597 行；
  2. crate 集成测试：kuna-decomp/tests/（按**阶段边界 B0-B5** 命名：deadcode_b4/
     heritage_b3/print_b5_boolless/decompile_e2e/flow_linkage/…）+ fixtures/；
  3. repo 级语料：tests/datatests（83 XML/675 断言，**Ghidra 上游 datatest 语料原样
     vendor**）、tests/stages（issue 测试件）、tests/golden、tests/cli；
  4. 差分 harness：kuna-harness（liftdiff=结构化差分、corpus=钉死案例表、unittest=
     C++ test.cc 1:1、testfunction=XML decompilertest runner）。
- **CI 门禁**（.github/workflows/tests.yml，四门）：`make test`（datatest 675/675
  PARITY）、`make test-stages`、`make rust-test`（~4300 测试）、`make check-spec`
  （docs/spec 锚点+每阶段文件夹恰属一章）+ `kuna catalog --check`。baseline 纪律：
  "Never re-pin docs/baseline.json to absorb a regression"——与我方 golden 纪律同精神。
- **codegen 防漂移**（ADR 0006）：phases.toml 单源真值 → build.rs 生成四张静态表 +
  OptionValues，"any drift a build failure"。对我方无直接需求，但 PIPELINE_STAGES
  文档同步可借鉴。

## 6. 对照与修正建议（逐点）

### 6.1 kuna 切法 vs Rugra 蓝图对照表

| 维度 | kuna 实测 | Rugra 蓝图 | 裁决 |
|---|---|---|---|
| SCC 处理 | 单 crate（469 文件），不破环 | core 60 单 crate | **一致，获独立证实** |
| crate 内分组 | 阶段文件夹 + glob 再导出保平铺名 | `#[path]` 目录分组保平铺名 | **同族手法**；我方 `#[path]` 更优（保 pub(crate)、少一跳） |
| 分组语义 | 概念管线（p0-p9，发散自 Ghidra） | Ghidra 亲缘组（foundation/pcode/…） | **保持我方组名**——我方账本键控=Ghidra file:line，组名是导航锚；kuna 已放弃 1:1 映射故可用概念名 |
| foundation 深度 | base 14 + num 6（address/pcoderaw/context/translate-trait 下沉） | foundation 9 | kuna 证明下沿可更深，但收益 60→~55 且触发重钉级联（见 R3） |
| SLEIGH | 纯 Rust kuna-sleigh + slacomp 复用其类型 | 蓝图 sleigh-ffi 1 文件+build.rs（C++ 构图随迁） | **蓝图已过时**：master 2fa1c792 已退役 C++ FFI，sleigh_ffi.rs 现为纯 Rust DTO 驱动 vendored kuna-sleigh（见 R2） |
| analysis 层 | 独立 crate kuna-analysis（core 之上） | B4+ 可选 rugra-verify（align+analysis） | 方向一致，获先例背书 |
| 测试 harness | kuna-harness dev-only crate（依赖全部，无人依赖它） | tests/oracle 233 runner（非 crate） | 形态不同：他们 port 期需要 in-process 差分；我方 runner 体系是 oracle 门禁资产，不因 crate 化改变（仅重钉） |
| oracle 纪律 | 移植期 C++ oracle，port 完删树，改冻结 baseline | 锁定 oracle 永久在线，逐函数账本 | **根本差异**：他们的 crate 边界无 oracle 稳定义务；采纳其切法必须过我方门禁约束 |
| 文件名映射 | 放弃 1:1（funcdata 拆 12、coreaction 拆 7、ruleaction 拆 8） | op.rs↔op.cc 1:1 是账本锚 | **不采纳其文件重组**；但 oracle 本体的 funcdata 4 文件族例外（见 R5） |
| 确定性 | clippy workspace 级禁 HashMap（ADR 0002） | canon 字节恒等门禁兜底 | 我方已有更强的输出级门禁；可选择性借鉴（非蓝图项） |

### 6.2 蓝图修订建议清单（按优先级）

**R2（必改，事实过时）— sleigh-ffi 切割线重定义**。蓝图基点 a6becff6 **不含**
2fa1c792（"sleigh: retire the C++ FFI runtime — the vendored kuna-sleigh engine is
the production decoder"，2026-09-26 落 master）。现 master 上：src/sleigh_ffi.rs 是
纯 Rust DTO 模块（VarnodeC/PcodeOpC），驱动 vendored crates/kuna-sleigh；**根 build.rs
已不存在**，无 C++ 构图可迁。修订：①三线切割之"sleigh-ffi"线改为"sleigh DTO 线"——
sleigh_ffi.rs 随 foundation 或 core 走（它只依赖 std + kuna-sleigh 类型面），或独立薄
crate `rugra-sleigh`（DTO + kuna-sleigh workspace 依赖）；②B2 步骤"C++ 构建图随迁
（~1-2 日）"作废，改"DTO 归位 + kuna-sleigh 依赖声明"（≤0.5 日）；③风险 R6（build.rs
C++ 构图随迁破坏 SLEIGH 链）**整体删除**；④蓝图 §2.4/§4.2-B2/§6-R6 相应改写。注意：
kuna 四件 vendor（crates/README.md，pinned 0096e984）已在 workspace，kuna-sleigh 在
rugra 构建图内——"kuna vendor 与 rugra-* 零依赖"的蓝图 §2.5 表述也已过时，需同步
改写（README 现况：kuna-sleigh **is in** the rugra build graph，Phase2 已接线）。

**R1（维持原案，信心增强）— Phase A 机制不动**。kuna 在 3.4 倍于我方 core 的规模
（469 vs 97 文件）上运行同族机制（文件夹分组+平铺名保真），下游零路径搅动。我方
`#[path]` 变体保留（优势：pub(crate) 不丢、无中间 mod 层）。组名维持 Ghidra 亲缘
命名（我方账本键控需要），不采 kuna 的 pN 概念名。

**R4（维持原案，获最强旁证）— core 不拆多 crate**。kuna 的阶段文件夹互环实测
（§4.3）证明：即使按概念管线重排全部代码，funcdata 枢纽/block→jumptable/typeop↔print
等忠实边依然成环。蓝图 §5.4 破环程序 C1-C5 维持"默认不排期"；其中 C1（E5 错置副本）
与 C3（签名移居）在 kuna 侧有同向旁证（kuna 的 address 干净下沉、get_use_point 类
签名归属正确层），若未来执行成功率预期上调。

**R3（可选，不改变默认）— foundation 加深候选**。kuna 先例：address（前提=C1 修
E5）/pcoderaw/float_emulate 有下沉路径，translate/loadimage 可 trait 化下沉。裁决：
**不进 Phase B 默认路径**——每项是语义改动（触发 B2 逐函数 fixture + canon cmp +
runner 重钉），收益仅 SCC 60→~55 且不改变"core 单 crate"结论。登记为 Phase B4+
之后的可选票，与 C 程序合并评估。kuna 的 translate-trait 化是发散重构（丢 C++ 类
形状），我方若做必须以"同输入同输出"fixture 证明行为等价，成本高于收益。

**R5（可选，1:1 保真度提升）— funcdata.rs 按 oracle 文件族拆分**。我方 funcdata.rs
= 19,391 行单文件，内含 141 处 `// Ghidra: funcdata_{block,op,varnode}.cc` 注解——
即 oracle 的 funcdata.cc/funcdata_block.cc/funcdata_op.cc/funcdata_varnode.cc 四文件
族被合并移植。kuna 对这四件做了忠实 1:1 拆分（另八件自创切分**不采纳**）。修订建议：
新增可选票"funcdata.rs → funcdata{,_block,_op,_varnode}.rs 四文件拆分"——这不是纯
移动（内容切分），须走完整 4.0 门禁 + runner 重钉（funcdata.rs 必在 overlay 清单），
但拆后 `// Ghidra:` 注解与 oracle 文件 1:1 对齐度提升，FUNCTION_MAP 键控更干净。
排期建议：Phase A 之后独立票，非 Phase A 内联步骤。

**R6（采纳参考）— trait 反转先例背书**。EngineTranslate 是"core 持 trait、下游
frontend 实现"的生产先例，直接背书蓝图 C0（action 注册点 trait 化）与 B4+ frontend
拆出的手法。无需蓝图文字改动，执行期引用本报告即可。

**R7（采纳参考）— analysis/verify 拆出方向背书**。kuna-analysis（142 文件独立 crate，
core 之上，loader+analyzers 分层）背书我方 B4+ rugra-verify（align+analysis）拆出。
同上，执行期引用。

**R8（登记不改）— kuna vendor 关系表述更新**。蓝图 §2.5"kuna vendor 四件与 rugra-*
零依赖关系，共存无冲突"已过时（Phase2 后 kuna-sleigh 在构建图内）。修订为：kuna
四件是 workspace 成员且 kuna-sleigh/kuna-slacomp 已是生产组件（SLEIGH-RUSTIFY
Phase2/3）；未来 rugra-foundation 与 kuna-base 的 dedup 候选面表述保留（README 仍
"deliberately deferred"）。

**不采纳清单**（明确记录，防后人翻案）：①kuna 的 pN 概念文件夹命名（账本键控冲突）；
②funcdata 八件自创切分/coreaction 按阶段拆 7 件/ruleaction 按族拆 8 件（同上，且
kuna 自身已无 1:1 义务）；③clippy workspace 级禁 HashMap（我方 canon 字节恒等门禁
是更强的输出级约束；容器纪律可作为独立讨论票，不入 CRATESPLIT 范围）；④kuna 的
"port 完删 oracle"路线（与我方永久对齐目标根本冲突）。

## 7. 诚实纪律裁决（总）

kuna 的架构证明的是：**"一个 Ghidra 系反编译器的核心可以是一个大 crate + 导航性
文件夹，且这在 33 万行规模上可持续工程化"**——这恰好是我方蓝图 Phase A+B 的核心
主张，故采纳其**机制证据**。kuna 没有证明的是：core 可拆多 crate（他们没做，实测
他们的概念分层也不无环）、crate 边界可对齐 Ghidra 语义层（他们已放弃该目标）、
以及任何切法在我方约束下可行（他们无 233 runner 重钉、无永久 oracle、无 9494
函数账本）。因此本报告全部修订建议以**事实校正（R2/R8）与先例背书（R1/R4/R6/R7）**
为主，唯一新增可选程序（R3/R5）均显式标注"须过我方完整门禁，默认不排期"。

## 8. 复现口径

- 克隆：`git clone --depth 1 https://github.com/Noelo-Lab/kuna`（HEAD 快照，浅克隆
  无历史；历史结论取自 repo 内 docs/history.md 自述）。
- 规模：`find <crate>/src -name "*.rs" | wc -l` + `xargs wc -l`。
- 文件夹互环：Python 脚本提取 `use crate::X`/`use super::X` 边（剥离注释），按顶层
  文件夹归约，模块名→文件夹经 lib.rs glob 再导出面解析；抽查 4 条上行边逐条看源
  定性（§4.3）。脚本随克隆删除，核心数字已全部誊入本文。
- 我方对照数字：src/ 98 文件 312,920 行（蓝图成文时 97，其后 +1）；funcdata.rs
  19,391 行 / 141 处族注解；oracle funcdata.hh:22-27 include 面；2fa1c792 不在
  a6becff6 祖先内（`git merge-base --is-ancestor` 判定）。

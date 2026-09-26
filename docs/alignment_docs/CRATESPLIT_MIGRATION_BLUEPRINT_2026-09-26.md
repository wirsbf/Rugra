# CRATESPLIT 迁移蓝图 — src 整理 + crate 化（CRATESPLIT-MIGRATION-0001 设计交付）

> 车道: wt/cratesplit（基=master a6becff6）· 日期: 2026-09-26 · 性质: **纯设计，零 src 改动**
> 执行阶段另派（触发判据见 §4.4，root 持有）。本蓝图实测数据全部来自本车道对
> src/ 97 文件与锁定 oracle e40ed130 源码树的机器测绘（工具脚本存档于
> /dev/shm/rugra-tests/cratesplit/，内存盘易失——关键数字已全部誊入本文）。

## 0. 摘要

1. **草案层序被实测证伪**。路线图 Phase 5 草案层序（pcode→types→struct→print→actions→varmap→driver）
   在 Rust 生产依赖图中不成立：**60 个模块构成单一强连通分量（SCC[60]）**，横跨全部草案层。
   根因不是移植混乱，而是**架构性**的：Ghidra 的 C++ 头文件 include 图（226 文件）**完全无环**
   （23 个拓扑层），靠前置声明承载类型互引；Rust 无前置声明，这些互引被物化为模块边。
2. **可行的 crate 切割线只有三条**（实测无环）：foundation（9 文件，含 marshal↔space 微环）、
   sleigh-ffi（1 文件+build.rs）、以及 SCC[60] 整体作为单 crate（60 文件）。上层 25 文件为无环带，
   可选做独立 crate。**core 内部按草案层再拆必须先执行 6 项破环重构**（§5.4，每项独立小改动+
   oracle 门禁，属可选程序）。
3. **推荐形态：两步走**。Phase A = 单 crate 内目录分组（`#[path]` 保模块路径，零 use 语句搅动、
   零 examples 搅动、零公共 API 破坏）；Phase B = 沿上述三条切割线 crate 化。一步到位 crate 化
   被否（SCC[60] 阻塞 + 单次搅动面 = 全部 15 件基础设施同时迁移，风险不可分步吸收）。
4. **基础设施迁移主导成本 = oracle runner 重钉级联**：233 个 tools/run_*.sh 中 36 个钉
   `rugra_base_src_tree`（src/ 整树 git tree hash——**任何**文件移动即失效）、28 个含
   `overlay_paths` 字面路径。这是比代码移动本身更重的工程量。
5. **工期估算**：Phase A ≈ 4-6 个工作日（单车道串行——lib.rs 是共享写点）；Phase B ≈ 2-3 周；
   可选破环程序 C1-C6 ≈ 每项 0.5-1.5 日。全部以触发判据解锁为前提。

---

## 1. 模块依赖测绘（实测）

### 1.1 方法与口径

- 工具：Python 解析器（deps_map3.py）逐文件提取 `use` 语句（含 brace 组形式、`as` 别名、
  `super::`/`self::` 相对路径解析、lib.rs 再导出名归位：`crate::Address`→address 等）+
  内联 `crate::X::` 全限定路径引用。
- **生产边 vs 测试边分离**：以首个 `#[cfg(test)]` 为界，之后的引用计入测试边
  （crate 化时测试边只影响 dev-dependency 决策，不构成生产依赖）。
- 注释与字符串先剥离，避免文档引用污染（v1 粗版曾把 printc.rs 注释里的
  "coreaction.cc:1521" 误计为 printc→coreaction 生产边，v3 已修正——该边不存在）。
- 结果：**102 个模块节点、557 条生产边（唯一 module 对）、184 条测试边**。
  原始边表存档 prod_edges.tsv / test_edges.tsv（已随本 commit 誊关键结论入文）。

### 1.2 实测结构：一个巨环 + 两条干净切割线

Tarjan SCC 分析（生产图）：

| 分量 | 规模 | 成员 |
|---|---|---|
| **SCC[60]** | 60 文件 | action, address, arch, block, blockaction, comment, condexe, constseq, context, coreaction, cover, cpool, database, debugproto, double_precis, drillfmt, drillobserve, dynamic, expression, float_emulate, flow, fspec, funcdata, grammar, heritage, jumptable, loadimage, merge, op, opbehavior, options, override_rs, pcodeinject, pcodeparse, pcoderaw, prefersplit, prettyprint, printc, printlanguage, rangeutil, ruleaction, stringmanage, subflow, tracedag, transform, translate, typeop, unionresolve, userop, utils, variable, varmap, varnode + type_system/{mod,cast,datatype,typefactory} + disasm/{mod,x86_64,x86_lift} |
| **SCC[2]** | 2 文件 | marshal ↔ space（互指） |
| foundation 无环带 | 9 文件 | opcodes, crc32, error, rangemap, types, space, marshal, sleigh_ffi, compression |
| upper 无环带 | 25 文件 | align×11, analysis×2, binary, callgraph, disasm::sleigh_lift, emulate, ffi, graph, memstate, modelrules, paramid, signature, type_system::protomodel, unify |
| 孤儿 | 1 文件 | **capability.rs——零生产入边/出边**（capability.hh 对应物存在但当前未接线，见 §6 风险 R7） |
| root | 2 文件 | lib.rs（门面再导出）, bin/rugra.rs |

缩图 DAG（condensation）层级：L0 foundation（含 marshal↔space）→ L1 **SCC[60]+lib 门面** →
L2 upper 大部 → L3 align::pcodeop/runtime_verify/varnode + emulate。**没有任何上层模块被
SCC[60] 反向依赖**（唯一近似违例：action→analysis 一条边，analysis 若独立 crate 则为向上
依赖——执行期把 analysis 并入 core 或把 action.rs 的注册点改经 trait 反转即可，见 §5.4-C0）。

### 1.3 草案修正（实测 vs Phase 5 草案）

| 草案假设 | 实测事实 | 修正 |
|---|---|---|
| pcode 核心（op/varnode/address/space/seqnum）是最底层 | address/varnode/op 全在 SCC[60]；space 在 foundation 但与 marshal 互环 | 真正的底层只有 foundation 9 文件；"pcode 核心"与上层无法分离 |
| types 层在 struct/print 之下 | type_system/{datatype,typefactory,cast} 确在 SCC[60] 内但经 type_system/mod 门面与 funcdata 等互达；**typeop 在 SCC[60] 内且与 printc/printlanguage/op/varnode 互环** | types 拆为两半：type_system 数据面（较独立）与 typeop 打印接口面（与 print 层熔合） |
| print 层在 actions 之上、依赖 types（"print 依赖 types 的反向边"预警） | 实测反向边是 **typeop→printc**（typeop.rs:65 `as_printc_mut` Any-downcast 取回具体 PrintC）与 **typeop→printlanguage**（后者忠实：typeop.hh:25 include printlanguage.hh）；printc→typeop 为正常向下边 | print 层无法单独成 crate：typeop↔print 互环需先破（§5.4-C2） |
| struct 层（block/blockaction/condexe）独立 | block→funcdata（block.rs:4040 等 5 处函数签名收 `&mut Funcdata`）把 struct 熔进 SCC[60] | Ghidra 靠前置声明承载同款签名（block.cc 同样收 Funcdata*）；Rust 物化为边 |
| varmap/database/merge 在 actions 之下独立 | varmap↔heritage、varmap↔fspec、fspec↔heritage、merge↔funcdata 全互环 | 同在 SCC[60]，不可分 |
| lifter（disasm）在 Phase 2 免费给出、可先拆 | disasm/{mod,x86_64,x86_lift} 在 SCC[60] 内（flow→disasm、funcdata→disasm 反向锚定）；**disasm::sleigh_lift 单独无环**（唯一可先行拆出的 lifter 件） | SLEIGH Phase2/3 换装后 lifter 面会重构，crate 化应排在换装后 |

### 1.4 Ghidra include 图对照（架构真相）

对锁定 oracle 226 个 .cc/.hh 提取 `#include "..."` 边并做 SCC：**零环**，23 个拓扑层。关键层序
（.hh 侧）：L0-3 基础（opcodes/rangemap/partmap/crc32/error/capability/float/marshal/opbehavior/
compression/options/space）→ L4 address → L5 pcoderaw/type/loadimage/comment/callgraph →
L6 cover/cpool/memstate/prettyprint/stringmanage/translate/cast/globalcontext → L7 varnode.hh/
printlanguage → L8 dynamic/prefersplit/printc.hh/transform/variable → L9 database.hh/typeop.hh →
L10 op.hh/override/userop/varmap.hh → L11 expression/modelrules/rangeutil/unionresolve →
L12 fspec/jumptable/merge/pcodeinject/pcodeparse → L13 block.hh → L14 action.hh/heritage.hh →
L15 architecture.hh/blockaction.hh/ruleaction.hh → L16 funcdata.hh/constseq/subflow →
L17-18 .cc 实现层+condexe/coreaction/flow/graph/paramid/signature/unify/double → L19+ 驱动
（architecture.cc/console/iface）。

已核验的单边事实（本车道 grep 锁定源）：op.hh:21 include typeop.hh（单向，typeop.hh 不含
op.hh——PcodeOp 为前置声明）；space.hh:22-23 include error.hh+marshal.hh（单向，marshal.hh:19-20
只含 xml.hh/opcodes.hh）；heritage.hh:23 include block.hh；varmap.hh:22 include database.hh；
fspec.hh:22-23 include modelrules.hh/rangemap.hh；varnode.hh:21-22 include pcoderaw.hh/cover.hh；
block.hh:22 include jumptable.hh；address.hh:29 include space.hh；typeop.hh:22-25 include
cpool/variable/opbehavior/printlanguage；printc.cc:16-17 include printc.hh/funcdata.hh。

**结论**：Ghidra 的架构分层真实存在且无环；Rust 的 60-SCC 是"前置声明→全类型引用"的物化代价
+ 少数移植伪影（§1.6）。crate 化的长期正确目标 = **镜像 Ghidra include 层序**；短期可行切割 =
§2.4 的三条实测线。

### 1.5 耦合强度（内联 `crate::X` 原始引用计数，Top 12）

op 1249 · space 1095 · varnode 823 · type_system 817 · block 709 · address 584 · opcodes 382 ·
funcdata 223 · marshal 220 · fspec 152 · unionresolve 111 · disasm 101。
（含义：任何把这些模块移出 `crate::` 可达面的方案，若不做再导出 shim，将搅动数百至上千处引用；
§2.2 的 `#[path]`/再导出机制正是为此。）

### 1.6 环边分类清单（SCC[60] 熔合根因，逐边定性）

| # | 环边 | Ghidra 侧形态 | 定性 | 破环手法（§5.4 详） |
|---|---|---|---|---|
| E1 | typeop→printlanguage | typeop.hh:25 include printlanguage.hh | **忠实互引** | 不破（Ghidra 同构；两者同 crate） |
| E2 | typeop→printc | 无此边；Rust typeop.rs:65 `as_printc_mut` Any-downcast | **移植伪影** | C2：经 PrintLanguage trait 方法分发 |
| E3 | varnode→funcdata | varnode.hh:214 `getUsePoint(const Funcdata&)` 前置声明 | **前置声明物化** | C3：签名移居 funcdata.rs 或泛型化 |
| E4 | block→funcdata | block.cc 多函数收 `Funcdata*`（前置声明） | **前置声明物化** | C3 同款 |
| E5 | address→varnode | 无此边；address.rs:2010 `functional_equality` 是 expression.cc:520 的**错置副本**（expression.rs 已有正主，GETPARAM 车道已证实 `crate::expression::functional_equality` 既有） | **错置副本** | C1：删副本改调用正主（最小破环） |
| E6 | typeop→op | typeop.hh 前置声明 PcodeOp | **前置声明物化** | 不单独破（随 C2 一并评估） |
| E7 | op↔varnode、op↔block | op.hh ↔ varnode.hh/block.hh 互引（Ghidra 本体互引） | **忠实互引** | 不破 |
| E8 | marshal→space | space.hh:22-23 单向 include marshal.hh；反向不存在 | **待核验伪影**（marshal.rs 某签名引用 AddressSpace） | C4：执行期定位具体引用点后小改 |
| E9 | funcdata↔（actions/varmap/print/…全层） | funcdata.hh include 几乎一切（Ghidra 自身设计：Funcdata 是顶层枢纽） | **忠实枢纽** | 不破；funcdata 永居 core 最高层 |
| E10 | varmap→heritage、fspec→varmap、fspec→heritage | heritage.hh:23 含 block.hh；varmap.hh:22 含 database.hh；反向 include 不存在 | **Rust 反向边**（具体函数执行期核验） | C5：登记后逐边处置 |
| E11 | action→analysis | 无（action.hh 是基类；Rugra action.rs 兼任注册表） | **注册表伪影** | C0：注册点经 trait 或并 analysis 入 core |
| E12 | drillfmt↔drillobserve | 无对应（RUGRA-GLUE 观测件） | **胶水互引** | 不破（同 crate；或随 upper 拆出） |

---

## 2. 结构提案

### 2.1 三个选项对比

| 维度 | 选项一：纯目录分组 | 选项二：目录分组→crate 化（两步） | 选项三：一步到位 crate 化 |
|---|---|---|---|
| 语义风险 | 零（纯移动+`#[path]`） | 零（每步 canon cmp 字节恒等门禁） | 零（同左）但不可分步吸收 |
| SCC[60] 阻塞 | 无（crate 内模块互引合法） | Phase B 只切实测无环线，绕开阻塞 | **被阻塞**：要么 60 文件单 crate（=选项二的 core），要么先做全部破环重构（语义风险面失控） |
| 编译并行收益 | 无 | foundation/sleigh-ffi/upper 各自并行；core 仍单单元 | 同左 |
| API 纪律收益 | 无（仍 crate 内可见） | foundation 边界强制 pub 面 | 最大 |
| 基础设施迁移 | 15 件中 ~10 件（路径字面量） | 15 件全量（含 Cargo/build 图） | 同左但一次付清 |
| 可回退性 | 每组一步可回退 | 每 crate 一步可回退 | 差 |
| **裁决** | 作为 Phase A | **推荐（Phase A+B）** | 否决 |

### 2.2 推荐机制：`#[path]` 保模块路径（Phase A 核心手法）

Rugra 的模块路径是**公共 API 与内部引用的共用锚**：src 内 557 条生产边几乎全走
`crate::X`/`super::X`，examples 28 个文件 ~600 处深层引用（`rugra::type_system::datatype` 等），
tests/oracle 的 Rust fixture 也按 `crate::X` 寻址。因此 Phase A 采用：

```rust
// lib.rs（唯一被编辑的 Rust 文件——每模块一行加 path 属性）
#[path = "pcode/op.rs"] pub mod op;            // 文件在 src/pcode/，路径仍是 crate::op
#[path = "types/type_system"] pub mod type_system;  // 目录整体迁移同理
```

- **零 use 语句搅动**（src 内部、examples、fixtures 全部不动）；
- `pub`/`pub(crate)` 可见性完全不变（对比 `pub use X::*` 再导出 shim 会丢 pub(crate) 项）；
- 顶层文件无文件背书子模块（已实测：仅 lib.rs 与既有 mod.rs 有 `mod X;` 声明；op.rs 的
  pcodeop_flags 是内联 mod），`#[path]` 迁移无相对路径解析陷阱；
- 被否决的替代方案：真嵌套重命名（`crate::pcode::op`）——搅动 ~500+ 内部 use + ~600 examples
  引用 + 公共 API 破坏，且 Ghidra 本体 decompile/cpp/ 就是**平铺单目录**，1:1 映射
  （op.rs↔op.cc）以平铺为正；分组是 Rugra 工程侧导航性选择，不进公共路径。

### 2.3 Phase A 目录分组映射表（97 文件全覆盖，组名=未来 crate 切割线）

| 组（src/ 下新目录） | 文件（模块名） | 数 | Ghidra 亲缘 |
|---|---|---|---|
| `foundation/` | opcodes, crc32, error, rangemap, types*, space, marshal, compression, sleigh_ffi | 9 | opcodes.hh/crc32.hh/error.hh/rangemap+partmap.hh/space.hh/marshal.hh/compression.hh；types=Rugra 原生枚举 |
| `pcode/` | address, op, varnode, pcoderaw, opbehavior, float_emulate, constseq, dynamic, transform, unify, userop, cpool, pcodeparse, pcodeinject, translate, loadimage, cover, rangeutil | 18 | P-code IR 与其工具族（address/op/varnode/pcoderaw/opbehavior/float/constseq/dynamic/transform/unify/userop/cpool/pcodeparse/pcodeinject/translate/loadimage/cover/rangeutil） |
| `types/` | type_system/（整目录 5 文件）, typeop, unionresolve | 7 | type.hh/cast.hh/typeop.hh/unionresolve.hh |
| `struct/` | block, blockaction, condexe, jumptable, subflow, flow, graph, tracedag | 8 | block.hh/blockaction.hh/condexe.hh/jumptable.hh/subflow.hh/flow.hh/graph.hh；tracedag=GLUE |
| `actions/` | action, coreaction, ruleaction, heritage, double_precis, prefersplit, merge, varmap, paramid, signature | 10 | action.hh/coreaction.hh/ruleaction.hh/heritage.hh/double.hh/prefersplit.hh/merge.hh/varmap.hh/paramid.hh/signature.hh |
| `print/` | printc, prettyprint, printlanguage, grammar, expression, comment | 6 | printc.hh/prettyprint.hh/printlanguage.hh/grammar.hh/expression.hh/comment.hh |
| `database/` | database, variable, callgraph | 3 | database.hh/variable.hh/callgraph.hh |
| `arch/` | arch, context, options, capability, stringmanage, override_rs, fspec, modelrules | 8 | architecture.hh/globalcontext.hh/options.hh/capability.hh/stringmanage.hh/override.hh/fspec.hh/modelrules.hh |
| `emulate/` | emulate, memstate | 2 | emulate.hh/memstate.hh |
| `funcdata/` | funcdata | 1 | funcdata.hh（+funcdata_*.cc 族）——11k+ 行枢纽独居 |
| `frontend/` | binary/（整目录）, disasm/（整目录）, debugproto, ffi | 8 | 前端边界（BFD/DWARF→fspec 桥、lifter、FFI 面） |
| `align/`、`analysis/` | 既有目录不动 | 13 | Rugra 侧验证/分析脚手架 |
| root 不动 | lib.rs, utils, drillfmt, drillobserve, bin/ | 5 | 门面+GLUE 观测件 |

（\* types.rs 是 `mod types`（lib.rs:127 私有 mod）——分组后仍私有，仅文件位置变。）
计数校验：9+18+7+8+10+6+3+8+2+1+8+13+5 = **97** ✓。组边界刻意与 §2.4 crate 切割线一致：
foundation 组 = 未来 rugra-foundation crate；其余组在 Phase B 全部落入 rugra-core（内部组目录
仅导航用）；frontend/emulate/align/analysis 组是 Phase B4+ 可选拆出候选。

### 2.4 Phase B crate 目标形态（沿实测无环线）

```
crates/
├── kuna-{base,num,sleigh,slacomp}     # 既有 vendor 四件，不动（见 §2.5）
├── rugra-foundation/   # 9 文件：opcodes/crc32/error/rangemap/types/space/marshal/compression
│                        #   依赖：仅外部 crate；marshal↔space 微环内部消化
│                        #   迁移要点：error/types 现为私有 mod → 升 pub mod + rugra 根再导出
├── rugra-sleigh-ffi/    # 1 文件：sleigh_ffi + build.rs（C++ SLEIGH 引擎构建随迁）
│                        #   依赖：rugra-foundation（无——实测 sleigh_ffi 仅依赖 std，可平行于 foundation 或其后）
├── rugra-core/          # 60 文件：SCC[60] 全体（内部保留 §2.3 组目录）
│                        #   依赖：foundation + sleigh-ffi
│                        #   迁移要点：54 处 pub(crate) 中被 upper 引用者升 pub（§5.2 审计）
└── (root rugra 包)      # 门面：lib.rs 再导出 + bin/ + examples/ + align/analysis/ffi/debugproto
                         #   + 可选 Phase B4 拆出：rugra-emulate{emulate,memstate}、
                         #   rugra-frontend{binary,disasm::sleigh_lift}、rugra-verify{align,analysis}
```

依赖方向规则（§5.1）：foundation ← sleigh-ffi ← core ← 门面/upper，**禁止任何向上边与横向边**；
每步落地后以 `cargo tree` + 自写扫描器断言无违例（执行期工具）。

### 2.5 crates/ 共存形态

- workspace members = `"crates/*"` glob（Cargo.toml:6）——新 crate 放入 crates/ **自动入
  workspace，零 members 编辑**。
- kuna vendor 四件是独立成员（"nothing in the rugra build graph depends on them"，
  crates/README.md 明文）；rugra-* 新 crate 与其**零依赖关系**，共存无冲突。
- kuna-base 与 rugra-foundation 存在概念重叠（addresses/spaces/XML+marshal/raw pcode/
  compression——crates/README "Runtime dedup … deliberately deferred (Phase 2 decision
  item)"）。**本蓝图不合并**：合并=语义等价证明工程，超出路径搅动范畴；维持 README 既定
  "deferred" 裁决，在 foundation crate 文档中标注未来 dedup 候选面。

---

## 3. 路径锚定基础设施迁移清单（关键交付）

逐件现状 → 迁移改动量。**DG**=目录分组（Phase A）触发；**CS**=crate 化（Phase B）触发；
✅=无需迁移。

| # | 件 | 路径锚定现状 | DG | CS | 迁移内容与量估 |
|---|---|---|---|---|---|
| ① | tools/check_ghidra_annotations.py | `SRC_DIR=PROJECT_ROOT/"src"`；`os.walk` 递归；staged 过滤 `f.startswith("src/")` | ✅ | CS | walk 递归天然覆盖子目录；CS 改多根枚举（SRC_DIR→[各 crate src]）+ 前缀过滤扩 `crates/*/src/`。~15 行 |
| ② | tools/check_ghidra_refs.py | 同①（os.walk SRC_DIR + staged src/ 过滤） | ✅ | CS | 同①。~10 行 |
| ③ | .zcode/align_gate.py | 门禁谓词 `file_rel.startswith("src/") and endswith(".rs")`（:290）；worktree 跨根 rebase（:420-465） | ✅ | CS | **静默失效风险**：谓词不匹配则直接放行——CS 若不改谓词，编辑门对 crate 文件停止保护。扩谓词至 `crates/*/src/`+rebase 根映射。~10 行+回归测试（hook 自测文件 .zcode/ 内已有用例形态） |
| ③b | .zcode/record_receipt.py | 回执按 **Ghidra 文件** 键控（ROOT/ghidra/...），与 src 路径无关 | ✅ | ✅ | 零迁移（实测确认） |
| ④ | docs/api/ 1:1 映射 | check_doc_sync.py:48 `docs/api/<src 相对路径去 src/ 前缀>.md`；目录已镜像既有子目录（api/align 等 9 个） | DG | CS | DG：**.md 文件随组镜像移动**（~73 个顶层 .md → 组子目录），映射函数 `relative_to("src")` 已支持子目录，零代码改动；generate_api_docs.py:47 写入的"源代码路径"字串随动（生成器改 1 行）。CS：映射函数加 crate 前缀参数 ~5 行 |
| ⑤ | tests/oracle runners（tools/run_*.sh，233 个） | 36 个钉 `rugra_base_src_tree`（**src/ 整树 git tree hash**）；28 个 `overlay_paths=(src/foo.rs …)` 字面路径（~20 个不同文件）；runner 以 pinned base checkout + overlay 现工作区文件方式构建 | DG | DG+CS | **主导成本**。任何 src 移动使 36 个 tree pin 全失效。DG/CS 各需一轮：①36 runner 重钉（base=移动后 commit 的 tree hash，重钉程序=AGENTS 实操备忘"双形态"：rev-parse blob id + sha256 文件哈希）；②28 runner overlay 路径改写（sed 批量+逐个核对）；③每 runner 重跑到绿才算重钉完成（~10-20 分/个，可 4-5 并行）。估 **36×重跑 + 28×改写 ≈ 2-3 车道日/轮** |
| ⑤b | tests/oracle/fixture_registry.json | 250 处 "src/…" 字串（from_path/to_path 等历史证据记录） | DG | — | **裁决建议：历史记录不改写**（证据不可变性——记录的是当时路径）；registry schema 加 `path_epoch` 字段（可选）或在新记录用新路径。执行期 root 拍板。若改写：250 处 sed+复核 ≈ 0.5 日 |
| ⑥ | docs/TODO_BOARD.md 租约行 | 活动票 write-set 以 `src/foo.rs` 字面表述（如 MIGW1 五票） | DG | DG | 触发判据保证执行时零待并分支+wave 边界=活动票最少；仍存留的票逐行改写路径（每票 1 行）。估 ≤30 行。**执行窗口内新增票必须直接用新路径** |
| ⑦ | tools/mirror_gate_baselines.tsv + verify_mirror_gate.sh | 基线按 corpus 键控（39 行，无 src 路径）；verify 脚本无 src 引用（实测 grep 零命中） | ✅ | ✅ | 零迁移 |
| ⑧ | build.rs | 引用 ghidra cpp 树 + sleigh_shim/（**无 src/ 引用**，实测）；[[example]] 路径全指 tests/oracle/*.rs（不动） | ✅ | CS | CS：build.rs 随 sleigh_ffi 迁入 rugra-sleigh-ffi crate（C++ 构建图整体随迁）；根包 build.rs 删除或仅留 ffi-test 联接。~1 日含构建验证 |
| ⑨ | examples/（28 个） | 深层公共路径 `rugra::type_system::datatype` 等 ~600 处 | ✅ | ✅ | `#[path]`（DG）与门面再导出（CS）均保公共路径 → 零迁移。若 CS 期决定改深层路径则另票（本蓝图默认不改） |
| ⑩ | .cargo/config、CI（.github/workflows/alignment-gates.yml） | 无 .cargo/ 目录（实测）；CI 只调 tools/*.py 与 verify_mirror_gate.sh，无直接 src 路径 | ✅ | CS | CI 随 ①②③ 工具修复自动正确；CS 期 CI 增加多 crate 构建矩阵 ~10 行（可选） |
| ⑪ | tools/check_alignment_evidence.py | Evidence 块路径形态校验：接受 `Rugra: src/...` 或 `examples/...`（:47-74） | ✅ | CS | CS 加 `crates/*/src/` 形态 ~3 行 |
| ⑫ | tools/check_corpus_markers.py | 作用域 `src/**/*.rs`（walk）+ 显式文件清单（"src/printc.rs" 等字面项） | DG | CS | DG：显式清单随组改写（清单内 ~10-20 项）；CS：作用域谓词扩展 ~5 行 |
| ⑬ | tools/select_fixtures.py | `relative.startswith("src/")` 过滤（:164,206,294） | ✅ | CS | CS 扩谓词 ~5 行 |
| ⑭ | tools/generate_function_ledger.py | 生成 from_path/to_path="src/flow.rs" 记录入账本 JSON | DG | — | 再生成时自然用新路径；历史账本记录同 ⑤b 裁决（不改写）。工具本身零改动 |
| ⑮ | Cargo.toml | workspace members glob `crates/*`；[[example]] 指 tests/oracle；[lib] 默认路径 | ✅ | CS | DG 零改动（#[path] 在 lib.rs 内）。CS：新 crate manifest ×3-4 + 根包 [dependencies] 增内 workspace 依赖 + workspace.dependencies 登记路径。~40 行 |
| ⑯ | `// Ghidra:` 注解（8526 处） | 键控=Ghidra file:line，与 src 路径无关 | ✅ | ✅ | 零迁移（实测确认——这是路径搅动下对齐账本的最大稳定资产） |
| ⑰ | tools/rugra_gate.py / rugra_build.py / check_gate_health.py | 仅引用 ghidra cpp 树路径（rugra_build.py:56 实测），无 src 锚 | ✅ | ✅ | 零迁移 |

**清单总计**：DG 触发 = ⑤(主导)+④+⑥+⑫ 四件；CS 触发 = ①②③⑧⑩⑪⑬⑮+⑤ 二轮+④ 扩展；
全程免迁 = ③b⑦⑨⑭⑯⑰。

---

## 4. 分步执行计划

### 4.0 门禁口径（每步通用）

每步完成后必须全绿才算可提交（行为中性证明）：

1. `cargo build --profile fast-release --lib` + `cargo test --lib`（基线失败集逐名相同）；
2. **canon cmp 字节恒等**：`cargo run --example curl_decompile` / `httpd_decompile`
   （fast-release 与 release 双 profile）输出与移动前 `cmp` 逐字节相同；
   `compare_ghidra.py` defects/numbering 与基线相同（canon curl 200/0/0、httpd 255/0/0 口径）；
3. `check_ghidra_annotations.py --all` + `check_ghidra_refs.py --all --strict` 绿；
4. `check_doc_sync.py --all` 绿（.md 已随组镜像）。

### 4.1 Phase A：目录分组（单 crate）

| 步 | 内容 | write-set | 基础设施同步 | 成本估 |
|---|---|---|---|---|
| A0 | 预检+看板清扫：触发判据核验（root）；活动票 write-set 路径改写；runner 重钉清单冻结（36+28 名单落档） | TODO_BOARD + /dev/shm 计划档 | ⑥ | 0.5 日 |
| A1 | foundation 组 9 文件移动 + lib.rs `#[path]`×9 + docs/api 镜像 9 .md | src/foundation/、lib.rs、docs/api/foundation/ | ④⑫（清单内 foundation 项） | 0.5 日（含门禁 4.0 全套） |
| A2 | pcode 组 18 文件 | 同上模式 | ④⑫ | 0.5-1 日 |
| A3 | types 组 7 文件（type_system 整目录+typeop+unionresolve） | 同上 | ④⑫ | 0.5 日 |
| A4 | struct 组 8 文件 | 同上 | ④⑫ | 0.5 日 |
| A5 | actions 组 10 文件 | 同上 | ④⑫ | 0.5 日 |
| A6 | print 组 6 文件 | 同上 | ④⑫（printc 在 corpus 清单内） | 0.5 日 |
| A7 | database+arch+emulate+funcdata 组 22 文件 | 同上 | ④⑫ | 1 日 |
| A8 | frontend 组 8 文件（binary/disasm 整目录+debugproto+ffi） | 同上 | ④⑫ | 0.5 日 |
| A9 | **runner 重钉批**：36 tree pin 重钉 + 28 overlay 路径改写 + 逐个重跑绿 | tools/run_*.sh（36-40 个） | ⑤ | 2-3 日（4-5 runner 并行） |
| A10 | 收尾：registry path_epoch 裁决执行、CURRENT_STATUS/ROADMAP 状态行、终验（4.0 全套双 profile） | 文档 | ⑤b⑥ | 0.5 日 |

- **串行约束**：A1-A8 全部编辑 lib.rs（共享写点）→ 单车道串行执行（铁律 6 单 writer）；
  A9 的 runner 重跑可并行派发（每 runner 独立缓存目录，互不重叠）。
- A1-A8 每步一个原子 commit（移动+lib.rs+docs/api 镜像+门禁证据）；A9 按 runner 分批 commit。
- Phase A 合计 ≈ **6-8 个工作日**（单车道移动 + 并行重钉）。

### 4.2 Phase B：crate 化（沿三条切割线）

| 步 | 内容 | 关键风险 | 成本估 |
|---|---|---|---|
| B0 | pub(crate) 审计（54 处全录+越界引用定性）+ crate manifest 骨架 + `cargo tree` 断言工具 | 审计漏项→编译期暴露（可修） | 1 日 |
| B1 | 抽 rugra-foundation（9 文件）：error/types 私有 mod 升 pub；根包 `pub use rugra_foundation::{...}` 保 `crate::error` 等内部路径可达（再导出 shim，pub(crate) 无跨界项——实测仅 marshal 1 处待审） | 再导出 shim 丢 pub(crate) 项（审计兜底） | 1-2 日（含 4.0 门禁+⑤ 二轮重钉） |
| B2 | 抽 rugra-sleigh-ffi（sleigh_ffi+build.rs 随迁） | C++ 构建图迁移（链接路径/feature 联动） | 1-2 日 |
| B3 | 抽 rugra-core（60 文件）：根包变门面（`pub use rugra_core::*` 族）；upper 25 文件暂留门面包或随组上收 | 公共 API 面（examples ~600 深层引用经再导出保持）；54-pub(crate) 中 upper 引用项升 pub | 3-5 日（含门禁+重钉） |
| B4+ | 可选拆出：rugra-emulate / rugra-frontend / rugra-verify（align+analysis） | 各自与 core 的 reach-in 面（§5.2 清单） | 每包 1-2 日 |

Phase B 合计 ≈ **2-3 周**（B4+ 可选另计）。

### 4.3 可选程序 C：破环重构（core 内部再分层的前置）

仅当目标是把 core 按草案层再拆成 pcode/types/print/actions 多 crate 时执行；每项独立票+
oracle 门禁（B2 逐函数 fixture + canon cmp），**默认不排期**（core 单 crate 已满足 Phase 5
"工程化"诉求）。顺序按依赖：C1（最小、无争议）→ C0/E11 → C4/E8 → C3/E3+E4 → C2/E2+E6 →
C5/E10。每项 0.5-1.5 日。详见 §5.4。

### 4.4 触发判据（root 持有，缺一不启）

1. **对齐收敛**：canon 双语料（curl/httpd）逐行差异清零或全部有锁定 oracle 非语义归因
   （"零未解释差异"口径，Phase 0 里程碑判据）；
2. **零待并分支**：无任何在飞/待并 worktree 分支（路径搅动作废面=0）；
3. **wave 边界**：当前 wave 收尾、主管线集成 commit 完成、看板活动票最少化；
4. （Phase B 追加）SLEIGH Phase2/3 换装落地（lifter 面稳定后再动 frontend 组）与
   TFSINGLE step-2 落地（§5.3）。

### 4.5 总工期

Phase A（6-8 日）→ Phase B（2-3 周）→ 可选 C（1-2 周）。串行关键路径 ≈ **4-5 周**（单车道
主导；runner 重钉与 pub 审计可并行车道加速）。所有估算在执行 kickoff 时以 A0 冻结的实测
清单复核后为准。

---

## 5. crate 边界设计

### 5.1 依赖方向规则

- 唯一合法方向：`foundation ← sleigh-ffi ← core ← {门面, emulate, frontend, verify}`；
  kuna vendor 四件与 rugra-* 完全隔离（§2.5）。
- **禁止**：向上依赖（lower crate 出现于上层 crate 的 [dependencies] 即 CI FAIL）、
  横向依赖（core 内部组间经 crate 边界互指）、门面被任何 crate 依赖。
- 执行期工具：`cargo tree --workspace` 断言 + 自写扫描器（解析各 crate Cargo.toml 的
  dependencies 集合做偏序校验），进 CI（机制 F 同款检查进版本化 CI）。

### 5.2 pub API 面与越界访问点（实测全录）

- **pub(crate) 总盘 = 54 处**（全 src 计数），分布：flow 13、coreaction 9、varnode 7、
  varmap 4、type_system/datatype 4、fspec 4、blockaction 4、cover 3、typefactory 2、
  funcdata 2、marshal 1、debugproto 1、其余文件 0。crate 边界切割时，**被对侧引用的
  pub(crate) 项必须升 pub**；同侧引用项保持 pub(crate)（API 面最小化）。
- **foundation 侧**（B1 切割面）：core→foundation 引用全部落在已 pub 项上（foundation
  九文件 pub(crate) 仅 marshal 1 处，执行期核对其引用方归属）；`mod error`/`mod types`
  现为 lib.rs 私有 mod（:126-127），升 pub mod + 根包再导出。
- **core 侧**（B3/B4 切割面）：upper→core 的 reach-in 模块对全录（生产边，51 对）：
  align::address→address；align::function_snapshot→{address,block,funcdata,varnode}；
  align::pcodeop→{op,varnode}；align::range→address；align::runtime_verify→{address,op,varnode}；
  align::varnode→varnode；analysis::type_infer→{funcdata,op,type_system,varnode}；
  binary→{address,disasm}；callgraph→{database,funcdata}；disasm::sleigh_lift→{address,pcoderaw}；
  emulate→{op,opbehavior,varnode}；ffi→{address,funcdata,varnode}；graph→{block,funcdata,op,varnode}；
  memstate→{address,loadimage}；modelrules→{address,fspec,type_system}；paramid→{address,funcdata,op,varnode}；
  signature→{address,funcdata,op,varnode}；type_system::protomodel→{address,fspec}；
  unify→{address,funcdata,op,opbehavior,varnode}。B0 审计把每对落到 item 级（54 处
  pub(crate) 与上述模块对的交集即升 pub 候选名单）。
- **门面 API 冻结**：examples 的 ~600 处深层引用（`rugra::type_system::datatype` 等 15+ 模块
  路径形态）= 公共 API 冻结面；B3 后以"examples 零改动编译通过"为门面完整性验收。

### 5.3 TypeFactory 单例 shim 与 crate 边界协同（TFSINGLE）

- 现状：typefactory.rs:2730 `static SHARED: OnceLock<Arc<RwLock<TypeFactory>>>` 全局单例
  shim（另 :147 `CANONICAL_UNKNOWN_BASE_1` OnceLock 常量缓存）。
- TFSINGLE step-2（PAREVAL-TF-PERARCH-WIRING-0002，Phase 1 排期）将 9 调用点全量穿参去
  shim，TypeFactory 变 per-Architecture 显式状态。
- **协同结论**：TFSINGLE 必须先于 Phase B 落地（§4.4 判据 4）。去 shim 后，未来 types 组
  若经破环程序独立成 crate，其边界上无全局静态隐耦合（OnceLock 跨 crate 虽合法但属隐式
  全局态，穿参形态使依赖显式化、per-Architecture 生命周期清晰）。step-2 未落地前 B3 不启动。
- typefactory.rs 本体在 SCC[60]（经 type_system/mod→funcdata 族互达），B3 随 core 整体迁移，
  单例问题不阻塞三条切割线。

### 5.4 破环程序 C（可选，逐项设计）

| 票 | 环边 | 手法 | Ghidra 依据 | 门禁 |
|---|---|---|---|---|
| C0 | E11 action→analysis | action.rs 的注册表引用改经既有 Action 基类 trait 面（或 analysis 并入 core——若 core 单 crate 则此边合法，仅在未来拆 analysis 时需处置） | action.hh 纯基类；universalaction.cc 才是注册点 | canon cmp + 注册面 fixture |
| C1 | E5 address→varnode | 删 address.rs:2010 `functional_equality` 副本，调用点改 `crate::expression::functional_equality`（正主已在，GETPARAM 车道证实） | expression.cc:520-526 | canon cmp + expression 既有 fixture 回归 |
| C2 | E2/E6 typeop→printc（+typeop→op 评估） | `as_printc_mut` Any-downcast 改为 PrintLanguage trait 虚方法分发（Ghidra 形态：TypeOp::print 经 PrintLanguage 虚派发，printc.hh:8-13 printc.cc 同族 override） | typeop.hh:25（printlanguage 单向）；printc.cc 无反向 | printc 域机制 B 差分 + typeop 52 push 族 fixture（MIGW1-TYPEOP-0002 交付后） |
| C3 | E3/E4 varnode→funcdata、block→funcdata | 签名移居：`get_use_point` 移 funcdata.rs（Ghidra 语义归属不变——Varnode 方法变 Funcdata 侧自由函数或扩展方法，调用点机械改写）；block.rs 5 处 `fd: &mut Funcdata` 函数同款评估 | varnode.hh:214 前置声明形态；block.cc 同 | varnode/block 域 B2 fixture + canon cmp |
| C4 | E8 marshal→space | 执行期定位 marshal.rs 引用 AddressSpace 的具体签名（预计 1-2 处），改经 foundation 内 trait 或移位 | space.hh:22-23 单向（marshal 在下） | marshal 域 fixture |
| C5 | E10 varmap→heritage、fspec→varmap、fspec→heritage 反向边 | 逐边核验具体函数后：调用反转（经参数穿入）或函数移居正确层 | heritage.hh:23/varmap.hh:22/fspec.hh:22-23 的单向 include | 各域机制 B/C 门禁 |

每项完成后重跑 §1 测绘脚本验证目标环边消失、SCC 收缩；**全部完成前不得宣称 core 可按草案层
拆分**。E1/E7/E9/E12（忠实互引/枢纽/胶水）永不破——它们是 Ghidra 架构本体。

---

## 6. 风险登记

| # | 风险 | 缓解 |
|---|---|---|
| R1 | runner 重钉级联被低估（36 pin×2 轮 + 28 overlay） | A0 冻结名单+逐个重跑绿才算完；重钉程序按 AGENTS 双形态纪律 |
| R2 | align_gate 谓词漏改 → 编辑门静默失效 | 机制 F 自检进 CI；CS 步骤把"谓词命中 crate 文件"写进 hook 自测 |
| R3 | 并发 agent 在执行窗口内开新票用旧路径 | 触发判据 2/3（零待并+wave 边界）+ A0 看板清扫 + 执行期公告 |
| R4 | `#[path]` 与 rust-analyzer/工具链兼容性 | 主流工具全支持；A1 试点步先行验证（foundation 组最小） |
| R5 | B3 门面再导出丢 pub(crate) 项 → 编译断裂 | B0 全量审计（54 处）先行；编译期即暴露、无静默风险 |
| R6 | build.rs C++ 构图随迁破坏 SLEIGH 链 | B2 独立步+`build_locked_x86_64_sla.sh`+ffi-test 全量回归 |
| R7 | capability.rs 孤儿（零生产边）被误当可删 | 不可删——capability.hh 对应物在账本内；执行期单独票决定接线或保留（Ghidra capability 注册体系是 architecture 构建期组件） |
| R8 | 路径搅动作废在飞分支（root 已裁决的背景约束） | 触发判据硬门；执行期任何新分支必须基于移动后 master |
| R9 | docs/api 镜像移动与 check_doc_sync 的 staged 判定竞态（同 commit 内 .rs+.md 同移） | 每步 commit 同时含两者（铁律 3 同 commit 文档同步） |

---

## 7. 票登记

主票 CRATESPLIT-MIGRATION-0001（设计 DONE / 执行 OPEN-待触发）+ 子票骨架已登记
docs/TODO_BOARD.md（CRATESPLIT 节）。子票：A0-A10（Phase A 十一步）、B0-B4（Phase B）、
C0-C5（可选破环）、R7（capability 接线裁决）。执行触发由 root 按本蓝图 §4.4 判据拍板。

## 附：本蓝图实测数据复现口径

- 依赖图：deps_map3.py（生产/测试分离 + brace use 解析 + lib.rs 再导出归位 + Tarjan SCC +
  缩图层）；prod_edges.tsv（557 边）/test_edges.tsv（184 边）。
- Ghidra include 图：ghidra_inc_graph.py（226 文件、零环、23 层）。
- 脚本与边表归档：`/dev/shm/rugra-reports/cratesplit-evidence/`（内存盘，重启即丢——
  复现只需对 src/ 与锁定 oracle cpp 树重跑两脚本，关键结论已全部内嵌正文）。
- 关键 grep 事实（防内存盘丢失，正文已引用）：typeop.hh:25、varnode.hh:214、op.hh:21、
  space.hh:22-23、marshal.hh:19-20、heritage.hh:23、varmap.hh:22、fspec.hh:22-23、
  address.rs:2010、typeop.rs:65、typefactory.rs:2730、lib.rs:126-127、Cargo.toml:6。

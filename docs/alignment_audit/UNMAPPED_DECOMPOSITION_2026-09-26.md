# 未映射 4956 定义四类分解报告（2026-09-26，车道 DECOMP）

> **任务**: 执行 AGENTS.md「对齐 Oracle」节遗留的"未映射三类分解"——把 REGEN 账本的 4956 条未映射定义
> 逐条判入 **SLEIGH 替代层 / 胶水吸收 / 未链接 / 真缺失**，产出可执行的 Rust 化移植路线图。
> **Oracle**: `Ghidra_12.0.4_build` / `e40ed13014025f82488b1f8f7bca566894ac376b`（114 `.cc` + 114 `.hh`）。
> **数据源**: `docs/alignment_audit/FUNCTION_LEDGER.json`（REGEN 重生成版，checkpoint `80ffb7d1`，
> definitions=9494 / mapped=4538 / unmapped=4956，ctags `Universal Ctags 6.2.0(d8622b793)`）。
> **分类工具**: `/dev/shm/rugra-reports/decomp/`（classify.py v1→classify2.py v2，附最终分类
> 明细 classified_final.json；本报告全部数字由脚本重放可得）。
> **写域纪律**: 本车道只写 `docs/alignment_audit/`、`docs/TODO_BOARD.md` 与内存盘工具；`src/` 与账本零触碰。

## TL;DR

| 类别 | 数量 | 占 4956 | 一句话定义 |
|---|---:|---:|---|
| **SLEIGH 替代层** | **1181** | 23.8% | SLEIGH 编译器/运行时翻译器域定义，由 `sleigh_shim`（C++ FFI 承载 Ghidra 自家 `Sleigh`）+ iced-x86 lifter 替代，Rugra 永不运行该域代码 |
| **胶水吸收** | **383** | 7.7% | `.hh` 单行 getter/setter/ctor/dtor 内联，且所属类已有 ≥3 条映射——行为由 Rust 语言结构（字段访问/构造/Drop/derive）吸收 |
| **未链接** | **747** | 15.1% | src/ 中存在可指名的疑似对应物（同名同类/同模块同名/孪生定义），仅缺 `// Ghidra:` 注解边——REGEN 可批量链接 |
| **真缺失** | **2645** | 53.4% | 以上皆非的真移植缺口；分三层：主管线 1799 / UI-控制台桥 618 / 分析外围 228 |
| **合计** | **4956** | 100% | = REGEN 账本未映射总数，闭环零残差 |

映射率展望：REGEN 批量链接未链接 747 条后，注解映射 4538→5285（47.8%→55.7%）。

---

## §1 方法与启发式

分类器两级流水（v1 → 抽样 → 修正 → v2 → 全量重跑 → 再抽样）：

**判序**（每条未映射定义依次尝试）:
1. **域规则（SLEIGH）**: 文件 ∈ SLEIGH 替代层文件集（§3）→ `sleigh`。
2. **T-twin**: 同 `(文件簇, qualified_name)` 组内存在已映射兄弟定义（`.hh` 内联 def 与 `.cc` 外线 def、
   const 重载对、部分 ctor 重载族）→ `unlinked`（机械可复制边）。
3. **U1-class**: Rust 生产函数（非测试/非声明）中存在 owner 类名与 Ghidra scope 末段类名相同、
   且 snake_case 名（含 get/set/is/has 剥离形）命中的函数 → `unlinked`。owner 解析覆盖 `impl:` 与 `trait:`。
4. **U2-module**: 精确 snake 名命中 + 命中函数所在模块 ∈ 该 Ghidra 文件簇的**证据模块集**
   （由该簇已映射条目的 Rust 模块反推）→ `unlinked`。
5. **胶水**: `source_kind==hh` 且函数体 ≤2 行且形态 ∈ {ctor, dtor, get/set/is/has/num/size/empty 前缀访问器}
   且所属类已有 **≥3** 条映射 → `glue`。
6. 其余 → `missing`，并按文件簇分层（主管线=簇内有映射且非豁免域 / UI-控制台桥 / 分析外围）。

**v1→v2 改进（由首轮抽样驱动）**:
- 删除 U3-unique（全局唯一名跨子系统撞名，抽样 7/15 FP，<80% 阈值触发整改）；自由函数改走模块证据门。
- 补 `trait:` owner 解析（block.rs 的 FlowBlock trait 方法族由此可命中）。
- 新增 T-twin 规则（97 条）。
- 胶水门槛从"类有任一映射"提高到"类有 ≥3 条映射"（ArchitectureGhidra 等仅 2 条映射的类不再误判）。
- **v2 全量后再修正一处**: typeop `push` 家族 52 条原判 unlinked（命中 `TypeOpBinary::push` 泛型分发），
  经读 `src/printc.rs:12143 op_binary` 证实其为泛型发射器（RUGRA-GLUE 注释自证"每个子类提供自己的
  lng->opXxx"未实现）→ 重判 `missing`（family=push-dispatch）。**该 52 条已列入 REGEN 排除清单，禁止链接。**

**known-FP 残余**: 未链接命中里 144/747 的 Rust 端是 `RUGRA-GLUE` 注解函数（marshal/prettyprint/arch 等），
抽样 1 条（`Element::addAttribute`→marshal.rs）为 TP，但该口袋精度低于整体，REGEN 链接时建议对其抽检 15%。

## §2 抽样核验（每类 15 条，seed=426926，人工逐条读 Ghidra 行 + Rust 行）

| 类别 | 抽样 | 正确 | 准确率 | 主要错误形态 |
|---|---:|---:|---:|---|
| unlinked（v2 后、口袋修正前） | 15 | 13 | **86.7%** | typeop push×2 命中泛型分发（已全量修正） |
| glue | 15 | 15 | **100%** | —（RuleIgnoreNan/TreeHandler/CallGraphNode 等类映射计数逐一复核） |
| sleigh | 15 | 15 | **100%** | 文件级域判定，逐条核对文件归属与 shim 覆盖路径 |
| missing | 15 | 15 | **100%** | 2 条带家族注记（clone-family/析构内存模型吸收），无漏判 |

补验（非抽样、定向）: `MultiSlotDualAssign::fillinOutputMap`（modelrules 类已移植但该方法缺）✅、
`BlockGraph::emit`/`createVirtualRoot`（block.rs 无对应物）✅、`ActionRestructureVarnode::
protectSwitchPathIndirects`（coreaction.rs 仅有 TODO 注释关联的另一函数 protectSwitchPaths）✅
——真缺失判定在高价值点位成立。

## §3 SLEIGH 替代层（1181 条）

| 子域 | 数量 | 文件（unmapped 条数） |
|---|---:|---|
| SLEIGH 编译器域（Rugra 消费预编译 `.sla`，编译器永不运行） | 1123 | slghsymbol.hh 173 / slghsymbol.cc 170 / slgh_compile.cc 148 / slghpatexpress.cc 128 / slghpatexpress.hh 107 / slghpattern.cc 58 / context.hh 57 / semantics.hh 54 / semantics.cc 51 / slghscan.cc 48 / slgh_compile.hh 42 / slghpattern.hh 38 / filemanage.cc 19 / context.cc 11 / slghparse.cc 11 / slaformat.cc 7 / filemanage.hh 1 |
| SLEIGH 运行时翻译器域（经 shim 进程内运行） | 58 | sleigh.cc 33 / sleighbase.cc 15 / sleighbase.hh 7 / sleigh.hh 3 |

**依据**（结构证据，非抽样推断）:
- `sleigh_shim/rugra_sleigh.cpp:336` 直接 `new Sleigh(&loader,&context)` 并以 `<sleigh>` XML 装载
  预编译 `.sla`——运行时翻译（sleigh.cc/sleighbase.cc 的 Sleigh/SleighBase）全部发生在 shim 内；
- `src/sleigh_ffi.rs` 与 `src/disasm/sleigh_lift.rs` 无任何 `// Ghidra:` 注解映射（纯 FFI 胶水），
  x86_64 路径走 `src/disasm/x86_64.rs`（iced-x86）；
- 编译器域（slgh_* / semantics / slaformat / context[ParserContext/Token] / filemanage）在 Rugra
  无任何调用面：`sleigh_specs/` 为预编译产物。
- **边界澄清**（防误伤）: `pcodecompile.*`（33 条已映射，pcodeparse.rs 移植）、`pcodeparse.*`、
  `inject_sleigh.*`（pcodeinject.rs 移植）、`unify.*`（unify.rs 移植）、`grammar.*`（grammar.rs 移植）
  **不在**替代层——它们是反编译主管线的 p-code/规则设施，与 SLEIGH 编译器无关。
  codedata 貌似 SLEIGH 实为 Iface 控制台工具（归 UI-控制台桥）。

**B2 语义**: 本类不宣称行为 MATCH，状态保持 `UNTESTED`。替代实现按 AGENTS 须证明"同一可观测输入下
行为等价"——对 SLEIGH 域的等价证明单位是**翻译器整面**（shim 级 fixture：同 `.sla` + 同指令字节流 →
p-code 序列逐条对比），非逐函数。在 Rugra 只服务 x86_64 反编译的当前目标下，该域维持替代层结论、
不进入移植 wave。

## §4 胶水吸收（383 条）

判定要件全部满足: `.hh` 内联 ≤2 行 + 访问器/ctor/dtor 形态 + 所属类 ≥3 条映射。

- **文件分布 top**: fspec.hh 34 / type.hh 29 / block.hh 28 / op.hh 25 / funcdata.hh 22 / ruleaction.hh 22 /
  varnode.hh 21 / prettyprint.hh 17 / typeop.hh 16 / database.hh 15 / printlanguage.hh 14 / printc.hh 13。
- **类分布 top**: PcodeOp 23 / Funcdata 21 / Varnode 20 / FuncProto 15 / PrintLanguage 14 / FlowBlock 13 /
  PrintC 13 / Datatype 11 / ProtoModel 10。
- **机读清单**: `/dev/shm/rugra-reports/decomp/glue_documentation_candidates.json`（ghidra_id/file/line/reason）。

**后续路径**: 胶水吸收 ≠ 自动 MATCH。建议（不阻塞本 wave）: 对 top 类做**类级 RUGRA-GLUE 文档化**
（在对应 Rust 结构体/impl 块头部一次性登记该类吸收的内联访问器族，例: `// RUGRA-GLUE: absorbs
varnode.hh:186-309 one-line accessors (23)`），避免 383 条逐函数注解噪音；涉及可观测行为的
（如 `getDisplay` 参与输出）仍需 B2 fixture 逐条裁决。

## §5 未链接（747 条）——REGEN 批量链接输入

| 规则 | 条数 | 其中 Rust 端已有其他映射边（多目标边） | 置信 |
|---|---:|---:|---|
| T-twin（同名同簇兄弟已映射） | 97 | —（边在兄弟 def 上） | 机械 |
| U1-class（同类同名命中） | 422 | 252 | 高 |
| U2-module（证据模块+精确名） | 228 | — | 中高（含 144 条 RUGRA-GLUE 命中口袋） |

样例边（完整 747 条见 `/dev/shm/rugra-reports/decomp/unlinked_link_candidates.json`）:
- `varnode.hh:236 Varnode::isExplicit` → `src/varnode.rs:1243 fn is_explicit`（U1）
- `xml.cc:2426 Element::getAttributeValue` → `src/marshal.rs:771 fn get_attribute_value`（U1，.cc 侧漏链实例）
- `database.cc:2405 ScopeInternal::findByName` → `src/database.rs:1811 Scope::find_by_name`（U2，方法上提到 trait）
- `address.hh:277 Address::Address` → 兄弟 `address.cc:91` 已映射（T-twin）

**给 REGEN 协议行的输入**:
1. 链接顺序建议 **T-twin（97）→ U1（422）→ U2（228）**；T-twin 可由生成器按
   `(cluster, qualified_name)` 机械复制边，无需人工。
2. 多目标边: Rust 记录的 `ghidra_mappings[]` 本就是列表——U1 中 252 条"Rust fn 已链接到同族另一 def"
   是 C++ 重载/虚函数族在 Rust 单函数坍缩的正常形态（如 `opbehavior.rs evaluate_unary` 承载全部
   `OpBehaviorX::evaluateUnary`），生成器只需支持一条 Rust fn 挂多条 `// Ghidra:` 注解行。
3. **排除清单（禁止链接）**: typeop.hh 各 `TypeOpX::push` 共 52 条——`printc.rs op_binary` 为泛型
   分发，per-op 打印语义未承载，链接即制造假映射。
4. U2 口袋（Rust 端为 RUGRA-GLUE 注解的 144 条）链接前抽检 15%。
5. 预期效果: 注解映射 4538 → 5285（55.7%），`--check` 断言同步更新。

**召回下界声明**: 747 是保守值。已知漏检形态: ① 类级注解/改名移植（`NameRecommend` 整类在
varmap.rs:2177 以类注解存在，fspec 侧 6 条方法被判缺失）；② 迭代器改名族（`Funcdata::beginLoc/endLoc`
等 24 条对应 Rust 迭代器方法但名不同）。这两族已按"真缺失"记账并在票面标注"先行核验是否已存在对应物"。

## §6 真缺失（2645 条）分层与分布

| 层 | 数量 | 内容 |
|---|---:|---|
| **主管线相关** | **1799** | 簇内有 Rust 映射证据的核心模块残缺（下表 top18 覆盖 ~92%） |
| **UI-控制台桥**（AGENTS 豁免候选） | **618** | ifacedecomp 144 / interface 57 / database_ghidra 55 / codedata 52 / ghidra_arch 51 / ghidra_process 32 / testfunction 28 / inject_ghidra 21 / ghidra_context 18 / loadimage_bfd 18 / sleighexample 14 / bfd_arch 12 …（Ghidra 宿主协议后端 + 控制台命令 + 测试 harness + 独立加载器） |
| **分析外围** | **228** | rulecompile 80 / emulate 47 / emulateutil 33 / printjava 17 / multiprecision 16 / expression 13 / callgraph 8 / paramid 7 / capability 4 / error 3 |

### 主管线真缺失 per-module 表（top 18；LOC=Ghidra 定义行数合计，复杂度=平均跨度）

| 模块簇 | 缺失 | 结构吸收* | 实移植 defs | Ghidra LOC | 复杂度 | 特征 |
|---|---:|---:|---:|---:|---:|---|
| typeop（+printlanguage/printc 钩子） | 160 | 0 | 160 | 936 | 5.8 | 52 条 per-op `push`（per-op C 输出语义）+ TypeOp 子类族 56 整类缺失（FloatInt2Float 等）+ getInputCast/getOutputToken |
| fspec | 136 | 0 | 136 | 982 | 7.2 | 参数绑定模型: ParameterBasic 13 / ParameterSymbol 12 / ProtoStoreSymbol 10 / ProtoParameter 4 / ParamListMerged 4 整类 + FuncProto/ProtoModel 方法残项 |
| block | 102 | 0 | 102 | 945 | 9.3 | BlockGraph::emit/createVirtualRoot、结构化输出面残项（96 partial-class） |
| funcdata | 77 | ~24（迭代器族） | ~53 | ~370 | 5.4 | printRaw/printVarnodeTree、loc/op 迭代器改名族（先行核验）、核心维护方法 |
| database | 76 | ~13（MapIterator/NullSubsort） | ~63 | 560 | 7.4 | Scope/Symbol 查询补全、UnionFacetSymbol/ExternRefSymbol 符号子类 |
| type | 88 | 15（clone） | 73 | 682 | 7.9 | Datatype 方法残项、TypeFactory 告警面 |
| printc | 68 | 0 | 68 | 315 | 4.6 | 单例族: emitSymbolScope/pushMismatchSymbol/pushImpliedField/doEmitWideCharPrefix… |
| coreaction | 101 | 62（clone） | 39 | 454 | 7.0 | **protectSwitchPathIndirects（53 行算法）** 等Action 方法 |
| sleigh_arch | 48 | 0 | 48 | 487 | 10.1 | LanguageDescription 等 spec 装载面（独立运行路径） |
| marshal | 44 | 0 | 44 | 343 | 7.8 | encode/decode 家族残项 |
| architecture | 41 | 0 | 41 | 594 | 14.5 | 高复杂度散点（avg span 14.5） |
| xml | 40 | 0 | 40 | 478 | 11.9 | TreeHandler/SAX 面 |
| blockaction | 43 | 7（clone） | 36 | 375 | 9.4 | 结构化残项（机制 C 白名单域） |
| action | 30 | 0 | 30 | 256 | 8.5 | ActionGroupList/注册面 |
| jumptable | 28 | 0 | 28 | 338 | 12.1 | JumpModel 虚族残项 |
| userop | 27 | 0 | 27 | 246 | 9.1 | UserPcodeOp 面 |
| subflow | 27 | 12（clone） | 15 | ~66 | 2.5 | 小残项 |
| ruleaction | 239 | 235（136 clone + 99 Rule ctor 注册族 + stragglers） | **~15** | ~90 | 3.1 | **实移植缺口极小**——Rule 子类本体已移植，残缺集中在 clone/ctor 工厂形态（需裁决而非移植） |

\* 结构吸收 = clone-family（Action/Rule 工厂复制，Rust 注册表模式替代）+ Rule 子类构造器 +
Rust 迭代器/内存模型吸收族——**不是零工作**，但工作形态是"等价裁决 + B2 fixture"而非逐行移植
（AGENTS 铁律 1.5: 替代实现须证明等价，不自动算数）。

### 移植优先级排序（输出面影响 × 缺口 × 依赖）

1. **fspec**（136）——参数绑定/原型模型直接决定函数签名与参数命名输出（curl/httpd 差分面）；
2. **typeop**（160）——per-op 打印语义直接决定 C 文本（printc 门禁白名单上游）；
3. **block+blockaction**（102+36）——BlockGraph emit/结构化残项直接决定控制流文本形态；
4. **funcdata**（~53 实移植）——核心 op/varnode 维护面，funcdata 是最高扇出地基之一；
5. **database**（~63 实移植）——Scope/Symbol 查询面，varmap 命名域依赖；
6. （wave-2 候选）printc 68 单例族 / coreaction 39（protectSwitchPathIndirects 高价值）/
   type 73 / marshal+xml encode-decode 家族 / architecture / jumptable / userop / sleigh_arch。

### 工作量预估（Rust LOC ≈ 1.6×Ghidra LOC 经验系数 + 每定义一份 B2 fixture）

| 票 | 实移植 defs | Ghidra LOC | 预估 Rust LOC | 规模 | B2 fixture 数 |
|---|---:|---:|---:|---|---:|
| fspec | 136 | 982 | ~1570 | XL | 136 |
| typeop | 160 | 936 | ~1500 | XL | 160（push 族可按 op 家族合并 fixture） |
| block+blockaction | 138 | 1320 | ~2110 | XL | 138 |
| funcdata | ~53 | ~370 | ~590 | M-L | 53（迭代器族先核验再定） |
| database | ~63 | ~470 | ~750 | L | 63 |

## §7 与既有机制的关系

- 本报告只做**静态分解**，不改任何 `behavior_status`；全部 9494 定义完成度仍以 B2 逐函数门禁为准。
- 移植票执行时: fspec→varmap 域改动触发机制 B 差分门禁；block/blockaction 触发机制 B + **机制 C
  独立复核**（核心算法白名单）；typeop/printc 同为白名单。
- UI-控制台桥 618 条: AGENTS.md 明文豁免"纯 UI/控制台桥接"，不进入移植 wave；其中 Ghidra 宿主协议
  后端（*_ghidra 族）若未来要跑 decomp 协议对拍，需按替代实现路径另行裁决（登记为后续票，未开）。
- SLEIGH 替代层 1181 条: 维持替代结论；shim 级 fixture 票未开（当前无非 x86 语料需求）。

## §8 残余风险

| # | 风险 | 缓解 |
|---|---|---|
| 1 | 未链接 747 中 U2/RUGRA-GLUE 口袋残余 FP（估 5-15%） | REGEN 链接分批 + 口袋 15% 抽检；链接是可回滚注解，不涉行为声明 |
| 2 | 未链接召回不足（改名/类注解族判入真缺失） | funcdata 迭代器族等已在票面标"先行核验" |
| 3 | 胶水吸收的类级文档化尚未落地（383 条无 per-fn 注解） | 建议随 MIGW1 各票在触碰对应类时顺手登记类级 RUGRA-GLUE 头注 |
| 4 | 结构吸收族（clone/Rule-ctor，~411 条）无 B2 fixture | 单列"工厂等价裁决"票（未开），不混入移植票冒充完成 |

## 附录: 复现

```bash
python3 /dev/shm/rugra-reports/decomp/classify2.py   # 四类 + 闭环断言（sum=4956）
# 产物: classified_final.json（2645+747+383+1181 明细）、unlinked_link_candidates.json、
#       glue_documentation_candidates.json、sleigh_replacement_layer.json（同目录）
```

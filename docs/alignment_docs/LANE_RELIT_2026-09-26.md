# LANE RELIT — 2020–2026 逆向/反编译论文系统测绘与增强杠杆地图

> 日期 2026-09-26 | 车道 RELIT（纯研究零 src 零 commit；MB18 并 master 期间未写主仓任何文件）
> 前置：LANE_DECBENCH_2026-09-26.md（三指标定义+榜单现状）、LANE_ACADEMIC_SURVEY_2026-09-26.md（头部论文已覆盖，本报告**不重复展开**，只做增量深挖）、RUGRA_MASTER_ROADMAP_2026-09-26.md（三护城河+Phase 4）
> 方法：websearch/webfetch 一手实查（USENIX/NDSS/EuroS&P/arXiv/ACL Anthology/ICLR proceedings/oaklandsok/官方 PDF）；2026 年 ACM CSUR 投稿综述（arXiv 2608.24955，72 篇一手研究 + 完整参考文献表）作为系统性骨架逐条核验 venue。所有条目标注验证级别：**[一手]** = 本轮直接取到官方页面/PDF；**[综述转引]** = 经 2608.24955 参考文献表或 SAILR/DecompileBench 引文网络确认（venue 精确，方法细节未读原文）。

---

## 〇、执行摘要（TL;DR）

1. **结构化域 2020–2026 没有出现 SAILR 之后的算法突破**。Euro S&P'25 的 Behner SoK 是系统化而非新算法；最新增量只有 ICSME'25 的 jump-table-agnostic switch 恢复（GCC -O0 口径）。GED 上限杠杆仍是 SAILR 三档 + **de-inlining（ERASE ICSME'24）**——后者是 ACADEMIC_SURVEY 完全遗漏的 O2 切片杠杆。
2. **类型恢复域 2024–2025 爆发，是最大的学术弹药库**：TRex（USENIX Sec'25，演绎式类型重构，123/125 二进制胜 Ghidra，artifacts available）、BinSub（SAS'24）、Manta（ASPLOS'24，**已是 Ghidra 插件**）、TyGr（Sec'24）、DRAGON（BAR'25，置信度门控）、STRIDE（n-gram，开源无 GPU）、XTRIDE（CODASPY'26）、Idioms（NDSS'26 联合代码+类型）。**kuna roadmap #261 无任何 ML/类型推断计划 → 护城河③有 8 篇一手文献支撑，且 type_match 榜首（LLM codex 9.27%）已证明该维度上限超过全部传统引擎。**
3. **byte_match 域拿到关键风险证据**：Decompile-Diverge（arXiv 2609.05370）实测"LLM 精修把 Ghidra 可编译率 75%→90% 的同时行为保持率 74%→62%"——可编译性不是语义门禁。我们 best-of-N 选择器必须三重门禁（汇编 diff + arity + 可选行为差分），这反而把我们与 kuna 单管线的差距变成设计优势。
4. **DirTy 与 RTD 两个任务点名目标经 6 种渠道（websearch×4、dblp×2、Semantic Scholar×2、arXiv API、USENIX 议程）无法在本环境验证**——如实标注"需深挖"，未编造（§四）。
5. **首推三件**（详见 §三）：① TRex 式确定性类型重构层（type_match 主杠杆）；② best-of-N 三重门禁选择器（吸收 Decompile-Diverge 教训）；③ STRIDE n-gram sidecar 起步（工程量最小的 ML 类型层管道）。

---

## 一、分域论文档案

### A. 结构化域（GED 落分面）

任务背景：phoenix（USENIX Sec'13，Brumley/Schwartz 系）→ DREAM（NDSS'15）→ Combing（AsiaCCS'20）→ SAILR（USENIX Sec'24）主线已由 ACADEMIC_SURVEY §1.1 覆盖，SAILR 论文附带了前三者的开源复现。以下为本轮新增。

| 论文 | venue/年/作者[验证] | 核心方法 | 改进什么 | 开源 | 落地性评估（Rugra 架构） |
|---|---|---|---|---|---|
| **SoK: No Goto, No Cry? The Fairy Tale of Flawless Control-Flow Structuring** | Euro S&P 2025；Behner/Enders/Padilla，Fraunhofer FKIE [一手：eurosp2025.ieee-security.org + oaklandsok.github.io/papers/behner2025.pdf] | 结构化技术系统化：模式匹配系 vs 模式独立系两大家谱、挑战分类 | 不改算法，给**选型地图** | SoK PDF 开放 | ★★★★ ENH-2 开工前必读：给出"哪些结构化变体值得 port"的独立判据（dewolf 团队=DecBench 榜上 dewolf 背后团队）。工作量=纯阅读。 |
| **A Jump-Table-Agnostic Switch Recovery on ASTs** | ICSME 2025；Enders/Behner/Padilla [一手：经 CSUR 参考文献表确认 venue] | 在 Ghidra 输出的 AST 上聚类"同一 selector 的比较簇"，把 if-else 链改写回 switch，不依赖跳转表模式 | switch 语义恢复（GED 的 switch 形状） | 需深挖（FKIE 系一般随 dewolf 发布） | ★★★ 小而准的增量杠杆：Ghidra 的 switch 恢复（jumptable.rs 域）在 non-jump-table lower 形态上确实漏；但论文口径仅 GCC -O0，O2 下的形态覆盖**需深挖**。工作量=中（AST 后处理 pass，print 层之后）。 |
| **dewolf: Improving Decompilation by Leveraging User Surveys**（含 PIdARCI） | BAR 2022；Enders 等，FKIE [一手：CSUR 参考文献表] | congruence 分析（合并语义等价变量）、图逻辑引擎、指针算术→数组下标改写；PIdARCI 自动合成编译器惯用语模式库 | 可读性/表达式简化（间接 GED） | dewolf 全开源 | ★★★ **警示范本+零件库**：dewolf 在 DecBench 全量榜 GED 仅 3.65%（rank 8）——论文的 goto/可读性叙事与 GED 分数错位，说明这些变换不改善结构保真。但其 congruence/pointer-transformation pass 可作为 best-of-N 的**第 N+1 个候选变体**。 |
| **ERASE: Optimizing Decompiler Output by Eliminating Redundant Data Flow in Self-Recursive Inlining** | ICSME 2024；R. Zhang/Y. Cao/R. Liang/P. Hu/K. Chen，清华 [一手：CSUR 参考文献表] | LLM 引导 + 递归符号执行 + 功能相似度，识别**内联进调用者体的库函数体并恢复为函数调用**（de-inlining） | GED（O2 切片！源码里有调用、内联后消失）+ 紧凑性 | 需深挖 | ★★★★（条件性）ACADEMIC_SURVEY 遗漏的 O2 杠杆：DecBench 的 O2/O2-noinline 两个优化级正是内联重灾区，恢复调用=结构向源码靠拢。但依赖 LLM+符号执行，只能做**增强轨可选 pass**；先在 O2noinline 切片试点。工作量=中高。 |
| **DREAM++（Helping Johnny to Analyze Malware）** | IEEE S&P 2016；Yakdan 等 [综述转引] | DREAM 之上的常量传播/CSE/Z3 表达式简化 + 库函数 outlining（内联体→调用）+ API 语义命名 | 可读性/紧凑性/ outlining | 随 angr/DREAM 系 | ★★★ outlining 思想与 ERASE 同源但规则版（无 LLM）——**规则优先，LLM 兜底**的组合可先做规则半边。 |
| phased structuring | — | mahaloz 自认的 open problem，本轮再次检索（含 angr DeepWiki 现状）**确认仍无论文成文** [一手：mahaloz.re/dec-history-pt1/pt2] | GED | 无 | 维持 ACADEMIC_SURVEY 结论：原创研究位，非可移植算法。 |
| 结构化正确性警世线：**Bin2Wrong** | USENIX ATC 2025；Yang & Nagy，Utah [一手：usenix.org/system/files/atc25-yang-zao.pdf] | 变异源码构造×编译配置空间（编译器/优化级/平台/ELF-PE-Mach-O）fuzz 反编译器，曝配置特异性语义错误 | （测试基建，防 GED/语义回归） | 开放获取 PDF | ★★★★ 回归基建候选：把 Rugra 纳入其变异空间=免费的大规模语义回归语料；也可借鉴其配置空间做我们自己的对拍矩阵。 |

**结构化域结论**：GED 的文献杠杆= SAILR 三档（已立项 ENH-2）> ERASE de-inlining（O2 切片新杠杆）> switch AST 恢复（小增量）> dewolf pass（候选变体）。Behner SoK 是 ENH-2 的设计输入。**没有可抄的新一代结构化算法**——SAILR 之后领域处于"系统化+小修补"平台期，与我们 Phase 0 残差收敛（逐函数≈Ghidra）+ SAILR 增强的路线自洽。

### B. 类型恢复域（type_match 落分面）

榜单语境：type_match 全场低（binja 8.83 > angr 8.47 > ghidra 7.56 > kuna 6.91），**榜首是 LLM codex@9.27**——该维度的机器学习上限已被证明。

| 论文 | venue/年/作者[验证] | 核心方法 | 改进什么 | 开源 | 落地性评估 |
|---|---|---|---|---|---|
| **TRex: Practical Type Reconstruction for Binary Code** | USENIX Sec'25（pp.6897–6915）；Bosamiya（MSR）/Woo/Parno（CMU） [一手：usenix.org presentation 页] | **演绎式（deductive）类型重构**：不猜源类型，构造"行为捕获型"类型（behavior-capturing types） | 类型质量：**123/125 二进制上优于 Ghidra**（论文自报） | USENIX Artifacts Available/Functional/Reproduced 三徽章 | ★★★★★ 本报告最高优先。确定性演绎=天然契合我们的门禁哲学（无幻觉、可差分、可进 fixture）；一手证据显示正面击败 Ghidra（type_match 榜上 Ghidra 7.56% 的天花板可抬）。工作量=中高（需读 artifact 定移植形态；实现语言/artifact 结构**需深挖**）。 |
| **BinSub: The Simple Essence of Polymorphic Type Inference for Machine Code** | SAS 2024（SPLASH）；I. Smith 等 [一手：arXiv 2409.01841 + 2024.splashcon.org + HotSoS'25 幻灯] | 代数子类型化（MLsub 系）替代 Retypd 的 WPDA 约束求解；保留 Retypd 推导保真，效率/表达力更好 | 类型推断的规模与精度（Retypd O(N³) 大二进制跑不完的问题） | arXiv+幻灯；代码需深挖 | ★★★★ Retypd 血统的现代化替品。angr 生态（=kuna 母体）有 typeink（Retypd port）——**kuna 若做推断层大概率走 Retypd/typeink**，我们先上 BinSub 即差异化。工作量=中高（约束系统 port）。 |
| **Manta: Hybrid-Sensitive Type Inference Toward Bug Detection in Binaries** | ASPLOS 2024；Sevie Zhou 等 [一手：seviezhou.github.io/files/asplos24fall-final196.pdf] | 混合敏感（指针+整数混合的精确处理）类型推断，**Ghidra 插件形态**，快于 Retypd | 静态分析的变量类型精度/召回 | 论文 PDF 开放；插件开源情况需深挖 | ★★★★ 关键卖点=**已验证可挂在 Ghidra 上**（与我们 PrintC/varmap 血统同源）；面向 bug 检测的类型面与 type_match 的 DWARF 对齐面部分重叠。工作量=中（插件逻辑 port 进 Rust varmap 侧）。 |
| **TyGr: Type Inference on Stripped Binaries using GNNs** | USENIX Sec'24；C. Zhu/Z. Li/A. Xue/A.P. Bajaj/W. Gibbs/Y. Liu/R. Alur/T. Bao/H. Dai/A. Doupé 等（Upenn+ASU 混编） [一手：usenix.org/system/files/usenixsecurity24-zhu-chang.pdf] | VEX IR 数据流图 + 轻量分析 + GNN；x64/x86/AArch64/Arm32/MIPS 五架构数据集（现存最大） | 类型推断准确率（自报超 DIRTY 和 OSPREY） | 开源（论文页） | ★★★★ ML 层主力候选之一。注意作者群=Upenn Alur 组+ASU sefcom（Bajaj/Gibbs/Doupé=Bao=Tian 系）——**与 kuna 同生态但 kuna roadmap 未吸收**（其 #261 无 ML 计划）。Rugra 走 P-code 图=天然同构（VEX→P-code 映射直接）。工作量=中（模型 sidecar ONNX/子进程）。 |
| **DRAGON: Predicting Decompiled Variable Data Types with Learned Confidence Estimates** | NDSS BAR 2025；C. Stewart/R.K. Gaede/J.H. Kulick [一手：ndss-symposium.org/wp-content/uploads/bar2025-final25.pdf] | GNN + **不确定性量化**（每次预测附置信度） | 类型预测 + **可信度输出** | BAR PDF 开放；代码需深挖 | ★★★★ **置信度门控**与我们的 gated 哲学完美咬合：高置信→直接应用（过重编译验证），低置信→弃用。论文自述"首个把 UQ 用于二进制类型推断 ML 的工作"。工作量=中。 |
| **STRIDE: Simple Type Recognition In Decompiled Executables** | arXiv 2407.02733，2024-07；H. Green/E.J. Schwartz/Le Goues/Vasilescu（CMU 系） [一手：arXiv 页 + github.com/hgarrereyn/STRIDE] | **n-gram 纯文本匹配**预测变量名+类型；自报与 DIRTY 竞争力但模型与开销小两个数量级 | 类型+命名，近零成本 | **GitHub 开源** | ★★★★★ 工程性价比之王：无 GPU、无深度模型、纯 n-gram 数据库匹配——ML 类型层的**最小可行起步**，先把管道/验证/门禁打通，再换强模型。工作量=小（数据库构建+匹配器）。 |
| **XTRIDE（Practical Type Inference: High-Throughput Recovery of Real-World Structures and Function Signatures）** | ACM CODASPY 2026；（mlsec.org 预印） [一手：mlsec.org/docs/2026-codaspy.pdf] | STRIDE 改进版：面向**部署性**（库/固件/标准件里反复出现的"真类型"），函数签名 n-gram 扩展 | 高吞吐真类型恢复（grounded prediction 端到端进反编译器类型系统） | 预印开放；代码需深挖 | ★★★ 直接展示了"n-gram 类型库**端到端接入反编译器**"的可行性——正是 STRIDE→Rugra 落地的参考实现。IDAHW 系背景对 DecBench 的嵌入式子集（cps）也有叙事价值。工作量=小–中。 |
| **Idioms: Neural Decompilation with Joint Code and Type Prediction**（+Realtype 数据集） | NDSS'26（NDSS 页面确认；arXiv 2502.04536）；Dramko/Le Goues/Schwartz（CMU） [一手] | LLM 微调**联合输出代码+全部用户自定义类型定义**；Realtype=更真实的类型语料；ExeBench 54.4% vs LLM4Decompile 46.3% | 端到端正确率（re-executability）与 UDT 恢复 | **github.com/squaresLab/idioms 开源**，模型放出 | ★★★（候选生成器定位）端到端模型本体不进主管线（铁律不变），但其"联合类型定义输出"思想可反哺增强轨：best-of-N 的 LLM 候选可用 Idioms 系列。另：neighbor-context 使 UDT 组合准确率 +63%——**类型恢复需要跨函数上下文**的设计输入。 |
| **Stir/StateFormer（Statistical Type Inference for Incomplete Programs）** | ESEC/FSE 2023；Peng 等 [综述转引 venue；arXiv 2304.03854 为其 Ghidra 复现篇，一手] | 静态(Stir)+动态(StateFormer)操作数行为建模 | 类型预测（O2 下） | 需深挖 | ★★☆ ML 层备选；其 Ghidra 复现篇（arXiv 2304.03854，ACADEMIC_SURVEY 已录）给出语料坑。 |
| **Benchmarking Binary Type Inference Techniques in Decompilers** | SURE Workshop 2025；Soni/Dutcher/Bao/R.Wang [一手：sure-workshop.org/accepted-papers/2025/sure25-8.pdf + CSUR 引] | **五引擎类型推断横评**（Hex-Rays/Binja/Ghidra/angr/Retypd-Ghidra-plugin），Nixpkgs 语料 O0/O2，函数级+变量级 | （度量方法学） | PDF 开放 | ★★★★ type_match 作战地图：给了各家类型强弱画像与典型错法（struct 识别、数组长度）；Rugra 增强轨的内部评估 harness 可直接抄其口径（DWARF 真值对齐法与 DecBench type_match 同族）。 |
| Retypd（前史锚点） | PLDI 2016；Noonan/Loginov/Cok [综述转引] | 多态机器码类型推断（CodeSurfer 上） | 类型推断奠基 | GrammaTech 系 | 血统说明：Retypd→BinSub（代数化）/→angr typeink（kuna 可能路径）——类型推断层的"GCC 家族树"。 |
| Osprey | S&P'21（ACADEMIC_SURVEY 已录） | 概率变量/结构恢复 | 类型 | 开源 | 维持原评估 ★★★。 |
| DirTy / RTD（任务点名） | **未能验证** | 见 §四 | — | — | 未能验证，不评估。 |

**类型域结论**：杠杆分三层——**确定性推断层**（TRex ★5 > BinSub/Manta ★4）：契合门禁哲学、可直接抬 type_match、kuna 完全没有；**ML 预测层**（TyGr/DRAGON ★4，STRIDE/XTRIDE ★5 性价比）：kuna roadmap 空白=护城河③，榜首已被 LLM 证明上限；**联合生成层**（Idioms ★3）：只做 best-of-N 候选。落地次序建议 STRIDE 起步（小）→ TRex（大而正）→ DRAGON 置信度门控（中）。

### C. 变量/函数命名域（可读性叙事，DecBench 无直接分）

DIRE(ASE'19)/DIRTY(Sec'22)/VarBERT(S&P'24)/DeMinify(FSE'23)/ReSym(CCS'24)/SymGen(NDSS'25)/GENNM(NDSS'25) 已在 ACADEMIC_SURVEY 覆盖（GENNM=NDSS'25 "Unleashing the Power of Generative Model in Recovering Variable Names from Stripped Binary"，Xu 等，本轮经 CSUR 参考表确认 venue [综述转引→一手 venue]）。新增：

| 论文 | venue/年[验证] | 方法 | 落地性 |
|---|---|---|---|
| **FuncRE（Learning to Find Usages of Library Functions in Optimized Binaries）** | IEEE TSE 48(10) 2021（Ahmed/Devanbu/Sawant） [综述转引] | RoBERTa+源级标记对齐，识别内联库函数使用 | ★★★ ERASE 的规则半边前身；与 de-inlining 杠杆同域。 |
| **AsmDepictor** | AsiaCCS 2023（Kim/Bak/Cho/Koo） [综述转引] | 汇编→函数名 Transformer 翻译 | ★★☆ 命名 sidecar 备选（不如 VarBERT 贴合）。 |
| **SymLM** | CCS 2022（Jin/Pei/Won/Lin） [综述转引] | caller/callee+指令上下文的函数名预测 | ★★☆ 同上；跨函数上下文思想与 Idioms 的 +63% 证据同向。 |
| **R2I: A Relative Readability Metric for Decompiled Code** | FSE 2024（Eom/Kim/Lim/Koo/Hwang） [一手：CSUR 引 + SK2 参考文献含 DOI 10.1145/3643744] | 31 个 AST 特征+逆向工程师问卷加权，归一化可读性分 | ★★★（叙事/排序）综述称其为**唯一为反编译量身定制的专用度量**；增强轨对外叙事与 best-of-N 软排序备选。工作量=小（特征提取器）。 |
| **认知复杂度改进（goto 间代码视为概念嵌套）** | ICPC 2026（Enders/Behner/Padilla） [一手：Semantic Scholar 引文页摘录] | goto→label 之间的代码按嵌套计权 | ★★★ best-of-N 软排序（goto 计数的更优替代——纯 goto 计数惩罚了源码里本来就有的 goto，与 SAILR 的"合法 goto"论点一致）。 |

**命名域结论**：对 DecBench 三指标零直接落分（type_match 比 type 不比 name），价值=对外叙事 + best-of-N 软排序。VarBERT 侧车维持 ENH-3 不变；R2I/认知复杂度作为选择器 tie-break 特征集的文献依据。

### D. 评估基准域（我们参赛策略的学术语境）

DecBench 本体、GED/CFGED 溯源（SAILR'24 + sailr-eval 开源 [一手：github.com/mahaloz/sailr-eval]、Decompile-Bench NeurIPS'25 已录）。新增/澄清：

| 基准/论文 | venue/年[验证] | 要点 | 对 Rugra 用途 |
|---|---|---|---|
| **DecompileBench**（注意与 Decompile-Bench 是两个东西） | **Findings of ACL 2025**，pp.23250–23267；Gao/Cui/Wang/Qin/Wang/Bolun/Chao Zhang（清华+IEE+PKU） [一手：aclanthology.org/2025.findings-acl.1194 + github vul337/DecompileBench] | 23,400 函数/130 个 **OSS-Fuzz** 真实程序；运行时行为验证 + LLM-as-Judge 双轨；横评 12 个反编译器 | ★★★★ 第三基准（DecBench+Decompile-Bench 之后）：**OSS-Fuzz 语料自带 fuzzing harness** → 行为差分门禁的现成弹药；runtime-aware 验证与我们 best-of-N 的行为门禁同构。 |
| **DecFuzzer** | 2020（Liu & Wang） [综述转引] | EMI（Equivalence Modulo Inputs）差分测试反编译器 | ★★☆ 前史锚点；Bin2Wrong 的思想祖先。 |
| **Cao et al.: Evaluating the Effectiveness of Decompilers** | ISSTA 2024（Y. Cao/R. Zhang/R. Liang/K. Chen，清华） [一手：CSUR 参考表] | Dsmith 随机程序生成器（带内嵌 checksum）+ 抽象符号比对，**免重编译**即可评正确性 | ★★★ 免重编译路径对我们有额外价值（byte_match abstain 的 ARM/PE 切片可用符号比对兜底）。需深挖 Dsmith 可用性。 |
| **DiscScope** | AsiaCCS 2025（Sirlanci/Yagemann/Lin） [一手：CSUR 参考表] | 原始/重编译二进制**并行符号执行到中间状态级**比对，差异定位到变量/栈偏移/语句 | ★★★★ 比文本 diff 强一档的正确性门禁（Decompile-Diverge 的静态版前身）；增强轨验收 oracle 候选。 |
| **D-Helix** | USENIX Sec'24（已录） | IR 真值差分 + TUNER 归因（关掉单个启发式定位根因） | 补充：其 **TUNER 按启发式开关归因**的设计，与我们 option-gated 增强/对拍矩阵直接同构——kuna 的 mine/triage 方法论同源，参考其实现可少走弯路。 |
| **Fidelity Taxonomy** | USENIX Sec'24（已录；本轮补作者：Dramko/Lacomis/Schwartz/Vasilescu/Le Goues [一手：USENIX Sec'24 Track 6 同场确认]） | 15 类/52 子码缺陷分类 | 维持 ENH-7。 |
| **ExeBench** | **MAPS 2022**（PLDI 周会；Armengol-Estapé 等，Edinburgh） [一手：dl.acm.org/doi/10.1145/3520312.3534867]（**纠错**：ACADEMIC_SURVEY 未给 venue，非 ICSE） | 4.5M 可编译 + 700k 可执行 C 函数带 I/O 例 | ★★★ LLM 增强层的训练/评估语料来源（Idioms/CoDe-R/D-LiFT 全用它）。 |
| **sailr-eval** | SAILR 论文管线 [一手：github.com/mahaloz/sailr-eval] | 26 个 Debian 包的编译-反编译-度量管线；支持 angr/IDA/Ghidra | ★★★★ 本地复现 GED 口径的官方参照（DecBench 的 GED 实现上游）。 |
| **（综述本体）The Evolution of Binary Decompilation in the Modern Era** | arXiv 2608.24955，2026-08，CSUR 在审；Abusabha 等（SKKU，Hwang 组——与 R2I 同组） [一手：全文抓取] | 66+6 篇 SLR、8 任务分类法、8 能力度量分类、14 开放挑战 | ★★★ 内部地图：其"评测能力 × 任务"矩阵与 48% 研究不开源的统计，是我们选择移植对象时"优先有 artifact 的"的依据。另其披露 **48% 不开源**——开源可用性需逐篇核（本报告已标注）。 |

### E. ML/LLM 反编译域（增强轨差异化来源）

ACADEMIC_SURVEY 已录 LLM4Decompile/DeGPT/SLaDe/SK2/ALT4/CoDe-R/PCodeTrans/Nova+。本轮修正与新增（Nova=ICLR'25 确认；arXiv 2311.13721 即 ACADEMIC_SURVEY 的"Nova+"，同一篇）：

| 论文 | venue/年[验证] | 管线位置/机制 | 落地性 |
|---|---|---|---|
| **Idioms**（同 B 域） | NDSS'26/arXiv 2502.04536 [一手] | 端到端联合代码+类型 | 候选生成器 + 联合类型输出设计输入。 |
| **D-LiFT** | arXiv 2506.10125，2025；Zou/Cai/Wu/**Basque**/Khan/Celik/Bianchi/Xu 等（Purdue+ASU） [一手：arXiv 页] | RL 微调，奖励=D-Score（可编译+可执行+**Symbolic-Model-Call：SMT 比对候选与二进制的外部调用序列**） | ★★★ 两个要点：① 外部调用序列 SMT 比对=**廉价强语义信号**，可直接并入我们选择器门禁；② **Basque 是共同作者=kuna 团队已在场**——此路线 kuna 大概率跟进，不是差异化。模型本体 SK2 论文称其 GitHub 为占位符（未放出）。 |
| **AutoDecompiler** | arXiv 2606.16162，2026；P. Liu 等 [一手：arXiv 页] | RL 训练的多轮反馈驱动精修 LLM | ★★ 反馈闭环同路人（ENH-1 思想的 LLM 版）；不采模型本体。 |
| **ReF-Decompile** | arXiv（2025-02）；Feng 等 [一手：SK2 引文 + emergentmind 条目] | 重标注策略 + 函数调用推断增强，6.7B 基于 LLM4Decompile；R_exec 61.4% | ★★☆ 候选生成器备选。 |
| **DecLLM** | **ISSTA 2025**（Proc. ACM Softw. Eng. 2）；Wong 等 [一手：CSUR 参考表] | 编译器诊断+sanitizer+运行时反馈迭代修复，面向"可重编译可用性" | ★★★ 反馈修复闭环的 ISSTA 正式版——ENH-1 编译器反馈门禁的文献锚点。 |
| **PseudoFix** | **ASE 2025**；Li 等 [一手：CSUR 参考表] | 检索相似"畸形伪码↔源码"对做 ICL 重构（goto/循环/谓词/临时变量），Twin-Closure 语义检查 | ★★★ LLM 候选生成器定位：其"检索增强重构"与 best-of-N 天然组合（生成第 N 个候选变体）。 |
| **sc²dec** | arXiv 2024（Feng 等） [一手：emergentmind 条目] | LLM 输出**重编译后回注为示范对**的自改进 | ★★ 与我们门禁同源思想（重编译即验证器），引用作哲学佐证。 |
| **ARMQwen2** | ICIC 2025（Liu 等） [一手：CSUR 参考表] | Qwen2 适配 ARM 反编译（literal pool/内联数据预处理） | ★★ WP7（ARM 车道）之后再看——ARM 伪码特异性处理经验。 |
| **WaDec / 智能合约 LLM 反编译 / CodableLLM / ICL4Decomp / SALT4Decompile / Constraint-Guided Multi-Agent（arXiv 2604.23940）/ FidelityGPT / RefDR / DecGPT** | 2024–2026 各 [一手：emergentmind LLM4Decompile 主题页 + AutoDecompiler 相关工作节——二手聚合，条目真实存在但未逐篇核 venue] | 长尾精修/数据管道/多智能体 | ★ 登记备查；增强轨不依赖。 |
| **（风险证据）When LLM Decompilers Recompile More and Preserve Less（Decompile-Diverge）** | arXiv 2609.05370，2026-09；Chang Liu 提交（清华 Chao Zhang 组系：与 DecompileBench/PCodeTrans 同组） [一手：arXiv 摘要页] | 每函数合成 driver+从参考实现生长 fuzzing 语料+同输入比对行为；8 系统 9 配置横评 | ★★★★★ **增强轨最重要的一篇风险论文**：LLM 精修把 Ghidra build rate 75%→90% 的同时 Matched 74%→62%；4.9%（单系统至 13%）候选过了全部自带测试仍行为分歧；CVE 轨 up to 1/10 漏洞"消失"。→ ① 证明纯可编译性/re-exec 指标会奖励错误路径（DecBench byte_match 的汇编 diff 是强门禁，但 fixup 注原型会掩盖 arity 错误——arity 检查必须保留）；② 其行为差分 oracle 是我们增强轨最终验收层的现成设计（ Decompile-Diverge 名字在 ACADEMIC_SURVEY 已出现，本轮补齐了实验数字与 2026-09 时间线）。 |

### F. 其他高杠杆（优化感知 / 形式化 / 正确性基建）

| 论文 | venue/年[验证] | 要点 | 落地性 |
|---|---|---|---|
| **A Deep Dive into Function Inlining and its Security Implications for ML-based Binary Analysis** | NDSS 2026；Abusabha/Uhm/Abuhmed/Koo [一手：CSUR 参考表] | 系统调谐 inlining 行为暴露二元结构差异；结论=基准须受控变化编译器变换 | ★★★ O2/O2noinline 战场的理论弹药（DecBench 三优化级设计的学术呼应）；给 ERASE 类 de-inlining 提供动机。作者=CSUR 综述同组。 |
| **FoxDec（Sound C Code Decompilation for a Subset of x86-64）** | SEFM 2020；Verbeek/Olivier/Ravindran [一手：CSUR 参考表] | Isabelle/HOL 验证 CFG 恢复+符号执行聚合；soundness 优先 | ★★ 方向参考（我们不追全验证，但"可重编译输出"的 soundness 论证可引用）。 |
| **BED（Evolving Exact Decompilation）** | BAR 2018；Schulte 等（GrammaTech） [一手：CSUR 参考表] | 遗传算法从语料合成候选+字节相似度适应度 | ★★★ 哲学祖先：**byte_match 目标的搜索式反编译 2018 年就有**；我们 best-of-N=其在"确定性基座+少量结构变体"上的收敛版。 |
| **Decomperson（How Humans Decompile...）** | USENIX Sec'22；Burk/Pagani/Kruegel/Vigna [一手：CSUR 参考表] | 人类逆向流程研究；定义"完美反编译=重编译字节等价" | ★★★（叙事）byte_match 指标的人类学正当性来源——对外叙事可引。 |
| **Control-Flow Deobfuscation using Trace-Informed Compositional Program Synthesis** | OOPSLA 2024 [一手：splashcon 页] | 轨迹引导合成去混淆 | ★ 领域相邻（混淆目标），DecBench 语料未混淆，登记不投入。 |

---

## 二、DecBench 三指标 × 增强杠杆地图

### 2.1 GED（结构保真；Ghidra 28.45% / kuna 39.05% / 榜一）

| 类别 | 杠杆 | 证据强度 | kuna 会跟吗 |
|---|---|---|---|
| **已有** | SAILR 三档（ENH-2：reducible 恒等/irreducible 回退/edge 排序） | kuna 实测 28.45→39.05 的同族增益 | **会**（其 phases.toml 已有 regionstructure/regionlooprefine，edge 排序还 LATENT） |
| **候选①** | **ERASE de-inlining（ICSME'24）+ DREAM++/FuncRE 规则版 outlining**——恢复被内联的调用边界，O2/O2noinline 切片结构直接向源码靠拢 | 中（论文面向可读性，GED 收益是推论，**需深挖**；源码有调用→结构同构的机理成立） | 半：kuna #261 有"无 outlining 支持"的自认缺口，angr 生态有 ERASE 同源工具，中期可能跟 |
| **候选②** | switch AST 恢复（ICSME'25） | 中（自报仅 GCC -O0） | 低（dewolf 系方向，非 kuna 生态） |
| **候选③** | dewolf pass（congruence/pointer-transform）作为 best-of-N 候选变体 | 低（dewolf 自己榜上 GED 3.65% 的反证） | 低 |
| **设计输入** | Behner SoK（Euro S&P'25）选型判据；SAILR 的"合法 goto"原则 | 高 | 双方共享 |
| **我们独有** | 逐函数 oracle 对拍驱动的残差收敛（GED 与 Phase 0 同战线）；结构变体进 best-of-N 由 GED 离线评估择优 | 高（DECBENCH 报告 §2.5） | **不会**（kuna 无活 oracle） |

### 2.2 type_match（类型恢复；binja 8.83 / ghidra 7.56 / kuna 6.91 / LLM 榜一 9.27）

| 类别 | 杠杆 | 证据强度 | kuna 会跟吗 |
|---|---|---|---|
| **候选①（确定性层）** | **TRex（Sec'25）**：演绎式行为捕获类型，123/125 胜 Ghidra，artifact 三徽章 | 高（一手页面数字） | **不会**（roadmap #261 无推断计划；其路线=angr usage-driven struct 识别） |
| **候选②（确定性层）** | **BinSub（SAS'24）/Manta（ASPLOS'24，Ghidra 插件）**：Retypd 系现代化 | 中–高 | 半（若走 typeink=Retypd 老路，BinSub 是弯道超车点） |
| **候选③（ML 层）** | **STRIDE/XTRIDE（n-gram，无 GPU）→ TyGr/DRAGON（GNN+置信度）**：置信度门控+重编译验证 | 高（ML 上限=LLM 榜一 9.27 已证） | **不会**（无 ML 计划——护城河③） |
| **候选④（联合层）** | Idioms 联合代码+类型（NDSS'26）作为 best-of-N LLM 候选；neighbor-context +63% UDT 证据=**类型恢复要跨函数上下文** | 中 | 不会 |
| **度量配套** | Soni SURE'25 五引擎横评口径=内部评估 harness；VarBERT type-stripping=训练语料构造法 | 高 | 共享文献 |
| **注意** | DWARF 传播类（DirTy/rtDwarf，未验证）对 DecBench **无效**——参赛输入是 stripped 副本；DWARF 杠杆只服务非 stripped 真实场景 | — | kuna 已做（dwarfstructs 等选项，不参赛） |

### 2.3 byte_match（可重编译字节恒等；kuna 5.82 / ghidra 4.52 / LLM 15.08 断层第一）

| 类别 | 杠杆 | 证据强度 | kuna 会跟吗 |
|---|---|---|---|
| **已有（已立项）** | best-of-N + 重编译汇编 diff 硬门禁（ENH-1；哲学祖先 BED'18/Decomperson'22） | 高 | **半**：rollback 是其 roadmap 16.4 未做项；D-Lift 有 Basque 参与——**窗口期存在，动作要快** |
| **强化①** | **三重门禁**：汇编 diff（byte_match 同款归一化）+ **arity 检查**（kuna 自认 GED-arity 盲区）+ **SMT 外部调用序列比对**（D-LiFT Symbolic-Model-Call，廉价强信号） | 高 | 部分（D-LiFT 论文在手，工程化未见于其 roadmap） |
| **强化②** | **行为差分验收**（Decompile-Diverge 2026：driver 合成+fuzzing 语料+同输入比对；DiscScope AsiaCCS'25 状态级符号比对；DecompileBench ACL'25 的 OSS-Fuzz harness 现成语料） | 高（75→90 build 同时 74→62 matched 的反面教材一手） | 低（需要重编译基建+行为 harness，其单管线哲学相斥） |
| **强化③** | 软排序升级：goto 计数 → **认知复杂度（ICPC'26）+ R2I（FSE'24）特征集** | 中 | 低 |
| **候选源扩充** | LLM 精修候选（PseudoFix ASE'25 / Idioms / ReF-Decomp）——**必须**被三重门禁拦截后才能胜出 | 中 | 可能（LLM 是其榜一短板，但无 selector 设计） |
| **风险纪律** | Decompile-Diverge：可编译≠保语义；fixup 注入原型会掩盖 arity 错误 | 高 | — |

### 2.4 Union 总账

逐函数≈Ghidra（Phase 0）≈ 32% 档 → +SAILR 三档（ENH-2）→ kuna 档 39–41% → **差异化超车点=type_match（TRex+ML 层，打其 6.91 的绝对洼地）+ byte_match（选择器闭环，打其未做的 16.4）**。LLM 榜一 codex 的教训（byte 15.08 但 GED 23.98，Union 仅 26.49）证明**单指标突进换不来 Union——只有门禁化组合杠杆能赢**，这正是我们三重门禁+逐函数择优的设计立足点。

---

## 三、增强轨路线建议

### 先做（按证据强度×工程量排序）

1. **ENH-1 升级为三重门禁选择器**（汇编 diff + arity + SMT 调用序列；软排序换认知复杂度特征）——本轮新证据全部指向这里（D-Lift 的 SMT 信号、Decompile-Diverge 的反面教材、DecLLM 的反馈修复正式版、BED/Decomperson 的哲学锚点）。kuna 的 roadmap 16.4 空窗是真实窗口。
2. **类型层双轨起步**：STRIDE n-gram sidecar（1–2 周，无 GPU，先通管道与验证）+ **TRex 深挖**（读 artifact 定移植形态；确定性演绎层与 fixture 门禁同构，type_match 主杠杆）。
3. **ENH-2 开工前读两份**：Behner SoK（Euro S&P'25）+ SAILR 原文 deopt 清单（已有），把 ERASE/FuncRE 的规则版 outlining 登记为 ENH-2 的可选第四档（O2 切片专用）。

### 差异化（kuna 结构性跟不了的）

- 活 oracle 逐函数对拍自证（护城河①，GED 叙事）；
- 三重门禁 best-of-N（护城河②，byte_match+Union 胜负手）；
- TRex 确定性类型层 + ML 类型层（护城河③，type_match 洼地）。

### 放弃 / 后置

- 端到端 LLM 进主管线（铁律不变；只做被门禁拦截的候选）；
- phased structuring 原创研究（平台期，SAILR 层收敛后再议学术输出位）;
- FuzzFlesh/Bin2Wrong/DecFuzzer 式 fuzzing 基建（中期回归语料，非增强杠杆，Phase 5 CI 化时并入）;
- DirTy/RTD（未验证）；混淆对抗线（OOPSLA'24 等，DecBench 语料无关）。

### 首推三件（若只做三件事）

1. **TRex 式确定性类型重构层**——type_match 是全场洼地+榜首已被证明非传统引擎，TRex 一手证据 123/125 胜 Ghidra、artifact 可用、确定性契合门禁。
2. **三重门禁 best-of-N 选择器**——本轮文献的最大增量共识（CoDe-R/sc²dec/D-LiFT/DecLLM/PseudoFix 全部收敛到"编译器/语义反馈即验证器"），叠加 Decompile-Diverge 的 arity/行为教训，是 Union 超 41.06 的唯一组合路径。
3. **STRIDE n-gram 类型/命名 sidecar**——工程量最小的 ML 层落点（开源、无 GPU、与 DIRTY 竞争力），把"ML 类型层"从路线图变成可测管道，为 DRAGON/TyGr 置换留插座。

---

## 四、诚实纪律记录

1. **DirTy**：任务点名为"DWARF 类型传播"类论文。本环境经 websearch（4 种措辞）、dblp（API+HTML，连接被重置/归因=本网络环境屏蔽 dblp）、Semantic Scholar API（持续 429 限流）、arXiv API（"DirTy" 全库无命中）、USENIX Sec'24 议程页（抓取在周三中午截断，未能覆盖全周）均**无法验证**。arXiv 无命中说明其（若存在）只在会议论文集。**不编造，标"需深挖"**——建议 root 若有线索（作者/年份/venue 任一）可 30 秒定位。
2. **RTD**：同上未验证。任务原文"RTD/DirTy（DWARF 类型传播）"——最接近的可验证事实：kuna 的 dwarfstructs/dwarfvariants/typedepth 选项（DECBENCH 报告一手）与 VarBERT 的 type-stripping DWARF 改写技术（VarBERT PDF 一手）。**另注意：DecBench 参赛输入为 stripped 副本，DWARF 传播类杠杆对参赛分数无效**，只影响非 stripped 真实工作流叙事。
3. **CoDe-R / PCodeTrans / AutoDecompiler / ReF-Decomp / sc²dec**：经引文网络（SK2Decompile ICLR'26 正式参考文献 + emergentmind 聚合页）确认存在与关键数字，**未取原文 PDF**——落地评估维持 ACADEMIC_SURVEY 的结论，本报告只增量引用其可验证数字（如 CoDe-R 26.0→83.9%）。
4. **dewolf/E2 长尾 LLM 条目**（WaDec/CodableLLM/ICL4Decomp/SALT4Decompile/FidelityGPT/RefDR/DecGPT/Constraint-Guided Multi-Agent 2604.23940）：二手聚合确认存在，venue 未逐篇核——全部标 ★ 登记级，不进入任何决策链。
5. **ExeBench venue 纠错**：MAPS 2022（PLDI 周会）而非 ICSE——本报告已按 ACM DL 一手记录修正。
6. **TRex/Ghidra 123/125、Idioms 54.4%、CoDe-R 83.9%、D-LiFT SMT 信号、Decompile-Diverge 75→90/74→62** 等数字均为论文自报，我们未复现——引用时保持"论文自报"口径。
7. 榜单数字（kuna 41.06/Ghidra 32.26/codex byte 15.08 等）引自 DECBENCH 报告钉死的 2026-09-23T19:00 scoreboard snapshot，带 snapshot 日期引用。

## 五、来源索引（一手实查）

- 综述骨架：arxiv.org/abs/2608.24955 + /html/2608.24955v1（CSUR 在审，72 篇+全参考文献表；GitHub lion10/csur2026_binary_decompilation）
- 结构化：eurosp2025.ieee-security.org/program.html + oaklandsok.github.io/papers/behner2025.pdf（Behner SoK）；usenixsecurity24-basque.pdf（SAILR）；mahaloz.re/dec-history-pt1/pt2；github.com/mahaloz/sailr-eval；deepwiki.com/angr/angr（结构化现状）
- 类型：usenix.org/conference/usenixsecurity25/presentation/bosamiya（TRex）；usenix.org/system/files/usenixsecurity24-zhu-chang.pdf（TyGr）；arxiv.org/abs/2409.01841 + 2024.splashcon.org（BinSub）；seviezhou.github.io/files/asplos24fall-final196.pdf（Manta）；ndss-symposium.org/wp-content/uploads/bar2025-final25.pdf（DRAGON）；arxiv.org/html/2407.02733 + github.com/hgarrereyn/STRIDE（STRIDE）；mlsec.org/docs/2026-codaspy.pdf（XTRIDE）；sure-workshop.org/accepted-papers/2025/sure25-8.pdf（类型横评）；arxiv.org/abs/2304.03854（Ghidra 复现）
- 命名/度量：arxiv.org/abs/2502.04536 + ndss-symposium.org/ndss-paper/idioms... + github.com/squaresLab/idioms；DOI 10.1145/3643744（R2I）
- LLM：arxiv.org/abs/2609.05370（Decompile-Diverge）；arxiv.org/abs/2506.10125（D-LiFT）；arxiv.org/html/2606.16162v1（AutoDecompiler）；proceedings.iclr.cc SK2Decompile 全文（引文网络）；openreview.net/forum?id=4ytRL3HJrq + github.com/lt-asset/nova（Nova=ICLR'25 确认）；iclr.cc/virtual/2025/poster/30979
- 基准：aclanthology.org/2025.findings-acl.1194 + github.com/vul337/DecompileBench（DecompileBench）；neurips.cc/virtual/2025/poster/121402（Decompile-Bench）；dl.acm.org/doi/10.1145/3520312.3534867（ExeBench）；usenix.org/system/files/atc25-yang-zao.pdf（Bin2Wrong）；usenix.org/conference/usenixsecurity24/technical-sessions（Sec'24 Track 6 同场确认）
- 检索失败归因：dblp.org（API/HTML 均连接重置，curl 同样为空——环境级屏蔽）；api.semanticscholar.org（持续 429）；USENIX Sec'24 议程页 948KB 截断（DirTy 验证失败的技术原因）

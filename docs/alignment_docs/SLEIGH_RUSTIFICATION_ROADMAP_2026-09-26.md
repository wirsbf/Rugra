# SLEIGH 层 Rust 化差距调研与路线图（2026-09-26，Lane SLEIGH-GAP）

> 车道 wt/sleighgap，基 = master `594d6982`，ghidra/ symlink = 锁定 oracle 树。
> oracle = Ghidra `Ghidra_12.0.4_build` / commit `e40ed13014025f82488b1f8f7bca566894ac376b`（`git -C ghidra rev-parse HEAD` 亲验）。
> 本车道零 `src/` 改动；全部数字可由本文命令复现。kuna 事实来自 github.com/Noelo-Lab/kuna
> 的 README/docs/crates（webfetch 2026-09-26）。

## 0. 结论速览

| 问题 | 结论 |
|---|---|
| SLEIGH 现在 Rust 化了吗 | **没有**。主提升路径走锁定树 C++ SLEIGH 引擎（build.rs 经 cc 编 21 个 .cc → `rugra_sleigh` 静态库 + `sleigh_shim/rugra_sleigh.cpp` C ABI 桥，`src/sleigh_ffi.rs` 644 行绑定） |
| "现状是 iced-x86 替代层"对吗 | **半对，需修正**。curl/httpd/gen/bin 主函数提升 = SLEIGH FFI（`follow_flow` 持 `SleighLifter`）；iced-x86（`x86_lift.rs` 5193 行）退居**原型预探测**（`external_prototypes` 数据源）、funcdata 测试、探针 examples 与 `X86_64Disassembler`（字符串/CFG 预扫） |
| 非 x86 架构 | **零路径**。`create_disassembler` 对 ARM 等返回 `UnsupportedArchitecture`（src/disasm/mod.rs:251-265） |
| SLEIGH 源码在哪 | 锁定树 `decompile/` 下只有 `cpp/ datatests/ unittests/ zlib/`——**没有独立 `sleigh/` 目录**，SLEIGH 编译器+运行时全部 31 个 .cc 就在 `cpp/` 里（这正是 root 种子事实"只有 cpp/"的解释） |
| 处理器规格 | 稀疏检出（磁盘只有 `Ghidra/Features`），但 commit 内 `Ghidra/Processors` tree `6429c9b0` 完整：**38 目录 / 146 .slaspec / 51 .ldefs** |
| SLEIGH 家族规模 | 31 个 .cc ≈ **34,299 行**（运行时 20,344 + 编译器 11,940 + 桥接 2,015）；账本口径 **1215 个 .cc 定义 / 270 exact / 944 unmapped（78%）**，编译器侧 207 定义 **0 mapped** |
| kuna 能否直接借用 | **有条件可行（推荐 Phase0 混合策略）**。crate 边界干净（kuna-sleigh 只依赖 kuna-base+kuna-num），但 kuna vendor 树**不是 12.0.4**（39 模块/148 specs vs 本仓 38/146，双计数失配），其 148/148 证据**不可转认**，借用后必须以锁定 oracle 重验 |
| 从零成本参照 | kuna 先例：编译器 slacomp 单独 ~1 天车道到 148/148 content-identical（06-19→06-20），全套 C++→Rust ~2 周/~$8k LLM 时间 |

---

## 1. Rugra 现状测绘（全部命令在案）

### 1.1 双路径架构：主提升已是 SLEIGH（C++ FFI），iced 是第二路径

**证据链**（基 594d6982）：

```bash
grep -n "SleighLifter\|X86Lifter" src/flow.rs
#   flow.rs:11  use crate::disasm::sleigh_lift::SleighLifter;
#   flow.rs:262 lifter: Option<&'a mut SleighLifter>,   ← FlowInfo 只持 SLEIGH lifter
grep -n "SleighLifter\|X86Lifter" examples/curl_decompile.rs
#   :19-20 两者都 import；:4073 X86Lifter（prototype_worker 内）；
#   :5777 SleighLifter → :6229 follow_flow_range（主反编译 worker）
grep -n "SleighLifter\|X86Lifter" examples/httpd_decompile.rs
#   :3199 SleighLifter（主流程）；:2588/:4066/:4130/:4845 X86Lifter（预探测/字符串面）
grep -rn "X86Lifter" src/funcdata.rs | wc -l   # ≈24 处，全部在 #[cfg(test)]
```

分工矩阵：

| 路径 | 实现 | 使用面 | 输出去向 |
|---|---|---|---|
| **SLEIGH C++（主）** | `src/sleigh_ffi.rs`（644 行）→ `sleigh_shim/rugra_sleigh.cpp`（21KB C ABI）→ 锁定树 SLEIGH 引擎，规格=`sleigh_specs/x86-64.sla` | curl/httpd/gen/bin_sweep/bin 的主函数提升（`follow_flow*`）、`src/flow.rs` FlowInfo | 主 IR → 全部 Action/Rule → C 输出 |
| **iced-x86（副）** | `src/disasm/x86_lift.rs`（**5193 行**，218KB）+ `src/disasm/x86_64.rs`（425 行）+ Cargo.toml `iced-x86 = "1.21"`（另 capstone 0.12 在 default feature） | ①curl/bin 的 `prototype_worker`：iced 提升 → `inject_raw_ops` → `ActionInferParams` → `num_params` → `external_prototypes`（**喂给最终输出**）；②funcdata 全部单测；③17 个 `x86*_probe/push/shift/flag/dbg` 探针 examples | 原型表/测试/探针 |
| **SleighLifter（Rust 侧薄壳）** | `src/disasm/sleigh_lift.rs`（148 行） | 把 FFI 结果转 `PcodeOpRaw`；`convert` 即 `PcodeEmitFd::dump`（funcdata.cc:878）语义适配 | — |

注意：x86_lift.rs 大量注释自证其输出是**对着锁定 .sla 经 shim 的 op-for-op dump 手工校正的**（如 "sleigh_shim op-for-op dumps /tmp/w-ext-*.out"），即 iced 层本身也以 SLEIGH 为真值源。

### 1.2 build.rs 的"锁定 SLEIGH 树硬依赖"到底是什么

build.rs（103 行，全文已读）：

- `build.rs:28-33`：`cpp/sleigh.cc` 不存在 → panic（即 root 提到的 mirror-gate CI 事故位）。
- `build.rs:36-58`：20+1 个源文件清单（xml/marshal/space/float/address/pcoderaw/translate/opcodes/globalcontext/sleigh/pcodeparse/pcodecompile/sleighbase/slghsymbol/slghpatexpress/slghpattern/semantics/context/slaformat/compression/filemanage）——**只编 SLEIGH 运行时，不编编译器**（无 slgh_compile/slghparse/slghscan，无 main）。
- `build.rs:87` 加 shim，`build.rs:101` `cc.compile("rugra_sleigh")`，`build.rs:102` 无条件 `cargo:rustc-cfg=has_sleigh`（src 里 **0 处 `cfg(has_sleigh)`**——引擎是无条件依赖，非可选 feature）。

`.sla` 资产管线（`tools/build_locked_x86_64_sla.sh`，全文已读）：从锁定 commit `git archive` 出 `cpp/` + `Processors/x86/data/languages`（**绕过稀疏检出**）→ `make sleigh_opt` → x86-64.slaspec 双编译要求字节恒等 → sha256 门禁（sla=`d5adc314…`，487,659 B）→ 装入 `sleigh_specs/`（7 文件：sla/pspec/cspec/ldefs/metadata.json 等）。`sleigh_specs/x86-64.spec-metadata.json` 记录完整 provenance（oracle commit、各输入 sha256、`oracle_status: NO_ORACLE`——只证资产溯源，不证行为）。

既有 SLEIGH 差分仪器：`tools/run_sleigh_decode_oracle.sh`（C++ 直编 fixture runner，锁 commit/tag/cpp-tree/language-tree/Makefile-blob 五重校验）+ `tests/oracle/` 6 个 sleigh 夹具（sleigh_decode_1204、sleigh_flow_relative 等，三件套 .cc/.rs/.metadata.json）。

### 1.3 已 Rust 化的 SLEIGH 邻接模块（现状不是零）

`src/` 已有 C++ 对应物：marshal.rs / translate.rs / compression.rs / context.rs / loadimage.rs / pcoderaw.rs / opcodes.rs / address.rs / space.rs / **pcodeparse.rs（pcodeparse.cc 3303 行+Bison 语法 805 行的完整移植，自述"L3 gaps cannot be filled without SLEIGH integration…exposes a clean Rust API that downstream SLEIGH work can plug into"）** / pcodeinject.rs。账本 exact 标注可证：pcodeparse.hh 16/16、pcodecompile.cc 31/33、marshal.cc 33/80、translate.cc 20/42、float.cc 34/36。即：**解码消费端的数据类型层大体在，缺的是 .sla 装载+构造表匹配+模板展开的引擎本体与编译器**。

---

## 2. oracle SLEIGH 范围钉死（数字全部可复现）

```bash
git -C ghidra log --oneline -1        # e40ed13014 GP-1 Updated Change History for Ghidra 12.0.4
git -C ghidra ls-tree HEAD Ghidra/Features/Decompiler/src/decompile/
#   .cproject / build.gradle / cpp(tree b02e230a) / datatests / unittests / zlib   ← 无 sleigh/
git -C ghidra ls-tree -d HEAD Ghidra/Processors/ | wc -l                # 38
git -C ghidra ls-tree -r HEAD Ghidra/Processors/ --name-only | grep -c '\.slaspec$'   # 146
git -C ghidra ls-tree -r HEAD Ghidra/Processors/ --name-only | grep -c '\.ldefs$'     # 51
```

38 个处理器目录：6502 68000 8048 8051 8085 AARCH64 ARM Atmel BPF CP1600 CR16 DATA Dalvik
HCS08 HCS12 JVM Loongarch M16C M8C MC6800 MCS96 MIPS NDS32 PA-RISC PIC PowerPC RISCV Sparc
SuperH SuperH4 TI_MSP430 Toy V850 Xtensa Z80 eBPF tricore x86。
（root 派单假设"39 个"与 kuna 文档口径一致但与锁定 12.0.4 实测差 1——kuna vendor 的是别版本，见 §3.4。）

x86 语言树：78 文件（`git ls-tree -r --long e40ed130 …/x86/data/languages/`），最大
`avx512.sinc` 790,429 B；`x86-64.slaspec` sha256 `9d66a01a…`。

### 2.1 SLEIGH 家族文件账（cpp/ 内，`wc -l` 亲测）

| 分层 | 文件 | 行数 |
|---|---|---:|
| **运行时 21 .cc**（build.rs 编译集） | xml 2510 / marshal 1273 / space 682 / float 673 / address 836 / pcoderaw 124 / translate 1018 / opcodes 137 / globalcontext 618 / sleigh 813 / pcodeparse 3303 / pcodecompile 781 / sleighbase 381 / slghsymbol 2484 / slghpatexpress 1674 / slghpattern 999 / semantics 962 / context 239 / slaformat 258 / compression 165 / filemanage 414 | **20,344** |
| **编译器侧 4 .cc**（build.rs 不编） | slgh_compile 4074 / slghparse 3871 / slghscan 3588 / sleighexample 407 | **11,940** |
| **桥接 6 .cc** | sleigh_arch 632 / inject_sleigh 520 / pcodeinject 361 / loadimage_xml 298 / xml_arch 159 / ghidra_context 45 | **2,015** |
| 合计 31 .cc | | **34,299** |
| 代表性 .hh | sleigh.hh 529 / slghsymbol.hh 636 / slghpatexpress.hh / slghpattern.hh / semantics.hh / slgh_compile.hh / sleigh_arch.hh…（家族 .hh inline 定义合计 **835**，账本口径） | ≈4,400+ |

### 2.2 函数账本口径（`docs/alignment_audit/FUNCTION_MAP.generated.md`，oracle=e40ed130）

| 切片 | .cc 定义数 | exact 标注 | unmapped |
|---|---:|---:|---:|
| 运行时 21 文件 | 893 | 244 | 649 |
| 编译器侧（slgh_compile 148 + slghparse 11 + slghscan 48） | 207 | **0** | 207 |
| 桥接 6 文件（sleigh_arch 30/inject_sleigh 31/pcodeinject 17/loadimage_xml 10/xml_arch 10/ghidra_context 3） | 101 | 26 | 75 |
| sleighexample.cc | 14 | 0 | 14 |
| **SLEIGH 家族合计** | **1215** | **270（22%）** | **944（78%）** |

（exact 标注只证来源指向，行为状态全部默认 UNTESTED——完成度判定以逐函数 oracle 行为门禁为准。）

---

## 3. kuna 借用可行性判定（root 追加评估项）

### 3.1 kuna 是什么、验证到什么程度

github.com/Noelo-Lab/kuna：Ghidra 起源的 Rust 反编译器（"originally ported from Ghidra, has
since diverged"），Apache-2.0。`docs/history.md`（webfetch 亲读）时间线：

- 2026-06-05：vendor Ghidra C++ 反编译器（~196k LOC）+ 全部 SLEIGH 处理器模块，Python 胶水。
- 2026-06-10：Rust 化开始（6-crate workspace、7 ADR、`--engine {cpp,rust}` 差分 harness、200 项清单；C++ 树全程字节不动当 oracle）。
- 06-11→13：wave W1-W9（**一个 wave 覆盖 SLEIGH 运行时**）；M1=207/207 单测 parity。
- 06-19：初版完成，675/675 datatests parity。
- 06-20：**slacomp（SLEIGH 编译器）落地：148/148 specs 编出 content-identical .sla**；同日删 C++ 树。
- 成本：全程 ~2 周近连续 LLM 时间、~$8k API 花费。
- slacomp 验证法：`sleigh_opt` 确定性 → 148 个 .sla 以**解压后元素流**做 content-identity（非裸字节），再用 Rust 编译器重建全部 specs 重跑全套。

### 3.2 模块边界与可分离性（决定借用成本的第一变量）

`decompiler/` 为 12-crate workspace。SLEIGH 相关四 crate 及依赖（raw Cargo.toml 亲读）：

| crate | 依赖 | 内容 |
|---|---|---|
| kuna-base | （基础） | 类型/错误/XML+marshal/地址空间/raw p-code/context db/compression/translate+loadimage trait |
| kuna-num | （基础） | 多精度/IEEE float 模拟/CircleRange |
| **kuna-sleigh** | **kuna-base + kuna-num（仅此两个）** | .sla 读取 + 指令解码运行时 + 编译侧 pattern 机构；src **逐文件镜像 C++**（sleigh.rs/sleighbase.rs/slghsymbol.rs/slghpatexpress.rs/slghpattern.rs/semantics.rs/pcodecompile.rs/pcodeparse.rs/slaformat.rs/translate.rs/context.rs/globalcontext.rs/loadimage.rs/loadimage_xml.rs/memstate.rs/emulate*.rs + kuna_* 胶水） |
| **kuna-slacomp** | **kuna-base + kuna-num + kuna-sleigh（仅此三个）** | slghscan.l→slghscan.rs(WS1 lexer) / slghparse.y→slghparse.rs(WS2 手写递归下降) / pcodecompile→pcodecompile_actions.rs(WS3) / slgh_compile→slgh_compile.rs(WS4 SleighCompile driver) / encode.rs(WS5 .sla 发射)；**复用**（不重写）kuna-sleigh 的符号表/模式/模板/FormatEncode |

判定：**零反编译器耦合**——kuna-sleigh/slacomp 不依赖 kuna-decomp/kuna-analysis/任何前端。
kuna-sleigh src ≈1.3MB Rust（GitHub API size 亲测：slghsymbol.rs 262KB、slghpatexpress.rs
120KB、sleigh.rs 113KB、semantics.rs 95KB、pcodeparse.rs 94KB…，约 30k 行量级，含
emulate/memstate 等 Rugra 已有对应物的部分）。

### 3.3 许可合规

- kuna 与 Rugra 同为 Apache-2.0，且 kuna 对 Ghidra(NSA)/angr(BSD-2) 的归属在 NOTICE。
- 借用动作的合规清单：①Rugra `NOTICE` 增补 kuna/Noelo-Lab 归属段（现 NOTICE 已有 Ghidra
  段，仅"includes software developed as a Rust port of the NSA Ghidra decompiler"措辞）；
  ②被借文件保留/移植其源头 `// Ghidra:` 双锚（Ghidra 行号 + kuna commit）；③kuna 的
  BSD-2（angr 部分）如随 kuna-num 进入，NOTICE 需连带列出。无许可证冲突，Rugra 无再分发限制。

### 3.4 版本失配（决定借用成本的第二变量，**关键风险**）

- kuna README/文档**未声明 vendor 的 Ghidra 源版本**；其 Ghidra GUI 扩展面向 12.1.2。
- 两个独立计数失配：kuna "39 SLEIGH processor modules / 148 specs" vs 锁定 12.0.4 实测
  **38 目录 / 146 .slaspec**。⇒ kuna vendor 树 ≠ e40ed130（更新版本）。
- 后果：kuna 的 148/148 content-identical 是**对其自己 oracle** 的证据，对本仓锁定 oracle
  **不可转认**（铁律 2.1：同输入同输出的 oracle 必须是锁定树）。.sla 格式与语义机构在
  12.0.x 系内预计漂移有限，但"预计"不算证据——必须以锁定 `sleigh_opt` 重跑 content-parity。
- git 历史考察（root 追加问项"更接近 Ghidra 原生的早期版本"）：kuna 的前身就是 vendor 的
  C++ 树本身，不存在"更原生"的早期 crate 形态；当前 1:1 文件镜像布局即移植原生形态，无
  更优历史锚点可借。

### 3.5 借用适配成本 vs 从零移植成本

| 维度 | 借用（混合） | 从零 |
|---|---|---|
| 编译器（slaspec→.sla） | vendor 4 crate → 重指向类型 → 锁定 oracle 重验 146 specs | 按 kuna 先例 ~1 天车道量级到首绿（其 06-19→06-20 单日完成），但对本仓需自建 WS1-WS5 全部 |
| 运行时（.sla 装载+decode） | kuna-sleigh ≈30k 行现成；适配=kuna-base→Rugra 类型（address/space/pcoderaw/opcodes/translate/loadimage **Rugra 已全有**，映射面小）+ emulate/memstate 去重 | 20,344 行 C++ 逐函数；类型层大半已在（§1.3），缺口集中在 sleigh.cc 813 + slghsymbol 2484 + slghpatexpress 1674 + slghpattern 999 + semantics 962 + slaformat 258 |
| 验证成本 | **相同**（都必须过锁定 oracle 门禁：.sla content-parity + 逐指令 P-code 差分） | 相同 |
| 风险 | 版本漂移暗坑（12.1.x 语义混入）；与 Rugra 风格/注解纪律磨合；上游演进不可控 | 工期风险；但每步都是本仓 oracle 直证 |
| 估计 | PoC（Phase0）数天级：vendor+改 import+跑 146 specs parity | Phase1+2 合计参照 kuna 波次 ~1.5-2 周连续 agent 时间 |

**判定**：推荐 **Phase0 借用 PoC 作为加速选项**——先做"kuna 四 crate vendor 进
`src/sleigh/`（或独立 workspace crate）+ 锁定 oracle 重验"。若 x86-64.sla 即刻
content-identical 且 decode 流差分零差异，则 Phase1/2 转为"借用+适配"；若 parity 失败面
大（版本语义漂移），则降级为"参考实现"（读其结构省读码时间，代码仍按锁定 oracle 从零写）。
PoC 本身即裁决实验，两条后路的成本都被它收窄。

---

## 4. 差距分析：全量 SLEIGH 化需要什么

1. **SLEIGH 编译器**（Phase1）：`.slaspec`（含 .sinc include、宏、构造表、语义动作）→
   `.sla`。涉及 slghscan.l（lexer）/slghparse.y（语法+语义动作）/slgh_compile.cc
   （SleighCompile driver：符号解析、pattern 归一、子表、冲突检测、上下文字段）/slaformat
   （序列化+deflate）。当前 Rugra 完全没有（207 定义 0 mapped，sleigh_opt 二进制依赖
   git-archive 临时构建）。
2. **运行时**（Phase2）：SleighBase::restoreXml(.sla 装载) + Sleigh::initialize +
   oneInstruction（构造表匹配→ConstructTpl 活化→OpTpl 流发射）+ resolveRelatives +
   context 寄存器读写 + PcodeEmit 回调 + LoadImage。当前= C++ 引擎经 shim（ABI 面 16 个
   extern 函数，`src/sleigh_ffi.rs` 在案），Rust 化后 shim 与 cc 依赖整体退役。
3. **x86 切换门**（Phase3）：iced 残留面退役——`prototype_worker` 的 X86Lifter 换 SLEIGH
   提升（或直接以 SLEIGH 主路径的 Funcdata 结果取原型）；funcdata 测试与探针 examples 迁
   SLEIGH；差分验证策略见 §6（先 A/B 后退役）。
4. **多架构解锁**（Phase4）：`Architecture` 枚举扩展 + `.ldefs` 驱动的语言发现（filemanage）
   + 各 arch pspec/cspec 资产管线（复用 build_locked 脚本模式）+ ARM/MIPS 等语料门禁
   （DecBench 类固件面）。**这是能力解锁而非残差修复**：当前 ARM 连 `create_disassembler`
   都过不去。

依赖顺序：编译器与运行时可并行启动（kuna 顺序相反：先运行时后编译器，因为 .sla 消费端
先承重）；x86 切换门依赖运行时；多架构依赖编译器（146 specs 产能）+运行时。

---

## 5. 分 Phase 路线图

> 验收形态总原则（铁律 2.1）：每 phase 的"绿"都定义为**锁定 oracle 同输入同输出**，
> Rust 自测/形似不算。

### Phase 0 — kuna 借用 PoC（裁决实验，可选加速，root 决策点）

- **写域**：新 `src/sleigh/`（vendor 四 crate 或薄适配层）+ NOTICE。
- **内容**：vendor kuna-{base,num,sleigh,slacomp} → import 重指向（优先映射到 Rugra 既有
  address/space/pcoderaw/opcodes/translate/loadimage；emulate/memstate 去重留 Rugra 版）→
  编译锁定 `x86-64.slaspec` 与 `sleigh_specs/x86-64.sla` 做 content-parity。
- **验收**：①x86-64.sla 解压元素流与锁定 `sleigh_opt` 产物恒等（复用
  build_locked_x86_64_sla.sh 的双编译确定性框架）；②若①过 → 扩到 146 specs 全量 parity
  （对锁定树 `git archive` 重建的 sleigh_opt 批量跑）；③decode 面：x86-64.sla 上抽样指令
  集与 shim 引擎逐 op 差分零差异。
- **裁决输出**：PASS → Phase1/2 改为"借用+适配"轨道；FAIL → 记录失配面清单，kuna 降级为
  参考实现，Phase1/2 走从零轨道。
- **成本参照**：数天级；NOTICE/归属同 commit。

### Phase 1 — SLEIGH 编译器（slaspec→.sla）

- **写域**：`src/sleigh/slacomp/`（slghscan/slghparse/pcodecompile_actions/slgh_compile/
  encode 五模块，无论从零或借 kuna 骨架）+ `tools/`（批量 parity 驱动）。
- **oracle 锚**：slghscan.l / slghparse.y / slgh_compile.cc:1-4074 / slaformat.cc。
- **验收**：**146/146 specs content-identical .sla**（解压元素流恒等，kuna 验证法）+
  x86-64.sla 裸字节 == `d5adc314…`（487,659 B，build_locked 脚本既有门禁直接复用）。
- **成本参照**：kuna 先例 slacomp 单 wave 完成（06-19→06-20）；从零轨道估 5-8 个车道日。
- **交付物**：`tools/build_locked_x86_64_sla.sh` 增加或切换 Rust 编译器路径（保留 C++ 路
  径作对照直至 Phase2 结束）。

### Phase 2 — SLEIGH 运行时 Rust 化（.sla 装载 + decode）

> **状态（2026-09-26，Lane SLEIGHP2）**：**DONE**（换装+门禁+退役全链，证据
> =`docs/alignment_docs/SLEIGH_PHASE2_SWAP_2026-09-26.md` 与
> `/dev/shm/rugra-reports/LANE_SLEIGHP2_2026-09-26.md`）。实际形态与本节
> 原案差异：写域收敛为 `src/sleigh_ffi.rs` 引擎枚举（kuna-sleigh 已在
> Phase1 vendor 为独立 workspace crate,Phase2 直接接线 `rust_backend`
> 模块,不再新开 `src/sleigh/`）；op-for-op 面比原案更宽（每语料**每字节
> 位置**为指令起始,36 面 698,605 decodes/5,550,599 ops 零差,超集覆盖
> "全部函数入口+全部可达指令"）。

- **写域**：`src/sleigh/`（sleighbase/slghsymbol/slghpatexpress/slghpattern/semantics/
  context/slaformat 消费端等）+ `src/sleigh_ffi.rs` 替换为原生引擎门面（保持
  `SleighLifter` 公开面不变，flow.rs 零改动）。
- **oracle 锚**：sleigh.cc:1-813（Sleigh::initialize/oneInstruction/resolveRelatives）、
  sleighbase.cc、semantics.cc、slaformat.cc。
- **验收**：①**逐指令 P-code 差分**：五语料（curl/httpd/vsh/sq/sqlite3）全部函数入口 +
  全部可达指令，Rust 引擎 vs C++ shim 引擎 op-for-op 恒等（复用 run_sleigh_decode_oracle.sh
  的 fixture 形态扩容）；②E2E：五语料 canon 输出与 C++ 引擎版**字节恒等**（A/B 双二进
  制）；③`build.rs` 删除 21 文件 cc 编译与 sleigh_shim（`has_sleigh` cfg 与 shim 退役）。
- **成本参照**：kuna 运行时= W1-W9 中一个 wave；从零估 8-12 车道日（类型层已有 §1.3）。

### Phase 3 — x86 全 SLEIGH 化切换门（iced 退役）

- **写域**：`examples/curl_decompile.rs`+`examples/httpd_decompile.rs`+`src/bin/rugra.rs`
  的 prototype_worker、`src/disasm/x86_lift.rs`（缩编或退役）、funcdata 测试迁移、probe
  examples。
- **验收**：①A/B：预探测换 SLEIGH 后 canon curl/httpd 差分（预期锚见 §6）；②iced-x86 与
  capstone 从 Cargo.toml 移除（或仅 probe feature 保留）；③五语料 + bank + 镜面棘轮全绿。
- **前置**：Phase2 完成。

> **2026-09-26 DONE（Lane SLEIGHP3 @ wt/sleighp3，基 master f3499354）**。
> 实际写域扩展：canon 双驱动 + CLI 预扫描 + funcdata 22 测试站点 + 7 个管线调试器 +
> `src/disasm/{x86_64,x86_lift,mod}.rs`/`src/binary/mod.rs`/`src/error.rs` 死面删除 +
> Cargo 去 iced-x86/capstone（含 capstone feature）+ 9 个 x86 探针与 disassemble_demo
> 退役。**①P-1 实测=证伪**：prototype_worker 全链换 SLEIGH 后 canon curl **字节恒等**
> （md5 c33052a3==基线，num_params A/B 30 函数 0 差）——A/G 残差非解码数据源贡献，
> 修法收敛到"改仲裁"（CURLCANON 两票已注记）；httpd 换装经两轮真实缺陷修复
> （CASED 判别器 const size、多字节 NOP 引擎操作数 pcode 需按 oracle printAssembly
> 分类过滤）后 311/0/0，残差 +82 全部归因持有域管线分歧（blockaction F5 族 +103、
> varmap 域），真实收敛 −45（oracle 形 IR）。**②完成**：Cargo.lock 双依赖出清。
> **③门禁**：canon curl 200/0/0 恒等 + canon httpd 311/0/0 + bank 391/391 + .sla 三元 +
> cargo test --lib 1786P/0F（−19=被删模块测试 9+6+4 精确对账）+ 镜面五面（见车道终报）。
> 附带发现：stackfold B2 fixture 驱动在基线即 panic（f6dcbed0 预存断裂，
> STACKFOLD-FIXTURE-F6DC-BREAK-0001）；fold 可观察量经生产路径验证保持
> （canon httpd in_RSP=0 双侧）。

### Phase 4 — 多架构解锁（ARM/MIPS/…）

- **写域**：`src/arch.rs`（Architecture 扩展）、`src/disasm/`（按 .ldefs 语言发现）、
  `sleigh_specs/` 扩容管线（AARCH64/ARM/MIPS/RISCV/PowerPC 优先）、examples 多 arch 驱动。
- **验收**：①Phase1 编译器对目标 arch spec 产出 content-identical .sla；②各 arch 小语料
  （gcc -m32/-marm/-mips 交叉编译 fixture）与 Ghidra oracle 输出差分门禁建立；③DecBench
  类固件面跑通为 stretch。
- **前置**：Phase1+2；与 Phase3 可并行。

---

## 6. iced 替代层残差族可检验预测

**先修正前提**（重要）：curl/httpd 的**主函数提升已经走 SLEIGH**（§1.1）。因此
"SLEIGH 化（Rust 重写引擎）"本身**不改变主 IR**——Phase2 的验收恰恰是字节恒等。现行
canon 残差（@master 合成态 curl 246/0/0、httpd 255/0/0）与后续 Rust SLEIGH 的关系是
"不变量"而非"自愈源"。真正与 iced 层有关的残差在其**数据下游**：

| 预测 | 依据 | 检验锚点（可执行） | 判定意义 |
|---|---|---|---|
| **P-1 原型预探测是 A/G/F 族的贡献源之一**：curl `prototype_worker` 用 iced 提升 + 简化 `ActionInferParams` 产 `num_params`，与 Ghidra（decompiler 全管线+分析器）不同源。A 族（原型驱动 cast，45 行）、G 族（\_\_stream 名推荐，12 行）、F 族（gp 局部类型仲裁，24 行）都消费原型/参数信息 | A/G/F 族的 CURLCANON 归因（docs/alignment_audit/CURL_CANON_ATTRIBUTION_2026-09-26.md §2）均落在"原型/参数→cast/命名"链上；该链上游数据=iced 预探测产物 | Phase3 的 A/B 实验：仅替换 prototype_worker 的 lifter（X86Lifter→SleighLifter），其余零改动，跑 canon curl 差分。**可检验预测：A/G 三族行数变化集中出现在多被调函数（main/parseconfig），且方向只能改善或不变——若出现新缺陷族则预测证伪** | 若 P-1 成立，A/G 部分行数归因上移到"预探测数据源"，CURLCANON-PROTOCAST/NAMEREC 票的修法可选"换源"而非"改仲裁"。**实测（2026-09-26 SLEIGHP3）：证伪**——换装后 canon curl 字节恒等（md5 c33052a3），A/G 行数原样保留且 num_params A/B 30 函数 0 差 ⇒ 残差根因在简化原型管线的仲裁本身，"换源"修法关闭，两票修法定向"改仲裁" |
| **P-2 B 族（helpf varargs 保存链 29 行）不是 iced 残差**：helpf 主提升走 SLEIGH，B 族根因在 condexe/fspec 参数试验/保存链（票面归因），与 lifter 无关 | §1.1 主路径事实 + HELPF-VARARGS-SAVECHAIN-0001 归因 | Phase2 验收的字节恒等实验顺带证伪/证实：Rust SLEIGH 后 B 族行数应**逐字节不变** | 把"换 SLEIGH 能不能治病"这类预期从 B/D/C 等主 IR 族上摘掉，避免误投工期。**实测（2026-09-26 SLEIGHP3）：证实**——canon curl 字节恒等下 helpf 29 行原样保留 |
| **P-3 funcdata 测试面（iced IR）与主管线（SLEIGH IR）存在系统性形态差**：24 处 X86Lifter 单测喂的 IR 与生产 IR 不同源，测试通过≠生产行为 | x86_lift.rs 自述以 .sla dump 校正（仍非恒等）；fspec.rs:9322 注释"iced builds"与 sleigh 路径分叉在案 | 抽样：同一函数同地址，X86Lifter::lift 与 SleighLifter::lift_instruction 的 PcodeOpRaw 序列 diff 计数（探针 examples/x86gap_probe.rs 既有同类仪器） | 若非零差，funcdata 单测的"绿"对生产行为的证明力打折，测试迁移（Phase3 ③）有实质工作量。**实测（2026-09-26 SLEIGHP3）：证实**——op-for-op 仪器钉死形态差族（cmp 链 9→10 op、mov 零扩展折叠、COPY tmp 前导、call-to-next CALL→BRANCH、常量地址 LOAD 折叠、SIMD 缺失、push 臂 STORE 形）；22 测试站点迁移 + 3 形态断言族按 SLEIGH 实测重写（cmp=10/store=2/seq_cmp_je=27），x86gap_probe 等校准仪器随 iced 退役删除 |
| **P-4 多架构解锁后的新语料将暴露 x86 特化假设**：flow/fspec/varmap 中按 x86-64 寄存器约定写的路径（如 segment base、calling convention 硬编码）在 ARM/MIPS 上首跑预期失败 | space.rs/arch.rs 的 x86-64 锁定值注释（sleigh_specs .sla 空间表）；create_disassembler 无 arch 分支 | Phase4 首个 ARM fixture 与 oracle 的首分歧点记录 | 新语料=新差分面，先立票后修，不降级 |

---

## 7. 风险与开放问题

1. **kuna 版本漂移**（§3.4）：唯一硬风险，Phase0 PoC 一票裁决。
2. **.sla 格式版本兼容**：12.0.4 slaformat 与 kuna 所编版本的元素流若有 schema 差，
   content-parity 首战即见分晓（这本身就是 PoC 的观测目标）。
3. **`sleigh_specs/` 单语言资产**：当前仅 x86-64；多语言引入后仓体增长（x86 语言树 78 文件
   中 .sinc 源不必入库——锁定 oracle `git archive` 可随时重建，入库 .sla 即可，指纹管账）。
4. **build.rs 退役顺序**：C++ 编译链是当前全部 E2E 的承重墙，Phase2 验收（字节恒等 A/B）
   未过前不得删除；镜像 CI（mirror-gate）同步切 Rust 引擎需 root 排期。
5. **funcdata 测试迁移量**：24 处 X86Lifter 用例 + 17 个探针 examples 的去留需 Phase3 逐个
   裁决（建议：probe examples 转 SLEIGH 后保留为解码差分仪器）。
6. **Phase1 票写域边界**：新 `src/sleigh/` 模块树必须从首 commit 起遵守 `// Ghidra:`
   注解纪律（机制 E hook 对新文件同样拦截；kuna 借用文件的注解=双锚，见 §3.3）。

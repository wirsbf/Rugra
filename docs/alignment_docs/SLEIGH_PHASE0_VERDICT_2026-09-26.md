# SLEIGH Phase0 裁决报告 — kuna slacomp 借用 PoC（2026-09-26，Lane SLEIGHPOC）

> 车道 `wt/sleighpoc`（worktree `/dev/shm/rugra-worktrees/sleighpoc`），基 = master `1c99ebad`，ghidra/ symlink = 锁定 oracle。
> oracle = Ghidra `Ghidra_12.0.4_build` / commit `e40ed13014025f82488b1f8f7bca566894ac376b`（`git -C ghidra rev-parse HEAD` 亲验）。
> 借用候选 = kuna（Apache-2.0，github.com/Noelo-Lab/kuna），clone `--depth 1` HEAD `0096e984d74846e45f42c1dbe1fb95252083dda2`（只读参考，未进仓）。
> 上游票：`SLEIGH-RUSTIFY-PHASE0-KUNAPOC-0001`（wt/sleighgap `55ae2b7d` 登记，root 决策点）；背景见
> `SLEIGH_RUSTIFICATION_ROADMAP_2026-09-26.md`（同分支）与 `/dev/shm/rugra-reports/LANE_SLEIGHGAP_2026-09-26.md`。
> 本车道零 `src/` 改动；全部实验产物在内存盘 `/dev/shm/rugra-tests/sleighpoc/`（结论已归档 `/dev/shm/rugra-reports/`）。

## 0. 裁决速览

| 问题 | 结论 |
|---|---|
| **裁决** | **BORROW-TRACK（借用+适配轨道）**，按票面规则触发：x86-64 主实验 PASS（content-identical）→ 且 3/3 非 x86 采样全 PASS |
| x86-64 主实验 | kuna slacomp 编锁定 `x86-64.slaspec` → 解压 packed 元素流与锁定 `sleigh_opt` 产物**逐字节恒等**（4,124,687 B，sha 同；2,052,483 事件流同；元素计数差 NONE） |
| 非 x86 采样（3/3） | ARM `ARM8_le` / MIPS `mips32le` / `AARCH64` 全部解压流逐字节恒等（事件流 1,040,340 / 662,533 / 1,971,093 双侧相等，零差异） |
| decode 面 | kuna 产物喂回**锁定 C++ 运行时**（git archive 重建的 sla_opt 对象）线性解码两语料（ELF 头字节 4,158 行 / 真实 .text 2,243 行），与 oracle .sla 解码流**逐字节恒等**，异常流（27 条）亦恒等 |
| 唯一系统性差异 | **deflate 后端**：zlib C（C++ `FormatEncode`）vs flate2/miniz_oxide（kuna）→ 压缩字节与尺寸不同（x86-64 −2,722 B / −0.56%；四样本 −0.15%~−0.91%），**内容零差异**；FORMAT_VERSION 双侧均为 4 |
| kuna vendor 版本失配风险 | 39 模块/148 specs vs 锁定 38/146——**未在本实验 4 样本中激活任何语义分叉**；残余风险由 Phase1 的 146/146 全量 sweep 强制门禁收口 |
| 成本对比 | 借用=vendor 四 crate（slacomp 10,385 行 + kuna-sleigh 32,687 + base/num 19,988 ≈ 63k 行现成 Rust，外部依赖仅 thiserror+flate2 且 flate2 已在 Rugra）+ 适配；从零=11,940 行编译器（roadmap 估 5-8 车道日）+ 相同的验证成本 |

---

## 1. 实验设置与自证链

### 1.1 双编译器来源

| 侧 | 来源 | 构建方式 |
|---|---|---|
| oracle `sleigh_opt` | 锁定树 `git archive e40ed130 …/cpp + Processors/{x86,ARM,MIPS,AARCH64}/data/languages`（绕过稀疏检出，规格源=树内对象，非工作区） | `make -s -j4 sleigh_opt`（g++ 12.x，系统 zlib） |
| `slacomp` | kuna HEAD `0096e98`，crate `kuna-slacomp` | `CARGO_TARGET_DIR=/dev/shm/rugra-targets/sleighpoc cargo build --release -p kuna-slacomp --bin slacomp`（rustc 1.96.0-nightly） |

**管线自证**：本地重建的锁定 `sleigh_opt` 编 `x86-64.slaspec` 输出 sha256
`d5adc314e2278228b380d8f653b2b579fa4a65986bb1d39b095e461fd5432481`（487,659 B），
与仓内 `sleigh_specs/x86-64.sla`（`build_locked_x86_64_sla.sh` 门禁钉值）**字节恒等**——实验
oracle 侧与既有资产管线完全一致。锁定 slaspec 输入 sha `9d66a01a…`（与脚本钉值一致）。

### 1.2 三级对比法（判据分级）

`.sla` = 4 字节头 `sla\x04`（`slaformat.cc` FORMAT_VERSION=4）+ zlib 流；解压体 =
`marshal.hh` PackedEncode 元素流（record 0x40/0x80/0xc0 + 7-bit 扩展 id + 类型码 1-7）。

1. **字节级**：整文件 sha256（Ghidra 自身产物在此级受 zlib 版本影响）。
2. **解压流级（正典判据，kuna 先例同法）**：zlib inflate 后 packed 元素流逐字节比对——
   编译器全部可观测输出（符号表/构造器/decision 树/模板/空间表/源文件索引）都在这一层。
3. **结构级**：自研 parser（`/dev/shm/rugra-tests/sleighpoc/sla_compare.py`+`sla_diff_fast.py`，
   id↔名字表逐条取自锁定 `slaformat.cc`）解码事件树，锁步走查 + 元素计数直方图 + 首分歧定位。

## 2. 主实验：x86-64（票面裁决点）

| 指标 | oracle `sleigh_opt`（锁定重建） | kuna `slacomp` | 判定 |
|---|---|---|---|
| 编译耗时 | 0.710 s | 0.674 s | 同量级 |
| .sla 字节 | 487,659 B，sha `d5adc314e227…`（==仓内参考） | 484,937 B，sha `406bfa48bca4…` | 字节级不同（deflate 后端） |
| 解压流 | 4,124,687 B，sha `2e36b32d8194…` | **4,124,687 B，sha `2e36b32d8194…`** | **IDENTICAL** |
| 事件数 | 2,052,483 | 2,052,483 | 相等 |
| 元素计数差 | — | `NONE`（全类型同数） | 零差异 |
| 首分歧 | — | `null`（无分歧事件） | 零差异 |

## 3. 采样实验：3 个非 x86 规格（分叉面采样）

从锁定树 146 个 `.slaspec` 中取 3 个跨族样本（ARM 现代核/MIPS 延迟槽/ARMv8 A64）：

| 规格 | oracle .sla | kuna .sla | 解压流（双侧） | 事件数（双侧） | 元素计数差 | 判定 |
|---|---|---|---|---|---|---|
| `ARM/ARM8_le.slaspec` | 266,604 B `e0430ed3…` | 265,411 B `8efcba03…` | **2,140,173 B 恒等** | 1,040,340 | NONE | content-IDENTICAL |
| `MIPS/mips32le.slaspec` | 166,093 B `58f26c36…` | 164,585 B `56b62d31…` | **1,372,990 B 恒等** | 662,533 | NONE | content-IDENTICAL |
| `AARCH64/AARCH64.slaspec` | 494,950 B `edbad506…` | 494,199 B `de0456dc…` | **4,043,534 B 恒等** | 1,971,093 | NONE | content-IDENTICAL |

**kuna 编译器确定性**：`ARM8_le` 复跑二次输出 sha 恒等（`8efcba03…`）——复现 `build_locked`
脚本"双编译字节恒等"框架的可移植性。

## 4. decode 面（Phase0 验收 ③）

`probe_decode.cc`（内存盘）链接**锁定树运行时对象**（sleigh/sleighbase/slaformat/marshal/
slghsymbol/slghpattern/slghpatexpress/semantics/…），以 `Sleigh::initialize(DocumentStorage)`
装载 .sla，线性解码固定 512 B 缓冲并 dump 全部 P-code op。

| 语料 | oracle .sla 解码流 | kuna .sla 解码流 | 判定 |
|---|---|---|---|
| ELF 头 512 B（垃圾指令流） | 4,158 行 + 251 指令 | 4,158 行 | **逐字节恒等**（`setarch -R` 下未做任何掩码的 diff=0） |
| `/usr/bin/ls` .text 512 B | 2,243 行 + 27 条异常 | 2,243 行 + 27 条异常 | **逐字节恒等**（异常流亦逐条相同） |

ASLR 噪声判定过程（如实记录）：垃圾字节解码路径会命中引擎对未初始化内存的读（dump 出
heap 指针形态常量，如 `const:5b53ba138090`，共 1,487 处，双侧同数同位）；开 ASLR 时该值逐跑
漂移（同一 .sla 两次运行 sha 即不同），`setarch -R`（正典 oracle 捕获配方同款）后双侧
**连这些伪常量都逐字节一致**——证明其为环境伪影而非 .sla 内容差异；干净 `.text` 语料不出现
该形态。**kuna 产物在锁定 C++ 运行时中完全可装载、可解码、与 oracle 产物不可区分。**

## 5. 差异分类总表

| 差异 | 级别 | 归因 | 处置 |
|---|---|---|---|
| 压缩字节/尺寸差（−0.15%~−0.91%） | 字节级 | flate2（miniz_oxide）vs zlib C 的 deflate 输出差 | 无内容语义；Phase1 字节门决策项（§7.3） |
| （无其他差异） | 解压流/结构/decode | — | — |

## 6. 裁决

按票面裁决规则："x86-64 过 → 扩 146 全量 parity；PASS → Phase1/2 转借用+适配轨道"：

- **主实验 PASS**：x86-64 解压元素流与锁定 oracle 产物逐字节恒等。
- **采样 PASS**：3/3 跨族规格（ARM/MIPS/AARCH64）同判。
- **decode 面 PASS**：锁定 C++ 运行时对 kuna 产物解码与 oracle 产物不可区分（双语料）。
- **kuna vendor 树版本失配（39/148 vs 38/146）在 4 样本上零激活**。

→ **BORROW-TRACK**：Phase1 以 kuna slacomp 为主体做"vendor+适配"，从零轨道（11,940 行编译器
重写）不采；kuna 的 148/148 证据仍**不可转认**（铁律 2.1），全部后续门禁仍以锁定 oracle 为唯一种子。

**诚实边界**：4/146 是抽样（约 30% 事件量覆盖 x86-64+ARM+MIPS+AARCH64 四族），非全量；
146/146 全量 sweep 是 Phase1 的**入场门禁**而非可选项。字节级 sha 门（`d5adc314…`）在
flate2 默认后端下**不可复现**——是门禁判据决策项，不是编译器缺陷。

## 7. Phase1 适配清单（BORROW-TRACK 轨道，写域 `src/sleigh/` + `tools/` + `NOTICE`）

1. **vendor 四 crate**（`kuna-base`/`kuna-num`/`kuna-sleigh`/`kuna-slacomp`，kuna HEAD
   `0096e98`，含 Cargo.toml/lock 锚定）：初版以 workspace member 形态整体进入（如
   `crates/sleigh/{…}` 或 `src/sleigh/vendor/…`），**Phase1 不做类型统一改写**；与 Rugra 既有
   `address/space/pcoderaw/opcodes/marshal/translate/loadimage` 的统一是 Phase2 的独立决策项
   （kuna-sleigh 32,687 行中 emulate/memstate 等 Rugra 已有对应物，届时去重）。
2. **外部依赖处置**：kuna 仅 `thiserror`（2.0）+ `flate2`（1.1）；Rugra 已有 `flate2 1.0` 与
   `thiserror 1.0`——统一为 thiserror 2.0 或将 vendored crate 降兼容，二选一在 Phase1 定。
3. **字节门决策项（root）**：(a) **推荐**：`.sla` 资产门禁判据由"裸字节 sha"改判
   "解压元素流 sha + FORMAT_VERSION + 尺寸带宽"（与 Ghidra 语义一致、跨 zlib 版本稳定），
   `build_locked_x86_64_sla.sh` 增 Rust 编译器路径并保留 C++ 路径对照至 Phase2 结束；
   (b) 备选：flate2 换 zlib 后端（libz-sys）尝试裸字节恒等——若 zlib 版本一致则可能达标，
   但引入系统库版本耦合，不推荐作正典。
4. **146/146 全量 sweep 驱动**（`tools/`）：批量 `slacomp` vs 锁定 `sleigh_opt`，
   解压流比对（本车道 `sla_diff_fast.py` 为种子，~0.7 s/规格，全量分钟级）；任一规格 FAIL →
   回到差异分类表逐项修（修 kuna 侧代码，锁定 oracle 为准），全 PASS 才算 Phase1 收口。
5. **NOTICE 增补**：kuna/Noelo-Lab（Apache-2.0）+ 其 angr（BSD-2）归属随 kuna-num 进入时连带
   列出；被借文件保留源头双锚注释（Ghidra 行号 + kuna commit `0096e98`），遵守本仓
   `// Ghidra:` 注解纪律（新文件首 commit 起）。
6. **spec 集失配解决**：kuna vendor 树（148 specs）**不进仓**；Rugra 侧输入永远=锁定树
   `git archive`（`build_locked` 脚本模式），kuna 树仅作代码来源。39/148 差异因此对 Rugra 无效。
7. **语义差异修正点**：本实验**零发现**；Phase1 sweep 若暴露（预期集中在极小众规格的
   构造器序/上下文编码差异），逐规格登记 TODO + 修 kuna 侧 + 复跑 sweep。
8. **Phase2 前置条件不变**（roadmap §Phase2）：Rust 运行时化仍需独立验证面（逐指令 P-code
   差分 + E2E A/B），slacomp 借用成功不豁免运行时侧的 oracle 门禁。

## 8. SCRATCH-TRACK 成本重估（不采，留档）

- 从零重写 slghscan/slghparse/pcodecompile_actions/slgh_compile/encode（锁定 oracle
  11,940 行 C++）：roadmap 原估 5-8 车道日；kuna 先例单 wave（06-19→06-20）到 148/148 是
  连续 LLM 高强度作业的产物，本仓无此带宽则上限取 8 车道日。
- 借用轨道的对应成本：vendor+构建接线 ≤1 车道日，sweep 驱动+门禁改造 ≤1 车道日，
  预留 sweep 修复 0-2 车道日（本实验证据面下预期趋 0）。
- 两条轨道的 oracle 验证成本**相同**（都必须过锁定树全量 sweep + decode 差分）。

## 9. 复现命令（全部产物在 `/dev/shm/rugra-tests/sleighpoc/`）

```bash
# 取材
git clone --depth 1 https://github.com/Noelo-Lab/kuna /dev/shm/rugra-tests/sleighpoc/kuna
cd /dev/shm/rugra-tests/sleighpoc/kuna/decompiler && \
  CARGO_TARGET_DIR=/dev/shm/rugra-targets/sleighpoc cargo build --release -p kuna-slacomp --bin slacomp
# 锁定规格源 + oracle 编译器
git -C ghidra archive --format=tar e40ed130… Ghidra/Features/Decompiler/src/decompile/cpp \
  Ghidra/Processors/{x86,ARM,MIPS,AARCH64}/data/languages | tar -x -C locked
make -s -C locked/…/cpp -j4 sleigh_opt          # 产物 == 仓内 x86-64.sla 字节恒等（自证）
# 四样本双编译 + 三级对比
…/sleigh_opt  locked/…/x86-64.slaspec out/x86-64.oracle.sla
…/release/slacomp locked/…/x86-64.slaspec out/x86-64.kuna.sla
python3 sla_diff_fast.py out/x86-64.oracle.sla out/x86-64.kuna.sla   # → inflated_identical:true
# decode 面
g++ -O2 -o probe_decode probe_decode.cc -I…/cpp …/cpp/sla_opt/*.o -lz
setarch -R ./probe_decode out/x86-64.oracle.sla probe_bytes.bin > a; setarch -R ./probe_decode out/x86-64.kuna.sla probe_bytes.bin > b; diff a b
```

## 10. 票据与路线图更新

- `SLEIGH-RUSTIFY-PHASE0-KUNAPOC-0001` → **DONE**（本报告为证据载体；裁决=BORROW-TRACK）。
- `SLEIGH-RUSTIFY-PHASE1-0001` → 按本报告 §7 细化（vendor 形态/字节门决策/146 sweep 入场门禁）。
- `SLEIGH_RUSTIFICATION_ROADMAP_2026-09-26.md`（wt/sleighgap，待 root 合并）：Phase0 节补记
  裁决结果 + Phase1 节按 §7 更新（合并时以本报告为准）。

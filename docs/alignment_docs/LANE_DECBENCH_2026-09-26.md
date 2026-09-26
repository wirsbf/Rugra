# LANE DECBENCH — DecBench 头对头对拍参与规格报告

> 日期 2026-09-26 | 车道 DECBENCH（纯研究零 src 零 commit）
> 前置：LANE_ACADEMIC_SURVEY_2026-09-26.md（kuna 五问）、RUGRA_MASTER_ROADMAP_2026-09-26.md（Phase B 规划）
> 方法：全部结论经 websearch/webfetch 一手实查（GitHub decbench/kuna raw 文档、decbench.com、HF dataset scoreboard.toml 原文），Rugra 侧经主仓只读勘察（CURRENT_STATUS/TODO_BOARD/examples/src/Cargo/sleigh_specs/tools）。MB18 并 master 期间未写主仓任何文件。

---

## 一、DecBench 全档案

### 1.1 本体

| 项 | 事实 | 出处 |
|---|---|---|
| 维护方 | Noelo Lab @ University of Georgia（Zion Leonahenahe Basque = mahaloz，SAILR 一作、angr/sefcom 系）——**与 kuna 同门** | github.com/Noelo-Lab、noelo.org/research |
| 仓库 | github.com/Noelo-Lab/decbench（Python 包，`pip install -e ".[dev]"`，CLI=`decbench`） | README |
| 网站 | decbench.com（living leaderboard，`?snapshot=DD-MM-YYYY` 冻结引用） | site changelog |
| 数据 | HF `noelo-lab/decbench-dataset`（二进制+`.i`+evalkit zip，LFS） | README |
| 性质 | 工程基准无论文；自我定位 = 对 Decompile-Bench (NeurIPS'25) 与 DecompileBench (ACL'25) 的"correctness 一等公民"回应；GED 指标源自 SAILR/cfgutils | about 页 |
| AI 政策 | **禁止全自动贡献**（issue/PR/comment 由 AI 端到端提交会被关）；允许 AI 生成代码但须人类拥有。→ Rugra 的对外提交必须 root/人类署名发出 | README AI Policy |

### 1.2 语料构成（published scoreboard 2026-09-23T19:00）

**总量：96,103 函数 / 770 二进制 / 41 项目 × {O0, O2, O2-noinline}**（kuna 文档 08-03 快照为 94,575/803/39——语料在演进，引用须带 snapshot 日期）。分母：GED 91,062；type_match 88,236；byte_match 56,465（仅 x86 宿主可测）；Union 95,421。

| 子集 | 项目 | 架构/工具链 | 对 Rugra 的意义 |
|---|---|---|---|
| **sailr**（26 个 Debian 包）| coreutils/grep/gzip/zlib/bzip2/tar/bash/openssh/gnutls/dpkg/e2fsprogs/iproute2/rsyslog/shadow/sysvinit/kmod/cronie/dash/diffutils/findutils/base-passwd/libacl/libbsd/libedit/libexpat/libselinux | **x86-64 ELF、宿主 gcc**、O0/O2/O2-noinline | ✅ 我们的射程内（canon 五语料同类） |
| **cps**（9 个）| libopencm3/FreeRTOS/ChibiOS/NuttX/RIOT-OS/Betaflight/Cleanflight/Crazyflie/U-Boot | **ARM 交叉编译**（arm-none-eabi / arm-linux-gnueabihf，Cortex-M/-A，Thumb） | ❌ 无 ARM spec；kuna 的翻车区（recall 池 98.3% 是嵌入式 ARM） |
| **malware**（6 个，theZoo 源码编译，只编译绝不执行，容器内静态）| mirai（ELF/x86 gcc）、mydoom/x0r-usb/minipig/dexter（**PE/i686 MinGW**） | x86-64 ELF + **32-bit x86 PE** | 半射程：x86-64✅；i686 PE 需 x86.sla+PE loader |
| **cpp** | leveldb（唯一 C++ 目标） | **默认禁用**（projects/cpp/disabled/） | ✅ 对我们有利——C-only，无 C++ 前端差距 |

### 1.3 三指标精确定义（docs/metrics.md 实查）

1. **GED（结构）**：Joern/pyjoern 把**源码（必须宏展开后的 `.i`/`.ii`）**与反编译 C 各提升为 CFG → 先做 entry/exit 角色感知的有向图同构判定（同构=0，无大小限）→ 非同构 ≤200 节点用 VJ-GED（SciPy 编译求解器）→ 更大图用 |Δnodes|+|Δedges| 非零下界。**只看控制流形状，不看节点标签**。perfect = GED 0。
2. **type_match（类型）**：DWARF 真值（pyelftools，ELF+PE 均可）vs 反编译变量。只有带 DWARF location 的变量计入分母（全优化掉的对所有人剔除）。三段对应：参数按 **ABI 位序**（name 无关）→ 栈变量按自动校准帧偏移 → 剩余变量按**验证过的指令地址重叠**。类型串经 `normalize_type` 集合相交判定（`int4`↔`int`、指针 pointee 规则、`undefined4*` 对 `size_t*` = miss）。**7 后端原生证据白名单**（angr/binja/dewolf/ghidra/ida/kuna/r2dec，需 VariableInfo.addresses/line_mappings）；其余后端走 caveat 的 fallback（签名解析+栈/名匹配，榜上带星号）。perfect = 1.0。
3. **byte_match（重编译字节）**：compilability fixup（只注入 gcc 报缺的 typedef/原型/struct——从不改写逻辑）→ 用**原工具链原 flag**（DWARF producer 读出；x86→gcc、ARM→arm-none-eabi、PE→MinGW）重编译 → 汇编逐行 diff，链接期操作数（call/jmp 目标、`[rip±disp]`）归一化抹除。工具链不在=abstain（非 0）。perfect = 1.0。
4. **Union = 至少一个指标 perfect 的函数占比**（分母=有 ≥1 可测指标的函数）。初始排序键。

已知口径细节（影响我们怎么做）：
- 评估**只吃反编译文本**（无深 API 也能参赛——LLM 都能上）；文本对齐误差是基准自身承认的限制。
- ARM/PE 的 byte_match 在维护者机器上 abstain（无交叉工具链）——GED/type_match 扛这些切片。**自跑时本机装了 arm-none-eabi/MinGW 即可测**。
- C++ 同名方法坍缩使 leveldb 的 GED 与 C 项目不可比（目前禁用，无影响）。
- `DECBENCH_DWARF_ABSTRACT_ORIGIN=1`（O2 下回收 inline+outline 双 DIE 函数 +13.7%）**默认关**，开了会动榜——引用口径时注意。

### 1.4 参与协议（三条路）

| 路 | 形态 | 覆盖 | 门槛 |
|---|---|---|---|
| **I. 插件后端**（正路）| 在 decbench 树内实现一个 Python 类：`is_available()/get_version()/decompile_binary(binary_path, functions, output_dir, function_names, progress_path) -> DecompilationResult` | 全量语料、全指标、可进原生白名单 | 需上游 PR（**AI 政策禁全自动提交**→人类署名）或自跑自证 |
| **II. LLM agent** | 每函数一次 agentic call | 仅 sample-set | 不适用 |
| **III. 外部提交** | 下载 evalkit（250 函数 sample-set，seed 1337，stripped+匿名二进制+functions.json 地址清单）→ 自己解 → `results/*.c`（每二进制一个整文件，函数拼接，允许 typedef/struct helper）+ `results/results.json`（`{"decompiler":{"name","version"},"results":{"bin_000.c":{"binary":"bin_000.elf","functions":{"sub_1234":"0x1234"}}}}`）→ `python3 package.py` → 结果 zip 发 decbench@zionbasque.com 或开 issue | **仅 sample-set 列**（250 函数）、type_match 走 fallback 带星号、可要求 `private_artifacts`（出分不公开代码） | **零安装零开源暴露**；partial 提交合法（未试函数计 missing） |

**关键输入语义（两条路通用）**：反编译器拿到的是 **stripped 二进制副本**（`.debug_*` 全删、`.text` 与原版字节恒等校验）+ **目标函数地址集**（DWARF `low_pc`，ELF-file-space=文件头程序头 vaddr 空间；PE 为 ImageBase+RVA；Thumb 取偶地址）。Ghidra/IDA 拿到同样输入——"honest RE setting"。**→ 函数发现不是基准考点，地址已奉上**；要做的只是"在给定地址反编译出 C + 正确回报地址空间"。
- `.text` 族过滤 + CRT/PLT 跳过集由 `raw/common.py` 统一提供（插件路直接 import）。
- kuna 的 CLI 形态（插件路模板）：`kuna decompile-all <bin> --json --max-fn-seconds <N>`，JSON 返回 `{functions:[{name,address,size,code,error,variables[{name,type,kind,arg_index,stack_offset,line_numbers,addresses}],line_mappings[{line_number,addresses}]}]}`；地址=Ghidra 系 link/file space 免换基；子进程 `start_new_session`+组杀；payload 按 binary 缓存。

### 1.5 资源/超时协议

- 每 `(binary, decompiler)`：硬 **3600s 墙钟**（`DECBENCH_DECOMPILE_TIMEOUT` 可改）+ **16 GiB 内存**（cgroup v2 + systemd-run 强制，含原生后代；容器另有 16 GiB Docker limit）。
- 每函数 watchdog **600s**（仅暴露可杀 API 的后端：Ghidra/Kuna/Glaurung/LLM；kuna 经 `--max-fn-seconds`）。
- 驱动按项目 checkpoint 断点续跑；`progress_path` 原子 pickle 部分结果（被 SIGKILL 也能回收）。
- 语料最大二进制 = O0 bash 1.44 MiB——**没有 mpengine 级怪物**；超时面对我们不构成威胁（见 §2.4）。

### 1.6 榜单现状（HF scoreboard.toml 2026-09-23T19:00 原文，全量榜）

| rank | 反编译器 | Union% | GED perfect% | type_match% | byte_match% |
|---|---|---|---|---|---|
| 1 | **kuna (v1.121)** | **41.06** | **39.05**(1) | 6.91(6) | 5.82(2) |
| 2 | ida | 40.21 | 37.68(2) | 7.46(5) | 3.60(5) |
| 3 | angr | 39.58 | 36.01(3) | 8.47(3) | 5.60(3) |
| 4 | binja | 32.58 | 28.79(4) | 8.83(2) | 2.13(6) |
| 5 | **ghidra** | **32.26** | 28.45(5) | 7.56(4) | 4.52(4) |
| 6 | codex@gpt-6-astra | 26.49 | 23.98(6) | **9.27**(1) | **15.08**(1) |
| 7 | r2dec | 21.06 | 20.27(7) | 2.50(8) | 0.20(7) |
| 8 | dewolf | 7.39 | 3.65(8) | 4.60(7) | 0.00(14) |
| 9-14 | codex/claude-code/glaurung/fission/reko/manifold | 0.16/0.15/0.087/0.077/0.042/0.023 | — | — | — |

**读法**：①Rugra-default 若逐函数≈Ghidra，落点=Union ~32% 档、rank ~5；**超越 kuna 的 41.06 需要 +8.8pp，只能靠 Phase 4 增强轨**。②Ghidra 自身 GED perfect 仅 28.45%——71.5% 函数连 Ghidra 都不结构完美，残差收敛=分数。③type_match 是 Ghidra 系弱项（kuna 6.91<ghidra 7.56<binja 8.83），ENH-3 ML 层的靶点。④byte_match 全场低（kuna 5.82 已是第 2）——LLM codex@gpt-6-astra 15.08 断层第一但 GED 崩（23.98），Union 仍落后传统引擎：单指标突进换不来 Union。

### 1.7 kuna 成绩细节与已知弱点（头对头侦察）

- **版本口径**：榜上 v1.121（2026-08-08 升级）；当前已 v1.160+（09 下旬）未重测——引用其分数必须带版本+日期。
- **跑分配置**（kuna 自己的 decbench-loop.md 交代）：`decompile-all --json`，`--mode auto` → **768/803 二进制走 aggressive**（<500KiB），35 个大件（bash/sshd/tar/u-boot 等）走 reliable；aggressive 携带 21 个 option override。**即其榜上分数是 aggressive 脸**。
- **已知弱点**：
  - `#510`（closed）：mpengine.dll 18MB 上 `decompile-project` 29m54s / `decompile-graph` 37m48s，Ghidra 约快 2×，两处 panic，8 函数失败（5 个 per-fn 10s 超时）——大二进制吞吐+鲁棒性（MB4 已复测 mpengine 战场规划）。
  - `#299`（open）：AIF 在大 i386 PE 上种 ~2100 个假入口、35% 落真函数体内——入口发现假阳性。
  - **ARM recall**：kuna 自测 recall 池 1,420–1,552 函数无可用 GED，98.3% 是嵌入式 ARM 入口粒度问题（median 24 字节离最近入口）；已修 4 个 discovery pass（cortexmvectors/ptrentry/tailcallentry/poolentry，entry recall 88.63%→93.31%），TBB/TBH switch 解析未动工。**DecBench 给地址，此坑我们可绕**。
  - **byte_match 口径伤**：kuna 的 ARM/PE byte_match 在 O2/O2-noinline 两个优化级上因维护机无交叉工具链而缺失（曾误删 checkpoint 被 coverage guard 拦下，`DECBENCH_ALLOW_DROPS=1` 惨案）——其 byte_match 5.82% 是**欠计**状态。
  - type_match 6.91%（rank 6，v1.121 公开测量）：落后 ghidra/angr/binja；roadmap #261 无 ML 计划。
- **kuna 把 DecBench 当改进仪器**（mine/triage/rescore/optsweep/entrysweep 闭环，docs/decbench-loop.md 6.5K 字方法论）——这套"信号→triage→feature→双向 sweep"打法值得整体移植到 Rugra（我们的 per-function oracle 对拍比它的更强）。

---

## 二、Rugra 参与差距分析（逐项核现状）

### 2.1 ① CLI 形态

| 需求（DecBench） | Rugra 现状 | 差距 |
|---|---|---|
| 批量：`decompile-all <bin> --json`（整二进制一次调用，尾端一份 JSON） | `bin/rugra`（ELF-only、符号驱动、stdout C 文本、无 JSON/无地址定向/无超时）= demo 级；**真正的驱动在 examples**：`gen_decompile`（BFD 符号发现+PT_LOAD+import 重定位+裸 face+`--one` 子进程隔离+`RUGRA_GEN_TIMEOUT_SECS`）、`bin_sweep`（鲁棒性扫）、`parallel_decompile`（PoC）、`curl/httpd_decompile`（canon manifest 驱动） | **中**：需一个 kuna 形态的 runner（新 driver，库件全齐）。缺：JSON schema、地址集定向（`--addr` 列表）、`.text` 族过滤+skip 集、per-fn 预算、progress checkpoint |
| 地址空间=ELF-file-space（min PT_LOAD vaddr，PIE 需正确换基） | F2B 后 canon 面 0x100000 image-base 载入；gen_decompile base-0 口径；换基件齐 | **小**：runner 里统一输出 file-space 即可（evalkit 明确：Ghidra 系减 0x100000） |
| 超时/预算：3600s/二进制、600s/函数（可杀+部分结果回收） | 子进程隔离+timeout 模式已有（bin_sweep/gen_decompile `--one`） | **小**：套用现有 child-process 模式 |

### 2.2 ② 输出格式

| 指标 | 消费物 | Rugra 现状 |
|---|---|---|
| GED | 反编译 C 文本（Joern 解析） | ✅ PrintC=Ghidra 格式 C；sqlite3 stripped 语料 1385/1385 全产出、defects 0 |
| byte_match | 同一 C 文本（fixup 后 gcc 重编译） | ✅ 文本即消费物；gcc 审计 curl 104OK/20FAIL、httpd 15OK/14FAIL（fixup 注入 typedef/原型后会更高） |
| type_match | C 签名（fallback 带星号）或 `variables[]`+`line_mappings`（原生白名单） | ⚠ fallback 可用即参赛；**原生证据需 print 层行→地址 provenance 导出**（varmap 侧变量信息已在，缺 LineMapping 面映射） |

### 2.3 ③ 语料覆盖（架构面 = 最大差距）

| DecBench 切片 | Rugra 现状 | 供给路径 |
|---|---|---|
| x86-64 ELF（sailr 26 项目 + mirai） | ✅ 生产射程（canon 五语料+bin_sweep 泛化面） | 无 |
| 32-bit x86 PE（malware 4 个 i686 MinGW） | `sleigh_specs/` 已有 x86.ldeps/x86.pspec/x86gcc.cspec，**x86.sla 未编**；`src/binary/mod.rs` 有 PE 解析骨架（X86/X86_64 machine 识别+ImageBase）；**无 PE loader/loadimage E2E** | slacomp 编 x86.sla=on-rails（Rust 编译器 146/146 spec 内容扫描已证）；PE 装载+MinGW 特性=实工作 |
| ARM Cortex-M/-A Thumb（cps 9 项目） | ❌ 零供给（无 .sla/无 armgcc.cspec/无 Thumb） | slacomp 编 ARM spec 族 + arch dispatch + cspec/pspec + Thumb 模式切换；kuna 的 ARM 战史（recall 池+4 discovery pass）=难度路标 |
| C++（leveldb） | 禁用中 | 无需 |

**spec 供给无 availability 问题**：`/home/ls/Rugra/ghidra` 是锁定 oracle 的完整 git 对象库（`git archive $LOCKED_ORACLE Ghidra/Processors/<arch>/...` 可取任何架构 spec——`build_locked_x86_64_sla.sh` 即此模式，且 Rust slacomp 对 146 个锁定 spec 全部编译通过）。

### 2.4 ④ 超时/资源竞争力

- **预算充裕**：DecBench 最大二进制 1.44 MiB（bash O0）、目标集=DWARF 收窄后的项目自有函数。Rugra 实测：canon curl 124 函数 1m54s（≈0.92s/fn 串行、子进程隔离含固定开销）、httpd 34 函数 ~59s、sqlite3 1,385 函数镜像臂 20m15s（并行分片；串行画像 987.9s/1355 fn ≈0.73s/fn）——对 3600s/二进制、600s/函数的预算，**除极少数大函数外无压力**。
- **已知病灶已排雷**：PATHOSLOW 非终止族（divchain 11 函数烧 600s）已修；PRETTYFLUSH panic 族已清；GEN5C 终版 1385/1385 ok、172s 零重试。
- **遗留固定开销**：PERF-DUAL-SLEIGH-INIT-0001（每子进程双 SLEIGH 装载 ≈430–480ms；curl CPU 3.16× oracle、~90% 固定项）在队——修后小函数成本减半级。**墙钟不是参与 blocker**；对外叙事仍按总路线图走"mpengine 级实测"而非 DecBench。
- 内存：单任务 16 GiB 上限，现状远低于。

### 2.5 ⑤ stripped 条件下的质量面（诚实核心）

DecBench 全员拿 stripped 二进制。Rugra 的 canon 高分（curl 200/0/0、httpd 229/0/0，MB17 后 master 合成态）是 **manifest 播种脸**；无播种的诚实参照是：

- **sqlite3 第五语料 = 唯一 stripped 口径对拍**（dynsym-only、golden=锁定 oracle 直跑同输入）：ok 1385/1385、**defects 0 / numbering 0**（语义零缺陷）、skeleton 26,833（镜像臂门禁口径）≈ **19.4 行/函数结构残差** vs oracle——这是 DecBench 条件下我们与 Ghidra 的真实距离。
- 镜像/裸面 ratchet 持续收紧（curl 58/65、httpd 156/156、vsh 15/16、sq 4481/7500）。
- **推论**：Rugra-default 的 GED perfect 率短期会**低于** Ghidra 的 28.45%（结构残差未清零前），Union 落点 <32%。逐函数≈Ghidra 的收敛度直接兑换成 GED 分数——Phase 0 主线与 DecBench 分数**同一条战线**。
- front-end：`src/frontend.rs` 已并（ELF 符号导入/函数发现/内存映射/demangle，FRONTEND-MINIMAL 数据层）。**DecBench 给地址→STRIPPED-DISCOVERY 决策点与参赛解耦**（它是真实世界胜负面，不是基准前置）。

---

## 三、工作包分解

| WP | 内容 | 量级 | 依赖 | 优先级 |
|---|---|---|---|---|
| **WP1 runner CLI** | kuna 形态驱动：`rugra decompile-all <bin> --json --max-fn-seconds N [--addrs file]`；JSON schema 对齐 §1.4；地址=file-space；`.text` 族过滤+skip 集；per-fn 子进程隔离+progress checkpoint。examples 层新驱动（库件全在） | 1–2 周 | 无 | **P0**（一切的前提） |
| **WP2 decbench 接入** | `rugra_raw.py` 插件后端（out-of-process，dewolf 模式）+ 冒烟（`decbench evaluate a.elf -d rugra -s a.i`）；或先用**外部 evalkit 通道**（零 PR） | 2–4 天 + 人类署名 PR（AI 政策） | WP1 | **P0** |
| **WP3 本地跑分手台** | `pip install -e decbench`；HF dataset materialize（免重编）；sailr x86-64 O0 首跑 `-d rugra -d ghidra`（本地装 Ghidra 12.0.4=锁定 oracle → **同口径逐函数 Rugra vs Ghidra diff 自证**）；装 arm-none-eabi/MinGW 可选（开 ARM/PE byte_match） | 3–5 天 | WP1（WP2 可后） | **P0** |
| **WP4 对拍改进闭环** | 移植 kuna 的 mine/triage/rescore 方法论（`decbench improvements -b ghidra -t rugra`）+ 接入既有 oracle fixture 体系；残差→TODO 票 | 1 周（持续运营） | WP3 | **P1**（分数引擎） |
| **WP5 variables/line_mappings 导出** | print 层行→指令地址 provenance → VariableInfo{arg_index=ABI 位序, addresses} → 争原生 type_match 白名单（去星号） | 1–2 周 | WP1 | **P1** |
| **WP6 x86-32 + PE** | slacomp 编 x86.sla（on-rails）→ arch dispatch 32 位 → PE loader/loadimage+import 重定位 → malware 子集 | 2–4 周 | WP1 | **P1**（sailr 后第二存在感面） |
| **WP7 ARM Cortex-M/-A** | ARM spec 族编译+cspec/pspec+Thumb 切换+嵌入式 quirks；kuna 战史为路标（其 recall 坑我们免，但其输出质量面未知） | 4–8 周 | WP6 经验 | **P2**（硬仗，后置） |
| **WP8 增强轨（Phase 4）** | best-of-N+重编译选择器（byte_match 口径可直接复用 DecBench 的 fixup/归一化规则抄本）/SAILR 层/ML 类型层 | 3–6 周（总路线图 Phase 4） | WP3（择优需跑分台） | **P1**（超越 kuna 的唯一路径） |

**明确不需要**：STRIPPED-DISCOVERY（地址奉上）；C++ 支持（leveldb 禁用）；mpengine 级吞吐优化（语料无大件）。

---

## 四、诚实评估

### 有把握
1. **参与即得分**：GED/byte_match 只吃 C 文本，PrintC 格式零适配；defects=0 的语义质量在 sqlite3 stripped 全语料已证。
2. **对齐自证是独家卖点**：本地 Ghidra 12.0.4=锁定 oracle，同 corpus 同 stripped 输入双跑 → "Rugra vs Ghidra 逐函数 diff=0/归因清单"——kuna 删了真 oracle 后做不到的声明（学术面 §3.1 已列为护城河①）。这在 DecBench 语境=可公开复核的对齐证据，且与打分互不冲突。
3. **墙钟/内存/鲁棒**：预算内舒适区；panic/timeout 族已清。
4. **C-only 语料**：无 C++ 前端差距暴露。

### 硬仗
1. **ARM cps（9 项目）**：零供给；kuna 同门在此深耕数轮仍有残局。全量榜缺席 ARM=每函数计失败拖 Union。**首跑应明确声明子集口径，全量 ARM 等 WP7。**
2. **Union 超越 kuna（41.06）**：即使逐函数≈Ghidra 完美收敛也只到 ~32% 档。+8.8pp 必须靠增强轨（GED 上限=kuna 的 SAILR 族增益路径 28.45→39.05 的差值空间；byte_match 空间大；type_match ML 层打其空白）。**默认轨的目标是"可自证的对齐"，不是榜首——两层叙事分开。**
3. **type_match 原生证据**：行→地址 provenance 是 print 层新面（Ghidra 的 HighVariable↔PcodeOp 地址信息在库内已有，导出即可，但要过 provenance.py fail-close 校验）。

### 需先补（P0 链）
WP1→WP2/WP3。在此之前一切分数讨论无载体。

### 决策点联动
- STRIPPED-DISCOVERY：**与参赛解耦**（地址目标给定）——按总路线图维持 Phase 3 后裁决。
- Phase 0 残差收敛：与 GED 分数同战线，无需额外投入方向。
- Phase 1 并行化：非 blocker（3600s 预算宽裕），但 WP3 全量三优化级跑时是加速器。

---

## 五、首跑建议（staged）

**Stage 0（内部存在感，~2 周内）**：WP1+WP3——本地 decbench + HF dataset materialize，sailr x86-64 **O0 单优化级**首跑，`-d rugra -d ghidra`（本地 12.0.4）双列。产出：①Rugra 首份 GED/type_match/byte_match 全指标画像；②逐函数 vs Ghidra diff=0/归因报告（对齐自证）；③残差池接入 TODO 体系（WP4 启动）。**零对外暴露。**

**Stage 1（对外存在感）**：扩 O2/O2-noinline + mirai（仍纯 x86-64）后，走**外部 evalkit 通道**（250 函数 sample-set；只解其中 x86-64 ELF 目标，partial 合法但 missing 会拉低——若 x86-64 占比不足可暂缓至 WP6 后）；或插件 PR（人类署名）。要求：`private_artifacts` 可选（首跑可不公开代码）；版本+snapshot 日期钉死引用。

**Stage 2**：WP6 后纳入 malware PE 面；WP5 后 type_match 去星号。

**Stage 3**：WP7 ARM cps 全量榜；此后才谈"全量榜 rank"。

**Stage 4（Phase 4 对应）**：enhanced 轨双列出分（rugra-default + rugra-enhanced），目标 Union>41.06 且 type_match>7.56。

---

## 六、来源索引

- DecBench README/docs（raw.githubusercontent.com/Noelo-Lab/decbench/main/）：README.md、docs/metrics.md、docs/benchmarking.md、docs/decompilers.md（Part I 契约/Part III evalkit）、decbench/decompilers/raw/kuna_raw.py（CLI 形态与 JSON schema）
- decbench.com（about/metrics/data/changelog/snapshots，2026-09-23 19:03 build）
- HF datasets/noelo-lab/decbench-dataset `results/scoreboard.toml`（2026-09-23T19:00 生成原文）
- kuna docs/decbench-loop.md（kuna 跑分配置、aggressive 脸、recall 池、byte_match 欠计、mine/triage 方法论）；issues #510/#299/#261（经学术调研报告一手实查转引）
- Rugra 主仓只读：CURRENT_STATUS.md（PFLIP/F2B/MERGEBATCH1-17 各节）、docs/TODO_BOARD.md（PERFAN/PERFBENCH/PATHOSLOW/PAREVAL/FRONTEND 各行）、Cargo.toml、src/bin/rugra.rs、examples/{gen_decompile,bin_sweep}.rs 头注、src/frontend.rs、src/binary/mod.rs、sleigh_specs/、tools/build_locked_x86_64_sla.sh

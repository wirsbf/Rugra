# PERF-BENCH 2026-09-26 — Rugra vs Ghidra 同口径反编译速度对拍

> 车道:wt/perfbench(worktree /dev/shm/rugra-worktrees/perfbench),基=master `a637227e`。
> 纯测量车道:**零 `src/` 改动**;write domain = `tools/` + `docs/`。
> 测量日期:2026-09-26 14:04–18:40。Rugra=fresh release 构建
> (`CARGO_TARGET_DIR=/dev/shm/rugra-targets/perfbench`,全量冷构建 5m40s);
> oracle=`git archive` 锁定 cpp 树(`b02e230a`)→ `libdecomp.a` → `golden_dump_1204`
> (B2/direct-runner 同基建,g++ -O2,BFD 2.38)。

## 0. 目的与口径设计(为什么这样比)

**问题**:Rugra 相对锁定 oracle Ghidra 12.0.4(`e40ed130`)在**同输入同口径纯反编译**下
慢/快多少?瓶颈面在哪?——补 kuna #510(mpengine.dll 29m54s vs Ghidra 约一半)之外缺失
的**同口径数据洞**。

**公平比法(口径矩阵)**:

| 层 | 内容 | 可否头对头 |
|---|---|---|
| **P1A 主对拍** | 逐函数 hermetic 子进程:oracle `golden_dump_1204 one` vs Rugra `gen_decompile --one`(发现逻辑 1:1 镜像:static+dynamic FUNC 符号+PLT JUMP_SLOT stub,(offset,name) 序;发现数四语料全部恒等)。canon golden 协议 12 并发 worker,每函数 20s cap,3 跑取中位数 | ✅ 同函数集/同输入/同进程模型 |
| P1B 串行 CPU 交叉 | 同 P1A 但 workers=1,每子 user/sys 精确归因(getrusage(RUSAGE_CHILDREN) 差分,每子零开销) | ✅ |
| P2 oracle 引擎面 | oracle `all` 模式:单进程单 Architecture 全函数(无每函数进程/规格加载开销)。Rugra 无进程内多函数驱动(车道零 src 约束)——**仅 oracle 侧上下文行,不是对拍格** | ❌(单侧) |
| P3 canon 驱动层 | `curl_decompile`/`httpd_decompile` All 模式整跑(canon gate 口径;函数面=ledger canon 面,种子/manifest 输入比 direct-runner 丰富) | ❌(上下文) |
| P4 analyzeHeadless | 真 Java headless 全量分析(loader/PLT/引用/demangler/DWARF 分析器,锁源 `tools/build_ghidra_1204_headless.sh` 构建,BUILD SUCCESSFUL)——**口径不同,不可与纯反编译直接比** | ❌(上下文) |

**测量纪律**(AGENTS.md 编译性能实验纪律 → 反编译基准同款):
- 每配置 3 跑取中位数;wall/user/sys 并录;峰值 RSS(/usr/bin/time -v 或 rusage)。
- **user CPU 时间为主指标**(31 用户共享机,测量期 load 75–170/112 核,每跑附 load 快照),
  wall 为辅。
- 页缓存状态:全部热态(发现 pass 已预热;无 root 不可 drop_caches,如实标注)。
- 每语料单跑均 <30min(超限降抽样的预案未触发;libLLVM 本来就按 100 等距索引抽样)。

## 1. 语料

| 语料 | 大小 | oracle 发现 | Rugra 发现(恒等断言) | 角色 |
|---|---|---|---|---|
| `examples/curl`(sha `8af50bca…`) | 162 KB | 74 | 74 ✅ | canon 小语料 |
| `examples/httpd`(sha `805f89cd…`) | 660 KB | 790 | 790 ✅ | canon 中语料(stripped) |
| `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`(sha `f5a7fc23…`) | 1.5 MB | 1385 | 1385 ✅ | GEN5 语料(大头,dynsym-only stripped 契约) |
| `/usr/lib/x86_64-linux-gnu/libLLVM-15.so.1` | 116 MB | 35387 | 35387 ✅ | **大二进制案例**(kuna #510 对照面;本机无 mpengine.dll/大 PE,如实以最大可用 stripped .so 替代;抽样 100/35387 等距索引) |

## 2. P1A 主对拍结果(canon 12-worker hermetic,20s cap,3 跑中位数)

| 语料 | n | oracle user+sys(CPU) | Rugra user+sys(CPU) | **CPU 倍率(Rugra/oracle)** | oracle CPU/函数 | Rugra CPU/函数 |
|---|---|---|---|---|---|---|
| curl | 74 | 11.2 s | 35.4 s | **3.16×** | 151 ms | 478 ms |
| httpd | 790 | 147.1 s | 488.1 s | **3.32×** | 186 ms | 618 ms |
| libsqlite3.so.0 | 1385 | 297.6 s | 1161.0 s | **3.90×** | 215 ms | 838 ms |
| libLLVM-15.so.1(抽样 100) | 100 | 112.8 s | 263.4 s | **2.34×** | 1128 ms | 2634 ms |

wall(参考,load 97–169 下测得,主表 CPU 为准):oracle curl/httpd/sqlite/LLVM 中位
5.3/50.7/126.6/19.7 s;Rugra 4.5/51.7/111.5/45.1 s。**本机 wall 不可作速度结论**:
负载 75–170 时两侧子进程均被调度器拉长(oracle 串行单子 wall/CPU 达 5.4×,见 §4),
wall 倍率(0.84–2.29×)随负载窗口漂移;两侧同窗口同协议,CPU 倍率稳定(rep 间
±10% 内)。

**结论(同口径纯反编译)**:Rugra 当前比锁定 oracle **慢 2.3×(大二进制)–3.9×(中
型语料)**(CPU 口径)。语料越大/函数越大,倍率越低(固定开销被摊薄,见 §5)。

**正确性面(P1A outcomes)**:oracle 两侧全语料全 OK(curl 74/74,httpd 790/790,
sqlite 1385/1385,LLVM 100/100)。Rugra:curl/httpd 全 OK;sqlite 1377–1378/1385 OK,
**7–8 个非终止超时**(20s cap;三 rep 稳定集 {834,835,836,946,1055,1321,1322}+
flaky 788;全部是 PERFAN 11 非终止集 {55,57,114,788,834,835,836,946,1055,1321,1322}
的子集——55/57/114 在 efc28f4a→a637227e 之间已被修复;**PERFAN 的 23 个
prettyprint.rs:3946 panic 在本基线零出现**,已修复);libLLVM 抽样 100 中 3–5 个超时
(idx 10723/3217/22876 稳定:oracle 5.1/—/15.0s wall 完成,Rugra >20s 不终止)。

## 3. 分解测量:固定开销 vs 引擎

**(a) 近零代码函数的整子成本(=每子固定开销,decompile≈0)**:

| 侧 | curl idx47(`register_tm_clones`,0 字节) | sqlite idx506(5 字节) |
|---|---|---|
| Rugra `--one` | **~400–500 ms user** | **~420–480 ms user** |
| oracle `one` | ~80–90 ms user | ~120–180 ms user |

Rugra `--list`(仅进程启动+ELF 发现,无规格加载):<10 ms。oracle `list`(含
startDecompilerLibrary 规格加载+BfdArchitecture):80–90 ms。

**(b) oracle 引擎面(P2 all 模式,单进程全函数,3 跑中位)**:

| 语料 | oracle 引擎 CPU | 每函数 |
|---|---|---|
| curl(74) | 0.74–1.6 s | **~10–21 ms** |
| httpd(790) | 9.9–10.2 s | **~12.5 ms** |
| sqlite(1385) | 86–91 s | **~62–66 ms**(RSS 1.29 GB,单进程累积) |

**读法**:oracle 的 hermetic 每子成本(151–186 ms)中,**~85% 是进程启动+规格加载+
输入重处理**,引擎本身只需 10–66 ms/函数。Rugra 的 hermetic 每子成本中固定开销
≈430–480 ms(约 3–5× oracle 的同项)。因此在 curl 这类小函数语料上,Rugra 每子
478 ms 里**绝大部分是固定开销**(规格加载/Architecture 初始化),不是反编译引擎;
在 libLLVM 大函数上(Rugra 2634 ms/函数)固定开销只占 ~17%,引擎差才是主体——
聚合引擎倍率 2.34×(§2),而**中位函数引擎倍率仅 1.2–1.4×**(§3(d),尾部病态
函数拉爆聚合)。

**(c) 固定开销归因(gdb 栈采样,RUSTFLAGS=-Cdebuginfo=1 符号构建 + strace)**:

时间线采样(同一 `--one` 近零代码子,负载下 wall 采样):

| 采样点 | 栈(符号化) | 相位 |
|---|---|---|
| @0.02s | `PackedDecode::openElement → OperandValue::decode → PatternExpression::decodeExpression` | **.sla 反序列化 #1** |
| @0.06s | `operator delete ← _Rb_tree<VarnodeData,string>::_M_erase ← rugra_sleigh_register_info` | 寄存器目录枚举(map 拆装) |
| @0.12s | `_Rb_tree<VarnodeData,string>::_M_copy`(深递归逐节点分配) | 寄存器 map 拷贝 |
| @0.18–0.24s | `_int_free/malloc_consolidate` | 大量释放 |
| @0.30s | `PackedDecode::skipAttribute → SymbolTable::decode → SleighBase::decode → Sleigh::initialize → rugra_sleigh_create` | **.sla 反序列化 #2** |
| @0.35s | `~Constructor/~SubtableSymbol` 析构链 | 退出拆卸 |

**根因:每个 Rugra hermetic 子进程加载 SLEIGH 两次**——
`examples/gen_decompile.rs` `run_one` 路径:
1. `build_architecture()`(gen_decompile.rs:337)为提取寄存器目录
   (`num_registers`/`register_info` 逐个枚举)创建 **SLEIGH 实例 #1**,取完目录即丢弃
   (完整 .sla 解码+寄存器 map 装拆+析构全为一次性开销);
2. `SleighLifter::new()`(gen_decompile.rs:520→src/disasm/sleigh_lift.rs:31)创建
   **SLEIGH 实例 #2** 供 follow_flow 提升。
strace:双侧各 open `x86-64.sla` 2 次(oracle=spec 扫描 1 次+真加载 1 次,仅 1 次解析;
Rugra=**两次完整加载与解析**——gdb 双 `PackedDecode` 相位 @0.02s/@0.30s 证实)。
oracle 单次加载+同一引擎内取寄存器 = 85–180 ms;Rugra 双加载+目录装拆 ≈430–480 ms。
**该项为纯基础设施缺口(无语义面),是 canon hermetic 口径(逐函数进程隔离)下 Rugra
固定开销 3–5× 于 oracle 的主因。**(修复方向——后续票:单 SLEIGH 实例共享/寄存器目录
缓存/进程 fork-server;不影响任何对齐语义,不属本车道写域。)

**(d) 串行逐函数 CPU 散点(P1B,按 oracle 单函数成本分桶,中位倍率)**:

| 语料 | 最小桶 | 次桶 | 第三桶 | 最大桶 |
|---|---|---|---|---|
| curl(74 匹配,串行) | 50–200ms:**2.51×**(n=70,1.8–3.3) | 200–500ms:3.22× | >500ms:3.93× | — |
| libLLVM(100 匹配,串行) | 0.3–1s:**1.40×**(n=80,0.92–25.1) | 1–2s:**1.21×**(n=15) | 2–5s:4.36×(n=4) | >5s:1.48× |

两个方向的梯度同时存在:
- curl(小函数):倍率随成本**上升**(2.5→3.9)——固定开销摊平后引擎差显形;
- libLLVM(大函数):**中位函数倍率仅 1.2–1.4×**(接近 oracle),但尾部病态函数拉爆总量
  ——idx 3217(oracle 0.8s vs rugra 20.1s cap=**25×**)、idx 10723(3.2s→19.7s=6.1×)、
  idx 15370(3.9s→19.6s=5.1×);真巨函数 idx 22876(oracle 13.5s)倍率仅 1.5×。

**（e） P4 analyzeHeadless 上下文（口径=全 Java 分析管线，不可与纯反编译比）**：

| 目标 | wall | user+sys CPU | RSS | 备注 |
|---|---|---|---|---|
| examples/curl(162 KB,3 跑) | 22.1–25.9 s | **~30–33 s**(中位 31.1+2.1) | 405–463 MB | loader+PLT+引用+demangler+DWARF 全分析，不含反编译；wall<user=JVM 多线程 |
| /tmp/sqlite3(8.6 MB 带 DWARF,2 跑) | 384.1 s(第 2 跑;第 1 跑 wall 解析失效) | **~615–633 s**(user 600.0–607.7 +sys 33–40) | 1.44–1.49 GB | 同上；比纯反编译 oracle 引擎面（同尺寸语料 94 s/1385 面）高一个量级，口径差所致 |

参照:kuna #510 的 Ghidra(mpengine.dll≈18MB)“约为 kuna 一半时间”——本表给出 Rugra 侧
同类“全分析 vs 纯反编译”的量级锚点(analyzeHeadless 是 Java 分析管线,引擎 CPU 与
direct-runner 不可直接比,已单列)。

## 4. 负载与噪音注记

- 本机 31 用户共享,112 核;测量窗口 load 1m 中位 ~110–155(极值 75/170)。
  所有记录逐跑存 `load_before/load_after`(原始 JSONL)。
- **wall 在本机不可靠**:oracle 串行单子 wall/CPU 最高 5.4×(纯调度等待;strace -c
  证实每子 syscall 总耗时仅 ~1.4 ms/602 次,无 I/O 阻塞)。安静窗口校准点:
  oracle 单子 0.16s wall/0.13s user,Rugra 0.57/0.46——安静时 wall≈CPU,倍率结论
  以 CPU 为准。
- rugra 并行 sweep 的 CPU 利用率(9–12 核)高于 oracle(1–2.6 核)同 worker 数:
  oracle 子进程 wall 大部分是调度等待,不耗 CPU;此现象只影响 wall,不影响 CPU 总量。
- rep 间 CPU 离散:curl Rugra rep2 +31%(load 136 窗口),中位数协议吸收。
- 页缓存全热态;两 runner 同机同窗口交替执行。

## 5. 结论与瓶颈归因

### 5.1 速度倍率(同口径,P1A 主表 + 分解)

| 面 | 倍率(Rugra/oracle,CPU) |
|---|---|
| 小函数语料(curl,151→478 ms/子) | **3.16×** |
| 中语料(httpd,186→618) | **3.32×** |
| 大语料(sqlite 1385,215→838) | **3.90×**(剔 7–8×20s cap 燃烧后 ≈**3.4×**) |
| 大二进制大函数(libLLVM 抽样,1128→2634) | **2.34×**(串行同口径 2.17×) |
| **libLLVM 中位函数**(0.3–2s 桶) | **仅 1.2–1.4×** |
| 分解:每子固定开销(430–480 vs 85–180 ms) | **~3–5×** |
| 分解:大函数引擎(真巨函数 idx 22876) | **≈1.5×** |

### 5.2 瓶颈面三层模型(对照 PERFAN 画像 + 本车道新证据)

**层 1 — 每子双重 SLEIGH 加载(本车道新发现,PERFAN 未覆盖)**:
`gen_decompile --one` 每子创建两个独立 SLEIGH 实例(build_architecture 的寄存器目录
枚举 + SleighLifter),同一 `x86-64.sla` 完整反序列化两次,寄存器 map 深拷贝/拆除两轮
(gdb 符号化时间线见 §3(c))。固定开销 ≈430–480 ms/子 vs oracle 单次加载 85–180 ms。
**在小函数语料上主导总成本**(curl 478 ms/子中 ~90%)。纯基础设施缺口,修复(单实例
共享/目录缓存/fork-server)不动任何对齐语义 → 建议 PERF 票(优先级 P1:canon hermetic
口径全线收益 3–5× 固定项)。

**层 2 — 尾部病态函数(非终止/超线性)**:
- sqlite:7–8/1385 稳定超时(PERFAN 11 面的子集;55/57/114 与 23 个 prettyprint panic
  已在 master 修复),cap 燃烧占 sqlite CPU 总量 12–14%;
- libLLVM:抽样 100 中 3–5 个超时/爆炸(idx 3217 = **25×**,10723 = 6.1×,15370 =
  5.1×),把总量倍率从中位 1.2–1.4× 拉到 2.17–2.34×。
与 PERFAN 锚点根因(RuleDivChain 移植缺陷丢守卫)同族——修尾部即把大语料倍率打到
≈1.5× 以下。→ 已有票 PATHOSLOW-DIVCHAIN-0001(P0)覆盖,本车道提供其在大二进制上的
损害面新证据。

**层 3 — 引擎常数因子(中位大函数 1.2–1.4×)**:
真巨函数(idx 22876,oracle 13.5s)倍率 1.5×、libLLVM 0.3–2s 桶中位 1.21–1.40×——
PERFAN 的 ActionPool 迭代常数(HashMap SipHash+range 重建 vs perop[CPUI_MAX])+
varmap remove_symbol O(n²) 的量级与此吻合。**中位层面 Rugra 引擎已接近 oracle**,
剩余为常数优化空间(已有票 PERF-ACTIONPOOL-ITER-0001/PERF-VARMAP-REMOVE-REKEY-0001)。

### 5.3 与 kuna #510 对照面的落点

| 项 | kuna #510(用户实测,Ryzen 9 7900) | 本车道(112 核共享机,load 75–170,user CPU 口径) |
|---|---|---|
| 目标 | mpengine.dll ≈18MB PE | libLLVM-15.so.1 116MB ELF(35387 面,抽样 100) |
| 同口径纯反编译 | 无公开数据 | **Rugra 2.34× / oracle**(P1A);中位函数 1.2–1.4× |
| 全分析口径 | Ghidra ≈ kuna 一半时间 | analyzeHeadless curl ~31s CPU / sqlite3-exe 8.6MB ~647s CPU(单列上下文) |
| 鲁棒性 | 2 处 panic + 8 函数失败 | sqlite 0 panic + 7–8 非终止;LLVM 抽样 3–5 爆炸(无 panic) |

结论句:**同口径纯反编译下,Rugra 当前慢 oracle 2.3–3.9×(CPU),但分解后=固定开销
(双 SLEIGH,可修)+ 尾部病态(DIVCHAIN 族,在修)+ 中位引擎 1.2–1.4×(常数优化)**;
三层都有明确修复路径且不动对齐语义。kuna 的“Ghidra 一半时间”案例在本车道获得了
Rugra 侧的同口径数据基线。

### 5.4 P3 canon 驱动层(上下文,口径不同)

| 驱动 | user CPU(3 跑中位) | RSS | 说明 |
|---|---|---|---|
| `curl_decompile`(canon All,~200 面 ledger canon 面+种子) | **140.3 s** | 76 MB | canon gate 口径,比 bare face 慢(更富输入+隔离 worker 面) |
| `httpd_decompile`(canon All,255 面) | **71.8 s** | 460 MB | 同上 |

## 6. 原始数据与可复现性

- 原始 JSONL:每跑一行(per-index wall(+串行 user/sys)、outcomes、load 快照、binary
  sha256)。会话内路径 `/dev/shm/rugra-tests/perfbench/sweeps.jsonl`;**归档副本**
  `/dev/shm/rugra-reports/perfbench-evidence/sweeps.jsonl`(含 phase 日志、语料 list
  JSON、strace/gdb 采样证据)。
- 复现入口:`bash tools/bench_decompile.sh`(全协议:发现恒等断言+P1A+P3+P2);
  单格:`python3 tools/perfbench_sweep.py hermetic|allmode|canon …`;
  汇总:`python3 tools/perfbench_report.py <sweeps.jsonl>`。
- oracle runner 复现:`tools/regen_ghidra_golden.py` `build_runner()`(git archive 锁定树);
  headless 复现:`tools/build_ghidra_1204_headless.sh`(BUILD SUCCESSFUL,
  `RESULT_ANALYZE_HEADLESS=/tmp/rugra-ghidra-1204-headless/dist/ghidra_12.0.4_DEV/support/analyzeHeadless`)。
- 固定开销归因方法:`RUSTFLAGS="-Cdebuginfo=1 -Cstrip=none"` 符号构建
  (`[profile.release] strip=true` 会剥掉普通 `-g`)+ gdb 批处理栈采样;
  `perf` 不可用(`perf_event_paranoid=4`)。
- phase 脚本(内存盘,归档于 perfbench-evidence/):`phase{1,2,3b,4}*.sh`。

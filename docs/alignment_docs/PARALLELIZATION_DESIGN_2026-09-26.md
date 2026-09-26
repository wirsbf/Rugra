# Rugra 并行化设计 + PoC（PAREVAL 车道，2026-09-26）

> 车道 wt/pareval，基 = master `1c99ebad`，oracle = Ghidra 12.0.4 `e40ed130`。
> PoC 驱动：`examples/pareval_poc.rs`（公示仿真面豁免——examples 写域）。
> 数据目录（内存盘，易失）：`/dev/shm/rugra-tests/pareval/`；结论已全部录入本文档。
> 机器：112 核 / 881GB，测量期外部负载 load≈45-50（多车道共机——所有加速比读数**偏保守**）。

## 0. 结论速览

| 问题 | 结论 |
|---|---|
| Phase1（多函数进程内线程并行）可行？ | **可行且已实证**：curl 31/31 字节恒等，sqlite3 44/45；加速比 curl 3.3-4.1×(8 workers)、sqlite3 **6.28×**(8 workers, 45 函数) |
| PoC 是否发现阻塞？ | **是**：sqlite3 `shell_exec` 输出非封闭（进程历史依赖，≥3 变体）——**P1 票 PAREVAL-DETERM-HERMETICITY-0001**。该缺陷同样影响串行（不同函数子集→同函数不同输出），并行只是暴露面 |
| TypeFactory 争用（PKGG 面） | shared 单例模式并行墙钟开销 ≈ +7-12%（8 workers，curl/sqlite3 双语料 A/B）；核心 decompile 阶段 CPU 近乎无争用（serial 4.57s vs 并行 CPU-sum 4.87s，+7%） |
| 每函数 Architecture 重建成本 | 串行占 46%（curl: arch 7.40s / 总 15.97s）；8 路并行下 CPU 膨胀 2.5×（7.40→18.24s sum）——后续最大优化杠杆（P2 票） |
| Phase2（函数内并行）可行？ | **oracle 语义上不安全为主**：oracle 114 文件零线程原语；规则池按 SeqNum 全序迭代+规则链有状态。少数只读/独立扫描 pass 理论可并行但无 oracle 先例，须逐个过"oracle 语义安全"判据（§5） |

---

## 1. 状态架构测绘

### 1.1 生命周期与所有权

| 对象 | 生命周期 | 所有权 | per-函数 / 共享 |
|---|---|---|---|
| `Funcdata`（funcdata.rs:415） | 单函数反编译全程 | 驱动层持有；`Arc<RwLock<Funcdata>>` + `self_ref: Weak`（自引用环） | **per-函数**。全部 IR（VarnodeBank/PcodeOpBank/两个 BlockGraph/Heritage/符号/注释）都在其中 |
| `Architecture`（arch.rs:437） | 当前驱动形态：**每函数新建**（`build_architecture` per call，bin_sweep/curl/httpd/rugra_decompile_func 四驱动一致） | `Arc<Architecture>` 经 `fd.set_arch()` 注入 | 名义共享、实际 per-函数。子组件几乎全部 `Option<Arc<RwLock<..>>>`：symboltab/types/userops/pcodeinjectlib/commentdb/string_manager/cpool/context_db/options_db |
| `TypeFactory`（type_system/typefactory.rs:29） | 双形态：①Architecture 挂载工厂（`arch.types`）②**进程级单例** `shared_default()`（typefactory.rs:2729-2755, `OnceLock<Arc<RwLock<TypeFactory>>>`） | ①随 arch ②进程唯一 | **①per-函数（按 oracle"每 Architecture 一工厂"模型）②全局共享**——`shared_default()` 被 **9 个 src 文件的引擎热路径**调用（§1.3），即"isolated"驱动形态下引擎仍在写单例 |
| SLEIGH ctx（sleigh_ffi.rs `SleighCtx` + disasm/sleigh_lift） | 每函数 `SleighCtx::new()`（重读 x86-64.sla）+ `SleighLifter::configure_x86_64(image)`（image 深拷贝进 C++ 侧） | 裸指针 `*mut c_void`，`unsafe impl Send` | per-函数。C++ shim（sleigh_shim/rugra_sleigh.cpp:32-35）仅一个 `static std::mutex` 且只护初始化段（:332）；翻译器实例互相独立 |
| `ActionDatabase`（action.rs:1903） | 每函数 `new()` + `set_default_actions()`（universal_action 树克隆构造） | 驱动局部 | per-函数；树本身无跨函数状态 |

### 1.2 RwLock 使用面（性质二分）

**(a) 单线程内部可变性（绝大多数）**——`Arc<RwLock<PcodeOp>>` / `Arc<RwLock<Varnode>>` / `Arc<RwLock<dyn FlowBlock>>` / `Arc<RwLock<FuncCallSpecs>>` 等遍布 dynamic.rs/flow.rs/varnode.rs。这是 Rust 借用检查的图结构 workaround，**不是跨线程共享**；同一函数内按序加锁。存在已知读读重入陷阱（dynamic.rs:917、flow.rs:2781 注释）。对 Phase1 无影响（对象不跨线程）。

**(b) 真共享读写锁**——只有 TypeFactory 面（单例）与 Architecture 挂载组件（per-函数 arch 形态下实际单线程访问）：
- `base_cache: RwLock<BTreeMap<(usize,Meta),Arc<Datatype>>>`（typefactory.rs:42）
- `base_type_tree: RwLock<BTreeMap<..>>`（:39）
- `char_cache` / `type_nochar`（:46/:50）
- `live_local_scopes: BTreeMap<u64, Arc<RwLock<ScopeLocal>>>`（:66，**非 RwLock 但跨函数可变**，见 §1.3）

PKGG 注记的"读→写升级"4 处 = `get_base`（:643-707 双检：read base_cache → drop → write；read base_type_tree → drop → write）+ oversize 分支（:663-673）+ `get_base_no_char`（:866+）+ `find_add`（:939+）——全部 `or_insert_with` 幂等写，键→值纯函数，**并行下确定性无害**（PoC 双模式字节恒等佐证），只有争用开销（§4.3 实测）。

### 1.3 跨函数可变共享点全录

| # | 共享点 | 位置 | 写者 | 确定性风险 |
|---|---|---|---|---|
| 1 | `TypeFactory::shared_default()` 进程单例 | typefactory.rs:2729；调用面 varnode.rs:1721（VarnodeBank 默认定型）、varmap.rs:5649/5661/6041/6063/6537（ScopeLocal 符号定型）、typeop.rs:2324/2335、funcdata.rs:11562、fspec.rs:1390/1452/1511/1668/8439、debugproto.rs ×6 | 每次反编译都写（findAdd 缓存填充、live_local_scopes 注册、data_organization 解码） | **首要嫌疑**：单例状态 = f(进程内前置函数集)。内容寻址缓存应中性，但 `live_local_scopes` 按帧偏移累积、`types` BTreeMap 跨函数增长。**shell_exec 变体缺陷（§4.4）与之相关待证** |
| 2 | TypeFactory 挂载工厂本体 | `arch.types`（per-函数新建） | 同一函数内 | 无（线程内） |
| 3 | `arch.commentdb` | arch.rs:539；Funcdata::warningHeader 写入（funcdata.cc:135-145 镜像） | 每函数累积 header 警告 | **per-函数 arch 形态的根因**：若 arch 跨函数复用，warning 注释串函数泄漏 → 输出污染。这是当前驱动全部 per-函数重建 arch 的正确性理由 |
| 4 | `string_manager` | arch.rs:541，`build_string_manager()` | 加载期一次 | 无（arch per-函数） |
| 5 | `ffi::CURRENT_PROGRAM`（`Mutex<Option<Funcdata>>` lazy_static） | ffi.rs:13-25 | 仅测试通道（set_current_program），生产驱动不触碰；已有 poison 恢复（TESTLIB-STATE-CONTAMINATION-0001） | 无（测试串行化 FFI_TEST_LOCK 已护） |
| 6 | `marshal::ID_TABLES` OnceLock | marshal.rs:560 | 初始化一次后只读 | 无 |
| 7 | `TypeFactory::CANONICAL_UNKNOWN_BASE_1` OnceLock | typefactory.rs:147/2751 | `shared_default()` 首次初始化后只读快路径 | 无 |
| 8 | `capability::GLOBAL_REGISTRY` + `once_cell_shim` | capability.rs:94-100 | 注册期一次 | 无 |
| 9 | `op::SENTINEL` / `opbehavior::FLOAT_FMT_{4,8}` OnceLock | op.rs:306、opbehavior.rs:1503-1504 | 惰性一次 | 无（不可变值） |
| 10 | **thread_local 面**：`SPACE_TAG_TABLE`（address.rs:69-72，空间 tag 实习表）、`TYPE_XML_IDS`（type_system/datatype.rs:63-70）、fspec 空间换算缓存（fspec.rs:2406-2409）、drillobserve RECORDER/IOP_REGISTRY（drillobserve.rs:54-63，RUGRA_STAGE_DRILL 门控默认关） | 各文件 | 同线程惰性 | **纪律级约束**：`AddrSpace = Rc<RefCell<..>>`（space.rs:1324）非 Send/Sync，`Address` 携带的 SpaceTag 只能在铸造线程解析（resolve 跨线程 panic）。官方文档口径 = "one-Architecture-per-worker thread discipline"（address.rs:64-68 注释）。并行模型必须整函数作业同线程完成（PoC 即此形态） |
| 11 | `iop` 空间常量编码 `Arc::as_ptr` | PcodeOpBank deadandgone 保留注释（op.rs:1573-1585）、`Funcdata::get_op_from_const` | 堆地址进入 IR 通道 | **嫌疑 2**：若任何排序/tie-break 依据编码地址值 → 分配器布局依赖 → 进程历史依赖。shell_exec 变体缺陷的候选通道之一（§4.4） |
| 12 | sleigh_shim C++ 侧 | rugra_sleigh.cpp:33 static mutex（仅初始化段 :332） | SleighCtx 创建互斥 | 无（初始化后实例独立） |

**结论**：Rugra 的跨函数可变面收敛为**两类**——①TypeFactory 进程单例（语义面），②堆布局依赖通道（iop 指针编码 + 任何 HashMap 容量/历史敏感迭代）。其余全部 per-函数或只读。这正是 Phase1 隔离设计与 §4.4 缺陷的战场。

### 1.4 Send/Sync 现状（Phase1 落地的 src 适配面）

- `AddrSpace`（Rc）→ `Architecture`（内含 AddrSpace 枚举字段——`space::AddressSpace` 枚举是 Copy 的，Rc 的是 `AddrSpace` 结构）不整体 Send：**无需适配**，PoC 证明"作业内同线程"模型绕开全部适配。
- 已有 `unsafe impl Send`：SleighCtx（sleigh_ffi.rs:242）、TransformManager（transform.rs:676）、SubvariableFlow（subflow.rs:271）、PreferSplitManager（prefersplit.rs:137）——皆为单线程使用的声明性放宽，Phase1 不依赖。
- **Phase1 落地无需任何 src/ Send/Sync 改动**（PoC 全部走 examples 驱动层）。Send/Sync 适配票不成立、不登记。

---

## 2. Phase1：多函数并行模式（主体设计）

### 2.1 模型：驱动层线程池 + 整函数作业

```
主线程: 装载 ELF 一次 → 发现函数 → 确定性选集(最大优先/地址 tie-break)
        → 派发队列 VecDeque<JobIndex>
workers: K × std::thread(stack_size=256MB)   # ActionGroup.perform 深递归需要大栈
  loop { pop job → [同线程内] build_architecture → Funcdata::new+set_arch
         → follow_flow_range(0,u64::MAX) → ActionDatabase::perform_action("decompile")
         → PrintC::doc_function → 提交 (idx, bytes) }
聚合: 按 idx 重排 → 与串行臂逐函数 cmp
```

要点（全部由 PoC 实证）：
1. **作业不可迁移**：一个函数的 Arch/Funcdata/SLEIGH/Address 全部在单线程内生成消费（SPACE_TAG_TABLE 线程域纪律，§1.3#10）。跨线程只传 `(u64 vaddr, String name, usize size)` 入参和 `String` C 文本出参。
2. **每函数新建 Architecture**（含 commentdb）——复用会串 warning 注释（§1.3#3）。代价见 §4.3，优化票 P2。
3. **256MB 栈**：与现有 curl_decompile/bin_sweep 驱动一致；K 个 worker 虚存 K×256MB，8-16 workers 无压力。
4. **动态队列**（largest-first 入队）：天然负载均衡，最短墙钟；完成序与作业序解耦由 idx 重排吸收——PoC 证明完成序不影响输出（par1 vs par2 恒等）。

### 2.2 确定性协议（"并行 = 观察中性"门禁）

**定义**：对同一函数集合，
- 串行臂（1 线程按 idx 序）输出 `S[i]`；
- 并行臂跑两遍（独立线程组）输出 `P1[i]`、`P2[i]`；
- 门禁 GREEN ⇔ ∀i: `S[i] == P1[i] == P2[i]` **按字节**（Ok 类），且非 Ok 结果（panic 消息+位置 / err 消息）三臂同签名。
- 双工厂模式各过一遍：`isolated`（每函数新工厂，rugra_decompile_func 形态）与 `shared`（进程单例，bin_sweep 形态）。

**实现**：`examples/pareval_poc.rs` 即门禁本体——进程退出码 0 ⇔ 全矩阵 GREEN；`matrix.json` 逐函数记录签名/比较结论/耗时；三臂文本落盘 `text/<mode>/{serial,par1,par2}/` 供审计。CI 接线 = 把该 example 挂进 verify 脚本（票 PAREVAL-PHASE1-LAND-0001）。

**运行中性保证**：参与门禁的运行必须独占机器计时（本车道实测期 load≈45-50，加速比读数保守）；stderr trace 噪音不进门禁（只比 stdout 文本产物）。

### 2.3 PoC 实测数据

语料：`examples/curl`（锁定 fixture，31 函数全量）与 `/tmp/sqlite3`（8.6MB, 2697 符号；48 最大函数中筛除 3 个非终止/超长函数 idx {8:do_meta_command 498s, 24:sqlite3VdbeExec 854s, 30:sqlite3Parser 359s}——PERFAN RuleDivChain PORT-DEFECT 家族 + 病态时长，测量集 45 函数）。

**表 1：curl 字节恒等 + workers 缩放（31 函数，双模式全部 GREEN）**

| workers | isolated 加速比 | shared 加速比 | 串行墙钟 | 备注 |
|---|---|---|---|---|
| 1 | 0.77× | 0.96× | 16.1-23.3s | 单 worker 线程机制开销 5-20% |
| 2 | 1.70× | 1.68× | 16.3-19.7s | 近线性 |
| 4 | 3.26× | 3.28× | 18.4-21.2s | 近线性 |
| 8 | 3.30-3.36× | 3.69-4.11× | 16.0-21.4s | 平台期起点 |
| 16 | 2.31-3.16× | 3.14-3.27× | 16.4-18.9s | 无增益（31 作业 + 最长链 + 共机负载） |

> 平台期主因：作业数 31 < 有效并行度、最长函数链（curl `main` 串行 2.5s/并行 3.5s）与每函数 arch 构建在并行下的 CPU 膨胀（§4.3）。16 workers 的一次 2.31× 低读数为共机负载尖峰（复测 3.16×），报告区间。

**表 2：sqlite3（45 函数，8 workers）**

| 模式 | 串行 | 并行 | 加速比 | 门禁 |
|---|---|---|---|---|
| isolated | 496.44s | 79.08s | **6.28×** | RED（1/45 函数，§4.4） |
| shared | 505.85s | 88.33s | **5.73×** | RED（同 1/45） |

44/45 函数三臂字节恒等；唯一 RED = `shell_exec`（idx 6, 3967 字节, 输出 38491 字节）——详见 §4.4。

**表 3：阶段画像（curl 31 函数，isolated，串行 vs 8 路并行 CPU-sum）**

| 阶段 | 串行 Σ | 并行 Σ(8w) | 膨胀 | 说明 |
|---|---|---|---|---|
| arch 构建（cspec/pspec 解析 + SLEIGH ctx + 工厂解码） | 7.40s (46%) | 18.24s | ×2.5 | **纯重复 setup**——最大优化杠杆 |
| flow（follow_flow_range + 提升注入） | 3.01s (19%) | 12.46s | ×4.1 | SLEIGH 每函数重载 .sla + image 深拷贝 |
| actions（反编译主管线） | 4.57s (29%) | 4.87s | ×1.07 | **引擎核心几乎零争用**——TypeFactory 单例热点只在读写锁瞬段 |
| print | 0.11s | 0.12s | ×1.1 | 可忽略 |

**表 4：TypeFactory 争用 A/B（PKGG 面的并行实测）**

| 语料 | isolated 并行墙钟 | shared 并行墙钟 | shared 开销 |
|---|---|---|---|
| curl 31f / 8w | 4.84-4.86s | 5.20-5.40s | +7-11% |
| sqlite3 45f / 8w | 79.08s | 88.33s | +11.7% |

PKGG 结论（"单线程无争用非问题"）在并行后**部分翻案**：单例在 8 路下带来 ~10% 墙钟开销，但核心 actions 阶段仍近线性——争用集中在 arch 构建期的工厂解码写锁与首次缓存填充。**判定：非阻塞、可优化**（票 PAREVAL-TF-SINGLETON-WIRING-0001：恢复 oracle 的 per-Architecture 工厂所有权）。

### 2.4 Phase1 落地形态（裁决）

1. **已落地**（PAREVAL-PHASE1-LAND-0001，wt/phaseland，write-set=examples/+tools/，零 src/ 改动）：
   - 生产并行驱动 `examples/parallel_decompile.rs`（PoC 的生产化形态：线程池 + per-worker
     Architecture 构造 + 函数集动态队列分发 + 按函数序收集落盘；`--jobs 1` 即串行形态退化，
     同一代码路径）；bin_sweep 族的进程级隔离形态保留为硬超时/病态语料兜底；
   - 确定性门禁 `tools/verify_parallel_determinism.sh` 常设化（"并行=观察中性"协议进 verify
     脚本族）：serial（jobs=1）vs parallel（jobs=N）逐函数字节 cmp + 非 Ok 签名恒等，
     exit code 即门禁；语料面 curl 31 / httpd 34 / sqlite3 45（PoC 覆盖面）。
2. **全语料 GREEN 的前置**：PAREVAL-DETERM-HERMETICITY-0001 修复（§2.5，HERMIT 车道已收口
   coreaction phi 边排序键根因）。修复前，含非封闭函数的语料必须用进程级隔离（每函数一进程，
   bin_sweep 现形态）兜底——PERFAN 的进程级并行全语料扫掠已给出双口径一致性旁证。
3. **per-worker Architecture 复用**暂缓：commentdb 串函数污染（§1.3#3）需先拆分"不可变规格态（cspec/pspec/寄存器目录/.sla）"与"per-函数累积态（commentdb）"，且必须过 PoC 门禁证明字节中性（P2 票 PAREVAL-ARCH-BUILD-COST-0001 承接，预期收益：串行 46% + 并行膨胀 2.5× 的大头）。

### 2.5 shell_exec 非封闭缺陷（PoC 核心发现）——P1 票

**现象**：sqlite3 `shell_exec` 同一函数在同一进程内产生**两个字节变体**（同长 38491，局部语句序置换——两相邻独立赋值 `param_2=0;`/`ppppbVar21=0;` 互换），变体由**进程内前置函数集合**决定：
- 45 作业大跑：isolated serial=A, par1=B, par2=A；shared serial=B, par1=A, par2=B；
- 单作业探针（3 进程 × 3 线程臂，warmup+serial+2 并行）**9/9 全等 = B**；
- predecessor 剂量实验（单线程，前置集 {k..7} 含 warmup f7，k=5..0）：shell_exec 变体 = k5:B, k4:A, k3:A, k2:B, k1:A, k0:A——**非单调**依赖前置集；**其余 7 个伴随函数在所有剂量下字节稳定**（受影响面收敛为单函数）；同跑门禁：k=5/1/0 GREEN（三臂同变体），k=4/3/2 RED（同跑内串行 vs 并行臂翻转）。

> 勘误注记：早先版本记录的"第三变体 C"系 PoC 驱动 write_text_dir 文件名映射缺陷（enumerate 槽位当函数索引）在 skip 运行下的误读；驱动已修复（按 job 位命名+冒烟验证）。门禁矩阵始终用 job 位比较，不受影响。实证变体数 = 2（A/B）。

**判别结论**：
1. **非线程 RandomState 种子依赖**（9/9 同序概率 ~(1/2)^8≈0.4%，排除纯线程掷硬币假说）；
2. **进程历史依赖**：同进程前置函数集合改变输出；跨进程（单作业）封闭；
3. **串行同样受害**：纯串行不同语料子集 → 同函数不同输出——违反铁律 2.1"同输入同输出"的进程模型前提；
4. 分歧面 = 同长局部置换，非语义差异（无符号/结构漂移）；
5. **受影响面收敛**：sqlite3 测量集 45 函数中唯一受影响函数 = shell_exec（剂量实验 7 个伴随函数全稳定；curl 31 函数全稳定）。

**嫌疑通道**（按可能性排序，供修复车道）：
1. `TypeFactory::shared_default()` 进程单例的跨函数累积态（§1.3#1；live_local_scopes 注册时序、types 增长改变下游 HashMap 容量/重哈希触发点）；
2. iop 常量的 `Arc::as_ptr` 编码参与某处 tie-break/排序 → 分配器布局依赖（§1.3#11）；
3. 某共享 HashMap 的 hashbrown 迭代序 = f(插入历史/容量)，泄漏进 op 插入序或 varmap 处理序（与 PERF-ACTIONPOOL-ITER-0001 的 HashMap 面同族，但该票是性能面、本票是**语义面**）。

**修复验收** = PoC 门禁 sqlite3 45 函数双模式三臂全 GREEN + 剂量实验 k=0..5 全部同 hash。证据文件：`/dev/shm/rugra-tests/pareval/{sq-w8,shellexec-probe*,dose-k*}/`（内存盘易失；关键 hash 与 diff 已录入本节与票）。

---

### 2.6 Phase1 落地实测（PHASE1-LAND 车道，wt/phaseland，2026-09-26）

生产驱动 `examples/parallel_decompile.rs` + 门禁 `tools/verify_parallel_determinism.sh` 落地后
的确定性协议实测（门禁口径：serial jobs=1 进程 vs parallel jobs=8 进程，**跨进程**逐函数
字节 cmp——比 PoC 的同进程三臂协议更强一层）：

| 语料面 | 函数数 | 门禁结论 |
|---|---|---|
| curl（examples/curl，31 全量） | 31 | **GREEN**：31/31 字节恒等（jobs=8；jobs=16 复验同 GREEN） |
| httpd（examples/httpd，34 全量） | 34 | **GREEN**：34/34 字节恒等 |
| sqlite3（/tmp/sqlite3，48 最大筛 3 病态 = 45） | 45 | **GREEN**：45/45 字节恒等（shell_exec 经 HERMIT 修复后经生产驱动确认封闭） |
| sqlite3 全量（2799 发现函数，--max-funcs all） | 2799 | **GREEN**：2799/2799 字节恒等，全 Ok 零 err/panic；4.18×@8w（load 107-180 尖峰期极端保守；Amdahl 瓶颈=4 巨函数 2238s 占串行 31%，上界 ~4.8×——巨函数即 DIVCHAIN 残差慢尾） |

**加速比曲线（生产驱动实测，load 95-140 共机——全部显著偏保守；PoC 期 load 45-50 时
sqlite3 8w 同口径 6.28×）**：

| 语料 | 1w | 2w | 4w | 8w | 16w |
|---|---|---|---|---|---|
| sqlite3 45f | 591.4s | 321.5s（1.84×） | 160.2s（3.69×） | 97.5s（**6.06×**） | 101.4s（5.83×，平台期） |
| curl 31f | 19.2s | 9.3s（2.07×） | 5.8s（3.30×） | 5.4s（**3.55×**） | 5.9s（3.27×） |

平台期主因不变（§2.3）：作业数 < 有效并行度、最长函数链、每函数 arch 构建并行 CPU 膨胀
（PAREVAL-ARCH-BUILD-COST-0001 承接）。

**TypeFactory 争用注记（TFSINGLE step1 待并）**：生产驱动沿用 bin_sweep 形态
`shared_default()` 进程单例（与串行驱动同工厂域——串并比较同口径的前提）。PoC 实测该
形态（step1）8 路并行争用 +7-12% 墙钟；PAREVAL-TF-SINGLETON-WIRING-0001 落地 per-Arch
工厂所有权后争用面变化，加速比预期改善——用本驱动曲线（1/2/4/8/16）复测即量化，且
确定性门禁对工厂域不敏感（同构建内串并自比对），该票落地后门禁复跑三面即其并行侧验收。

**落地期发现 1——typedef 前导是进程级 artifact，不是并行缺陷**：`printc.rs` 的
`TYPEDEFS_EMITTED` 是进程级 AtomicBool（"once per decompiled file"，多函数单进程运行中
进程即文件），每进程恰好一个函数的文本带 215 字节固定 typedef 前导块，**载体由打印序决定**
（串行=首 idx；并行=首完成）。四个正典门禁早已把它归一化（compare_ghidra.py:109/141，
"the preamble is invisible to all four gates"）。生产驱动侧处置：剥离精确 215 字节前导
（边界=前导自身的收尾 tag_line；docFunction cc:2653 的 `emit->tagLine()` 给**每个**函数
文档发一个前导换行，属函数文本不属前导——剥 216 字节会让载体函数文本重新位置依赖），
落盘一次 `typedef_preamble.c` 于 run 目录，函数文件=纯函数文档，门禁恢复纯字节 cmp。
httpd 面首跑 RED（f000 main 差一个前导换行）即此 artifact 暴露+修正的实证；curl 面首跑
GREEN 是侥幸（两臂载体恰好同为 f000）。

**落地期发现 2——跨进程确定性成立**：PoC 协议是同进程三臂（serial/par1/par2 一个进程），
落地门禁是两臂两个进程。curl/httpd 全量跨进程字节恒等证明 bare-native 面的输出不依赖
进程级分配器布局/ASLR/HashMap 种子（HERMIT 修复 phi 边排序键后，shell_exec 族进程历史
依赖已在 oracle 侧证伪为对齐缺陷并收口）。



---

## 3. Phase2：函数内并行可行性评估（诚实分级）

### 3.0 Oracle 事实基线

**Ghidra 12.0.4 反编译器（锁定 oracle，114 文件）不含任何线程原语**：`grep -rln "pthread|std::thread|std::async|OpenMP" decompile/cpp/` = 空。oracle 的可复现输出模型 = **单函数单线程全序执行**。Ghidra 自身的并行（Java 侧 DecompInterface 多进程、headless 多函数）**全部在函数间**——即 Phase1 轴。函数内并行没有任何 oracle 先例，任何此类改动都改变可观察的中间序，举证责任在改动方。

### 3.1 不可并行面（oracle 序依赖硬约束）

| 面 | oracle 证据 | 为什么不能并行 |
|---|---|---|
| **Rule 池（ActionPool, rule_repeatapply）** | action.cc:877-884 `apply`: `op_state = data.beginOpAll()` 按 **SeqNum 全序**迭代 optree；processOp（action.cc:822-875）按 `perop[opc]` **有序规则链**逐条 apply，`rule_index` 跨规则有状态，规则改 opcode 时重置链（:860-863），规则杀死后续 op（:859） | 规则间/op 间全序即语义：并行 apply 会改变哪个规则先看到 op、死 op 是否被访问——**IR 结果序依赖**。PERF-ACTIONPOOL-ITER-0001 的 SeqNum 语义正是此面 |
| **ActionGroup 主管线（issueOrder）** | action.hh ActionGroup::perform 按 `sort finalaction` 的 issueOrder 串行；ActionRestartGroup 的 restart 循环（breakpoint/timer 重入） | 后续 action 观察前面 action 的全部突变；restart 点不可分割 |
| **Heritage/SSA**（heritage.cc） | 逐 latency/pass 的 worklist 数据流，split/merge 依赖前轮完成 | 数据流不动点本质串行 |
| **结构化（BlockAction/ActionStructurePtr）** | 依据当前边集做决策，每步改图 | 图重写序依赖 |
| **varmap/ScopeLocal 重构** | RangeHint/AliasChecker 按地址序消费前序 IR | 同上 |
| **参数恢复/ProtoModel** | fspec.cc 依据 callspecs 现值迭代收敛 | 同上 |

**结论**：主管线（fullloop/mainloop 内全部 rule_repeatapply 池与顺序 action）在 oracle 语义下**不可并行**——除非做出"并行重排后最终 IR/文本仍逐字节同 oracle 串行结果"的完整证明，而规则链的交叉杀伤使该证明在一般情况下不可行。

### 3.2 理论可并行面（但无 oracle 先例 → 默认不做）

| 面 | 并行机会 | 风险 | 评级 |
|---|---|---|---|
| 初始反汇编+提升（指令级独立） | 逐指令 SLEIGH 翻译无数据依赖 | Rugra 现实现 lifter 有序输出 SeqNum；并行需保序聚合；SLEIGH C++ 库线程安全未证（shim 仅 init 互斥）；**收益极小**（表 3: flow 19%且大头是 .sla 重载，非翻译 CPU） | 不值得 |
| 只读扫描类 pass（如 VarnodeProps 初扫、只读属性标记） | 只读不改 IR 则序无关 | 需逐个证明"纯读"；oracle 无此拆分；一旦未来加写即静默破坏 | 仅在 profile 证明热点时逐 pass 评估 |
| **函数间**（Phase1） | 见 §2 | 已实证 | **唯一推荐轴** |

### 3.3 "oracle 语义安全"判定标准（Phase2 任何尝试的准入门槛）

1. **不可变输入证明**：并行段读取的全部状态在段内无写入者（或写入者与读取者按 oracle 全序可交换——需给出 oracle 行级论证）。
2. **顺序保持证明**：段输出进入后续 pass 前，与 oracle 串行执行在该边界上的可观察状态（IR 逐 op 逐 flag、注释、警告、统计计数）完全一致——用 stage 投影（STAGE_BISECT_SPEC_1204 机制）对拍。
3. **无共享可变面**：段内不触碰 §1.3 表中任何共享点；thread_local 面在同线程。
4. **观察中性门禁**：段并行版 vs 串行版在 PoC 协议（§2.2）下三臂字节恒等，覆盖语料含大函数（sqlite3 类）。
5. **默认拒绝**：不满足 1-4 任一 → 记 MISSING/不可并行，不允许"近似并行"。

当前评估：**没有任何一个主管线 pass 同时满足 1-4**；Phase2 判定 = 现阶段不可行，性能主路径应为 Phase1 落地 + PERFAN 机会表（RuleDivChain 修复直接消掉 3 个非终止函数与 37.3× 差距的主项）。

---

## 4. 附录

### 4.1 PoC 复现命令

```bash
CARGO_TARGET_DIR=/dev/shm/rugra-targets/pareval cargo build --profile fast-release --example pareval_poc
# 门禁主跑（curl 全量）
/dev/shm/rugra-targets/pareval/fast-release/examples/pareval_poc examples/curl \
    --max-funcs 31 --workers 8 --out-dir <dir>          # exit 0 = GREEN
# sqlite3（先筛后测；--skip 8,24,30 = 非终止/病态时长）
... pareval_poc /tmp/sqlite3 --max-funcs 48 --skip 8,24,30 --workers 8 --out-dir <dir>
# 筛选模式（外部 watchdog 建 skip 表）
... pareval_poc /tmp/sqlite3 --screen --max-funcs 48 --out-dir <dir>
```

### 4.2 shell_exec 变体指纹（md5 摘录）

- 变体 A `9e5bc8ea…`：45 跑 isolated serial/par2、shared par1；剂量 k=0/1/4
- 变体 B `afc7f416…`：单作业探针 9/9；45 跑 isolated par1、shared serial/par2；剂量 k=2/3/5
- 分歧内容：单行位移（`param_2 = (byte *****)0x0;` 与 `pppppbVar21 = (byte *****)0x0;` 相邻互换），diff 4 行。
- 剂量实验伴随 7 函数（main/KeccakF1600Step/shell_callback/exec_prepared_stmt/recoverStep/sqlite3_expert_analyze/arDotCommand）全配置字节稳定；curl 31 函数全稳定。
- 证据归档：`/dev/shm/rugra-reports/pareval-evidence/`（shellexec/ 双变体全文 + 剂量 k0..5 提取 + 双语料 matrix.json + 筛选 JSONL）。

### 4.3 成本模型（Phase1 扩展预测）

加速比上界 = min(K, N_jobs) × 1/(1 + 膨胀·(1-串行占比))。串行占比：最长函数/总和（sqlite3 45 函数 ≈ 60.5/496 ≈ 12% → 8 workers 理论 ~6.9×，实测 6.28× 吻合；curl 最长链占比 ~16% → 理论 ~5.5×，实测 3.3-4.1×，差值 = arch/flow 膨胀 + 共机负载）。规模化推论：N≫K 且函数大小均匀时 8-16 workers 可得 6-13×；上探更高并行度需先落地 PAREVAL-ARCH-BUILD-COST-0001（消 arch 重复构建与 .sla 重载）。

### 4.4 相关既有票

- PERF-ACTIONPOOL-ITER-0001（P1, 性能面 HashMap 迭代）——与本车道 HERMETICITY 票同族不同面。
- PATHOSLOW-DIVCHAIN-0001（P0, RuleDivChain PORT-DEFECT）——sqlite3 筛选期 3 个非终止/病态函数的上游根因。
- PERFAN 终报 `/dev/shm/rugra-reports/LANE_PERFAN_2026-09-26.md`。

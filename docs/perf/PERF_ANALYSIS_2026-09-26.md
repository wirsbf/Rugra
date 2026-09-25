# PERF ANALYSIS 2026-09-26 — 运行时性能深度分析(Lane PERFAN,wt/perfan)

> 基线 = master `efc28f4a`(worktree `/dev/shm/rugra-worktrees/perfan`)。
> 语料 = GEN5 第五语料 `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`(1385 函数,oracle=Ghidra 12.0.4 锁定 commit `e40ed130`)。
> 方法 = 纯分析(零 `src/` 改动):gdb 采样(poor-man's profiler,`perf_event_paranoid=4` 禁 perf)、
> `RUGRA_RULE_STATS=1` 池级计数、gdb 双快照 `rule_states[].count_apply` 差分归因、
> 全语料有界扫描(15s/20s cap)。工具与原始数据:`/dev/shm/rugra-tests/perfan/`(易失,结论已录本文)。
> **每项机会的验收口径 = 差分门禁保持全绿(defects=0/numbering=0),性能改动必须观察中性。**

---

## 0. 执行摘要

| 指标 | 数值 |
|---|---|
| 锚点 idx 55 `sqlite3BitvecTestNotNull` | **非终止**(Rugra 烧 ≥600s 至 harness 墙;oracle 全 1385 函数总耗时 30.3s) |
| 根因 | **RuleDivChain 移植缺陷**:oracle 5 道守卫+in(0) 基数替换被丢弃 → repeatapply 池死循环 |
| 全语料(并行 16 路,15s cap) | 1067.8s 累计 wall(oracle 串行 30.3s);11/1385 非终止;23/1385 panic(同一处 unwrap) |
| 全语料(串行复测,20s cap,oracle 口径) | **1130.3s 总耗时 = oracle 30.3s 的 37.3×**;非终止 11 个(见 §1.3 名单);真 panic 23 个(§1.3);两个环境瞬态窗口(1063-1102、1318-1329,共享 checkout/spec 读取扰动,复跑全绿)已从结论剔除 |
| 分类汇总 | PORT-DEFECT ×2(P0-1/P2-3);RUST-LEVEL ×4(P1-2/P2-4/P2-5/P3-8);BUILD ×1(P3-B) |

**锚点机制一句话**:oppool1(`rule_repeatapply`)每 pass 报 `pass_changes=2` 恒定不变 →
`lcount<count` 永真 → 单一规则(RuleDivChain)对同一 op 无限重写 → ~7k pass/s 烧 CPU 直到超时。
这不是"慢",是**算法非终止**;修复属于对齐事项(恢复 oracle 守卫),不属于优化。

---

## 1. 锚点剖析:idx 55 sqlite3BitvecTestNotNull

### 1.1 复现与定位链(证据链,可复跑)

1. `RUGRA_GEN_MIRROR=1 gen_decompile libsqlite3.so.0 --one 55`(fast-release 与 release 均复现;
   fast-release 下 600s 仍未完成;stderr 停在 `[BLOCKSTRUCT] finalize_structure: 12 -> 1` 之后 →
   卡点在结构化之后的 universal/fix 规则池)。
2. gdb 采样热线程栈(20 样本):全部落在
   `ActionRestartGroup::perform → ActionGroup×3 → ActionPool::apply_from_status`,
   叶帧分布:`PcodeOpRef::cmp`(BTreeMap 序比较)×5、`OpCode` SipHash×2、各 Rule `apply_op`×8、
   其余迭代机制×5 → **CPU 全部在规则池应用循环内**。
3. `RUGRA_RULE_STATS=1`:55s 内 **380,842 次 oppool1 pass**,每 pass `pass_changes=2` 恒定 →
   repeatapply 不动点循环永不收敛(≈6,900 pass/s)。
4. gdb 双快照差分 `rule_states[134].count_apply`(间隔 5s):
   **仅索引 88 增长**(92,979 次/5s;其余 133 条零增长)。
   索引 88 = `build_oppool1` 注册序 0-based 88 = **RuleDivChain**(oracle coreaction.cc:5600 注册)。
5. 同族验证:idx 57 `sqlite3BitvecClear` 同法归因 → **同样仅索引 88**(13,546 次/5s);
   idx 114 `sqlite3BitvecSet` 同签名(32,733 pass/20s 全部 `pass_changes=1` 恒定,rc=124)。

### 1.2 双侧源码对照(oracle 亲读,ruleaction.cc:8392-8455)

oracle `RuleDivChain::applyOp` 的完整守卫链 vs Rugra `src/ruleaction.rs:9283-9330`(`apply_op`):

| oracle 行 | 语义 | Rugra 状态 |
|---|---|---|
| cc:8412-8417 | constVn2 常量 / vn written / divOp / opc1∈{同 opc2, RIGHT+DIV} | ✅ 有 |
| cc:8421-8427 | constVn1 常量 / `vn->loneDescend()` 单一后继 | ✅ 有 |
| cc:8427-8428 | `baseVn = divOp->getIn(0); if (baseVn->isFree()) return 0;` | ❌ **缺失** |
| cc:8430-8432 | `resval=(val1*val2)&mask; if (resval==0) return 0;` | ❌ **缺失零结果守卫**(Rugra 算了 new_val 但从不检查 0) |
| cc:8433-8436 | `signbit_negative` → 绝对值归一 | ❌ 缺失 |
| cc:8437-8439 | `bitcount > sz*8`(DIV)/`> sz*8-2`(SDIV)溢出守卫 | ❌ **缺失** |
| cc:8440 | **`data.opSetInput(op, baseVn, 0);`** — in(0) 换成基数 | ❌ **缺失(非终止的直接机制)** |
| cc:8441 | `opSetInput(op, newConstant(sz,resval), 1)` | ✅ 有 |
| (无对应) | — | Rugra 额外 `op_set_opcode(RIGHT→DIV)`:因守卫链已限定 opc2==DIV,该语句为无害冗余 |

**非终止机制**:Rugra 版只重写 in(1) 常数(`c2 → c1*c2 → c1*c1*c2 → …`),in(0) 始终是
`(x/c1)` 子表达式 → 下一个 pass 模式 `(x/c1)/新常数` 依旧命中全部前置守卫 → 无限重写。
oracle 的 in(0) 替换使模式每 pass 消费一层链(链长有限 → 必然终止);即便链条退化,
`resval==0` 与 bitcount 溢出守卫双保险封死无限循环。

**分类:PORT-DEFECT**(oracle 算法必然终止;Rugra 结构性丢弃守卫)。
修复 = 恢复 cc:8427-8441 的 5 项语义,**不是优化**;差分门禁零变化是验收底线
(该规则当前在语料上的"输出"来自永不停止的错误重写,修复后 idx 55/57/114 等 11 函数
应能正常完成并与 oracle 对拍)。

### 1.3 损害面(全语料有界扫描,16 路并行,15s cap)

**非终止(11/1385,并行 15s 与串行 20s 双口径一致,rc=124,每例 cap,真实形态=无限)**:
`55, 57, 114, 788, 834, 835, 836, 946, 1055, 1321, 1322`
(bitvec 家族 55/57/114 已逐个归因到 RuleDivChain;1055 `sqlite3VdbeExec`(30,609B 大函数)
归因形态不同——25 条规则在动,主导 deadcode/PropagateCopy 2516+1865 次/5s——与
"DivChain 每 pass 制造新常数喂养下游折叠/清理级联"的机制一致,修复后必须复测;
788/834/835/836/946/1321/1322 待修复后复测确认是否同根因)。

**panic(23/1385,rc=101,全部同一处)**:`src/prettyprint.rs:3946:56`
`self.indentstack.last().unwrap()` 空栈 unwrap。名单:
`93,94,172,214,216,218,219,227,285,302,411,412,418,419,491,643,765,827,844,953,954,955,1315`。
属正确性缺陷(非性能),oracle prettyprint.cc 对应分支在空栈时不可达——状态分歧上游存在。
登记独立票(§6 P2),归 printc/prettyprint 域。

**慢但终止(并行口径,受自争用膨胀,串行数字见 §5)**:468(14.3s)、966/967(12.6s)、389、353、
1342、395(12.3s+)等;轻载下 468 实测 ~3s 完成 → 并行数字含调度噪声,慢因待 DivChain 修复后
在干净负载下重新归因(468 热点栈采样在自争用窗口内不可靠,未采)。

---

## 2. 全库复杂度审计(vs oracle),逐项分类

### P0-1 RuleDivChain 非终止(锚点根因)— PORT-DEFECT
见 §1。**预估收益**:11 函数从 ∞ → 亚秒级;语料总耗时主要减项。
**风险**:低(恢复 oracle 逐行语义,行为面由差分门禁裁决)。**写域**:`src/ruleaction.rs`
(RuleDivChain::apply_op)+ 机制 B2 fixture(div 链双侧 fixture)。

### P1-2 ActionPool 逐 op 迭代常量 — RUST-LEVEL
**证据**(锚点 20 样本叶帧):50% 在纯迭代机制(`PcodeOpRef::cmp`×5 + OpCode SipHash×2 +
sip write + `Address::cmp` + apply_from_status 自身),50% 在规则体。
**oracle 对照**(action.cc:877-887 / action.hh:264):
- oracle `perop[CPUI_MAX]`:**定长数组直索引**,O(1) 无哈希;
  Rugra `HashMap<OpCode, Vec<usize>>`(action.rs:1212)+ `RandomState` SipHash —— 每 op 每 pass 一次哈希。
- oracle `op_state` = `PcodeOpTree::const_iterator` **存储迭代器**(`op_state++` 摊还 O(1));
  Rugra `next_op_after` 每 op 重建 `BTreeMap::range((Excluded(current), Unbounded))`
  (action.rs:1420-1448)= 每 op O(log n) 新下降 + `current.clone()` Arc 原子操作 +
  `process_op` 内 `op_state.clone()` 再一次 Arc clone + 每 op 多次 RwLock 读。
- `per_op` 迭代序与 SeqNum 序**必须逐字节保持**(铁律 2.1);修法=保留键序游标或
  peek-next-key 模式,不得换成无序容器。
**预估收益**:规则池主机时的常数因子 ~2×(锚点形态);大函数(VdbeExec 级)更显著。
**风险**:中(迭代序是可观测语义;需全量 E2E 字节恒等验收)。**写域**:`src/action.rs`。

### P2-3 ScopeInternal::remove_symbol 全量重键 — PORT-DEFECT
**证据**(静态,双侧亲读):`src/varmap.rs:2709-2743` — `symbols.remove(idx)`(O(S) 移位)
+ nametree 全 values 重键 + category_lists 全槽重键 + mapentry_log retain+重键,单次 O(S+N+C+E);
调用点 `varmap.rs:2674` `while let Some(idx)=find_overlap(...) { remove_symbol(idx) }` 循环 → **O(n²)**。
**oracle**(database.cc:2117-2149, database.hh:812-818):符号=堆指针身份,
`nametree`=`set<Symbol*>` 排序树(erase O(log n)),`maptable`=`vector<EntryMap*>` 树形 rangemap
(erase O(log n)),`category`=指针矩阵——**根本不存在重键**。
**预估收益**:符号重建密集的函数(局部作用域 churn)二次方消除;绝对量随语料待测。
**风险**:中高(索引稳定性假设遍布调用方;需调用闭包审计+机制 B2 fixture)。
**写域**:`src/varmap.rs`(ScopeInternal 存储层,保持公共 API)。

### P2-4 Arc<RwLock<PcodeOp>> 逐访问锁 — RUST-LEVEL(结构性,长期)
**证据**:锚点栈中每个 op-rule 对多次 `read()` guard(unsafe-free 代价);oracle=裸指针。
**预估收益**:全面常数;**风险**:高(所有权模型重构)。建议作为独立设计票,先量化再动。
**写域**:全库(不属于本 wave)。

### P2-5 热路径无条件 stderr 追踪 — RUST-LEVEL(LOW)
**证据**:idx 468 正常跑 384 行 stderr([COLLAPSE]/[JUMPTABLE]/[BLOCKSTRUCT] 无 env 门);
全语料 ~42MB 写 syscall。blockaction.rs 362 处 eprintln 多数在 `RUGRA_BS_*` 门内,
但 COLLAPSE/JUMPTABLE 族常开。
**预估收益**:微量 syscall/分配;主要收益=噪声纪律(stderr TAG 混入 compare 的坑,见机制 B 注记)。
**风险**:低(纯 env 门控,输出面不变)。**写域**:`src/blockaction.rs`/`src/jumptable.rs` 日志行。

### P2-6 prettyprint.rs:3946 空 unwrap panic(23/1385)— 正确性(交叉)
见 §1.3。登记票供 printc 域认领;**非性能项**。

### P3-7 PKGG TypeFactory 写 guard — 实测非问题(降级观察项)
**证据**:单函数管线单线程(driver 主线程 join worker;TypeFactory 无并发读者);
`arch.types` 外层 guard 调用点仅 7 处(funcdata 4/coreaction 2/constseq 1);
锚点 20 样本零锁等待帧;uncontended RwLock 写获取≈一次原子交换。
**结论**:写 guard 串行化读者在本形态下不存在;仅当管线并行化(多函数并发共享 factory)
时才需重评。无需票,留观察。

### P3-8 TypeFactory find_add 次级常量 — RUST-LEVEL(LOW)
`find_add`(typefactory.rs:939-1030)匿名臂 `type_tree_key` 构建两次(probe read + insert);
具名臂 `get_name().to_string()` 每次分配;oracle `set<Datatype*>` 查找零分配。
锚点形态不可见;DivChain 修复后如 type 系热点浮出再排。
**写域**:`src/type_system/typefactory.rs`。

### P3-B 构建性能(有界,详见 §4)
登记实验票,按 AGENTS.md 度量协议执行(-Zthreads/codegen-units/jobs 网格)。

---

## 3. oracle 复杂度对照结论(每热点亲读的 oracle 算法类)

| Rugra 热点 | oracle 算法/结构 | 复杂度类(oracle) | Rugra 现状 | 分类 |
|---|---|---|---|---|
| oppool1 repeatapply 收敛 | ruleaction.cc 每规则守卫保证单调消费(链长有限) | 必然终止 | DivChain 丢守卫 → 非终止 | PORT-DEFECT |
| ActionPool 逐 op 派发 | perop[CPUI_MAX] 数组 + 存储迭代器 | O(1)/op 摊还 | HashMap SipHash + range 重建 | RUST-LEVEL |
| removeSymbol | 指针身份 + set/rangemap erase | O(log n) | Vec 全量重键,循环 O(n²) | PORT-DEFECT |
| PcodeOp 访问 | 裸指针 | O(1) | Arc<RwLock> guard | RUST-LEVEL |
| TypeFactory 查找 | set<Datatype*> 结构树 | O(log n) 零分配 | BTreeMap 元组键 + String 名表 | RUST-LEVEL(低) |

---

## 4. 构建性能(有界测量 + 实验票)

当前配置(Cargo.toml,本 worktree=master efc28f4a):
- `release`:opt-level=3,lto=fat,codegen-units=1,strip=true(正式门禁产物)
- `fast-release`:thin LTO,codegen-units=16,incremental,strip=false(日常反馈)
- `dev`:opt-level=1

**已测(同快照 efc28f4a,稳定 toolchain,依赖温缓存,单车道,中背景负载;单次,非中位)**:

| 目标 | profile | wall | 备注 |
|---|---|---|---|
| `--example gen_decompile` | fast-release | 1m13s | 基准点 1 |
| 同上 + `CARGO_PROFILE_FAST_RELEASE_DEBUG=2` | fast-release | 1m31s | +debuginfo +25%(性能分析可用,已验证 gdb DWARF 可读) |
| `--example gen_decompile` | release | 3m48s | fat LTO/cg1 代价 ≈3.1× fast-release |

**结论(单次,有界)**:fast-release 相对 release 的迭代收益(≈3×)与 AGENTS.md 的
"日常 fast-release/正式 release"分层一致,现状配置无需改动;`DEBUG=2` 环境变量形态
是性能分析(采样需要符号)的低成本通道,建议保留此知识(无需改 Cargo.toml)。
**正式实验票**(P3):按协议在固定快照/固定 toolchain/冷热状态固定/固定背景负载下,
重复取中位测量 `-Zthreads=4/8/16`(nightly)、`codegen-units=16/32/64`、
jobs∈物理核邻域;记录 wall/user/sys+峰值 RSS+Cargo timing。见 §6 票
`PERF-BUILD-CARGO-EXP-0001`。

---

## 5. 全语料串行复测(oracle 口径)——终值

方法:`xargs -P 1`(真串行),timeout 20s/函数,`RUGRA_GEN_MIRROR=1`,fast-release 符号版二进制;
环境瞬态窗口(1063-1102、1318-1329:共享 checkout/compiler-spec 读取扰动,特征=0.01s 失败+空
stderr,单独复跑全部 rc=0)已用干净复跑行覆盖。

| 指标 | 终值 |
|---|---|
| 函数数 | 1385 |
| 总 wall(含 11×20s cap) | **1130.3s** |
| oracle(同语料,GEN5 实测) | 30.3s |
| **聚合比** | **37.3×** |
| 平均/最大(终止者) | 0.82s / 20.07s(cap);最大真完成=967 的 15.68s |
| 非终止(11) | 55, 57, 114, 788, 834, 835, 836, 946, 1055, 1321, 1322(§1.3;1321/1322 串行复确认为真挂起) |
| 真 panic(23) | 全部 `prettyprint.rs:3946:56`(§1.3 名单) |
| 慢而终止 Top | 967(15.7s)、468(13.7s)、966(12.1s)、1342(12.0s)、353(11.7s)、395(11.6s)、389(11.2s)、492(10.8s) |

**归因注**:37.3× 是聚合口径;其中 11 个非终止贡献 ∞(被 cap 在 20s×11=220s),
修复 P0 后语料聚合时间的主要减项即此;剩余 ~910s(终止者合计)与 oracle 的差距
归 P1-2(迭代常量)/P2-3(符号重键)/P2-4(锁税)等常量项,待 P0 修复后重新归因排序。

---

## 6. TODO 票登记(同步写入 docs/TODO_BOARD.md)

| 稳定 ID | 优先级 | 摘要 | 分类 | 写域 |
|---|---|---|---|---|
| `PATHOSLOW-DIVCHAIN-0001` | P0 | RuleDivChain 丢 oracle 5 守卫+in(0) 替换 → oppool1 非终止(11/1385 函数烧穿 600s) | PORT-DEFECT | src/ruleaction.rs + B2 fixture |
| `PATHOSLOW-PRINT-INDENT-UNWRAP-0001` | P1 | prettyprint.rs:3946 空缩进栈 unwrap,23/1385 panic | 正确性(printc 域) | src/prettyprint.rs |
| `PERF-ACTIONPOOL-ITER-0001` | P1 | per_op HashMap SipHash → 定长数组;op_state range 重建 → 存储游标;序=SeqNum 语义 | RUST-LEVEL | src/action.rs |
| `PERF-VARMAP-REMOVE-REKEY-0001` | P2 | remove_symbol 全量重键 O(n²) → 指针/代际身份 | PORT-DEFECT | src/varmap.rs |
| `PERF-STDERR-TRACE-GATE-0001` | P3 | 热路径无条件 [COLLAPSE]/[JUMPTABLE] stderr → env 门控 | RUST-LEVEL | src/blockaction.rs, src/jumptable.rs |
| `PERF-BUILD-CARGO-EXP-0001` | P3 | 构建参数网格实验(协议中位数法) | BUILD | Cargo.toml(实验分支) |

**验收总口径(所有票)**:curl/httpd E2E compare `defects=0 numbering=0` 保持;
P0 另需 idx 55/57/114/1055 等完成并与 oracle 对拍(修复即对齐,输出应向 golden 收敛);
P1-2/P1-3 需全量输出**字节恒等**(纯性能改动观察中性);机制 C:P0 票(ruleaction 主管线
Rule)集成前需独立复核。

---

## 7. 方法备忘(供后续车道复用)

- `perf_event_paranoid=4` 环境:perf 不可用 → gdb 采样脚本
  `/dev/shm/rugra-tests/perfan/pstack_sample.sh`(attach+bt×N)。
- 规则归因:`CARGO_PROFILE_FAST_RELEASE_DEBUG=2 cargo build --profile fast-release --example gen_decompile`
  → gdb `break action.rs:1509` → `p self.rule_states.buf.inner.ptr.pointer.pointer` 得基址 →
  `x/536xw <base>` 双快照(16B/记录:flags,breakpoint,count_tests,count_apply)→ 差分 =
  开火规则索引(`build_oppool1` 注册序)。**全程零 src 改动**。
- 池级收敛观测:`RUGRA_RULE_STATS=1`(`pass_changes` 恒非零 = 非收敛签名)。
- 有界语料扫描:timeout+并行/串行双口径;并行数字只用于损害面定性,定量必须串行。

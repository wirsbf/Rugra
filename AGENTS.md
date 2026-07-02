# AGENTS.md — Rugra AI 开发铁律

> Rugra 是 Ghidra 的 Rust 重写版，目标是**完整实现 Ghidra 反编译器的所有算法**。

## 架构流水线

`二进制解析 → 汇编提升(iced-x86) → P-code IR → SSA/Heritage → 控制流结构化 → C 代码生成`

Ghidra 源码位于 `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`（114 个 `.cc` 文件）。

## 🔴 核心铁律（违反即失败）

### 1. Ghidra 源码先行

**移植任何模块前，必须先读对应 `.cc` + `.hh`。** 禁止凭记忆实现。

关键源文件：`blockaction.cc`(结构化) `coreaction.cc`(Actions) `ruleaction.cc`(Rules) `varmap.cc`(变量映射) `merge.cc`(合并) `jumptable.cc`(跳转表) `condexe.cc`(条件折叠) `type.cc`(类型系统) `block.hh`(FlowBlock)

### 2. 禁止空轮

每轮对话必须产出以下之一：
- ✅ 新代码 commit
- ✅ Ghidra 源码深度分析（记录到 `ALIGNMENT_ROADMAP.md` 或 `docs/alignment_docs/`）
- ✅ Bug 根因定位（记录修复方案）
- ✅ 测试验证证据（gcc 审计、Ghidra 结构骨架 diff、输出对比）
- ❌ **禁止纯"目标尚未完成"声明**

遇到技术难题时，禁止说"多会话项目"。继续尝试不同方案，读 Ghidra 源码找答案。

### 3. 原子化提交

每个逻辑自洽的改动单元立即 `git commit`。禁止积累未提交改动。

### 4. 文档同步

- `src/*.rs` 改动 → 同 commit 更新 `docs/api/*.md`（pre-commit hook 强制）
- 模块状态变更 → 同 commit 更新 `ALIGNMENT_ROADMAP.md`（L1→L2→L3）

### 5. 🔴 禁止移除/禁用 Ghidra 有的东西 — 必须修复对齐

**Ghidra 源码里存在的 Rule/Action/算法，Rugra 侧出现 bug 时，禁止用"禁用/移除/skip"绕过。必须读 Ghidra 源码搞清它的正确机制，移植那个机制来修复。**

违反本条 = 简化 = 作弊，与"完整实现"目标直接冲突。

**本轮实例（用户强制纠正）**：
- ❌ 错误：RuleMultNegOne 与 Rule2Comp2Mult 循环 → 移除 RuleMultNegOne。声称"Ghidra 没有"（未核实）
- ✅ 正确：核实发现 Ghidra **有** RuleMultNegOne（ruleaction.cc:7171），在独立 `actcleanup` 池（coreaction.cc:5694）。移植**阶段分隔**机制 → 循环消失，curl 0/24→24/24
- ❌ 错误：RuleEarlyRemoval 产空 varnode → 禁用
- ✅ 正确：移植 Ghidra 6 守卫（ruleaction.cc:30-40）+ 保守空间门 → 重新启用

**判定准则**：如果一个 Rule/Action 在 Ghidra oppool1/actcleanup/actmainloop 里注册，Rugra 侧出 bug，默认假设是**移植缺陷**（守卫缺失/算法不完整/基础设施缺口），去读 Ghidra 源码修；只有核实 Ghidra 确实没有该机制时，才考虑保守降级（且必须注释说明降级理由 + 修复路径）。

### 5.5. 🔴 Ghidra 怎么做，Rugra 就怎么实现 — 禁止任何临时不对齐的操作

**每一行实现都要对照 Ghidra 源码。禁止"先用简化版/临时方案，以后再对齐"的思路。简化版 = 技术债 = 后面处处受阻。**

**本轮实例**：
- ❌ 错误：rename 用 `!is_written` 做 `isHeritageKnown` 检查 —— 实际 Ghidra 检查的是 `Varnode::insert` flag（varnode.hh:298），不是 written。凭记忆猜错 flag 语义
- ✅ 正确：读 varnode.hh:84/298 确认 `isHeritageKnown = flags & (insert | constant | annotation)`，实现 `insert` flag + `activeHeritage` flag + 正确的 rename 守卫

**操作准则**：
1. 写任何代码前，先读 Ghidra 对应源码的**精确行**（不是"大概那里"）
2. 如果发现 Rugra 已有实现偏离 Ghidra（如 `is_free` 替代 `isHeritageKnown`），**立即修正为 Ghidra 的精确语义**
3. 禁止"先跑起来再说"——每个 flag 的值、语义、检查时机必须和 Ghidra 一致
4. 遇到 Rugra 缺失的基础设施（如 `insert`/`activeHeritage` flag），**补齐它**，不要用别的东西绕

### 6. 🔴 遇 bug 先看 Ghidra 怎么做 — 禁止凭猜测修

**任何 bug/失败/非收敛/输出错误，第一步是读 Ghidra 对应源码看它怎么处理，第二步才是改 Rugra。禁止凭记忆/猜测/经验直接改。**

本轮实例：
- Rule 池死循环 → 先读 `action.cc:298-362`（perform 循环）+ `coreaction.cc:5511-5649`（oppool1 注册）+ `:5694`（actcleanup）→ 发现是**阶段分隔**机制，而非猜测的"禁用某 Rule"
- RSP 泄漏 → 先读 Ghidra `printc.cc`（几乎无栈指针处理）+ `coreaction.cc:481`（ActionStackPtrFlow）→ 发现 Ghidra 在**分析层**解析 RSP，Rugra 是空桩

### 7. 🔴 P-code 必须完整实现 — 禁止绕过缺失的 P-code 基础设施

**如果某个 Ghidra P-code op（如 CPUI_CAST）缺失，或 P-code 语义不完整，必须补齐 P-code 层，禁止让上层 Action/Rule "适配/绕过"缺失的 op。**

P-code IR 是整个反编译器的基石。上层绕过 = 在地基缺口上盖楼。

本轮实例：
- ActionSetCasts 卡在 `CPUI_CAST` 不存在 → ❌ 让 agent 绕过 / ✅ 补齐 `opcodes.rs` 的 CPUI_CAST（opcodes.hh:119）+ ffi.rs 映射
- 3 个 opcode 改名偏离 Ghidra 规范名（BOOL_NOT←BOOL_NEGATE 等）→ 改回规范名（118 处替换）

### 8. 🔴 禁止随意回退已验证的工作

**已通过 build + 测试 + curl/httpd 验证的改动，禁止因后续步骤受阻就 `git checkout`/回退。回退 = 白干。应当向前修剩余 bug。**

违反本条的代价：本轮一次错误回退丢失了诊断 instrumentation + Rule 修复（未提交），被迫重做。**已验证的成果必须立即原子化提交锁定**（见规则 3），提交后任何 agent 的 git 操作都动不了。

**并发 agent 协作警示**：后台 agent 可能跑 `git restore`/`checkout` 清工作区，回滚你的未提交编辑。策略：① 同一文件的 edit 必须串行（并发会互相覆盖）；② 关键编辑后立即 build + commit，别留在工作区给 agent 踩。

### 9. 🔴 不管多复杂都要忠实对齐 Ghidra — 禁止任何畏惧困难的情绪

**目标始终是"完整、忠实、1:1 对齐 Ghidra"。复杂度不是降级的理由，困难不是偷懒的借口。**

Rugra 要复刻的是 Ghidra **全部**算法——包括最难的：跳转表的 switch 恢复、SSA heritage 的多重 def 合并、控制流结构化的循环/switch/goto 展开、类型推断、条件执行折叠（condexe）、subflow 子流分析、unify 统一化、float_emulate 浮点仿真、pcodeinject 注入、paramid 参数识别……每一个都复杂、每一个都和前后环节紧耦合，但**必须实现**，一个都不许跳过。

**心理准则**：
1. **禁止"太难了所以先做别的"** —— 难正是要攻的点。Rugra 之所以存在，就是为了把这些难的东西都搬过来。看到难就绕 = 永远做不完 = 项目失败。
2. **禁止"这个模块太复杂，先简化"** —— 简化版永远跑不出 Ghidra 的输出。要么 1:1 移植，要么不做。不允许存在"半成品简化版"长期占据代码库。
3. **禁止"这部分我看不懂，跳过"** —— 看不懂就去读 Ghidra 源码、读注释、读相关论文/文档，直到看懂。读不懂源码说明还没读够，不是"跳过"的理由。
4. **禁止"差不多就行"** —— 差不多 = 不对齐 = bug 源。每个数据结构的字段、每个算法的分支、每个 flag 的位、每个循环的边界都要核对 Ghidra。
5. **禁止"以后再说"** —— 技术债复利。现在不对齐，后面每一层都受牵连，最后被迫推倒重来。一次性做对。

**正确心态**：
- 看到一个复杂的 Ghidra 模块 → **兴奋**，这是项目价值的所在，不是负担
- 遇到算法死结/非收敛 → **去读 Ghidra**，它一定有解法（因为 Ghidra 能跑），找不到说明读得不够细
- 遇到基础设施缺口（缺 op / 缺 flag / 缺数据结构）→ **从底向上补齐**，不要在上层糊
- 一段 Ghidra 代码看了 3 遍还不懂 → 看第 4 遍，拆成更小的片段，画数据流图，写注释，直到懂

**判定准则**：任何"因为复杂所以降级/简化/跳过/推迟"的决策都是失败的。复杂度越高，忠实对齐的**价值**越高——因为那是 Rugra 与 Ghidra 真正对齐的分水岭。在 1:1 对齐面前，没有"太难"，只有"还没读够 Ghidra 源码"。

**本轮根因**：用户反复纠正的就是这一条——遇到 Rule 池死循环就禁用 Rule、遇到 P-code op 缺失就绕过、遇到 flag 语义不明就猜……**全部都是畏惧困难的表现**。复杂度本身不可怕，可怕的是用简化绕开复杂度后留下的、会扩散到整个项目的对齐裂缝。

---

## 🛡 防漏机制（铁律 10-13 + Red Flags）

> 本节由 2026-07-02 事故驱动设立：commit `181538f`（变量重编号）声称"faithful port of assignDefaultNames (database.cc:2862)"并引用了正确行号，但漏掉了 `int4 &base` 的引用语义（误做成 per-prefix 计数器）、`SymbolCompareName` 的字典序遍历、`printNameBase` 的动态前缀——**三处决定性语义都没去读对应行确认**，靠"前缀 scheme 看起来对"蒙混过关，单元测试全绿，4 天后才被发现。下列铁律专为防止此类"形式上读了、实质没验证"的对齐自欺。

### 10. 🔴 对齐证据块（Alignment Evidence）— 每个"对齐"commit 必须附

**任何 commit message 出现 `align`/`port`/`对齐`/`faithful` 字样时，message 体必须包含一个 `## Alignment Evidence` 块。**

块格式：

```
## Alignment Evidence
Ghidra: <file>:<line> <函数签名逐字摘录>
  关键决定性语义（四类，逐条核对）:
  - 引用/输出参数: <如 int4 &base 是引用 → 跨调用共享递增>
  - 循环边界/遍历顺序: <如 nametree 按 SymbolCompareName 字典序>
  - 计数器/累加器: <如 base=1 初值, 单调递增, 单一共享>
  - 排序/比较键: <如 name.compare() + nameDedup>
Rugra: <file>:<line> <对应函数>
  - <逐条对应, 注明如何对齐上述每一类>
四类决定性语义核对: [x]引用参数 [x]遍历顺序 [x]计数器 [x]排序键
```

**四类决定性语义**（必须在读 Ghidra 行时逐项确认，缺一项即为未读够）：

1. **引用/输出参数**（`&` / `*` / 返回值 / out 参数）——是否跨调用共享状态？是拷贝还是引用？
2. **循环边界与遍历顺序**——`begin()/end()` 是什么容器？排序键是什么？边界 `<` 还是 `<=`？
3. **计数器/累加器的初值、增量时机、作用域**——是 per-X 独立还是全局共享？何时重置？
4. **排序/比较键**——`operator()` / `compare()` 比的是什么字段？相等时 tie-break 是什么？

**判定准则**：
- 引用行号但没逐字摘录那一行的签名（含 `&`/`*`）= 未读够
- 摘录了签名但没核对四类语义 = 未读够
- 核对了但 Rugma 侧写"对齐"而实际用了不同机制 = 作弊

**执行**：pre-commit hook 扫 message，命中 `align|port|对齐|faithful` 关键词但缺 `## Alignment Evidence` 块 → 拒绝提交。

### 11. 🔴 差分测试门禁（Differential Test Gate）— 可见输出模块必跑

**凡改动影响"可见输出"的模块，单元测试全绿不等于对齐。必须跑 Ghidra 黄金输出差分测试。**

**白名单模块**（改动这些文件时触发门禁）：
- `src/printc.rs`、`src/prettyprint.rs`（C 文本输出）
- `src/varmap.rs`（变量命名/符号）
- `src/blockaction.rs`、`src/coreaction.rs`（控制流结构化、Actions 影响输出）
- `src/ruleaction.rs`（Rules 影响 IR 形态）

**门禁流程**：

```bash
# 1. 维护黄金输出集: tests/golden/ghidra/<bin>_<func>.c
#    (从真实 Ghidra 跑出来, 人工核定正确, 入库)
# 2. 改动后跑差分
python tools/diff_against_ghidra.py \
  --bin tests/fixtures/mini.c \
  --func '*' \
  --mode varnames   # 或 controlflow / full
```

**判定**：
- **0 diff**：完全对齐，可提交。
- **有 diff**：commit message 必须含 `## Differential` 块，逐处解释每个 diff 的性质（对齐缺陷 / Ghidra 本身可接受的差异 / 待修）。**未解释的 diff = 不可提交。**

**为什么这条必要**：`181538f` 的 `test_compact_name_for` 单元测试验证的是"我的 per-prefix 逻辑自洽"，验证不了"和 Ghidra 的单一 base 共享计数一致"。只有逐位 diff Ghidra 输出才能抓到编号顺序错位。自洽性测试是必要非充分条件。

### 12. 🔴 强制独立复核（Cross-Review）— 核心算法必走双 Agent

**核心算法模块的"对齐"改动，单 agent 自检不可信，必须由另一个 agent 独立复核。**

**核心算法白名单**（高价值、紧耦合、错了扩散面大）：
- `src/heritage*.rs`（SSA heritage / 多重 def 合并）
- `src/jumptable.rs`（跳转表 switch 恢复）
- `src/blockaction.rs`（控制流结构化：循环/switch/goto）
- `src/condexe*.rs`（条件执行折叠）
- `src/varmap.rs` 的核心算法层（RangeHint/AliasChecker/MapState/ScopeLocal）
- `src/merge.rs`（HighVariable 合并）
- 任何被 AGENTS.md 标注为"主管线 Action/Rule"的改动

**双 Agent 流程**：

```
实现 Agent → 提交(commit 可临时, 不合并)
                ↓
复核 Agent（独立读 Ghidra 源码, 不看实现 Agent 的推理）
  产出 ## Cross-Review 报告:
    独立读 <Ghidra file>:<line> <函数>
    四类决定性语义清单:
      [ ] 引用参数: ... MISMATCH / OK
      [ ] 遍历顺序: ... MISMATCH / OK
      [ ] 计数器:    ... MISMATCH / OK
      [ ] 排序键:    ... MISMATCH / OK
    结论: APPROVE / REJECT (附理由)
                ↓
REJECT → 回实现 Agent 修 → 重新复核
APPROVE → 合并
```

**复核 Agent 的独立性要求**：
- 必须自己打开 Ghidra 源码读对应行，**不得直接采信实现 Agent 的 Alignment Evidence 块**（那只是声明，不是证据）
- 必须独立列出四类语义清单再对比，不得"看着实现 Agent 的清单点头"
- 发现任一 MISMATCH → REJECT，并指出 Rugra 行号 + Ghidra 行号 + 修正方向

**判定准则**：核心算法白名单模块的 commit，若无 `## Cross-Review: APPROVE` 块，不得合并到主管线分支。

### 13. 🔴 Red Flags 自查清单 — 命中即停

**commit message 或代码出现以下信号时，作者必须立即停下手，回去重读 Ghidra 对应行的决定性语义。不得"先提交再说"。**

🚩 **commit message 信号**：
- `faithful port` / `对齐` / `aligns with` 但**没贴** Ghidra 关键行的逐字签名摘录
- `Known limitation:` 后跟**作者自己归因**（常是误诊，如 "only numbering differs" 掩盖了计数器模型错位）
- `scheme matches, only X differs`（局部正确掩盖整体错误的典型句式）
- 引用行号（如 `database.cc:2862`）但**没引用那一行的语义细节**（`&` / `<` / 初值 / 边界）
- 测试只列 `N/N pass` **没有 Ghidra 输出对比**

🚩 **代码信号**：
- `HashMap<&str, u32>` 当计数器，而 Ghidra 是单一 `int4 base`（暗示 per-X 独立 vs 全局共享，**必查**）
- `per-prefix` / `each X` / `各自` 等暗示独立计数的措辞
- 写死的字符串列表/枚举匹配，而 Ghidra 用 `virtual` 方法动态派发（如 `printNameBase` vs `PREFIXES` 数组）
- 在 `print` / `emit` 阶段做 Ghidra 在 `Action` 阶段做的事（阶段错位）
- Rust 侧有 `discovery_pass` / 两阶段 guard，而 Ghidra 单阶段确定性完成（暗示 Rugra 有非确定性，需查为何）

🚩 **流程信号**：
- 用"这个模块我先做了，那个以后再对齐"绕过当前模块的对齐（违反铁律 9）
- 把 Ghidra 有的东西标 `// TODO` 或 `// simplified` 而无 ALIGNMENT_ROADMAP 记录
- 测试通过就提交，没问自己"Ghidra 跑同一输入会得到一样的东西吗"

**自查执行**：提交前作者通读自己的 diff + message，命中任一 Red Flag → 强制回到铁律 1（读 Ghidra 源码对应行）→ 补齐 Alignment Evidence 块（铁律 10）。命中不处理直接提交 = 违反铁律。

## 📋 L1/L2/L3 路线图

详见 `ALIGNMENT_ROADMAP.md`。当前状态：

| 级别 | 含义 | 数量 |
|---|---|---|
| ✅ L3 | 已完整实现 + **接入主管线** + 对齐验证 | 14 |
| 🟢 L2.5 | 核心算法 1:1 移植完成 + 有测试，但**未接入主管线**（缺 Rule 包装器/被 Sleigh 阻塞/Ghidra 设计如此） | 9 |
| 🔧 L2 | 核心算法缺失/未对齐 | 16 |
| 📋 L1 | 完全缺失，需从零实现 | 6 |
| ⚪ 无标记 | 表格行未标状态（需补） | 4 |

（2026-06-29 依赖分析：核实核心算法完整性后，将 9 个"代码完整但未接入"的模块从 L2 细分为 **L2.5**（区别于算法未完成的真 L2）。分三类：① 缺 Rule 包装器（subflow）；② Ghidra 设计上非 universalAction（callgraph/unify/float_emulate/grammar）；③ 被 Sleigh 架构初始化阻塞（userop/pcodeinject/pcodeparse/emulate/paramid）。最高 ROI 解锁路径：subflow 的 9 个 Rule 包装器。详见 `ALIGNMENT_ROADMAP.md` 依赖关系图。）

状态变更必须当场更新路线图。

## 📁 文档归属

| 文档 | 内容 |
|---|---|
| `ALIGNMENT_ROADMAP.md` | **L1/L2/L3 全量模块对齐路线图** |
| `CURRENT_STATUS.md` | 项目整体状态与可靠性评估 |
| `GAP_ANALYSIS.md` | 功能鸿沟对比 |
| `ALIGNMENT_PROGRESS.md` | 类/算法层面的 Ghidra 映射进度 |
| `docs/VERIFICATION_GUIDE.md` | 对拍验证实操手册 |
| `docs/alignment_docs/` | 硬核对齐规则（寄存器映射、P-code 对照等） |
| `docs/api/` | 与 `src/` 1:1 映射的 API 参考文档 |

## ⚙️ 构建与验证

```bash
cargo build --release                              # 构建
cargo test                                         # 单元测试（736 个，2026-06-28 核实）
cargo run --release --example curl_decompile       # curl 反编译
cargo run --release --example httpd_decompile      # httpd 反编译
python tools/audit_syntax.py result/curl_cur.c     # gcc 语法审计
```

## 🛠 代码规范

- **不可变性优先**（`let` 而非 `let mut`，借用而非拷贝）
- **卫语句**（Early Returns，降低圈复杂度）
- **`anyhow::Result`** 错误处理（不 `.unwrap()`）
- **精准英文命名**（`snake_case` / `PascalCase` / `SCREAMING_SNAKE_CASE`）

## 🐛 调试输出

- 用 `eprintln!`（stderr），不用 `println!`（污染 stdout 的 C 输出）
- 标准 TAG：`[ACTION]` `[STEP]` `[INJECT]` `[COLLAPSE]` `[BLOCKSTRUCT]` `[DECOMP]` `[PREPASS]` `[PTRSTAMP]`
- 临时 TAG（`[DBG]` `[DEBUG]` 等）提交前必须删除

## 💡 Commit Style

```text
align: port varmap.cc RangeHint/AliasChecker/MapState to Rust
core: implement ActionCast in coreaction pipeline
fix: emit_block_structured preserves while loops after return
```

## 🎯 当前反编译质量（2026-06-28 核实）

- **curl**: 22/24 函数通过 gcc 语法审计（glob_set 类型错误，CFG 修复暴露）。**结构骨架 diff（`tools/compare_ghidra.py`）实测 17/24 函数有真实缺陷**（空 else、寄存器泄漏、调用丢失）+ 332 个变量编号问题（181538f 类 bug）。0 goto，0 uVar。注：旧 while 计数 KPI 已废弃（见铁律 11）
- **httpd**: 待重新核实（CFG 修复导致性能回归，需长超时），0 goto，0 uVar
- **测试**: 736/736 通过（`cargo test --lib`；`cargo test` 默认含 examples，需先 `cargo build --examples`）
- **已完成的核心移植**: identifyInternal/selfIdentify, ruleBlockCat chain, ruleBlockGoto+clipExtraRoots, TraceDAG(BadEdgeScore+visit-count), structure_loops_first, **Datatype get_align_size/get_sub_type/get_hole_size/type_order**, **varmap RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐 + printc 集成 + Stack-spacebase**, **Varnode flag 访问器 + get_nz_mask + lone_descend/has_no_descend + get_consume/set_consume/get_nzm/set_nzm + is_boolean_value (varnode.hh)**, **PcodeOp::is_calculated_bool (op.hh:211)**, **Funcdata op-edit API (funcdata.hh:281-479) + op_swap_input + op_set_output + op_destroy + op_unset_input + op_unset_output + new_varnode_out + replace_lessequal + distribute_int_mult_add**, **get_booleanflip (opcodes.cc:94)**, **bit helpers signbit_negative/calc_mask/leastsigbit_set/mostsigbit_set + functional_equality (address.cc/expression.cc)**, **expression.rs: TermOrder/AdditiveEdge/AddExpression**, **ActionRestructureVarnode (coreaction.cc:2274)**, **Rules: ~100 个 struct 定义于 ruleaction.rs（含 NegateIdentity/NotDistribute/ConcatZero/XorCollapse/AddMultCollapse/...；完整列表见 `grep -oE 'struct Rule[A-Z][A-Za-z0-9_]*' src/ruleaction.rs`）**, **L1模块骨架(14): condexe/transform/subflow/unify/constseq/opbehavior(完整)/rangeutil(完整)/userop/mem-state/float_emulate(完整)/pcodeinject/emulate/callgraph(完整)/signature**, **jumptable.rs L1→L2 (LoadTable/PathMeld/GuardRecord/JumpValues(+Range/RangeDefault)/JumpModel trait/JumpModelTrivial/JumpBasic/JumpTable/EmulateFunction)**, **override_rs.rs L1→L2 (Override + FlowOverride 完整 in-memory)**, **arch.rs L1→L2 (Ghidra Architecture 配置容器 + ArchitectureCapability + CapabilityRegistry)**, **database.rs L1→L2 (SymbolEntry/Symbol/FunctionSymbol/EquateSymbol/LabSymbol/Scope/Database)**, **findSpanningTree DFS 边分类 (block.cc:1009-1110) + F_BACK_EDGE 循环回边检测 + 回边保护（对齐 TraceDAG 跳过 loop edges）**, **CFG 基本块划分修复（build_blocks_from_ops 跳转目标分裂点）→ curl while 4→26**

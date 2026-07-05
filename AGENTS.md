# AGENTS.md — Rugra AI 开发铁律

> Rugra 是 Ghidra 的 Rust 重写版,目标是**完整、1:1 对齐 Ghidra 反编译器的所有算法**。

## 架构流水线

`二进制解析 → 汇编提升(iced-x86/SLEIGH) → P-code IR → SSA/Heritage → 控制流结构化 → C 代码生成`

Ghidra 源码位于 `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`(114 个 `.cc` 文件)。

---

## 🔴 核心铁律(违反即失败)

### 铁律 1 — Ghidra 源码先行,禁止任何简易实现

**(1.1) 移植任何模块前,必须先读对应 `.cc` + `.hh`。禁止凭记忆/猜测/经验实现。**

**(1.2) 修改任何 `src/*.rs` 函数前,本 session 内必须重新读过该函数对应的 Ghidra 函数代码全貌**(不止签名行,要读完整个函数体)。PreToolUse hook (`.zcode/align_gate.py`) 通过 `.alignment_receipts.json` 回执强制此规则。

**(1.3) 每个 `src/*.rs` 非测试函数上方必须有一行 `// Ghidra: <file>:<line> <ghidraFn>` 注释**(指向 Ghidra 函数定义的起始行)或 `// RUGRA-GLUE: <为何 Ghidra 没有对应物>`(纯 Rust 语言结构胶水:构造器/访问器/trait impl/借用安全 helper)。无注释 = 自创函数 = 违反对齐。`tools/check_ghidra_annotations.py` 在 commit 时强制。

**(1.4) 禁止任何形式的简易实现**。包括但不限于:
- ❌ "先用简化版,以后再对齐" / "差不多就行" / "这个我看不懂,跳过"
- ❌ 把 Ghidra 有的东西标 `// TODO` / `// simplified` 而无 `ALIGNMENT_ROADMAP.md` 记录
- ❌ 因 Rugra 缺基础设施(缺 op / 缺 flag / 缺数据结构)就在上层绕过 — 必须**从底向上补齐**
- ❌ 凭记忆猜 flag/字段/边界语义 — 必须读 Ghidra 行确认
- ✅ 复杂度高时,**兴奋**地读 Ghidra,拆小片段,画数据流图,直到懂

**(1.5) 禁止移除/禁用 Ghidra 有的 Rule/Action/算法**。Rugra 侧出 bug 时,默认假设是**移植缺陷**(守卫缺失/算法不完整/基础设施缺口),去读 Ghidra 源码修。只有核实 Ghidra 确实没有该机制时,才考虑保守降级(必须注释说明降级理由 + 修复路径)。

**(1.6) P-code 必须完整**。缺失的 op / 不完整的 op 语义必须补齐 P-code 层,禁止让上层 Action/Rule 适配/绕过。

### 铁律 2 — 遇 bug 先看 Ghidra 怎么做

任何 bug / 失败 / 非收敛 / 输出错误,**第一步是读 Ghidra 对应源码看它怎么处理,第二步才是改 Rugra**。Ghidra 能跑就有解法,找不到说明读得不够细。

### 铁律 3 — 原子化提交 + 文档同步

- 每个逻辑自洽的改动单元立即 `git commit`。禁止积累未提交改动。
- `src/*.rs` 改动 → 同 commit 更新 `docs/api/*.md`(pre-commit hook 强制)。
- 模块状态变更 → 同 commit 更新 `ALIGNMENT_ROADMAP.md`(L1→L2→L3)。

### 铁律 4 — 禁止空轮

每轮对话必须产出以下之一:✅ 新代码 commit / ✅ Ghidra 源码深度分析(记录到 `ALIGNMENT_ROADMAP.md` 或 `docs/alignment_docs/`)/ ✅ Bug 根因定位(记录修复方案)/ ✅ 测试验证证据(gcc 审计、Ghidra 结构骨架 diff、输出对比)。❌ 禁止纯"目标尚未完成"声明。遇难题禁止说"多会话项目",继续读 Ghidra 找答案。

### 铁律 5 — 禁止随意回退已验证的工作

已通过 build + 测试 + curl/httpd 验证的改动,禁止因后续步骤受阻就 `git checkout`/回退。已验证成果必须立即原子化提交锁定(铁律 3)。**并发 agent 协作警示**:后台 agent 可能跑 `git restore`/`checkout` 清工作区 — 同一文件的 edit 必须串行,关键编辑后立即 build + commit。

---

## 🛡 防漏机制

### 机制 A — 对齐证据块(Alignment Evidence)

**任何 commit message 出现 `align`/`port`/`对齐`/`faithful` 字样时,message 体必须包含 `## Alignment Evidence` 块。** pre-commit hook 扫 message,缺块拒绝提交。

块必须逐条核对**四类决定性语义**(在读 Ghidra 行时逐项确认,缺一项即为未读够):

1. **引用/输出参数**(`&` / `*` / 返回值 / out 参数)——是否跨调用共享状态?是拷贝还是引用?
2. **循环边界与遍历顺序**——`begin()/end()` 是什么容器?排序键是什么?边界 `<` 还是 `<=`?
3. **计数器/累加器的初值、增量时机、作用域**——per-X 独立还是全局共享?何时重置?
4. **排序/比较键**——`operator()` / `compare()` 比的是什么字段?相等时 tie-break?

块格式:

```
## Alignment Evidence
Ghidra: <file>:<line> <函数签名逐字摘录>
  关键决定性语义（四类，逐条核对）:
  - 引用/输出参数: ...
  - 循环边界/遍历顺序: ...
  - 计数器/累加器: ...
  - 排序/比较键: ...
Rugra: <file>:<line> <对应函数>
  - <逐条对应, 注明如何对齐上述每一类>
四类决定性语义核对: [x]引用参数 [x]遍历顺序 [x]计数器 [x]排序键
```

### 机制 B — 差分测试门禁(Differential Test Gate)

**凡改动影响"可见输出"的模块,单元测试全绿不等于对齐。必须跑 Ghidra 黄金输出差分测试。**

白名单模块(改动这些文件时触发门禁):
- `src/printc.rs`、`src/prettyprint.rs`(C 文本输出)
- `src/varmap.rs`(变量命名/符号)
- `src/blockaction.rs`、`src/coreaction.rs`(控制流结构化、Actions 影响输出)
- `src/ruleaction.rs`(Rules 影响 IR 形态)

```bash
python tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl.c --summary-only
python tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl.c --func <改动函数> -v
```

**判定**:
- `defects=0 + numbering=0`:可提交。
- `defects>0 或 numbering>0`:commit message 必须含 `## Differential` 块,逐处解释每个缺陷(对齐缺陷 / 已知限制 / 待修)。**未解释的缺陷 = 不可提交。**
- `skeleton diff>0`:不一定是对齐缺陷(for↔while 等价变换),但需在 `## Differential` 块说明。

### 机制 C — 强制独立复核(Cross-Review)

**核心算法模块的"对齐"改动,单 agent 自检不可信,必须由另一个 agent 独立复核。**

核心算法白名单(高价值、紧耦合、错了扩散面大):
- `src/heritage*.rs` / `src/jumptable.rs` / `src/blockaction.rs` / `src/condexe*.rs`
- `src/varmap.rs` 核心算法层(RangeHint/AliasChecker/MapState/ScopeLocal)
- `src/merge.rs`
- 任何被标注为"主管线 Action/Rule"的改动

复核 Agent 必须:
- 自己打开 Ghidra 源码读对应行,**不得直接采信实现 Agent 的 Alignment Evidence 块**(那只是声明,不是证据)。
- 独立列出四类语义清单再对比,发现任一 MISMATCH → REJECT,指出 Rugra 行号 + Ghidra 行号 + 修正方向。
- 在 commit message 加 `## Cross-Review: APPROVE` 块。

**判定准则**:核心算法白名单模块的 commit,若无 `## Cross-Review: APPROVE` 块,不得合并到主管线分支。

### 机制 D — Red Flags 自查(命中即停)

**commit message 或代码出现以下信号时,作者必须立即停下手,回去重读 Ghidra 对应行的决定性语义。不得"先提交再说"。**

🚩 commit message:`faithful port`/`对齐`/`aligns with` 但**没贴** Ghidra 关键行的逐字签名摘录;`Known limitation:` 后跟**作者自己归因**;`scheme matches, only X differs`;引用行号但**没引用那一行的语义细节**;测试只列 `N/N pass` **没有 Ghidra 输出对比**。

🚩 代码:`HashMap<&str, u32>` 当计数器而 Ghidra 是单一 `int4 base`;`per-prefix`/`each X`/`各自` 等暗示独立计数;写死字符串列表而 Ghidra 用 `virtual` 动态派发;`print`/`emit` 阶段做 Ghidra 在 `Action` 阶段做的事;`discovery_pass`/两阶段 guard 而 Ghidra 单阶段确定性。

🚩 流程:"这个先做,那个以后再对齐";`// TODO`/`// simplified` 无 ALIGNMENT_ROADMAP 记录;测试通过就提交,没问"Ghidra 跑同输入会一样吗"。

### 机制 E — 编辑前重读 Ghidra(hook 强制)

铁律 1.2 的机器强制版。详见 `docs/alignment_docs/HOOK_GUIDE.md`:
- **PreToolUse hook** (`.zcode/align_gate.py`):每次 Edit/Write/MultiEdit 拦截 `src/*.rs`,要求 `.alignment_receipts.json` 里有该 Ghidra 文件**本 session 内**的 read 回执。无回执 → deny。
- **PostToolUse hook** (`.zcode/record_receipt.py`):agent 每读 `ghidra/.../cpp/*.cc|*.hh`,自动写回执。
- **commit 兜底** (`tools/check_ghidra_refs.py`):校验所有 `// Ghidra:` 引用的 `file:line` 真实存在。
- **手动补回执**:`python .zcode/record_receipt.py <ghidra_file> <line_start> <line_end>`。
- **紧急逃生** `ZCODE_ALIGN_GATE=0`(必须记录理由)。⚠ 配置仅在新 session 加载,中途改不生效。

---

## 📋 L1/L2/L3 路线图

详见 `ALIGNMENT_ROADMAP.md`。状态变更必须当场更新路线图。

| 级别 | 含义 |
|---|---|
| ✅ L3 | 已完整实现 + 接入主管线 + 对齐验证 |
| 🟢 L2.5 | 核心算法 1:1 移植完成 + 有测试,但未接入主管线 |
| 🔧 L2 | 核心算法缺失/未对齐 |
| 📋 L1 | 完全缺失,需从零实现 |

模块级逐行状态以 `ALIGNMENT_ROADMAP.md` 为准(该文件头部「最后核实」日期标注时效)。

---

## 📁 文档归属

| 文档 | 内容 |
|---|---|
| `ALIGNMENT_ROADMAP.md` | L1/L2/L3 全量模块对齐路线图 |
| `CURRENT_STATUS.md` | 项目整体状态、可靠性评估、当前反编译质量数据 |
| `GAP_ANALYSIS.md` | 功能鸿沟对比 |
| `ALIGNMENT_PROGRESS.md` | 类/算法层面的 Ghidra 映射进度 |
| `docs/VERIFICATION_GUIDE.md` | 对拍验证实操手册 |
| `docs/alignment_docs/` | 硬核对齐规则(寄存器映射、P-code 对照、HOOK_GUIDE 等) |
| `docs/api/` | 与 `src/` 1:1 映射的 API 参考文档 |
| `docs/alignment_audit/` | 跨 agent 对齐审计报告 |

---

## ⚙️ 构建与验证

```bash
cargo build --release                              # 构建
cargo test --lib                                   # 单元测试
cargo run --release --example curl_decompile       # curl 反编译
cargo run --release --example httpd_decompile      # httpd 反编译
python tools/audit_syntax.py result/curl_cur.c     # gcc 语法审计
python tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl.c --summary-only  # 差分门禁
```

当前反编译质量数据见 `CURRENT_STATUS.md`(不再放 AGENTS.md,避免数据过期)。

---

## 🛠 代码规范

- **不可变性优先**(`let` 而非 `let mut`,借用而非拷贝)
- **卫语句**(Early Returns,降低圈复杂度)
- **`anyhow::Result`** 错误处理(不 `.unwrap()`)
- **精准英文命名**(`snake_case` / `PascalCase` / `SCREAMING_SNAKE_CASE`)
- **`// Ghidra:` 注释必须指向函数定义起始行**,不是类声明行/构造函数行(否则触发机制 D 的 cited-line-drift Red Flag)
- **调试输出**:用 `eprintln!`(stderr),不用 `println!`(污染 stdout 的 C 输出)。标准 TAG:`[ACTION]` `[STEP]` `[INJECT]` `[COLLAPSE]` `[BLOCKSTRUCT]` `[DECOMP]` `[PREPASS]` `[PTRSTAMP]`。临时 TAG(`[DBG]` `[DEBUG]`)提交前必须删除。

---

## 💡 Commit Style

```text
align: port varmap.cc RangeHint/AliasChecker/MapState to Rust
core: implement ActionCast in coreaction pipeline
fix: emit_block_structured preserves while loops after return
```

含 `align`/`port`/`对齐`/`faithful` 关键词的 commit 必须附 `## Alignment Evidence` 块(机制 A)。核心算法白名单模块的 commit 必须附 `## Cross-Review: APPROVE` 块(机制 C)。

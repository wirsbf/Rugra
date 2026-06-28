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
- ✅ 测试验证证据（gcc 审计、if/while 计数、输出对比）
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

- **curl**: 22/24 函数通过 gcc 语法审计（glob_set 类型错误，CFG 修复暴露），**26 个 while**（从 4 跃升！接近 Ghidra 34），0 goto，0 uVar
- **httpd**: 待重新核实（CFG 修复导致性能回归，需长超时），0 goto，0 uVar
- **测试**: 736/736 通过（`cargo test --lib`；`cargo test` 默认含 examples，需先 `cargo build --examples`）
- **已完成的核心移植**: identifyInternal/selfIdentify, ruleBlockCat chain, ruleBlockGoto+clipExtraRoots, TraceDAG(BadEdgeScore+visit-count), structure_loops_first, **Datatype get_align_size/get_sub_type/get_hole_size/type_order**, **varmap RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐 + printc 集成 + Stack-spacebase**, **Varnode flag 访问器 + get_nz_mask + lone_descend/has_no_descend + get_consume/set_consume/get_nzm/set_nzm + is_boolean_value (varnode.hh)**, **PcodeOp::is_calculated_bool (op.hh:211)**, **Funcdata op-edit API (funcdata.hh:281-479) + op_swap_input + op_set_output + op_destroy + op_unset_input + op_unset_output + new_varnode_out + replace_lessequal + distribute_int_mult_add**, **get_booleanflip (opcodes.cc:94)**, **bit helpers signbit_negative/calc_mask/leastsigbit_set/mostsigbit_set + functional_equality (address.cc/expression.cc)**, **expression.rs: TermOrder/AdditiveEdge/AddExpression**, **ActionRestructureVarnode (coreaction.cc:2274)**, **Rules: ~100 个 struct 定义于 ruleaction.rs（含 NegateIdentity/NotDistribute/ConcatZero/XorCollapse/AddMultCollapse/...；完整列表见 `grep -oE 'struct Rule[A-Z][A-Za-z0-9_]*' src/ruleaction.rs`）**, **L1模块骨架(14): condexe/transform/subflow/unify/constseq/opbehavior(完整)/rangeutil(完整)/userop/mem-state/float_emulate(完整)/pcodeinject/emulate/callgraph(完整)/signature**, **jumptable.rs L1→L2 (LoadTable/PathMeld/GuardRecord/JumpValues(+Range/RangeDefault)/JumpModel trait/JumpModelTrivial/JumpBasic/JumpTable/EmulateFunction)**, **override_rs.rs L1→L2 (Override + FlowOverride 完整 in-memory)**, **arch.rs L1→L2 (Ghidra Architecture 配置容器 + ArchitectureCapability + CapabilityRegistry)**, **database.rs L1→L2 (SymbolEntry/Symbol/FunctionSymbol/EquateSymbol/LabSymbol/Scope/Database)**, **findSpanningTree DFS 边分类 (block.cc:1009-1110) + F_BACK_EDGE 循环回边检测 + 回边保护（对齐 TraceDAG 跳过 loop edges）**, **CFG 基本块划分修复（build_blocks_from_ops 跳转目标分裂点）→ curl while 4→26**

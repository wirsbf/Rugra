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

## 📋 L1/L2/L3 路线图

详见 `ALIGNMENT_ROADMAP.md`。当前状态：

| 级别 | 含义 | 数量 |
|---|---|---|
| ✅ L3 | 已完整实现并对齐验证 | 16 |
| 🔧 L2 | 部分实现，关键功能缺失 | 17 |
| 📋 L1 | 完全缺失，需从零实现 | 33+ |

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
cargo test                                         # 单元测试（176 个）
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

## 🎯 当前反编译质量（2026-06-26）

- **curl**: 24/24 函数通过 gcc 语法审计，16 个 while 循环
- **httpd**: 29/29 函数通过 gcc 语法审计，39 个 while 循环，0 goto
- **测试**: 266/266 通过
- **已完成的核心移植**: identifyInternal/selfIdentify, ruleBlockCat chain, ruleBlockGoto+clipExtraRoots, TraceDAG(BadEdgeScore+visit-count), structure_loops_first, **Datatype get_align_size/get_sub_type/get_hole_size/type_order**, **varmap RangeHint/AliasChecker/MapState/ScopeLocal 算法层 1:1 对齐 + printc 集成 + Stack-spacebase**, **Varnode flag 访问器 + get_nz_mask + lone_descend/has_no_descend (varnode.hh)**, **Funcdata op-edit API (funcdata.hh:281-479) + op_swap_input + op_set_output**, **get_booleanflip (opcodes.cc:94)**, **bit helpers signbit_negative/calc_mask/leastsigbit_set/mostsigbit_set (address.cc:641-745)**, **ActionRestructureVarnode (coreaction.cc:2274)**, **Rules (25): NegateIdentity/NotDistribute/ConcatZero/XorCollapse/AddMultCollapse/Less2Zero/LessEqual2Zero/BoolNegate/OrMask/AndOrLump/Piece2Zext/Piece2Sext/Bxor2NotEqual/TermOrder/Shift2Mult/DoubleSub/TrivialShift/SlessToLess/OrCollapse/ConcatLeftShift/DoubleShift/IdentityEl/SignShift/SubZext/ConcatShift**

# B7 — 机制 F 门禁健康自检报告（只读体检）

- 仓库：`/home/wirs/DEV/Rugra`（master @ 4599b50）
- 体检时间：2026-08-24
- 体检 Agent：只读门禁体检 Agent（未修改仓库任何文件、未执行 cargo 构建）
- 结论：**8/8 项 PASS，0 项 FAIL**；附 1 个潜在 fail-open 缺陷（GATE-WORKTREE-ROOTMISMATCH-0001）与 TODO 草案，供主 Agent 裁定优先级。

---

## 检查项结果

| # | 检查项 | 结果 |
|---|---|---|
| 1 | ghidra HEAD == 锁定 oracle | ✅ PASS |
| 2 | core.hooksPath 版本化 + hook 可执行 | ✅ PASS |
| 3 | `tools/check_gate_health.py` | ✅ PASS (exit 0) |
| 4 | `tools/check_ghidra_annotations.py --all` | ✅ PASS (exit 0, 95 文件) |
| 5 | `tools/check_ghidra_refs.py --all --strict` | ✅ PASS (exit 0) |
| 6 | `tools/check_alignment_evidence.py` dry-run | ✅ PASS (self-test 5/5 + inline 正反例) |
| 7 | 回执路径解析 / worktree 落位分析 | ✅ PASS（附潜在缺陷 GATE-WORKTREE-ROOTMISMATCH-0001） |
| 8 | hook 无硬编码路径、用 python3 | ✅ PASS |

---

## 逐项证据

### 1. Oracle HEAD 锁定 — PASS

```
$ git -C /home/wirs/DEV/Rugra/ghidra rev-parse HEAD
e40ed13014025f82488b1f8f7bca566894ac376b     (exit 0)
```

与 AGENTS.md 锁定 commit 完全一致。

### 2. 版本化 git hooks — PASS

```
$ git -C /home/wirs/DEV/Rugra config core.hooksPath
.githooks                                      (exit 0)
$ git ls-files .githooks/
.githooks/commit-msg      # -rwxr-xr-x, 181 bytes, tracked
.githooks/pre-commit      # -rwxr-xr-x, 1276 bytes, tracked
$ git status --porcelain .githooks/            # 空 = 工作区干净
```

- `core.hooksPath` 为相对值 `.githooks`，指向 git 跟踪目录（版本化 ✅）。
- 两个 hook 均存在且可执行（`-rwxr-xr-x`）。
- `pre-commit` 依次执行：`check_gate_health.py` → `check_doc_sync.py --staged` → `check_ghidra_annotations.py --all` → `check_ghidra_refs.py --all --strict`，任一失败即 `exit`。
- `commit-msg` 执行 `check_alignment_evidence.py "$1"`（机制 A）。
- 在 worktree 中 `git rev-parse --show-toplevel` 返回 worktree 根，hook 自适应，无需修改。

### 3. `tools/check_gate_health.py` — PASS

```
$ python3 tools/check_gate_health.py
gate health: OK (oracle=e40ed130, cc=114, hooks=.githooks, zcode=project-relative)
(exit 0)
```

该脚本本身覆盖面远超题设（共 10 类断言，本次全部通过）：
- oracle HEAD + 114 个 `.cc` 文件数；
- hooksPath/hook 可执行/python3/无陈旧嵌套仓路径（`$REPO_ROOT/rugra/`）；
- `tools/rust_fn_scanner.py` 存在（align_gate 的 import 依赖）；
- pre-commit 必含 4 条命令、commit-msg 必须校验消息文件；
- `.zcode/config.json` 三个事件（PreToolUse `Edit|Write|MultiEdit` / PostToolUse `Read` / SessionStart `startup|resume`）的 matcher、`command=python3`、`${ZCODE_PROJECT_DIR}` 项目相对 args；
- CI workflow `.github/workflows/alignment-gates.yml` 含全部 8 项必查串。
- 另修复了 worktree 下 GIT_DIR 环境劫持（注释 ID `GATE-WORKTREE-GITDIR-0001`，运行时清洗 6 个 `GIT_*` 环境变量）。

### 4. `tools/check_ghidra_annotations.py --all` — PASS

```
$ python3 tools/check_ghidra_annotations.py --all
✅ 扫描 95 个 .rs 文件：所有非测试函数都有 Ghidra/RUGRA-GLUE 注释
(exit 0)
```

铁律 1.3 注释门禁全库通过。

### 5. `tools/check_ghidra_refs.py --all --strict` — PASS

```
$ python3 tools/check_ghidra_refs.py --all --strict
check_ghidra_refs: OK (95 file(s), all // Ghidra refs resolve)
(exit 0)
```

机制 E 兜底：全部 `// Ghidra: file:line` 引用在锁定 12.0.4 源码树中真实存在且行号未越界。

### 6. `tools/check_alignment_evidence.py` dry-run — PASS

脚本不支持 `--help`（`argv[1]` 直接当消息文件路径，`--help` 会 FileNotFoundError exit 1——这是接口设计而非缺陷，文档用法即 `<commit_msg_file>` / `--inline` / `--self-test`）。dry-run 采用脚本内建方式：

```
$ python3 tools/check_alignment_evidence.py --self-test
check_alignment_evidence: self-test OK (5 cases, strict 4/4)   (exit 0)

$ python3 tools/check_alignment_evidence.py --inline "align: port Foo"
[机制A 拒绝提交]  …缺少 `## Alignment Evidence` 块…             (exit 1)

$ python3 tools/check_alignment_evidence.py --inline "core: ordinary fix"
[机制A] (未触发对齐检查…)                                      (exit 0)
```

5 用例含正例、触发词无块、3/4 勾选、内容占位（“未核对”）等，严格 4/4 语义核对均按预期判定。

### 7. 回执路径解析与 worktree 落位 — PASS（附潜在缺陷）

**路径解析逻辑（两脚本一致）：**

```python
ROOT      = Path(__file__).resolve().parents[1]        # 脚本自身位置的上一级 = repo root
RECEIPTS  = ROOT / ".alignment_receipts.json"
GHIDRA_CPP= ROOT / "ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
```

- 锚定**脚本文件自身位置**（非 cwd、非被编辑文件位置），`resolve()` 会穿透 symlink。
- hook 由 `.zcode/config.json` 以 `${ZCODE_PROJECT_DIR}/.zcode/<script>` 调起，因此 ROOT = **ZCode 解析出的项目目录**，与 shell cwd 无关。

**worktree 场景验证（实测样本 `/tmp/rugra-wt-rule-identityel`，全仓共约 50 个 worktree）：**

- worktree 内 `.zcode/`（git 跟踪）已检出，hooks 在 worktree 本地生效；
- `ghidra -> /home/wirs/DEV/Rugra/ghidra` symlink 存在（AGENTS.md 记载的惯例）；
- **实测证据**：worktree 本地存在 `.alignment_receipts.json`（799 B，含 `ruleaction.cc`/`coreaction.cc`/`action.cc`/`action.hh` 的 reads，行号区间正确）与 `.zcode/align_gate.log`（7 条 `[RECEIPT]` 今日条目）。Read 回执确实落在 worktree 本地，`record_receipt` 的 `p.resolve().relative_to(GHIDRA_CPP.resolve())` 经 symlink 归一化后 key 正确（如 `ruleaction.cc`）。
- 结论：**当会话的项目目录 = worktree 时（子 Agent 以 worktree 为 cwd 启动的标准形态），回执正确落位，gate 与 receipts 同根锚定，闭环成立。**

**潜在缺陷 GATE-WORKTREE-ROOTMISMATCH-0001（fail-open，已复现）：**

当 hook 副本与被编辑文件不同根时（例：hook 按主仓 `.zcode/` 调起、编辑发生在 worktree；或 agent 手动执行主仓脚本处理 worktree 文件），`align_gate.py` 主流程：

```python
try:    file_rel = str(file_path.relative_to(ROOT))   # ROOT=主仓, file=worktree → 抛异常
except: file_rel = file_path_str                      # 回退为绝对路径
...
if not (file_rel.startswith("src/") and file_rel.endswith(".rs")):
    return 0                                          # ← 静默放行，不查任何回执
```

零副作用复现（本次体检已执行，实验本身经早退路径、未写任何文件）：

```
$ echo '{"tool_name":"Edit","tool_input":{"file_path":"/tmp/rugra-wt-rule-identityel/src/ruleaction.rs","old_string":"fn x","new_string":"fn y"}}' \
    | python3 /home/wirs/DEV/Rugra/.zcode/align_gate.py
$ echo $?
0                                                  # = ALLOW，无任何输出/阻断
```

影响评估：
- 触发条件是 ZCode 对子 Agent 会话的 `ZCODE_PROJECT_DIR` 解析（若子 Agent cwd=worktree 且项目目录随 cwd 重解析，则不触发——现有 worktree 实测证据支持重解析成立）；若协调者会话（项目目录=主仓）派生 cwd=worktree 的子 Agent 且项目目录不随 cwd 重解析，则子 Agent 的 src/*.rs 编辑全部绕过铁律 1.2 门禁。
- 属 fail-open（漏放行），但 commit 时静态门禁（注释/refs/evidence，经 `git rev-parse --show-toplevel` 在 worktree 内正确解析）仍兜底，故为**运行时强制弱化**而非全门禁失效。
- 逃生阀 `ZCODE_ALIGN_GATE=0` 为已文档化设计（会写 log 记录）。
- `.alignment_receipts.json` 被 gitignore（`.gitignore:61`），回执为会话态、不跨 worktree/主仓共享——这是设计属性，同时意味着跨根读取的回执互不可见（与上述缺陷同源）。

### 8. 无硬编码路径 / python3 — PASS

- `.githooks/pre-commit`、`.githooks/commit-msg`：`#!/bin/sh` + `REPO_ROOT="$(git rev-parse --show-toplevel)"` + 一律 `python3 "$REPO_ROOT/tools/..."`。
- `.zcode/config.json`：`command: "python3"`，args 用 `${ZCODE_PROJECT_DIR}` 项目相对路径。
- `align_gate.py` / `record_receipt.py`：`#!/usr/bin/env python3`，ROOT 由 `__file__` 推导。
- grep 全部 hook 与 check_gate_health.py：无 `C:\`、`Users\`、`/home/<user>`、`.exe`、裸 `python`（仅 docstring 用法示例提及 `python record_receipt.py`，非执行路径）。

**附加自测（机制 E 运行件）：** `python3 .zcode/align_gate.py --self-test` → `✅ align_gate self-test passed`（exit 0；自测用 NamedTemporaryFile，不触碰仓库）。

---

## TODO 草案（只报告，不修复）

### GATE-WORKTREE-ROOTMISMATCH-0001（建议 P1，若主 Agent 判定 ZCode 子 Agent 会话共享主仓项目目录则升 P0）

- **问题**：`align_gate.py` 在 hook ROOT ≠ 被编辑文件根（主仓 hook / worktree 文件）时，`relative_to` 回退绝对路径 → `startswith("src/")` 不匹配 → 静默 `return 0` 放行，铁律 1.2 编辑门禁被绕过且无日志。
- **修复方案**：`file_rel` 回退分支中，若 `file_path` 位于任一 git worktree（`git rev-parse --show-toplevel`）或路径含 `/src/*.rs` 形态，则改以 toplevel 重新计算 rel 并照常 gate；或最低限度在回退分支 `log(...)` + 输出 deny（fail-closed），提示“hook 根与文件根不一致”。
- **write-set**：`.zcode/align_gate.py`（main 的 file_rel 计算段）、`tools/check_gate_health.py`（新增对回退分支的断言）、`.github/workflows/alignment-gates.yml`（若加 self-test 用例）、`docs/alignment_docs/HOOK_GUIDE.md`。
- **验收**：模拟 payload（主仓 hook + worktree src 文件）从 exit 0/静默 改为正确 gate 或显式 deny；`align_gate.py --self-test`、`check_gate_health.py`、四项 commit 门禁全绿；现有 50 个 worktree 标准流程（项目目录=worktree）行为不回归。

---

## 体检环境备注

- 主仓当前无 `.alignment_receipts.json` / `.alignment_session_start`（本会话未发生 src 编辑，属正常会话态）。
- `git worktree list` 显示约 50 个活跃 worktree（`/home/wirs/.cache/rugra-*`、`/tmp/rugra-wt-*` 等），与铁律 6 并行开发模式一致。
- 本体检全程只读：唯一写动作是 `/tmp/rugra-reports/B7-GATE-HEALTH.md`（仓库外）与两个 `/tmp/*.txt` 输出捕获文件。

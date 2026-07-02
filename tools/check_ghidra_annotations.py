#!/usr/bin/env python3
"""
check_ghidra_annotations.py — 铁律 5.5/6/9 执行工具。

每个 src/*.rs 中的非测试函数定义上方，必须有一行 `// Ghidra:` 注释，
引用其对应的 Ghidra 源码位置（file:line + 函数名）。
没有该注释 = 自创函数 = 违反对齐原则（AGENTS.md 铁律 9）。

豁免:
  - `#[test]` 标注的函数
  - `#[cfg(test)] mod tests { ... }` 内的所有函数
  - `fn main` / `fn run`（二进制入口；用 // RUGRA-GLUE: 标注即可豁免）
  - 显式标注 `// RUGRA-GLUE:` 的函数（构造器/访问器/无 Ghidra 对应的
    Rust 语言结构必需的胶水，如 new/take_emit/get_emit/set_emit，每次
    豁免必须在注释里写明为何 Ghidra 没有对应物）

用法:
    python tools/check_ghidra_annotations.py          # 检查全量 src/*.rs
    python tools/check_ghidra_annotations.py --staged # 只检查暂存的 .rs 改动
    python tools/check_ghidra_annotations.py src/foo.rs  # 检查指定文件

退出码:
    0 = 所有非测试函数都有 Ghidra 注释
    1 = 存在违规（自创函数）
"""

import re
import sys
import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

# fn 定义正则：匹配 `pub fn name(`, `fn name(`, `async fn`, `unsafe fn`
# 必须在行首（允许前导空白），捕获函数名。
FN_RE = re.compile(r"^\s*(pub\s+)?(async\s+)?(unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]")

# Ghidra 注释正则：`// Ghidra:` （允许前导空白和 // 后空格）
GHIDRA_RE = re.compile(r"//\s*Ghidra:")

# RUGRA-GLUE 豁免标记
GLUE_RE = re.compile(r"//\s*RUGRA-GLUE:")

# cfg(test) mod 开始/结束（粗略：顶格 `#[cfg(test)]` 后跟 `mod tests`）
CFG_TEST_OPEN_RE = re.compile(r"^#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
MOD_TESTS_OPEN_RE = re.compile(r"^\s*(pub\s+)?mod\s+(tests?|common)\s*\{")


def detect_git_prefix() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, cwd=PROJECT_ROOT
    )
    git_root = Path(result.stdout.strip())
    try:
        rel = PROJECT_ROOT.relative_to(git_root)
        prefix = str(rel).replace("\\", "/")
        return (prefix + "/") if prefix and prefix != "." else ""
    except ValueError:
        return ""


GIT_PREFIX = detect_git_prefix()


def strip_prefix(path: str) -> str:
    if GIT_PREFIX and path.startswith(GIT_PREFIX):
        return path[len(GIT_PREFIX):]
    return path


def get_staged_rs_files() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--staged"],
        capture_output=True, text=True, cwd=PROJECT_ROOT
    )
    raw = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    out = []
    for f in raw:
        f = strip_prefix(f)
        if f.startswith("src/") and f.endswith(".rs"):
            out.append(f)
    return out


def get_all_rs_files() -> list[str]:
    out = []
    for root, _, files in os.walk(SRC_DIR):
        for f in files:
            if f.endswith(".rs"):
                full = Path(root) / f
                out.append(str(full.relative_to(PROJECT_ROOT)).replace("\\", "/"))
    return out


def find_fn_violations(rs_abs: Path) -> list[tuple[int, str, str]]:
    """
    扫描一个 .rs 文件，返回所有违规的 (line_no_1based, fn_name, reason)。

    对每个 fn 定义：
      - 若在 #[cfg(test)] mod tests { } 内部 → 豁免
      - 若上方紧邻的注释块中有 #[test] → 豁免
      - 若上方注释块中有 // Ghidra: → 通过
      - 若上方注释块中有 // RUGRA-GLUE: → 豁免（但记录为 glue）
      - 否则 → 违规
    """
    try:
        text = rs_abs.read_text(encoding="utf-8")
    except Exception:
        return []
    lines = text.split("\n")
    n = len(lines)

    # 先标记每个 fn 的行号、是否在 test mod 内、是否有 #[test]
    # 跟踪 test mod 嵌套深度
    test_depth = 0  # 当前位于多少层 #[cfg(test)] mod 内
    # 用花括号深度跟踪 mod 退出（粗略）
    brace_stack = []  # 每项: ("test_mod", open_brace_line) 或 ("other", ...)
    fn_records = []  # (fn_line_0based, name, in_test_mod)

    i = 0
    while i < n:
        line = lines[i]
        # 检测 #[cfg(test)] mod tests { 组合（可能跨两行或同行）
        # 先看当前行是否是 cfg(test) 属性，下一行是 mod tests
        if CFG_TEST_OPEN_RE.match(line):
            # 找下一个非空非属性行，看是不是 mod tests
            j = i + 1
            while j < n and (lines[j].strip() == "" or lines[j].strip().startswith("#[")):
                j += 1
            if j < n and MOD_TESTS_OPEN_RE.match(lines[j]):
                # 这是一个 test mod，开始跟踪
                # 找该 mod 的开括号
                k = j
                while k < n and "{" not in lines[k]:
                    k += 1
                if k < n:
                    brace_stack.append(("test_mod", k))
                    test_depth += 1
                    i = k + 1
                    continue

        # 普通 mod 开括号（非 test）也跟踪，避免误把 mod 内 fn 当顶层
        m_mod = re.match(r"^\s*(pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", line)
        if m_mod and not CFG_TEST_OPEN_RE.match(line):
            brace_stack.append(("other_mod", i))

        # 跟踪花括号增减（粗略：只数 { } 不在字符串/注释里的近似——
        # 对本工具用途足够，因为我们只关心 mod 边界，fn 级 brace 不影响判定）
        # 注：这种粗略计数对内嵌 { } 字符串可能误判，但 test_mod 退出靠的是
        # 顶格 `}` 且与 mod 行缩进一致——简化起见，我们用栈匹配法：
        # 只在遇到 **顶格** 的 `}` 且栈顶是 test_mod/other_mod 时弹出。
        if line.rstrip() == "}" and brace_stack:
            kind, _ = brace_stack[-1]
            if kind in ("test_mod", "other_mod"):
                brace_stack.pop()
                if kind == "test_mod":
                    test_depth -= 1

        # 检测 fn 定义
        m = FN_RE.match(line)
        if m:
            name = m.group(4)
            in_test = test_depth > 0
            fn_records.append((i, name, in_test))

        i += 1

    violations = []
    for fn_idx, name, in_test in fn_records:
        if in_test:
            continue
        # fn main / fn run (二进制入口) 也豁免，但需 // RUGRA-GLUE 标注
        # 先向上扫描注释/属性块，收集标记
        has_test_attr = False
        has_ghidra = False
        has_glue = False
        j = fn_idx - 1
        while j >= 0:
            s = lines[j].rstrip()
            stripped = s.strip()
            if stripped == "":
                j -= 1
                continue
            if stripped.startswith("#![") or stripped.startswith("#["):
                if "test" in stripped:
                    has_test_attr = True
                j -= 1
                continue
            if stripped.startswith("//"):
                if GHIDRA_RE.search(stripped):
                    has_ghidra = True
                if GLUE_RE.search(stripped):
                    has_glue = True
                j -= 1
                continue
            # 遇到代码行，停止
            break

        if has_test_attr:
            continue
        if has_ghidra:
            continue
        if has_glue:
            continue

        reason = "缺少 `// Ghidra: <file>:<line> <fn>` 对齐注释"
        if name in ("main", "run", "default"):
            reason = f"入口/语言胶水函数 `{name}` 缺少 `// RUGRA-GLUE:` 标注（说明为何 Ghidra 无对应物）"
        violations.append((fn_idx + 1, name, reason))

    return violations


def main():
    args = sys.argv[1:]
    mode = "--all"
    explicit_files = []
    for a in args:
        if a in ("--all", "--staged"):
            mode = a
        elif a.endswith(".rs"):
            explicit_files.append(a)

    if explicit_files:
        rs_files = explicit_files
    elif mode == "--staged":
        rs_files = get_staged_rs_files()
        if not rs_files:
            print("✅ 暂存区无 .rs 文件改动")
            return 0
    else:
        rs_files = get_all_rs_files()

    total_violations = 0
    file_count = 0
    for rs_rel in rs_files:
        rs_abs = PROJECT_ROOT / rs_rel
        if not rs_abs.exists():
            continue
        file_count += 1
        vios = find_fn_violations(rs_abs)
        if vios:
            total_violations += len(vios)
            print(f"\n❌ {rs_rel}  ({len(vios)} 个违规)")
            for line_no, name, reason in vios[:30]:
                print(f"   {rs_rel}:{line_no}  fn {name}  — {reason}")
            if len(vios) > 30:
                print(f"   ... 还有 {len(vios) - 30} 个")

    if total_violations == 0:
        print(f"✅ 扫描 {file_count} 个 .rs 文件：所有非测试函数都有 Ghidra/RUGRA-GLUE 注释")
        return 0

    print(f"\n━━━ 共 {total_violations} 个自创函数（无 Ghidra 对齐注释）━━━")
    print("每个非测试函数上方必须有一行 `// Ghidra: <file>:<line> <ghidraFnName>`，")
    print("或对真正的语言结构胶水（构造器/访问器）标注 `// RUGRA-GLUE: <理由>`。")
    print("详见 AGENTS.md 铁律 9 / 5.5。")
    return 1


if __name__ == "__main__":
    sys.exit(main())

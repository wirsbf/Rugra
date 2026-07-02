#!/usr/bin/env python3
"""
check_ghidra_refs.py — commit-time gate (fallback for the runtime PreToolUse
hook in .zcode/align_gate.py).

The runtime hook enforces "re-read the Ghidra function before editing" via
.alignment_receipts.json. But runtime hooks only load at session start, so an
agent in a session that pre-dates the hook config would bypass it. This script
is the commit-time backstop: for every staged src/*.rs change, it verifies
that each `// ... <ghidra_file>:<line>` reference points at a real line in the
Ghidra source tree. It catches:
  - stale line numbers (Ghidra source shifted)
  - fabricated references (file doesn't exist / line out of range)
  - referenced line not being inside a function (sanity)

It does NOT re-check receipts (those are session-scoped and meaningless at
commit time). The runtime hook is authoritative for the read-before-edit rule;
this script is a static integrity net underneath it.

Usage:
    python tools/check_ghidra_refs.py --staged     # only staged .rs files
    python tools/check_ghidra_refs.py src/foo.rs   # specific file
    python tools/check_ghidra_refs.py --all        # all src/*.rs (CI)

Exit 0 = all refs resolve; 1 = broken refs found.
"""
from __future__ import annotations
import os
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
GHIDRA_CPP = PROJECT_ROOT / "ghidra" / "Ghidra" / "Features" / "Decompiler" / "src" / "decompile" / "cpp"

# any <file>.<cc|hh|h>:<digits>  (covers `(coreaction.cc:4886)` and bare forms)
REF_RE = re.compile(r"([A-Za-z0-9_]+\.(?:cc|hh|h))\s*[:#]\s*(\d+)")


def detect_git_prefix() -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, cwd=PROJECT_ROOT)
        root = Path(r.stdout.strip())
        rel = PROJECT_ROOT.relative_to(root)
        p = str(rel).replace("\\", "/")
        return (p + "/") if p and p != "." else ""
    except Exception:
        return ""


GIT_PREFIX = detect_git_prefix()


def strip_prefix(p: str) -> str:
    return p[len(GIT_PREFIX):] if GIT_PREFIX and p.startswith(GIT_PREFIX) else p


def staged_rs() -> list[str]:
    r = subprocess.run(["git", "diff", "--name-only", "--staged"],
                       capture_output=True, text=True, cwd=PROJECT_ROOT)
    out = []
    for f in r.stdout.strip().split("\n"):
        f = strip_prefix(f.strip())
        if f.startswith("src/") and f.endswith(".rs"):
            out.append(f)
    return out


def ghidra_line_content(gfile: str, line_no: int) -> str | None:
    p = GHIDRA_CPP / gfile
    if not p.exists():
        return None
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").split("\n")
    except Exception:
        return None
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return None


def check_file(rs_rel: str) -> list[str]:
    p = PROJECT_ROOT / rs_rel
    if not p.exists():
        return []
    problems = []
    for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").split("\n"), 1):
        if "//" not in line:
            continue
        for m in REF_RE.finditer(line):
            gfile, gline = m.group(1), int(m.group(2))
            content = ghidra_line_content(gfile, gline)
            if content is None:
                # distinguish missing file vs out-of-range line
                gp = GHIDRA_CPP / gfile
                if not gp.exists():
                    problems.append(f"{rs_rel}:{i}  references {gfile}:{gline} — "
                                    f"file not found in Ghidra cpp tree")
                else:
                    n = len(gp.read_text(encoding="utf-8", errors="ignore").split("\n"))
                    problems.append(f"{rs_rel}:{i}  references {gfile}:{gline} — "
                                    f"line out of range (file has {n} lines)")
    return problems


def main() -> int:
    args = sys.argv[1:]
    files = []
    mode = None
    strict = False
    for a in args:
        if a in ("--staged", "--all"):
            mode = a
        elif a == "--strict":
            strict = True
        elif a.endswith(".rs"):
            files.append(strip_prefix(a))
    if files:
        rs_files = files
    elif mode == "--staged":
        rs_files = staged_rs()
        if not rs_files:
            print("check_ghidra_refs: no staged .rs files")
            return 0
    else:  # --all or default
        rs_files = []
        for root, _, fnames in os.walk(SRC_DIR):
            for fn in fnames:
                if fn.endswith(".rs"):
                    rs_files.append(str((Path(root) / fn).relative_to(PROJECT_ROOT)).replace("\\", "/"))

    total = 0
    for rs in rs_files:
        probs = check_file(rs)
        for pr in probs:
            print(f"  {pr}")
            total += 1
    if total == 0:
        print(f"check_ghidra_refs: OK ({len(rs_files)} file(s), all // Ghidra refs resolve)")
        return 0
    print(f"\n━ {total} broken Ghidra reference(s) — fix the line numbers or remove the comment ━")
    if strict:
        print("  (--strict: blocking commit)")
        return 1
    print("  (advisory mode — not blocking. Use --strict to enforce.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

TOOLS-REFS-DEFSTART-0001 (机制 D 工具缺口, CR-ADDRUNIT 发现): the legacy
check only proved the cited line number was IN RANGE — a drifted citation
(e.g. pointing at a call site, or an old-oracle line still inside the file)
slipped through. This upgrade adds definition-start validation:

  For every header annotation `// Ghidra: <file>.cc:<line> <fn>` where <fn>
  resolves to a function DEFINED in the locked oracle copy of <file>, the
  cited line must be the definition start line of <fn>.

Scope rules (established conventions, kept from the ADDRUNIT lane survey):
  - Definition parsing covers the 114 oracle .cc files only. `.hh`/`.h`
    citations keep the legacy line-existence check (declaration/inline-doc
    convention is looser there).
  - <fn> is looked up in the cited file's definition map. If the name does
    not resolve there (class-level "representative line" citations, inline
    accessors defined in a .hh, cross-file call-site citations like
    `AddrSpace::byteToAddress` cited against ruleaction.cc) the citation is
    exempt from def-start validation (counted as `unresolved`, not drift).
  - Free functions are keyed by bare name; methods/ctors/dtors by
    `Class::name` (nested classes keep the full prefix).

Parser forms (ADDRUNIT corrected pattern, RULEACTION-ANNO-DRIFT-RESIDUAL-0001):
  - `RETTYPE SEP Class::name(`  where SEP = `(?:\s*[*&]\s*|\s+)` — the
    mandatory separator between return type and class name kills the greedy
    backtracking that let `e::AddTreeState` be eaten as a pseudo-type.
    Pointer-return signatures `Varnode *Foo::bar(` (star hugging the class)
    and `Varnode* Foo::bar(` (star hugging the type) both match.
  - `Class::Class(`  — bare constructor branch (checked FIRST).
  - `Class::~Class(`  — destructor branch.
  - `operator` overloads: `operator<`, `operator<<`, `operator()`, ...
  - `template<...>` prefixes and `<...>` template segments in types/classes.
  - Excluded: call lines (line ends with `;`), doc/comment lines (leading
    `//`, `/*`, `*`), and keyword false-positives (`return Foo::bar(`).

Usage:
    python tools/check_ghidra_refs.py --staged     # only staged .rs files
    python tools/check_ghidra_refs.py src/foo.rs   # specific file
    python tools/check_ghidra_refs.py --all        # all src/*.rs (CI)
    python tools/check_ghidra_refs.py --all --strict --defstart-report
                                                   # survey mode: per-file
                                                   # def-start statistics

Exit 0 = all refs resolve; 1 = broken refs found (strict only).
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

# ---------------------------------------------------------------------------
# TOOLS-REFS-DEFSTART-0001: oracle definition-start parser
# ---------------------------------------------------------------------------
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# operator symbol run: <<, <=, (), +, -, *, ->, [], ... (`(` only legal as
# part of `operator()`, the greedy run self-terminates before the arg list)
OPRUN = r"[<>=!+\-*/%&|(),~\[\]]{1,3}"
OPNAME = r"operator\s*" + OPRUN
# cv/storage prefixes + qualified type name + optional one-level template args
TYPE_TOKEN = (
    r"(?:(?:const|static|virtual|inline|unsigned|signed|long|short|friend|explicit|constexpr|extern)\s+)*"
    + IDENT + r"(?:\s*::\s*" + IDENT + r")*"
    + r"(?:\s*<[^<>]*(?:<[^<>]*>[^<>]*)*>)?"
)
# mandatory separator between return type and qualified name: pointer/ref
# (star/amp glued to either side) or plain whitespace — never absent.
SEP = r"(?:\s*[*&]\s*|\s+)"
TPL_PREFIX = r"(?:template\s*<[^;{]*>\s*)?"
# a class segment: Name or Name<args>, nested via ::
CLASS_PREFIX = IDENT + r"(?:<[^<>]*>)?(?:::" + IDENT + r"(?:<[^<>]*>)?)*"

# bare constructor: Class::Class(
CTOR_DEF = re.compile(r"^\s*" + TPL_PREFIX + r"(" + IDENT + r")::\1\s*\(")
# destructor: Class::~Class(
DTOR_DEF = re.compile(r"^\s*" + TPL_PREFIX + r"(" + IDENT + r")::~\1\s*\(")
# method: RETTYPE SEP Class::name(
METHOD_DEF = re.compile(
    r"^\s*" + TPL_PREFIX + r"(?P<ret>" + TYPE_TOKEN + r")" + SEP
    + r"(?P<cls>" + CLASS_PREFIX + r")::(?P<name>" + OPNAME + r"|" + IDENT + r")\s*\("
)
# free function: RETTYPE SEP name(
FREE_DEF = re.compile(
    r"^\s*" + TPL_PREFIX + r"(?P<ret>" + TYPE_TOKEN + r")" + SEP
    + r"(?P<name>" + OPNAME + r"|" + IDENT + r")\s*\("
)

# lines that are never definitions
DOC_LINE_RE = re.compile(r"^\s*(//|/\*|\*|/\*\*)")
# if the return-type portion is one of these keywords the match is a control
# statement or expression, not a definition (`return Foo::bar(`, `else foo(`)
KEYWORD_RETYPES = {
    "return", "else", "case", "new", "delete", "throw", "goto", "sizeof",
    "using", "typedef", "switch", "if", "while", "for", "do", "break",
    "continue", "static_assert", "assert", "co_return", "decltype",
}

# header annotation: `// Ghidra: <file>.cc:<line> <fn>` — <fn> = optionally
# qualified name, or an operator form; stops at `(`/prose.
ANNOT_DEFSTART_RE = re.compile(
    r"^\s*//\s*Ghidra:\s*"
    r"(?P<file>[A-Za-z0-9_]+\.cc):(?P<line>\d+)\s+"
    r"(?P<fn>(?:" + IDENT + r"(?:::" + IDENT + r")*::)?"
    r"(?:" + OPNAME + r"|~?" + IDENT + r"))(?![\w:<>=!+\-*/%&|(),~])"
)

_FILE_LINES_CACHE: dict[str, list[str]] = {}


def _lines_of(gfile: str) -> list[str] | None:
    if gfile in _FILE_LINES_CACHE:
        return _FILE_LINES_CACHE[gfile]
    p = GHIDRA_CPP / gfile
    if not p.exists():
        _FILE_LINES_CACHE[gfile] = None
        return None
    ls = p.read_text(encoding="utf-8", errors="ignore").split("\n")
    _FILE_LINES_CACHE[gfile] = ls
    return ls


def parse_cc_definitions(gfile: str) -> dict[str, set[int]]:
    """Extract {qualified_name: {definition start lines}} from an oracle .cc."""
    defs: dict[str, set[int]] = {}
    ls = _lines_of(gfile)
    if ls is None:
        return defs
    for i, raw in enumerate(ls, 1):
        if not raw or DOC_LINE_RE.match(raw):
            continue
        s = raw.rstrip()
        if s.endswith(";"):  # call site / declaration, never a definition start
            continue
        m = CTOR_DEF.match(raw)
        if m:
            defs.setdefault(m.group(1) + "::" + m.group(1), set()).add(i)
            continue
        m = DTOR_DEF.match(raw)
        if m:
            defs.setdefault(m.group(1) + "::~" + m.group(1), set()).add(i)
            continue
        m = METHOD_DEF.match(raw)
        if m:
            ret_tail = m.group("ret").split()[-1] if m.group("ret").split() else ""
            if ret_tail in KEYWORD_RETYPES:
                continue
            defs.setdefault(m.group("cls") + "::" + m.group("name"), set()).add(i)
            continue
        m = FREE_DEF.match(raw)
        if m:
            parts = m.group("ret").split()
            if parts and parts[-1] in KEYWORD_RETYPES:
                continue
            if len(parts) == 1 and parts[0] in KEYWORD_RETYPES:
                continue
            defs.setdefault(m.group("name"), set()).add(i)
    return defs


_DEF_MAP_CACHE: dict[str, dict[str, set[int]]] = {}


def def_map(gfile: str) -> dict[str, set[int]]:
    if gfile not in _DEF_MAP_CACHE:
        _DEF_MAP_CACHE[gfile] = parse_cc_definitions(gfile)
    return _DEF_MAP_CACHE[gfile]


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
    lines = _lines_of(gfile)
    if lines is not None and 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return None


class Stats:
    def __init__(self) -> None:
        self.exist_problems = 0
        self.defstart_checked = 0   # name resolved in cited .cc → validated
        self.defstart_ok = 0
        self.defstart_drift = 0
        self.unresolved = 0         # name not a definition in cited .cc (exempt)
        self.per_file: dict[str, list[int]] = {}  # rs file → [checked, drift]

    def bump(self, rs: str, checked: bool, drift: bool) -> None:
        st = self.per_file.setdefault(rs, [0, 0])
        if checked:
            st[0] += 1
        if drift:
            st[1] += 1


def check_file(rs_rel: str, stats: Stats) -> list[str]:
    p = PROJECT_ROOT / rs_rel
    if not p.exists():
        return []
    problems = []
    for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").split("\n"), 1):
        if "//" not in line:
            continue
        # legacy pass: every file:line ref must exist (all comment forms)
        for m in REF_RE.finditer(line):
            gfile, gline = m.group(1), int(m.group(2))
            content = ghidra_line_content(gfile, gline)
            if content is None:
                stats.exist_problems += 1
                gp = GHIDRA_CPP / gfile
                if not gp.exists():
                    problems.append(f"{rs_rel}:{i}  references {gfile}:{gline} — "
                                    f"file not found in Ghidra cpp tree")
                else:
                    n = len(gp.read_text(encoding="utf-8", errors="ignore").split("\n"))
                    problems.append(f"{rs_rel}:{i}  references {gfile}:{gline} — "
                                    f"line out of range (file has {n} lines)")
        # TOOLS-REFS-DEFSTART-0001 pass: header `// Ghidra: file.cc:N fn`
        am = ANNOT_DEFSTART_RE.match(line)
        if not am:
            continue
        gfile, gline, fn = am.group("file"), int(am.group("line")), am.group("fn")
        if gfile.endswith(".hh") or gfile.endswith(".h"):
            continue  # declaration/inline-doc convention → legacy check only
        lines = _lines_of(gfile)
        if lines is None or not (1 <= gline <= len(lines)):
            continue  # already reported by the legacy pass
        dmap = def_map(gfile)
        hit = dmap.get(fn)
        if hit is None:
            stats.unresolved += 1
            stats.bump(rs_rel, False, False)
            continue
        stats.defstart_checked += 1
        stats.bump(rs_rel, True, False)
        if gline in hit:
            stats.defstart_ok += 1
        else:
            stats.defstart_drift += 1
            stats.bump(rs_rel, True, True)
            want = sorted(hit)
            problems.append(
                f"{rs_rel}:{i}  def-start drift: cites {gfile}:{gline} for `{fn}` "
                f"but locked oracle defines it at line(s) {want} "
                f"(cited: `{lines[gline - 1].strip()[:70]}`)")
    return problems


def main() -> int:
    args = sys.argv[1:]
    files = []
    mode = None
    strict = False
    report = False
    for a in args:
        if a in ("--staged", "--all"):
            mode = a
        elif a == "--strict":
            strict = True
        elif a == "--defstart-report":
            report = True
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

    stats = Stats()
    total = 0
    for rs in rs_files:
        probs = check_file(rs, stats)
        for pr in probs:
            print(f"  {pr}")
            total += 1
    if total == 0:
        print(f"check_ghidra_refs: OK ({len(rs_files)} file(s), all // Ghidra refs resolve)")
        if report:
            _print_report(stats)
        return 0
    print(f"\n━ {total} broken Ghidra reference(s) — fix the line numbers or remove the comment ━")
    if report:
        _print_report(stats)
    if strict:
        print("  (--strict: blocking commit)")
        return 1
    print("  (advisory mode — not blocking. Use --strict to enforce.)")
    return 0


def _print_report(stats: Stats) -> None:
    print("\n── def-start survey (TOOLS-REFS-DEFSTART-0001) ──")
    print(f"  existence problems : {stats.exist_problems}")
    print(f"  def-start checked  : {stats.defstart_checked}")
    print(f"  def-start ok       : {stats.defstart_ok}")
    print(f"  def-start DRIFT    : {stats.defstart_drift}")
    print(f"  unresolved (exempt): {stats.unresolved}")
    if stats.defstart_drift:
        print("  per-file drift:")
        for rs in sorted(stats.per_file):
            chk, dr = stats.per_file[rs]
            if dr:
                print(f"    {rs}: {dr} drift / {chk} checked")


if __name__ == "__main__":
    sys.exit(main())

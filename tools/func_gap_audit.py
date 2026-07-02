#!/usr/bin/env python3
"""
func_gap_audit.py — STRICT per-function output gap audit.

Criterion (user-specified, 2026-07-02): given identical binary input,
the decompiled C output must be EXACTLY identical (token-level), NOT
"semantically equivalent". This tool measures that.

For each function present in BOTH Rugra output and Ghidra golden output:
  1. Normalize (strip comments, collapse whitespace, drop the `/* addr: */` header).
  2. Compare normalized token streams.
  3. Classify the difference.

Usage:
  python tools/func_gap_audit.py result/curl_cur.c tests/golden/ghidra_curl.c
  python tools/func_gap_audit.py result/curl_cur.c tests/golden/ghidra_curl.c --func next_url -v
  python tools/func_gap_audit.py result/curl_cur.c tests/golden/ghidra_curl.c --report docs/alignment_docs/FUNCTION_GAP_REPORT.md
"""
import re
import sys
import argparse
import difflib
from pathlib import Path

# Rugra "pseudo-functions" that are actually fragments of a real Ghidra function.
# These are CFG/cloning bugs (a function's basic blocks emitted as a separate fn).
PSEUDO_SUFFIXES = ("_part_0", "_constprop_0", "_constprop_1")
# Map a Rugra pseudo-name back to its real Ghidra parent function.
def real_name(rugra_fn):
    for suf in PSEUDO_SUFFIXES:
        if rugra_fn.endswith(suf):
            return rugra_fn[: -len(suf)]
    return rugra_fn


def split_functions(text):
    """Return {fn_name: full_body_text} for top-level C function definitions.

    A top-level def is a line at col 0 matching `<type> <name>(<params>) {` ...
    terminated by a `}` at col 0. Handles nested braces by depth counting.
    """
    # Match header at column 0
    header_re = re.compile(
        r'^([A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\(([^;]*)\))\s*\{',
        re.M,
    )
    funcs = {}
    for m in header_re.finditer(text):
        sig = m.group(1)
        name = m.group(2)
        if sig.startswith(("extern", "typedef")):
            continue
        # find the body by walking braces from end of match
        start = m.end()  # just after '{'
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = text[m.start():i]  # full header+body incl outer braces
        # keep the LAST occurrence (redefinitions override; Ghidra re-declares lib stubs)
        funcs[name] = body
    return funcs


def strip_addr_header(body):
    """Drop the `/* ---- 0xADDR: name (N bytes) ---- */` comment Ghidra prefixes."""
    return re.sub(r'^\s*/\*\s*-{2,}.*?-{2,}\s*/\s*', "", body, count=1, flags=re.S)


def normalize(body):
    """Normalize for EXACT comparison: drop comments + addr headers, collapse ws,
    strip trailing whitespace per line. Keep tokens/order intact — this is the
    strictest fair normalization (no variable renaming, no literal folding)."""
    body = strip_addr_header(body)
    # remove block + line comments
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)
    # collapse runs of whitespace
    body = re.sub(r"\s+", " ", body).strip()
    return body


def diff_kind(rugra_norm, ghidra_norm):
    """High-level classification of WHY they differ (after exact match fails)."""
    reasons = []
    r, g = rugra_norm, ghidra_norm

    # placeholder names leaking in Rugra
    if re.search(r"\bparam_\d+", r) and not re.search(r"\bparam_\d+", g):
        reasons.append("param_N placeholder (var naming)")
    if re.search(r"\bStackX_\d+", r) and not re.search(r"\bStackX_\d+", g):
        reasons.append("StackX_ placeholder (varmap)")
    if re.search(r"\buVar_[0-9a-f]+\b", r) and not re.search(r"\buVar_[0-9a-f]+\b", g):
        reasons.append("uVar_ placeholder (merge/SSA)")
    # control-flow shape divergence
    for kw in ("goto", "switch"):
        rc, gc = r.count(kw), g.count(kw)
        if rc != gc and (rc > 0 or gc > 0):
            reasons.append(f"{kw} count {rc} vs {gc}")
    # empty / malformed statements (Rugra-specific garbage)
    if re.search(r"if *\(\) *goto", r):
        reasons.append("if()goto; syntax error")
    if re.search(r"if *\(\)", r):
        reasons.append("if() empty condition")
    if "{}" in r:
        reasons.append("empty block {}")
    if not reasons:
        reasons.append("token-order/naming/expression diff (needs -v)")
    return reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rugra")
    ap.add_argument("ghidra")
    ap.add_argument("--func", help="inspect a single function verbosely")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--report", help="write a markdown report to this path")
    args = ap.parse_args()

    rugra_txt = Path(args.rugra).read_text(encoding="utf-8", errors="replace")
    ghidra_txt = Path(args.ghidra).read_text(encoding="utf-8", errors="replace")
    R = split_functions(rugra_txt)
    G = split_functions(ghidra_txt)

    if args.func:
        fn = args.func
        if fn not in R:
            print(f"[!] {fn} not in Rugra output", file=sys.stderr)
        if fn not in G:
            print(f"[!] {fn} not in Ghidra golden", file=sys.stderr)
        r = normalize(R.get(fn, ""))
        g = normalize(G.get(fn, ""))
        print(f"=== {fn}: Rugra ({len(R.get(fn,''))}B raw) vs Ghidra ({len(G.get(fn,''))}B raw) ===")
        print(f"normalized EXACT match: {r == g}")
        if r != g:
            print("diff reasons:", diff_kind(r, g))
            print("\n--- unified diff (normalized) ---")
            for line in difflib.unified_diff(
                g.splitlines(), r.splitlines(),
                fromfile="ghidra", tofile="rugra", lineterm=""
            ):
                print(line)
            print("\n--- Rugra normalized (first 600 chars) ---")
            print(r[:600])
        return

    # Build pairing: for each Rugra fn, find its Ghidra counterpart (real_name).
    rugra_fns = list(R.keys())
    ghidra_fns = set(G.keys())

    rows = []  # (rugra_fn, ghidra_fn, status, reasons, rsize, gsize)
    unpaired_rugra = []
    for rfn in rugra_fns:
        gfn = real_name(rfn)
        if gfn in G:
            r = normalize(R[rfn])
            g = normalize(G[gfn])
            status = "EXACT" if r == g else "DIFF"
            reasons = [] if r == g else diff_kind(r, g)
            rows.append((rfn, gfn, status, reasons, len(R[rfn]), len(G[gfn])))
        else:
            unpaired_rugra.append(rfn)

    # Ghidra user functions Rugra is MISSING entirely
    rugra_real = {real_name(f) for f in rugra_fns}
    # crude filter: Ghidra golden includes library stubs; flag missing USER fns by
    # absence of underscore prefix patterns — but keep all for the report.
    missing_in_rugra = [g for g in ghidra_fns if real_name(g) not in rugra_real and g not in rugra_real]

    exact = [row for row in rows if row[2] == "EXACT"]
    diff = [row for row in rows if row[2] == "DIFF"]

    out = []
    out.append(f"# Per-function STRICT output gap audit\n")
    out.append(f"**Rugra**: `{args.rugra}`  |  **Ghidra golden**: `{args.ghidra}`\n")
    out.append(f"**Criterion**: token-level EXACT match after comment/whitespace normalization (NOT semantic equivalence).\n")
    out.append(f"\n## Summary\n")
    out.append(f"| metric | value |")
    out.append(f"|---|---|")
    out.append(f"| Rugra functions | {len(rugra_fns)} |")
    out.append(f"| Ghidra functions | {len(ghidra_fns)} |")
    out.append(f"| Paired (in both) | {len(rows)} |")
    out.append(f"| **EXACT match** | **{len(exact)}** |")
    out.append(f"| DIFF | {len(diff)} |")
    out.append(f"| Rugra unpaired (pseudo/extra) | {len(unpaired_rugra)} |")
    out.append(f"| In Ghidra, missing from Rugra | {len(missing_in_rugra)} |")

    out.append(f"\n## EXACT matches ({len(exact)})\n")
    if exact:
        out.append("| Rugra fn | Ghidra fn | size |")
        out.append("|---|---|---|")
        for rfn, gfn, _, _, rs, gs in exact:
            out.append(f"| `{rfn}` | `{gfn}` | {rs}B |")
    else:
        out.append("_(none)_")

    out.append(f"\n## DIFF ({len(diff)}) — needs alignment\n")
    out.append("| Rugra fn | Ghidra fn | rugra/ghidra size | diff reasons |")
    out.append("|---|---|---|---|")
    for rfn, gfn, _, reasons, rs, gs in diff:
        out.append(f"| `{rfn}` | `{gfn}` | {rs}/{gs} | {', '.join(reasons)} |")

    if unpaired_rugra:
        out.append(f"\n## Rugra pseudo/extra functions (no direct Ghidra pair)\n")
        for f in unpaired_rugra:
            mapped = real_name(f)
            note = f"→ fragment of `{mapped}`" if mapped != f else "(extra fn)"
            out.append(f"- `{f}` {note}")

    if missing_in_rugra:
        out.append(f"\n## Ghidra functions absent from Rugra output ({len(missing_in_rugra)})\n")
        out.append("_(includes library stubs; USER fns = the real gap)_\n")
        for f in sorted(missing_in_rugra):
            out.append(f"- `{f}`")

    report = "\n".join(out)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"[wrote] {args.report}")
    print(report)
    # exit code: nonzero if any DIFF (useful as a gate)
    sys.exit(1 if diff else 0)


if __name__ == "__main__":
    main()

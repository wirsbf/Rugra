#!/usr/bin/env python3
# EVMANIFEST: per-function skeleton-identical list, gate 口径 (compare_ghidra semantics).
import sys
import importlib.util

spec = importlib.util.spec_from_file_location(
    "cg", "/dev/shm/rugra-worktrees/evmanifest/tools/compare_ghidra.py")
cg = importlib.util.module_from_spec(spec)
sys.modules["cg"] = cg
spec.loader.exec_module(cg)


def skeleton_identical(rugra_path, golden_path, label):
    rug_text = open(rugra_path, encoding="utf-8", errors="replace").read()
    gol_text = open(golden_path, encoding="utf-8", errors="replace").read()
    rug = cg.parse_functions(rug_text)
    gol = cg.parse_functions(gol_text)
    pairs = cg.match_functions(rug, gol)
    ident, differ, total = [], [], 0
    for addr, rn, rbody, gn, gbody in pairs:
        res = cg.diff_function(rbody, gbody, mode="skeleton")
        diff = res["skeleton_diff"]
        n = sum(1 for l in diff if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))
        total += n
        (ident if not diff else differ).append(rn)
    print(f"[{label}] matched={len(pairs)} skeleton-identical={len(ident)} differ={len(differ)} total_diff_lines={total}")
    print(f"[{label}] identical list: {', '.join(sorted(ident))}")
    print(f"[{label}] new-vs-GB reference: see scoreboard")


if __name__ == "__main__":
    skeleton_identical(sys.argv[1], sys.argv[2], sys.argv[3])

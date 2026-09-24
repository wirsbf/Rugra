#!/usr/bin/env python3
# GB scoreboard: Level-1 byte-exact per-function comparison (read-only).
# Uses the gate tool's own function splitter (compare_ghidra.parse_functions)
# so function identity == gate identity; adds a raw byte-exact layer that the
# gate skeleton normalization deliberately does not measure.
import re
import sys
import importlib.util

spec = importlib.util.spec_from_file_location(
    "cg", "/dev/shm/rugra-worktrees/evmanifest/tools/compare_ghidra.py")
cg = importlib.util.module_from_spec(spec)
sys.modules["cg"] = cg
spec.loader.exec_module(cg)

IMPORT_STUB_HINTS = re.compile(
    r"^(?:__.*|_init|_start|__libc_csu_init|__do_global_dtors_aux|"
    r"deregister_tm_clones|register_tm_clones|frame_dummy|.*@plt)$")


def load_blocks(path, base_offset=0x100000):
    """Return [(norm_addr, name, block_text)], one per header occurrence.

    block_text spans the header line through the line before the next header
    (byte-exact incl. newlines), so Level-1 equality is full-function text
    equality, not body-only. Identity = compare_ghidra.match_functions
    semantics: normalized address (addr - 0x100000 vs raw addr for the
    direct-runner baseline), stripped-name fallback. Duplicate names
    (PLT stub + EXTERNAL target) are kept distinct via address keying.
    """
    text = open(path, encoding="utf-8", errors="replace").read()
    lines = text.splitlines(keepends=True)
    blocks = []
    starts = [i for i, ln in enumerate(lines) if cg.HEADER_RE.match(ln)]
    for idx, i in enumerate(starts):
        j = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        m = cg.HEADER_RE.match(lines[i])
        addr = int(m.group(1), 16)
        name = m.group(2)
        # Level-1 compares the function BODY text (header line excluded: the
        # canon golden carries the +0x100000 image base in its header addr).
        body = "".join(lines[i + 1:j])
        blocks.append((addr - base_offset, name, body))
    return blocks


def classify(name):
    if IMPORT_STUB_HINTS.match(name):
        return "import-stub"
    return "real-code"


def compare(rugra_c, golden_c, base_offset=0x100000, label=""):
    rugra = load_blocks(rugra_c)
    golden = load_blocks(golden_c)
    # gate semantics: rugra addr is raw; golden (canon) addr = rugra + 0x100000
    golden_by_key = {a: (a, n, b) for a, n, b in golden}
    golden_by_name = {}
    for a, n, b in golden:
        golden_by_name.setdefault(cg.strip_gcc_suffix(n), (a, n, b))
    matched = 0
    exact = []
    missing = []
    for addr, name, rblk in rugra:
        g = golden_by_key.get(addr) or golden_by_name.get(
            cg.strip_gcc_suffix(name))
        if g is None:
            missing.append(name)
            continue
        matched += 1
        if rblk == g[2]:
            exact.append((name, classify(name)))
    print(f"[{label}] rugra_fns={len(rugra)} golden_fns={len(golden)} "
          f"matched={matched} unmatched_rugra={len(missing)}")
    print(f"[{label}] BYTE-EXACT = {len(exact)} / {matched} matched "
          f"({100.0 * len(exact) / max(matched, 1):.1f}%)")
    stubs = sorted(n for n, c in exact if c == "import-stub")
    real = sorted(n for n, c in exact if c == "real-code")
    print(f"[{label}]   real-code ({len(real)}): {', '.join(real)}")
    print(f"[{label}]   import-stub ({len(stubs)}): {', '.join(stubs)}")
    if missing:
        print(f"[{label}]   unmatched rugra fns: {', '.join(sorted(missing))}")
    return exact, matched


if __name__ == "__main__":
    compare(sys.argv[1], sys.argv[2], label=sys.argv[3] if len(sys.argv) > 3 else "")

#!/usr/bin/env python3
"""harvest_local_manifest.py — C1 TYPE-SEED-LOCAL manifest harvester.

Harvests the committed-local seed manifest from a canonical analyzeHeadless
golden (HEADLESS_BRIDGE_V1_DESIGN.md 5.1): per function, the declaration
block between the opening '{' and the first non-declaration line yields
(type, name, array dims) for every `local_[0-9a-f]+` declarator.  Stack
offset = -int(name[6:], 16) (the offset is embedded in the name by Ghidra's
stack buildDefaultName).

Output manifest records oracle commit + golden sha256 (B2 provenance).

Usage:
  harvest_local_manifest.py GOLDEN.c CORPUS ORACLE_COMMIT OUT.json [--typed-only]
"""
import hashlib
import json
import re
import sys

FUNC_HEADER = re.compile(r"^/\* ---- 0x([0-9a-f]+): (.+) \(\d+ bytes\) ---- \*/$")
DECL = re.compile(
    r"^\s*(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*?)"
    r"(?P<stars>\s*\*+\s*|\s+)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<arr>(?:\s*\[\d+\])+)?"
    r";\s*$"
)
LOCAL_NAME = re.compile(r"^local_[0-9a-f]+$")
# Parenthesized declarators (function pointers / array-of pointers to
# arrays): `undefined1 (*pauVar6) [16];` — must not end the decl block.
DECL_PAREN = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_ ]*?\(\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
    r"(?P<arr>(?:\s*\[\d+\])+)?"
    r"\s*;\s*$"
)


# Bases the C1 v1 seed channel can install with faithful size/metatype
# (scalar/pointer/array domain). Struct-typed committed locals (sigaction,
# sigset_t, ...) are C4 composite-channel domain and are skipped here so the
# manifest never carries a type the channel would mistype.
KNOWN_BASES = {
    "void", "char", "byte",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "short", "ushort", "int", "uint", "long", "ulong", "size_t",
    "__pid_t", "float", "double", "bool",
}


def base_of(type_expr):
    return type_expr.split("[")[0].rstrip("*").strip()


def parse_type_expr(type_text, stars, arr):
    base = " ".join(type_text.split())
    if not base:
        return None
    nstars = stars.count("*")
    ptr = " " + "*" * nstars if nstars else ""
    dims = "".join("[%d]" % int(d) for d in re.findall(r"\[(\d+)\]", arr or ""))
    return base + ptr + dims


def split_functions(text):
    """Yield (addr, name, [lines]) per golden function block."""
    cur_addr = None
    cur_name = None
    cur_lines = []
    for line in text.split("\n"):
        m = FUNC_HEADER.match(line)
        if m:
            if cur_addr is not None:
                yield cur_addr, cur_name, cur_lines
            cur_addr, cur_name, cur_lines = "0x" + m.group(1), m.group(2), []
        elif cur_addr is not None:
            cur_lines.append(line)
    if cur_addr is not None:
        yield cur_addr, cur_name, cur_lines


def harvest_function(lines):
    locals_ = []
    started = False
    for line in lines:
        stripped = line.strip()
        if not started:
            if stripped == "{":
                started = True
            continue
        if not stripped:
            continue
        dm = DECL.match(line)
        if dm is None:
            dm = DECL_PAREN.match(line)
            if dm is not None:
                continue  # parenthesized declarator: never a local_ seed (v1 domain)
        if dm is None:
            break  # first statement ends the declaration block
        if not LOCAL_NAME.match(dm.group("name")):
            continue
        type_expr = parse_type_expr(dm.group("type"), dm.group("stars"), dm.group("arr"))
        if type_expr is None:
            continue
        if base_of(type_expr) not in KNOWN_BASES:
            continue  # C4 composite domain: outside the v1 seed channel
        name = dm.group("name")
        locals_.append(
            {"offset": -int(name[6:], 16), "name": name, "type": type_expr, "typelock": True}
        )
    return locals_


def harvest(path):
    text = open(path, "r", encoding="utf-8").read()
    functions = {}
    for addr, name, lines in split_functions(text):
        locs = harvest_function(lines)
        if locs:
            functions[addr] = {"name": name, "locals": locs}
    return functions


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    golden, corpus, oracle_commit, out = sys.argv[1:5]
    typed_only = "--typed-only" in sys.argv[5:]
    funcs = harvest(golden)
    if typed_only:
        for fn in funcs.values():
            fn["locals"] = [l for l in fn["locals"] if not l["type"].startswith("undefined")]
        funcs = {k: v for k, v in funcs.items() if v["locals"]}
    nlocals = sum(len(f["locals"]) for f in funcs.values())
    manifest = {
        "oracle_commit": oracle_commit,
        "corpus": corpus,
        "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
        "harvest_rule": (
            "decl-block lines matching '(type)([*]*)local_[0-9a-f]+([N])*;' before "
            "first statement; offset = -int(name[6:],16)"
        ),
        "functions": funcs,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    print(
        "harvested %d functions / %d committed locals (%s) -> %s"
        % (len(funcs), nlocals, "typed-only" if typed_only else "all", out)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

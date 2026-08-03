#!/usr/bin/env python3
"""Analyze Rugra IR dumps for the 5 target functions.

For each function's PRE and POST IR, count:
- total ops, alive ops, dead ops, basic blocks
- PTRSUB, CAST, MULTIEQUAL, INDIRECT counts
- INT_ADD(register_ptr, const) candidates for RulePtrArith conversion
- input-flagged varnodes ([in] markers)
- dead-op anomalies (ops on all-constants, MULTIEQUAL with identical inputs)
"""
import re
import sys
from collections import Counter

# op_addr lines look like: "  [0x4f74] COPY            out=...  in0=..."
OP_RE = re.compile(r'^\s*\[0x[0-9a-f]+\]\s+(\S+)\s*(.*?)\s*$')
VN_RE = re.compile(r'(out|in\d+)=(\S+)')
BB_RE = re.compile(r'^BB 0x[0-9a-f]+ \((\d+) ops\):')
LIVE_RE = re.compile(r'(\d+) bblocks, (\d+) live ops')
# A varnode token like reg@0x20#8[in][w]  or  ram@0x1174f0#8[in]
VN_PARTS = re.compile(r'^(reg|ram|u|const|stack|join|iop)@0x([0-9a-f]+)#(\d+)(.*)$')


def parse_vn(token):
    """Return (space, off, size, flags_list) or None."""
    m = VN_PARTS.match(token)
    if not m:
        return None
    space, off, size, flags = m.groups()
    fl = []
    if '[in]' in flags: fl.append('in')
    if '[c]' in flags: fl.append('c')
    if '[w]' in flags: fl.append('w')
    return (space, int(off, 16), int(size), fl)


def parse_file(path):
    """Return dict with stats."""
    with open(path) as f:
        lines = f.read().splitlines()

    ops = []  # list of dicts: {opc, out, ins, dead, bb}
    cur_bb = None
    live_blocks = 0
    header_alive = None
    header_blocks = None

    for line in lines:
        m = LIVE_RE.search(line)
        if m:
            header_blocks = int(m.group(1))
            header_alive = int(m.group(2))
            continue
        m = BB_RE.match(line)
        if m:
            cur_bb = int(m.group(1)) if False else line  # keep raw; not needed
            continue
        m = OP_RE.match(line)
        if m:
            opc = m.group(1)
            rest = m.group(2)
            dead = '[DEAD]' in rest
            rest = rest.replace('[DEAD]', '').strip()
            vns = VN_RE.findall(rest)
            out = vns[0][1] if vns and vns[0][0] == 'out' else ''
            ins = [tok for (slot, tok) in vns if slot.startswith('in')]
            ops.append({'opc': opc, 'out': out, 'ins': ins, 'dead': dead})

    return {'ops': ops, 'header_alive': header_alive, 'header_blocks': header_blocks}


def analyze(path, label):
    d = parse_file(path)
    ops = d['ops']
    alive = [o for o in ops if not o['dead']]
    dead = [o for o in ops if o['dead']]

    opc_counter = Counter(o['opc'] for o in alive)

    def count(name):
        return opc_counter.get(name, 0)

    # Input-flagged varnodes: distinct [in] varnodes across all alive ops
    in_vns = set()
    for o in alive:
        for tok in [o['out']] + o['ins']:
            pv = parse_vn(tok)
            if pv and 'in' in pv[3]:
                in_vns.add((pv[0], pv[1], pv[2]))
    # Also count input varnodes that appear ONLY as inputs (typical for params)
    in_only_inputs = set()
    for o in alive:
        for tok in o['ins']:
            pv = parse_vn(tok)
            if pv and 'in' in pv[3]:
                in_only_inputs.add((pv[0], pv[1], pv[2]))

    # PTRSUB candidates: INT_ADD where in0 is a register pointer (reg space) and in1 is const
    ptrsub_candidates = []
    for o in alive:
        if o['opc'] != 'INT_ADD':
            continue
        if len(o['ins']) < 2:
            continue
        in0 = parse_vn(o['ins'][0])
        in1 = parse_vn(o['ins'][1])
        if in0 and in1 and in0[0] == 'reg' and 'c' in in1[3]:
            ptrsub_candidates.append(o)
    # Also count INT_ADD where in0 is a ram varnode (struct base on stack/ram)
    ram_add_candidates = []
    for o in alive:
        if o['opc'] != 'INT_ADD':
            continue
        if len(o['ins']) < 2:
            continue
        in0 = parse_vn(o['ins'][0])
        in1 = parse_vn(o['ins'][1])
        if in0 and in1 and in0[0] in ('ram', 'stack', 'u') and 'c' in in1[3]:
            ram_add_candidates.append(o)

    # Dead-op anomalies: ops on all-constant inputs that survived
    all_const_dead = []
    for o in ops:
        if o['opc'] in ('COPY', 'STORE', 'BRANCH', 'CBRANCH', 'CALL', 'RETURN', 'LOAD'):
            continue
        ins = [parse_vn(t) for t in o['ins']]
        if ins and all(iv is not None and 'c' in iv[3] for iv in ins):
            all_const_dead.append(o)

    # MULTIEQUAL with all-identical inputs
    trivial_multiequal = []
    for o in alive:
        if o['opc'] != 'MULTIEQUAL':
            continue
        if len(set(o['ins'])) == 1 and len(o['ins']) > 1:
            trivial_multiequal.append(o)

    print(f"\n{'='*70}")
    print(f"  {label}: {path}")
    print(f"{'='*70}")
    print(f"  Header: {d['header_blocks']} bblocks, {d['header_alive']} live ops")
    print(f"  Parsed: {len(ops)} total ops ({len(alive)} alive, {len(dead)} dead)")
    print(f"  Top opcodes: {opc_counter.most_common(12)}")
    print(f"  --- Key opcodes (alive only) ---")
    print(f"  PTRSUB:       {count('PTRSUB')}")
    print(f"  PTRADD:       {count('PTRADD')}")
    print(f"  CAST:         {count('CAST')}")
    print(f"  MULTIEQUAL:   {count('MULTIEQUAL')}")
    print(f"  INDIRECT:     {count('INDIRECT')}")
    print(f"  INT_ADD:      {count('INT_ADD')}")
    print(f"  STORE:        {count('STORE')}")
    print(f"  CALL:         {count('CALL')}")
    print(f"  --- PTRSUB conversion candidates ---")
    print(f"  INT_ADD(reg, const) [should -> PTRSUB]: {len(ptrsub_candidates)}")
    print(f"  INT_ADD(ram/stack/u, const)          : {len(ram_add_candidates)}")
    if ptrsub_candidates[:3]:
        print(f"    examples:")
        for o in ptrsub_candidates[:3]:
            print(f"      out={o['out']}  in0={o['ins'][0]}  in1={o['ins'][1]}")
    print(f"  --- Input-flagged varnodes ([in]) ---")
    print(f"  distinct [in] varnodes (anywhere): {len(in_vns)}")
    print(f"  distinct [in] varnodes (as input): {len(in_only_inputs)}")
    # Group input varnodes by space
    by_space = Counter(v[0] for v in in_only_inputs)
    print(f"  by space: {dict(by_space)}")
    # List reg inputs (params)
    reg_ins = sorted([(v[1], v[2]) for v in in_only_inputs if v[0] == 'reg'])
    if reg_ins:
        print(f"  reg inputs (off,size): {[(hex(o),s) for o,s in reg_ins]}")
    print(f"  --- Anomalies ---")
    print(f"  ops on all-constant inputs (folded? dead?): {len(all_const_dead)} "
          f"({sum(1 for o in all_const_dead if o['dead'])} dead)")
    print(f"  MULTIEQUAL with identical inputs      : {len(trivial_multiequal)}")

    return {
        'alive': len(alive), 'dead': len(dead),
        'ptrsub': count('PTRSUB'), 'cast': count('CAST'),
        'multiequal': count('MULTIEQUAL'), 'indirect': count('INDIRECT'),
        'int_add': count('INT_ADD'),
        'ptrsub_cand_reg': len(ptrsub_candidates),
        'ptrsub_cand_ram': len(ram_add_candidates),
        'in_vns': len(in_only_inputs),
        'all_const_ops': len(all_const_dead),
        'trivial_me': len(trivial_multiequal),
    }


def main():
    import os
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'result', 'ir_dumps')
    funcs = ['glob_url', 'my_fwrite', 'GetStr', 'myprogress', 'main']
    results = {}
    for fn in funcs:
        pre = analyze(os.path.join(base, f'rugra_{fn}_pre.txt'), f'{fn} PRE')
        post = analyze(os.path.join(base, f'rugra_{fn}_post.txt'), f'{fn} POST (no seed)')
        post_seed = analyze(os.path.join(base, f'rugra_{fn}_post_seed.txt'), f'{fn} POST (seeded)')
        results[fn] = (pre, post, post_seed)

    print(f"\n{'#'*70}")
    print(f"  SUMMARY TABLE  (POST=no-seed, POST*=seeded = real-driver equivalent)")
    print(f"{'#'*70}")
    print(f"{'func':<12} {'PRE':>6} {'POST':>6} {'POST*':>6} {'PTRSUB':>7}/{'*':>3} "
          f"{'CAST':>5}/{'*':>3} {'ME':>4}/{'*':>3} {'IND':>4}/{'*':>3} "
          f"{'ADDreg':>6}/{'*':>3} {'inVN':>5}/{'*':>3}")
    for fn, (pre, post, post_seed) in results.items():
        print(f"{fn:<12} {pre['alive']:>6} {post['alive']:>6} {post_seed['alive']:>6} "
              f"{post['ptrsub']:>7}/{post_seed['ptrsub']:>3} "
              f"{post['cast']:>5}/{post_seed['cast']:>3} "
              f"{post['multiequal']:>4}/{post_seed['multiequal']:>3} "
              f"{post['indirect']:>4}/{post_seed['indirect']:>3} "
              f"{post['ptrsub_cand_reg']:>6}/{post_seed['ptrsub_cand_reg']:>3} "
              f"{post['in_vns']:>5}/{post_seed['in_vns']:>3}")


if __name__ == '__main__':
    main()

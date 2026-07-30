#!/usr/bin/env python3
"""Node-level IR diff: Rugra vs Ghidra for the same function.
Reads both IR dump files, normalizes addresses (Ghidra uses image-base 0x100000),
and prints a side-by-side comparison highlighting structural differences."""
import re, sys

# Ghidra opcode number -> name
OPCODES = {
    1:'COPY', 2:'LOAD', 3:'STORE', 4:'BRANCH', 5:'CBRANCH', 6:'BRANCHIND',
    7:'CALL', 8:'CALLIND', 9:'CALLOTHER', 10:'RETURN',
    11:'INT_EQUAL', 12:'INT_NOTEQUAL', 13:'INT_SLESS', 14:'INT_SLESSEQUAL',
    15:'INT_LESS', 16:'INT_LESSEQUAL', 17:'INT_ZEXT', 18:'INT_SEXT',
    19:'INT_ADD', 20:'INT_SUB', 21:'INT_CARRY', 22:'INT_SCARRY', 23:'INT_SBORROW',
    24:'INT_2COMP', 25:'INT_NEGATE', 26:'INT_XOR', 27:'INT_AND', 28:'INT_OR',
    29:'INT_LEFT', 30:'INT_RIGHT', 31:'INT_SRIGHT', 32:'INT_MULT', 33:'INT_DIV',
    34:'INT_SDIV', 35:'INT_REM', 36:'INT_SREM',
    37:'BOOL_NEGATE', 38:'BOOL_AND', 39:'BOOL_OR', 40:'BOOL_XOR',
    41:'FLOAT_EQUAL', 42:'FLOAT_NOTEQUAL', 43:'FLOAT_LESS',
    44:'FLOAT_LESSEQUAL', 45:'FLOAT_NAN',
    46:'FLOAT_ADD', 47:'FLOAT_SUB', 48:'FLOAT_MULT', 49:'FLOAT_DIV',
    50:'FLOAT_INT2FLOAT', 51:'FLOAT_FLOAT2FLOAT', 52:'FLOAT_TRUNC', 53:'FLOAT_CEIL',
    54:'FLOAT_FLOOR', 55:'FLOAT_ROUND', 56:'FLOAT_SQRT',
    57:'INT_SEXT1', 58:'SUBPIECE', 59:'PIECE',
    60:'MULTIEQUAL', 61:'INDIRECT', 62:'INDIRECT', 63:'INDIRECT',
    64:'CAST', 65:'PTRADD', 66:'PTRSUB', 67:'SEGMENTOP', 68:'CPOOLREF',
    69:'NEW', 70:'INSERT', 71:'EXTRACT', 72:'POPCOUNT',
    73:'LZCOUNT', 74:'PUNION', 75:'PDISJOINT', 76:'PCONCAT', 77:'PCONST',
}

def parse_ir(path, is_ghidra):
    """Parse IR dump into list of (bb_addr, op_addr, opc_name, out_vn, in_vns, is_dead)."""
    with open(path) as f:
        lines = f.read().split('\n')
    ops = []
    cur_bb = None
    for line in lines:
        line = line.strip()
        if not line: continue
        m = re.match(r'BB 0x([0-9a-f]+)', line)
        if m:
            cur_bb = int(m.group(1), 16)
            continue
        # op line: [0xADDR] OPC  out=...  in0=...
        m = re.match(r'\[0x([0-9a-f]+)\]\s+(\S+)\s*(.*)', line)
        if m:
            op_addr = int(m.group(1), 16)
            opc_raw = m.group(2)
            rest = m.group(3)
            # Normalize opcode
            if opc_raw.isdigit():
                opc = OPCODES.get(int(opc_raw), f'OPC_{opc_raw}')
            else:
                opc = opc_raw.replace('CPUI_', '')
            # Normalize address: Ghidra uses image base 0x100000, Rugra doesn't
            if is_ghidra:
                op_addr -= 0x100000
            # Extract varnodes
            is_dead = '[DEAD]' in rest
            rest = rest.replace('[DEAD]', '').strip()
            out_m = re.search(r'out=(\S+)', rest)
            out_vn = out_m.group(1) if out_m else ''
            in_vns = re.findall(r'in\d+=(\S+)', rest)
            # Normalize addresses in varnodes (subtract image base for Ghidra)
            def norm_vn(vn):
                if is_ghidra:
                    return re.sub(r'@0x([0-9a-f]+)', lambda m: '@0x%x' % (int(m.group(1),16) - 0x100000), vn)
                return vn
            out_vn = norm_vn(out_vn)
            in_vns = [norm_vn(v) for v in in_vns]
            ops.append((cur_bb, op_addr, opc, out_vn, in_vns, is_dead))
    return ops

def summarize(ops, label):
    """Print opcode distribution + key stats."""
    from collections import Counter
    opc_counts = Counter(op[2] for op in ops if not op[5])  # exclude DEAD
    print(f"\n=== {label} ({len(ops)} ops total, {sum(1 for o in ops if not o[5])} alive) ===")
    print(f"  Top opcodes: {opc_counts.most_common(15)}")
    # Count CALLs, STOREs, return-addr STOREs
    calls = [o for o in ops if o[2] == 'CALL' and not o[5]]
    stores = [o for o in ops if o[2] == 'STORE' and not o[5]]
    ptrsubs = [o for o in ops if o[2] == 'PTRSUB' and not o[5]]
    multiequal = [o for o in ops if o[2] == 'MULTIEQUAL' and not o[5]]
    indirect = [o for o in ops if o[2] == 'INDIRECT' and not o[5]]
    print(f"  CALL: {len(calls)}, STORE: {len(stores)}, PTRSUB: {len(ptrsubs)}")
    print(f"  MULTIEQUAL: {len(multiequal)}, INDIRECT: {len(indirect)}")

def main():
    ghidra_ops = parse_ir('ghidra_proj/ghidra_main_ir.txt', is_ghidra=True)
    rugra_ops = parse_ir('ghidra_proj/rugra_main_ir.txt', is_ghidra=False)
    summarize(ghidra_ops, 'Ghidra main')
    summarize(rugra_ops, 'Rugra main')

    # Find the first divergence: compare op-by-op at each address
    print("\n=== First divergence (op-by-op at matching addresses) ===")
    ghidra_by_addr = {op[1]: op for op in ghidra_ops}
    rugra_by_addr = {op[1]: op for op in rugra_ops}
    common_addrs = sorted(set(ghidra_by_addr) & set(rugra_by_addr))
    print(f"Common addresses: {len(common_addrs)} / Ghidra {len(ghidra_by_addr)} / Rugra {len(rugra_by_addr)}")

    diverged = 0
    for addr in common_addrs[:50]:
        g = ghidra_by_addr[addr]
        r = rugra_by_addr[addr]
        if g[2] != r[2]:  # opcode differs
            if diverged < 10:
                print(f"  DIVERGE @0x{addr:x}: Ghidra={g[2]} vs Rugra={r[2]}")
            diverged += 1
    if diverged == 0:
        print("  (no opcode divergence in first 50 common addresses)")

    # Specific: compare around curl_version call (0x25f2)
    print("\n=== Around curl_version call (BB 0x25a4 / 0x25ef) ===")
    for label, ops_list in [('Ghidra', ghidra_ops), ('Rugra', rugra_ops)]:
        print(f"\n--- {label} ---")
        for op in ops_list[:25]:
            bb, addr, opc, out, ins, dead = op
            d = ' [DEAD]' if dead else ''
            print(f"  [0x{addr:x}] {opc:14} out={out:30} ins={ins}{d}")

if __name__ == '__main__':
    main()

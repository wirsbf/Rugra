#!/usr/bin/env python3
"""
resid_decomp.py — Lane FP: merged-state (master 8cf844a1) residual map.

Method (EV delta_decomp.py adapted to the post-merge world):
  merged  = current master E2E output           (canon gate target: curl 2147 / httpd 2153)
  canon   = tests/golden/ghidra_<bin>_1204.c    (headless canonical gate baseline)
  direct  = tests/golden/ghidra_<bin>_1204.direct-runner.c  (EG2/FI-ruled C++ library truth)

Per matched function (same matching as compare_ghidra):
  gate diff n_mc  = unified-diff(canon_sk, merged_sk)   [must equal compare tool per-fn number]
  direct dist n_md = unified-diff(direct_sk, merged_sk)
  headless<->direct divergence n_cd = unified-diff(canon_sk, direct_sk)   [context]

  Net-ADDED lines (merged has, canon lacks; multiset cancellation vs canon):
    BRIDGE       : line present in direct same-function skeleton (exact text, within multiplicity)
    OVER_BRIDGE  : copies beyond direct multiplicity
    OVER_CANON   : copies of a canon line beyond canon multiplicity
    CAST         : cast-normalized form matches either baseline (within multiplicity)
    OVER_CAST    : beyond that multiplicity
    GAP_STRICT   : neither baseline has the line (same-function) -> library-level gap
  Net-REMOVED lines (canon has, merged lacks):
    LOST_BOTH    : direct also has the line (both goldens have it, merged dropped)
    LOST_HEADLESS: direct lacks it too (merged sits in the library world; not a lib defect)
  GAP/OVER lines get family tags (EV FAMILIES + merged-state additions).

Self-check: sum(n_mc) over matched functions must equal the canon gate total.
"""
import re
import sys
import difflib
from pathlib import Path
from collections import Counter

sys.path.insert(0, '/dev/shm/rugra-worktrees/residmap/tools')
import compare_ghidra as cg

SB = Path('/dev/shm/rugra-tests/sb-residmap')
WT = Path('/dev/shm/rugra-worktrees/residmap')

# EV families (regexes adjusted where normalize_skeleton rewrites the text)
FAMILIES = [
    ('IN_REG',    r'\bin_(?:R|E)[A-Z0-9]+\b'),
    ('IN_RIP',    r'\bin_RIP\b'),
    ('IN_STK',    r'\bin_stack_[0-9a-zA-Z]+\b'),
    ('RAWSTACK',  r'\b[iupa]{1,2}Stack_[0-9a-fA-F]+\b'),
    ('RAM',       r'\b[a-z]{1,3}Ram[0-9a-fA-F]+\b'),
    ('EXTRAOUT',  r'\bextraout_\w+'),
    ('CONCAT',    r'\bCONCAT\d+'),
    ('ZSEXT',     r'\b[ZS]EXT\d+'),
    ('SUBPIECE',  r'\._(?:LIT|[0-9a-fA-F]+)_(?:LIT|[0-9a-fA-F]+)_'),
    ('BADTYPE',   r'\bBADSPACEBASE\b|\bBADTYPE\b|\bBADSPACE\b'),
    ('WARN',      r'/\* WARNING'),
    ('UNIQUE',    r'\bunique(?:0x[0-9a-fA-F]+|LIT)\b'),
    ('DAT_LAB',   r'\bDAT_[0-9a-fA-F]+\b|\bLAB_[0-9a-fA-F]+\b'),
    ('CODEREF',   r'\bcode_rLIT\b|\bcode_r0x[0-9a-fA-F]+\b'),
    ('SWITCHD',   r'\bswitchD_\w+'),
    ('RVAL_ASSIGN', r'^\*.*\+ LIT = '),
    ('FS_OFF',    r'\bin_FS_OFFSET\b|\bFS_OFFSET\b'),
]
FAM_RES = [(n, re.compile(p, re.M)) for n, p in FAMILIES]


def fams(line):
    return [n for n, r in FAM_RES if r.search(line)]


def load(path):
    text = Path(path).read_text(errors='replace')
    return {n: b for _, n, _, b in cg.parse_functions(text)}


def diffcount(a_sk, b_sk):
    d = difflib.unified_diff(a_sk, b_sk, 'g', 'r', lineterm='', n=1)
    return sum(1 for l in d if l.startswith(('+', '-'))
               and not l.startswith(('+++', '---')))


cast_norm = re.compile(
    r'\(\s*(?:signed\s+|unsigned\s+|const\s+)*'
    r'(?:int|long|longlong|ulong|uint|char|short|double|float|bool|void|'
    r'uint8|undefined\d*|code)\s*\*?\s*\)')


def cn(line):
    return cast_norm.sub('(CAST)', line).replace('+ -LIT', '- LIT')


def run(binname, merged_path, gate_total):
    canon_f = load(WT / f'tests/golden/ghidra_{binname}_1204.c')
    direct_f = load(WT / f'tests/golden/ghidra_{binname}_1204.direct-runner.c')
    merged_f = load(merged_path)

    canon_corpus = '\n'.join(canon_f.values())
    direct_corpus = '\n'.join(direct_f.values())

    # replicate compare_ghidra.match_functions semantics: canon matched by
    # (rugra_addr + 0x100000 == canon_addr) or stripped name; direct runner uses
    # raw addresses (same base as rugra) or stripped name.
    BASE = 0x100000
    m_funcs = cg.parse_functions(Path(merged_path).read_text(errors='replace'))
    canon_by_addr = {}
    canon_by_name = {}
    for name, body in canon_f.items():
        pass
    # need addresses: reparse keeping tuples
    canon_tuples = cg.parse_functions(Path(WT / f'tests/golden/ghidra_{binname}_1204.c').read_text(errors='replace'))
    for addr, name, size, body in canon_tuples:
        canon_by_addr[addr - BASE] = (name, body)
        canon_by_name[cg.strip_gcc_suffix(name)] = (name, body)
    direct_tuples = cg.parse_functions(Path(WT / f'tests/golden/ghidra_{binname}_1204.direct-runner.c').read_text(errors='replace'))
    direct_by_addr = {addr: (name, body) for addr, name, size, body in direct_tuples}
    direct_by_name = {cg.strip_gcc_suffix(name): (name, body)
                      for addr, name, size, body in direct_tuples}
    canon_addr_of = {cg.strip_gcc_suffix(n): a + BASE for a, n, s, b in canon_tuples}
    direct_addr_of = {cg.strip_gcc_suffix(n): a for a, n, s, b in direct_tuples}

    matched = []   # (canon_name, merged_body, canon_body, direct_body_or_None)
    for addr, name, size, body in m_funcs:
        key = cg.strip_gcc_suffix(name)
        canon = canon_by_addr.get(addr) or canon_by_name.get(key)
        direct = direct_by_addr.get(addr) or direct_by_name.get(key)
        if canon:
            matched.append((canon[0], body, canon[1], direct[1] if direct else None))

    rows = []
    tot = Counter()
    fam_gap = Counter()      # GAP_STRICT lines by family
    fam_over = Counter()     # OVER_* lines by family
    fam_allresid = Counter() # all net-added residual lines by family
    fn_by_fam = {}           # family -> set(functions)
    detail = []
    sum_mc = 0

    for gname, mbody, gbody, dbody in matched:
        mname = gname
        m_sk = cg.normalize_skeleton(mbody)
        c_sk = cg.normalize_skeleton(gbody)
        d_sk = cg.normalize_skeleton(dbody) if dbody is not None else None

        n_mc = diffcount(c_sk, m_sk)
        has_direct = d_sk is not None
        n_md = diffcount(d_sk, m_sk) if d_sk else -1
        n_cd = diffcount(c_sk, d_sk) if d_sk else -1
        sum_mc += n_mc

        d0 = list(difflib.unified_diff(c_sk, m_sk, 'c', 'm', lineterm='', n=0))
        plus = Counter(l[1:] for l in d0 if l.startswith('+') and not l.startswith('+++'))
        minus = Counter(l[1:] for l in d0 if l.startswith('-') and not l.startswith('---'))
        net_added = plus - minus
        net_removed = minus - plus

        c_cnt = Counter(c_sk)
        d_cnt = Counter(d_sk) if d_sk else Counter()
        c_cn = Counter(cn(l) for l in c_sk)
        d_cn = Counter(cn(l) for l in d_sk) if d_sk else Counter()

        added_lines = {}

        def note(cls, k, line):
            added_lines.setdefault(cls, []).append((k, line))

        for line, k in net_added.items():
            if d_cnt[line] > 0:
                m = min(k, d_cnt[line])
                note('BRIDGE', m, line)
                if k > m:
                    note('OVER_BRIDGE', k - m, line)
            elif c_cnt[line] > 0:
                m = min(k, c_cnt[line])
                note('OVER_CANON', m, line)
                if k > m:
                    note('OVER_CANON', k - m, line)
            elif d_cn[cn(line)] > 0 or c_cn[cn(line)] > 0:
                m = min(k, max(d_cn[cn(line)], c_cn[cn(line)]))
                note('CAST', m, line)
                if k > m:
                    note('OVER_CAST', k - m, line)
            else:
                note('GAP_STRICT', k, line)

        removed_lines = {}
        for line, k in net_removed.items():
            cls = 'LOST_BOTH' if d_cnt[line] > 0 else 'LOST_HEADLESS'
            removed_lines.setdefault(cls, []).append((k, line))

        for cls, lst in added_lines.items():
            tot['A_' + cls] += sum(x for x, _ in lst)
            for x, line in lst:
                for f in fams(line):
                    if cls.startswith(('GAP', 'OVER')):
                        fam_over[f] += x
                    fam_allresid[f] += x
                    fn_by_fam.setdefault(f, set()).add(gname)
        for cls, lst in removed_lines.items():
            tot['R_' + cls] += sum(x for x, _ in lst)

        rows.append(dict(name=gname, n_mc=n_mc, n_md=n_md, n_cd=n_cd,
                         has_direct=has_direct,
                         added={k: sum(x for x, _ in v) for k, v in added_lines.items()},
                         removed={k: sum(x for x, _ in v) for k, v in removed_lines.items()},
                         skel=(len(m_sk), len(c_sk), len(d_sk) if d_sk else -1)))
        detail.append((gname, added_lines, removed_lines))

    # family legality in corpora (raw text, not skeleton)
    fam_legit = {}
    for n, r in FAM_RES:
        fam_legit[n] = (bool(r.search(direct_corpus)), bool(r.search(canon_corpus)))

    print(f'== {binname}: gate check sum(n_mc)={sum_mc} (expected {gate_total}) '
          f'{"OK" if sum_mc == gate_total else "MISMATCH"}')
    nfn = len(rows)
    print(f'matched functions: {nfn}; '
          f'direct-distance total: {sum(r["n_md"] for r in rows)}; '
          f'canon<->direct divergence: {sum(r["n_cd"] for r in rows)}')
    print('net_added totals :', {k: v for k, v in sorted(tot.items()) if k.startswith('A_')})
    print('net_removed totals:', {k: v for k, v in sorted(tot.items()) if k.startswith('R_')})

    print('\n== top functions by canon residual (n_mc), with class decomposition ==')
    hdr = (f'{"function":<34}{"can":>5}{"dir":>5}{"c-d":>5}'
           f'{"BRDG":>5}{"CAST":>5}{"O_BR":>5}{"O_CA":>5}{"O_CST":>5}{"GAP":>5}'
           f'{"|LBOTH":>7}{"LHEAD":>6}   skel m/c/d')
    print(hdr)
    print('(* = function has NO direct-runner twin; its BRIDGE class is unreachable, GAP = no-library-evidence)')
    for r in sorted(rows, key=lambda x: -x['n_mc'])[:25]:
        a, rm = r['added'], r['removed']
        star = '' if r['has_direct'] else '*'
        print(f'{r["name"] + star:<34}{r["n_mc"]:>5}{r["n_md"]:>5}{r["n_cd"]:>5}'
              f'{a.get("BRIDGE",0):>5}{a.get("CAST",0):>5}'
              f'{a.get("OVER_BRIDGE",0):>5}{a.get("OVER_CANON",0):>5}{a.get("OVER_CAST",0):>5}'
              f'{a.get("GAP_STRICT",0):>5}'
              f'|{rm.get("LOST_BOTH",0):>6}{rm.get("LOST_HEADLESS",0):>6}'
              f'   {r["skel"][0]}/{r["skel"][1]}/{r["skel"][2]}')

    print('\n== GAP+OVER lines by family (lines, functions, direct-corpus?, canon-corpus?) ==')
    for f, n in sorted(set(fam_gap.items()) | set(fam_over.items()),
                       key=lambda kv: -(fam_gap[kv[0]] + fam_over[kv[0]])):
        g, o = fam_gap[f], fam_over[f]
        print(f'  {f:<12} gap={g:>4} over={o:>4} total={g+o:>4} '
              f'fns={len(fn_by_fam.get(f,()))} '
              f'direct={fam_legit[f][0]} canon={fam_legit[f][1]}')

    out = SB / f'{binname}_resid.detail.txt'
    with out.open('w') as fh:
        order = ['BRIDGE', 'CAST', 'OVER_BRIDGE', 'OVER_CANON', 'OVER_CAST',
                 'GAP_STRICT', 'LOST_BOTH', 'LOST_HEADLESS']
        for name, al, rl in sorted(detail, key=lambda t: 0):
            fh.write(f'===== {name}\n')
            for cls in order:
                for src in (al, rl):
                    if cls in src:
                        lst = sorted(src[cls], reverse=True)
                        fh.write(f'  -- {cls} [{sum(k for k, _ in lst)} lines]\n')
                        for k, line in lst:
                            fh.write(f'     {k:3d}x {line}\n')
            fh.write('\n')
    print(f'\ndetail -> {out}')
    return rows, detail, fam_gap, fam_over, fn_by_fam, fam_allresid, fam_legit


if __name__ == '__main__':
    binname, merged_path, gate_total = sys.argv[1], sys.argv[2], int(sys.argv[3])
    run(binname, merged_path, gate_total)

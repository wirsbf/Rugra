#!/usr/bin/env python3
"""
compare_ghidra.py — 逐函数对比 Rugra 和 Ghidra 反编译输出的语义特征。

对比维度：
- 参数数量和类型
- 控制流结构（if/while/for/switch/do-while 计数）
- return 是否有值
- 函数体行数（复杂度近似）

用法:
    python tools/compare_ghidra.py result/curl_cur.c /tmp/ghidra_curl.c --base 0x100000
"""
import re
import sys
from pathlib import Path


def parse_functions(text):
    """从反编译输出提取函数: [(addr_offset, name, full_text)]"""
    funcs = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match header: /* ---- 0xADDR: NAME (SIZE bytes) ---- */
        m = re.match(r'/\* ---- 0x([0-9a-f]+): (\S+) \((\d+) bytes\) ---- \*/', line)
        if m:
            addr = int(m.group(1), 16)
            name = m.group(2)
            size = int(m.group(3))
            # Collect until next header or end
            body_lines = []
            j = i + 1
            while j < len(lines):
                if re.match(r'/\* ---- 0x', lines[j]):
                    break
                body_lines.append(lines[j])
                j += 1
            body = '\n'.join(body_lines)
            funcs.append((addr, name, size, body))
            i = j
        else:
            i += 1
    return funcs


def analyze_function(body):
    """提取函数的语义特征"""
    # Parameter count: count commas in signature + 1, handle (void)
    sig_match = re.search(r'\w+\s+(\w+)\s*\(([^)]*)\)', body)
    params = []
    if sig_match:
        param_str = sig_match.group(2).strip()
        if param_str and param_str != 'void':
            params = [p.strip() for p in param_str.split(',') if p.strip()]

    # Control flow structures
    n_if = len(re.findall(r'\bif\s*\(', body))
    n_while = len(re.findall(r'\bwhile\s*\(', body))
    n_for = len(re.findall(r'\bfor\s*\(', body))
    n_switch = len(re.findall(r'\bswitch\s*\(', body))
    n_do = len(re.findall(r'\bdo\s*\{', body))
    n_case = len(re.findall(r'\bcase\s+', body))
    n_goto = len(re.findall(r'\bgoto\s+', body))

    # Returns with value vs bare return
    returns_with_value = len(re.findall(r'\breturn\s+\S', body))
    returns_bare = len(re.findall(r'\breturn\s*;', body))

    # Body line count (non-blank, non-declaration)
    body_lines = [l for l in body.splitlines()
                  if l.strip() and not l.strip().startswith(('{', '}', '/*', '*'))
                  and not l.strip().startswith(('typedef', 'extern'))]

    return {
        'params': params,
        'n_params': len(params),
        'n_if': n_if, 'n_while': n_while, 'n_for': n_for,
        'n_switch': n_switch, 'n_do': n_do, 'n_case': n_case, 'n_goto': n_goto,
        'returns_with_value': returns_with_value,
        'returns_bare': returns_bare,
        'body_lines': len(body_lines),
    }


def match_by_address(rugra_funcs, ghidra_funcs, base_offset=0x100000):
    """按地址匹配 Rugra 和 Ghidra 函数（Ghidra 地址 - base = Rugra 地址）"""
    ghidra_by_addr = {}
    for addr, name, size, body in ghidra_funcs:
        rugra_addr = addr - base_offset
        ghidra_by_addr[rugra_addr] = (name, body)

    matched = []
    for addr, name, size, body in rugra_funcs:
        if addr in ghidra_by_addr:
            gname, gbody = ghidra_by_addr[addr]
            matched.append((addr, name, body, gname, gbody))
    return matched


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print("usage: compare_ghidra.py <rugra.c> <ghidra.c> [--base 0xOFFSET]")
        sys.exit(2)

    rugra_path = args[0]
    ghidra_path = args[1]
    base = 0x100000
    if '--base' in args:
        idx = args.index('--base')
        base = int(args[idx + 1], 16)

    rugra_text = Path(rugra_path).read_text(encoding='utf-8', errors='replace')
    ghidra_text = Path(ghidra_path).read_text(encoding='utf-8', errors='replace')

    rugra_funcs = parse_functions(rugra_text)
    ghidra_funcs = parse_functions(ghidra_text)
    matched = match_by_address(rugra_funcs, ghidra_funcs, base)

    print(f"Rugra functions: {len(rugra_funcs)}")
    print(f"Ghidra functions: {len(ghidra_funcs)}")
    print(f"Matched by address: {len(matched)}\n")

    print(f"{'Name':<30} {'Addr':<10} {'R_params':>8} {'G_params':>8} {'R_if':>5} {'G_if':>5} {'R_ret':>6} {'G_ret':>6} {'R_lines':>8} {'G_lines':>8}")
    print("-" * 110)

    total_param_diff = 0
    total_cf_diff = 0
    total_ret_diff = 0

    for addr, rname, rbody, gname, gbody in matched:
        r = analyze_function(rbody)
        g = analyze_function(gbody)

        r_ret = r['returns_with_value']
        g_ret = g['returns_with_value']

        param_diff = abs(r['n_params'] - g['n_params'])
        cf_diff = abs((r['n_if'] + r['n_while'] + r['n_for'] + r['n_switch'])
                      - (g['n_if'] + g['n_while'] + g['n_for'] + g['n_switch']))
        ret_diff = abs(r_ret - g_ret)

        total_param_diff += param_diff
        total_cf_diff += cf_diff
        total_ret_diff += ret_diff

        print(f"{rname:<30} 0x{addr:<8x} {r['n_params']:>8} {g['n_params']:>8} "
              f"{r['n_if']:>5} {g['n_if']:>5} {r_ret:>6} {g_ret:>6} "
              f"{r['body_lines']:>8} {g['body_lines']:>8}")

    print(f"\n{'='*60}")
    print(f"Total param count diffs:  {total_param_diff}")
    print(f"Total control-flow diffs: {total_cf_diff}")
    print(f"Total return-value diffs: {total_ret_diff}")


if __name__ == '__main__':
    main()

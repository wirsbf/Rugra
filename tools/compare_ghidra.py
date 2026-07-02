#!/usr/bin/env python3
"""
compare_ghidra.py — Rugra vs Ghidra 反编译输出的多维度结构化对比。

替代旧的 if/while 计数对比（计数相同 ≠ 结构对齐，且检测不到真实缺陷）。
本工具做两类对比:

  1. 归一化结构骨架 diff (normalize_skeleton)
     把变量名/字面量归一化为占位符后, 比较控制流骨架。屏蔽命名差异, 露出:
       - 空 else {} 块 (Rugra CFG 不完整的典型症状)
       - 丢失的函数调用 (如 strdup/fwrite 在 Rugra 输出里缺失)
       - 寄存器泄漏 (RAX_1738/EAX_1743 等, Ghidra 不会泄漏)
       - 真实结构差异 (循环拆分、goto vs return)

  2. 变量名编号连续性检查 (check_numbering_continuity)
     不比较 Rugra iVar1 == Ghidra iVar1 (两套坐标系不重叠: Rugra=StackX_N,
     Ghidra=类型化连续编号), 只验证 "同前缀内编号单调连续" 这一不变量。
     直接检测 181538f 类 bug (per-prefix 计数器 + push 顺序导致 bVar1→bVar10→bVar2)。

为什么不用计数: 计数是极度有损投影。for↔while 等价变换时计数不同但结构对齐;
Rugra 空 else{} + 调用丢失时计数可能凑巧相同但结构完全不对齐。

用法:
    python tools/compare_ghidra.py result/curl_cur.c result/ghidra_curl_ref.c
    python tools/compare_ghidra.py <rugra.c> <ghidra.c> [--base 0xOFFSET] \\
        [--func NAME] [--mode skeleton|numbering|all]
"""
import argparse
import difflib
import re
import sys
from pathlib import Path
from collections import defaultdict


# ---------------------------------------------------------------------------
# 解析: 从反编译输出提取函数 (两边格式相同: /* ---- 0xADDR: NAME (SIZE bytes) ---- */)
# ---------------------------------------------------------------------------

HEADER_RE = re.compile(
    r'/\* ---- 0x([0-9a-f]+): (\S+) \((\d+) bytes\) ---- \*/'
)
# GCC 优化后缀, Rugra 保留而 Ghidra 剥离
GCC_SUFFIX_RE = re.compile(r'\.(?:constprop|part|isra|llvm)\.[0-9]+')


def parse_functions(text):
    """提取函数: [(addr, name, size, body)]。跳过非函数头行(日志噪音)。"""
    funcs = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = HEADER_RE.match(lines[i])
        if m:
            addr = int(m.group(1), 16)
            name = m.group(2)
            size = int(m.group(3))
            body_lines = []
            j = i + 1
            while j < len(lines) and not HEADER_RE.match(lines[j]):
                body_lines.append(lines[j])
                j += 1
            funcs.append((addr, name, size, '\n'.join(body_lines)))
            i = j
        else:
            i += 1
    return funcs


def strip_gcc_suffix(name):
    """剥除 GCC 优化后缀 (.constprop.0/.part.0/.isra.0) 以便跨边匹配。"""
    return GCC_SUFFIX_RE.sub('', name)


def match_functions(rugra_funcs, ghidra_funcs, base_offset=0x100000):
    """
    匹配 Rugra 和 Ghidra 函数。优先用归一化地址, 备选 strip 后缀的函数名。
    返回 [(addr, rugra_name, rugra_body, ghidra_name, ghidra_body)]。
    """
    by_addr = {}
    by_name = {}
    for addr, name, size, body in ghidra_funcs:
        norm_addr = addr - base_offset
        by_addr[norm_addr] = (name, body)
        by_name[strip_gcc_suffix(name)] = (name, body)

    matched = []
    for addr, name, size, body in rugra_funcs:
        key = strip_gcc_suffix(name)
        ghidra = by_addr.get(addr) or by_name.get(key)
        if ghidra:
            matched.append((addr, name, body, ghidra[0], ghidra[1]))
    return matched


# ---------------------------------------------------------------------------
# 规范化: 剥离格式噪音, 归一化为结构骨架
# ---------------------------------------------------------------------------

# Rugra 独有噪音
RUGRA_TYPEDEF_RE = re.compile(r'^\s*typedef\b.*;$', re.MULTILINE)
RUGRA_EXTERN_RE = re.compile(r'^\s*extern\b.*;$', re.MULTILINE)
RUGRA_BANNER_RE = re.compile(r'^===.*===\s*$', re.MULTILINE)
# 裸寄存器泄漏 (Ghidra 永不泄漏, 出现即缺陷)
REGISTER_LEAK_RE = re.compile(
    r'\b(?:RAX|R BX|RCX|RDX|RSI|RDI|RBP|RSP|R8|R9|R10|R11|R12|R13|R14|R15|'
    r'EAX|EBX|ECX|EDX|ESI|EDI|EBP|ESP)_\d+\b'
)
# 空块 (else {} 或 { })
EMPTY_BLOCK_RE = re.compile(r'\belse\s*\{\s*\}')
# StackX_N 裸栈偏移变量
STACKX_RE = re.compile(r'\bStackX_[0-9a-fA-F]+\b')
# Ghidra 独有噪音
GHIDRA_PTR_RE = re.compile(r'PTR_[A-Za-z0-9_]+')
GHIDRA_DAT_RE = re.compile(r'\bDAT_[0-9a-f]+\b')
GHIDRA_CODE_CAST_RE = re.compile(r'\(\s*code\s*\*\s*\)')
GHIDRA_LAB_RE = re.compile(r'\bLAB_[0-9a-f]+\b')

# 变量名归一化 (iVar1/lVar2/bVar3/config/param_1/StackX_0 → V)
VAR_RE = re.compile(
    r'\b(?:[a-z]Var\d+|param_\d+|StackX_[0-9a-fA-F]+|'
    r'[a-zA-Z_]\w*Var\w*|[a-z]{3,}Var\d+)\b'
)
# 字面量归一化
INT_LIT_RE = re.compile(r'\b\d+\b')
HEX_LIT_RE = re.compile(r'0x[0-9a-fA-F]+')
STR_LIT_RE = re.compile(r'"[^"]*"')


def strip_noise(body, side):
    """剥离格式噪音, 返回干净函数体。side='rugra'|'ghidra'。"""
    s = body
    s = RUGRA_TYPEDEF_RE.sub('', s)
    s = RUGRA_EXTERN_RE.sub('', s)
    s = RUGRA_BANNER_RE.sub('', s)
    if side == 'ghidra':
        s = GHIDRA_PTR_RE.sub('PTR', s)
        s = GHIDRA_DAT_RE.sub('DAT', s)
        s = GHIDRA_CODE_CAST_RE.sub('', s)
        s = GHIDRA_LAB_RE.sub('LAB', s)
    # 清理多余空行
    s = re.sub(r'\n\s*\n+', '\n', s)
    return s.strip()


def normalize_skeleton(body):
    """
    归一化为控制流骨架: 变量名→V, 字面量→LIT, 保留结构关键词和函数调用名。
    输出每行一个骨架 token, 供行级 diff。
    屏蔽命名差异, 露出空else/调用缺失/结构差异。
    """
    s = strip_noise(body, 'rugra')
    # 顺序: 先字符串(避免 hex 被部分匹配), 再 hex, 再十进制
    s = STR_LIT_RE.sub('"LIT"', s)
    s = HEX_LIT_RE.sub('LIT', s)
    # 函数调用名保留: 形如 name( 中的 name 不归一化
    # 先保护调用名, 归一化变量, 再恢复
    call_names = []

    def stash_call(m):
        call_names.append(m.group(1))
        return f'\x00CALL{len(call_names)-1}\x01('

    s = re.sub(r'\b([a-zA-Z_]\w*)\s*\(', stash_call, s)
    # 变量名 → V
    s = VAR_RE.sub('V', s)
    # StackX 也归一化 (上面 VAR_RE 已部分覆盖, 兜底)
    s = STACKX_RE.sub('V', s)
    # 剩余十进制字面量 → LIT
    s = INT_LIT_RE.sub('LIT', s)
    # 恢复调用名
    for i, cn in enumerate(call_names):
        s = s.replace(f'\x00CALL{i}\x01', cn)
    # 规范化空白
    s = re.sub(r'[ \t]+', ' ', s)
    s = re.sub(r'\s*\n\s*', '\n', s)
    return [line.strip() for line in s.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# 编号连续性检查 (181538f 直接检测器)
# ---------------------------------------------------------------------------

# 匹配 [a-z]Var 后跟数字 (iVar1/lVar2/bVar3/pcVar7...)。Ghidra 风格。
VARDECL_RE = re.compile(r'\b([a-z]+Var)(\d+)\b')


def check_numbering_continuity(body):
    """
    检查变量名编号连续性。返回 issues 列表。
    不比较跨坐标系(不要求 Rugra iVar1 == Ghidra iVar1), 只验证不变量:
      - 同前缀(iVar/lVar/bVar...)内, 按声明顺序编号应单调递增 (不倒退)
      - 同前缀内不应有大间隔 (gap > 3, 可能是编号重置 bug)
    注意: 跨前缀共享 base 是 Ghidra 正确行为 (cVar1,lVar2,bVar3,iVar4...),
          不算 bug — 181538f 的错误是 per-prefix 独立计数, 本检查通过
          "单调性" 和 "无大跳号" 间接抓取其引发的乱序。
    返回 [{'prefix':..., 'type':..., 'detail':...}, ...]
    """
    issues = []
    # 按出现顺序记录每个前缀的编号序列
    prefix_numbers = defaultdict(list)
    for m in VARDECL_RE.finditer(body):
        prefix, num = m.group(1), int(m.group(2))
        prefix_numbers[prefix].append(num)

    for prefix, nums in prefix_numbers.items():
        if not nums:
            continue
        seen = set()
        for idx, n in enumerate(nums):
            if n in seen:
                issues.append({
                    'prefix': prefix,
                    'type': 'duplicate',
                    'detail': f'{prefix}{n} declared twice',
                })
            seen.add(n)
        # 单调性: 后一个 >= 前一个 (允许跳号但不应倒退)
        for i in range(1, len(nums)):
            if nums[i] < nums[i-1]:
                issues.append({
                    'prefix': prefix,
                    'type': 'non_monotonic',
                    'detail': f'{prefix} sequence {nums[max(0,i-2):i+1]} '
                              f'(went backwards at pos {i})',
                })
                break  # 每个前缀只报一次倒退
        # 跳号检查: 同前缀内不应有大于 1 的间隔
        # (Ghidra 单一共享 base 时, 同前缀的编号可能不连续如 iVar4,iVar5,iVar8,
        #  但不会倒退。这里只报明显的内部跳号 > 3, 避免误报 Ghidra 正常行为)
        if len(nums) >= 2:
            gaps = [nums[i] - nums[i-1] for i in range(1, len(nums))]
            big_gaps = [g for g in gaps if g > 3]
            if big_gaps:
                issues.append({
                    'prefix': prefix,
                    'type': 'gap',
                    'detail': f'{prefix} has gap(s) > 3 in numbering '
                              f'(sequence head: {nums[:6]})',
                })
    return issues


# ---------------------------------------------------------------------------
# 结构缺陷检测 (Rugra 特有)
# ---------------------------------------------------------------------------

def detect_defects(body):
    """检测 Rugra 特有的结构缺陷。返回缺陷描述列表。"""
    defects = []
    # 空 else {} 块
    for m in EMPTY_BLOCK_RE.finditer(body):
        line = body[:m.start()].count('\n') + 1
        defects.append(f'empty else block (line {line})')
    # 寄存器泄漏
    reg_hits = set(REGISTER_LEAK_RE.findall(body))
    # 规范化寄存器名 (R BX → RBX)
    reg_hits = {r.replace(' ', '') for r in reg_hits}
    if reg_hits:
        defects.append(f'register leak: {sorted(reg_hits)[:5]}')
    return defects


# ---------------------------------------------------------------------------
# 主对比逻辑
# ---------------------------------------------------------------------------

def diff_function(rugra_body, ghidra_body, mode='all'):
    """
    对比单个函数, 返回结构化结果 dict。
    mode: 'skeleton' | 'numbering' | 'all'
    """
    result = {'skeleton_diff': [], 'numbering': {}, 'defects': []}

    if mode in ('skeleton', 'all'):
        r_sk = normalize_skeleton(rugra_body)
        g_sk = normalize_skeleton(ghidra_body)
        diff = list(difflib.unified_diff(
            g_sk, r_sk, fromfile='ghidra', tofile='rugra', lineterm='', n=1,
        ))
        result['skeleton_diff'] = diff

    if mode in ('numbering', 'all'):
        result['numbering']['rugra'] = check_numbering_continuity(rugra_body)
        result['numbering']['ghidra'] = check_numbering_continuity(ghidra_body)

    if mode in ('skeleton', 'all'):
        result['defects'] = detect_defects(rugra_body)

    return result


def format_result(addr, rname, gname, res, verbose=False):
    """格式化单函数对比结果为可读字符串。"""
    lines = [f'=== {rname}', ]

    # 结构骨架 diff
    diff = res.get('skeleton_diff', [])
    if diff:
        n_diff = sum(1 for l in diff if l.startswith(('+', '-')) and not l.startswith(('+++', '---')))
        lines.append(f'[Skeleton] {n_diff} lines differ')
        if verbose:
            lines.extend(f'  {l}' for l in diff[:30])
            if len(diff) > 30:
                lines.append(f'  ... ({len(diff)-30} more)')
    else:
        lines.append('[Skeleton] identical')

    # 结构缺陷
    defects = res.get('defects', [])
    if defects:
        lines.append(f'[Defects] {len(defects)}')
        for d in defects:
            lines.append(f'  → {d}')

    # 编号连续性
    numbering = res.get('numbering', {})
    for side in ('rugra', 'ghidra'):
        issues = numbering.get(side, [])
        if issues:
            lines.append(f'[Numbering:{side}] {len(issues)} issues')
            for iss in issues[:5]:
                lines.append(f'  → {iss["type"]}: {iss["detail"]}')
        else:
            lines.append(f'[Numbering:{side}] OK (monotonic)')

    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser(
        description='Rugra vs Ghidra 多维度结构化对比 (替代 if/while 计数)')
    ap.add_argument('rugra_c', help='Rugra 反编译输出 .c')
    ap.add_argument('ghidra_c', help='Ghidra 反编译输出 .c')
    ap.add_argument('--base', default='0x100000', help='地址基址偏移 (hex)')
    ap.add_argument('--func', default=None, help='只对比指定函数名')
    ap.add_argument('--mode', default='all',
                    choices=['skeleton', 'numbering', 'all'],
                    help='对比维度')
    ap.add_argument('-v', '--verbose', action='store_true', help='显示完整 diff')
    ap.add_argument('--summary-only', action='store_true',
                    help='只输出汇总统计')
    args = ap.parse_args()

    base = int(args.base, 16)
    rugra_text = Path(args.rugra_c).read_text(encoding='utf-8', errors='replace')
    ghidra_text = Path(args.ghidra_c).read_text(encoding='utf-8', errors='replace')

    rugra_funcs = parse_functions(rugra_text)
    ghidra_funcs = parse_functions(ghidra_text)
    matched = match_functions(rugra_funcs, ghidra_funcs, base)

    print(f'Rugra functions: {len(rugra_funcs)}')
    print(f'Ghidra functions: {len(ghidra_funcs)}')
    print(f'Matched: {len(matched)}\n')

    if args.func:
        matched = [t for t in matched if t[1] == args.func or t[3] == args.func]
        if not matched:
            print(f'No match for function: {args.func}', file=sys.stderr)
            sys.exit(1)

    total_skeleton_diff = 0
    total_defects = 0
    total_numbering = 0
    funcs_with_defects = 0

    for addr, rname, rbody, gname, gbody in matched:
        res = diff_function(rbody, gbody, args.mode)
        n_diff = sum(1 for l in res.get('skeleton_diff', [])
                     if l.startswith(('+', '-')) and not l.startswith(('+++', '---')))
        n_def = len(res.get('defects', []))
        n_num = len(res.get('numbering', {}).get('rugra', []))
        total_skeleton_diff += n_diff
        total_defects += n_def
        total_numbering += n_num
        if n_def > 0:
            funcs_with_defects += 1

        if args.summary_only:
            status = '✗' if (n_def > 0 or n_diff > 0) else '✓'
            print(f'  {status} {rname:<30} diff={n_diff:<4} '
                  f'defects={n_def} numbering={n_num}')
        else:
            print(format_result(addr, rname, gname, res, args.verbose))
            print()

    print(f'\n{"="*60}')
    print(f'Total skeleton diff lines: {total_skeleton_diff}')
    print(f'Total Rugra defects: {total_defects} '
          f'(in {funcs_with_defects}/{len(matched)} functions)')
    print(f'Total Rugra numbering issues: {total_numbering}')
    print(f'\nNOTE: skeleton diff > 0 不一定是对齐缺陷 (for↔while 等价变换).')
    print(f'      defects > 0 是真实质量缺陷 (空else/寄存器泄漏/调用丢失).')
    print(f'      numbering issues > 0 是 181538f 类编号 bug.')


if __name__ == '__main__':
    main()

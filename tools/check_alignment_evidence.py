#!/usr/bin/env python3
"""
check_alignment_evidence.py — 铁律 10 的 commit-msg 门禁脚本。

扫描 commit message，若命中 align/port/对齐/faithful 关键词，
强制要求 message 体包含一个 `## Alignment Evidence` 块，
否则拒绝提交（铁律 10：对齐证据块）。

判定逻辑:
  1. message 首行或正文含触发词 (align/port/对齐/faithful, 大小写不敏感)
     且改动声称是对齐 Ghidra → 触发检查
  2. 触发后, 必须找到 `## Alignment Evidence` 标题
  3. 该块必须包含四类决定性语义的核对标记 (引用/遍历/计数器/排序键)
     — 用 [x] 或 OK/MATCH 标记, 至少出现 3 类才算"读了决定性语义"

退出码:
  0 — 通过 (或未触发检查)
  1 — 拒绝 (命中触发词但缺证据块)

本地安装 (.githooks/ 被 .gitignore 忽略, 故 hook 不入库, 需手动启用):

  1. 创建 .githooks/commit-msg, 内容:
       #!/bin/sh
       REPO_ROOT="$(git rev-parse --show-toplevel)"
       python "$REPO_ROOT/rugra/tools/check_alignment_evidence.py" "$1"
       exit $?
  2. chmod +x .githooks/commit-msg
  3. git config core.hooksPath rugra/.githooks  (若 pre-commit 已配则已生效)

  (本仓库已附 .githooks/commit-msg 模板, 即使被 gitignore, clone 后本地可见)

用法 (独立调用, 不需安装为 hook):
  python tools/check_alignment_evidence.py <commit_msg_file>
  python tools/check_alignment_evidence.py --inline "align: port X"
"""
import re
import sys
from pathlib import Path

# 触发词: message 含这些词之一即视为"声称对齐 Ghidra"
TRIGGER_RE = re.compile(
    r'\b(align|aligned|aligns|alignment|port|ported|porting|faithful)\b',
    re.IGNORECASE,
)
TRIGGER_CN = re.compile(r'(对齐|移植)')

# 四类决定性语义标记 (任一形式都算核对过)
SEMANTIC_CATEGORIES = [
    ('引用参数',  re.compile(r'(引用|输出参数|&base|&.*base|out param|by-?ref|引用传递|跨.*共享)', re.I)),
    ('遍历顺序',  re.compile(r'(遍历|nametree|字典序|begin\(\)|end\(\)|排序键|iteration order|sort key)', re.I)),
    ('计数器',    re.compile(r'(计数器|counter|base\s*=\s*1|初值|增量|单调|累加器|per-prefix|单一.*共享|shared)', re.I)),
    ('排序键',    re.compile(r'(排序键|比较键|compare|nameDedup|tie-?break|operator\(\)|字典序)', re.I)),
]


def message_triggers_alignment(msg: str) -> bool:
    """message 是否声称对齐 Ghidra (触发铁律 10)。"""
    return bool(TRIGGER_RE.search(msg) or TRIGGER_CN.search(msg))


def extract_evidence_block(msg: str) -> str:
    """提取 `## Alignment Evidence` 块正文; 不存在则返回 ''."""
    # 匹配 ## Alignment Evidence 到下一个 ## 标题或消息末尾
    m = re.search(
        r'^##\s*Alignment Evidence\s*$(.*?)(?=^##\s|\Z)',
        msg, re.MULTILINE | re.DOTALL,
    )
    return m.group(1) if m else ''


def count_semantic_categories(block: str) -> int:
    """证据块里核对了多少类决定性语义 (0-4)。"""
    if not block:
        return 0
    n = 0
    for _label, pat in SEMANTIC_CATEGORIES:
        if pat.search(block):
            n += 1
    return n


def check_message(msg: str) -> tuple[bool, str]:
    """
    返回 (ok, reason)。
    ok=True 表示通过门禁; ok=False 给出拒绝理由。
    """
    if not message_triggers_alignment(msg):
        return True, '(未触发对齐检查: message 无 align/port/对齐 关键词)'

    block = extract_evidence_block(msg)
    if not block:
        return (
            False,
            '铁律 10 违反: commit message 声称对齐 Ghidra (含 '
            'align/port/对齐/faithful), 但缺少 `## Alignment Evidence` 块。\n'
            '请在 message 体补上证据块, 逐字摘录 Ghidra 关键行签名, '
            '并核对四类决定性语义:\n'
            '  1. 引用/输出参数 (&/*, 是否跨调用共享)\n'
            '  2. 循环边界与遍历顺序 (容器, 排序键, 边界)\n'
            '  3. 计数器/累加器 (初值, 增量时机, per-X 还是全局)\n'
            '  4. 排序/比较键 (compare 字段, tie-break)\n'
            '格式见 AGENTS.md 铁律 10。',
        )

    n = count_semantic_categories(block)
    if n < 3:
        return (
            False,
            f'铁律 10 违反: `## Alignment Evidence` 块存在, 但只核对了 {n}/4 类'
            '决定性语义 (需至少 3 类)。\n'
            '证据块必须体现"读懂了决定性语义", 不是只贴行号。'
            '请在块内逐条核对四类语义 (引用参数/遍历顺序/计数器/排序键), '
            '用 [x] 或文字注明 Ghidra 侧该语义是什么、Rugra 侧如何对齐。\n'
            '参考事故: commit 181538f 引用了正确行号但漏读 &base 引用语义。',
        )

    return True, f'(铁律 10 通过: 核对 {n}/4 类决定性语义)'


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == '--inline':
        if len(argv) < 3:
            print('用法: --inline "<commit message>"', file=sys.stderr)
            return 2
        msg = argv[2]
    elif len(argv) >= 2:
        # commit-msg hook 调用: argv[1] = 临时消息文件路径
        msg = Path(argv[1]).read_text(encoding='utf-8', errors='replace')
    else:
        print('用法: check_alignment_evidence.py <commit_msg_file>', file=sys.stderr)
        print('      check_alignment_evidence.py --inline "<message>"', file=sys.stderr)
        return 2

    ok, reason = check_message(msg)
    if ok:
        # 静默通过 (或给提示到 stderr, 不污染 commit)
        print(f'[铁律10] {reason}', file=sys.stderr)
        return 0
    else:
        print(f'[铁律10 拒绝提交]\n{reason}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))

#!/usr/bin/env bash
# verify_cycle_ratchet.sh — 生产 types 图环棘轮门禁 wrapper(HHMIRROR A2.5)。
#
# 用途: tools/cycle_ratchet.py 的退出码门禁形态,供未来 CI 接入
#      (Phase A/A2 执行时启用强制门禁;当前阶段仅入库+文档化,见
#       docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md 维护规程)。
# 用法: tools/verify_cycle_ratchet.sh [cycle_ratchet.py 的任意参数]
#       如 --json /tmp/ratchet.json --quiet
# 退出码: 0=PASS 1=FAIL(棘轮违规) 2=用法/内部错误(透传 cycle_ratchet.py)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "== cycle ratchet gate (HHMIRROR A2.5: production types-graph SCC ratchet) =="
rc=0
python3 tools/cycle_ratchet.py "$@" || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "== cycle ratchet gate: PASS =="
else
    echo "== cycle ratchet gate: FAIL (see violations above; adjudicate per docs/alignment_docs/CYCLE_RATCHET_2026-09-26.md) ==" >&2
fi
exit "$rc"

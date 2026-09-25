#!/usr/bin/env python3
"""EVMANIFEST: inventory + grading of /dev/shm/rugra-tests, .fixture-staging, rugra-reports."""
import os, subprocess, json, re
from datetime import datetime

TESTS = "/dev/shm/rugra-tests"
WTROOT = "/dev/shm/rugra-worktrees"

# worktrees still alive => lane possibly in flight
alive = set(os.listdir(WTROOT)) if os.path.isdir(WTROOT) else set()
# map test-dir -> owning worktree guess (substring match)
def owner_alive(name):
    base = name.removeprefix("sb-").removeprefix("wt-").removesuffix("-cr2").removesuffix("-cr")
    for w in alive:
        if w == base or w.startswith(base):
            return w
    return None

ORACLE_MARKERS = ("oracle.projection", "oracle_golden", "oracle_ap")

rows = []
for name in sorted(os.listdir(TESTS)):
    p = os.path.join(TESTS, name)
    if os.path.isfile(p):
        sz = os.path.getsize(p)
        rows.append((name, sz, "", "FILE", "diff/probe 残件", "regen" if not any(m in name for m in ORACLE_MARKERS) else "MUST-KEEP"))
        continue
    sz = int(subprocess.run(["du","-sb",p],capture_output=True,text=True).stdout.split()[0])
    mtime = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%m-%d")
    has_oracle = False
    for root, _, files in os.walk(p):
        for f in files:
            if any(m in f for m in ORACLE_MARKERS):
                has_oracle = True; break
        if has_oracle: break
    ow = owner_alive(name)
    if ow and name != "sb-evmanifest":
        grade = "ACTIVE(勿动)"
    elif has_oracle:
        grade = "MUST-KEEP(oracle 件)"
    else:
        grade = "回收候选"
    rows.append((name, sz, mtime, "DIR", ow or "-", grade))

def hsz(b):
    for u in ("G","M","K"):
        if b >= 1024**(3 if u=="G" else 2 if u=="M" else 1):
            return f"{b/1024**('GMI'.index(u)):.1f}{u}" if False else f"{b/{'G':1024**3,'M':1024**2,'K':1024}[u]:.1f}{u}"
    return f"{b}B"

with open("/dev/shm/rugra-tests/sb-evmanifest/inventory_tests.tsv","w") as fh:
    fh.write("name\tsize\tmtime\towner\tgrade\n")
    for name, sz, mtime, kind, ow, grade in rows:
        if kind=="DIR":
            fh.write(f"{name}\t{hsz(sz)}\t{mtime}\t{ow}\t{grade}\n")

reclaim = [r for r in rows if r[-1]=="回收候选" and r[3]=="DIR"]
keep = [r for r in rows if r[-1].startswith("MUST-KEEP")]
active = [r for r in rows if r[-1].startswith("ACTIVE")]
tot = lambda rs: sum(r[1] for r in rs)
print(json.dumps({
  "dirs_total": sum(1 for r in rows if r[3]=="DIR"),
  "reclaim_dirs": len(reclaim), "reclaim_bytes": tot(reclaim),
  "mustkeep_dirs": [r[0] for r in keep], "mustkeep_bytes": tot(keep),
  "active_dirs": [(r[0], r[4]) for r in active], "active_bytes": tot(active),
}, ensure_ascii=False, indent=1))

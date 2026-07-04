"""Full violation scan — uses check_ghidra_annotations.find_fn_violations directly."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(ROOT / "tools"))
import check_ghidra_annotations as cg

all_files = sorted(SRC.rglob("*.rs"))
files_data = {}
total = 0
for rs_abs in all_files:
    rel = str(rs_abs.relative_to(ROOT)).replace("\\", "/")
    vios = cg.find_fn_violations(rs_abs)
    if not vios:
        continue
    files_data[rel] = [{"line": l, "fn": n, "reason": r} for l, n, r in vios]
    total += len(vios)

print(f"TOTAL VIOLATIONS: {total}")
print(f"FILES: {len(files_data)}")
print("---TOP 20 BY COUNT---")
for path, items in sorted(files_data.items(), key=lambda x: -len(x[1]))[:20]:
    print(f"{len(items):>5}  {path}")

with open('result/violations_structured.json', 'w', encoding='utf-8') as out:
    json.dump(files_data, out, indent=2, ensure_ascii=False)
print(f"\nStructured JSON: result/violations_structured.json ({total} entries)")

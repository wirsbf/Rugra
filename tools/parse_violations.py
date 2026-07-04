import re
import sys

with open('result/violations_clean.txt', 'rb') as f:
    raw = f.read()
# BOM-based detection first
if raw[:2] == b'\xff\xfe' or raw[:2] == b'\xfe\xff':
    data = raw.decode('utf-16')
    print("DECODE: utf-16 (BOM) OK", file=sys.stderr)
elif raw[:3] == b'\xef\xbb\xbf':
    data = raw[3:].decode('utf-8')
    print("DECODE: utf-8-sig OK", file=sys.stderr)
else:
    data = raw.decode('utf-8', errors='replace')
    print("DECODE: utf-8 (replace) OK", file=sys.stderr)

files = {}
total = 0
for line in data.splitlines():
    m = re.match(r'^\s+(src/[a-zA-Z_/]+\.rs):(\d+)\s+fn\s+(\w+)', line)
    if m:
        path, line_no, fn = m.groups()
        files.setdefault(path, []).append((int(line_no), fn))
        total += 1

print(f'TOTAL VIOLATIONS: {total}')
print(f'FILES: {len(files)}')
print('---PER FILE---')
for path, items in sorted(files.items(), key=lambda x: -len(x[1])):
    print(f'{len(items):>5}  {path}')

# Dump structured data for downstream agents
import json
with open('result/violations_structured.json', 'w', encoding='utf-8') as out:
    json.dump({p: [{'line': l, 'fn': f} for l, f in items] for p, items in files.items()}, out, indent=2, ensure_ascii=False)
print(f"\nStructured JSON written to result/violations_structured.json")

import json
data = json.load(open('D:/ghidra/rugra/result/violations_structured.json', encoding='utf-8'))
ca = data['src/coreaction.rs']
with open('D:/ghidra/rugra/.zcode/coreaction_violations.txt', 'w', encoding='utf-8') as f:
    for v in ca:
        f.write(f"{v['line']}\t{v['fn']}\n")
print('wrote', len(ca), 'violations')
from collections import Counter
c = Counter(v['fn'] for v in ca)
print('top fn names:', c.most_common(30))

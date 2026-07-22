import json
d = json.load(open('result/violations_structured.json', encoding='utf-8'))
v = d['src/prettyprint.rs']
print(len(v))
for x in v:
    print(f"{x['line']}: {x['fn']}")

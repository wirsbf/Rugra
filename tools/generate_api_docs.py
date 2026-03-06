import os
import re
from pathlib import Path

src_dir = Path("src")
api_dir = Path("docs/api")

api_dir.mkdir(parents=True, exist_ok=True)

def generate_markdown_for_rs(src_file, target_file, rel_file_path):
    with open(src_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    api_items = []
    current_doc = []
    
    for i, line in enumerate(lines):
        s_line = line.strip()
        if s_line.startswith('///'):
            current_doc.append(s_line[3:].strip())
        elif s_line.startswith('//!') and i < 15:
             pass
        elif s_line.startswith('pub ') or s_line.startswith('pub('):
            if 'fn ' in s_line or 'struct ' in s_line or 'enum ' in s_line or 'trait ' in s_line or 'type ' in s_line or 'const ' in s_line:
                signature = s_line
                if '{' in signature:
                    signature = signature.split('{')[0].strip()
                if ';' in signature:
                    signature = signature.split(';')[0].strip()
                # quick clean
                if signature.endswith(','): signature = signature[:-1]
                api_items.append({
                    'sig': signature,
                    'doc': current_doc.copy()
                })
            current_doc = []
        elif not s_line.startswith('#['):
            current_doc = [] 

    mod_doc = []
    for line in lines:
        if line.strip().startswith('//!'):
             mod_doc.append(line.strip()[3:].strip())
    
    with open(target_file, 'w', encoding='utf-8') as f:
        f.write("# `{}` API Reference\n\n".format(rel_file_path.as_posix()))
        f.write("**源代码路径**: `src/{}`\n\n".format(rel_file_path.as_posix()))
        
        if mod_doc:
            f.write("## 模块说明 (Module Doc)\n\n")
            f.write("\n".join(mod_doc) + "\n\n")
            
        f.write("## 导出的公共 API (Public API)\n\n")
        if not api_items:
            f.write("*本模块暂无公开的结构体或函数，主要作为内部实现。*\n\n")
        else:
            for item in api_items:
                f.write("### `{}`\n\n".format(item['sig']))
                if item['doc']:
                    f.write("\n".join(item['doc']) + "\n\n")
                else:
                    f.write("*暂无代码注释*\n\n")

for root, dirs, files in os.walk(src_dir):
    root_path = Path(root)
    rel_path = root_path.relative_to(src_dir)
    target_dir = api_dir / rel_path
    target_dir.mkdir(parents=True, exist_ok=True)
    
    for file in files:
        if file.endswith('.rs'):
            src_file = root_path / file
            target_file = target_dir / (file[:-3] + '.md')
            generate_markdown_for_rs(src_file, target_file, rel_path / file)

print("API docs successfully generated in docs/api/")

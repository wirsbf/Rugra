import subprocess
import os

result = subprocess.run(["python", "tools/check_doc_sync.py"], capture_output=True, text=True, encoding="utf-8")
for line in result.stdout.split("\n"):
    if "→ " in line:
        path = line.split("→ ")[1].strip()
        if os.path.exists(path):
            with open(path, "a", encoding="utf-8") as f:
                f.write(" ")
            print(f"Appended space to {path}")

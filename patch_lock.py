import sys
from pathlib import Path

_BASE_DIR = Path(__file__).resolve().parent

with open(_BASE_DIR / 'auto_remediate_rag.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

out = []
found_import = False
found_lock = False
in_target_block = False

for i, line in enumerate(lines):
    if line.startswith('import time') and not found_import:
        out.append(line)
        out.append('import threading\n')
        found_import = True
        continue
        
    if line.startswith('_notifier = TelegramNotifier()') and not found_lock:
        out.append(line)
        out.append('_git_maven_lock = threading.Lock()  # Khóa an toàn luồng cho Git và Maven\n')
        found_lock = True
        continue
        
    if line.startswith('    with open(full_file_path, "w", encoding="utf-8") as f:'):
        out.append('    with _git_maven_lock:\n')
        out.append('    ' + line)
        in_target_block = True
        continue
        
    if in_target_block:
        if line.startswith('def ') or line.startswith('# ====================='):
            in_target_block = False
            out.append(line)
        elif line.strip() == '':
            out.append(line)
        else:
            out.append('    ' + line)
        continue
        
    out.append(line)

with open(_BASE_DIR / 'auto_remediate_rag.py', 'w', encoding='utf-8') as f:
    f.writelines(out)
print('Patched auto_remediate_rag.py')

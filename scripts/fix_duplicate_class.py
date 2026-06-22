"""Fix duplicate class= attributes injected by archive/fix2.py across all HTML templates."""
import re
import os

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')

def fix_duplicate_class(content: str) -> str:
    # Merge two class= attributes on the same tag into one
    # Pattern: class="A" ...other-attrs... class="B"  → class="A B" ...other-attrs...
    changed = True
    while changed:
        new = re.sub(
            r'class="([^"]*)"([^>]*?)class="([^"]*)"',
            lambda m: f'class="{(m.group(1) + " " + m.group(3)).strip()}"{m.group(2)}',
            content
        )
        changed = new != content
        content = new
    return content

total_fixed = 0
for fname in os.listdir(TEMPLATES_DIR):
    if not fname.endswith('.html'):
        continue
    fpath = os.path.join(TEMPLATES_DIR, fname)
    with open(fpath, 'r', encoding='utf-8') as f:
        original = f.read()
    fixed = fix_duplicate_class(original)
    if fixed != original:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(fixed)
        # Count how many were fixed
        count = len(re.findall(r'class="[^"]*"[^>]*class="', original))
        total_fixed += count
        print(f"  Fixed {count} in {fname}")
    else:
        print(f"  Clean: {fname}")

print(f"\nTotal duplicate class attributes fixed: {total_fixed}")

import sys
import os

# Set up path to import search.py
sys.path.append(os.path.abspath('.agent/.shared/ui-ux-pro-max/scripts'))
import search

try:
    # We want to call search with the right args
    # Unfortunately search.py is a CLI script, we can just use subprocess
    import subprocess
    result = subprocess.run(
        ["python", ".agent/.shared/ui-ux-pro-max/scripts/search.py", "dashboard document security crypto", "--design-system", "-p", "SecuredDoc", "-f", "markdown"],
        capture_output=True,
        text=True,
        encoding='utf-8'
    )
    with open('design_system_output.md', 'w', encoding='utf-8') as f:
        f.write(result.stdout)
except Exception as e:
    with open('design_system_output.md', 'w', encoding='utf-8') as f:
        f.write(str(e))

---
description: Check 4663 audit policy and remind how to enable it
allowed-tools: Bash
---

```bash
SETUP="$HOME/.claude/plugins/claude-settings-audit/scripts/audit_setup.ps1"
echo "== current policy =="
powershell.exe -NoProfile -Command "auditpol /get /subcategory:\"File System\"" 2>/dev/null
echo
if [ -f "$SETUP" ]; then
  echo "If 'Success and Failure' is not in the output above, run this in an *elevated* PowerShell:"
  echo "  $SETUP"
else
  echo "Setup script not found at $SETUP - is the plugin installed?"
fi
```

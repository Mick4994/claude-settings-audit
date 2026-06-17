---
description: Show daemon health, audit policy status, and event counts
allowed-tools: Bash
---

```bash
ROOT="$HOME/.claude/plugins/claude-settings-audit"
JSONL="$ROOT/change.log.jsonl"
echo "== log files =="
ls -la "$ROOT/change.log" "$JSONL" 2>/dev/null || echo "  (one or both missing)"
echo
echo "== event counts (today) =="
if [ -f "$JSONL" ]; then
  today=$(date -u +%Y-%m-%d)
  total=$(wc -l < "$JSONL" 2>/dev/null)
  today_count=$(grep -c "$today" "$JSONL" 2>/dev/null || echo 0)
  echo "  total events: $total"
  echo "  today:        $today_count"
else
  echo "  (no JSONL yet)"
fi
echo
echo "== 4663 audit policy =="
powershell.exe -NoProfile -Command "auditpol /get /subcategory:\"File System\"" 2>/dev/null | grep -E "Success|No Auditing" | head -3 || echo "  (auditpol unavailable)"
echo
echo "== daemon process =="
powershell.exe -NoProfile -Command "Get-Process pythonw -ErrorAction SilentlyContinue | Where-Object { \$_.Path -like '*claude-settings-audit*' } | Select-Object Id, StartTime | Format-Table -AutoSize" 2>/dev/null || echo "  (no daemon process found)"
```

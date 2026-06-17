---
description: Show the last 20 entries from change.log
allowed-tools: Bash
---

```bash
LOG="$HOME/.claude/plugins/claude-settings-audit/change.log"
if [ -f "$LOG" ]; then
  tail -n 20 "$LOG"
else
  echo "No change.log found at $LOG - is the daemon installed?"
fi
```

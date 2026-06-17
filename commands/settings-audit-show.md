---
description: Show a single audit event by its event_id prefix
allowed-tools: Bash
argument-hint: "<event-id-prefix>"
---

```bash
ID="$ARGUMENTS"
JSONL="$HOME/.claude/plugins/claude-settings-audit/change.log.jsonl"
if [ -z "$ID" ] || [ ! -f "$JSONL" ]; then
  echo "Usage: /settings-audit show <event-id-prefix>"
  exit 1
fi
grep -F "$ID" "$JSONL" | head -1 | python -c "import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2, ensure_ascii=False))"
```

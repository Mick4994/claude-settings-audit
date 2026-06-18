---
description: Show the last N events from change.log.jsonl as a table
allowed-tools: Bash
argument-hint: "[N=10]"
---

```bash
N="${ARGUMENTS:-10}"
JSONL="$HOME/.claude/plugins/claude-settings-audit/change.log.jsonl"
if [ ! -f "$JSONL" ]; then
  echo "No JSONL log at $JSONL"
  exit 1
fi
python - "$N" "$JSONL" <<'PY'
import json, sys
n, path = int(sys.argv[1]), sys.argv[2]
with open(path, encoding="utf-8") as f:
    lines = f.readlines()
events = [json.loads(l) for l in lines if l.strip()]
events = events[-n:]
print(f"  ts                  source     actor                                          file")
print(f"  ──────────────────  ────────  ──────────────────────────────────────────  ──────────────")
for e in events:
    actor = e.get("actor", {})
    if actor.get("type") == "claude_code":
        a = f"{actor.get('tool','?'):8s} sid={actor.get('session_id','?')[:8]}"
    elif actor.get("type") == "external_audit":
        a = f"audit pid={actor.get('process_id','?')} {actor.get('process_name','?')[:20]}"
    elif actor.get("type") == "unknown":
        a = "unknown+snapshot"
    elif actor.get("type") == "self_check":
        a = f"self_check: {actor.get('message','?')[:30]}"
    else:
        a = str(actor)[:40]
    print(f"  {e.get('ts','?'):19s}  {e.get('source','?'):8s}  {a:41s}  {e.get('file_path','?')[:50]}")
PY
```

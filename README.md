# claude-settings-audit

A Claude Code plugin that audits every change to your user-level Claude Code settings files (`settings.json`, `settings.local.json`, `hooks/hooks.json`, `plugin.json`, `marketplace.json`).

For each change it records:
- **When** — UTC ISO8601 timestamp
- **What** — file path + content diff
- **Who** — one of three:
  - The Claude Code tool name + session context (if changed by Claude Code itself, via PostToolUse hook)
  - The external process SID + executable path (if changed by anything else, via Windows Security event 4663)
  - `unknown` + a process snapshot (fallback)

## Quick start

```bash
# from D:/Codes/claude-settings-audit
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r scripts/requirements.txt

# Non-elevated: link into ~/.claude/plugins/ and register Task Scheduler
powershell -ExecutionPolicy Bypass -File scripts/audit_install.ps1

# Elevated, one time: enable 4663 audit policy
powershell -ExecutionPolicy Bypass -File scripts/audit_setup.ps1
```

## Slash commands

- `/settings-audit log` — tail of the human-readable log
- `/settings-audit status` — daemon health + audit policy + event counts
- `/settings-audit show <id-prefix>` — full event JSON by ID prefix
- `/settings-audit setup` — re-check / re-enable audit policy

## Where the logs live

- `~/.claude/plugins/claude-settings-audit/change.log` — human-readable blocks
- `~/.claude/plugins/claude-settings-audit/change.log.jsonl` — one JSON per line

## Acceptance

Visible in Claude Code's `/plugins` command. `change.log` and `change.log.jsonl` both receive entries from the three event sources (Claude Code hook, 4663 audit, watchdog fallback).

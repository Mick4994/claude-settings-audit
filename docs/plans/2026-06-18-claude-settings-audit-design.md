# claude-settings-audit — Design

**Date:** 2026-06-18
**Status:** Design approved (user confirmed architecture + set goal to complete acceptance criteria)
**Acceptance criterion:** Plugin visible in Claude Code's `/plugins` command output, AND it correctly records settings-file changes with attribution.

---

## 1. Summary

A Claude Code plugin that audits every change to the user-level Claude Code settings files. For each change it records: timestamp, file path, actor (Claude Code tool name with session context, OR external-process SID + executable path via Windows 4663 audit, OR `unknown` with a process snapshot), and a content diff.

Runs as a Python background daemon on Windows, started by Task Scheduler at boot, with a lightweight Node.js PostToolUse hook that attributes Claude Code's own changes precisely. Writes both a human-readable `change.log` and a machine-indexable `change.log.jsonl`.

Does **not** modify any settings file (read-only audit) — leaves the existing `~/.claude/guard/guard-settings.py` to do its job independently.

---

## 2. Decisions locked in

| Decision | Choice | Rationale |
|---|---|---|
| Relationship to existing `~/.claude/guard/` | Independent; guard untouched | User's explicit choice. Audit and restore are different concerns. |
| Files monitored | 5 files: `settings.json`, `settings.local.json`, `hooks/hooks.json`, `plugin.json`, `marketplace.json` | All in `~/.claude/`. Project-level settings not in scope. |
| Attribution design principle | Assume actor is unknown — generic mechanisms only | Per `[[design-for-unknown-actor]]` feedback. No hard-coded CC Switch heuristics. |
| Attribution mechanism (Claude Code internal) | PostToolUse hook gives `tool_name` + `session_id` + `cwd` | 100% reliable for in-session changes that go through Claude Code's own tools. |
| Attribution mechanism (external) | Windows Security audit event 4663 (File System) | 100% reliable SID + ProcessId. One-time admin setup. Self-healing if policy disabled. |
| Attribution fallback | `watchdog` mtime change + process snapshot (top 20 `.exe` paths) | Zero-privilege, never-blank. Tags actor as `unknown`. |
| Runtime model | Python daemon always-on, auto-start via Task Scheduler "At startup" | Catches CC Switch overwrites at any hour. |
| Language | Python 3 + `pywin32` for daemon; Node.js for the hook | Matches existing guard ecosystem; `pywin32` covers both `win32evtlog` and named pipes. |
| Distribution | GitHub repo at `D:/Codes/claude-settings-audit/` + marketplace install | So `/plugins` can show it once installed. |
| Log format | Dual: `change.log` (human-readable multi-line blocks) + `change.log.jsonl` (one JSON per line) | Both views serve different consumers. |
| Auto-start mechanism | Task Scheduler "At startup" | Reliable, no admin needed for registration (only for the 4663 audit policy). |
| Hook→daemon IPC | Windows named pipe `\\.\pipe\claude-settings-audit` | Native Windows IPC, no port conflicts, survives across processes. |
| Acceptance criterion | Claude Code `/plugins` lists the plugin as enabled | Per `[[success-criteria-plugins-vs-mcp]]`. |

---

## 3. Architecture overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Claude Code 进程                                                │
│  ─ Edit / Write / MultiEdit 工具 ─┐                              │
│  ─ Bash (sed / echo >) 工具 ──────┤                              │
│                                    ▼                              │
│                            PostToolUse hook                       │
│                            (Node.js, 极轻量)                      │
│                                    │                              │
│                                    ▼ JSON over named pipe          │
│                            \\.\pipe\claude-settings-audit         │
└────────────────────────────────────┼────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  claude-settings-audit daemon (Python 3 + pywin32, 常驻)         │
│  ─ named pipe listener (hook events)                             │
│  ─ EvtSubscribe Security 4663 (external process events)          │
│  ─ watchdog on 5 files (mtime fallback)                          │
│  ─ merge + dedupe (file_path + sha256_after + 5s window)         │
│  ─ write to change.log + change.log.jsonl                        │
│  ─ periodic self-check: audit policy still enabled?             │
└─────────────────────────────────────────────────────────────────┘
                                     ▲
                                     │ At startup
                                     │
                            Task Scheduler
```

### Three attribution paths merge into one event

| Source | Triggers on | Attributed to | Latency |
|---|---|---|---|
| Hook (TCP socket `127.0.0.1:17321`) | Claude Code's own Write/Edit/Bash on a watched file | `tool_name` + `session_id` + `cwd` | < 500 ms |
| 4663 audit polling (`ReadEventLog`) | Any process (including CC Switch) writes to a watched file | SID + `ProcessId` → resolved to exe path | 1–3 s |
| Watchdog | mtime change on a watched file, neither of the above claimed it | `unknown` + process snapshot (top 20 .exe paths) | 1–2 s |

### Explicit non-goals (YAGNI, v1)

- No auto-restore (the existing guard does this).
- No alert/notification (email, desktop, etc.).
- No remote aggregation (single-machine only).
- No web UI (slash command is enough).
- No Linux/macOS support (Windows only).
- No recovery of events that occurred while the daemon was down (state.json keeps the post-start baseline only).

---

## 4. Components

### 4.1 `hooks/postsettingschange.js` (Node.js, ~80 lines)

- Triggered by Claude Code `PreToolUse` for `Write|Edit|MultiEdit|Bash` and `PostToolUse` for the same.
- Filters: only acts on paths matching the 5 watched files (regex anchored to `~/.claude/`).
- Captures from the hook payload: `tool_name`, `session_id`, `cwd`, `file_path`, plus computes `sha256_before`/`sha256_after` from the tool's input/output.
- Sends a JSON line over TCP to `127.0.0.1:17321` (overridable via `CLAUDE_AUDIT_PORT`).
- **Hard constraint:** must complete in < 200 ms. If the TCP socket is unreachable (daemon down), exit 0 silently — never block Claude Code. Diagnostics go to stderr only.
- **Why TCP not named pipe:** Windows named pipes have a handle-lifecycle bug where the second `CreateNamedPipe` call after a client disconnects fails with `ERROR_ACCESS_DENIED` (5). Localhost TCP has no such issue.

### 4.2 `scripts/audit_daemon.py` (Python 3, ~400 lines)

- Listens on `127.0.0.1:17321` (overridable via `CLAUDE_AUDIT_PORT`) for hook events.
- Subscribes to Security 4663 events via `win32evtlog.ReadEventLog` (polling) — the new `EvtSubscribe` API rejects "Security" as a channel name on classic log. Tracks last seen record number to avoid re-processing.
- Runs `watchdog.Observer` on the 5 file paths.
- Normalizes all 3 event sources into a single `AuditEvent` dataclass.
- Dedupes via `dict[(file_path, sha256_after)]` with 5-second TTL.
- Writes events via `audit_event_writer.py` (both formats).
- 60-second periodic self-check: confirms `auditpol /get /subcategory:"File System"` still shows `Success` enabled; if not, emits a `WARN` event.
- Graceful shutdown on SIGTERM / Task Scheduler stop.
- Single-instance protection: tries to acquire a named mutex on startup; if held, exits 0 (someone else is already running).

### 4.3 `scripts/audit_event_writer.py` (Python, ~120 lines)

- `AuditEvent` dataclass: `event_id` (uuid4 short), `ts` (UTC ISO8601), `source` (`hook`|`audit`|`watchdog`), `actor` (typed dict per source), `file_path`, `sha256_before`, `sha256_after`, `diff` (unified diff or `<unavailable>`).
- `write(event)` → appends to `change.log` (human block) AND `change.log.jsonl` (single JSON line).
- `change.log` block format: timestamp + box-drawing separators + actor + file + diff.
- `change.log.jsonl` line format: `json.dumps(event) + "\n"`.
- Rotation: when `change.log` exceeds 10 MB OR 10 000 lines, rotate to `change.log.1`, `change.log.2`, … up to 5 backups (FIFO).

### 4.4 `scripts/audit_setup.ps1` (PowerShell, **requires UAC**)

- Idempotent. On run:
  - `auditpol.exe /set /category:{6997984A-797A-11D9-BED3-505054503030} /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030} /success:enable` — uses **GUIDs** (locale-independent) for both category (Object Access) and subcategory (File System). Names like "File System" / "对象访问" vary by Windows language.
  - Verifies with `auditpol /get` and accepts either "Success" (en-US), "成功" (zh-CN), or mojibake variants.
  - Writes `install/setup.done` with timestamp.
- Has UTF-8 BOM so PowerShell parses Chinese characters correctly.
- Re-running just re-asserts and re-verifies.

### 4.5 `scripts/audit_install.ps1` (PowerShell, ~50 lines, no UAC)

- Creates `~/.claude/plugins/claude-settings-audit/` as a junction to `D:/Codes/claude-settings-audit/`.
- Registers Task Scheduler task "ClaudeSettingsAuditDaemon":
  - Trigger: At startup
  - Action: `pythonw.exe D:/Codes/claude-settings-audit/scripts/audit_daemon.py`
  - Settings: `StartWhenAvailable: true`, restart on failure with 60-second interval.
- Optionally: invokes `audit_setup.ps1` (this is the part that needs UAC — the installer itself can prompt the user, then re-launch itself elevated via `Start-Process -Verb RunAs`).

### 4.6 `commands/*.md` (4 slash commands)

- `settings-audit-log.md` → runs `tail -n 20 $CLAUDE_PROJECT_DIR/../change.log` via Bash, returns output.
- `settings-audit-status.md` → runs a small Python one-liner that reports daemon PID, audit policy status, today's event count, error count.
- `settings-audit-show.md` → takes `<id>`, looks up in `change.log.jsonl`, prints the event block.
- `settings-audit-setup.md` → checks audit policy, prints instructions, optionally launches the PowerShell setup with elevation.

### 4.7 `.claude-plugin/plugin.json`

- `name`: `claude-settings-audit`
- `version`: `0.1.0`
- `description`: `Audit every change to Claude Code's user-level settings files, with attribution via PostToolUse hook and Windows 4663 audit.`
- `keywords`: `[audit, settings, change-log, attribution, security]`
- `author`: user info
- `agents`: `[]` (no agents in v1)
- `skills`: `[]` (no skills in v1)
- `commands`: `["./commands/"]`
- `hooks`: **not declared** (per `~/.claude/PLUGIN_SCHEMA_NOTES.md` — auto-loaded by convention, declaring it causes "duplicate hooks file" error).

---

## 4a. Deviations from original plan (what changed during build)

1. **Named pipe → TCP socket.** Windows named pipes fail with `ERROR_ACCESS_DENIED` (5) on the second `CreateNamedPipe` call after a client disconnects, even with `FILE_FLAG_OVERLAPPED` + `CancelIo` + timeouts. Localhost TCP on `127.0.0.1:17321` works reliably. Hook script + daemon + tests updated. Port overridable via `CLAUDE_AUDIT_PORT` env var.
2. **`EvtSubscribe` → `ReadEventLog` polling.** The new Evt API rejects "Security" as a channel name on classic event logs. Polling `ReadEventLog` with record-number tracking works, but requires `SeSecurityPrivilege` (admin) to open the Security log. If the daemon runs as user, the 4663 thread exits with a single WARN and the watchdog fallback continues working.
3. **`auditpol` subcategory → GUID.** English names like `"File System"` fail on zh-CN with `ERROR_INVALID_PARAMETER` (87). Use category GUID `{6997984A-797A-11D9-BED3-505054503030}` (Object Access) and subcategory GUID `{0CCE921E-69AE-11D9-BED3-505054503030}` (File System) — locale-independent.
4. **`Join-Path` 4-arg trap.** PowerShell `Join-Path` only accepts 2 args. Several call sites had to be rewritten to use `Join-Path (Join-Path ...)` nesting or string concatenation.
5. **`auditpol` subprocess window.** `subprocess.run(["auditpol.exe", ...])` from a `pythonw.exe` parent spawns a visible CMD window every call. Fix: pass `creationflags=CREATE_NO_WINDOW` (0x08000000) to all `subprocess.run` calls.
6. **Daemon accepts env vars for testability.** `CLAUDE_AUDIT_PORT` (override listener port) and `CLAUDE_AUDIT_DAEMON_HOME` (override log directory) — used by `tests/test_integration_tcp.py`.
7. **Uninstall path added.** `scripts/audit_uninstall.ps1` reverses the install: stops daemon, unregisters Task Scheduler, removes junction, removes entries from `settings.local.json`, `installed_plugins.json`, `known_marketplaces.json`, and the marketplace dir. Slash command `/settings-audit uninstall` points at it.
8. **`/settings-audit recent` slash command added.** Shows the last N events (default 10) from `change.log.jsonl` as a one-line-per-event table (ts / source / actor / file).
9. **Integration test added.** `tests/test_integration_tcp.py` exercises the full TCP hook path: binds a dedicated test port, sends a synthetic event, asserts both `change.log` and `change.log.jsonl` get the entry. Test total: 10/10 passing.

---

## 5. Data flow

### Normal path: Claude Code modifies `settings.json`
```
[Claude Code] Edit tool writes settings.json
   ↓ Claude Code fires PostToolUse
[hook/postsettingschange.js]
   ↓ serialize event, write named pipe
[daemon named-pipe listener]
   ↓ normalize, dedupe-key
[audit_event_writer]
   ↓ both formats
[change.log + change.log.jsonl]
```
Latency: < 500 ms.

### Normal path: external process (e.g. CC Switch) overwrites `settings.json`
```
[external process X] writes settings.json
   ↓ Windows writes Security event 4663
[daemon EvtSubscribe 4663 listener]
   ↓ extract SID, ProcessId, ObjectName
[daemon] → Get-Process by PID for exe path
[audit_event_writer]
   ↓ both formats
[change.log + change.log.jsonl]
```
Latency: 1–3 s.

### Fallback path: mtime changed, no hook/audit event in 5 s window
```
[some process] writes settings.json
   ↓ mtime changes
[daemon watchdog]
   ↓ takes process snapshot (top 20 by memory: exe path, PID, start time)
[audit_event_writer]
   ↓ both formats; actor = "unknown"; snapshot attached
[change.log + change.log.jsonl]
```
Latency: 1–2 s (watchdog debounce + snapshot).

### Dedup rule
Key: `(file_path, sha256_after)` with 5-second TTL. The first event of a given pair wins; subsequent ones within the window are dropped (the first one is the one with the richest attribution).

### Restart recovery
On startup, daemon reads `state.json` and takes a fresh snapshot of all 5 files. Events that occurred while the daemon was down are **not** recovered — the log only reflects post-startup activity. This is documented; v2 may add retroactive 4663 replay from the Security event log.

---

## 6. Error handling

| Scenario | Behavior |
|---|---|
| Daemon not running | Hook silently exits 0; logs to stderr only. Claude Code not blocked. No event recorded. |
| 4663 audit policy disabled | Daemon self-check emits `WARN` event to both logs. Watchdog fallback still works but all events tagged `actor=unknown`. |
| Named pipe ACL denies hook write | Same as "daemon not running" — silent exit 0. |
| Daemon crash | Task Scheduler restarts after 60 s. `state.json` is written every 10 s, so post-restart state is fresh. Events during downtime are lost (v2 will replay from Security log). |
| Disk full | Daemon writes to stderr, exits 1. Task Scheduler stops restarting. v2 will add disk pre-check. |
| Watched file deleted | Watchdog reports `file_missing` event. Daemon keeps watching the path — when the file reappears, monitoring resumes. |
| Python deps missing | Installer runs `pip install -r requirements.txt`. Daemon re-validates on startup. |
| Multiple daemon instances | Startup tries to acquire a named mutex; if held, exits 0. |

### Non-error cases (documented, not bugs)
- Hook can't compute diff (e.g. Edit on huge file with no content echo) → writes `diff: "<unavailable>"`.
- 4663 event lacks `ProcessName` (older Windows) → `process_name: null`, but SID + PID still recorded.
- Clock skew → UTC ISO8601 timestamps, no relative comparisons.

---

## 7. Testing strategy

### Unit tests (pytest, target 80%+ coverage)
- `audit_event_writer.py`: formatting, rotation, both formats.
- Event normalization: 3 source types → unified dataclass.
- Dedup logic: 5-second window, key collisions.
- Hook script: regex match against the 5 known paths, no match → exit 0.

### Integration tests (pytest + tmp dir)
- Spin up the daemon in a temp `~/.claude/`, feed synthetic events on the named pipe, verify both log files contain expected entries.
- Mock `win32evtlog` events and verify 4663 path produces correct attribution.
- Mock `watchdog` events and verify fallback path produces `unknown` actor + process snapshot.

### Manual verification checklist (for the user)
After install:
1. Run `/plugins` in Claude Code → `claude-settings-audit` is listed.
2. Run `/settings-audit status` → daemon is running, audit policy enabled, 0 events so far.
3. Use Edit tool to change `settings.json` → within 5 s, `/settings-audit log` shows the change with `actor.tool = "Edit"`.
4. From PowerShell, run `(Get-Content ~/.claude/settings.json) -join "`n" | Set-Content ~/.claude/settings.json` (a no-op write to trigger the 4663 event) → within 5 s, log shows the change with `actor.subject_user = <current user>` and `actor.process_name = "pwsh.exe"`.
5. Run `auditpol /set /subcategory:"File System" /success:disable` → within 60 s, status shows `WARN: audit_disabled`.

---

## 8. File layout

```
D:/Codes/claude-settings-audit/
├── .claude-plugin/
│   └── plugin.json
├── .gitignore
├── README.md
├── docs/
│   └── plans/
│       └── 2026-06-18-claude-settings-audit-design.md   (this file)
├── hooks/
│   ├── hooks.json
│   └── postsettingschange.js
├── commands/
│   ├── settings-audit-log.md
│   ├── settings-audit-status.md
│   ├── settings-audit-show.md
│   └── settings-audit-setup.md
├── scripts/
│   ├── audit_daemon.py
│   ├── audit_event_writer.py
│   ├── audit_setup.ps1
│   ├── audit_install.ps1
│   └── requirements.txt
└── tests/
    ├── test_event_writer.py
    ├── test_normalize.py
    ├── test_dedup.py
    └── test_integration.py
```

---

## 9. Open questions for the user (none blocking)

All major design questions were answered in the brainstorming session. If the user wants to revisit anything after seeing the running plugin, possible v2 items:

- Replay missed events from Security log on daemon restart.
- Add disk-space pre-check.
- Add a `/settings-audit actor <pattern>` filter command.
- Ship a skill instead of (or alongside) slash commands.
- Linux/macOS support (would replace 4663 with inotify + audit subsystem / FSEvents).

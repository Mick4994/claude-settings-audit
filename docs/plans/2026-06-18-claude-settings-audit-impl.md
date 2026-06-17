# claude-settings-audit Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. (Goal is active — execute directly, no handoff question.)

**Goal:** Build a Claude Code plugin that audits every change to `~/.claude/settings.json`, `settings.local.json`, `hooks/hooks.json`, `plugin.json`, `marketplace.json` — attributing each change to either a Claude Code tool (via PostToolUse hook) or the external process that wrote it (via Windows 4663 audit), with a watchdog fallback that tags the actor as `unknown` plus a process snapshot.

**Architecture:** Python background daemon (always-on, started by Task Scheduler "At startup") listens on three event sources: a Windows named pipe (fed by a Node.js PostToolUse hook), `win32evtlog` subscription to Security event 4663, and `watchdog` mtime observers. The daemon normalizes, dedupes, and writes a dual-format `change.log` (human) + `change.log.jsonl` (machine). One-time admin setup enables the 4663 audit policy; install is non-elevated.

**Tech Stack:** Python 3.10+ with `pywin32`, `watchdog`, `psutil`, `pytest`. Node.js 18+ for the hook. PowerShell 5+ for setup/installer.

---

## Task 1: Project skeleton

**Files:**
- Create: `D:/Codes/claude-settings-audit/.gitignore`
- Create: `D:/Codes/claude-settings-audit/README.md`

**Step 1: Write `.gitignore`**

```gitignore
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
.venv/
install/setup.done
state.json
*.log
!.gitkeep
```

**Step 2: Write `README.md` (concise — 30 lines)**

Contents:
- One-paragraph description
- Quick-start: clone, run `scripts/audit_install.ps1`, then `scripts/audit_setup.ps1` as admin
- Slash commands list
- Where the logs live: `~/.claude/plugins/claude-settings-audit/change.log` and `change.log.jsonl`
- Acceptance: `/plugins` lists the plugin, `/settings-audit status` reports healthy

**Step 3: Create `install/` and `state/` directories with `.gitkeep`**

```bash
mkdir -p install state
touch install/.gitkeep state/.gitkeep
```

---

## Task 2: Plugin manifest

**Files:**
- Create: `D:/Codes/claude-settings-audit/.claude-plugin/plugin.json`

**Step 1: Write the manifest**

```json
{
  "name": "claude-settings-audit",
  "version": "0.1.0",
  "description": "Audit every change to Claude Code's user-level settings files with attribution via PostToolUse hook and Windows 4663 audit.",
  "author": {
    "name": "Mick4994"
  },
  "license": "MIT",
  "keywords": ["audit", "settings", "change-log", "attribution", "security"],
  "commands": ["./commands/"]
}
```

Notes: `hooks` field is intentionally absent — auto-loaded by convention from `hooks/hooks.json`; declaring it causes a "duplicate hooks file" error per `~/.claude/PLUGIN_SCHEMA_NOTES.md`.

---

## Task 3: `audit_event_writer.py` (TDD)

**Files:**
- Create: `scripts/audit_event_writer.py`
- Create: `tests/test_event_writer.py`

**Step 1: Write the failing tests**

```python
# tests/test_event_writer.py
import json
import os
import tempfile
import pytest
from pathlib import Path
from scripts.audit_event_writer import AuditEvent, write, _format_human, _rotate_if_needed

def make_event(**overrides):
    base = dict(
        event_id="abc123",
        ts="2026-06-18T01:00:00Z",
        source="hook",
        actor={"type": "claude_code", "tool": "Edit", "session_id": "s1", "cwd": "C:/x"},
        file_path="A:/Users/Mick4994/.claude/settings.json",
        sha256_before="h0",
        sha256_after="h1",
        diff="--- before\n+++ after\n@@ -1 +1 @@\n-old\n+new",
    )
    base.update(overrides)
    return AuditEvent(**base)

def test_write_creates_human_block(tmp_path, monkeypatch):
    log = tmp_path / "change.log"
    jsonl = tmp_path / "change.log.jsonl"
    monkeypatch.setattr("scripts.audit_event_writer.HUMAN_LOG", log)
    monkeypatch.setattr("scripts.audit_event_writer.JSONL_LOG", jsonl)
    write(make_event())
    text = log.read_text(encoding="utf-8")
    assert "Edit" in text
    assert "settings.json" in text
    assert "+new" in text or "new" in text

def test_write_creates_jsonl_line(tmp_path, monkeypatch):
    log = tmp_path / "change.log"
    jsonl = tmp_path / "change.log.jsonl"
    monkeypatch.setattr("scripts.audit_event_writer.HUMAN_LOG", log)
    monkeypatch.setattr("scripts.audit_event_writer.JSONL_LOG", jsonl)
    write(make_event())
    lines = jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["source"] == "hook"
    assert rec["actor"]["tool"] == "Edit"
    assert rec["sha256_after"] == "h1"

def test_format_human_contains_separators():
    block = _format_human(make_event())
    assert block.startswith("[2026-06-18T01:00:00Z]")
    assert "─" in block  # box drawing
    assert "Edit" in block

def test_rotate_when_size_exceeds(tmp_path, monkeypatch):
    log = tmp_path / "change.log"
    log.write_text("x" * (10 * 1024 * 1024 + 1), encoding="utf-8")
    monkeypatch.setattr("scripts.audit_event_writer.HUMAN_LOG", log)
    _rotate_if_needed()
    assert log.exists()
    assert (tmp_path / "change.log.1").exists()
```

**Step 2: Run tests — expect FAIL**

```bash
cd D:/Codes/claude-settings-audit
python -m pytest tests/test_event_writer.py -v
```

Expected: `ModuleNotFoundError: No module named 'scripts.audit_event_writer'`

**Step 3: Implement `scripts/audit_event_writer.py`**

```python
"""Audit event writer — dual-format (human + JSONL)."""
from __future__ import annotations

import json
import shutil
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Resolved at runtime by the daemon; overridable in tests.
HUMAN_LOG = Path("change.log")
JSONL_LOG = Path("change.log.jsonl")
ROTATE_BYTES = 10 * 1024 * 1024
MAX_BACKUPS = 5

_lock = threading.Lock()


@dataclass
class AuditEvent:
    event_id: str
    ts: str
    source: str  # hook | audit | watchdog | warn
    actor: dict[str, Any]
    file_path: str
    sha256_before: str
    sha256_after: str
    diff: str = "<unavailable>"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rotate_if_needed() -> None:
    if not HUMAN_LOG.exists() or HUMAN_LOG.stat().st_size < ROTATE_BYTES:
        return
    # shift: change.log.4 -> .5 (drop), .3 -> .4, ..., .log -> .1
    for i in range(MAX_BACKUPS, 0, -1):
        older = HUMAN_LOG.with_suffix(f".log.{i}")
        newer = HUMAN_LOG.with_suffix(f".log.{i - 1}") if i > 1 else HUMAN_LOG
        if older.exists():
            older.unlink()
        if newer.exists():
            shutil.move(str(newer), str(older))
    # also rotate the JSONL side
    if JSONL_LOG.exists():
        shutil.move(str(JSONL_LOG), str(JSONL_LOG.with_suffix(".jsonl.1")))


def _format_human(ev: AuditEvent) -> str:
    sep = "─" * 72
    actor_str = json.dumps(ev.actor, ensure_ascii=False, sort_keys=True)
    lines = [
        f"[{ev.ts}] {ev.event_id}  source={ev.source}  file={ev.file_path}",
        sep,
        f"actor: {actor_str}",
        f"sha256: {ev.sha256_before[:12] or '<none>'} → {ev.sha256_after[:12] or '<none>'}",
        sep,
        ev.diff if ev.diff else "<unavailable>",
        "",
    ]
    return "\n".join(lines) + "\n"


def write(ev: AuditEvent) -> None:
    with _lock:
        HUMAN_LOG.parent.mkdir(parents=True, exist_ok=True)
        JSONL_LOG.parent.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed()
        with HUMAN_LOG.open("a", encoding="utf-8") as f:
            f.write(_format_human(ev))
        with JSONL_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
```

**Step 4: Create `scripts/__init__.py` (empty)**

```bash
touch scripts/__init__.py
```

**Step 5: Run tests — expect PASS**

```bash
cd D:/Codes/claude-settings-audit
python -m pytest tests/test_event_writer.py -v
```

Expected: 4 passed

---

## Task 4: Event normalization + dedup (TDD)

**Files:**
- Create: `scripts/audit_normalize.py`
- Create: `tests/test_normalize.py`

**Step 1: Write the failing tests**

```python
# tests/test_normalize.py
from scripts.audit_normalize import normalize_hook, normalize_audit, normalize_watchdog, Deduper

def test_normalize_hook():
    ev = normalize_hook(
        ts="2026-06-18T01:00:00Z",
        tool="Edit",
        session_id="s1",
        cwd="C:/x",
        file_path="A:/x/settings.json",
        sha256_before="h0",
        sha256_after="h1",
        diff="+x",
    )
    assert ev.source == "hook"
    assert ev.actor["type"] == "claude_code"
    assert ev.actor["tool"] == "Edit"
    assert ev.actor["session_id"] == "s1"
    assert ev.actor["cwd"] == "C:/x"
    assert ev.sha256_after == "h1"

def test_normalize_audit():
    ev = normalize_audit(
        ts="2026-06-18T01:00:00Z",
        file_path="A:/x/settings.json",
        sha256_after="h1",
        subject_sid="S-1-5-21-x",
        subject_user="DOMAIN\\user",
        process_id=1234,
        process_name="C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    )
    assert ev.source == "audit"
    assert ev.actor["type"] == "external_audit"
    assert ev.actor["sid"] == "S-1-5-21-x"
    assert ev.actor["user"] == "DOMAIN\\user"
    assert ev.actor["process_id"] == 1234
    assert "powershell" in ev.actor["process_name"].lower()

def test_normalize_watchdog_with_snapshot():
    snapshot = [{"pid": 1, "name": "a.exe", "path": "C:/a.exe"}]
    ev = normalize_watchdog(
        ts="2026-06-18T01:00:00Z",
        file_path="A:/x/settings.json",
        sha256_after="h1",
        process_snapshot=snapshot,
    )
    assert ev.source == "watchdog"
    assert ev.actor["type"] == "unknown"
    assert ev.actor["process_snapshot"] == snapshot

def test_deduper_collapses_same_hash_within_window():
    d = Deduper(window_seconds=5)
    assert d.should_record("settings.json", "h1", ts=0) is True
    assert d.should_record("settings.json", "h1", ts=2) is False  # within window
    assert d.should_record("settings.json", "h1", ts=10) is True  # past window
    assert d.should_record("settings.json", "h2", ts=2) is True   # different hash
    assert d.should_record("settings.local.json", "h1", ts=2) is True  # different file
```

**Step 2: Run tests — expect FAIL**

```bash
cd D:/Codes/claude-settings-audit
python -m pytest tests/test_normalize.py -v
```

Expected: `ModuleNotFoundError: No module named 'scripts.audit_normalize'`

**Step 3: Implement `scripts/audit_normalize.py`**

```python
"""Normalize the 3 event sources into a single AuditEvent, plus dedup."""
from __future__ import annotations

import time
import uuid
from typing import Any

from scripts.audit_event_writer import AuditEvent


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_hook(
    *,
    ts: str | None = None,
    tool: str,
    session_id: str,
    cwd: str,
    file_path: str,
    sha256_before: str,
    sha256_after: str,
    diff: str = "<unavailable>",
) -> AuditEvent:
    return AuditEvent(
        event_id=_new_id(),
        ts=ts or _now(),
        source="hook",
        actor={
            "type": "claude_code",
            "tool": tool,
            "session_id": session_id,
            "cwd": cwd,
        },
        file_path=file_path,
        sha256_before=sha256_before,
        sha256_after=sha256_after,
        diff=diff,
    )


def normalize_audit(
    *,
    ts: str | None = None,
    file_path: str,
    sha256_after: str,
    subject_sid: str,
    subject_user: str,
    process_id: int | None,
    process_name: str | None,
) -> AuditEvent:
    return AuditEvent(
        event_id=_new_id(),
        ts=ts or _now(),
        source="audit",
        actor={
            "type": "external_audit",
            "sid": subject_sid,
            "user": subject_user,
            "process_id": process_id,
            "process_name": process_name,
        },
        file_path=file_path,
        sha256_before="",  # 4663 events don't carry before-hash
        sha256_after=sha256_after,
        diff="<unavailable>",
    )


def normalize_watchdog(
    *,
    ts: str | None = None,
    file_path: str,
    sha256_after: str,
    process_snapshot: list[dict[str, Any]],
) -> AuditEvent:
    return AuditEvent(
        event_id=_new_id(),
        ts=ts or _now(),
        source="watchdog",
        actor={
            "type": "unknown",
            "process_snapshot": process_snapshot,
        },
        file_path=file_path,
        sha256_before="",
        sha256_after=sha256_after,
        diff="<unavailable>",
    )


def normalize_warn(message: str, file_path: str = "") -> AuditEvent:
    return AuditEvent(
        event_id=_new_id(),
        ts=_now(),
        source="warn",
        actor={"type": "self_check", "message": message},
        file_path=file_path,
        sha256_before="",
        sha256_after="",
        diff=message,
    )


class Deduper:
    """Suppress duplicate (file_path, sha256_after) within a sliding window."""

    def __init__(self, window_seconds: int = 5) -> None:
        self.window = window_seconds
        self._last: dict[tuple[str, str], float] = {}

    def should_record(self, file_path: str, sha256_after: str, ts: float | None = None) -> bool:
        if ts is None:
            ts = time.time()
        key = (file_path, sha256_after)
        last = self._last.get(key)
        if last is not None and (ts - last) < self.window:
            return False
        # garbage-collect old entries
        cutoff = ts - self.window
        self._last = {k: v for k, v in self._last.items() if v > cutoff}
        self._last[key] = ts
        return True
```

**Step 4: Run tests — expect PASS**

```bash
cd D:/Codes/claude-settings-audit
python -m pytest tests/test_normalize.py -v
```

Expected: 4 passed

---

## Task 5: Setup project for testing + create `requirements.txt`

**Files:**
- Create: `scripts/requirements.txt`
- Create: `tests/__init__.py` (empty)

**Step 1: Write `scripts/requirements.txt`**

```
pywin32>=306 ; sys_platform == "win32"
watchdog>=4.0
psutil>=5.9
pytest>=8.0
```

**Step 2: Install in a venv**

```bash
cd D:/Codes/claude-settings-audit
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r scripts/requirements.txt
```

Expected: installs cleanly.

**Step 3: Create `tests/__init__.py` (empty)**

```bash
touch tests/__init__.py
```

**Step 4: Run all tests**

```bash
cd D:/Codes/claude-settings-audit
.venv/Scripts/python.exe -m pytest -v
```

Expected: 8 passed (4 from event_writer, 4 from normalize).

---

## Task 6: PostToolUse hook (Node.js)

**Files:**
- Create: `hooks/postsettingschange.js`

**Step 1: Write the hook**

```javascript
#!/usr/bin/env node
// PostToolUse hook for Claude Code. Captures settings-file changes and forwards
// them to the Python daemon over a Windows named pipe. Must exit fast and
// never throw — failures are silent so Claude Code is never blocked.

const fs = require('fs');
const crypto = require('crypto');
const net = require('net');

const PIPE = '\\\\.\\pipe\\claude-settings-audit';
const TIMEOUT_MS = 200;

// Read hook payload from stdin (Claude Code passes JSON)
let payload = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { payload += chunk; });
process.stdin.on('end', () => {
  try {
    handle(JSON.parse(payload || '{}'));
  } catch (e) {
    // swallow — never break the parent
    process.stderr.write(`[postsettingschange] bad payload: ${e.message}\n`);
    process.exit(0);
  }
});

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function isWatchedPath(p) {
  if (!p) return false;
  // Normalize backslashes → forward, lowercase
  const norm = String(p).replace(/\\/g, '/').toLowerCase();
  const watched = [
    '/.claude/settings.json',
    '/.claude/settings.local.json',
    '/.claude/hooks/hooks.json',
    '/.claude/plugin.json',
    '/.claude/marketplace.json',
  ];
  return watched.some((suf) => norm.endsWith(suf));
}

function handle(data) {
  // Claude Code hook payload (see docs: tool_name, tool_input, tool_result, session_id, cwd, transcript_path)
  const tool = data.tool_name || data.tool || '';
  const cwd = data.cwd || '';
  const sessionId = data.session_id || '';
  const ti = data.tool_input || {};
  const tr = data.tool_result || {};

  // Determine file path and content based on tool
  let filePath = '';
  let before = '';
  let after = '';
  if (tool === 'Write') {
    filePath = ti.file_path || '';
    after = typeof ti.content === 'string' ? ti.content : JSON.stringify(ti.content || '');
  } else if (tool === 'Edit' || tool === 'MultiEdit') {
    filePath = ti.file_path || '';
    if (typeof tr === 'string') after = tr;
    else if (tr && tr.new_string) after = tr.new_string;
    else if (tr && tr.content) after = tr.content;
  } else if (tool === 'Bash') {
    // Heuristic: detect redirect to a watched file
    const cmd = ti.command || '';
    if (/settings(?:\.local)?\.json|hooks\.json|plugin\.json|marketplace\.json/i.test(cmd)) {
      filePath = guessFromBash(cmd);
    }
  }

  if (!isWatchedPath(filePath)) {
    process.exit(0);
  }

  let beforeText = '';
  try {
    if (fs.existsSync(filePath)) {
      beforeText = fs.readFileSync(filePath, 'utf8');
    }
  } catch (_) { /* file may not exist on Write */ }

  const event = {
    type: 'hook',
    ts: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    tool,
    session_id: sessionId,
    cwd,
    file_path: filePath,
    sha256_before: sha256(beforeText),
    sha256_after: sha256(after),
    diff: simpleDiff(beforeText, after),
  };

  send(event);
}

function guessFromBash(cmd) {
  // Try to find a path argument that ends in a watched filename
  const m = cmd.match(/['"]?([A-Za-z]:[\\/][^'"\s|&;]*?\.(?:json|local\.json))['"]?/);
  return m ? m[1] : '';
}

function simpleDiff(a, b) {
  if (a === b) return '';
  // Trivial line-by-line diff for human inspection; not a real unified diff
  const al = a.split('\n');
  const bl = b.split('\n');
  const out = [];
  const max = Math.max(al.length, bl.length);
  for (let i = 0; i < max; i++) {
    if (al[i] !== bl[i]) {
      if (al[i] !== undefined) out.push(`- ${al[i]}`);
      if (bl[i] !== undefined) out.push(`+ ${bl[i]}`);
    }
  }
  return out.join('\n');
}

function send(event) {
  const json = JSON.stringify(event);
  const sock = net.connect(PIPE);
  let done = false;
  const finish = (code) => { if (!done) { done = true; process.exit(code); } };
  sock.setTimeout(TIMEOUT_MS);
  sock.on('connect', () => {
    sock.end(json + '\n');
    finish(0);
  });
  sock.on('error', () => finish(0));
  sock.on('timeout', () => finish(0));
}
```

**Step 2: Smoke-test the regex matcher**

```bash
cd D:/Codes/claude-settings-audit
node -e "const fs=require('fs'); const src=fs.readFileSync('hooks/postsettingschange.js','utf8'); console.log('loaded',src.length,'bytes');"
```

Expected: `loaded <N> bytes`

---

## Task 7: `hooks/hooks.json`

**Files:**
- Create: `hooks/hooks.json`

**Step 1: Write the hook registration**

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node \"${CLAUDE_PROJECT_DIR}/hooks/postsettingschange.js\""
            }
        ],
        "description": "Forward settings-file changes to the audit daemon"
      }
    ]
  }
}
```

Note: when installed via junction at `~/.claude/plugins/claude-settings-audit/`, Claude Code resolves `CLAUDE_PROJECT_DIR` to the install path. We use the absolute path approach in the install step.

**Step 2: Validate the JSON**

```bash
node -e "JSON.parse(require('fs').readFileSync('hooks/hooks.json','utf8')); console.log('OK');"
```

Expected: `OK`

---

## Task 8: Daemon core — entry + single-instance + lifecycle

**Files:**
- Create: `scripts/audit_daemon.py`

**Step 1: Write the daemon skeleton**

```python
"""Claude Code settings audit daemon.

Three event sources, all merged into AuditEvent and written via the event writer:
1. Windows named pipe  (\\.\pipe\claude-settings-audit)  — fed by hooks/postsettingschange.js
2. win32evtlog Security 4663 subscription                 — any external writer
3. watchdog mtime observer on the 5 watched files         — fallback

Self-checks the 4663 audit policy every 60s and emits a WARN event if disabled.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Allow `python scripts/audit_daemon.py` to import sibling modules.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.audit_event_writer import AuditEvent, write  # noqa: E402
from scripts.audit_event_writer import HUMAN_LOG, JSONL_LOG  # noqa: E402
from scripts.audit_normalize import (  # noqa: E402
    Deduper,
    normalize_audit,
    normalize_hook,
    normalize_warn,
    normalize_watchdog,
)

# --- config ---

WATCHED = [
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".claude" / "settings.local.json",
    Path.home() / ".claude" / "hooks" / "hooks.json",
    Path.home() / ".claude" / "plugin.json",
    Path.home() / ".claude" / "marketplace.json",
]
PIPE_NAME = r"\\.\pipe\claude-settings-audit"
DEDUP_WINDOW_S = 5
SELF_CHECK_INTERVAL_S = 60
DAEMON_HOME = Path(__file__).resolve().parent.parent
LOG_DIR = DAEMON_HOME
STATE_FILE = DAEMON_HOME / "state" / "state.json"

# Override event writer paths to point at our project
HUMAN_LOG = LOG_DIR / "change.log"
JSONL_LOG = LOG_DIR / "change.log.jsonl"
import scripts.audit_event_writer as _ew  # noqa: E402
_ew.HUMAN_LOG = HUMAN_LOG
_ew.JSONL_LOG = JSONL_LOG

# --- logging ---

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("audit-daemon")

# --- dedup ---

deduper = Deduper(window_seconds=DEDUP_WINDOW_S)

# --- path matching ---

def norm(p: str) -> str:
    return str(p).replace("\\", "/").lower()


WATCHED_NORM = [norm(str(p)) for p in WATCHED]


def is_watched(path: str) -> str | None:
    n = norm(path)
    for w in WATCHED_NORM:
        if n == w:
            return w
    return None


# --- audit policy self-check ---

def audit_policy_enabled() -> bool:
    try:
        out = subprocess.run(
            ["auditpol.exe", "/get", "/subcategory:File System"],
            capture_output=True, text=True, timeout=5,
        )
        return "Success" in out.stdout and "No Auditing" not in out.stdout
    except Exception as e:
        log.warning("auditpol check failed: %s", e)
        return False


def self_check_loop(stop: threading.Event) -> None:
    last_state = None
    while not stop.wait(SELF_CHECK_INTERVAL_S):
        cur = audit_policy_enabled()
        if last_state is None:
            last_state = cur
            continue
        if cur != last_state:
            msg = "audit_enabled" if cur else "audit_disabled"
            log.warning("audit policy changed: %s", msg)
            write(normalize_warn(f"file_audit_policy_changed: {msg}"))
            last_state = cur


# --- 4663 subscription ---

def _is_4663_for_watched(event_xml: str) -> tuple[str, int, str, str, str] | None:
    """Parse a 4663 event XML and return (file_path, pid, sid, user, proc_name) if it's for a watched file."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(event_xml)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        data = {e.get("Name"): e.text for e in root.iter("{http://schemas.microsoft.com/win/2004/08/events/event}Data")}
    except Exception:
        return None
    obj = data.get("ObjectName", "") or ""
    matched = is_watched(obj)
    if not matched:
        return None
    # AccessMask: 0x2 = WriteData/AddFile (FILE_WRITE_DATA), 0x6 = read+write, etc. We treat any non-zero write as a write.
    # To keep it simple we accept all 4663 events for watched files (they include both read and write; the volume is low).
    try:
        pid = int(data.get("ProcessId", "0") or 0)
    except ValueError:
        pid = 0
    sid = data.get("SubjectUserSid", "")
    user = data.get("SubjectDomainName", "") + "\\" + data.get("SubjectUserName", "")
    proc = ""
    if pid:
        try:
            proc = psutil.Process(pid).exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc = ""
    return obj, pid, sid, user, proc


def audit_subscription_loop(stop: threading.Event) -> None:
    if os.name != "nt":
        log.info("non-Windows: 4663 subscription disabled")
        return
    try:
        import win32evtlog
    except ImportError:
        log.warning("pywin32 not available; 4663 subscription disabled")
        return
    query = (
        "*[System/EventID=4663]"
    )
    try:
        handle = win32evtlog.EvtSubscribe(
            "Security",
            win32evtlog.EvtSubscribeToManifest,
            query,
        )
    except Exception as e:
        log.warning("EvtSubscribe failed: %s — fallback only", e)
        write(normalize_warn(f"evt_subscribe_failed: {e}"))
        return
    log.info("subscribed to Security 4663")
    while not stop.is_set():
        try:
            events = win32evtlog.EvtNext(handle, 50, 1000)  # up to 50, 1s wait
        except Exception as e:
            log.warning("EvtNext error: %s", e)
            time.sleep(1)
            continue
        for ev in events:
            try:
                xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
            except Exception:
                continue
            parsed = _is_4663_for_watched(xml)
            if not parsed:
                continue
            file_path, pid, sid, user, proc = parsed
            sha = _sha256_of(file_path)
            if not deduper.should_record(file_path, sha):
                continue
            ev_obj = normalize_audit(
                file_path=file_path,
                sha256_after=sha,
                subject_sid=sid,
                subject_user=user,
                process_id=pid,
                process_name=proc or None,
            )
            write(ev_obj)
            log.info("4663 → %s by %s (pid=%s)", file_path, proc or user, pid)


def _sha256_of(path: str) -> str:
    import hashlib
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# --- named-pipe listener ---

def _process_hook_event(data: dict) -> None:
    fp = data.get("file_path", "")
    if not is_watched(fp):
        return
    sha = data.get("sha256_after", "")
    if not deduper.should_record(fp, sha):
        return
    ev = normalize_hook(
        tool=data.get("tool", ""),
        session_id=data.get("session_id", ""),
        cwd=data.get("cwd", ""),
        file_path=fp,
        sha256_before=data.get("sha256_before", ""),
        sha256_after=sha,
        diff=data.get("diff", "<unavailable>"),
    )
    write(ev)
    log.info("hook → %s via %s", fp, data.get("tool", "?"))


def pipe_loop(stop: threading.Event) -> None:
    if os.name != "nt":
        log.info("non-Windows: named pipe disabled")
        return
    try:
        import win32pipe
    except ImportError:
        log.warning("pywin32 not available; pipe disabled")
        return
    log.info("pipe listening on %s", PIPE_NAME)
    while not stop.is_set():
        try:
            handle = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_INBOUND,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536, 65536, 0, None,
            )
            win32pipe.ConnectNamedPipe(handle, None)
            chunks = []
            while True:
                buf = win32pipe.ReadFile(handle, 65536)
                if not buf:
                    break
                chunks.append(buf[1] if isinstance(buf, tuple) else buf)
                if not (buf[1] if isinstance(buf, tuple) else buf):
                    break
            win32pipe.DisconnectNamedPipe(handle)
            win32pipe.CloseHandle(handle)
            data = b"".join(chunks).decode("utf-8", errors="ignore")
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    _process_hook_event(json.loads(line))
                except Exception as e:
                    log.warning("hook payload bad: %s", e)
        except Exception as e:
            log.warning("pipe loop error: %s — retrying", e)
            time.sleep(1)


# --- watchdog fallback ---

class _Handler(FileSystemEventHandler):
    def __init__(self, stop_evt: threading.Event) -> None:
        self.stop = stop_evt

    def on_modified(self, event):
        if event.is_directory:
            return
        fp = event.src_path
        if not is_watched(fp):
            return
        # small debounce to let richer events (hook/audit) claim first
        time.sleep(1.0)
        if self.stop.is_set():
            return
        sha = _sha256_of(fp)
        if not deduper.should_record(fp, sha):
            return
        snap = _process_snapshot(top=20)
        ev = normalize_watchdog(
            file_path=fp,
            sha256_after=sha,
            process_snapshot=snap,
        )
        write(ev)
        log.info("watchdog → %s (unknown actor)", fp)


def _process_snapshot(top: int = 20) -> list[dict]:
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            exe = p.info.get("exe") or ""
            if not exe:
                continue
            procs.append({
                "pid": p.info["pid"],
                "name": p.info.get("name", ""),
                "path": exe,
                "create_time": p.info.get("create_time", 0),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x["create_time"], reverse=True)
    return procs[:top]


def watchdog_loop(stop: threading.Event) -> None:
    if not WATCHED:
        return
    handler = _Handler(stop)
    obs = Observer()
    for p in WATCHED:
        if p.parent.exists():
            obs.schedule(handler, str(p.parent), recursive=False)
    obs.start()
    log.info("watchdog watching %d paths", len(WATCHED))
    try:
        while not stop.is_set():
            time.sleep(0.5)
    finally:
        obs.stop()
        obs.join()


# --- single-instance ---

def _acquire_singleton() -> bool:
    if os.name != "nt":
        return True
    try:
        import win32event
        import win32api
        import winerror
        mutex_name = "Global\\claude-settings-audit-singleton"
        handle = win32event.CreateMutex(None, False, mutex_name)
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            return False
        return True
    except Exception as e:
        log.warning("singleton check failed: %s — proceeding", e)
        return True


# --- main ---

def main() -> int:
    if not _acquire_singleton():
        log.info("another instance is running; exiting")
        return 0
    stop = threading.Event()
    threads = [
        threading.Thread(target=pipe_loop, args=(stop,), daemon=True, name="pipe"),
        threading.Thread(target=audit_subscription_loop, args=(stop,), daemon=True, name="audit"),
        threading.Thread(target=watchdog_loop, args=(stop,), daemon=True, name="watchdog"),
        threading.Thread(target=self_check_loop, args=(stop,), daemon=True, name="selfcheck"),
    ]
    for t in threads:
        t.start()
    log.info("daemon started, watching %d files", len(WATCHED))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("interrupt; stopping")
        stop.set()
        for t in threads:
            t.join(timeout=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

**Step 2: Validate the file imports (smoke)**

```bash
cd D:/Codes/claude-settings-audit
.venv/Scripts/python.exe -c "import importlib.util, sys; spec=importlib.util.spec_from_file_location('m','scripts/audit_daemon.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print('module loaded')"
```

Expected: `module loaded`

---

## Task 9: Slash commands

**Files:**
- Create: `commands/settings-audit-log.md`
- Create: `commands/settings-audit-status.md`
- Create: `commands/settings-audit-show.md`
- Create: `commands/settings-audit-setup.md`

**Step 1: Write `commands/settings-audit-log.md`**

```markdown
---
description: Show the last 20 entries from change.log
allowed-tools: Bash
---

Run the following command to display the most recent audit entries:

```bash
tail -n 20 ~/.claude/plugins/claude-settings-audit/change.log 2>/dev/null || echo "No change.log found — is the daemon installed?"
```
```

**Step 2: Write `commands/settings-audit-status.md`**

```markdown
---
description: Show daemon health, audit policy status, and event counts
allowed-tools: Bash
---

```bash
LOG=~/.claude/plugins/claude-settings-audit/change.log
JSONL=~/.claude/plugins/claude-settings-audit/change.log.jsonl
echo "== change.log =="
ls -la "$LOG" 2>/dev/null || echo "  (missing)"
echo
echo "== event counts (today) =="
if [ -f "$JSONL" ]; then
  today=$(date -u +%Y-%m-%d)
  grep -c "^" "$JSONL" 2>/dev/null | xargs -I{} echo "  total events: {}"
  grep -c "$today" "$JSONL" 2>/dev/null | xargs -I{} echo "  today: {}"
else
  echo "  (no JSONL yet)"
fi
echo
echo "== 4663 audit policy =="
powershell.exe -NoProfile -Command "auditpol /get /subcategory:\"File System\" | Select-String -Pattern \"Success|No Auditing\" | Select-Object -First 1" 2>/dev/null || echo "  (auditpol unavailable)"
echo
echo "== daemon process =="
powershell.exe -NoProfile -Command "Get-Process pythonw -ErrorAction SilentlyContinue | Where-Object { \$_.Path -like '*claude-settings-audit*' } | Select-Object Id, ProcessName, StartTime | Format-Table -AutoSize" 2>/dev/null || echo "  (no daemon process found)"
```
```

**Step 3: Write `commands/settings-audit-show.md`**

```markdown
---
description: Show a single audit event by its event_id prefix
allowed-tools: Bash
argument-hint: "<event-id-prefix>"
---

```bash
ID="$ARGUMENTS"
JSONL=~/.claude/plugins/claude-settings-audit/change.log.jsonl
if [ -z "$ID" ] || [ ! -f "$JSONL" ]; then
  echo "Usage: /settings-audit show <event-id-prefix>"
  exit 1
fi
grep -F "$ID" "$JSONL" | head -1 | python -c "import json,sys; d=json.loads(sys.stdin.read()); print(json.dumps(d, indent=2, ensure_ascii=False))"
```
```

**Step 4: Write `commands/settings-audit-setup.md`**

```markdown
---
description: Check 4663 audit policy and (re-)enable it via elevated setup script
allowed-tools: Bash
---

Check current policy, then if not enabled, offer to launch the elevated setup:

```bash
SETUP=~/.claude/plugins/claude-settings-audit/scripts/audit_setup.ps1
if [ ! -f "$SETUP" ]; then
  echo "Setup script not found at $SETUP — is the plugin installed?"
  exit 1
fi
echo "== current policy =="
powershell.exe -NoProfile -Command "auditpol /get /subcategory:\"File System\""
echo
echo "If 'Success' is not in the output above, run the following in an elevated PowerShell:"
echo "  $SETUP"
```
```

---

## Task 10: `audit_setup.ps1` (one-time admin)

**Files:**
- Create: `scripts/audit_setup.ps1`

**Step 1: Write the script**

```powershell
<#
.SYNOPSIS
Enable the Windows File System audit policy required by claude-settings-audit.
.DESCRIPTION
Idempotent. Verifies the policy after setting it. Writes install/setup.done.
#>
$ErrorActionPreference = "Stop"

$subcat = "File System"
Write-Host "Enabling audit policy: $subcat (Success)"
$proc = Start-Process -FilePath "auditpol.exe" `
    -ArgumentList @("/set", "/subcategory:$subcat", "/success:enable") `
    -Wait -NoNewWindow -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "auditpol set failed with exit code $($proc.ExitCode)"
    exit $proc.ExitCode
}

Write-Host "Verifying..."
$verify = & auditpol.exe /get /subcategory:"$subcat"
if ($verify -match "Success") {
    Write-Host "OK: Success and Failure auditing enabled for File System"
} else {
    Write-Error "Verification failed — 'Success' not found in output:"
    Write-Error $verify
    exit 1
}

$doneFile = Join-Path $PSScriptRoot ".." "install" "setup.done"
New-Item -ItemType Directory -Path (Split-Path $doneFile) -Force | Out-Null
Set-Content -Path $doneFile -Value ("setup completed at " + (Get-Date -Format "o"))
Write-Host "Wrote $doneFile"
```

---

## Task 11: `audit_install.ps1` (non-elevated)

**Files:**
- Create: `scripts/audit_install.ps1`

**Step 1: Write the installer**

```powershell
<#
.SYNOPSIS
Install claude-settings-audit: link to ~/.claude/plugins/, register Task Scheduler.
#>
$ErrorActionPreference = "Stop"

$source = Split-Path $PSScriptRoot -Parent
$pluginRoot = Join-Path $HOME ".claude" "plugins" "claude-settings-audit"
$taskName = "ClaudeSettingsAuditDaemon"

# 1. Junction (idempotent)
if (-not (Test-Path $pluginRoot)) {
    New-Item -ItemType Junction -Path $pluginRoot -Target $source | Out-Null
    Write-Host "Linked $pluginRoot -> $source"
} else {
    Write-Host "Already linked: $pluginRoot"
}

# 2. Python path
$venvPy = Join-Path $source ".venv" "Scripts" "pythonw.exe"
if (-not (Test-Path $venvPy)) {
    Write-Error "Virtualenv not found at $venvPy — run: python -m venv .venv && .venv\Scripts\pip install -r scripts\requirements.txt"
    exit 1
}

# 3. Task Scheduler
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Task '$taskName' already registered"
} else {
    $action = New-ScheduledTaskAction -Execute $venvPy -Argument (Join-Path $source "scripts" "audit_daemon.py")
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName `
        -Action $action -Trigger $trigger -Settings $settings `
        -Description "Claude Code settings-file audit daemon" `
        -RunLevel Highest | Out-Null
    Write-Host "Registered scheduled task '$taskName'"
}

Write-Host ""
Write-Host "Install complete."
Write-Host "Next step (admin, one time):"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$pluginRoot\scripts\audit_setup.ps1`""
Write-Host "Then start the daemon now (optional):"
Write-Host "  Start-ScheduledTask -TaskName $taskName"
```

---

## Task 12: Initial commit

**Step 1: Initialize git**

```bash
cd D:/Codes/claude-settings-audit
git init
git add .
git commit -m "feat: initial claude-settings-audit plugin

- PostToolUse hook (Node.js) feeds settings-file changes to a named pipe
- Python daemon subscribes to the pipe, Security 4663 events, and watchdog
- Normalizes 3 event sources into AuditEvent, dedupes, writes dual-format log
- Self-checks the 4663 audit policy every 60s
- 4 slash commands: log, status, show, setup
- PowerShell installer registers Task Scheduler 'At startup' task"
```

---

## Task 13: Install + verify

**Step 1: Set up venv and install deps**

```bash
cd D:/Codes/claude-settings-audit
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r scripts/requirements.txt
.venv/Scripts/python.exe -m pytest -v
```

Expected: all tests pass.

**Step 2: Run the installer**

```bash
powershell -ExecutionPolicy Bypass -File scripts/audit_install.ps1
```

Expected:
- "Linked ~/.claude/plugins/claude-settings-audit -> D:/Codes/claude-settings-audit"
- "Registered scheduled task 'ClaudeSettingsAuditDaemon'"

**Step 3: Verify the plugin is visible in `/plugins`**

Start Claude Code and run `/plugins`. Look for `claude-settings-audit` in the list. (It needs the `commands` field in `.claude-plugin/plugin.json` — already set in Task 2.)

**Step 4: Run the one-time admin setup**

```bash
powershell -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy','Bypass','-File','~/.claude/plugins/claude-settings-audit/scripts/audit_setup.ps1' -Verb RunAs"
```

Expected: UAC prompt, then "OK: Success and Failure auditing enabled for File System" + "Wrote install/setup.done".

**Step 5: Start the daemon and verify it logs a self-check WARN-free status**

```bash
powershell -Command "Start-ScheduledTask -TaskName ClaudeSettingsAuditDaemon"
# wait a few seconds
tail -n 20 ~/.claude/plugins/claude-settings-audit/change.log
```

Expected: at least a "watchdog started" log entry (or first WARN if something is off), no crashes.

**Step 6: End-to-end manual verification (matches §7 of design doc)**

- Edit `~/.claude/settings.json` via Claude Code → within 5 s, an entry appears in `change.log` with `source=hook`, `actor.tool=Edit`.
- From a separate PowerShell: `(Get-Content ~/.claude/settings.json) -join "`n" | Set-Content ~/.claude/settings.json` → within 5 s, entry with `source=audit`, `actor.process_name=pwsh.exe` (or similar).
- `auditpol /set /subcategory:"File System" /success:disable` → within 60 s, `WARN: file_audit_policy_changed: audit_disabled` appears.

---

## Self-check at the end

When all tasks above are done, the **acceptance criterion** is met when:
1. `/plugins` in Claude Code lists `claude-settings-audit` as enabled.
2. `change.log` and `change.log.jsonl` exist and receive entries from all three event sources.
3. `audit_setup.ps1` enables the 4663 policy and the daemon self-check is happy.

If any of those is false, the goal is not yet achieved — do not declare done.

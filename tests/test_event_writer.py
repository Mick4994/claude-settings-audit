import json
import sys
from pathlib import Path

# Allow `python -m pytest` from project root to find scripts/
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

from scripts.audit_event_writer import AuditEvent, write, _format_human, _rotate_if_needed
import scripts.audit_event_writer as ew


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
    monkeypatch.setattr(ew, "HUMAN_LOG", log)
    monkeypatch.setattr(ew, "JSONL_LOG", jsonl)
    write(make_event())
    text = log.read_text(encoding="utf-8")
    assert "Edit" in text
    assert "settings.json" in text
    assert "+new" in text or "new" in text


def test_write_creates_jsonl_line(tmp_path, monkeypatch):
    log = tmp_path / "change.log"
    jsonl = tmp_path / "change.log.jsonl"
    monkeypatch.setattr(ew, "HUMAN_LOG", log)
    monkeypatch.setattr(ew, "JSONL_LOG", jsonl)
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
    assert "─" in block
    assert "Edit" in block


def test_rotate_when_size_exceeds(tmp_path, monkeypatch):
    log = tmp_path / "change.log"
    payload = "x" * (10 * 1024 * 1024 + 1)
    log.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(ew, "HUMAN_LOG", log)
    _rotate_if_needed()
    # After rotation, the big file is moved to .log.1; the original may not exist
    rotated = tmp_path / "change.log.1"
    assert rotated.exists()
    assert len(rotated.read_text(encoding="utf-8")) == len(payload)

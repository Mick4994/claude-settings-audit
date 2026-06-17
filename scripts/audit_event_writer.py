"""Audit event writer — dual-format (human + JSONL)."""
from __future__ import annotations

import json
import shutil
import threading
from dataclasses import dataclass, asdict
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

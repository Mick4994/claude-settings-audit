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
        sha256_before="",
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

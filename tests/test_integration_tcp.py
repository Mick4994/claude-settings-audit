"""Integration test: hook_loop TCP listener.

Tests the listener logic directly without spawning a subprocess — that way
the test can use a dedicated test port, write to a tmp log dir, and run in
the test process's Python where state is controllable.
"""
import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Use a high port unlikely to clash with the real daemon
TEST_PORT = 17322


def _send_event(port: int, ev: dict, timeout: float = 2.0) -> None:
    s = socket.socket()
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    s.sendall((json.dumps(ev) + "\n").encode())
    s.close()


def _wait_for_jsonl_line(jsonl_path: Path, timeout: float = 5.0) -> dict:
    """Poll the JSONL log until at least one line appears, then return the last."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
            lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
            return json.loads(lines[-1])
        time.sleep(0.05)
    pytest.fail(f"no event written to {jsonl_path} within {timeout}s")


def test_hook_loop_accepts_event(tmp_path, monkeypatch):
    import scripts.audit_event_writer as ew
    import scripts.audit_daemon as ad
    from scripts.audit_normalize import Deduper

    # Isolated log dir for this test
    human_log = tmp_path / "change.log"
    jsonl_log = tmp_path / "change.log.jsonl"
    monkeypatch.setattr(ew, "HUMAN_LOG", human_log)
    monkeypatch.setattr(ew, "JSONL_LOG", jsonl_log)
    # Override the captured PORT so we don't clash with the real daemon
    monkeypatch.setattr(ad, "PORT", TEST_PORT)
    # Pretend our tmp file is a watched settings file
    watched_path = tmp_path / "settings.json"
    watched_path.write_text('{"a": 1}', encoding="utf-8")
    monkeypatch.setattr(ad, "WATCHED", [watched_path])
    monkeypatch.setattr(ad, "WATCHED_NORM", [ad.norm(str(watched_path))])

    # Reset the singleton deduper so we don't carry state across tests
    ad.deduper = Deduper(window_seconds=ad.DEDUP_WINDOW_S)

    # Spin up hook_loop on the test port
    stop = threading.Event()
    t = threading.Thread(
        target=ad.hook_loop, args=(stop,), daemon=True, name="hook-test"
    )
    t.start()
    # Give it a moment to bind
    time.sleep(0.2)

    try:
        # Send one event
        ev = {
            "type": "hook",
            "ts": "2026-06-18T20:00:00Z",
            "tool": "Edit",
            "session_id": "test-socket",
            "cwd": "C:/test",
            "file_path": str(tmp_path / "settings.json"),
            "sha256_before": "h0",
            "sha256_after": "h1",
            "diff": "+integration",
        }
        _send_event(TEST_PORT, ev)

        # Wait for the daemon to log it
        rec = _wait_for_jsonl_line(jsonl_log)
        assert rec["source"] == "hook"
        assert rec["actor"]["tool"] == "Edit"
        assert rec["actor"]["session_id"] == "test-socket"
        assert rec["sha256_after"] == "h1"
        # Human log also written
        assert human_log.exists()
        assert "Edit" in human_log.read_text(encoding="utf-8")
    finally:
        stop.set()
        # The thread uses socket timeouts; it'll exit on the next loop iteration


@pytest.fixture
def free_port():
    """Find a free TCP port and return it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

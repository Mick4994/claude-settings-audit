from scripts.audit_normalize import (
    normalize_hook,
    normalize_audit,
    normalize_watchdog,
    normalize_warn,
    Deduper,
)


def test_normalize_hook():
    ev = normalize_hook(
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
        file_path="A:/x/settings.json",
        sha256_after="h1",
        process_snapshot=snapshot,
    )
    assert ev.source == "watchdog"
    assert ev.actor["type"] == "unknown"
    assert ev.actor["process_snapshot"] == snapshot


def test_normalize_warn():
    ev = normalize_warn("audit_disabled")
    assert ev.source == "warn"
    assert ev.actor["type"] == "self_check"
    assert ev.actor["message"] == "audit_disabled"


def test_deduper_collapses_same_hash_within_window():
    d = Deduper(window_seconds=5)
    assert d.should_record("settings.json", "h1", ts=0) is True
    assert d.should_record("settings.json", "h1", ts=2) is False
    assert d.should_record("settings.json", "h1", ts=10) is True
    assert d.should_record("settings.json", "h2", ts=2) is True
    assert d.should_record("settings.local.json", "h1", ts=2) is True

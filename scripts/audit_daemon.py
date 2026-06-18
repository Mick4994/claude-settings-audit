r"""Claude Code settings audit daemon.

Three event sources, all merged into AuditEvent and written via the event writer:
1. Windows named pipe  (\\.\pipe\claude-settings-audit)  - fed by hooks/postsettingschange.js
2. win32evtlog Security 4663 subscription                 - any external writer
3. watchdog mtime observer on the 5 watched files         - fallback

Self-checks the 4663 audit policy every 60s and emits a WARN event if disabled.
"""
from __future__ import annotations

import hashlib
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

import scripts.audit_event_writer as ew  # noqa: E402
from scripts.audit_event_writer import AuditEvent, write  # noqa: E402
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

# Override event writer paths to point at our project (after install via junction,
# DAEMON_HOME and ~/.claude/plugins/claude-settings-audit resolve to the same dir).
ew.HUMAN_LOG = DAEMON_HOME / "change.log"
ew.JSONL_LOG = DAEMON_HOME / "change.log.jsonl"

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


def _sha256_of(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# --- audit policy self-check ---

def audit_policy_enabled() -> bool | None:
    """Return True/False if we can determine, None if we lack permission or hit an error."""
    try:
        out = subprocess.run(
            ["auditpol.exe", "/get", "/subcategory:File System"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception as e:
        log.warning("auditpol check failed: %s", e)
        return None
    if out.returncode != 0:
        # Non-zero usually means we lack admin to query policy. Don't WARN spam.
        return None
    if "Success" in out.stdout and "No Auditing" not in out.stdout:
        return True
    return False


def self_check_loop(stop: threading.Event) -> None:
    last_state: bool | None = None
    while not stop.wait(SELF_CHECK_INTERVAL_S):
        cur = audit_policy_enabled()
        if last_state is None or cur is None:
            last_state = cur
            continue
        if cur != last_state:
            msg = "audit_enabled" if cur else "audit_disabled"
            log.warning("audit policy changed: %s", msg)
            write(normalize_warn(f"file_audit_policy_changed: {msg}"))
            last_state = cur


# --- 4663 subscription ---

def _is_4663_for_watched(event_xml: str) -> tuple[str, int, str, str, str] | None:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(event_xml)
        data = {}
        for elem in root.iter():
            name = elem.get("Name")
            if name:
                data[name] = elem.text or ""
    except Exception:
        return None
    obj = data.get("ObjectName", "") or ""
    matched = is_watched(obj)
    if not matched:
        return None
    try:
        pid = int(data.get("ProcessId", "0") or 0)
    except ValueError:
        pid = 0
    sid = data.get("SubjectUserSid", "")
    user = (data.get("SubjectDomainName", "") or "") + "\\" + (data.get("SubjectUserName", "") or "")
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
        import win32evtlogutil
    except ImportError:
        log.warning("pywin32 not available; 4663 subscription disabled")
        return
    # Probe once: can we read Security log? If not, warn once and back off.
    try:
        hand = win32evtlog.OpenEventLog(None, "Security")
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        log.warning("cannot read Security log (%s) - 4663 attribution disabled; run audit_setup.ps1 as admin to enable", e)
        write(normalize_warn(f"security_log_unreadable: {e}"))
        return
    log.info("polling Security log for 4663 events")
    last_record = 0
    backoff = 1
    while not stop.is_set():
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            hand = win32evtlog.OpenEventLog(None, "Security")
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            finally:
                win32evtlog.CloseEventLog(hand)
            backoff = 1
        except Exception as e:
            backoff = min(60, backoff * 2)
            if backoff >= 60:
                log.warning("ReadEventLog still failing (every 60s): %s", e)
            time.sleep(backoff)
            continue
        for ev in events:
            if ev.EventID != 4663:
                continue
            rno = ev.RecordNumber
            if rno <= last_record:
                continue
            last_record = max(last_record, rno)
            file_path = ""
            for s in ev.Strings or []:
                ls = (s or "").lower()
                if any(k in ls for k in ("settings.json", "settings.local.json", "hooks.json", "plugin.json", "marketplace.json")):
                    file_path = s
                    break
            if not is_watched(file_path):
                continue
            try:
                sid = win32evtlogutil.SidToString(ev.UserSID) if ev.UserSID else ""
            except Exception:
                sid = ""
            user = ev.ComputerName or ""
            pid = 0
            try:
                data = bytes(ev.Data or b"")
                for off in range(0, max(1, len(data) - 4)):
                    candidate = int.from_bytes(data[off:off + 4], "little")
                    if 100 < candidate < 100000:
                        pid = candidate
                        break
            except Exception:
                pid = 0
            proc = ""
            if pid:
                try:
                    proc = psutil.Process(pid).exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc = ""
            sha = _sha256_of(file_path)
            if not deduper.should_record(file_path, sha):
                continue
            ev_obj = normalize_audit(
                file_path=file_path,
                sha256_after=sha,
                subject_sid=sid,
                subject_user=user,
                process_id=pid or None,
                process_name=proc or None,
            )
            write(ev_obj)
            log.info("4663 -> %s by %s (pid=%s)", file_path, proc or user, pid)
        time.sleep(1)


# --- hook listener (TCP socket on localhost) ---

HOST = "127.0.0.1"
PORT = 17321


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
    log.info("hook -> %s via %s", fp, data.get("tool", "?"))


def hook_loop(stop: threading.Event) -> None:
    import socket
    import select
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, PORT))
    except OSError as e:
        log.warning("hook socket bind %s:%d failed (%s) - hook channel disabled", HOST, PORT, e)
        write(normalize_warn(f"hook_socket_bind_failed: {e}"))
        return
    sock.listen(8)
    sock.settimeout(1.0)
    log.info("hook socket listening on %s:%d", HOST, PORT)
    while not stop.is_set():
        try:
            try:
                client, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError as e:
                log.warning("hook accept error: %s", e)
                time.sleep(0.5)
                continue
            client.settimeout(2.0)
            try:
                chunks: list[bytes] = []
                while True:
                    try:
                        data = client.recv(65536)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
                    if b"\n" in data:
                        break
                blob = b"".join(chunks).decode("utf-8", errors="ignore")
                for line in blob.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        _process_hook_event(json.loads(line))
                    except Exception as e:
                        log.warning("hook payload bad: %s", e)
            finally:
                try:
                    client.close()
                except Exception:
                    pass
        except Exception as e:
            log.warning("hook loop error: %s - retrying", e)
            time.sleep(1)
    try:
        sock.close()
    except Exception:
        pass


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
        # small debounce so richer events (hook/audit) can claim first
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
        log.info("watchdog -> %s (unknown actor)", fp)


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
    handler = _Handler(stop)
    obs = Observer()
    watched_parents = set()
    for p in WATCHED:
        parent = p.parent
        if parent.exists() and str(parent) not in watched_parents:
            obs.schedule(handler, str(parent), recursive=False)
            watched_parents.add(str(parent))
    if not watched_parents:
        log.warning("no watched paths exist; watchdog idle")
    obs.start()
    log.info("watchdog watching %d parents covering %d files", len(watched_parents), len(WATCHED))
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
        log.warning("singleton check failed: %s - proceeding", e)
        return True


# --- main ---

def main() -> int:
    if not _acquire_singleton():
        log.info("another instance is running; exiting")
        return 0
    log.info("watched paths:")
    for p in WATCHED_NORM:
        log.info("  %s", p)
    stop = threading.Event()
    threads = [
        threading.Thread(target=hook_loop, args=(stop,), daemon=True, name="hook"),
        threading.Thread(target=audit_subscription_loop, args=(stop,), daemon=True, name="audit"),
        threading.Thread(target=watchdog_loop, args=(stop,), daemon=True, name="watchdog"),
        threading.Thread(target=self_check_loop, args=(stop,), daemon=True, name="selfcheck"),
    ]
    for t in threads:
        t.start()
    log.info("daemon started")
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

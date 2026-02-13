from typing import Dict
from pathlib import Path
import time
import uuid
import threading
import os
import signal
import json

# --------------------------------------------------
# Registry persistence config
# --------------------------------------------------

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

REGISTRY_FILE = STATE_DIR / "scan_registry.json"

# --------------------------------------------------
# In-memory registry
# --------------------------------------------------

_SCAN_REGISTRY: Dict[str, dict] = {}
_REGISTRY_LOCK = threading.Lock()

# --------------------------------------------------
# Persistence helpers
# --------------------------------------------------

def _load_registry():
    """
    Load registry state from disk on MCP startup.
    Never crash MCP if state is corrupted.
    """
    if not REGISTRY_FILE.exists():
        return

    try:
        data = json.loads(REGISTRY_FILE.read_text())
        if isinstance(data, dict):
            _SCAN_REGISTRY.update(data)
    except Exception:
        pass  # fail safe


def _save_registry():
    """
    Persist registry to disk.
    Runtime-only fields are stripped.
    """
    serializable = {}

    for scan_id, scan in _SCAN_REGISTRY.items():
        clean = dict(scan)
        clean.pop("process", None)  # not serializable
        serializable[scan_id] = clean

    REGISTRY_FILE.write_text(json.dumps(serializable, indent=2))


# Load persisted state at import time
_load_registry()

# --------------------------------------------------
# Public API
# --------------------------------------------------

def attach_process(scan_id: str, process):
    """
    Attach a running subprocess to a scan entry.
    """
    with _REGISTRY_LOCK:
        scan = _SCAN_REGISTRY.get(scan_id)
        if not scan:
            return

        scan["pid"] = process.pid
        scan["process"] = process
        _save_registry()


def create_scan(firmware: Path, log_dir: Path) -> str:
    """
    Create and register a new scan.
    """
    scan_id = f"emba-{uuid.uuid4().hex[:10]}"

    with _REGISTRY_LOCK:
        _SCAN_REGISTRY[scan_id] = {
            "scan_id": scan_id,
            "firmware": str(firmware),
            "log_dir": str(log_dir),
            "status": "running",      # running | stopping | finished | failed
            "started_at": time.time(),
            "finished_at": None,
            "error": None,
            "pid": None,
            "meta": {},
        }
        _save_registry()

    return scan_id


def mark_finished(scan_id: str):
    """
    Mark scan as successfully finished.
    """
    with _REGISTRY_LOCK:
        scan = _SCAN_REGISTRY.get(scan_id)
        if not scan:
            return

        scan["status"] = "finished"
        scan["finished_at"] = time.time()
        _save_registry()


def mark_failed(scan_id: str, error: str):
    """
    Mark scan as failed.
    """
    with _REGISTRY_LOCK:
        scan = _SCAN_REGISTRY.get(scan_id)
        if not scan:
            return

        scan["status"] = "failed"
        scan["error"] = error
        scan["finished_at"] = time.time()
        _save_registry()


def get_scan(scan_id: str) -> dict:
    """
    Retrieve a single scan (defensive copy).
    """
    with _REGISTRY_LOCK:
        scan = _SCAN_REGISTRY.get(scan_id)
        if not scan:
            return {"error": "unknown scan_id"}

        return dict(scan)


def list_scans() -> Dict[str, dict]:
    """
    List all scans (defensive copies).
    """
    with _REGISTRY_LOCK:
        return {k: dict(v) for k, v in _SCAN_REGISTRY.items()}


def stop_scan(scan_id: str) -> dict:
    """
    Gracefully stop a running EMBA scan.
    Uses process-group termination (SIGTERM).
    """
    with _REGISTRY_LOCK:
        scan = _SCAN_REGISTRY.get(scan_id)
        if not scan:
            return {"error": "unknown scan_id"}

        proc = scan.get("process")
        if not proc:
            return {"error": "no process attached"}

        if scan["status"] != "running":
            return {"status": scan["status"]}

        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)

            scan["status"] = "stopping"
            _save_registry()

            return {
                "status": "stopping",
                "pgid": pgid,
            }

        except Exception as e:
            return {"error": str(e)}

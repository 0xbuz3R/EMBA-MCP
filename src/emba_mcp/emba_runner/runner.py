# runner.py
import os
import subprocess
import threading
from pathlib import Path
import logging
import time
import uuid

from .registry import create_scan, mark_finished, mark_failed, attach_process
from .config import get_emba_binary

log = logging.getLogger("emba-mcp")


def _run_emba_process(
    scan_id: str,
    firmware: Path,
    output_dir: Path,
    force_overwrite: bool,
):
    try:
        emba_bin = get_emba_binary()
        emba_home = emba_bin.parent
        profile = emba_home / "scan-profiles" / "default-scan.emba"

        if not emba_bin.exists():
            raise RuntimeError(f"EMBA binary not found: {emba_bin}")

        if not profile.exists():
            raise RuntimeError(f"Scan profile not found: {profile}")

        # Explicit environment (CRITICAL for MCP)
        env = os.environ.copy()
        env["EMBA_HOME"] = str(emba_home)

        cmd = [
            "./emba",
            "-l", str(output_dir),
            "-f", str(firmware),
            "-p", str(profile),
        ]

        log.info(
            "Starting EMBA scan %s | firmware=%s | output=%s | overwrite=%s",
            scan_id,
            firmware,
            output_dir,
            force_overwrite,
        )

        proc = subprocess.Popen(
            cmd,
            cwd=str(emba_home),           # MUST run inside EMBA dir
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,       # allows kill later
        )

        # Attach PID for stop support
        attach_process(scan_id, proc)

        # Only answer prompt if overwrite is allowed
        input_data = "y\n" if force_overwrite else None
        stdout, stderr = proc.communicate(input=input_data)

        if proc.returncode != 0:
            raise RuntimeError(
                f"EMBA exited with code {proc.returncode}\nSTDERR:\n{stderr.strip()}"
            )

        mark_finished(scan_id)
        log.info("EMBA scan %s completed successfully", scan_id)

    except Exception as e:
        log.exception("EMBA scan %s failed", scan_id)
        mark_failed(scan_id, str(e))


def start_emba_scan(
    firmware_path: Path,
    base_log_dir: Path,
    force_overwrite: bool = False,
) -> dict:
    """
    Start a single EMBA scan for one firmware image.
    """
    firmware_path = firmware_path.expanduser().resolve()

    if not firmware_path.exists():
        raise RuntimeError(f"Firmware not found: {firmware_path}")

    base_log_dir = base_log_dir.expanduser().resolve()
    base_log_dir.mkdir(parents=True, exist_ok=True)

    # One scan = one unique directory
    scan_suffix = uuid.uuid4().hex[:6]
    output_dir = base_log_dir / f"emba_scan_{firmware_path.stem}_{scan_suffix}"

    if output_dir.exists() and not force_overwrite:
        raise RuntimeError(
            f"Log directory already exists: {output_dir}. "
            "Set force_overwrite=true to allow overwrite."
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    scan_id = create_scan(firmware_path, output_dir)

    thread = threading.Thread(
        target=_run_emba_process,
        args=(scan_id, firmware_path, output_dir, force_overwrite),
        daemon=True,
        name=f"emba-scan-{scan_id}",
    )
    thread.start()

    return {
        "scan_id": scan_id,
        "status": "running",
        "firmware": str(firmware_path),
        "log_dir": str(output_dir),
        "force_overwrite": force_overwrite,
        "started_at": time.time(),
    }

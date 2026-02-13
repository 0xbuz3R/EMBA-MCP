# config.py
from pathlib import Path
import os

def get_emba_binary() -> Path:
    emba_home = os.getenv("EMBA_HOME")
    if not emba_home:
        raise RuntimeError("EMBA_HOME is not set")

    emba_home = Path(emba_home).expanduser().resolve()
    if not emba_home.exists():
        raise RuntimeError(f"EMBA_HOME does not exist: {emba_home}")

    emba_bin = emba_home / "emba"
    if not emba_bin.exists():
        raise RuntimeError(f"EMBA binary not found at: {emba_bin}")

    if not os.access(emba_bin, os.X_OK):
        raise RuntimeError(f"EMBA binary is not executable: {emba_bin}")

    return emba_bin

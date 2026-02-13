from pathlib import Path
from typing import Dict, List, Optional
import stat

COMMON_ROOT_NAMES = [
    "squashfs-root",
    "rootfs",
    "filesystem",
]

def find_filesystem_root(log_dir: Path) -> Optional[Path]:
    firmware_dir = log_dir / "firmware"
    if not firmware_dir.exists():
        return None

    for path in firmware_dir.rglob("*"):
        if path.is_dir() and path.name in COMMON_ROOT_NAMES:
            return path

    return None


def walk_filesystem(root: Path) -> List[Path]:
    files = []
    for p in root.rglob("*"):
        try:
            if p.is_file():
                files.append(p)
        except Exception:
            continue
    return files


def basic_filesystem_summary(log_dir: Path) -> Dict:
    root = find_filesystem_root(log_dir)

    if not root:
        return {
            "found": False,
            "reason": "Filesystem root not found",
            "confidence": "low",
        }

    files = walk_filesystem(root)

    summary = {
        "total_files": len(files),
        "config_files": 0,
        "binaries": 0,
        "scripts": 0,
    }

    for f in files:
        name = f.name.lower()
        try:
            mode = f.stat().st_mode
        except Exception:
            continue

        if name.endswith((".conf", ".cfg", ".ini")):
            summary["config_files"] += 1
        elif f.suffix in {".sh", ".cgi", ".py", ".lua", ".php", ".pl"}:
            summary["scripts"] += 1
        elif (f.suffix in {"", ".bin"}) and (mode & stat.S_IXUSR):
            summary["binaries"] += 1

    return {
        "found": True,
        "filesystem_root": str(root),
        "summary": summary,
        "confidence": "high",
    }

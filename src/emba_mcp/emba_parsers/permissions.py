from pathlib import Path
from typing import Dict, List
import stat


def _is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def _is_suid(mode: int) -> bool:
    return bool(mode & stat.S_ISUID)


def _is_sgid(mode: int) -> bool:
    return bool(mode & stat.S_ISGID)


def parse_permissions(log_dir: Path, fs_root: Path | None) -> Dict:
    """
    Inventory permission-related risks from extracted filesystem.
    Conservative, evidence-only.
    """

    if not fs_root:
        return {
            "found": False,
            "reason": "Filesystem root not found",
            "confidence": "low",
        }

    suid_binaries: List[str] = []
    sgid_binaries: List[str] = []
    world_writable_files: List[str] = []
    world_writable_dirs: List[str] = []

    scanned = 0

    for p in fs_root.rglob("*"):
        try:
            if not p.exists():
                continue

            st = p.stat()
            mode = st.st_mode
            scanned += 1

            if p.is_file():
                if _is_suid(mode):
                    suid_binaries.append(str(p))
                if _is_sgid(mode):
                    sgid_binaries.append(str(p))
                if _is_world_writable(mode):
                    world_writable_files.append(str(p))

            elif p.is_dir():
                if _is_world_writable(mode):
                    world_writable_dirs.append(str(p))

        except Exception:
            continue

    # Confidence logic (transparent)
    confidence = "low"
    if suid_binaries or sgid_binaries:
        confidence = "high"
    elif world_writable_files or world_writable_dirs:
        confidence = "medium"

    return {
        "found": True,
        "summary": {
            "scanned_paths": scanned,
            "suid_binaries": sorted(suid_binaries),
            "sgid_binaries": sorted(sgid_binaries),
            "world_writable_files": sorted(world_writable_files),
            "world_writable_dirs": sorted(world_writable_dirs),
        },
        "confidence": confidence,
    }

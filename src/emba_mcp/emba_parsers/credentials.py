from pathlib import Path
from typing import Dict, List
import re


PASSWD_FILES = {
    "passwd": "etc/passwd",
    "shadow": "etc/shadow",
    "group": "etc/group",
}

SECRET_EXTENSIONS = (
    ".bak", ".old", ".save", ".orig", ".backup"
)

KEY_FILES = (
    "id_rsa",
    "id_dsa",
    "authorized_keys",
    "dropbear_rsa_host_key",
)


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def _parse_passwd(text: str) -> List[Dict]:
    users = []
    for line in text.splitlines():
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            users.append({
                "user": parts[0],
                "uid": parts[2],
                "shell": parts[-1],
            })
    return users


def parse_credentials(log_dir: Path, fs_root: Path | None) -> Dict:
    findings = {
        "users": [],
        "shadow_present": False,
        "ssh_keys": [],
        "backup_files": [],
        "config_files": [],
    }

    sources: List[str] = []

    if not fs_root:
        return {
            "found": False,
            "reason": "Filesystem root not found",
            "confidence": "low",
        }

    # ---- passwd / shadow ----
    passwd_path = fs_root / "etc" / "passwd"
    shadow_path = fs_root / "etc" / "shadow"

    if passwd_path.exists():
        text = _safe_read(passwd_path)
        findings["users"] = _parse_passwd(text)
        sources.append(str(passwd_path))

    if shadow_path.exists():
        findings["shadow_present"] = True
        sources.append(str(shadow_path))

    # ---- SSH keys ----
    for p in fs_root.rglob("*"):
        if not p.is_file():
            continue

        name = p.name.lower()

        if name in KEY_FILES:
            findings["ssh_keys"].append(str(p))
            sources.append(str(p))

        if p.suffix in SECRET_EXTENSIONS:
            findings["backup_files"].append(str(p))
            sources.append(str(p))

        if p.suffix in {".conf", ".cfg"} and "password" in _safe_read(p).lower():
            findings["config_files"].append(str(p))
            sources.append(str(p))

    confidence = "low"
    if findings["users"] or findings["ssh_keys"]:
        confidence = "high"
    elif findings["backup_files"] or findings["shadow_present"]:
        confidence = "medium"

    return {
        "found": True,
        "summary": findings,
        "confidence": confidence,
        "sources": sorted(set(sources)),
    }

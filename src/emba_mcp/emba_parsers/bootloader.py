from pathlib import Path
import re
from typing import Dict, List, Optional


# -------------------------
# Helpers
# -------------------------

def _read_text_files(paths: List[Path]) -> List[str]:
    contents = []
    for p in paths:
        try:
            if p.exists() and p.is_file():
                contents.append(p.read_text(errors="ignore"))
        except Exception:
            continue
    return contents


def _detect_bootloader(text: str) -> Optional[str]:
    bootloader_patterns = {
        "u-boot": r"\bU-Boot\b",
        "redboot": r"\bRedBoot\b",
        "cfe": r"\bCFE\b",
        "barebox": r"\bbarebox\b",
        "uboot-env": r"bootcmd=|bootargs=",
    }

    for name, pattern in bootloader_patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            return name

    return None


def _detect_startup_system(text: str) -> Optional[str]:
    if re.search(r"/etc/inittab", text):
        return "sysvinit"
    if re.search(r"/etc/init\.d/", text):
        return "sysvinit"
    if re.search(r"rcS|rc\.d", text):
        return "sysvinit"
    if re.search(r"procd", text):
        return "openwrt-procd"
    return None


# -------------------------
# Main parser
# -------------------------

def parse_bootloader_info(log_dir: Path) -> Dict:
    """
    Parse bootloader and system startup information from EMBA output.
    """

    sources: List[str] = []
    text_blobs: List[str] = []

    candidate_dirs = [
        log_dir / "s07_bootloader_check",
        log_dir / "s06_distribution_identification",
    ]

    for d in candidate_dirs:
        if d.exists() and d.is_dir():
            files = list(d.glob("*.txt"))
            sources.extend(str(f) for f in files)
            text_blobs.extend(_read_text_files(files))

    combined_text = "\n".join(text_blobs)

    bootloader = _detect_bootloader(combined_text)
    startup_system = _detect_startup_system(combined_text)

    startup_files = []
    for p in [
        log_dir / "etc" / "inittab",
        log_dir / "etc" / "rcS",
        log_dir / "etc" / "init.d",
        log_dir / "etc" / "rc.d",
    ]:
        if p.exists():
            startup_files.append(str(p))

    confidence = "low"
    if bootloader and startup_system:
        confidence = "high"
    elif bootloader or startup_system:
        confidence = "medium"

    return {
        "bootloader": bootloader,
        "startup_system": startup_system,
        "startup_files_detected": startup_files,
        "confidence": confidence,
        "sources": sources,
    }

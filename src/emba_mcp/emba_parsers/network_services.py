from pathlib import Path
from typing import Dict, List
import re


SERVICE_SIGNATURES = {
    "ssh": [
        "dropbear",
        "sshd",
    ],
    "telnet": [
        "telnetd",
    ],
    "http": [
        "lighttpd",
        "uhttpd",
        "httpd",
    ],
    "ftp": [
        "ftpd",
        "vsftpd",
        "busybox ftpd",
    ],
    "tftp": [
        "tftpd",
    ],
}


def _scan_text_for_services(text: str) -> List[str]:
    found = set()
    for service, keywords in SERVICE_SIGNATURES.items():
        for kw in keywords:
            if re.search(rf"\b{re.escape(kw)}\b", text, re.IGNORECASE):
                found.add(service)
    return list(found)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def parse_network_services(log_dir: Path, fs_root: Path | None = None) -> Dict:
    """
    Identify network services present in firmware.
    Evidence-only, conservative.
    """

    services_found = set()
    evidence: Dict[str, List[str]] = {}

    # ---- EMBA logs ----
    for d in log_dir.iterdir():
        if not d.is_dir():
            continue

        if "ssh" in d.name or "telnet" in d.name or "http" in d.name:
            for f in d.glob("*.txt"):
                text = _read_text(f)
                found = _scan_text_for_services(text)
                for s in found:
                    services_found.add(s)
                    evidence.setdefault(s, []).append(str(f))

    # ---- Filesystem scan ----
    if fs_root:
        for p in fs_root.rglob("*"):
            try:
                if not p.is_file():
                    continue

                name = p.name.lower()

                for service, keywords in SERVICE_SIGNATURES.items():
                    for kw in keywords:
                        if kw in name:
                            services_found.add(service)
                            evidence.setdefault(service, []).append(str(p))

                # Init scripts
                if p.parent.name in {"init.d", "rc.d"}:
                    text = _read_text(p)
                    found = _scan_text_for_services(text)
                    for s in found:
                        services_found.add(s)
                        evidence.setdefault(s, []).append(str(p))

            except Exception:
                continue

    confidence = "low"
    if len(services_found) >= 2:
        confidence = "high"
    elif services_found:
        confidence = "medium"

    return {
        "services_detected": sorted(services_found),
        "evidence": evidence,
        "confidence": confidence,
    }

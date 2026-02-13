from pathlib import Path
from typing import Dict, List
import re


CRYPTO_FILES = {
    "private_keys": (".key",),
    "certificates": (".crt", ".cer", ".pem", ".der", ".p12"),
}

WEAK_ALGO_KEYWORDS = {
    "md5": r"\bmd5\b",
    "sha1": r"\bsha1\b",
    "des": r"\bdes\b",
    "rc4": r"\brc4\b",
    "ecb": r"\becb\b",
}

SECRET_KEYWORDS = (
    "private key",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "token",
)


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def _scan_for_weak_algos(text: str) -> List[str]:
    found = []
    for name, pattern in WEAK_ALGO_KEYWORDS.items():
        if re.search(pattern, text, re.IGNORECASE):
            found.append(name)
    return found


def parse_weak_crypto(log_dir: Path, fs_root: Path | None) -> Dict:
    """
    Inventory weak crypto indicators and embedded keys/certs.
    Evidence-only, conservative.
    """

    if not fs_root:
        return {
            "found": False,
            "reason": "Filesystem root not found",
            "confidence": "low",
        }

    findings = {
        "private_keys": [],
        "certificates": [],
        "weak_algorithms": {},
        "hardcoded_secrets": [],
    }

    sources: List[str] = []

    for p in fs_root.rglob("*"):
        try:
            if not p.is_file():
                continue

            lower_name = p.name.lower()

            # ---- Keys / certs ----
            for category, exts in CRYPTO_FILES.items():
                if any(lower_name.endswith(ext) for ext in exts):
                    findings[category].append(str(p))
                    sources.append(str(p))

            # ---- Config / script scanning ----
            if p.suffix in {".conf", ".cfg", ".ini", ".sh", ".cgi", ".php", ".lua"}:
                text = _safe_read(p)

                # Weak algorithms
                algos = _scan_for_weak_algos(text)
                if algos:
                    findings["weak_algorithms"][str(p)] = algos
                    sources.append(str(p))

                # Hardcoded secrets (keyword-based, not values)
                if any(k in text.lower() for k in SECRET_KEYWORDS):
                    findings["hardcoded_secrets"].append(str(p))
                    sources.append(str(p))

        except Exception:
            continue

    # De-duplicate
    for k in ("private_keys", "certificates", "hardcoded_secrets"):
        findings[k] = sorted(set(findings[k]))

    confidence = "low"
    if findings["private_keys"] or findings["certificates"]:
        confidence = "high"
    elif findings["weak_algorithms"] or findings["hardcoded_secrets"]:
        confidence = "medium"

    return {
        "found": True,
        "summary": findings,
        "confidence": confidence,
        "sources": sorted(set(sources)),
    }

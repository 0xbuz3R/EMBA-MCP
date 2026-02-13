from pathlib import Path
import re
from typing import List, Dict


def parse_php_vulnerabilities(log_dir: Path) -> Dict:
    php_dir = log_dir / "s22_php_check"

    if not php_dir.exists():
        return {
            "count": 0,
            "findings": [],
            "confidence": "low",
            "error": "s22_php_check not found",
        }

    findings: List[Dict] = []
    sources: List[str] = []

    # ----------------------------
    # Regex patterns per section
    # ----------------------------

    SEMGREP_RE = re.compile(
        r"Found possible PHP vulnerability\s+(.*?)\s+in\s+(.*)",
        re.IGNORECASE,
    )

    PROGPILOT_RE = re.compile(
        r"Possible vulnerability detected.*?file:\s*(.*)",
        re.IGNORECASE,
    )

    PHPINI_BAD_RE = re.compile(
        r"(register_globals|allow_url_include|display_errors)\s*=\s*On",
        re.IGNORECASE,
    )

    PHPINFO_RE = re.compile(
        r"phpinfo\(\)",
        re.IGNORECASE,
    )

    # ----------------------------
    # Scan all text / log files
    # ----------------------------

    for f in php_dir.rglob("*"):
        if not f.is_file():
            continue

        text = f.read_text(errors="ignore")
        sources.append(str(f))

        for line in text.splitlines():

            # ---- Semgrep ----
            m = SEMGREP_RE.search(line)
            if m:
                findings.append({
                    "type": "code_vulnerability",
                    "engine": "semgrep",
                    "rule": m.group(1),
                    "file": m.group(2),
                    "evidence": line.strip(),
                    "severity": "high",
                })
                continue

            # ---- Progpilot ----
            m = PROGPILOT_RE.search(line)
            if m:
                findings.append({
                    "type": "code_vulnerability",
                    "engine": "progpilot",
                    "file": m.group(1),
                    "evidence": line.strip(),
                    "severity": "high",
                })
                continue

            # ---- php.ini misconfig ----
            if PHPINI_BAD_RE.search(line):
                findings.append({
                    "type": "configuration_issue",
                    "engine": "php_ini",
                    "setting": line.strip(),
                    "severity": "medium",
                })
                continue

            # ---- phpinfo exposure ----
            if PHPINFO_RE.search(line):
                findings.append({
                    "type": "information_disclosure",
                    "engine": "phpinfo",
                    "evidence": line.strip(),
                    "severity": "medium",
                })

    # ----------------------------
    # Confidence scoring
    # ----------------------------

    confidence = "low"
    if any(f["severity"] == "high" for f in findings):
        confidence = "high"
    elif findings:
        confidence = "medium"

    return {
        "count": len(findings),
        "findings": findings,
        "confidence": confidence,
        "sources": sorted(set(sources)),
    }

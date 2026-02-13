from pathlib import Path
from typing import Dict, List
import re


def _parse_password_lines(text: str) -> List[Dict]:
    findings = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Typical EMBA output lines:
        # /etc/shadow
        # Found password file: /etc/passwd
        match = re.search(r"(/[\w/\.-]*(passwd|shadow|credentials|password)[\w/\.-]*)", line, re.IGNORECASE)
        if not match:
            continue

        findings.append({
            "file": match.group(1),
            "reason": "Potential password or credential file",
            "source": line,
        })

    return findings


def parse_password_files(log_dir: Path) -> Dict:
    """
    Parse password / credential file findings from EMBA output.
    """

    results = {
        "files": [],
        "confidence": "low",
        "sources": [],
    }

    candidate_dirs = [
        log_dir / "s108_stacs_password_search",
        log_dir / "s50_authentication_check",
    ]

    for d in candidate_dirs:
        if not d.exists():
            continue

        for f in d.glob("*.txt"):
            text = f.read_text(errors="ignore")
            results["sources"].append(str(f))
            results["files"].extend(_parse_password_lines(text))

    count = len(results["files"])

    if count > 5:
        results["confidence"] = "high"
    elif count > 0:
        results["confidence"] = "medium"

    results["count"] = count
    return results

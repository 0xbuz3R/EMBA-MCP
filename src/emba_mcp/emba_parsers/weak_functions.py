from pathlib import Path
import re
from typing import Dict, List


def _parse_weak_function_lines(text: str, mode: str) -> List[Dict]:
    findings = []

    for line in text.splitlines():
        # Example patterns EMBA usually emits
        # strcpy in /bin/httpd
        match = re.search(
            r"(strcpy|sprintf|gets|scanf|strcat|vsprintf|memcpy|system).*?(/[\w/\.-]+)",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        findings.append({
            "function": match.group(1),
            "binary": match.group(2),
            "mode": mode,
            "confidence": "raw",   # keep EMBA confidence unmodified
            "source": line.strip(),
        })

    return findings


def parse_weak_functions(log_dir: Path) -> Dict:
    """
    Parse weak function findings from EMBA output.
    Covers:
      - Intense mode
      - Radare mode
    """

    results = {
        "intense": [],
        "radare": [],
        "confidence": "low",
        "sources": [],
    }

    intense_dir = log_dir / "s13_weak_func_check"
    radare_dir = log_dir / "s14_weak_func_radare_check"

    # ---- Intense mode ----
    if intense_dir.exists():
        for f in intense_dir.glob("*.txt"):
            text = f.read_text(errors="ignore")
            results["sources"].append(str(f))
            results["intense"].extend(
                _parse_weak_function_lines(text, mode="intense")
            )

    # ---- Radare mode ----
    if radare_dir.exists():
        for f in radare_dir.glob("*.txt"):
            text = f.read_text(errors="ignore")
            results["sources"].append(str(f))
            results["radare"].extend(
                _parse_weak_function_lines(text, mode="radare")
            )

    total = len(results["intense"]) + len(results["radare"])

    if total > 10:
        results["confidence"] = "high"
    elif total > 0:
        results["confidence"] = "medium"

    results["count"] = total
    return results

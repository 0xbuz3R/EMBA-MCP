
from pathlib import Path
from typing import List, Dict
import csv

def parse_interesting_files(log_dir: Path) -> Dict:
    findings: List[Dict] = []
    sources = []

    # ---- CSV (best-effort) ----
    csv_path = log_dir / "csv_logs" / "s95_interesting_files_check.csv"
    if csv_path.exists():
        sources.append(str(csv_path))
        with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("FILE"):
                    findings.append({
                        "file": row.get("FILE"),
                        "reason": row.get("REASON", "interesting file"),
                        "confidence": row.get("CONFIDENCE", "medium"),
                    })

    # ---- TXT (authoritative) ----
    txt_path = log_dir / "s95_interesting_files_check.txt"
    if txt_path.exists():
        sources.append(str(txt_path))
        for line in txt_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line.startswith("/"):
                continue

            findings.append({
                "file": line.split()[0],
                "reason": "Interesting file (EMBA s95)",
                "confidence": "high",
            })

    # ---- Dedup ----
    seen = set()
    unique = []
    for f in findings:
        if f["file"] not in seen:
            seen.add(f["file"])
            unique.append(f)

    return {
        "count": len(unique),
        "findings": unique,
        "confidence": "high" if unique else "low",
        "sources": sources,
    }

import re
from pathlib import Path
from typing import Dict,List



def parse_binary_protections(log_dir: Path) -> Dict:
    sources = []
    binaries = []

    # EMBA truth source
    txt_files = list(log_dir.glob("s12_binary_protection*.txt"))

    for txt in txt_files:
        text = txt.read_text(errors="ignore")
        sources.append(str(txt))

        for line in text.splitlines():
            if "/" not in line:
                continue

            entry = {
                "binary": None,
                "nx": "unknown",
                "pie": "unknown",
                "relro": "unknown",
                "stack_canary": "unknown",
            }

            # Binary path
            m = re.search(r"(/[\w/\.\-]+)", line)
            if not m:
                continue
            entry["binary"] = m.group(1)

            # RELRO
            if "Full RELRO" in line:
                entry["relro"] = "full"
            elif "No RELRO" in line:
                entry["relro"] = "none"

            # Canary
            if "No Canary found" in line:
                entry["stack_canary"] = False
            elif "Canary found" in line:
                entry["stack_canary"] = True

            # NX
            if "NX disabled" in line:
                entry["nx"] = False
            elif "NX enabled" in line:
                entry["nx"] = True

            # PIE
            if "No PIE" in line:
                entry["pie"] = False
            elif "PIE" in line:
                entry["pie"] = True

            binaries.append(entry)

    confidence = "high" if binaries else "low"

    return {
        "binary_count": len(binaries),
        "binaries": binaries,
        "confidence": confidence,
        "sources": sources,
    }

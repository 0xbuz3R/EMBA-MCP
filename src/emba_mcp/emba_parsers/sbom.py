from pathlib import Path
from typing import Dict, List
import json
import re


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def _parse_package_lines(text: str) -> List[Dict]:
    """
    Parse loose package listings like:
      busybox 1.27.2
      openssl-1.0.2k
    """
    packages = []

    for line in text.splitlines():
        line = line.strip()
        if not line or len(line) > 120:
            continue

        match = re.match(r"([a-zA-Z0-9_.+-]+)[\s:-]+([0-9][^\s]*)", line)
        if match:
            packages.append({
                "name": match.group(1),
                "version": match.group(2),
                "source": "text"
            })

    return packages


def _parse_json_sbom(path: Path) -> List[Dict]:
    packages = []

    try:
        data = json.loads(path.read_text())
    except Exception:
        return packages

    # 🔥 FIX: normalize root
    if isinstance(data, list):
        components = data
    elif isinstance(data, dict):
        components = (
            data.get("components")
            or data.get("packages")
            or data.get("artifacts")
            or []
        )
    else:
        return packages

    for c in components:
        if not isinstance(c, dict):
            continue

        name = c.get("name")
        version = (
            c.get("version")
            or c.get("versionInfo")
            or c.get("pkgVersion")
        )

        if name:
            packages.append({
                "name": name,
                "version": version,
                "source": "json",
            })

    return packages



def parse_sbom(log_dir: Path) -> Dict:
    """
    Extract SBOM / component information from EMBA output.
    """
    sbom_dirs = [
        log_dir / "SBOM",
        log_dir / "s08_main_package_sbom",
        log_dir / "s09_firmware_base_sbom",
        log_dir / "json_logs",
    ]

    packages: List[Dict] = []
    sources: List[str] = []

    for d in sbom_dirs:
        if not d.exists() or not d.is_dir():
            continue

        for f in d.iterdir():
            sources.append(str(f))

            if f.suffix == ".json":
                packages.extend(_parse_json_sbom(f))
            elif f.suffix in {".txt", ".log"}:
                text = _read_text(f)
                packages.extend(_parse_package_lines(text))

    # De-duplicate
    seen = set()
    unique_packages = []
    for p in packages:
        key = (p.get("name"), p.get("version"))
        if key not in seen:
            seen.add(key)
            unique_packages.append(p)

    confidence = "low"
    if len(unique_packages) >= 20:
        confidence = "high"
    elif unique_packages:
        confidence = "medium"

    return {
        "package_count": len(unique_packages),
        "packages": unique_packages,
        "confidence": confidence,
        "sources": sources,
    }

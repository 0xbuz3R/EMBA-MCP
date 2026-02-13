from pathlib import Path
from typing import Optional
from emba_mcp.models import DistributionInfo

def parse_distribution(log_dir: Path) -> DistributionInfo:
    """
    Parse EMBA s06_distribution_identification.txt
    """
    path = log_dir / "s06_distribution_identification.txt"

    if not path.exists():
        return DistributionInfo(
            name=None,
            version=None,
            architecture=None,
            raw=""
        )

    raw = path.read_text(errors="ignore")

    name: Optional[str] = None
    version: Optional[str] = None
    arch: Optional[str] = None

    for line in raw.splitlines():
        l = line.lower()

        if "distribution" in l or "os" in l:
            name = line.strip()

        if "version" in l:
            version = line.strip()

        if "arch" in l or "architecture" in l:
            arch = line.strip()

    return DistributionInfo(
        name=name,
        version=version,
        architecture=arch,
        raw=raw
    )

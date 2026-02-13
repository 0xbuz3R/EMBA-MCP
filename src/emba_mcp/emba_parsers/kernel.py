from pathlib import Path
import re
from typing import Dict, List, Optional


# ----------------------------
# Helpers
# ----------------------------

def _read_text_files(paths: List[Path]) -> List[str]:
    """Safely read multiple text files"""
    contents = []
    for p in paths:
        try:
            if p.exists() and p.is_file():
                contents.append(p.read_text(errors="ignore"))
        except Exception:
            continue
    return contents


# ----------------------------
# Extractors
# ----------------------------

def _extract_kernel_version(text: str) -> Optional[str]:
    """
    Extract kernel version from strings like:
      Linux version 2.6.36 (gcc version 4.3.6)
    """
    match = re.search(
        r"Linux version\s+([0-9]+\.[0-9]+\.[0-9]+[^\s]*)",
        text,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def _extract_architecture(text: str) -> Optional[str]:
    """
    Detect architecture from EMBA outputs.
    Order matters (mipsel before mips).
    """
    arch_patterns = [
        ("mipsel", r"\bmipsel\b"),
        ("mips", r"\bmips\b"),
        ("aarch64", r"\baarch64\b|\barm64\b"),
        ("arm", r"\barm\b|\barmv[0-9]+\b|\barmhf\b|\barmel\b"),
        ("x86", r"\bx86\b|\bi[3-6]86\b"),
    ]

    for arch, pattern in arch_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return arch
    return None


def _extract_compiler(text: str) -> Optional[str]:
    """
    Extract compiler version if present.
    """
    match = re.search(
        r"gcc version\s+([0-9]+\.[0-9]+(\.[0-9]+)?)",
        text,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def _extract_build_date(text: str) -> Optional[str]:
    """
    Extract kernel build date if present.
    """
    match = re.search(
        r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"\d+\s+\d+:\d+:\d+\s+\d{4}",
        text,
    )
    return match.group(0) if match else None


def _detect_hardening(text: str) -> Dict[str, str | bool]:
    """
    Very conservative hardening detection.
    Never guess.
    """
    hardening = {
        "nx": "unknown",
        "aslr": "unknown",
        "stack_canary": "unknown",
    }

    if re.search(r"\bNX enabled\b", text, re.IGNORECASE):
        hardening["nx"] = True
    elif re.search(r"\bNX disabled\b|\bno nx\b", text, re.IGNORECASE):
        hardening["nx"] = False

    if re.search(r"\bASLR enabled\b", text, re.IGNORECASE):
        hardening["aslr"] = True
    elif re.search(r"\bASLR disabled\b", text, re.IGNORECASE):
        hardening["aslr"] = False

    if re.search(r"\bstack protector\b|\bcanary\b", text, re.IGNORECASE):
        hardening["stack_canary"] = True

    return hardening


# ----------------------------
# Main parser
# ----------------------------

def parse_kernel_info(log_dir: Path) -> Dict:
    """
    Parse kernel metadata from EMBA output directories.
    """

    sources: List[str] = []
    text_blobs: List[str] = []

    candidate_dirs = [
        log_dir / "s24_kernel_bin_identifier",
        log_dir / "s25_kernel_check",
        log_dir / "s26_kernel_vuln_verifier",
        log_dir / "s02_firmware_bin_base_analyzer",
        log_dir / "csv_logs",
    ]

    # Read text-like artifacts
    for d in candidate_dirs:
        if d.exists() and d.is_dir():
            for ext in ("*.txt", "*.log", "*.out", "*.csv"):
                files = list(d.glob(ext))
                sources.extend(str(f) for f in files)
                text_blobs.extend(_read_text_files(files))

    # HTML report fallback (IMPORTANT)
    html_report = log_dir / "html-report" / "index.html"
    if html_report.exists():
        sources.append(str(html_report))
        try:
            text_blobs.append(html_report.read_text(errors="ignore"))
        except Exception:
            pass

    combined_text = "\n".join(text_blobs)

    kernel_version = _extract_kernel_version(combined_text)
    architecture = _extract_architecture(combined_text)
    compiler = _extract_compiler(combined_text)
    build_date = _extract_build_date(combined_text)
    hardening = _detect_hardening(combined_text)

    confidence = "low"
    if kernel_version and architecture:
        confidence = "high"
    elif kernel_version or architecture:
        confidence = "medium"

    return {
        "kernel_version": kernel_version,
        "architecture": architecture,
        "compiler": compiler,
        "build_date": build_date,
        "hardening": hardening,
        "confidence": confidence,
        "sources": sources,
    }

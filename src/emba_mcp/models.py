from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


# -----------------------------
# Core Identification Models
# -----------------------------

@dataclass
class DistributionInfo:
    vendor: Optional[str] = None
    device: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    architecture: Optional[str] = None
    confidence: str = "unknown"
    sources: List[str] = field(default_factory=list)
    raw: Optional[str] = None


@dataclass
class KernelInfo:
    kernel_version: Optional[str] = None
    architecture: Optional[str] = None
    compiler: Optional[str] = None
    build_date: Optional[str] = None
    hardening: Dict[str, Any] = field(default_factory=dict)
    confidence: str = "unknown"
    sources: List[str] = field(default_factory=list)
    raw: Optional[str] = None


@dataclass
class BootloaderInfo:
    name: Optional[str] = None
    version: Optional[str] = None
    type: Optional[str] = None   # u-boot, barebox, redboot, etc
    confidence: str = "unknown"
    sources: List[str] = field(default_factory=list)
    raw: Optional[str] = None


# -----------------------------
# Filesystem / SBOM
# -----------------------------

@dataclass
class FilesystemSummary:
    root: Optional[str]
    file_count: int
    directory_count: int
    interesting_paths: List[str] = field(default_factory=list)
    confidence: str = "unknown"


@dataclass
class SBOMPackage:
    name: str
    version: Optional[str] = None
    source: Optional[str] = None


@dataclass
class SBOMSummary:
    package_count: int
    packages: List[SBOMPackage] = field(default_factory=list)
    confidence: str = "unknown"
    sources: List[str] = field(default_factory=list)


# -----------------------------
# Security Findings
# -----------------------------

@dataclass
class CredentialFinding:
    path: str
    type: str                 # passwd, shadow, ssh_key, config, etc
    detail: Optional[str] = None


@dataclass
class PermissionIssue:
    path: str
    issue: str                # suid, sgid, world-writable
    severity: str = "medium"


@dataclass
class NetworkService:
    service: str              # http, ssh, telnet
    port: Optional[int]
    config_path: Optional[str] = None


@dataclass
class WeakCryptoFinding:
    path: str
    issue: str                # hardcoded key, weak cert, md5, etc
    severity: str = "high"


@dataclass
class BinaryProtection:
    binary: str
    nx: Optional[bool]
    pie: Optional[bool]
    relro: Optional[str]
    canary: Optional[bool]


@dataclass
class WeakFunctionFinding:
    binary: str
    function: str
    count: int
    analysis: str             # intense | radare


# -----------------------------
# Phase 2 – Correlation Layer
# -----------------------------

@dataclass
class HighRiskFinding:
    title: str
    description: str
    severity: str             # critical / high
    affected_components: List[str]
    evidence: Dict[str, Any]
    confidence: str = "medium"


@dataclass
class AttackPath:
    entry_point: str
    preconditions: List[str]
    exploitation_steps: List[str]
    impact: str
    related_findings: List[str]

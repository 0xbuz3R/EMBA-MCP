from pathlib import Path
from typing import Dict, List
from emba_mcp.filesystem import find_filesystem_root
from emba_mcp.emba_parsers.kernel import parse_kernel_info
from emba_mcp.emba_parsers.network_services import parse_network_services
from emba_mcp.emba_parsers.credentials import parse_credentials
from emba_mcp.emba_parsers.weak_crypto import parse_weak_crypto
from emba_mcp.emba_parsers.weak_functions import parse_weak_functions
from emba_mcp.emba_parsers.binary_protection import parse_binary_protections


def get_high_risk_findings(log_dir: Path) -> Dict:
    findings: List[Dict] = []

    fs_root = find_filesystem_root(log_dir)

    kernel     = parse_kernel_info(log_dir)
    services   = parse_network_services(log_dir, fs_root)
    creds      = parse_credentials(log_dir, fs_root)
    crypto     = parse_weak_crypto(log_dir, fs_root)
    weak_funcs = parse_weak_functions(log_dir)
    bin_prot   = parse_binary_protections(log_dir)

    # ---- Rule A: Telnet + credentials ----
    if "telnet" in services.get("services_detected", []) and creds.get("found"):
        findings.append({
            "title": "Telnet service with credentials present",
            "severity": "critical",
            "confidence": "high",
            "attack_vector": "remote",
            "components": ["telnet", "credentials"],
            "evidence": {
                "services": services,
                "credentials": creds,
            },
            "reasoning": (
                "Telnet provides unauthenticated remote access and credentials "
                "were found in the firmware, enabling trivial compromise."
            ),
        })

    # ---- Rule B: Old kernel + weak hardening ----
    if kernel.get("kernel_version"):
        major = int(kernel["kernel_version"].split(".")[0])
        if major < 4 and kernel.get("hardening", {}).get("nx") is False:
            findings.append({
                "title": "Old kernel with NX disabled",
                "severity": "high",
                "confidence": "medium",
                "attack_vector": "local/remote",
                "components": ["kernel"],
                "evidence": kernel,
                "reasoning": (
                    "Outdated kernel without NX significantly lowers exploitation cost."
                ),
            })

    # ---- Rule C: Weak crypto + credentials ----
    if crypto.get("summary", {}).get("weak_algorithms") and creds.get("found"):
        findings.append({
            "title": "Weak cryptography used for credential storage",
            "severity": "high",
            "confidence": "medium",
            "attack_vector": "offline",
            "components": ["crypto", "credentials"],
            "evidence": {
                "crypto": crypto,
                "credentials": creds,
            },
            "reasoning": (
                "Weak crypto combined with stored credentials enables offline attacks."
            ),
        })

    # ---- Rule D: Dangerous functions + SUID ----
    if weak_funcs.get("dangerous_calls") and bin_prot.get("suid_binaries"):
        findings.append({
            "title": "Dangerous functions in privileged binaries",
            "severity": "critical",
            "confidence": "high",
            "attack_vector": "local",
            "components": ["binary", "privilege escalation"],
            "evidence": {
                "functions": weak_funcs,
                "suid": bin_prot["suid_binaries"],
            },
            "reasoning": (
                "Unsafe functions inside SUID binaries allow privilege escalation."
            ),
        })

    return {
        "count": len(findings),
        "findings": findings,
    }

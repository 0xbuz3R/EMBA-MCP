from pathlib import Path
from typing import Dict, List

from emba_mcp.filesystem import find_filesystem_root
from emba_mcp.emba_parsers.kernel import parse_kernel_info
from emba_mcp.emba_parsers.network_services import parse_network_services
from emba_mcp.emba_parsers.credentials import parse_credentials
from emba_mcp.emba_parsers.weak_crypto import parse_weak_crypto
from emba_mcp.emba_parsers.weak_functions import parse_weak_functions
from emba_mcp.emba_parsers.binary_protection import parse_binary_protections


# ----------------------------
# Risk classification
# ----------------------------

HIGH_RISK_REMOTE_SERVICES = {
    "telnet",
    "ftp",
    "tftp",
}

AUTHENTICATED_REMOTE_SERVICES = {
    "ssh",
    "http",
    "https",
}


# ----------------------------
# Main analyzer
# ----------------------------

def get_high_risk_findings(log_dir: Path) -> Dict:
    findings: List[Dict] = []

    fs_root = find_filesystem_root(log_dir)

    kernel     = parse_kernel_info(log_dir)
    services   = parse_network_services(log_dir, fs_root)
    creds      = parse_credentials(log_dir, fs_root)
    crypto     = parse_weak_crypto(log_dir, fs_root)
    weak_funcs = parse_weak_functions(log_dir)
    bin_prot   = parse_binary_protections(log_dir)

    detected_services = set(services.get("services_detected", []))

    dangerous_services = detected_services & HIGH_RISK_REMOTE_SERVICES
    auth_services      = detected_services & AUTHENTICATED_REMOTE_SERVICES

    # --------------------------------------------------
    # Rule A: Remote service + credentials (GENERALIZED)
    # --------------------------------------------------
    if creds.get("found") and (dangerous_services or auth_services):
        findings.append({
            "title": "Remote service exposed with embedded credentials",
            "severity": "critical" if dangerous_services else "high",
            "confidence": "high",
            "attack_vector": "remote",
            "components": sorted(dangerous_services | auth_services | {"credentials"}),
            "evidence": {
                "services": services,
                "credentials": creds,
            },
            "reasoning": (
                "One or more remotely accessible services were detected together "
                "with embedded credentials. This enables authenticated or "
                "unauthenticated remote compromise depending on service behavior."
            ),
        })

    # --------------------------------------------------
    # Rule B: Insecure remote services (even without creds)
    # --------------------------------------------------
    if dangerous_services:
        findings.append({
            "title": "Insecure remote services exposed",
            "severity": "high",
            "confidence": "medium",
            "attack_vector": "remote",
            "components": sorted(dangerous_services),
            "evidence": services,
            "reasoning": (
                "Legacy or insecure remote services were detected. These services "
                "frequently lack authentication or use weak default configurations."
            ),
        })

    # --------------------------------------------------
    # Rule C: Old kernel + weak hardening
    # --------------------------------------------------
    if kernel.get("kernel_version"):
        try:
            major = int(kernel["kernel_version"].split(".")[0])
            if major < 4 and kernel.get("hardening", {}).get("nx") is False:
                findings.append({
                    "title": "Outdated kernel with NX disabled",
                    "severity": "high",
                    "confidence": "medium",
                    "attack_vector": "local/remote",
                    "components": ["kernel"],
                    "evidence": kernel,
                    "reasoning": (
                        "Outdated kernel combined with missing NX protection "
                        "significantly reduces exploit complexity."
                    ),
                })
        except Exception:
            pass

    # --------------------------------------------------
    # Rule D: Weak crypto + credentials
    # --------------------------------------------------
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
                "Weak cryptographic primitives were detected alongside stored "
                "credentials, enabling offline attacks."
            ),
        })

    # --------------------------------------------------
    # Rule E: Dangerous functions + privileged binaries
    # --------------------------------------------------
    if weak_funcs.get("dangerous_calls") and bin_prot.get("suid_binaries"):
        findings.append({
            "title": "Dangerous functions in privileged binaries",
            "severity": "critical",
            "confidence": "high",
            "attack_vector": "local",
            "components": ["binary", "privilege escalation"],
            "evidence": {
                "functions": weak_funcs,
                "suid_binaries": bin_prot.get("suid_binaries"),
            },
            "reasoning": (
                "Unsafe C library functions were detected inside privileged "
                "binaries, enabling reliable local privilege escalation."
            ),
        })

    return {
        "count": len(findings),
        "findings": findings,
    }

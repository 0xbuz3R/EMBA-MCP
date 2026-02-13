from typing import Dict
from pathlib import Path

from emba_mcp.emba_analyzers.high_risk import get_high_risk_findings


def explain_attack_path(log_dir: Path, finding_index: int = 0) -> Dict:
    """
    Explain a realistic attack path for a given high-risk finding.
    """

    data = get_high_risk_findings(log_dir)

    if "error" in data:
        return {
            "error": data["error"],
            "confidence": "error",
        }

    findings = data.get("findings", [])

    if not findings:
        return {
            "error": "No high-risk findings available",
            "confidence": "low",
        }

    if finding_index < 0 or finding_index >= len(findings):
        return {
            "error": "Invalid finding index",
            "available_findings": len(findings),
        }

    f = findings[finding_index]

    components = set(f.get("components", []))
    severity = f.get("severity", "unknown")
    title = f.get("title", "Unnamed finding")

    # --------------------------------------------------
    # SERVICE + CREDENTIALS (ANY NETWORK SERVICE)
    # --------------------------------------------------
    if "credentials" in components and any(
        s in components for s in {"telnet", "ssh", "ftp", "http", "tftp"}
    ):
        service = next(
            s for s in components if s in {"telnet", "ssh", "ftp", "http", "tftp"}
        )

        return {
            "title": title,
            "attack_vector": "remote",
            "entry_point": f"{service} service",
            "preconditions": [
                "Network access to the device",
                "Valid, default, or recoverable credentials",
            ],
            "exploit_class": "authenticated remote access",
            "attacker_effort": "low",
            "impact": "Remote shell / service abuse",
            "severity": severity,
            "confidence": "high",
            "why_this_matters": (
                f"The {service} service is reachable and credentials are "
                "embedded or recoverable, allowing direct remote compromise."
            ),
        }

    # --------------------------------------------------
    # KERNEL WEAKNESS
    # --------------------------------------------------
    if "kernel" in components:
        return {
            "title": title,
            "attack_vector": "local or remote",
            "entry_point": "kernel attack surface",
            "preconditions": [
                "Ability to reach kernel code paths (local or via services)",
            ],
            "exploit_class": "kernel privilege escalation / RCE",
            "attacker_effort": "medium",
            "impact": "Full device compromise",
            "severity": severity,
            "confidence": "medium",
            "why_this_matters": (
                "Outdated or weakly hardened kernels significantly reduce "
                "exploit complexity and reliability."
            ),
        }

    # --------------------------------------------------
    # LOCAL PRIVILEGE ESCALATION
    # --------------------------------------------------
    if {"binary", "privilege escalation"} <= components:
        return {
            "title": title,
            "attack_vector": "local",
            "entry_point": "privileged binary execution",
            "preconditions": [
                "Local execution capability",
            ],
            "exploit_class": "local privilege escalation",
            "attacker_effort": "medium",
            "impact": "Root privileges",
            "severity": severity,
            "confidence": "high",
            "why_this_matters": (
                "Dangerous functions inside privileged binaries allow attackers "
                "to hijack execution flow and escalate privileges."
            ),
        }

    # --------------------------------------------------
    # CRYPTO + SECRETS
    # --------------------------------------------------
    if {"crypto", "credentials"} <= components:
        return {
            "title": title,
            "attack_vector": "offline",
            "entry_point": "firmware secrets",
            "preconditions": [
                "Access to firmware image or filesystem",
            ],
            "exploit_class": "offline cracking / key recovery",
            "attacker_effort": "low to medium",
            "impact": "Credential disclosure / impersonation",
            "severity": severity,
            "confidence": "medium",
            "why_this_matters": (
                "Weak cryptography combined with embedded secrets enables "
                "offline attacks without device interaction."
            ),
        }

    # --------------------------------------------------
    # FALLBACK (FUTURE-PROOF)
    # --------------------------------------------------
    return {
        "title": title,
        "attack_vector": f.get("attack_vector", "unknown"),
        "exploit_class": "context-dependent",
        "severity": severity,
        "confidence": f.get("confidence", "low"),
        "why_this_matters": (
            "This finding represents a combination of weaknesses whose "
            "exploitability depends on deployment and runtime conditions."
        ),
    }

from typing import Dict
from pathlib import Path

from emba_mcp.emba_analyzers.high_risk import get_high_risk_findings


def explain_attack_path(log_dir: Path, finding_index: int = 0) -> Dict:
    """
    Explain a realistic attack path for a given high-risk finding.
    """

    data = get_high_risk_findings(log_dir)

    # 🛡️ defensive guard
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

    # ---- Rule-based explanation ----

    if {"telnet", "credentials"} <= components:
        return {
            "title": f["title"],
            "attack_vector": "remote",
            "entry_point": "telnet service",
            "preconditions": [
                "Network access to the device",
                "Valid or default credentials",
            ],
            "exploit_class": "authentication bypass / remote shell access",
            "attacker_effort": "low",
            "impact": "Full device compromise",
            "severity": severity,
            "confidence": "high",
            "why_this_matters": (
                "Telnet transmits credentials in cleartext and provides "
                "direct shell access. Combined with embedded credentials, "
                "this allows trivial compromise of the device."
            ),
        }

    if "kernel" in components:
        return {
            "title": f["title"],
            "attack_vector": "local or remote",
            "entry_point": "kernel memory corruption vulnerability",
            "preconditions": [
                "Ability to trigger kernel code paths",
            ],
            "exploit_class": "kernel privilege escalation / RCE",
            "attacker_effort": "medium",
            "impact": "Root access to device",
            "severity": severity,
            "confidence": "medium",
            "why_this_matters": (
                "Outdated kernels without modern hardening significantly "
                "reduce the complexity and cost of exploitation."
            ),
        }

    if {"binary", "privilege escalation"} <= components:
        return {
            "title": f["title"],
            "attack_vector": "local",
            "entry_point": "privileged binary execution",
            "preconditions": [
                "Ability to execute local binaries",
            ],
            "exploit_class": "local privilege escalation",
            "attacker_effort": "medium",
            "impact": "Root privileges",
            "severity": severity,
            "confidence": "high",
            "why_this_matters": (
                "Unsafe libc calls inside privileged binaries enable attackers "
                "to hijack execution flow and escalate privileges."
            ),
        }

    # ---- Fallback ----
    return {
        "title": f["title"],
        "attack_vector": f.get("attack_vector", "unknown"),
        "exploit_class": "context-dependent",
        "severity": severity,
        "confidence": f.get("confidence", "low"),
        "why_this_matters": (
            "This finding represents a combination of weaknesses whose "
            "exploitability depends on runtime conditions."
        ),
    }

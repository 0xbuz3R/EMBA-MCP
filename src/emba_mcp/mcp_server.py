from mcp.server.fastmcp import FastMCP, Context

# -------------------------
# Parsers
# -------------------------
from emba_mcp.emba_parsers.interesting_files import parse_interesting_files
from emba_mcp.emba_parsers.distribution import parse_distribution
from emba_mcp.emba_parsers.kernel import parse_kernel_info
from emba_mcp.emba_parsers.bootloader import parse_bootloader_info
from emba_mcp.emba_parsers.sbom import parse_sbom
from emba_mcp.emba_parsers.credentials import parse_credentials
from emba_mcp.emba_parsers.permissions import parse_permissions
from emba_mcp.emba_parsers.network_services import parse_network_services
from emba_mcp.emba_parsers.weak_crypto import parse_weak_crypto
from emba_mcp.emba_parsers.binary_protection import parse_binary_protections
from emba_mcp.emba_parsers.weak_functions import parse_weak_functions
from emba_mcp.emba_parsers.password_files import parse_password_files
from emba_mcp.emba_parsers.php_vulns import parse_php_vulnerabilities

# -------------------------
# Filesystem helpers
# -------------------------
from emba_mcp.filesystem import basic_filesystem_summary, find_filesystem_root

# -------------------------
# Analyzers
# -------------------------
from emba_mcp.emba_analyzers.high_risk import get_high_risk_findings
from emba_mcp.emba_analyzers.attack_path import explain_attack_path

# -------------------------
# EMBA runner + registry
# -------------------------
from emba_mcp.emba_runner.runner import start_emba_scan
from emba_mcp.emba_runner.registry import (
    get_scan,
    list_scans,
    stop_scan,
)

# -------------------------
# Stdlib
# -------------------------
import sys
import logging
from pathlib import Path

# --------------------------------------------------
# Logging (stderr only – MCP requirement)
# --------------------------------------------------
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(levelname)s %(message)s",
)
log = logging.getLogger("emba-mcp")

# --------------------------------------------------
# MCP Server
# --------------------------------------------------
mcp = FastMCP("EMBA-MCP")

# --------------------------------------------------
# Core helper (SOURCE OF TRUTH)
# --------------------------------------------------
def resolve_log_dir(log_dir: str) -> Path:
    p = Path(log_dir).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        raise RuntimeError(f"Invalid EMBA log directory: {p}")
    return p


def _safe(fn, *args):
    try:
        return fn(*args)
    except Exception as e:
        log.exception("Tool execution failed")
        return {"error": str(e), "confidence": "error"}

# --------------------------------------------------
# Parsing tools (scan_id OR log_dir)
# --------------------------------------------------

@mcp.tool(name="get_kernel_info")
def get_kernel_info(ctx: Context, log_dir: str) -> dict:
    p = Path(log_dir).expanduser().resolve()
    if not p.exists():
        return {"error": f"log_dir does not exist: {p}"}
    return parse_kernel_info(p)



@mcp.tool(name="get_distribution_info")
def get_distribution_info(ctx: Context, log_dir: str) -> dict:
    try:
        return parse_distribution(resolve_log_dir(log_dir))
    except Exception as e:
        return {"error": str(e), "confidence": "error"}



@mcp.tool(name="get_bootloader_info")
def get_bootloader_info(ctx: Context, log_dir: str) -> dict:
    return _safe(parse_bootloader_info, resolve_log_dir(log_dir))



@mcp.tool(name="get_sbom")
def get_sbom(ctx: Context, log_dir: str) -> dict:
    return _safe(parse_sbom, resolve_log_dir(log_dir))




@mcp.tool(name="get_filesystem_overview")
def get_filesystem_overview(ctx: Context, log_dir: str) -> dict:
    return _safe(basic_filesystem_summary, resolve_log_dir(log_dir))


@mcp.tool(name="get_interesting_files")
def get_interesting_files(ctx: Context, log_dir: str) -> dict:
    return _safe(parse_interesting_files, resolve_log_dir(log_dir))



@mcp.tool(name="get_credentials_and_secrets")
def get_credentials_and_secrets(ctx: Context, log_dir: str) -> dict:
    try:
        p = resolve_log_dir(log_dir)
        fs_root = find_filesystem_root(p)
        return parse_credentials(p, fs_root)
    except Exception as e:
        return {"error": str(e), "confidence": "error"}



@mcp.tool(name="get_permissions_issues")
def get_permissions_issues(ctx: Context, log_dir: str) -> dict:
    log_path = resolve_log_dir(log_dir)
    fs_root = find_filesystem_root(log_path)
    return _safe(parse_permissions, log_path, fs_root)



@mcp.tool(name="get_network_services")
def get_network_services(ctx: Context, log_dir: str) -> dict:
    try:
        log_path = resolve_log_dir(log_dir)
        fs_root = find_filesystem_root(log_path)
        return parse_network_services(log_path, fs_root)
    except Exception as e:
        log.exception("Network services tool failed")
        return {"error": str(e), "confidence": "error"}





@mcp.tool(name="get_weak_crypto_and_keys")
def get_weak_crypto_and_keys(ctx: Context, log_dir: str) -> dict:
    log_path = resolve_log_dir(log_dir)
    fs_root = find_filesystem_root(log_path)
    return _safe(parse_weak_crypto, log_path, fs_root)


@mcp.tool(name="get_binary_protection_mechanisms")
def get_binary_protection_mechanisms(ctx: Context, log_dir: str) -> dict:
    return _safe(parse_binary_protections, resolve_log_dir(log_dir))


@mcp.tool(name="get_weak_functions")
def get_weak_functions(ctx: Context, log_dir: str) -> dict:
    try:
        return parse_weak_functions(resolve_log_dir(log_dir))
    except Exception as e:
        return {"error": str(e), "confidence": "error"}



@mcp.tool(name="search_password_files")
def search_password_files(ctx: Context, log_dir: str) -> dict:
    return _safe(parse_password_files, resolve_log_dir(log_dir))



@mcp.tool(name="get_high_risk_findings")
def get_high_risk_findings_tool(ctx: Context, log_dir: str) -> dict:
    return _safe(get_high_risk_findings, resolve_log_dir(log_dir))



@mcp.tool(name="explain_attack_path")
def explain_attack_path_tool(
    ctx: Context,
    log_dir: str,
    finding_index: int = 0,
) -> dict:
    return _safe(
        explain_attack_path,
        resolve_log_dir(log_dir),
        finding_index,
    )


@mcp.tool(name="get_php_vulnerabilities")
def get_php_vulnerabilities(ctx: Context,log_dir: str) -> dict:
    return _safe(parse_php_vulnerabilities, resolve_log_dir(log_dir))



# -------------------------------------------------
# Scan lifecycle tools
# --------------------------------------------------

@mcp.tool(name="run_emba_scan")
def run_emba_scan(ctx: Context, firmware_path: str, log_base_dir: str, force_overwrite: bool = False) -> dict:
    return start_emba_scan(
        firmware_path=Path(firmware_path),
        base_log_dir=Path(log_base_dir),
        force_overwrite=force_overwrite,
    )


@mcp.tool(name="get_emba_scan_status")
def get_emba_scan_status(ctx: Context, scan_id: str) -> dict:
    return get_scan(scan_id)


@mcp.tool(name="list_emba_scans")
def list_emba_scans_tool(ctx: Context) -> dict:
    return list_scans()


@mcp.tool(name="stop_emba_scan")
def stop_emba_scan_tool(ctx: Context, scan_id: str) -> dict:
    return stop_scan(scan_id)

# --------------------------------------------------
if __name__ == "__main__":
    mcp.run()

🧠 EMBA-MCP

Model Context Protocol (MCP) server for EMBA firmware analysis. EMBA-MCP exposes EMBA firmware analysis results as structured tools via MCP, allowing LLMs (Claude, ChatGPT, etc.) to query, reason, and correlate firmware security findings programmatically.
It parses, normalizes, and reasons over EMBA output.


✨ Features

📦 Parse EMBA results (kernel, services, credentials, crypto, SBOM, binaries, PHP, etc.)
🔍 Filesystem-aware analysis (SUID, secrets, weak crypto, services)
🚨 High-risk correlation engine (multi-signal findings)
🧭 Attack-path explanation engine
🧠 MCP-native tools (plug into Claude / MCP clients)
🔁 Works with existing EMBA output (no re-scan required)


📋 Requirements
**System**
Linux (recommended: Ubuntu / Kali)
Python 3.10+
EMBA Tool
uvx

Python dependencies
mcp
pydantic

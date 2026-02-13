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


🛠️ Installation

```bash
git clone https://github.com/0xbuz3R/EMBA-MCP.git
cd EMBA-MCP

Set Up a Virtual Environment (Recommended)
Bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS:
source venv/bin/activate

3. Install Dependencies
Bash
pip install -e .


```

Make sure EMBA is installed in your local machine: **https://github.com/e-m-b-a/emba**

🧩 Claude Desktop MCP Configuration (Required)

To use EMBA-MCP inside Claude Desktop, you must register the MCP server in Claude’s config file.
This step is mandatory and is the most common setup issue.

📍 1. Locate claude_config_desktop.json

Claude Desktop stores the MCP configuration in the following location:

Linux

~/.config/claude/claude_config_desktop.json


If the file does not exist, create it manually.

📍 2. Add EMBA-MCP Server Configuration

Add the following JSON under the mcpServers section.

⚠️ Do NOT copy paths blindly — replace them with paths valid on your system.

``` json
{
  "mcpServers": {
    "emba": {
      "command": "<PATH_TO_PYTHON>",
      "args": ["-m", "emba_mcp.mcp_server"],
      "env": {
        "EMBA_HOME": "<PATH_TO_EMBA_DIRECTORY>"
      }
    }
  }
}

```

📌 3. How to Fill the Paths Correctly

🔹 PATH_TO_PYTHON

This must be the Python interpreter where EMBA-MCP is installed.
Examples:
``` bash
which python
which python3

```
Typical values:

/usr/bin/python3
/home/user/.venv/bin/python
/home/user/.local/bin/python

🔹 PATH_TO_EMBA_DIRECTORY

This must be the root directory of EMBA, where the emba executable exists.

Example:

ls <EMBA_HOME>/emba

Example value:

/home/user/tools/emba

📍 4. Restart Claude Desktop

After saving the file:
1. Fully close Claude Desktop
2. Reopen it

Claude will now auto-load the EMBA MCP server

✅ 5. Verify MCP Is Loaded

Inside Claude, try:

List EMBA scans
or
Run EMBA scan on firmware


If configured correctly, Claude will respond without MCP errors.

📽️ Demo



![demo](https://github.com/user-attachments/assets/7f81717e-181f-4ab1-80ad-5c038aeb007e)








## 🤝 Contributing & Feedback
I am still working on a few other data items to integrate; I'll update in the next release. 

Meanwhile, please give it a try and provide feedback on how to improve! You can leave your suggestions in our [Pinned Feedback Issue](LINK_TO_YOUR_ISSUE_HERE).
















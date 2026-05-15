# NexusGuard AI

NexusGuard AI is a defensive security assessment script centered on one current file:

```text
src/nexus.py
```

Older experiments, profile assets, and previous README drafts have been moved into `archive/deprecated/` so the active project is easier to understand and maintain.

## Current Repository Structure

```text
.
+-- README.md
+-- pyproject.toml
+-- uv.lock
+-- src/
|   +-- nexus.py
+-- archive/
|   +-- deprecated/
|       +-- Project_README.md
|       +-- purple_agentic.root.py
|       +-- source/
|           +-- README.md
|           +-- generate_profile_pic.py
|           +-- github_bio.md
|           +-- github_profile_pic.png
|           +-- purple_agentic.py
+-- source/
    +-- empty legacy directory
```

## Active File

`src/nexus.py` is the only current application file.

It provides an interactive defensive security assessment workflow with modules for:

- DNS reconnaissance
- Port and service scanning
- SSL/TLS checks
- HTTP security header review
- Sensitive path discovery
- Technology fingerprinting
- Subdomain enumeration
- Shodan intelligence, when `SHODAN_API_KEY` is configured
- WAF/CDN detection

The script generates TXT, JSON, and HTML reports after the scan review stage.

## Deprecated Files

Everything in `archive/deprecated/` is kept for reference only.

Those files should not be treated as part of the current application unless they are intentionally restored or rewritten. The old `purple_agentic.py` files describe a previous command-wrapper style project and are no longer the main direction of this repo.

## Requirements

Python dependencies are listed in:

```text
pyproject.toml
```

Create the local virtual environment and install dependencies with `uv`:

```bash
uv sync
```

The scanner also expects several external security tools to be installed on the host system depending on which modules you run, such as:

- `nmap`
- `dig`
- `whatweb`
- `wafw00f`

Some checks can still run without every tool installed, but missing tools will limit the available scan results.

## Usage

Run the active script from the project root:

```bash
uv run python src/nexus.py
```

The program will ask for:

1. A target domain or IP address
2. Confirmation that you are authorized to scan the target
3. Which assessment modules to run
4. Which findings to keep in the final report

Reports are written to the project root with names like:

```text
nexus_v6_report_YYYYMMDD_HHMMSS.txt
nexus_v6_report_YYYYMMDD_HHMMSS.json
nexus_v6_report_YYYYMMDD_HHMMSS.html
```

These generated report files are ignored by Git.

## Optional Configuration

Set a Shodan API key to enable the Shodan module:

```bash
export SHODAN_API_KEY="your_api_key_here"
```

On Windows PowerShell:

```powershell
$env:SHODAN_API_KEY = "your_api_key_here"
```

## Safety Notice

Only scan systems you own or have written permission to test. This project is intended for defensive assessment, authorized security testing, and lab use.

Unauthorized scanning can violate computer misuse laws and can disrupt systems.

## Maintenance Notes

- Keep active application code under `src/`.
- Use `uv` for virtual environments, dependency installation, and local runs.
- Keep generated reports out of version control.
- Put obsolete experiments under `archive/deprecated/` instead of mixing them with current code.
- Update this README whenever the active project structure changes.

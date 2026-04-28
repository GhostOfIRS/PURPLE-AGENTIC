PURPLE AGENTIC
=============

Overview
--------
`purple_agentic.py` is a command-line security assistant that wraps a large set of offensive and defensive security tools behind a single interactive prompt.

It combines two things:

1. A local language model created with `OllamaLLM(model="qwen2:0.5b")`
2. A menu of shell commands for reconnaissance, web testing, vulnerability checks, password attacks, system inspection, and basic post-exploitation enumeration

At a high level, the script lets a user type commands such as:

`run nmap example.com`

It then:

1. Chooses the matching Python wrapper function from a `tools` dictionary
2. Runs the underlying operating system command with `subprocess.run(...)`
3. Prints part of the command output
4. Sends a shortened version of that output to the language model
5. Prints the model's short analysis


What The Script Is Doing
------------------------
The file is organized as a lightweight command dispatcher.

- `run_tool(...)` is the shared executor. It runs an external command, captures stdout/stderr, applies a timeout, and returns the resulting text.
- `analyse(...)` sends the first 1000 characters of a tool's output to the local LLM and asks for a 3-bullet summary.
- Dozens of small `run_*` functions define individual tools. Each one builds a command line and passes it to `run_tool(...)`.
- A `tools` dictionary maps user-facing names such as `nmap`, `nikto`, `hydra`, `lynis`, or `whoami` to those wrapper functions.
- An infinite input loop provides a basic shell-like interface with `run`, `help`, and `exit`.


Main Tool Groups
----------------
The script groups its wrappers into several practical categories:

- Reconnaissance: `nmap`, `whois`, `dnsenum`, `dnsrecon`, `theHarvester`, `fierce`, `ping`, `traceroute`
- Web testing: `dirb`, `gobuster`, `nikto`, `sqlmap`, `wfuzz`, `whatweb`, `wafw00f`, `curl`
- Vulnerability scanning: Nmap NSE-based scans, `wpscan`, `enum4linux`, `sslscan`
- Password and credential attacks: `hydra`, `john`, `hashcat`, `medusa`
- Exploitation support: `searchsploit`
- Network inspection: `tcpdump`, `nc`, `netstat`, `ss`
- Wireless: `aircrack-ng`, `iwconfig`
- Defensive and host auditing: `lynis`, `chkrootkit`, `rkhunter`, log checks, service checks, open-port checks
- Post-exploitation and local enumeration: `linpeas`, `LinEnum`, `id`, `uname`, `ps`, `find` for SUID files
- Basic system helpers: `ifconfig`, `ip`, `whoami`, `hostname`, `cat`, `ls`

There are also a few bundled workflows:

- `full-audit` runs a small offensive audit sequence
- `full-defense-audit` runs a small defensive audit sequence


How Interaction Works
---------------------
The prompt supports three main paths:

- `help`: prints the available tool names
- `run <toolname> <target>`: executes a wrapper and then asks the LLM to summarize the result
- Any other text: sends the text directly to the local LLM as a plain chat prompt

That means the script acts partly like a scanner launcher and partly like a very small chatbot.


Dependencies And Assumptions
----------------------------
This script assumes a Linux-style environment with many security tools already installed and reachable on `PATH`.

Examples include:

- `nmap`
- `nikto`
- `sqlmap`
- `gobuster`
- `hydra`
- `john`
- `hashcat`
- `lynis`
- `rkhunter`
- `aircrack-ng`

It also assumes:

- Ollama is installed and running
- The `qwen2:0.5b` model is available locally
- Wordlists exist in places like `/usr/share/wordlists/rockyou.txt`
- Optional scripts such as `~/tools/linpeas.sh` and `~/tools/LinEnum.sh` are already present


Important Limitations
---------------------
The script is useful as a launcher, but it is not a full agent framework.

- It does not plan multi-step operations on its own.
- It does not validate that a target is the right kind of input for each tool.
- It truncates displayed output and analysis input, so important findings can be missed.
- It trusts raw command output enough to feed it straight into the LLM for interpretation.
- It is tightly coupled to a Linux penetration-testing setup.


In Short
--------
`purple_agentic.py` is a local purple-team helper that gives one interactive interface for running many common security tools, then uses a small local language model to summarize their results. It is best understood as a command wrapper plus LLM-based result summarizer, not as a fully autonomous security agent.

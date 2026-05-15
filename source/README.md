# PURPLE AGENTIC

## Extended Description

`purple_agentic.py` is a terminal-based purple team assistant that brings together offensive security tooling, defensive host inspection, and lightweight LLM summarization in a single interactive workflow. Its goal is to make common security tasks easier to launch and easier to interpret by giving the user one prompt where they can run tools, inspect results, and ask a small local language model for a short explanation of what those results mean.

The script is called "purple" because it blends red-team style actions such as scanning, enumeration, and web assessment with blue-team style checks such as service inspection, log review, host hardening review, and open-port monitoring. Rather than acting as a full autonomous agent that decides what to do next, it behaves more like a command hub: it runs the tool you ask for, captures the output, and then asks the model to summarize the output in simple bullet points.

In practice, this makes it useful as a learning aid, a personal lab helper, or a quick launcher for common tasks in a Linux security environment. It is especially suited to situations where you already know which tool you want to run but want a simpler interface and a brief plain-language recap of the results.

## What The Script Actually Does

The file is organized around three core responsibilities:

1. It loads a local Ollama-backed language model using `langchain_ollama`.
2. It defines a large set of wrappers for external security tools.
3. It starts an interactive command loop where the user can launch tools or chat with the model.

When a user enters a command such as:

```text
run nmap 192.168.1.10
```

the script follows a straightforward flow:

1. It parses the input and extracts the tool name and target.
2. It looks up the matching function in the `tools` dictionary.
3. That function builds a command-line argument list for the selected external program.
4. The shared `run_tool(...)` helper executes the command with `subprocess.run(...)`.
5. The script prints part of the raw result to the console.
6. The `analyse(...)` helper sends a shortened slice of that output to the local LLM.
7. The model returns a short summary, which is then shown to the user.

So the script is not scanning by itself in a native Python way. It is mainly orchestrating already existing command-line tools and then using the model as a summarizer sitting on top of those tools.

## Main Architecture

### 1. Shared command runner

`run_tool(command, timeout=120)` is the central execution function. Nearly every feature in the file depends on it. It is responsible for:

- launching the external command
- capturing standard output and standard error
- applying a timeout so commands do not run forever
- returning text back to the calling wrapper

This helper gives the rest of the file a consistent pattern. Each specific tool function only needs to define the right command arguments.

### 2. LLM-based analysis layer

`analyse(tool, target, output)` is the interpretation step. It sends a prompt to the local model asking it to analyze the tool output in three bullet points. Only the first 1000 characters of output are forwarded, which keeps prompts small but can also hide important findings if the real result is longer.

This means the model is being used as an explainer, not as the system that performs the actual scan. The real work is still done by programs such as `nmap`, `nikto`, `hydra`, `lynis`, and others.

### 3. Tool wrapper layer

Most of the file consists of many small functions named like `run_nmap`, `run_nikto`, `run_lynis`, and `run_whoami`. Each one wraps a single external utility by passing a fixed set of arguments to `run_tool(...)`.

This design makes the code easy to extend. To add another capability, the author would normally:

1. create a new wrapper function
2. add it to the `tools` dictionary
3. call it using `run <toolname> <target>`

### 4. Interactive shell loop

At the bottom of the file, the script prints a banner and enters a continuous `while True` input loop. This loop gives the program its shell-like behavior.

It supports:

- `help` to list all available tool names
- `run <toolname> <target>` to execute a tool wrapper
- `exit` to stop the program
- any other text as a direct prompt to the LLM

That last behavior turns the script into a hybrid tool launcher and chatbot.

## Tool Categories

The tool registry is broad and covers a mix of offensive, defensive, and administrative workflows.

### Reconnaissance

These commands gather network and domain intelligence:

- `nmap`
- `nmap-full`
- `nmap-udp`
- `whois`
- `dnsenum`
- `dnsrecon`
- `harvester`
- `fierce`
- `ping`
- `traceroute`
- `netdiscover`
- `arp-scan`

These are used for target discovery, service mapping, DNS enumeration, and basic network visibility.

### Web assessment

These commands focus on web servers and web applications:

- `dirb`
- `gobuster`
- `gobuster-dns`
- `nikto`
- `sqlmap`
- `wfuzz`
- `whatweb`
- `wafw00f`
- `curl`

This group helps identify directories, technologies, potential injection points, and web misconfigurations.

### Vulnerability checks

These wrappers lean into service-specific or scripted vulnerability inspection:

- `vuln-scan`
- `vuln-full`
- `wpscan`
- `enum4linux`
- `sslscan`
- `smtp-vuln`
- `ftp-vuln`
- `smb-vuln`
- `http-vuln`
- `full-audit`

The `full-audit` helper is a mini workflow that chains a few offensive checks together and combines their output.

### Password and credential attacks

These wrappers support password spraying, cracking, or basic brute-force style usage:

- `hydra`
- `hydra-http`
- `john`
- `hashcat`
- `medusa`

This section assumes common wordlists exist locally, especially `rockyou.txt`.

### Exploitation support

- `searchsploit`

This is meant for looking up exploit references related to discovered services or products.

### Network inspection

- `tcpdump`
- `netcat`
- `netstat`
- `ss`

These commands are useful for observing traffic, checking listening services, or validating connectivity.

### Wireless

- `aircrack`
- `iwconfig`

These are aimed at wireless assessment environments where the required tools and permissions already exist.

### Defensive and host-audit checks

- `lynis`
- `chkrootkit`
- `rkhunter`
- `fail2ban`
- `ufw-status`
- `open-ports`
- `active-connections`
- `check-users`
- `check-sudoers`
- `check-crons`
- `check-logs`
- `auth-logs`
- `check-processes`
- `check-startup`
- `disk-usage`
- `check-updates`
- `full-defense-audit`

This side of the script is what makes it "purple" rather than purely offensive. It allows the same interface to be used for system visibility and defensive review.

### Post-exploitation and local enumeration

- `linpeas`
- `linenum`
- `id`
- `uname`
- `ps`
- `find-suid`

These commands are geared toward privilege escalation review and local system profiling after access has already been obtained.

### General system utilities

- `ifconfig`
- `ip`
- `whoami`
- `hostname`
- `cat`
- `ls`

These helpers make the prompt more flexible by exposing a few basic host inspection actions.

## Why This Can Be Useful

This script lowers the friction of using a large toolset by giving everything one consistent entry point. Instead of remembering exact flags for every tool, the user can rely on prebuilt wrappers. The extra LLM summary also makes it easier for beginners or busy operators to get a quick interpretation without manually reading every line of output first.

It can be useful for:

- home lab experimentation
- capture-the-flag practice
- security learning and demonstration
- quick service checks on systems you are authorized to assess
- blue-team host inspection in a Linux environment

## Operational Assumptions

The script assumes a fairly specific setup. It is not portable in a plug-and-play sense.

It expects:

- a Linux or Kali-style operating environment
- many external security tools installed and available on `PATH`
- Ollama installed and reachable locally
- the `qwen2:0.5b` model already downloaded
- local wordlists in standard Linux locations
- optional helper scripts like `linpeas.sh` and `LinEnum.sh` stored under `~/tools/`

Without those dependencies, many commands will fail even though the Python file itself can still start.

## Important Limitations

Although the interface looks agent-like, it is important to understand what it does not do.

- It does not independently choose the next best action.
- It does not maintain a structured memory of findings.
- It does not normalize or parse outputs into reliable structured data.
- It does not verify whether a command actually succeeded before summarizing the result in a meaningful way.
- It does not enforce target validation per tool.
- It truncates output before display and before LLM analysis.
- It depends heavily on external binaries and local filesystem conventions.

Because of that, it should be treated as a convenience wrapper, not as a full security automation platform.

## Security And Reliability Notes

The current design is simple, but that simplicity comes with a few tradeoffs:

- raw tool output is passed directly into the LLM summarizer
- failed commands may still be summarized like valid findings
- some wrappers assume very specific target formats
- the script executes immediately on import because the shell loop is not isolated behind a `main()` guard

Those issues do not make the project useless, but they do matter if the script is going to be used beyond a personal lab environment.

## Summary

`purple_agentic.py` is best described as a local purple-team command console with LLM-assisted output explanation. It brings a wide set of red-team, blue-team, and host-inspection commands into one interactive interface, then uses a small local model to translate raw command output into short human-readable summaries. Its strength is convenience and breadth, while its main weakness is that it remains a thin wrapper around external tools rather than a deeply structured or safety-hardened agent system.

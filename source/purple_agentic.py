from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import subprocess
import os

llm = OllamaLLM(model="qwen2:0.5b", timeout=30)

def run_tool(command: list, timeout=120) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.stdout or result.stderr or "No output returned"
    except subprocess.TimeoutExpired:
        return f"Tool timed out after {timeout} seconds"
    except FileNotFoundError:
        return f"Tool not found: {command[0]}. Install with: sudo apt install {command[0]} -y"
    except Exception as e:
        return f"Error: {str(e)}"

def analyse(tool, target, output):
    try:
        result = llm.invoke(f"Analyse this {tool} output for {target} in 3 bullet points:\n{output[:1000]}")
        return result
    except Exception as e:
        return f"Analysis unavailable: {str(e)}"

# Recon
def run_nmap(t): return run_tool(["nmap", "-sV", "-sC", "-T4", t])
def run_nmap_full(t): return run_tool(["nmap", "-sV", "-sC", "-p-", "-T4", t], timeout=300)
def run_nmap_udp(t): return run_tool(["nmap", "-sU", "-T4", t], timeout=300)
def run_whois(t): return run_tool(["whois", t])
def run_dnsenum(t): return run_tool(["dnsenum", t])
def run_dnsrecon(t): return run_tool(["dnsrecon", "-d", t])
def run_harvester(t): return run_tool(["theHarvester", "-d", t, "-b", "all"])
def run_fierce(t): return run_tool(["fierce", "--domain", t])
def run_ping(t): return run_tool(["ping", "-c", "4", t])
def run_traceroute(t): return run_tool(["traceroute", t])
def run_netdiscover(t): return run_tool(["netdiscover", "-i", t, "-P"])
def run_arp_scan(t): return run_tool(["arp-scan", t])

# Web
def run_dirb(t): return run_tool(["dirb", t])
def run_gobuster(t): return run_tool(["gobuster", "dir", "-u", t, "-w", "/usr/share/wordlists/dirb/common.txt"])
def run_gobuster_dns(t): return run_tool(["gobuster", "dns", "-d", t, "-w", "/usr/share/wordlists/dirb/common.txt"])
def run_nikto(t): return run_tool(["nikto", "-h", t])
def run_sqlmap(t): return run_tool(["sqlmap", "-u", t, "--batch", "--level=1"])
def run_wfuzz(t): return run_tool(["wfuzz", "-c", "-z", "file,/usr/share/wordlists/dirb/common.txt", f"{t}/FUZZ"])
def run_whatweb(t): return run_tool(["whatweb", t])
def run_wafw00f(t): return run_tool(["wafw00f", t])
def run_curl(t): return run_tool(["curl", "-I", t])

# Vulnerability
def run_vuln_scan(t): return run_tool(["nmap", "--script", "vuln", "-T4", t], timeout=300)
def run_vuln_full(t): return run_tool(["nmap", "--script", "vuln,exploit", "-sV", t], timeout=300)
def run_wpscan(t): return run_tool(["wpscan", "--url", t, "--enumerate", "vp,u"])
def run_enum4linux(t): return run_tool(["enum4linux", "-a", t])
def run_sslscan(t): return run_tool(["sslscan", t])
def run_smtp_vuln(t): return run_tool(["nmap", "--script", "smtp-vuln*", "-p", "25", t])
def run_ftp_vuln(t): return run_tool(["nmap", "--script", "ftp-vuln*", "-p", "21", t])
def run_smb_vuln(t): return run_tool(["nmap", "--script", "smb-vuln*", "-p", "445", t])
def run_http_vuln(t): return run_tool(["nmap", "--script", "http-vuln*", "-p", "80,443", t])
def run_full_audit(t):
    results = []
    results.append("=== NMAP VULN SCAN ===")
    results.append(run_vuln_scan(t))
    results.append("=== WEB VULNERABILITIES ===")
    results.append(run_nikto(t))
    results.append("=== SMB VULNERABILITIES ===")
    results.append(run_smb_vuln(t))
    return "\n".join(results)

# Passwords
def run_hydra(t): return run_tool(["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", t, "ssh"])
def run_hydra_http(t): return run_tool(["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "-s", "80", t, "http-get"])
def run_john(t): return run_tool(["john", t, "--wordlist=/usr/share/wordlists/rockyou.txt"])
def run_hashcat(t): return run_tool(["hashcat", "-m", "0", t, "/usr/share/wordlists/rockyou.txt"])
def run_medusa(t): return run_tool(["medusa", "-h", t, "-u", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "-M", "ssh"])

# Exploitation
def run_searchsploit(t): return run_tool(["searchsploit", t])

# Network
def run_tcpdump(t): return run_tool(["tcpdump", "-i", t, "-c", "50"])
def run_netcat(t): return run_tool(["nc", "-zv"] + t.split())
def run_netstat(): return run_tool(["netstat", "-tulnp"])
def run_ss(): return run_tool(["ss", "-tulnp"])

# Wireless
def run_aircrack(t): return run_tool(["aircrack-ng", t, "-w", "/usr/share/wordlists/rockyou.txt"])
def run_iwconfig(): return run_tool(["iwconfig"])

# Defensive
def run_lynis(t): return run_tool(["lynis", "audit", "system"])
def run_chkrootkit(t): return run_tool(["chkrootkit"])
def run_rkhunter(t): return run_tool(["rkhunter", "--check", "--skip-keypress"])
def run_fail2ban_status(t): return run_tool(["fail2ban-client", "status"])
def run_ufw_status(t): return run_tool(["ufw", "status", "verbose"])
def run_open_ports(t): return run_tool(["ss", "-tulnp"])
def run_active_connections(t): return run_tool(["netstat", "-antp"])
def run_check_users(t): return run_tool(["cat", "/etc/passwd"])
def run_check_sudoers(t): return run_tool(["cat", "/etc/sudoers"])
def run_check_crons(t): return run_tool(["crontab", "-l"])
def run_check_logs(t): return run_tool(["tail", "-n", "50", "/var/log/syslog"])
def run_auth_logs(t): return run_tool(["tail", "-n", "50", "/var/log/auth.log"])
def run_check_processes(t): return run_tool(["ps", "aux", "--sort=-%cpu"])
def run_check_startup(t): return run_tool(["systemctl", "list-units", "--type=service", "--state=running"])
def run_disk_usage(t): return run_tool(["df", "-h"])
def run_check_updates(t): return run_tool(["apt", "list", "--upgradable"])
def run_full_defense_audit(t):
    results = []
    results.append("=== OPEN PORTS ===")
    results.append(run_open_ports(t))
    results.append("=== ACTIVE CONNECTIONS ===")
    results.append(run_active_connections(t))
    results.append("=== AUTH LOGS ===")
    results.append(run_auth_logs(t))
    results.append("=== RUNNING SERVICES ===")
    results.append(run_check_startup(t))
    return "\n".join(results)

# Post Exploitation
def run_linpeas():
    p = os.path.expanduser("~/tools/linpeas.sh")
    return run_tool(["bash", p]) if os.path.exists(p) else "Download from: https://github.com/carlospolop/PEASS-ng"
def run_linenum():
    p = os.path.expanduser("~/tools/LinEnum.sh")
    return run_tool(["bash", p]) if os.path.exists(p) else "Download from: https://github.com/rebootuser/LinEnum"
def run_id(): return run_tool(["id"])
def run_uname(): return run_tool(["uname", "-a"])
def run_ps(): return run_tool(["ps", "aux"])
def run_find_suid(): return run_tool(["find", "/", "-perm", "-4000", "-type", "f"])

# System
def run_ifconfig(): return run_tool(["ifconfig"])
def run_ip(): return run_tool(["ip", "a"])
def run_whoami(): return run_tool(["whoami"])
def run_hostname(): return run_tool(["hostname"])
def run_cat(t): return run_tool(["cat", t])
def run_ls(t): return run_tool(["ls", "-la", t or "."])

tools = {
    "nmap": run_nmap, "nmap-full": run_nmap_full, "nmap-udp": run_nmap_udp,
    "whois": run_whois, "dnsenum": run_dnsenum, "dnsrecon": run_dnsrecon,
    "harvester": run_harvester, "fierce": run_fierce, "ping": run_ping,
    "traceroute": run_traceroute, "netdiscover": run_netdiscover, "arp-scan": run_arp_scan,
    "dirb": run_dirb, "gobuster": run_gobuster, "gobuster-dns": run_gobuster_dns,
    "nikto": run_nikto, "sqlmap": run_sqlmap, "wfuzz": run_wfuzz,
    "whatweb": run_whatweb, "wafw00f": run_wafw00f, "curl": run_curl,
    "vuln-scan": run_vuln_scan, "vuln-full": run_vuln_full,
    "wpscan": run_wpscan, "enum4linux": run_enum4linux,
    "sslscan": run_sslscan, "smtp-vuln": run_smtp_vuln,
    "ftp-vuln": run_ftp_vuln, "smb-vuln": run_smb_vuln,
    "http-vuln": run_http_vuln, "full-audit": run_full_audit,
    "hydra": run_hydra, "hydra-http": run_hydra_http,
    "john": run_john, "hashcat": run_hashcat, "medusa": run_medusa,
    "searchsploit": run_searchsploit,
    "tcpdump": run_tcpdump, "netcat": run_netcat,
    "netstat": lambda t: run_netstat(), "ss": lambda t: run_ss(),
    "aircrack": run_aircrack, "iwconfig": lambda t: run_iwconfig(),
    "lynis": run_lynis, "chkrootkit": run_chkrootkit,
    "rkhunter": run_rkhunter, "fail2ban": run_fail2ban_status,
    "ufw-status": run_ufw_status, "open-ports": run_open_ports,
    "active-connections": run_active_connections, "check-users": run_check_users,
    "check-sudoers": run_check_sudoers, "check-crons": run_check_crons,
    "check-logs": run_check_logs, "auth-logs": run_auth_logs,
    "check-processes": run_check_processes, "check-startup": run_check_startup,
    "disk-usage": run_disk_usage, "check-updates": run_check_updates,
    "full-defense-audit": lambda t: run_full_defense_audit(t),
    "linpeas": lambda t: run_linpeas(), "linenum": lambda t: run_linenum(),
    "id": lambda t: run_id(), "uname": lambda t: run_uname(),
    "ps": lambda t: run_ps(), "find-suid": lambda t: run_find_suid(),
    "ifconfig": lambda t: run_ifconfig(), "ip": lambda t: run_ip(),
    "whoami": lambda t: run_whoami(), "hostname": lambda t: run_hostname(),
    "cat": run_cat, "ls": run_ls,
}

print("=" * 55)
print("   Purple Team Security Agent — Attack and Defend")
print("=" * 55)
print("\nRED TEAM:  nmap, vuln-scan, dirb, gobuster, nikto")
print("           sqlmap, hydra, searchsploit, full-audit")
print("BLUE TEAM: lynis, rkhunter, auth-logs, open-ports")
print("           active-connections, full-defense-audit")
print("RECON:     whois, dnsenum, ping, traceroute, fierce")
print("SYSTEM:    whoami, hostname, ifconfig, ps, uname")
print("\nUsage: run <toolname> <target>")
print("Type 'help' to list all tools | 'exit' to quit")
print("=" * 55 + "\n")

while True:
    user_input = input("You: ").strip()
    if not user_input:
        continue
    if user_input.lower() == "exit":
        print("\nShutting down. Stay secure!")
        break
    if user_input.lower() == "help":
        print("\nAll tools:", ", ".join(tools.keys()), "\n")
        continue
    if user_input.lower().startswith("run "):
        parts = user_input.split(None, 2)
        if len(parts) >= 2:
            tool_name = parts[1].lower()
            target = parts[2] if len(parts) > 2 else ""
            if tool_name in tools:
                print(f"\nRunning {tool_name}...\n")
                output = tools[tool_name](target)
                print(f"{'─'*50}")
                print(output[:3000])
                print(f"{'─'*50}")
                print("\nAnalysing...\n")
                print(analyse(tool_name, target, output))
                print()
            else:
                print(f"\nUnknown tool: '{tool_name}' — type 'help' to see all tools\n")
        else:
            print("\nUsage: run <toolname> <target>\n")
    else:
        try:
            response = llm.invoke(user_input)
            print(f"\nAgent: {response}\n")
        except Exception as e:
            print(f"\nError: {str(e)}\n")

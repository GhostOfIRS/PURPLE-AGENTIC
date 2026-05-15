#!/usr/bin/env python3

import subprocess
import requests
import socket
import ssl
import json
import os
import sys
import re
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ============================================================
# NEXUSGUARD AI v6 — Production Ready Defensive Framework
# ============================================================

BANNER = r"""
███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗ ██╗   ██╗ ██████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝ ██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║ ╚██╗ ██╔╝╚════██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║  ╚████╔╝ ███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝
         NEXUSGUARD AI v6 — PRODUCTION DEFENSIVE FRAMEWORK
"""

# ============================================================
# Colors
# ============================================================

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"

SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       3,
    "INFO":      0
}

SEVERITY_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
    "INFO":     C.CYAN
}

findings   = []
risk_score = 0
lock       = threading.Lock()
log_lines  = []

# ============================================================
# Logging
# ============================================================

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    log_lines.append(line)

# ============================================================
# Core Helpers
# ============================================================

def run(cmd, timeout=120, retries=2):
    """Run a shell command with automatic retry."""
    for attempt in range(retries + 1):
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            if attempt < retries:
                time.sleep(2)
            else:
                return "[!] Command timed out after retries"
        except Exception as e:
            return f"[ERROR] {e}"

def safe_request(url, retries=3, timeout=10, verify=True):
    """HTTP GET with retry, backoff, and fallback to HTTP."""
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=timeout, verify=verify,
                             allow_redirects=True,
                             headers={"User-Agent": "NexusGuard/6.0 SecurityScanner"})
            return r
        except requests.exceptions.SSLError:
            # Retry without SSL verification
            try:
                r = requests.get(url, timeout=timeout, verify=False,
                                 allow_redirects=True,
                                 headers={"User-Agent": "NexusGuard/6.0 SecurityScanner"})
                return r
            except Exception:
                pass
        except requests.exceptions.ConnectionError:
            # Try HTTP fallback
            if url.startswith("https://"):
                try:
                    r = requests.get(url.replace("https://", "http://"),
                                     timeout=timeout,
                                     headers={"User-Agent": "NexusGuard/6.0 SecurityScanner"})
                    return r
                except Exception:
                    pass
        except Exception:
            pass
        if attempt < retries - 1:
            time.sleep(2 ** attempt)  # exponential backoff
    return None

def resolve_target(target, retries=3):
    """Resolve hostname to IP with retry."""
    for attempt in range(retries):
        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror:
            if attempt < retries - 1:
                print(f"  {C.YELLOW}[RETRY {attempt+1}] DNS resolution failed, retrying...{C.RESET}")
                time.sleep(2)
    return None

def add_finding(title, severity, evidence, recommendation=""):
    global risk_score
    with lock:
        risk_score += SEVERITY_WEIGHT.get(severity, 0)
        col = SEVERITY_COLOR.get(severity, C.RESET)
        msg = f"  {col}[{severity}]{C.RESET} {title}"
        print(msg)
        log(f"[{severity}] {title} | {evidence[:80]}")
        findings.append({
            "title":          title,
            "severity":       severity,
            "evidence":       evidence,
            "recommendation": recommendation,
            "timestamp":      datetime.now().strftime("%H:%M:%S")
        })

def section(title):
    print(f"\n{C.BOLD}{C.BLUE}{'='*62}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'='*62}{C.RESET}\n")
    log(f"--- {title} ---")

def spinner(msg, stop_event):
    chars = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    while not stop_event.is_set():
        print(f"\r  {C.CYAN}{chars[i % len(chars)]}{C.RESET} {msg}   ", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r  {C.GREEN}✓{C.RESET} {msg}   ")

# ============================================================
# Pre-Flight Check
# ============================================================

def preflight_check(target):
    section("PRE-FLIGHT: Target Validation")

    # 1. Resolve
    print(f"  {C.DIM}Resolving {target}...{C.RESET}")
    ip = resolve_target(target, retries=3)
    if not ip:
        print(f"  {C.RED}[FAIL] Cannot resolve '{target}' after 3 attempts.{C.RESET}")
        print(f"  {C.YELLOW}Tips:{C.RESET}")
        print("    • Check your internet connection")
        print("    • Try: ping google.com")
        print("    • Use a real domain e.g. scanme.nmap.org")
        return False, None

    print(f"  {C.GREEN}[OK]{C.RESET} Resolved: {target} → {ip}")

    # 2. Ping check
    ping = run(f"ping -c 2 -W 2 {target}", timeout=10)
    if "0 received" in ping or "unreachable" in ping:
        print(f"  {C.YELLOW}[WARN]{C.RESET} Host may block ICMP — continuing anyway.")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET} Host is responding to ping.")

    # 3. HTTP reachability
    r = safe_request(f"https://{target}", retries=2, timeout=8)
    if r:
        print(f"  {C.GREEN}[OK]{C.RESET} HTTPS reachable — HTTP {r.status_code}")
    else:
        r = safe_request(f"http://{target}", retries=2, timeout=8)
        if r:
            print(f"  {C.YELLOW}[WARN]{C.RESET} Only HTTP reachable (no HTTPS) — HTTP {r.status_code}")
        else:
            print(f"  {C.YELLOW}[WARN]{C.RESET} HTTP/HTTPS not reachable — port scans will still run.")

    return True, ip

# ============================================================
# Authorization Gate
# ============================================================

def authorize(target):
    print(f"\n{C.RED}{C.BOLD}")
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║         LEGAL AUTHORIZATION REQUIRED        ║")
    print("  ║  Only scan systems you OWN or have WRITTEN  ║")
    print("  ║  permission to test. Unauthorized scanning  ║")
    print("  ║  is illegal under the CFAA and equivalents. ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(C.RESET)
    auth = input(f"  Do you have authorization to scan {C.BOLD}{target}{C.RESET}? (yes/no): ").strip().lower()
    return auth == "yes"

# ============================================================
# MODULE 1: DNS Recon
# ============================================================

def dns_recon(target):
    section("MODULE 1: DNS Reconnaissance")
    try:
        import dns.resolver
    except ImportError:
        print(f"  {C.YELLOW}[SKIP] dnspython not installed. Run: uv sync{C.RESET}")
        return

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5

    spf_found   = False
    dmarc_found = False

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            records = [r.to_text() for r in answers]
            add_finding(f"DNS {rtype} Record", "INFO", ", ".join(records))

            if rtype == "TXT":
                joined = " ".join(records)
                if "v=spf1" in joined:
                    spf_found = True
                if "v=DMARC1" in joined:
                    dmarc_found = True
        except Exception:
            pass

    if not spf_found:
        add_finding("Missing SPF Record", "MEDIUM",
                    "No SPF TXT record found",
                    "Add SPF record to prevent email spoofing.")
    if not dmarc_found:
        add_finding("Missing DMARC Record", "MEDIUM",
                    "No DMARC policy found",
                    "Implement DMARC to block phishing abuse of your domain.")

    # Zone transfer attempt
    try:
        ns_answers = resolver.resolve(target, "NS")
        for ns in ns_answers:
            zt = run(f"dig axfr {target} @{ns.to_text()} +time=3", timeout=8)
            if zt and len(zt) > 100 and "Transfer failed" not in zt:
                add_finding("DNS Zone Transfer ALLOWED", "CRITICAL",
                            f"Zone transfer succeeded via {ns.to_text()}",
                            "Restrict AXFR on all nameservers immediately.")
    except Exception:
        pass

# ============================================================
# MODULE 2: Port & Service Scan
# ============================================================

def network_scan(target):
    section("MODULE 2: Port & Service Discovery")

    stop = threading.Event()
    t = threading.Thread(target=spinner, args=("Running nmap scan (this may take ~60s)...", stop))
    t.start()

    output = run(f"nmap -Pn -sV -sC --top-ports 200 --open -T4 {target}", timeout=180)
    stop.set()
    t.join()

    if not output or "Failed to resolve" in output:
        print(f"  {C.YELLOW}[WARN]{C.RESET} Nmap could not scan target — may be offline or firewalled.")
        return

    dangerous = {
        "21":    ("FTP — unencrypted file transfer",        "HIGH"),
        "23":    ("Telnet — plaintext remote access",       "CRITICAL"),
        "25":    ("SMTP — open relay risk",                 "MEDIUM"),
        "110":   ("POP3 — unencrypted mail",                "MEDIUM"),
        "139":   ("NetBIOS — lateral movement risk",        "HIGH"),
        "445":   ("SMB — ransomware attack surface",        "HIGH"),
        "1433":  ("MSSQL exposed",                         "CRITICAL"),
        "3306":  ("MySQL exposed",                          "CRITICAL"),
        "3389":  ("RDP — brute force target",               "HIGH"),
        "4444":  ("Possible backdoor/C2",                   "CRITICAL"),
        "5432":  ("PostgreSQL exposed",                     "CRITICAL"),
        "5900":  ("VNC — remote desktop exposed",           "HIGH"),
        "6379":  ("Redis — no auth by default",             "CRITICAL"),
        "8080":  ("HTTP alt port — review content",         "LOW"),
        "8443":  ("HTTPS alt — review content",             "LOW"),
        "9200":  ("Elasticsearch — unauthenticated API",    "CRITICAL"),
        "27017": ("MongoDB — unauthenticated by default",   "CRITICAL"),
        "2375":  ("Docker API — full container control",    "CRITICAL"),
    }

    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0].strip()
            if port in dangerous:
                desc, sev = dangerous[port]
                add_finding(
                    f"Dangerous Port {port} Open: {desc}",
                    sev,
                    line.strip(),
                    f"Restrict port {port} with firewall rules. Use VPN or disable if unused."
                )
            else:
                add_finding(
                    f"Open Port {port}",
                    "LOW",
                    line.strip(),
                    "Verify this service is intentionally exposed."
                )

# ============================================================
# MODULE 3: SSL/TLS Analysis
# ============================================================

def ssl_scan(target):
    section("MODULE 3: SSL/TLS Analysis")

    # Certificate check
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(10)
            s.connect((target, 443))
            cert    = s.getpeercert()
            cipher  = s.cipher()

            # Expiry
            exp_str  = cert.get("notAfter", "")
            exp_dt   = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days     = (exp_dt - datetime.utcnow()).days
            sev      = "CRITICAL" if days < 7 else "HIGH" if days < 30 else "INFO"
            add_finding(f"SSL Certificate: {days} days until expiry", sev,
                        f"Expires: {exp_str}",
                        "Renew certificate ASAP." if days < 30 else "")

            # Cipher
            add_finding(f"Active Cipher: {cipher[0]}", "INFO", str(cipher))

            # Subject / SAN
            subject = dict(x[0] for x in cert.get("subject", []))
            san     = [v for t,v in cert.get("subjectAltName", []) if t == "DNS"]
            add_finding("Certificate Subject", "INFO",
                        f"CN={subject.get('commonName','?')} | SANs: {', '.join(san[:5])}")

    except ssl.SSLCertVerificationError as e:
        add_finding("SSL Certificate Verification FAILED", "CRITICAL", str(e),
                    "Fix certificate chain — browsers will show scary warnings.")
    except ssl.SSLError as e:
        add_finding("SSL Error", "HIGH", str(e), "Review SSL configuration.")
    except ConnectionRefusedError:
        add_finding("Port 443 Closed", "INFO", "No HTTPS listener on port 443.")
    except Exception as e:
        add_finding("SSL Check Failed", "INFO", str(e))

    # Weak protocol check
    stop = threading.Event()
    t = threading.Thread(target=spinner, args=("Checking cipher suites...", stop))
    t.start()
    cipher_out = run(f"nmap --script ssl-enum-ciphers -p 443 {target}", timeout=60)
    stop.set()
    t.join()

    if cipher_out:
        for weak in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
            if weak in cipher_out:
                add_finding(f"Weak Protocol Enabled: {weak}", "HIGH",
                            f"{weak} supported",
                            f"Disable {weak}. Only TLS 1.2 and TLS 1.3 should be allowed.")
        if "TLSv1.3" in cipher_out:
            add_finding("TLS 1.3 Supported", "INFO", "Modern TLS detected — good.")

# ============================================================
# MODULE 4: HTTP Security Headers
# ============================================================

def header_scan(target):
    section("MODULE 4: HTTP Security Headers & Cookies")

    headers_cfg = {
        "Strict-Transport-Security": ("HIGH",   "Set HSTS: max-age=31536000; includeSubDomains; preload"),
        "Content-Security-Policy":   ("HIGH",   "Define a strict CSP to prevent XSS."),
        "X-Frame-Options":           ("MEDIUM", "Set X-Frame-Options: DENY to prevent clickjacking."),
        "X-Content-Type-Options":    ("MEDIUM", "Set X-Content-Type-Options: nosniff"),
        "Referrer-Policy":           ("LOW",    "Set Referrer-Policy: strict-origin-when-cross-origin"),
        "Permissions-Policy":        ("LOW",    "Add Permissions-Policy to restrict APIs like camera/mic."),
        "X-XSS-Protection":          ("LOW",    "Set X-XSS-Protection: 1; mode=block"),
        "Cross-Origin-Opener-Policy":("LOW",    "Set COOP: same-origin"),
        "Cross-Origin-Resource-Policy":("LOW",  "Set CORP: same-origin"),
    }

    leak_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                    "X-Generator", "X-Drupal-Cache", "X-Runtime"]

    r = safe_request(f"https://{target}", retries=3, timeout=10)
    if not r:
        r = safe_request(f"http://{target}", retries=3, timeout=10)
    if not r:
        add_finding("Header Scan Failed", "INFO",
                    "Target not reachable via HTTP or HTTPS",
                    "Verify target is online and accessible.")
        return

    h = r.headers
    add_finding(f"HTTP Status: {r.status_code}", "INFO", r.url)

    # Security headers
    for header, (sev, rec) in headers_cfg.items():
        if header not in h:
            add_finding(f"Missing Header: {header}", sev, "Not present", rec)
        else:
            add_finding(f"Present: {header}", "INFO", h[header][:120])

    # Info leakage
    for lh in leak_headers:
        if lh in h:
            add_finding(f"Server Info Leaked: {lh}: {h[lh]}", "MEDIUM",
                        h[lh],
                        f"Remove or obscure the {lh} header.")

    # Cookies
    for cookie in r.cookies:
        issues = []
        if not cookie.secure:      issues.append("missing Secure flag")
        if "httponly" not in str(cookie.__dict__).lower(): issues.append("missing HttpOnly")
        if not cookie.has_nonstandard_attr("SameSite"):    issues.append("missing SameSite")
        if issues:
            add_finding(f"Insecure Cookie: {cookie.name}", "MEDIUM",
                        " | ".join(issues),
                        "Set Secure, HttpOnly, SameSite=Strict on all session cookies.")

# ============================================================
# MODULE 5: Sensitive Path Discovery
# ============================================================

def dir_scan(target):
    section("MODULE 5: Sensitive Path Discovery")

    paths = [
        # Config / secrets
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/config.php", "/wp-config.php", "/configuration.php",
        "/web.config", "/appsettings.json", "/database.yml",
        "/secrets.json", "/credentials.json",
        # Admin panels
        "/admin", "/administrator", "/admin/login", "/wp-admin",
        "/phpmyadmin", "/pma", "/adminer.php",
        "/cpanel", "/webmail", "/plesk",
        # APIs / Dev
        "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
        "/swagger-ui.html", "/openapi.json", "/api-docs",
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/actuator/metrics", "/actuator/beans",
        # Backup / Logs
        "/backup", "/backup.zip", "/backup.tar.gz",
        "/db.sql", "/dump.sql", "/site.sql",
        "/error.log", "/access.log", "/debug.log",
        # Info
        "/robots.txt", "/sitemap.xml", "/.htaccess",
        "/server-status", "/server-info", "/.DS_Store",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/phpinfo.php", "/info.php", "/test.php",
    ]

    critical_paths = {
        "/.env", "/.git/config", "/wp-config.php",
        "/actuator/heapdump", "/db.sql", "/dump.sql",
        "/phpinfo.php", "/adminer.php"
    }

    found = []

    def check(path):
        r = safe_request(f"https://{target}{path}", retries=1, timeout=6)
        if not r:
            r = safe_request(f"http://{target}{path}", retries=1, timeout=6)
        if r and r.status_code in [200, 301, 302, 403]:
            sev = "CRITICAL" if path in critical_paths and r.status_code == 200 \
                  else "HIGH" if r.status_code == 200 else "LOW"
            found.append((path, sev, r.status_code))

    stop = threading.Event()
    t = threading.Thread(target=spinner, args=(f"Checking {len(paths)} sensitive paths...", stop))
    t.start()

    with ThreadPoolExecutor(max_workers=15) as ex:
        ex.map(check, paths)

    stop.set()
    t.join()

    if not found:
        print(f"  {C.GREEN}[OK]{C.RESET} No sensitive paths exposed.")
    for path, sev, code in sorted(found, key=lambda x: x[1]):
        add_finding(f"Exposed Path: {path}", sev,
                    f"HTTP {code}",
                    f"Block access to {path} in server/firewall config.")

# ============================================================
# MODULE 6: Technology Fingerprinting
# ============================================================

def tech_scan(target):
    section("MODULE 6: Technology Fingerprinting")
    out = run(f"whatweb -a 3 {target} --no-errors", timeout=30)
    if out and len(out) > 10:
        add_finding("Technology Stack", "INFO", out[:600],
                    "Suppress version numbers in headers and error pages.")
    else:
        # Fallback: parse response headers ourselves
        r = safe_request(f"https://{target}", retries=2)
        if r:
            for h in ["Server", "X-Powered-By", "X-Generator"]:
                if h in r.headers:
                    add_finding(f"Tech via Header: {h}", "INFO", r.headers[h])
        else:
            add_finding("Tech Scan", "INFO", "WhatWeb unavailable and target unreachable.")

# ============================================================
# MODULE 7: Subdomain Enumeration
# ============================================================

def subdomain_enum(target):
    section("MODULE 7: Subdomain Enumeration")

    wordlist = [
        "www","mail","smtp","pop","imap","ftp","ssh","vpn",
        "remote","api","dev","test","staging","beta","alpha",
        "admin","administrator","portal","dashboard","panel",
        "shop","store","blog","forum","support","help","status",
        "secure","login","auth","sso","id","accounts",
        "app","apps","mobile","cdn","static","assets","media",
        "internal","corp","intranet","extranet","private",
        "db","mysql","postgres","redis","mongo","elastic",
        "jenkins","gitlab","github","jira","confluence","sonar",
        "git","svn","repo","registry","docker","k8s","kubernetes",
        "monitoring","grafana","kibana","prometheus","nagios",
        "backup","archive","old","legacy","demo","sandbox",
    ]

    found = []

    def check_sub(sub):
        hostname = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(hostname)
            found.append((hostname, ip))
        except Exception:
            pass

    stop = threading.Event()
    t = threading.Thread(target=spinner,
                         args=(f"Checking {len(wordlist)} subdomains...", stop))
    t.start()

    with ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(check_sub, wordlist)

    stop.set()
    t.join()

    if not found:
        print(f"  {C.DIM}No subdomains found from wordlist.{C.RESET}")
    for hostname, ip in sorted(found):
        sev = "HIGH" if any(w in hostname for w in
              ["dev","test","staging","internal","admin","db","jenkins","gitlab"]) else "INFO"
        add_finding(f"Subdomain: {hostname}", sev, f"→ {ip}",
                    "Audit forgotten/dev subdomains — common attack vector.")

# ============================================================
# MODULE 8: Shodan Intelligence
# ============================================================

def shodan_check(target, ip):
    section("MODULE 8: Shodan Intelligence")
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        print(f"  {C.YELLOW}[SKIP]{C.RESET} Set SHODAN_API_KEY env var to enable.")
        print(f"  {C.DIM}  export SHODAN_API_KEY=your_key_here{C.RESET}")
        return
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=10
        )
        data = r.json()
        if "error" in data:
            add_finding("Shodan", "INFO", data["error"])
            return
        vulns = data.get("vulns", [])
        for cve in vulns:
            add_finding(f"CVE: {cve}", "CRITICAL",
                        f"Shodan confirmed on {ip}",
                        f"Patch {cve} immediately — publicly known exploit exists.")
        ports = data.get("ports", [])
        if ports:
            add_finding("Shodan Open Ports", "INFO", str(ports))
        org = data.get("org", "Unknown")
        add_finding(f"Shodan Org: {org}", "INFO", f"IP: {ip}")
    except Exception as e:
        add_finding("Shodan Failed", "INFO", str(e))

# ============================================================
# MODULE 9: WAF Detection
# ============================================================

def waf_detect(target):
    section("MODULE 9: WAF / CDN Detection")
    out = run(f"wafw00f https://{target} -a 2>/dev/null", timeout=30)
    if out and "is behind" in out.lower():
        add_finding("WAF Detected", "INFO", out[:300],
                    "WAF is present — good. Ensure rules are tuned.")
    elif out and "no waf" in out.lower():
        add_finding("No WAF Detected", "HIGH",
                    "wafw00f found no WAF",
                    "Consider deploying a WAF (Cloudflare, AWS WAF, ModSecurity).")
    else:
        # Fallback: check headers for CDN clues
        r = safe_request(f"https://{target}", retries=2)
        if r:
            cdn_hints = {
                "cf-ray":       "Cloudflare",
                "x-amz-cf-id":  "AWS CloudFront",
                "x-cache":      "CDN Cache",
                "x-fastly-id":  "Fastly",
                "x-sucuri-id":  "Sucuri WAF",
            }
            detected = [name for h, name in cdn_hints.items() if h in {k.lower(): v for k,v in r.headers.items()}]
            if detected:
                add_finding(f"CDN/WAF via Headers: {', '.join(detected)}", "INFO",
                            "Detected from response headers")
            else:
                add_finding("No WAF/CDN Detected via Headers", "MEDIUM",
                            "No WAF signatures found",
                            "Consider a WAF to protect against automated attacks.")

# ============================================================
# Human Review
# ============================================================

def human_review():
    section("HUMAN REVIEW STAGE")

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sorted_findings = sorted(findings, key=lambda f: sev_order.index(f["severity"]))

    reviewed = []
    total    = len(sorted_findings)

    for i, f in enumerate(sorted_findings, 1):
        col = SEVERITY_COLOR.get(f["severity"], C.RESET)
        print(f"\n  {C.DIM}[{i}/{total}]{C.RESET}")
        print(f"  {C.BOLD}Finding     :{C.RESET} {f['title']}")
        print(f"  {col}Severity    :{C.RESET} {f['severity']}")
        print(f"  Evidence    : {f['evidence'][:150]}")
        if f["recommendation"]:
            print(f"  {C.GREEN}Fix         :{C.RESET} {f['recommendation']}")

        while True:
            action = input("\n  Keep? (y=yes / n=no / s=skip all remaining / q=accept all): ").strip().lower()
            if action in ["y", "n", "s", "q"]:
                break
        if action == "q":
            reviewed.extend(sorted_findings[i-1:])
            break
        if action == "s":
            break
        if action == "y":
            reviewed.append(f)

    return reviewed

# ============================================================
# Risk Rating
# ============================================================

def risk_rating(score):
    if score >= 120: return ("CRITICAL RISK", C.RED)
    if score >= 80:  return ("HIGH RISK",     C.RED)
    if score >= 40:  return ("MEDIUM RISK",   C.YELLOW)
    if score >= 10:  return ("LOW RISK",      C.GREEN)
    return ("MINIMAL RISK", C.CYAN)

# ============================================================
# Reports — TXT + HTML + JSON
# ============================================================

def generate_report(target, ip, reviewed):
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    rating, _ = risk_rating(risk_score)

    counts = {}
    for f in reviewed:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # ── TXT ──────────────────────────────────────────────────
    txt = f"nexus_v6_report_{ts}.txt"
    with open(txt, "w") as fh:
        fh.write("=" * 62 + "\n")
        fh.write("       NEXUSGUARD AI v6 — ASSESSMENT REPORT\n")
        fh.write("=" * 62 + "\n\n")
        fh.write(f"Target    : {target} ({ip})\n")
        fh.write(f"Generated : {datetime.now()}\n")
        fh.write(f"Risk Score: {risk_score} — {rating}\n\n")
        fh.write("Severity Breakdown:\n")
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            fh.write(f"  {s:10}: {counts.get(s,0)}\n")
        fh.write("\n" + "-"*62 + "\n\n")
        for i, f in enumerate(reviewed, 1):
            fh.write(f"[{i}] {f['title']}\n")
            fh.write(f"    Severity : {f['severity']}\n")
            fh.write(f"    Evidence : {f['evidence']}\n")
            if f["recommendation"]:
                fh.write(f"    Fix      : {f['recommendation']}\n")
            fh.write("\n")
        fh.write("\n--- SCAN LOG ---\n")
        fh.write("\n".join(log_lines))

    # ── JSON ─────────────────────────────────────────────────
    jsn = f"nexus_v6_report_{ts}.json"
    with open(jsn, "w") as fh:
        json.dump({
            "target": target, "ip": ip,
            "generated": str(datetime.now()),
            "risk_score": risk_score, "rating": rating,
            "counts": counts, "findings": reviewed
        }, fh, indent=2)

    # ── HTML ─────────────────────────────────────────────────
    sev_col = {
        "CRITICAL": "#ff3333", "HIGH": "#ff8800",
        "MEDIUM":   "#ffcc00", "LOW":  "#44cc44", "INFO": "#44aaff"
    }

    rows = ""
    for i, f in enumerate(reviewed, 1):
        col = sev_col.get(f["severity"], "#aaa")
        rows += f"""
        <tr>
          <td style="color:#888">{i}</td>
          <td>{f['title']}</td>
          <td style="color:{col};font-weight:bold">{f['severity']}</td>
          <td style="color:#bbb;font-size:12px">{f['evidence'][:200]}</td>
          <td style="color:#0f0;font-size:12px">{f['recommendation']}</td>
        </tr>"""

    bar = "".join(
        f'<span style="display:inline-block;background:{sev_col[s]};'
        f'width:{counts.get(s,0)*18}px;height:18px;margin:2px;'
        f'border-radius:3px" title="{s}: {counts.get(s,0)}"></span>'
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>NexusGuard v6 — {target}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Courier New',monospace;background:#080810;color:#ddd;padding:30px}}
  h1{{color:#00ffcc;font-size:24px;margin-bottom:6px}}
  h2{{color:#00aaff;font-size:16px;margin:24px 0 10px}}
  .meta{{color:#888;font-size:13px;margin-bottom:16px;line-height:1.8}}
  .score{{font-size:20px;font-weight:bold;color:#ff8800}}
  table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}}
  th{{background:#0d1117;color:#00ffcc;padding:10px;text-align:left;border-bottom:1px solid #222}}
  td{{border-bottom:1px solid #1a1a1a;padding:8px 10px;vertical-align:top}}
  tr:hover{{background:#0d1117}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold}}
  footer{{color:#444;font-size:11px;margin-top:30px;text-align:center}}
</style>
</head>
<body>
<h1>&#9632; NEXUSGUARD AI v6 — Security Assessment</h1>
<div class="meta">
  Target: <b style="color:#fff">{target}</b> ({ip})<br>
  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
  <span class="score">Risk Score: {risk_score} — {rating}</span>
</div>
<div>{bar}</div>
<div class="meta" style="margin-top:8px">
  {'  '.join(f'<span style="color:{sev_col[s]}">{s}: {counts.get(s,0)}</span>'
             for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"])}
</div>
<h2>Findings ({len(reviewed)} in report / {len(findings)} total)</h2>
<table>
  <tr><th>#</th><th>Finding</th><th>Severity</th><th>Evidence</th><th>Recommendation</th></tr>
  {rows}
</table>
<footer>NexusGuard AI v6 — Defensive Use Only</footer>
</body>
</html>"""

    htf = f"nexus_v6_report_{ts}.html"
    with open(htf, "w") as fh:
        fh.write(html)

    print(f"\n{C.BOLD}{C.GREEN}  Reports saved:{C.RESET}")
    print(f"  {C.GREEN}✓ TXT :{C.RESET} {txt}")
    print(f"  {C.GREEN}✓ JSON:{C.RESET} {jsn}")
    print(f"  {C.GREEN}✓ HTML:{C.RESET} {htf}")

# ============================================================
# Main
# ============================================================

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(C.CYAN + BANNER + C.RESET)

    target = input(f"{C.BOLD}  Enter target domain/IP: {C.RESET}").strip()
    if not target:
        print(f"{C.RED}[!] No target entered.{C.RESET}")
        sys.exit(1)

    # Strip protocol if user pastes a URL
    target = re.sub(r"^https?://", "", target).split("/")[0].strip()

    if not authorize(target):
        print(f"\n{C.RED}[!] Authorization not confirmed. Exiting.{C.RESET}")
        sys.exit(1)

    ok, ip = preflight_check(target)
    if not ok:
        sys.exit(1)

    # Module selection
    print(f"\n{C.CYAN}  Select modules or press Enter for ALL:{C.RESET}")
    print("  1=DNS  2=Ports  3=SSL  4=Headers  5=Paths")
    print("  6=Tech 7=Subdomains  8=Shodan  9=WAF")
    choice = input("  Modules (e.g. 1,2,4 or Enter for all): ").strip()

    all_modules = {
        "1": lambda: dns_recon(target),
        "2": lambda: network_scan(target),
        "3": lambda: ssl_scan(target),
        "4": lambda: header_scan(target),
        "5": lambda: dir_scan(target),
        "6": lambda: tech_scan(target),
        "7": lambda: subdomain_enum(target),
        "8": lambda: shodan_check(target, ip),
        "9": lambda: waf_detect(target),
    }

    selected = (
        list(all_modules.values())
        if not choice
        else [all_modules[c.strip()] for c in choice.split(",")
              if c.strip() in all_modules]
    )

    start = time.time()
    for module in selected:
        module()

    elapsed = round(time.time() - start, 1)

    # Summary
    rating, col = risk_rating(risk_score)
    print(f"\n{C.BOLD}{'='*62}{C.RESET}")
    print(f"  {col}{C.BOLD}RISK SCORE : {risk_score} — {rating}{C.RESET}")
    print(f"  Findings   : {len(findings)}")
    print(f"  Scan Time  : {elapsed}s")
    print(f"{C.BOLD}{'='*62}{C.RESET}")

    reviewed = human_review()
    generate_report(target, ip, reviewed)

    print(f"\n{C.CYAN}{C.BOLD}  NexusGuard v6 complete. Stay defensive.{C.RESET}\n")

if __name__ == "__main__":
    main()

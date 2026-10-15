#!/usr/bin/env python3
"""
Samiul IP Scanner v3 -- fast port scanner + banner grabbing + HTML reports
Developed by Samiul (https://github.com/samiul14)

Based on W8IPReverseInfo by W8Team / MD SOJIB (MIT License).
Original: https://github.com/W8SOJIB/W8IPReverseInfo
v2: bug fixes + speed (single-IP scan, /24 cap, progress display)
v3: rebranded to Samiul, banner grabbing on open ports, HTML reports.

USE ONLY ON SYSTEMS YOU OWN OR HAVE PERMISSION TO TEST
(e.g. your own site, your home router, scanme.nmap.org, TryHackMe labs).
"""

import asyncio
import html as htmlmod
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import ip_network
from urllib.parse import urlparse

import requests

# ---------- colors (work even if colorama is missing) ----------
try:
    from colorama import Fore, init
    init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = _NoColor()

# ---------- config ----------
CONNECT_TIMEOUT = 1.0      # seconds per port attempt
BANNER_TIMEOUT  = 2.0      # seconds to wait for a service banner
MAX_CONCURRENT  = 200      # simultaneous connections (safe for mobile data)
RANGE_WORKERS   = 50       # threads for IP-range server/title probing
HTTP_TIMEOUT    = 3        # seconds for server/title grab
TXT_LOG         = "scan_results.txt"
HTML_REPORT     = "scan_report.html"
GEO_API         = "https://ip-api.com/json/{ip}?fields=66846719"

# Ports where we politely ask for an HTTP response to grab the Server header
HTTP_PORTS = {80, 8000, 8008, 8010, 8020, 8080, 8081, 8088, 8090,
              8118, 8123, 8181, 8443, 8888, 9000, 9080, 9090}

# Fallback service labels for well-known ports
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP", 636: "LDAPS",
    873: "rsync", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 2181: "ZooKeeper",
    2222: "SSH-alt", 2375: "Docker", 2376: "Docker-TLS", 3000: "Dev",
    3128: "Proxy", 3306: "MySQL", 3389: "RDP", 3478: "STUN",
    4000: "Dev", 4444: "Alt", 5000: "UPnP/Dev", 5060: "SIP",
    5061: "SIP-TLS", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "RabbitMQ", 5900: "VNC", 5938: "TeamViewer", 5985: "WinRM",
    6000: "X11", 6379: "Redis", 6443: "Kubernetes", 6667: "IRC",
    7001: "WebLogic", 8000: "HTTP-alt", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "Sonar/PHP-FPM",
    9042: "Cassandra", 9100: "Print", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9999: "Alt", 10000: "Webmin",
    11211: "Memcached", 25565: "Minecraft", 27015: "Game", 27017: "MongoDB",
}

# Top 100 most commonly open ports -- the "quick" scan list
TOP_PORTS = [
    21, 22, 23, 25, 53, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 179, 389, 443, 445, 465, 514, 515, 587, 636, 873, 990,
    993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083,
    2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000, 3128,
    3306, 3389, 3478, 4000, 4444, 5000, 5001, 5060, 5061,
    5432, 5601, 5672, 5900, 5938, 5985, 5986, 6000, 6379, 6443, 6667, 7001,
    8000, 8008, 8009, 8010, 8020, 8080, 8081, 8088, 8090, 8118, 8123,
    8181, 8333, 8443, 8761, 8888, 9000, 9001, 9042, 9080, 9090,
    9100, 9200, 9300, 9999, 10000, 11211, 25565, 27015, 27017,
]

# In-memory HTML report sections (rebuilt into scan_report.html after each scan)
REPORT_SECTIONS = []


# ================= helpers =================
def ask(prompt):
    """input() that returns None on Ctrl+D / EOF instead of crashing."""
    try:
        return input(prompt)
    except EOFError:
        print()
        return None


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print(Fore.RED + r"""
  ____                   _       __
 / ___|  __ _ _ __ ___ (_)_   _| |
 \___ \ / _` | '_ ` _ \| | | | | |
  ___) | (_| | | | | | | | |_| | |
 |____/ \__,_|_| |_| |_|_|\__,_|_|
   IP SCANNER  v3
""")
    print(Fore.GREEN + "   Developed by Samiul  |  github.com/samiul14\n")


def esc(text):
    return htmlmod.escape(str(text) if text is not None else "")


def save_txt_header(title):
    with open(TXT_LOG, "a") as f:
        f.write("\n" + "=" * 50 + "\n")
        f.write("%s  %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), title))
        f.write("=" * 50 + "\n")


def save_txt_line(text):
    with open(TXT_LOG, "a") as f:
        f.write(text + "\n")


def add_report_section(title, inner_html):
    REPORT_SECTIONS.append(
        "<div class='card'><h2>%s</h2><div class='meta'>%s</div>%s</div>"
        % (esc(title), esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), inner_html))
    save_report()


def save_report():
    body = "\n".join(REPORT_SECTIONS) or "<p class='empty'>No scans yet.</p>"
    page = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Samiul IP Scanner - Report</title>
<style>
body{background:#0b0e14;color:#d7dce4;font-family:system-ui,Arial,sans-serif;margin:0;padding:16px}
h1{color:#ff4d5e;font-size:22px;margin:4px 0 2px}
.sub{color:#8b93a3;font-size:13px;margin-bottom:16px}
.card{background:#131722;border:1px solid #232a3a;border-radius:10px;padding:14px;margin-bottom:14px}
.card h2{font-size:16px;color:#7ee787;margin:0 0 2px}
.meta{color:#8b93a3;font-size:12px;margin-bottom:10px}
table{width:100%%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #232a3a;vertical-align:top}
th{color:#8b93a3;font-weight:600}
.open{color:#7ee787;font-weight:700}
.banner{color:#9ecbff;word-break:break-all}
.empty{color:#8b93a3}
.foot{color:#5b6373;font-size:11px;text-align:center;margin-top:18px}
</style></head>
<body>
<h1>Samiul IP Scanner</h1>
<div class="sub">Scan report &mdash; developed by Samiul</div>
%s
<div class="foot">Generated by Samiul IP Scanner v3 &mdash; use only on systems you own or have permission to test.</div>
</body></html>""" % body
    with open(HTML_REPORT, "w") as f:
        f.write(page)


def clean_domain(value):
    value = value.strip()
    if value.startswith("http"):
        value = urlparse(value).netloc or value
    return value.split("/")[0]


def resolve_target(target):
    """Return an IP for a domain, IP string, or None."""
    target = clean_domain(target)
    try:
        socket.inet_aton(target)  # already an IPv4 address?
        return target
    except OSError:
        pass
    try:
        return socket.gethostbyname(target)
    except OSError:
        return None


def parse_ports(spec):
    """'80' / '1-1000' / '80,443,8080' / '20-25,80' -> sorted unique list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                start, end = int(a), int(b)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for p in range(max(1, start), min(65535, end) + 1):
                ports.add(p)
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def extract_title(html):
    """Grab <title> keeping the original casing."""
    try:
        low = html.lower()
        i = low.find("<title>")
        if i != -1:
            j = low.find("</title>", i)
            if j != -1:
                return html[i + 7:j].strip() or None
    except Exception:
        pass
    return None


def clean_banner(data):
    """Turn raw banner bytes into a safe one-line string."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return ""
    # If it looks like HTTP, pull the Server header / status line
    if text.lstrip().upper().startswith("HTTP/"):
        m = re.search(r"(?im)^server:\s*(.+?)\s*$", text)
        if m:
            return "HTTP " + m.group(1).strip()[:100]
        first = text.splitlines()[0].strip() if text.splitlines() else ""
        return first[:100]
    line = text.splitlines()[0] if text.splitlines() else ""
    line = "".join(c for c in line if c.isprintable()).strip()
    return line[:100]


# ================= option 1: domain -> IP + info =================
def domain_lookup():
    target = ask("Domain / IP > ")
    if target is None:
        return
    target = target.strip()
    if not target:
        return

    print(Fore.YELLOW + "\n[...] Resolving...\n")
    ip = resolve_target(target)
    if not ip:
        print(Fore.RED + "[!] Could not resolve. Check the domain and try again.\n")
        return

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        hostname = "Not found"

    try:
        geo = requests.get(GEO_API.format(ip=ip), timeout=5).json()
    except Exception:
        geo = {}

    rows = [
        ("Domain", clean_domain(target)), ("IP", ip), ("Hostname", hostname),
        ("Country", geo.get("country", "Unknown")), ("City", geo.get("city", "Unknown")),
        ("ISP", geo.get("isp", "Unknown")), ("Org", geo.get("org", "Unknown")),
        ("ASN", geo.get("as", "Unknown")),
    ]
    print(Fore.GREEN + "=" * 46)
    for k, v in rows:
        print(Fore.GREEN + "  %-9s: %s" % (k, v))
    print(Fore.GREEN + "=" * 46 + "\n")

    save_txt_header("Domain lookup: %s -> %s" % (target, ip))
    save_txt_line(" | ".join("%s: %s" % (k, v) for k, v in rows))
    add_report_section(
        "Domain lookup: %s" % clean_domain(target),
        "<table>" + "".join(
            "<tr><th>%s</th><td>%s</td></tr>" % (esc(k), esc(v)) for k, v in rows)
        + "</table>")
    print(Fore.CYAN + "  Saved -> %s, %s\n" % (TXT_LOG, HTML_REPORT))


# ================= option 3: IP range scan =================
def probe_host(ip):
    """Reverse DNS + HTTP server/title probe for one IP. Returns a dict."""
    info = {"ip": ip, "hostname": None, "server": None, "title": None}
    try:
        info["hostname"] = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass
    try:
        r = requests.get("http://%s" % ip, timeout=HTTP_TIMEOUT)
        info["server"] = r.headers.get("Server")
        info["title"] = extract_title(r.text)
    except Exception:
        pass
    return info


def range_scan():
    cidr = ask("CIDR (e.g. 192.168.1.0/24 -- /24 or smaller only) > ")
    if cidr is None:
        return
    cidr = cidr.strip()
    try:
        network = ip_network(cidr, strict=False)
    except ValueError:
        print(Fore.RED + "[!] Invalid CIDR.\n")
        return

    # Safety: refuse ranges bigger than a /24 (would be 512+ hosts, slow + noisy)
    if network.prefixlen < 24:
        print(Fore.RED + "[!] Too big: %s has %d addresses." % (cidr, network.num_addresses))
        print(Fore.YELLOW + "    Only /24 or smaller is allowed (max 256 hosts).\n")
        return

    hosts = [str(h) for h in network.hosts()]
    print(Fore.YELLOW + "\n[*] Probing %d hosts...\n" % len(hosts))
    save_txt_header("Range scan: %s (%d hosts)" % (cidr, len(hosts)))

    found_rows = []
    try:
        with ThreadPoolExecutor(max_workers=RANGE_WORKERS) as pool:
            futures = {pool.submit(probe_host, ip): ip for ip in hosts}
            done = 0
            for fut in as_completed(futures):
                done += 1
                info = fut.result()
                ip, hn, srv, title = (info["ip"], info["hostname"],
                                     info["server"], info["title"])
                if hn or srv:
                    found_rows.append((ip, hn or "-", srv or "-", title or "-"))
                    print(Fore.GREEN + "[+] %s" % ip)
                    if hn:
                        print(Fore.CYAN + "    Hostname : %s" % hn)
                    if srv:
                        print(Fore.YELLOW + "    Server   : %s" % srv)
                    if title:
                        print(Fore.BLUE + "    Title    : %s" % title)
                    save_txt_line("%s | Hostname: %s | Server: %s | Title: %s"
                                  % (ip, hn, srv, title))
                if done % 25 == 0 or done == len(hosts):
                    print(Fore.CYAN + "    ... %d/%d hosts probed" % (done, len(hosts)),
                          end="\r", flush=True)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopped by user.\n")
        return

    print(Fore.GREEN + "\n[OK] Done: %d hosts probed, %d responded."
          % (len(hosts), len(found_rows)))
    if found_rows:
        table = ("<table><tr><th>IP</th><th>Hostname</th><th>Server</th>"
                 "<th>Title</th></tr>" + "".join(
                     "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                     % tuple(esc(c) for c in row) for row in found_rows) + "</table>")
    else:
        table = "<p class='empty'>No hosts responded.</p>"
    add_report_section("Range scan: %s (%d hosts)" % (cidr, len(hosts)), table)
    print(Fore.CYAN + "  Saved -> %s, %s\n" % (TXT_LOG, HTML_REPORT))


# ================= option 2: port scan + banner grabbing =================
async def check_port(ip, port, sem, state):
    async with sem:
        try:
            _r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            state["open"].append(port)
            print(Fore.GREEN + "  [OPEN] %d" % port)
        except Exception:
            pass
        finally:
            state["done"] += 1
            if state["done"] % 500 == 0 or state["done"] == state["total"]:
                print(Fore.CYAN + "  ... %d/%d ports scanned, %d open"
                      % (state["done"], state["total"], len(state["open"])),
                      end="\r", flush=True)


async def grab_banner(ip, port, sem):
    """Connect to an open port and read the service banner."""
    async with sem:
        banner_text = ""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=BANNER_TIMEOUT)
            try:
                if port in HTTP_PORTS:
                    writer.write(("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip).encode())
                    try:
                        await asyncio.wait_for(writer.drain(), timeout=BANNER_TIMEOUT)
                    except asyncio.TimeoutError:
                        pass
                data = await asyncio.wait_for(reader.read(2048), timeout=BANNER_TIMEOUT)
                banner_text = clean_banner(data)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            pass
        return port, banner_text


async def run_port_scan(ip, ports):
    state = {"done": 0, "total": len(ports), "open": []}
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    start = time.time()
    await asyncio.gather(*[check_port(ip, p, sem, state) for p in ports])
    scan_time = time.time() - start
    open_ports = sorted(state["open"])

    # Banner grabbing on every open port (concurrent, fast)
    banners = {}
    if open_ports:
        print(Fore.YELLOW + "\n[*] Grabbing banners on %d open port(s)..."
              % len(open_ports))
        sem_b = asyncio.Semaphore(MAX_CONCURRENT)
        results = await asyncio.gather(
            *[grab_banner(ip, p, sem_b) for p in open_ports])
        banners = dict(results)
    return open_ports, banners, scan_time


def port_scan():
    target = ask("\nTarget IP / domain > ")
    if target is None:
        return
    target = target.strip()
    ip = resolve_target(target)
    if not ip:
        print(Fore.RED + "[!] Could not resolve target.\n")
        return

    print("""
  [1] Quick  - top %d common ports (seconds)
  [2] Full   - all 65535 ports (minutes)
  [3] Custom - your own list / range
""" % len(TOP_PORTS))
    mode = ask("Select > ")
    if mode is None:
        return
    mode = mode.strip()

    if mode == "1":
        ports = list(TOP_PORTS)
        label = "quick (%d ports)" % len(ports)
    elif mode == "2":
        ports = list(range(1, 65536))
        label = "full (65535 ports)"
        go = ask("Full scan opens 65535 connections and takes a few minutes. "
                 "Continue? (y/n) > ")
        if go is None or go.strip().lower() != "y":
            print(Fore.YELLOW + "Cancelled.\n")
            return
    elif mode == "3":
        spec = ask("Ports (e.g. 1-1000 or 80,443,8080) > ")
        if spec is None:
            return
        ports = parse_ports(spec)
        if not ports:
            print(Fore.RED + "[!] No valid ports. Example: 1-1000 or 80,443\n")
            return
        label = "custom (%d ports)" % len(ports)
    else:
        print(Fore.RED + "[!] Invalid choice.\n")
        return

    print(Fore.YELLOW + "\n[*] %s scan on %s ..." % (label, ip))
    save_txt_header("Port scan (%s): %s" % (label, ip))
    try:
        open_ports, banners, elapsed = asyncio.run(run_port_scan(ip, ports))
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopped by user.\n")
        return

    print(Fore.GREEN + "\n[OK] %s scanned in %.1fs -- %d open port(s)."
          % (ip, elapsed, len(open_ports)))

    rows_html = ""
    for p in open_ports:
        svc = SERVICE_NAMES.get(p, "")
        bnr = banners.get(p, "")
        tag = ("%d%s" % (p, " (%s)" % svc if svc else ""))
        print(Fore.GREEN + "  [OPEN] %-18s %s" % (tag, bnr))
        save_txt_line("%s:%d OPEN%s%s" % (
            ip, p, " [%s]" % svc if svc else "", " | %s" % bnr if bnr else ""))
        rows_html += ("<tr><td class='open'>%d</td><td>%s</td>"
                      "<td class='banner'>%s</td></tr>"
                      % (p, esc(svc or "-"), esc(bnr or "-")))
    if not open_ports:
        print(Fore.YELLOW + "  No open ports found.")
    print(Fore.CYAN + "  Saved -> %s, %s\n" % (TXT_LOG, HTML_REPORT))

    table = ("<p>Target <b>%s</b> &mdash; %s scan, %d port(s) checked in %.1fs, "
             "<b>%d open</b>.</p>"
             % (esc(ip), esc(label), len(ports), elapsed, len(open_ports)))
    if open_ports:
        table += ("<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>"
                  + rows_html + "</table>")
    add_report_section("Port scan: %s (%s)" % (ip, label), table)


# ================= main menu =================
def main():
    clear()
    banner()
    while True:
        print("""
[1] Domain -> IP + info
[2] Port scan + banner grabbing
[3] IP range scan (/24 or smaller)
[4] Exit
""")
        try:
            choice = ask("Select > ")
        except KeyboardInterrupt:
            print()
            break
        if choice is None:
            break
        choice = choice.strip()

        if choice == "1":
            domain_lookup()
        elif choice == "2":
            port_scan()
        elif choice == "3":
            range_scan()
        elif choice == "4":
            break
        else:
            print(Fore.RED + "[!] Invalid choice.\n")

    print(Fore.CYAN + "Bye!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopped.\n")

# Samiul IP Scanner

Fast IP intelligence & port scanner with **banner grabbing** and **HTML reports**.
Termux supported. Developed by **Samiul**.

## Features

- Domain → IP + geo info (country, city, ISP, ASN)
- Port scan on a single IP/host:
  - **Quick** — top 100 common ports (seconds)
  - **Full** — all 65535 ports
  - **Custom** — your own list or range (e.g. `1-1000`, `80,443,8080`)
- **Banner grabbing** — shows which service/version runs on each open port
- IP range scan (/24 or smaller) with reverse DNS + server/title detection
- Saves results to `scan_results.txt` **and** a mobile-friendly `scan_report.html`
- Progress display, Ctrl+C safe stop, works without colorama too

## Installation

### Termux (Android)

```
pkg install python git -y
git clone https://github.com/samiul14/Samiul-IPScanner
cd Samiul-IPScanner
pip install -r requirements.txt
python ipscanner.py
```

### PC (Linux / Windows)

```
git clone https://github.com/samiul14/Samiul-IPScanner
cd Samiul-IPScanner
pip install -r requirements.txt
python ipscanner.py
```

## Usage

```
[1] Domain -> IP + info
[2] Port scan + banner grabbing
[3] IP range scan (/24 or smaller)
[4] Exit
```

Example port-scan output:

```
[OK] 93.184.216.34 scanned in 4.2s -- 2 open port(s).
  [OPEN] 80 (HTTP)          HTTP nginx/1.24.0
  [OPEN] 443 (HTTPS)        -
```

## Output files

- `scan_results.txt` — plain-text log of every scan
- `scan_report.html` — styled report, open it in any browser

## Disclaimer

For **educational and authorized testing only**. Scan only systems you own
or have explicit permission to test (your own site, your home router,
`scanme.nmap.org`, TryHackMe/HackTheBox labs). Unauthorized scanning of
other people's systems can get you blocked and may break the law.

## Credits

- Developed by **Samiul** — https://github.com/samiul14
- Based on W8IPReverseInfo by W8Team / MD SOJIB (MIT License)

## License

MIT — see [LICENSE](LICENSE).

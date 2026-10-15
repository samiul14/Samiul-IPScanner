<div align="center">

# 🔍 Samiul IP Scanner

**Fast IP intelligence & port scanner with banner grabbing and HTML reports.**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20Windows-green)](https://github.com/samiul14/Samiul-IPScanner)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

*Developed by [Samiul](https://github.com/samiul14)*

</div>

---

## ✨ Features

| Feature | What it does |
|---|---|
| 🌐 Domain → IP + info | Country, city, ISP, organization, ASN |
| ⚡ Port scan | **Quick** (top 100 ports, seconds) · **Full** (all 65535) · **Custom** (`1-1000`, `80,443,8080`) |
| 🎣 Banner grabbing | Detects the service & version running on every open port |
| 📡 IP range scan | /24 or smaller — reverse DNS + web server/title detection |
| 📄 HTML report | Mobile-friendly `scan_report.html` plus plain-text `scan_results.txt` |
| 📱 Termux ready | Built for Android · progress display · Ctrl+C stops cleanly |

## 📥 Installation

### Termux (Android)

```bash
pkg install python git -y
git clone https://github.com/samiul14/Samiul-IPScanner
cd Samiul-IPScanner
pip install -r requirements.txt
python ipscanner.py
```

### PC (Linux / Windows)

```bash
git clone https://github.com/samiul14/Samiul-IPScanner
cd Samiul-IPScanner
pip install -r requirements.txt
python ipscanner.py
```

## 🚀 Usage

```
[1] Domain -> IP + info
[2] Port scan + banner grabbing
[3] IP range scan (/24 or smaller)
[4] Exit
```

Example port-scan output:

```
[*] quick (100 ports) scan on 127.0.0.1 ...
  [OPEN] 8000
  [OPEN] 9999

[*] Grabbing banners on 2 open port(s)...
[OK] 127.0.0.1 scanned in 0.4s -- 2 open port(s).
  [OPEN] 8000 (HTTP-alt)    HTTP SimpleHTTP/0.6 Python/3.12.3
  [OPEN] 9999 (Alt)         220 fake-smtp.test ESMTP FakeMail v2.1
```

## 📂 Output files

| File | Contents |
|---|---|
| `scan_report.html` | Styled report — open it in any browser |
| `scan_results.txt` | Plain-text log of every scan |

## ⚠️ Disclaimer

For **educational and authorized testing only**. Scan only systems you own
or have explicit permission to test — your own site, your home router,
`scanme.nmap.org`, TryHackMe / HackTheBox labs. Unauthorized scanning of
other people's systems can get you blocked and may break the law.

## 👑 Credits

- Developed by **[Samiul](https://github.com/samiul14)**
- Based on W8IPReverseInfo by W8Team / MD SOJIB (MIT License)

## 📜 License

MIT — see [LICENSE](LICENSE).

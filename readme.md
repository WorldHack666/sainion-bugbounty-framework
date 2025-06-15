# 🛡️ SainiON Bug Bounty Framework

An all-in-one Python-based automation tool for bug bounty hunters and penetration testers. Built to streamline recon, vulnerability scanning, exploitation, and reporting. Designed to run on Kali Linux with automated tool installation and HTML report generation.

## 📌 Features

- Subdomain enumeration using `subfinder`
- Live host detection with `httpx`
- Port scanning with `nmap`
- URL collection from archives using `gau` & `katana`
- JavaScript file enumeration
- Vulnerability detection with `nuclei`
- Sensitive pattern recognition with `gf`
- SQL injection testing with `sqlmap`
- Post-exploitation checks using `ffuf`
- HTML report generation with recon, ports, and vulnerabilities

## ⚙️ Requirements

Ensure the following tools are installed or auto-installed:

- `subfinder`
- `httpx`
- `gau`
- `katana`
- `dirsearch`
- `gf`
- `nuclei`
- `sqlmap`
- `ffuf`
- `nmap`
- `curl`

## 🚀 Installation

```bash
git clone https://github.com/WorldHack666/sainion-bugbounty-framework.git
cd sainion-bugbounty-framework
chmod +x bug_bounty.py
```

## 🧪 Usage

```bash
python3 bug_bounty.py <target_domain>
```

### 🔍 Example:

```bash
python3 bug_bounty.py example.com
```

### 📁 Output:

Creates a folder `bugbounty_<target>` with:

- `subdomains.txt`: Enumerated subdomains
- `subdomains_alive.txt`: Responsive hosts
- `ports_all.txt`: Port scan results
- `file_leaks.txt`: Sensitive files
- `nuclei_findings.txt`: Vulnerabilities
- `report.html`: Final bug bounty report

## 🧠 Author

**Created by XIS10CIAL / SainiON**

For advanced cybersecurity automation, visit: [https://www.xis10cial.com](https://www.xis10cial.com)

## 📜 License

[MIT License](LICENSE)

---

> ⚠️ For educational and authorized testing purposes only. Do not use against targets without permission.


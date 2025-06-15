#!/usr/bin/env python3

"""
🐉 Kali GPT - Bug Bounty Automation Script (Python Version)
Author: XIS10CIAL | Kali GPT
Version: 1.0 | June 2025
"""

import os
import subprocess
import sys
import datetime
from pathlib import Path
import shutil

def print_banner():
    banner = r"""
    ╔════════════════════════════════════════════════════╗
    ║             🛡️  SainiON Hacks Framework             ║
    ║      Automated Recon & Exploitation Pipeline       ║
    ╚════════════════════════════════════════════════════╝
    """
    print(banner)

def show_help():
    help_text = """
Usage:
  python3 bug_bounty.py <target_domain>

Description:
  This script performs deep reconnaissance, vulnerability scanning,
  exploitation, and generates a structured HTML report.

Example:
  python3 bug_bounty.py example.com
    """
    print(help_text)

def install_tool(tool, github_repo=None):
    print(f"[+] Checking for tool: {tool}")
    if not shutil.which(tool):
        print(f"[-] {tool} not found. Installing...")
        try:
            subprocess.run(["sudo", "apt", "install", "-y", tool], check=True)
        except:
            if github_repo:
                subprocess.run(["git", "clone", github_repo])
                folder = github_repo.split('/')[-1].replace('.git', '')
                subprocess.run(["sudo", "cp", "-r", folder, "/usr/local/bin/"])
            else:
                print(f"[!] Could not install {tool}. Skipping...")

def run_command(command, output_file=None):
    print(f"[>] Running: {command}")
    if output_file:
        with open(output_file, "w") as out:
            subprocess.run(command, shell=True, stdout=out, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main(target):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    outdir = f"bugbounty_{target}"
    Path(outdir).mkdir(parents=True, exist_ok=True)
    print(f"[+] Target: {target}\n[+] Output Directory: {outdir}")

    # ------------------ Tool Check ------------------
    required_tools = {
        "subfinder": None,
        "httpx": None,
        "gau": None,
        "katana": "https://github.com/projectdiscovery/katana.git",
        "dirsearch": "https://github.com/maurosoria/dirsearch.git",
        "gf": None,
        "nuclei": None,
        "sqlmap": None,
        "ffuf": None,
        "curl": None,
        "nmap": None
    }
    for tool, repo in required_tools.items():
        install_tool(tool, repo)

    # ------------------ Recon ------------------
    run_command(f"subfinder -d {target} -all -silent", f"{outdir}/subdomains.txt")

    # ------------------ Batch Port Scan ------------------
    port_file_all = f"{outdir}/ports_all.txt"
    port_summary = []
    run_command(f"nmap -Pn -sS -T4 -iL {outdir}/subdomains.txt -p- -oN {port_file_all}")
    if os.path.exists(port_file_all):
        with open(port_file_all) as pf:
            current_host = ""
            current_summary = []
            for line in pf:
                if "Nmap scan report for" in line:
                    if current_host and current_summary:
                        port_summary.append(f"## {current_host}\n" + "\n".join(current_summary) + "\n")
                    current_host = line.strip().split("for")[-1].strip()
                    current_summary = []
                elif "/tcp" in line and "open" in line:
                    current_summary.append(line.strip())
            if current_host and current_summary:
                port_summary.append(f"## {current_host}\n" + "\n".join(current_summary) + "\n")

    run_command(f"cat {outdir}/subdomains.txt | httpx -silent", f"{outdir}/subdomains_alive.txt")
    run_command(f"echo {target} | gau | grep -E '\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|gz|bak|7z|log|db|yml|env|conf)$'", f"{outdir}/file_leaks.txt")
    run_command(f"katana -u {outdir}/subdomains_alive.txt -d 5 -ps -kf -jc -fx -o {outdir}/allurls.txt")
    run_command(f"cat {outdir}/allurls.txt | grep -E '\\.js$'", f"{outdir}/jsfiles.txt")
    run_command(f"dirsearch -u https://{target} -x 301,302,400,401,403,404 -r -R 6 -e conf,config,bak,sql,php,py,log,db -o {outdir}/dirsearch.txt")
    run_command(f"curl -s https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey", f"{outdir}/wayback.txt")

    # ------------------ Findings ------------------
    run_command(f"cat {outdir}/subdomains_alive.txt | nuclei -tags cve,exposures,misconfig,token", f"{outdir}/nuclei_findings.txt")
    run_command(f"cat {outdir}/allurls.txt | gf xss", f"{outdir}/xss.txt")
    run_command(f"cat {outdir}/allurls.txt | gf sqli", f"{outdir}/sqli.txt")
    run_command(f"cat {outdir}/allurls.txt | gf lfi", f"{outdir}/lfi.txt")

    # ------------------ Exploitation ------------------
    if os.path.getsize(f"{outdir}/sqli.txt") > 0:
        with open(f"{outdir}/sqli.txt") as f:
            for url in f:
                run_command(f"sqlmap -u {url.strip()} --batch --dbs --random-agent --output-dir={outdir}/sqlmap/", f"{outdir}/sqlmap_results.txt")

    # ------------------ Post-Exploitation ------------------
    run_command(f"cat {outdir}/subdomains_alive.txt | ffuf -w /usr/share/seclists/Discovery/Web-Content/admin-panels.txt -u https://FUZZ.{target} -mc 200 -t 50", f"{outdir}/post_exploit_ffuf.json")

    # ------------------ Reporting ------------------
    report_path = f"{outdir}/report.html"
    with open(report_path, "w") as report:
        report.write(f"<html><head><title>Bug Bounty Report - {target}</title></head><body>")
        report.write(f"<h1>Bug Bounty Recon Report for {target} - {date}</h1>")
        report.write(f"<h2>Findings Summary</h2><pre>{Path(outdir + '/nuclei_findings.txt').read_text()}</pre>")
        report.write(f"<h2>Exposed Files</h2><pre>{Path(outdir + '/file_leaks.txt').read_text()}</pre>")
        report.write(f"<h2>SQLi Results</h2><pre>{Path(outdir + '/sqlmap_results.txt').read_text()}</pre>")
        if port_summary:
            report.write("<h2>Port Scan Results</h2><pre>")
            report.write('\n\n'.join(port_summary))
            report.write("</pre>")
        report.write("</body></html>")

    # ------------------ Next Steps ------------------
    print("[+] Next Steps:")
    print("- Review the HTML report for high-impact findings.")
    print("- Validate any reported issues manually for false positives.")
    print("- Expand scan using SSRF, IDOR, and CORS checks.")
    print("- Manually test parameters from JS files.")
    print("- Use Burp Suite for endpoint testing.")
    print("- Prepare PoCs and submit to the responsible program.")
    print(f"[+] Report generated at: {report_path}")

if __name__ == "__main__":
    print_banner()
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        show_help()
        sys.exit(0)
    main(sys.argv[1])

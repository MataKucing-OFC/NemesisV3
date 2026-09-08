#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

from colorama import Fore, Style

def show_help():
    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + """
╔═══════════════════════════════════════════════════════════╗
║  NEMESIS TOOLS - Help & Documentation                    ║
║  Team: Nemesis | Author: MataKucing                     ║
╚═══════════════════════════════════════════════════════════╝

  📡 Available Modules:
  ──────────────────────────────────────────────────────────
  1. Host Scanner     - Scan hosts with multiple methods
  2. Subdomain Scanner - Scan subdomains from file
  3. IP Scanner       - Scan IP ranges/CIDRs
  4. Subdomain Finder - Find subdomains from multiple sources
  5. IP Lookup        - Find domains hosted on same IP
  6. TXT Toolkit     - Manipulate text files
  7. Open Port Checker - Check open ports
  8. DNS Records     - Get DNS records (A, CNAME, MX, NS, TXT)
  9. OSINT           - HTTP methods & SNI info
  10. Help            - Show this help

  🧬 CVE Exploits:
  ──────────────────────────────────────────────────────────
  - CVE-2025-6934    : WordPress Opal Estate Pro
  - CVE-2025-13486   : WordPress ACF Extended
  - CVE-2025-14156   : WordPress Fox LMS
  - CVE-2025-15030   : WordPress Auth Bypass
  - CVE-2025-55182   : React2Shell
  - CVE-2026-0920    : WordPress LA-Studio Element Kit
  - CVE-2026-18366   : WordPress Events Manager
  - CVE-2026-41940   : cPanel/WHM Auth Bypass

  📂 Output: All results saved to 'result/' directory
  ⚠️  Disclaimer: Use responsibly. For educational & research purposes only.

""")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from colorama import Fore, init
import socket
from modules.sub_scan import get_input
from pathlib import Path

# ==================== OUTPUT DIR ====================
RESULTS_DIR = Path(__file__).resolve().parent.parent / "result"
RESULTS_DIR.mkdir(exist_ok=True)

init(autoreset=True)
file_write_lock = threading.Lock()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
    3306, 3389, 5900, 8080, 8443, 8888
]

def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        return port if result == 0 else None

def open_port_checker():
    target = get_input(Fore.CYAN + "➜  Enter the IP address or hostname to scan: ").strip()
    if not target:
        print(Fore.RED + "⚠️ IP or hostname cannot be empty.")
        return
    try:
        ip = socket.gethostbyname(target)
        print(Fore.GREEN + f"\n🔍 Scanning target: {ip} ({target})")
    except socket.gaierror:
        print(Fore.RED + "⚠️ Error resolving IP for the provided hostname.")
        return

    choice = get_input(Fore.YELLOW + "\nSelect scan type:\n"
                                 "1. 🥭 Scan common ports\n"
                                 "2. 🌐 Scan all ports (1-65535)\n"
                                 " ➜  Enter your choice (1 or 2): ").strip()
    if choice == "1":
        ports = COMMON_PORTS
        print(Fore.GREEN + "\n🚀 Starting scan on common ports...")
    elif choice == "2":
        ports = range(1, 65536)
        print(Fore.GREEN + "\n🚀 Starting scan on all ports (this may take time)...")
    else:
        print(Fore.RED + "⚠️ Invalid choice. Exiting.")
        return

    open_ports = []
    max_threads = 100
    total_ports = len(ports)
    print(Fore.LIGHTYELLOW_EX + f"\nScanning {total_ports} ports...")
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_port, ip, port): port for port in ports}
        for i, future in enumerate(as_completed(futures), start=1):
            port = futures[future]
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
                    print(Fore.LIGHTGREEN_EX + f"🟢 Port {result} is open")
            except Exception as e:
                print(Fore.RED + f"⚠️ Error scanning port {port}: {e}")
            sys.stdout.write(Fore.LIGHTCYAN_EX + f"\r🔄 Progress: {i} of {total_ports}")
            sys.stdout.flush()

    print(Fore.GREEN + "\n🎉 Scan complete!")
    if open_ports:
        print(Fore.LIGHTCYAN_EX + "Open ports:")
        for port in open_ports:
            print(Fore.LIGHTCYAN_EX + f"- Port {port}")
    else:
        print(Fore.LIGHTRED_EX + "No open ports found.")

    output_file = str(RESULTS_DIR / f"{target}_open_ports.txt")
    with open(output_file, "w") as file:
        for port in open_ports:
            file.write(f"Port {port} is open\n")
    print(Fore.GREEN + f"\n✅ Results saved to {output_file}")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

from concurrent.futures import ThreadPoolExecutor, as_completed
import math
import os
from pathlib import Path
import socket
import threading
import time
from colorama import Fore, Style
import requests

DEFAULT_TIMEOUT1 = 5
EXCLUDE_LOCATIONS = ["https://jio.com/BalanceExhaust", "http://filter.ncell.com.np/nc"]
file_write_lock = threading.Lock()

# ==================== OUTPUT DIR ====================
RESULTS_DIR = Path(__file__).resolve().parent.parent / "result"
RESULTS_DIR.mkdir(exist_ok=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_input(prompt, default=None):
    response = input(prompt + Style.BRIGHT).strip()
    print(Style.RESET_ALL)
    return response if response else default or ""

def get_hosts_from_file(file_path):
    path = Path(file_path)
    if path.is_file():
        try:
            return [line.strip() for line in path.read_text().splitlines() if line.strip()]
        except Exception:
            print(Fore.RED + f"Error reading file: {e}")
    return []

def get1_http_method():
    methods = ['GET', 'POST', 'PATCH', 'OPTIONS', 'PUT', 'DELETE', 'TRACE', 'HEAD']
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "🌐 Available HTTP methods: " + ", ".join(methods))
    method = get_input(Fore.CYAN+"\n ➜  Select an HTTP method (default: HEAD): ", "HEAD").upper()
    return method if method in methods else "HEAD"

def file_manager(start_dir, max_up_levels=None, max_invalid_attempts=3):
    current_dir = start_dir
    levels_up = 0
    directory_stack = [start_dir]
    invalid_attempts = 0

    while True:
        files_in_directory = [f for f in current_dir.iterdir() if f.is_file() and f.suffix == '.txt']
        directories_in_directory = [d for d in current_dir.iterdir() if d.is_dir()]

        if not files_in_directory and not directories_in_directory:
            print(Fore.RED + "⚠️  No .txt files or directories found.")
            return None

        print(Fore.CYAN + f"\n📂 Contents of '{current_dir}':")
        combined_items = directories_in_directory + files_in_directory
        half = math.ceil(len(combined_items) / 2)

        for i in range(half):
            left_item = combined_items[i]
            left_prefix = "📁 " if left_item.is_dir() else "📄 "
            left_name = f"{Fore.YELLOW + Style.BRIGHT if left_item.is_dir() else Fore.WHITE}{left_item.name}{Style.RESET_ALL}"
            left = f"{i + 1}. {left_prefix}{left_name}"

            right = ""
            if i + half < len(combined_items):
                right_item = combined_items[i + half]
                right_prefix = "📁 " if right_item.is_dir() else "📄 "
                right_name = f"{Fore.YELLOW + Style.BRIGHT if right_item.is_dir() else Fore.WHITE}{right_item.name}{Style.RESET_ALL}"
                right = f"{i + half + 1}. {right_prefix}{right_name}"

            print(f"{left:<50} {right}")

        print(Fore.LIGHTBLUE_EX +"\n0. " + Fore.LIGHTBLUE_EX + " ↑ Move up a directory" + Style.RESET_ALL)

        file_selection = get_input(Fore.CYAN + " ➜  Enter the number or filename (e.g., 1 or domain.txt): ").strip()

        if file_selection == '0':
            if max_up_levels is not None and levels_up >= max_up_levels:
                print(Fore.RED + "⚠️ You've reached the maximum level above the start directory.")
            elif current_dir.parent == current_dir:
                print(Fore.RED + "⚠️ You are at the root directory and cannot move up further.")
            else:
                current_dir = current_dir.parent
                levels_up += 1
                continue

        try:
            file_index = int(file_selection) - 1
            if file_index < 0 or file_index >= len(combined_items):
                raise IndexError
            selected_item = combined_items[file_index]

            if selected_item.is_dir():
                directory_stack.append(current_dir)
                current_dir = selected_item
                levels_up = 0
                txt_files = [f for f in current_dir.iterdir() if f.is_file() and f.suffix == '.txt']
                sub_dirs = [d for d in current_dir.iterdir() if d.is_dir()]
                if not txt_files and not sub_dirs:
                    print(Fore.RED + "⚠️ No .txt files or directories found. Returning to previous directory.")
                    current_dir = directory_stack.pop()
                continue
            else:
                return selected_item
        except (ValueError, IndexError):
            file_input = current_dir / file_selection
            if file_input.is_file() and file_input.suffix == '.txt':
                return file_input
            else:
                print(Fore.RED + f"⚠️  File '{file_input}' not found or not a .txt file. Please try again.")
                invalid_attempts += 1

        if invalid_attempts >= max_invalid_attempts:
            print(Fore.RED + "⚠️ Too many invalid attempts. Returning to the main menu.")
            return None

def get1_scan_inputs():
    start_dir = Path('.').resolve()
    selected_file = file_manager(start_dir, max_up_levels=3)

    if not selected_file:
        print(Fore.RED + "⚠️ No valid file selected. Returning to main menu.")
        return None, None, None, None, None

    hosts = get_hosts_from_file(selected_file)
    if not hosts:
        print(Fore.RED + "⚠️ No valid hosts found in the file.")
        return None, None, None, None, None

    ports_input = get_input(Fore.CYAN + "➜ Enter port list (default: 80): ", "80").strip()
    ports = ports_input.split(',') if ports_input else ["80"]
    output_file = get_input(Fore.CYAN + "➜ Enter output file name (default: results_inputfile.txt): ", f"results_{selected_file.name}").strip()
    output_file = output_file or f"results_{selected_file.name}"
    output_file = str(RESULTS_DIR / output_file)
    threads = int(get_input(Fore.CYAN + "➜ Enter number of threads (default: 50): ", "50") or "50")
    http_method = get1_http_method()
    return hosts, ports, output_file, threads, http_method

def format1_row(code, server, port, ip_address, host, use_colors=True):
    return (f"{Fore.GREEN if use_colors else ''}{code:<4} " +
            f"{Fore.CYAN if use_colors else ''}{server:<20} " +
            f"{Fore.YELLOW if use_colors else ''}{port:<5} " +
            f"{Fore.MAGENTA if use_colors else ''}{ip_address:<15} " +
            f"{Fore.LIGHTBLUE_EX if use_colors else ''}{host}")

def check1_http_response(host, port, method):
    url = f"{'https' if port in ['443', '8443'] else 'http'}://{host}:{port}"
    try:
        response = requests.request(method, url, timeout=DEFAULT_TIMEOUT1, allow_redirects=True)
        if any(exclude in response.headers.get('Location', '') for exclude in EXCLUDE_LOCATIONS):
            return None
        status_code = response.status_code
        server_header = response.headers.get('Server', 'N/A')
        ip_address = get_ip_from_host(host) or 'N/A'
        return (status_code, server_header, port, ip_address, host)
    except requests.exceptions.RequestException:
        return None

def get_ip_from_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return "N/A"

def format1_time(elapsed_time):
    return f"{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s" if elapsed_time >= 60 else f"{elapsed_time:.2f}s"

def perform1_scan(hosts, ports, output_file, threads, method):
    if hosts is None:
        return
    clear_screen()
    print(Fore.LIGHTGREEN_EX + f"🔍 Scanning using HTTP method: {method}...\n")

    headers = Fore.GREEN + Style.BRIGHT + "Code  " + Fore.CYAN + "Server               " + \
              Fore.YELLOW + "Port   " + Fore.MAGENTA + "IP Address     " + Fore.LIGHTBLUE_EX + "Host" + Style.RESET_ALL
    separator = "-" * 65

    try:
        existing_lines = Path(output_file).is_file() and sum(1 for _ in open(output_file, 'r'))
        with open(output_file, 'a') as file:
            if not existing_lines:
                file.write(f"{headers}\n{separator}\n")
    except Exception as e:
        print(Fore.RED + f"Error opening output file: {e}")
        return

    print(headers, separator, sep='\n')

    start_time = time.time()
    total_hosts, scanned_hosts, responded_hosts = len(hosts) * len(ports), 0, 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check1_http_response, host, port, method) for host in hosts for port in ports]
        
        for future in as_completed(futures):
            scanned_hosts += 1
            try:
                result = future.result(timeout=DEFAULT_TIMEOUT1 + 1)
                if result:
                    responded_hosts += 1
                    row = format1_row(*result)
                    print(row)
                    with file_write_lock:
                        with open(output_file, 'a') as file:
                            file.write(format1_row(*result, use_colors=False) + "\n")
            except Exception:
                pass

            elapsed_time = time.time() - start_time
            print(Style.BRIGHT + f"Scanned {scanned_hosts}/{total_hosts} - Responded: {responded_hosts} - Elapsed: {format1_time(elapsed_time)}", end='\r')

    print(f"\n\n{Fore.GREEN}✅ Scan completed! {responded_hosts}/{scanned_hosts} hosts responded.")
    print(f"{Fore.GREEN}Results saved to {output_file}.{Style.RESET_ALL}")
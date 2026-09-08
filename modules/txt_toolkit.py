#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re
from colorama import Fore, Style, Back, init
import socket
from collections import defaultdict
from modules.sub_scan import get_input
from pathlib import Path

# ==================== OUTPUT DIR ====================
RESULTS_DIR = Path(__file__).resolve().parent.parent / "result"
RESULTS_DIR.mkdir(exist_ok=True)

init(autoreset=True)
file_write_lock = threading.Lock()

def split_txt_file(file_path, parts):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
        lines_per_file = len(lines) // parts
        file_base = os.path.splitext(file_path)[0]
        for i in range(parts):
            part_lines = lines[i * lines_per_file: (i + 1) * lines_per_file] if i < parts - 1 else lines[i * lines_per_file:]
            part_file = str(RESULTS_DIR / f"{os.path.basename(file_base)}_part_{i + 1}.txt")
            with open(part_file, "w", encoding="utf-8") as part_file_obj:
                part_file_obj.writelines(part_lines)
            print(Fore.GREEN + f"✅ Created file: {part_file}")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error splitting file: {e}")

def merge_txt_files():
    directory = get_input(Fore.YELLOW + "📂Input the directory path where your text files are located (or press Enter to use current directory): ").strip()
    if not directory:
        directory = os.getcwd()
    if not os.path.isdir(directory):
        print(Fore.YELLOW + "⚠️ The provided directory does not exist.")
        return
    merge_all = get_input(Fore.YELLOW + "🤔Do you want to merge all .txt files in the directory? (yes/no): ").strip().lower()
    files_to_merge = []
    if merge_all == 'yes':
        files_to_merge = [f for f in os.listdir(directory) if f.endswith('.txt')]
    else:
        filenames = input(Fore.YELLOW + "🗃️ Enter the filenames to merge, separated by commas: ").strip()
        files_to_merge = [filename.strip() for filename in filenames.split(',') if filename.strip()]
        files_to_merge = [f for f in files_to_merge if os.path.isfile(os.path.join(directory, f))]
        if not files_to_merge:
            print(Fore.YELLOW + "😒 No valid files were selected.")
            return
    output_file = get_input(Fore.YELLOW + "📤Enter the name for the merged output file: ").strip()
    if not output_file:
        output_file = "merged_output.txt"
    output_file = str(RESULTS_DIR / output_file)
    with open(output_file, 'w') as outfile:
        for filename in files_to_merge:
            with open(os.path.join(directory, filename), 'r') as infile:
                outfile.write(infile.read())
                outfile.write("\n")
    print(Fore.GREEN + f"✅ Files merged into '{output_file}'")

def remove_duplicate_domains(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            domains = set(file.read().splitlines())
        output_file = str(RESULTS_DIR / f"{Path(file_path).stem}_deduped.txt")
        with open(output_file, "w", encoding="utf-8") as file:
            for domain in sorted(domains):
                file.write(f"{domain}\n")
        print(Fore.GREEN + f"✅ Duplicates removed from {file_path} -> {output_file}")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error removing duplicates: {e}")

def txt_cleaner():
    input_file = get_input(Fore.YELLOW + "📂Enter the name of the input file containing the data: ").strip()
    try:
        with open(input_file, 'r') as infile:
            file_contents = infile.readlines()
    except FileNotFoundError:
        print(Fore.RED + "❌ The specified input file does not exist.")
        return
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b')
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    domains = set()
    ips = set()
    for line in file_contents:
        domains.update(domain_pattern.findall(line))
        ips.update(ip_pattern.findall(line))
    domain_output_file = str(RESULTS_DIR / "domains_clean.txt")
    ip_output_file = str(RESULTS_DIR / "ips_clean.txt")
    with open(domain_output_file, 'w') as domain_file:
        for domain in sorted(domains):
            domain_file.write(domain + "\n")
    with open(ip_output_file, 'w') as ip_file:
        for ip in sorted(ips):
            ip_file.write(ip + "\n")
    print(Fore.GREEN + f"✅ Domains saved to '{domain_output_file}', IPs to '{ip_output_file}'.")

def convert_subdomains_to_domains(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            subdomains = file.read().splitlines()
        root_domains = set()
        for subdomain in subdomains:
            parts = subdomain.split('.')
            if len(parts) >= 2:
                root_domains.add(parts[-2] + '.' + parts[-1])
        output_file = str(RESULTS_DIR / f"{Path(file_path).stem}_root_domains.txt")
        with open(output_file, "w", encoding="utf-8") as file:
            for domain in sorted(root_domains):
                file.write(f"{domain}\n")
        print(Fore.GREEN + f"✅ Subdomains converted to root domains -> {output_file}")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error converting subdomains: {e}")

def separate_domains_by_extension(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            domains = file.read().splitlines()
        extensions_dict = defaultdict(list)
        for domain in domains:
            extension = domain.split('.')[-1]
            extensions_dict[extension].append(domain)
        base_name = Path(file_path).stem
        for extension, domain_list in extensions_dict.items():
            ext_file = str(RESULTS_DIR / f"{base_name}_{extension}.txt")
            with open(ext_file, "w", encoding="utf-8") as file:
                file.write("\n".join(domain_list))
            print(Fore.GREEN + f"✅ Domains with .{extension} saved to {ext_file}")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error separating domains by extension: {e}")

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"{domain} -> {ip}"
    except socket.gaierror:
        return f"{domain} -> Resolution failed"

def domains_to_ip(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            domains = file.read().splitlines()
        output_file = str(RESULTS_DIR / f"{Path(file_path).stem}_with_ips.txt")
        with open(output_file, "w", encoding="utf-8") as file:
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_domain = {executor.submit(resolve_domain_to_ip, domain): domain for domain in domains}
                for future in as_completed(future_to_domain):
                    file.write(future.result() + "\n")
        print(Fore.GREEN + f"✅ Domain-to-IP mappings saved to {output_file}")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error resolving domains to IPs: {e}")

def txt_toolkit_main_menu():
    while True:
        print(Fore.CYAN + "🛠️  TXT Toolkit - Select an Option:\n")
        print(Fore.YELLOW + " [1] ✂️  Split TXT File")
        print(Fore.YELLOW + " [2] 🗑️   Remove Duplicate Domains")
        print(Fore.YELLOW + " [3] 🧹  Txt cleaner (extract domains, subdomains & IP)")
        print(Fore.YELLOW + " [4] 📄  Separate Domains by Extensions")
        print(Fore.YELLOW + " [5] 🌍  Convert Domains to IP Addresses")
        print(Fore.YELLOW + " [6] 🗂️   Merge Txt files")
        print(Fore.YELLOW + " [8] 🌐  Convert Subdomains to Root domains")
        print(Fore.RED + " [0] 🚪  Exit" + Style.RESET_ALL)

        choice = get_input(Fore.CYAN + "➜  Enter your choice (0-8): " + Style.RESET_ALL).strip()
        if choice == "1":
            file_path = get_input(Fore.CYAN + "📂 Enter the file path: ").strip()
            parts = int(get_input(Fore.CYAN + "🔢 Enter number of parts: ").strip())
            split_txt_file(file_path, parts)
        elif choice == "2":
            file_path = get_input(Fore.CYAN + "📂 Enter the file path: ").strip()
            remove_duplicate_domains(file_path)
        elif choice == "3":
            txt_cleaner()
        elif choice == "4":
            file_path = get_input(Fore.CYAN + "📂 Enter the file path: ").strip()
            separate_domains_by_extension(file_path)
        elif choice == "5":
            file_path = get_input(Fore.CYAN + "📂 Enter the file path: ").strip()
            domains_to_ip(file_path)
        elif choice == "6":
            merge_txt_files()
        elif choice == "8":
            file_path = get_input(Fore.CYAN + "📂 Enter the file path: ").strip()
            convert_subdomains_to_domains(file_path)
        elif choice == "0":
            print(Fore.RED + "🚪 Exiting TXT Toolkit!")
            break
        else:
            print(Fore.RED + "⚠️ Invalid choice. Please try again.")
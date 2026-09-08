#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

import sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests
from colorama import Fore, Style, Back, init
from bs4 import BeautifulSoup
from modules.sub_scan import get_input
from pathlib import Path

# ==================== OUTPUT DIR ====================
RESULTS_DIR = Path(__file__).resolve().parent.parent / "result"
RESULTS_DIR.mkdir(exist_ok=True)

init(autoreset=True)
file_write_lock = threading.Lock()

session = requests.Session()
DEFAULT_TIMEOUT2 = 10

def fetch_subdomains(source_func, domain):
    try:
        subdomains = source_func(domain)
        return set(sub for sub in subdomains if isinstance(sub, str))
    except Exception:
        return set()

def crtsh_subdomains(domain):
    subdomains = set()
    response = session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=DEFAULT_TIMEOUT2)
    if response.status_code == 200 and response.headers.get('Content-Type') == 'application/json':
        for entry in response.json():
            subdomains.update(entry['name_value'].splitlines())
    return subdomains

def hackertarget_subdomains(domain):
    subdomains = set()
    response = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=DEFAULT_TIMEOUT2)
    if response.status_code == 200 and 'text' in response.headers.get('Content-Type', ''):
        subdomains.update([line.split(",")[0] for line in response.text.splitlines()])
    return subdomains

def rapiddns_subdomains(domain):
    subdomains = set()
    response = session.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=DEFAULT_TIMEOUT2)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('td'):
            text = link.get_text(strip=True)
            if text.endswith(f".{domain}"):
                subdomains.add(text)
    return subdomains

def anubisdb_subdomains(domain):
    subdomains = set()
    response = session.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=DEFAULT_TIMEOUT2)
    if response.status_code == 200:
        subdomains.update(response.json())
    return subdomains

def alienvault_subdomains(domain):
    subdomains = set()
    response = session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=DEFAULT_TIMEOUT2)
    if response.status_code == 200:
        for entry in response.json().get("passive_dns", []):
            subdomains.add(entry.get("hostname"))
    return subdomains

def urlscan_subdomains(domain):
    subdomains = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    try:
        response = session.get(url, timeout=DEFAULT_TIMEOUT2)
        if response.status_code == 200:
            data = response.json()
            for result in data.get('results', []):
                page_url = result.get('page', {}).get('domain')
                if page_url and page_url.endswith(f".{domain}"):
                    subdomains.add(page_url)
    except requests.RequestException:
        pass
    return subdomains

recently_seen_subdomains = set()

def c99_subdomains(domain, days=10):
    base_url = "https://subdomainfinder.c99.nl/scans"
    subdomains = set()
    dates = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(days)]
    urls = [f"{base_url}/{date}/{domain}" for date in dates]

    def fetch_url(url):
        try:
            response = session.get(url, timeout=DEFAULT_TIMEOUT2)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    text = link.get_text(strip=True)
                    if text.endswith(f".{domain}") and text not in recently_seen_subdomains:
                        subdomains.add(text)
                        recently_seen_subdomains.add(text)
        except requests.RequestException:
            pass

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            future.result()
    return subdomains

def display_progress_bar(progress, total, length=30):
    filled_length = int(length * progress // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    percent = (progress / total) * 100
    sys.stdout.write(f'\r|{bar}| {percent:.2f}% Completed')
    sys.stdout.flush()
    if progress == total:
        sys.stdout.write('\n')

def process_domain(domain, output_file, sources):
    print(Fore.CYAN + f"🔍 Enumerating {domain}\n")
    subdomains = set()
    total_sources = len(sources)
    progress_counter = 0
    progress_lock = threading.Lock()

    def fetch_and_update(source, domain):
        nonlocal progress_counter
        result = fetch_subdomains(source, domain)
        with progress_lock:
            subdomains.update(result)
            progress_counter += 1
            display_progress_bar(progress_counter, total_sources)

    with ThreadPoolExecutor(max_workers=min(total_sources, 10)) as source_executor:
        futures = {source_executor.submit(fetch_and_update, source, domain): source for source in sources}
        for future in as_completed(futures):
            future.result()

    print(Fore.GREEN + f"\n✅ Completed {domain} - {len(subdomains)} subdomains found")
    with open(output_file, "a", encoding="utf-8") as file:
        for subdomain in sorted(subdomains):
            file.write(f"{subdomain}\n")

def find_subdomains():
    input_choice = get_input(Fore.CYAN + " \n ➜  Enter '1' for single domain or '2' for multiple from txt file: ").strip()
    if input_choice == '1':
        domain = get_input(Fore.CYAN + "\n ➜  Enter the domain to find subdomains for: ").strip()
        if not domain:
            print(Fore.RED + "\n⚠️ Domain cannot be empty.")
            return
        domains_to_process = [domain]
        sources = [
            crtsh_subdomains, hackertarget_subdomains, rapiddns_subdomains,
            anubisdb_subdomains, alienvault_subdomains,
            urlscan_subdomains, c99_subdomains
        ]
        default_filename = f"{domain}_subdomains.txt"
    elif input_choice == '2':
        file_path = get_input(Fore.CYAN + "\n ➜  Enter the path to the file containing domains: ").strip()
        try:
            with open(file_path, 'r') as file:
                domains_to_process = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + "\n⚠️ File not found. Please check the path.")
            return
        sources = [
            crtsh_subdomains, hackertarget_subdomains, rapiddns_subdomains,
            anubisdb_subdomains, alienvault_subdomains,
            urlscan_subdomains
        ]
        default_filename = f"{file_path.split('/')[-1].split('.')[0]}_subdomains.txt"
    else:
        print(Fore.RED + "\n⚠️ Invalid choice.")
        return

    output_file = get_input(Fore.CYAN + "\n ➜ Enter the output file name (without extension): ").strip()
    output_file = output_file + "_subdomains.txt" if output_file else default_filename
    output_file = str(RESULTS_DIR / output_file)

    with ThreadPoolExecutor(max_workers=5) as domain_executor:
        futures = {domain_executor.submit(process_domain, domain, output_file, sources): domain for domain in domains_to_process}
        for future in as_completed(futures):
            future.result()

    print(Fore.GREEN + f"\n✅ All results saved to {output_file}")
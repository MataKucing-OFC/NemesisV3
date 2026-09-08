#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

import threading
import requests
from colorama import Fore, Style, Back, init
import socket
import ssl
from requests.exceptions import RequestException
import concurrent
from modules.sub_scan import get_input

init(autoreset=True)
file_write_lock = threading.Lock()

HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"]

def check_http_method(url, method):
    try:
        response = requests.request(method, url, timeout=5)
        print(Fore.LIGHTCYAN_EX + f"{method} response code: {response.status_code}")
        print(Fore.LIGHTMAGENTA_EX + f"{method} headers:\n{response.headers}")
    except RequestException as e:
        print(Fore.RED + f"{method} request failed: {e}")

def check_http_methods(url):
    print(Fore.GREEN + f"\nChecking HTTP methods for {url}...")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_http_method, url, method) for method in HTTP_METHODS]
        concurrent.futures.wait(futures)

def get_sni_info(host):
    print(Fore.GREEN + f"\nRetrieving SNI info for {host}...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                cert = ssl_sock.getpeercert()
                sni_info = {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "serialNumber": cert.get("serialNumber"),
                }
                print(Fore.LIGHTCYAN_EX + f"SNI Information: {sni_info}")
    except Exception as e:
        print(Fore.RED + f"Failed to retrieve SNI info: {e}")

def osint_main():
    host = get_input(Fore.CYAN + " ➜  Enter the host (without 'http' or 'https'): ").strip()
    url = f"https://{host}"
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.submit(check_http_methods, url)
        executor.submit(get_sni_info, host)
    print(Style.RESET_ALL)
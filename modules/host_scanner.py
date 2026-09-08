#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: MataKucing | Team: Nemesis
# Attribution: github.com/MataKucing-OFC

import re
import socket
import ssl
import sys
from pathlib import Path
from colorama import Fore, Style
import multithreading
import requests

# ==================== OUTPUT DIR ====================
RESULTS_DIR = Path(__file__).resolve().parent.parent / "result"
RESULTS_DIR.mkdir(exist_ok=True)

def get_input(prompt, default=None):
    response = input(prompt + Style.BRIGHT).strip()
    print(Style.RESET_ALL)
    return response if response else default or ""

class BugScanner(multithreading.MultiThreadRequest):
    threads: int

    def request_connection_error(self, *args, **kwargs):
        return 1

    def request_read_timeout(self, *args, **kwargs):
        return 1

    def request_timeout(self, *args, **kwargs):
        return 1

    def convert_host_port(self, host, port):
        return host + (f':{port}' if port not in ['80', '443'] else '')

    def get_url(self, host, port, uri=None):
        if not host or not self.is_valid_host(host):
            return None
        port = str(port)
        protocol = 'https' if port == '443' else 'http'
        return f'{protocol}://{self.convert_host_port(host, port)}' + (f'/{uri}' if uri else '')

    def is_valid_host(self, host):
        return bool(re.match(r'^[a-zA-Z0-9.-]+$', host))

    def task(self, payload):
        method = payload.get('method')
        host = payload.get('host')
        port = payload.get('port')
        if not method or not host or not port:
            return
        url = self.get_url(host, port)
        if not url:
            return
        try:
            response = self.request(method, url, retry=1, timeout=3, allow_redirects=False)
            if response:
                self.handle_response(response, method, host, port)
        except requests.exceptions.RequestException:
            pass

class DirectScanner(BugScanner):
    method_list = []
    host_list = []
    port_list = []

    def log_info(self, **kwargs):
        for key in ['method', 'status_code', 'server', 'port', 'ip', 'host', 'location']:
            kwargs[key] = kwargs.get(key, '')
        colors = {
            'method': Fore.CYAN,
            'status_code': Fore.GREEN,
            'server': Fore.YELLOW,
            'port': Fore.MAGENTA,
            'ip': Fore.BLUE,
            'host': Fore.RED
        }
        message = (
            f"{colors['method']}{kwargs.get('method', ''):<6}{Style.RESET_ALL}  "
            f"{colors['status_code']}{kwargs.get('status_code', ''):<4}{Style.RESET_ALL}  "
            f"{colors['server']}{kwargs.get('server', ''):<22}{Style.RESET_ALL}  "
            f"{colors['port']}{kwargs.get('port', ''):<4}{Style.RESET_ALL}  "
            f"{colors['ip']}{kwargs.get('ip', ''):<15}{Style.RESET_ALL}  "
            f"{colors['host']}{kwargs.get('host', '')}"
        )
        super().log(message)
        if hasattr(self, 'output') and self.output:
            try:
                with open(self.output, 'a') as file:
                    file.write(f"{kwargs['method']} {kwargs['host']}:{kwargs['port']} "
                            f"[{kwargs['ip']}] -> Status: {kwargs['status_code']}, "
                            f"Server: {kwargs['server']}, Location: {kwargs['location']}\n")
            except IOError:
                pass

    def get_task_list(self):
        for method in self.filter_list(self.method_list):
            for host in self.filter_list(self.host_list):
                for port in self.filter_list(self.port_list):
                    yield {
                        'method': method.upper(),
                        'host': host,
                        'port': port,
                    }

    def init(self):
        super().init()
        self.log_info(method='Method', status_code='Code', server='Server', port='Port', ip='IP Address', host='Host')
        self.log_info(method='------', status_code='----', server='------', port='----', ip='----------', host='----')

    def task(self, payload):
        method = payload.get('method')
        host = payload.get('host')
        port = payload.get('port')
        if not method or not host or not port:
            return
        url = self.get_url(host, port)
        if not url:
            return
        try:
            response = self.request(method, url, retry=1, timeout=3, allow_redirects=False)
            if response:
                location = response.headers.get('location', '')
                if location != 'https://jio.com/BalanceExhaust':
                    self.handle_response(response, method, host, port)
        except requests.exceptions.RequestException:
            pass

    def handle_response(self, response, method, host, port):
        if not hasattr(self, 'output'):
            self.output = None
        try:
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            ip_address = "Unknown"
        status_code = response.status_code
        server = response.headers.get('server', '')
        location = response.headers.get('location', '')
        data = {
            'method': method,
            'host': host,
            'port': port,
            'ip': ip_address,
            'color': self.logger.special_chars['W1'],
            'status_code': status_code,
            'server': server,
            'location': location,
        }
        self.log_info(**data)
        if self.output:
            with open(self.output, 'a') as file:
                file.write(f"{method} {host}:{port} [{ip_address}] -> Status: {status_code}, Server: {server}, Location: {location}\n")

class ProxyScanner(DirectScanner):
    proxy = []

    def log_replace(self, *args):
        super().log_replace(':'.join(self.proxy), *args)

    def request(self, *args, **kwargs):
        proxy = self.get_url(self.proxy[0], self.proxy[1])
        return super().request(*args, proxies={'http': proxy, 'https': proxy}, **kwargs)

class SSLScanner(BugScanner):
    host_list = []

    def get_task_list(self):
        for host in self.filter_list(self.host_list):
            yield {
                'host': host,
            }

    def log_info(self, color, status, server_name_indication):
        super().log(f'{color}{status:<6}  {server_name_indication}')

    def log_info_result(self, **kwargs):
        G1 = self.logger.special_chars['G1']
        status = kwargs.get('status', False)
        server_name_indication = kwargs.get('server_name_indication', '')
        if status:
            self.log_info(G1, 'True', server_name_indication)

    def init(self):
        super().init()
        self.log_info('', 'Status', 'Server Name Indication')
        self.log_info('', '------', '----------------------')

    def task(self, payload):
        server_name_indication = payload['host']
        self.log_replace(server_name_indication)
        response = {'server_name_indication': server_name_indication}
        try:
            socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_client.settimeout(5)
            socket_client.connect(("77.88.8.8", 443))
            socket_client = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2).wrap_socket(
                socket_client, server_hostname=server_name_indication, do_handshake_on_connect=True
            )
            response['status'] = True
            self.task_success(server_name_indication)
        except Exception:
            response['status'] = False
        self.log_info_result(**response)

class UdpScanner(BugScanner):
    udp_server_host: str
    udp_server_port: int
    host_list: list

    def get_task_list(self):
        for host in self.host_list:
            yield {
                'host': host,
            }

    def log_info(self, color, status, hostname):
        super().log(f'{color}{status:<6}  {hostname}')

    def init(self):
        super().init()
        self.log_info('', 'Status', 'Host')
        self.log_info('', '------', '----')

    def task(self, payload):
        host = payload['host']
        self.log_replace(host)
        bug = f'{host}.{self.udp_server_host}'
        G1 = self.logger.special_chars['G1']
        W2 = self.logger.special_chars['W2']
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(3)
            client.sendto(bug.encode(), (bug, int(self.udp_server_port)))
            client.recv(4)
            client.settimeout(5)
            client.sendto(bug.encode(), (bug, int(self.udp_server_port)))
            client.recv(4)
            client.settimeout(5)
            client.sendto(bug.encode(), (bug, int(self.udp_server_port)))
            client.recv(4)
            self.log_info(G1, 'True', host)
            self.task_success(host)
        except (OSError, socket.timeout):
            self.log_info(W2, '', host)
        finally:
            client.close()

def is_valid_host(host):
    return bool(re.match(r'^[a-zA-Z0-9.-]+$', host))

def get_host_list(filename):
    try:
        with open(filename) as file:
            return [
                line.strip() for line in file.readlines()
                if line.strip() and not line.startswith('#') and is_valid_host(line.strip().split(':')[0])
            ]
    except FileNotFoundError:
        sys.exit(Fore.RED + f"Error: The file '{filename}' does not exist.")

def get_mode():
    mode = get_input(Fore.CYAN+" ➜  Select mode (direct, proxy, ssl, udp): ").strip().lower()
    if mode not in ['direct', 'proxy', 'ssl', 'udp']:
        sys.exit(Fore.RED+'Invalid mode! Choose from: direct, proxy, ssl, udp.')
    return mode

def get_proxy():
    proxy_input = get_input(Fore.CYAN+ " ➜  Enter proxy (host:port): ").strip().split(':')
    if len(proxy_input) != 2:
        sys.exit(Fore.RED + "Invalid proxy format. Use 'host:port'.")
    return proxy_input

def get_int_input(prompt, default=None):
    try:
        return int(input(prompt+Style.BRIGHT).strip() or default)
    except ValueError:
        sys.exit(Fore.RED + "Invalid input. Please enter a valid integer.")

def bugscanner_main():
    filename = get_input(Fore.CYAN + " ➜  Enter filename containing host list: ").strip()
    host_list = get_host_list(filename)
    mode = get_mode()
    method_list = get_input(Fore.CYAN + " ➜  Enter method list (e.g., head,get,post): ").split(',')
    port_list = get_input(Fore.CYAN + " ➜  Enter port list (e.g., 80,443): ").split(',')
    threads = get_int_input(Fore.CYAN + "  ➜ Enter number of threads: ")
    output = get_input(Fore.CYAN + " ➜  Enter output filename (optional): ").strip() or None
    
    if output:
        output = str(RESULTS_DIR / output)
    
    proxy = None
    if mode == 'proxy':
        proxy = get_proxy()

    if mode == 'direct':
        scanner = DirectScanner()
    elif mode == 'ssl':
        scanner = SSLScanner()
    elif mode == 'proxy':
        scanner = ProxyScanner()
        scanner.proxy = proxy
    elif mode == 'udp':
        scanner = UdpScanner()
        scanner.udp_server_host = 'bugscanner.tppreborn.my.id'
        scanner.udp_server_port = '8853'

    scanner.method_list = method_list
    scanner.host_list = host_list
    scanner.port_list = port_list
    scanner.threads = threads
    scanner.output = output
    scanner.start()
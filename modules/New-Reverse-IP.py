
#!/usr/bin/env python3
# Attribution: github.com/MataKucing-OFC

from urllib.parse import urlparse
import sys
import re
import time
import os
import shutil
import asyncio
import json
import warnings
warnings.filterwarnings("ignore")

IS_WINDOWS = sys.platform == "win32"

try:
    import aiohttp
except ImportError:
    os.system("pip install aiohttp -q")
    import aiohttp

aiodns = None
if not IS_WINDOWS:
    try:
        import aiodns
    except ImportError:
        os.system("pip install aiodns -q")
        try:
            import aiodns
        except ImportError:
            aiodns = None


OUTPUT_ALL = "results.txt"
TIMEOUT = 10
DNS_TIMEOUT = 4
FP_TIMEOUT = 6
FP_RATIO = 2
FP_READ_BYTES = 24000
PROGRESS_EVERY = 0.1

DEFAULT_CONC = 150 if IS_WINDOWS else 200
MAX_CONC = 1000 if IS_WINDOWS else 2000

CMS_FILES = {
    "wordpress":   "wordpress.txt",
    "laravel":     "laravel.txt",
    "joomla":      "joomla.txt",
    "drupal":      "drupal.txt",
    "magento":     "magento.txt",
    "shopify":     "shopify.txt",
    "codeigniter": "codeigniter.txt",
    "prestashop":  "prestashop.txt",
    "opencart":    "opencart.txt",
    "vbulletin":   "vbulletin.txt",
    "phpbb":       "phpbb.txt",
}

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
DIM = "\033[2m"
BLD = "\033[1m"
RST = "\033[0m"
CL = "\033[2K\r"

if IS_WINDOWS:
    os.system("")


def bold(t): return f"{BLD}{t}{RST}"


# ============================================================
# API ENDPOINTS - 18+ SOURCES
# ============================================================
API_ENDPOINTS = {
    "webscan":     "http://api.webscan.cc/?action=query&ip={ip}",
    "tntcode":     "https://domains.tntcode.com/ip/{ip}",
    "rapiddns":    "https://rapiddns.io/sameip/{ip}?full=1&t=None",
    "thc":         "https://ip.thc.org/{ip}",
    "alienvault":  "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns",
    "hostio":      "https://host.io/ip/{ip}",
    "virustotal":  "https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
    "securitytrails": "https://api.securitytrails.com/v1/ip/{ip}/domains",
    "farsight":    "https://api.farsightsecurity.com/v1/dnsdb/ip/{ip}",
    "circl":       "https://www.circl.lu/pdns/query/{ip}",
    "riskq":       "https://api.riskq.io/v1/ip/{ip}/domains",
    "whoisxml":    "https://ip-whois.whoisxmlapi.com/api/v1?ip={ip}",
    "ipinfo":      "https://ipinfo.io/{ip}/domains",
    "dnslytics":   "https://dnslytics.com/ip/{ip}",
    "yougetsignal": "http://domains.yougetsignal.com/domains.php?ip={ip}",
    "viewdns":     "https://viewdns.info/reverseip/?host={ip}&t=1",
    "myip":        "https://myip.ms/api/v1/ip/{ip}/domains",
    "domaintools": "https://api.domaintools.com/v1/{ip}/reverse-ip/",
}

API_AUTH = {
    "virustotal": {"x-apikey": ""},
    "securitytrails": {"APIKEY": ""},
    "domaintools": {"Authorization": "Bearer "},
}

_ANSI_STRIP = re.compile(r'\x1b\[[0-9;]*m')
_RE_TNTCODE = re.compile(r'href="/domain/([^"]+)"')
_RE_HOSTIO = re.compile(
    r'class="border-b border-gray-400"[^>]*rel="nofollow">([^<]+)</a>', re.I)
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def _is_valid_domain(d):
    d = d.strip().lower()
    if not d or len(d) > 253:
        return False
    return bool(_DOMAIN_RE.match(d))

# ============================================================
# PARSER FUNCTIONS
# ============================================================


def _parse_webscan(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        if isinstance(data, list):
            for i in data:
                if isinstance(i, dict) and "domain" in i:
                    domains.append(i["domain"])
        elif isinstance(data, dict) and "data" in data:
            for i in data["data"]:
                if isinstance(i, dict) and "domain" in i:
                    domains.append(i["domain"])
    except Exception:
        pass
    return domains


def _parse_tntcode(body_text):
    return [m for m in _RE_TNTCODE.findall(body_text) if _is_valid_domain(m)]


def _parse_rapiddns(body_text):
    domains = []
    rows = re.findall(
        r'<tr>\s*<th[^>]*>\d+</th>\s*<td>([^<]+)</td>', body_text, re.I)
    for d in rows:
        d = d.strip()
        if _is_valid_domain(d):
            domains.append(d)
    return domains


def _parse_thc(body_text):
    domains = []
    clean = _ANSI_STRIP.sub('', body_text)
    for line in clean.splitlines():
        line = line.strip()
        if line.startswith(';') or line.startswith(';;') or not line:
            continue
        if _is_valid_domain(line):
            domains.append(line)
    return domains


def _parse_alienvault(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for entry in data.get("passive_dns", []):
            h = entry.get("hostname", "")
            if h and _is_valid_domain(h):
                domains.append(h)
    except Exception:
        pass
    return domains


def _parse_hostio(body_text):
    return [m for m in _RE_HOSTIO.findall(body_text) if _is_valid_domain(m)]


def _parse_virustotal(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            host = attrs.get("host_name", "")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


def _parse_securitytrails(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data.get("data", []):
            host = item.get("hostname", "")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


def _parse_farsight(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data.get("results", []):
            host = item.get("rrname", "").rstrip(".")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


def _parse_circl(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data:
            host = item.get("rdata", "")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


def _parse_riskq(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data.get("domains", []):
            host = item.get("domain", "")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


def _parse_whoisxml(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data.get("domains", []):
            host = item.get("domainName", "")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


def _parse_ipinfo(body_text):
    domains = []
    try:
        data = json.loads(body_text)
        for item in data.get("domains", []):
            if _is_valid_domain(item):
                domains.append(item)
    except Exception:
        pass
    return domains


def _parse_dnslytics(body_text):
    domains = []
    pattern = re.compile(r'href="/domain/([^"]+)"')
    for m in pattern.findall(body_text):
        if _is_valid_domain(m):
            domains.append(m)
    return domains


def _parse_yougetsignal(body_bytes):
    domains = []
    try:
        text = body_bytes.decode('utf-8', errors='ignore')
        start = text.find('(')
        end = text.rfind(')')
        if start != -1 and end != -1:
            json_str = text[start+1:end]
            data = json.loads(json_str)
            for item in data.get("domainArray", []):
                if len(item) >= 2 and _is_valid_domain(item[0]):
                    domains.append(item[0])
    except Exception:
        pass
    return domains


def _parse_viewdns(body_text):
    domains = []
    pattern = re.compile(r'<td><a href="[^"]+domain\.php\?domain=([^"]+)"')
    for m in pattern.findall(body_text):
        if _is_valid_domain(m):
            domains.append(m)
    return domains


def _parse_myip(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data.get("data", []):
            host = item.get("domain", "")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


def _parse_domaintools(body_bytes):
    domains = []
    try:
        data = json.loads(body_bytes)
        for item in data.get("response", {}).get("ip_addresses", []):
            host = item.get("domain_name", "")
            if host and _is_valid_domain(host):
                domains.append(host)
    except Exception:
        pass
    return domains


PARSERS = {
    "webscan": lambda b, _: _parse_webscan(b),
    "tntcode": lambda _, t: _parse_tntcode(t),
    "rapiddns": lambda _, t: _parse_rapiddns(t),
    "thc": lambda _, t: _parse_thc(t),
    "alienvault": lambda b, _: _parse_alienvault(b),
    "hostio": lambda _, t: _parse_hostio(t),
    "virustotal": lambda b, _: _parse_virustotal(b),
    "securitytrails": lambda b, _: _parse_securitytrails(b),
    "farsight": lambda b, _: _parse_farsight(b),
    "circl": lambda b, _: _parse_circl(b),
    "riskq": lambda b, _: _parse_riskq(b),
    "whoisxml": lambda b, _: _parse_whoisxml(b),
    "ipinfo": lambda _, t: _parse_ipinfo(t),
    "dnslytics": lambda _, t: _parse_dnslytics(t),
    "yougetsignal": lambda b, _: _parse_yougetsignal(b),
    "viewdns": lambda _, t: _parse_viewdns(t),
    "myip": lambda b, _: _parse_myip(b),
    "domaintools": lambda b, _: _parse_domaintools(b),
}

# ============================================================
# FUNGSI UTAMA
# ============================================================


def banner():
    os.system("cls" if os.name == "nt" else "clear")
    logo = [
        f"{R}   ╔══════════════════════════════════════════════════════════╗",
        f"{R}   ║{W}{BLD}  REVERSE IP TOOL v3.0 - 18+ API SOURCES           {R}║",
        f"{R}   ║{DIM}                                                  {R}║",
        f"{R}   ╚══════════════════════════════════════════════════════════╝",
    ]
    for line in logo:
        print(line)


def extract_host(raw):
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        try:
            return urlparse(raw).hostname or ""
        except Exception:
            return ""
    return raw.split("/")[0]


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
def is_ip(value): return bool(_IP_RE.match(value))


async def resolve_aiodns(resolver, host):
    try:
        result = await asyncio.wait_for(resolver.query(host, "A"), timeout=DNS_TIMEOUT)
        return result[0].host if result else None
    except Exception:
        return None


async def resolve_asyncio(loop, host):
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=1),
            timeout=DNS_TIMEOUT
        )
        for info in infos:
            ip = info[4][0]
            if is_ip(ip):
                return ip
        return None
    except Exception:
        return None


async def _fetch_endpoint(session, name, ip):
    url = API_ENDPOINTS[name].format(ip=ip)
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; RecScan/3.0)"}
        if name in API_AUTH:
            headers.update(API_AUTH[name])
        if name == "thc":
            headers["Accept"] = "text/plain"
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ssl=False,
            headers=headers,
        ) as resp:
            body_bytes = await resp.read()
            body_text = body_bytes.decode("utf-8", errors="ignore")
            parser = PARSERS[name]
            return parser(body_bytes, body_text)
    except Exception:
        return []


async def lookup(session, ip, active_apis):
    all_domains = set()
    tasks = [_fetch_endpoint(session, name, ip) for name in active_apis]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            for d in result:
                d = d.strip().lower()
                if d:
                    all_domains.add(d)
    return list(all_domains)

_SIG_WP = re.compile(rb"wp-content|wp-includes|wp-json", re.I)
_SIG_JOOMLA = re.compile(
    rb"content=['\"]Joomla!|/media/jui/|/components/com_", re.I)
_SIG_DRUPAL = re.compile(
    rb"Drupal\.settings|/sites/default/files/|/sites/all/", re.I)
_SIG_MAGENTO = re.compile(
    rb"Mage\.Cookies|/skin/frontend/|var BLANK_URL|Magento_", re.I)
_SIG_PRESTA = re.compile(rb"content=['\"]PrestaShop|var prestashop", re.I)
_SIG_OPENCART = re.compile(rb"catalog/view/theme|route=product/", re.I)
_SIG_VBUL = re.compile(rb"vBulletin|vbulletin_global\.js", re.I)
_SIG_PHPBB = re.compile(rb"phpBB|phpbb/styles/", re.I)
_SIG_GEN_LRV = re.compile(rb"<meta name=[\"']csrf-token[\"']", re.I)


def fingerprint(headers, cookies, body):
    found = set()
    server = headers.get("Server", "").lower()
    generator = headers.get("X-Generator", "").lower()
    drupal_hdr = headers.get(
        "X-Drupal-Cache", "") or headers.get("X-Drupal-Dynamic-Cache", "")
    shopify_hdr = headers.get(
        "X-Shopify-Stage", "") or headers.get("X-Shopid", "") or headers.get("X-ShardId", "")
    magento_hdr = headers.get("X-Magento-Cache-Debug",
                              "") or headers.get("X-Magento-Tags", "")

    if "drupal" in generator or drupal_hdr:
        found.add("drupal")
    if shopify_hdr or "shopify" in server:
        found.add("shopify")
    if magento_hdr:
        found.add("magento")

    cookie_names = {ck.key.lower()
                    for ck in cookies.values()} if cookies else set()
    set_cookie_raw = ""
    for h, v in headers.items():
        if h.lower() == "set-cookie":
            set_cookie_raw += v.lower() + ";"
    cookie_blob = set_cookie_raw + " " + " ".join(cookie_names)

    if "laravel_session" in cookie_blob or "xsrf-token" in cookie_blob:
        found.add("laravel")
    if "ci_session" in cookie_blob:
        found.add("codeigniter")
    if "prestashop-" in cookie_blob or "presta-" in cookie_blob:
        found.add("prestashop")
    if "ocsessid" in cookie_blob:
        found.add("opencart")
    if "bbsessionhash" in cookie_blob:
        found.add("vbulletin")
    if "phpbb3_" in cookie_blob or "phpbb_" in cookie_blob:
        found.add("phpbb")

    if body:
        if _SIG_WP.search(body):
            found.add("wordpress")
        if _SIG_JOOMLA.search(body):
            found.add("joomla")
        if _SIG_DRUPAL.search(body):
            found.add("drupal")
        if _SIG_MAGENTO.search(body):
            found.add("magento")
        if _SIG_PRESTA.search(body):
            found.add("prestashop")
        if _SIG_OPENCART.search(body):
            found.add("opencart")
        if _SIG_VBUL.search(body):
            found.add("vbulletin")
        if _SIG_PHPBB.search(body):
            found.add("phpbb")
        if "laravel" not in found and _SIG_GEN_LRV.search(body) and b"laravel" in body.lower():
            found.add("laravel")

    return found


async def detect_cms(session, domain):
    for scheme in ("http://", "https://"):
        url = f"{scheme}{domain}/"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=FP_TIMEOUT),
                allow_redirects=True,
                ssl=False,
                max_redirects=3,
            ) as resp:
                body = await resp.content.read(FP_READ_BYTES)
                return fingerprint(resp.headers, resp.cookies, body or b"")
        except Exception:
            continue
    return set()


class Stats:
    __slots__ = ("lookup_done", "fp_done", "domain_total", "ip_unique",
                 "start", "last_render", "cms_count", "cms_enabled", "api_hits")

    def __init__(self, cms_enabled):
        self.lookup_done = 0
        self.fp_done = 0
        self.domain_total = 0
        self.ip_unique = 0
        self.start = time.time()
        self.last_render = 0.0
        self.cms_count = {name: 0 for name in CMS_FILES}
        self.cms_enabled = cms_enabled
        self.api_hits = {name: 0 for name in API_ENDPOINTS}


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _visible_len(s):
    return len(_ANSI_RE.sub('', s))


def render(stats, lookup_total, force=False):
    now = time.time()
    if not force and (now - stats.last_render) < PROGRESS_EVERY:
        return
    stats.last_render = now

    ld, lt = stats.lookup_done, lookup_total
    pct = (ld / lt) * 100 if lt else 0
    bar_len = 20
    filled = int(bar_len * ld / lt) if lt else 0
    bar = f"{G}{'█' * filled}{DIM}{'░' * (bar_len - filled)}{RST}"
    elapsed = now - stats.start
    rps = ld / elapsed if elapsed > 0 else 0

    if stats.cms_enabled:
        top = sorted(stats.cms_count.items(), key=lambda x: -x[1])[:3]
        cms_parts = [f"{DIM}{k[:4]}{RST}{M}{v}{RST}" for k, v in top if v > 0]
        cms_str = " ".join(cms_parts) if cms_parts else f"{DIM}--{RST}"
        tail = f"{DIM}fp{RST}{W}{stats.fp_done}{RST} {cms_str} "
    else:
        tail = ""

    body = (
        f"[{bar}] {Y}{pct:5.1f}%{RST} "
        f"{DIM}lk{RST}{W}{ld}{RST}{DIM}/{lt}{RST} "
        f"{DIM}ip{RST}{C}{stats.ip_unique}{RST} "
        f"{DIM}dom{RST}{W}{stats.domain_total}{RST} "
        f"{tail}"
        f"{DIM}{rps:.0f}r/s{RST}"
    )

    try:
        term_w = shutil.get_terminal_size((120, 20)).columns
    except Exception:
        term_w = 120
    max_w = max(40, term_w - 2)

    if _visible_len(body) > max_w:
        body = (
            f"[{bar}] {Y}{pct:5.1f}%{RST} "
            f"{DIM}lk{RST}{W}{ld}{RST}{DIM}/{lt}{RST} "
            f"{DIM}ip{RST}{C}{stats.ip_unique}{RST} "
            f"{DIM}dom{RST}{W}{stats.domain_total}{RST} "
            f"{DIM}{rps:.0f}r/s{RST}"
        )

    pad_count = max(0, max_w - _visible_len(body))
    line = "\r " + body + (" " * pad_count)

    sys.stdout.write(line)
    sys.stdout.flush()


class CMSWriter:
    __slots__ = ("files", "written")

    def __init__(self):
        self.files = {}
        self.written = {name: set() for name in CMS_FILES}

    def write(self, cms, domain):
        if domain in self.written[cms]:
            return False
        self.written[cms].add(domain)
        fp = self.files.get(cms)
        if fp is None:
            fp = open(CMS_FILES[cms], "w", encoding="utf-8", buffering=1)
            self.files[cms] = fp
        fp.write(domain + "\n")
        return True

    def close_all(self):
        for fp in self.files.values():
            try:
                fp.close()
            except Exception:
                pass


async def lookup_worker(target_q, domain_q, session, resolve_fn, seen_ips, seen_lock,
                        stats, lookup_total, out_fp, written_domains, cms_enabled, active_apis):
    while True:
        raw = await target_q.get()
        if raw is None:
            target_q.task_done()
            break
        try:
            host = extract_host(raw)
            if not host:
                continue
            ip = host if is_ip(host) else await resolve_fn(host)
            if not ip:
                continue

            async with seen_lock:
                if ip in seen_ips:
                    need_fetch = False
                else:
                    seen_ips[ip] = []
                    need_fetch = True

            if need_fetch:
                domains = await lookup(session, ip, active_apis)
                async with seen_lock:
                    seen_ips[ip] = domains
                    stats.ip_unique = len(seen_ips)
                for d in domains:
                    if d not in written_domains:
                        written_domains.add(d)
                        out_fp.write(d + "\n")
                        stats.domain_total += 1
                        if cms_enabled:
                            await domain_q.put(d)
        except Exception:
            pass
        finally:
            stats.lookup_done += 1
            render(stats, lookup_total)
            target_q.task_done()


async def fp_worker(domain_q, fp_session, stats, writer, lookup_total):
    while True:
        domain = await domain_q.get()
        if domain is None:
            domain_q.task_done()
            break
        try:
            cms_set = await detect_cms(fp_session, domain)
            for cms in cms_set:
                if writer.write(cms, domain):
                    stats.cms_count[cms] += 1
        except Exception:
            pass
        finally:
            stats.fp_done += 1
            render(stats, lookup_total)
            domain_q.task_done()


async def run(targets, concurrency, cms_enabled, active_apis):
    lookup_total = len(targets)
    stats = Stats(cms_enabled)
    seen_ips = {}
    seen_lock = asyncio.Lock()
    written_domains = set()
    writer = CMSWriter() if cms_enabled else None

    target_q = asyncio.Queue(maxsize=concurrency * 4)
    domain_q = asyncio.Queue(maxsize=concurrency * 8) if cms_enabled else None

    loop = asyncio.get_running_loop()
    if aiodns is not None and not IS_WINDOWS:
        resolver = aiodns.DNSResolver(timeout=DNS_TIMEOUT, tries=2)

        async def resolve_fn(host):
            return await resolve_aiodns(resolver, host)
    else:
        async def resolve_fn(host):
            return await resolve_asyncio(loop, host)

    lookup_conn = aiohttp.TCPConnector(
        limit=concurrency, limit_per_host=concurrency,
        ttl_dns_cache=300, use_dns_cache=True,
        enable_cleanup_closed=True,
    )
    headers = {"User-Agent": "Mozilla/5.0 (compatible; RecScan/3.0)"}
    session = aiohttp.ClientSession(connector=lookup_conn, headers=headers)

    fp_session = None
    fp_conn = None
    if cms_enabled:
        fp_conn = aiohttp.TCPConnector(
            limit=concurrency * FP_RATIO, limit_per_host=0,
            ttl_dns_cache=300, use_dns_cache=True,
            enable_cleanup_closed=True, ssl=False,
        )
        fp_session = aiohttp.ClientSession(connector=fp_conn, headers=headers)

    out_fp = open(OUTPUT_ALL, "w", encoding="utf-8", buffering=1)

    try:
        lookup_workers = [
            asyncio.create_task(lookup_worker(
                target_q, domain_q, session, resolve_fn,
                seen_ips, seen_lock, stats, lookup_total, out_fp, written_domains, cms_enabled, active_apis))
            for _ in range(concurrency)
        ]

        fp_workers = []
        if cms_enabled:
            fp_n = concurrency * FP_RATIO
            fp_workers = [
                asyncio.create_task(fp_worker(
                    domain_q, fp_session, stats, writer, lookup_total))
                for _ in range(fp_n)
            ]

        async def feeder():
            for t in targets:
                await target_q.put(t)
            for _ in range(concurrency):
                await target_q.put(None)
        feeder_task = asyncio.create_task(feeder())

        await feeder_task
        await asyncio.gather(*lookup_workers, return_exceptions=True)

        if cms_enabled:
            for _ in range(len(fp_workers)):
                await domain_q.put(None)
            await asyncio.gather(*fp_workers, return_exceptions=True)
    finally:
        out_fp.close()
        if writer:
            writer.close_all()
        try:
            await session.close()
        except Exception:
            pass
        if fp_session:
            try:
                await fp_session.close()
            except Exception:
                pass
        await asyncio.sleep(0.25)

    render(stats, lookup_total, force=True)
    elapsed = time.time() - stats.start
    rps = lookup_total / elapsed if elapsed else 0

    print("\n\n  " + DIM + "─"*60 + RST)
    print("  " + G + "[✓] Selesai!" + RST)
    print("  " + G + "▸" + RST + " Waktu total   : " +
          bold(f'{elapsed:.2f}s') + "  " + DIM + f"({rps:.1f} target/s)" + RST)
    print("  " + G + "▸" + RST + " IP unik       : " +
          bold(f'{stats.ip_unique:,}'))
    print("  " + G + "▸" + RST + " Domain unik   : " +
          bold(f'{stats.domain_total:,}') + "  " + DIM + "→ " + OUTPUT_ALL + RST)
    print("  " + G + "▸" + RST + " API aktif     : " +
          bold(', '.join(active_apis)))

    if cms_enabled:
        print("  " + DIM + "─"*60 + RST)
        print("  " + BLD + W + "[CMS BREAKDOWN]" + RST)
        any_hit = False
        for name in CMS_FILES:
            n = stats.cms_count[name]
            if n > 0:
                any_hit = True
                pct = (n * 100 / stats.domain_total) if stats.domain_total else 0
                print("  " + M + "▸" + RST + " " + name.ljust(12) + " : " +
                      bold(f'{n:,}') + " " + DIM + f"({pct:.1f}%) → " + CMS_FILES[name] + RST)
        if not any_hit:
            print("  " + DIM + "  (tidak ada CMS terdeteksi)" + RST)
    print("  " + DIM + "─"*60 + RST + "\n")


def render_cms_only(stats, total, force=False):
    now = time.time()
    if not force and (now - stats.last_render) < PROGRESS_EVERY:
        return
    stats.last_render = now

    done = stats.fp_done
    pct = (done / total) * 100 if total else 0
    bar_len = 20
    filled = int(bar_len * done / total) if total else 0
    bar = f"{G}{'█' * filled}{DIM}{'░' * (bar_len - filled)}{RST}"
    elapsed = now - stats.start
    rps = done / elapsed if elapsed > 0 else 0

    top = sorted(stats.cms_count.items(), key=lambda x: -x[1])[:3]
    cms_parts = [f"{DIM}{k[:4]}{RST}{M}{v}{RST}" for k, v in top if v > 0]
    cms_str = " ".join(cms_parts) if cms_parts else f"{DIM}--{RST}"

    body = (
        f"[{bar}] {Y}{pct:5.1f}%{RST} "
        f"{DIM}chk{RST}{W}{done}{RST}{DIM}/{total}{RST} "
        f"{cms_str} "
        f"{DIM}{rps:.0f}r/s{RST}"
    )

    try:
        term_w = shutil.get_terminal_size((120, 20)).columns
    except Exception:
        term_w = 120
    max_w = max(40, term_w - 2)
    pad_count = max(0, max_w - _visible_len(body))
    line = "\r " + body + (" " * pad_count)
    sys.stdout.write(line)
    sys.stdout.flush()


async def cms_only_worker(domain_q, fp_session, stats, writer, total):
    while True:
        domain = await domain_q.get()
        if domain is None:
            domain_q.task_done()
            break
        try:
            cms_set = await detect_cms(fp_session, domain)
            for cms in cms_set:
                if writer.write(cms, domain):
                    stats.cms_count[cms] += 1
        except Exception:
            pass
        finally:
            stats.fp_done += 1
            render_cms_only(stats, total)
            domain_q.task_done()


async def run_cms_only(domains, concurrency):
    total = len(domains)
    stats = Stats(cms_enabled=True)
    writer = CMSWriter()

    domain_q = asyncio.Queue(maxsize=concurrency * 4)

    fp_conn = aiohttp.TCPConnector(
        limit=concurrency, limit_per_host=0,
        ttl_dns_cache=300, use_dns_cache=True,
        enable_cleanup_closed=True, ssl=False,
    )
    headers = {"User-Agent": "Mozilla/5.0 (compatible; RecScan/3.0)"}
    fp_session = aiohttp.ClientSession(connector=fp_conn, headers=headers)

    try:
        workers = [
            asyncio.create_task(cms_only_worker(
                domain_q, fp_session, stats, writer, total))
            for _ in range(concurrency)
        ]

        for d in domains:
            await domain_q.put(d)
        for _ in range(concurrency):
            await domain_q.put(None)

        await asyncio.gather(*workers, return_exceptions=True)
    finally:
        writer.close_all()
        try:
            await fp_session.close()
        except Exception:
            pass
        await asyncio.sleep(0.25)

    render_cms_only(stats, total, force=True)
    elapsed = time.time() - stats.start
    rps = total / elapsed if elapsed else 0

    print("\n\n  " + DIM + "─"*60 + RST)
    print("  " + G + "[✓] Selesai!" + RST)
    print("  " + G + "▸" + RST + " Waktu total   : " +
          bold(f'{elapsed:.2f}s') + "  " + DIM + f"({rps:.1f} domain/s)" + RST)
    print("  " + G + "▸" + RST + " Domain dicek  : " + bold(f'{total:,}'))
    print("  " + DIM + "─"*60 + RST)
    print("  " + BLD + W + "[CMS BREAKDOWN]" + RST)
    any_hit = False
    for name in CMS_FILES:
        n = stats.cms_count[name]
        if n > 0:
            any_hit = True
            pct = (n * 100 / total) if total else 0
            print("  " + M + "▸" + RST + " " + name.ljust(12) + " : " +
                  bold(f'{n:,}') + " " + DIM + f"({pct:.1f}%) → " + CMS_FILES[name] + RST)
    if not any_hit:
        print("  " + DIM + "  (tidak ada CMS terdeteksi)" + RST)
    print("  " + DIM + "─"*60 + RST + "\n")


def load_file(path):
    if not os.path.isfile(path):
        print(f"  {R}[✗] File tidak ditemukan:{RST} {path}")
        sys.exit(1)
    seen = set()
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line not in seen:
                seen.add(line)
                items.append(line)
    if not items:
        print(f"  {R}[✗] File kosong atau tidak ada target valid.{RST}")
        sys.exit(1)
    return items


def main():
    banner()

    active_apis = list(API_ENDPOINTS.keys())

    print("\n  " + BLD + W + "[MODE]" + RST)
    print("  " + C + "1." + RST + " Reverse IP + CMS Detection  " +
          DIM + "(input: IP/domain list)" + RST)
    print("  " + C + "2." + RST + " Reverse IP only              " +
          DIM + "(input: IP/domain list)" + RST)
    print("  " + C + "3." + RST + " CMS Check only               " +
          DIM + "(input: domain list, tanpa reverse IP)" + RST)
    print()
    mode_choice = input("  " + C + "›" + RST + " Pilih mode " +
                        DIM + "(1/2/3, default=1)" + RST + " : ").strip()
    if mode_choice not in ("1", "2", "3"):
        mode_choice = "1"

    print("\n  " + BLD + W + "[INPUT]" + RST)
    input_file = input("  " + C + "›" + RST + " File input  : ").strip()
    conc_inp = input("  " + C + "›" + RST + " Concurrency " + DIM +
                     f"(default={DEFAULT_CONC}, max={MAX_CONC})" + RST + " : ").strip()
    concurrency = int(conc_inp) if conc_inp.isdigit() and int(
        conc_inp) > 0 else DEFAULT_CONC
    if concurrency > MAX_CONC:
        concurrency = MAX_CONC
    print()

    targets = load_file(input_file)

    if IS_WINDOWS:
        try:
            asyncio.set_event_loop_policy(
                asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:
            pass

    if mode_choice == "3":
        print("  " + DIM + "─"*60 + RST)
        print("  " + G + "▸" + RST + " Total domain  : " +
              bold(f'{len(targets):,}'))
        print("  " + G + "▸" + RST + " Mode          : " + bold("CMS Check Only"))
        print("  " + G + "▸" + RST + " Concurrency   : " + bold(str(concurrency)))
        print("  " + M + "▸" + RST + " CMS detected  : " +
              DIM + ', '.join(CMS_FILES.keys()) + RST)
        print("  " + DIM + "─"*60 + RST + "\n")
        print("  " + BLD + "[PIPELINE]" + RST + "  " +
              DIM + "CMS detection only" + RST + "\n")

        try:
            asyncio.run(run_cms_only(targets, concurrency))
        except KeyboardInterrupt:
            print("\n\n  " + Y + "[!] Dihentikan oleh user." + RST)
        except Exception as e:
            print("\n\n  " + R + "[✗] Error:" + RST + " " + str(e))
    else:
        cms_enabled = mode_choice == "1"

        print("  " + DIM + "─"*60 + RST)
        print("  " + BLD + W + "[API SOURCES]" + RST)
        for i, name in enumerate(active_apis):
            has_auth = " 🔑" if name in API_AUTH and API_AUTH[name].get(
                list(API_AUTH[name].keys())[0]) else ""
            print("  " + M + f"{i+1:2}." + RST +
                  " " + name + DIM + has_auth + RST)
        print("  " + DIM + f"  Total: {len(active_apis)} API sources" + RST)
        print("  " + DIM + "─"*60 + RST)

        print("  " + G + "▸" + RST + " Total target  : " +
              bold(f'{len(targets):,}'))
        print("  " + G + "▸" + RST + " API aktif     : " +
              bold(str(len(active_apis))) + " " + DIM + "(semua)" + RST)
        if cms_enabled:
            print("  " + G + "▸" + RST + " Mode          : " +
                  bold("Reverse IP (Multi-API) + CMS Detection"))
            print("  " + G + "▸" + RST + " Concurrency   : " + bold(str(concurrency)) + " " + DIM +
                  "(lookup)" + RST + " + " + bold(str(concurrency*FP_RATIO)) + " " + DIM + "(fingerprint)" + RST)
            print("  " + M + "▸" + RST + " CMS detected  : " +
                  DIM + ', '.join(CMS_FILES.keys()) + RST)
        else:
            print("  " + G + "▸" + RST + " Mode          : " +
                  bold("Reverse IP (Multi-API) only"))
            print("  " + G + "▸" + RST + " Concurrency   : " +
                  bold(str(concurrency)) + " " + DIM + "(lookup)" + RST)
        print("  " + G + "▸" + RST + " Output all    : " + bold(OUTPUT_ALL))
        print("  " + DIM + "─"*60 + RST + "\n")
        mode_str = "reverse-ip (multi-api) → Check CMS" if cms_enabled else "reverse-ip (multi-api) only"
        print("  " + BLD + "[PIPELINE]" + RST +
              "  " + DIM + mode_str + RST + "\n")

        try:
            asyncio.run(run(targets, concurrency, cms_enabled, active_apis))
        except KeyboardInterrupt:
            print("\n\n  " + Y + "[!] Dihentikan oleh user." + RST)
        except Exception as e:
            print("\n\n  " + R + "[✗] Error:" + RST + " " + str(e))


if __name__ == "__main__":
    main()

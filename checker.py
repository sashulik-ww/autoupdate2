#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse, urlsplit
import urllib.request

# ====================== НАСТРОЙКИ ======================
SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
)
TIMEOUT = float(os.getenv("TIMEOUT", "8"))
CONCURRENCY = int(os.getenv("CONCURRENCY", "150"))
XRAY_WORKERS = int(os.getenv("XRAY_WORKERS", "8"))          # одновременных xray
XRAY_TIMEOUT = float(os.getenv("XRAY_TIMEOUT", "9"))
MAX_XRAY_CANDIDATES = int(os.getenv("MAX_XRAY_CANDIDATES", "1200"))  # сколько пропускаем в xray

OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

MAX_PER_COUNTRY = 20
MAX_TOTAL = 500
WHITE_MAX_PER_IP = 2
WHITE_MAX_PER_COUNTRY = 20
WHITE_MAX_TOTAL = 600

XRAY_BIN = os.getenv("XRAY_BIN", "xray")

SUPPORTED_SCHEMES = (
    "vless", "vmess", "trojan", "ss", "ssr",
    "hysteria2", "hy2", "tuic", "socks5", "http", "https"
)

GOOD_SNI = {
    "vk.com", "www.vk.com", "m.vk.com",
    "yandex.ru", "ya.ru", "www.yandex.ru",
    "mail.ru", "www.mail.ru", "ok.ru", "www.ok.ru",
    "userapi.com", "api.vk.com",
    "google.com", "www.google.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "cloudflare.com", "www.cloudflare.com",
    "github.com", "www.github.com", "discord.com",
}

COUNTRY_DATA = {
    "DE": ("Germany", "🇩🇪"), "NL": ("Netherlands", "🇳🇱"),
    "US": ("United States", "🇺🇸"), "FR": ("France", "🇫🇷"),
    "GB": ("United Kingdom", "🇬🇧"), "SG": ("Singapore", "🇸🇬"),
    "CA": ("Canada", "🇨🇦"), "JP": ("Japan", "🇯🇵"),
    "FI": ("Finland", "🇫🇮"), "PL": ("Poland", "🇵🇱"),
    "RU": ("Russia", "🇷🇺"), "TR": ("Turkey", "🇹🇷"),
    "KZ": ("Kazakhstan", "🇰🇿"), "SE": ("Sweden", "🇸🇪"),
    "CH": ("Switzerland", "🇨🇭"), "IT": ("Italy", "🇮🇹"),
    "ES": ("Spain", "🇪🇸"), "AT": ("Austria", "🇦🇹"),
    "BE": ("Belgium", "🇧🇪"), "CZ": ("Czechia", "🇨🇿"),
    "HK": ("Hong Kong", "🇭🇰"), "KR": ("South Korea", "🇰🇷"),
    "TW": ("Taiwan", "🇹🇼"), "AU": ("Australia", "🇦🇺"),
    "IN": ("India", "🇮🇳"), "UA": ("Ukraine", "🇺🇦"),
    "HU": ("Hungary", "🇭🇺"), "RO": ("Romania", "🇷🇴"),
    "BG": ("Bulgaria", "🇧🇬"), "RS": ("Serbia", "🇷🇸"),
    "SK": ("Slovakia", "🇸🇰"), "LT": ("Lithuania", "🇱🇹"),
    "LV": ("Latvia", "🇱🇻"), "EE": ("Estonia", "🇪🇪"),
    "IE": ("Ireland", "🇮🇪"), "PT": ("Portugal", "🇵🇹"),
    "GR": ("Greece", "🇬🇷"), "NO": ("Norway", "🇳🇴"),
    "DK": ("Denmark", "🇩🇰"), "MX": ("Mexico", "🇲🇽"),
    "BR": ("Brazil", "🇧🇷"), "AR": ("Argentina", "🇦🇷"),
    "IL": ("Israel", "🇮🇱"), "AE": ("UAE", "🇦🇪"),
    "TH": ("Thailand", "🇹🇭"), "VN": ("Vietnam", "🇻🇳"),
    "ID": ("Indonesia", "🇮🇩"), "MY": ("Malaysia", "🇲🇾"),
    "UNKNOWN": ("Server", "🌐"),
}

COUNTRY_MAP = {
    "germany": "DE", "deutschland": "DE", "германия": "DE",
    "netherlands": "NL", "nederland": "NL", "нидерланды": "NL", "голландия": "NL",
    "united states": "US", "usa": "US", "america": "US", "сша": "US",
    "france": "FR", "франция": "FR",
    "united kingdom": "GB", "uk": "GB", "britain": "GB", "великобритания": "GB", "англия": "GB",
    "singapore": "SG", "сингапур": "SG",
    "canada": "CA", "канада": "CA",
    "japan": "JP", "япония": "JP",
    "finland": "FI", "финляндия": "FI",
    "poland": "PL", "польша": "PL",
    "russia": "RU", "россия": "RU",
    "turkey": "TR", "турция": "TR",
    "kazakhstan": "KZ", "казахстан": "KZ",
    "sweden": "SE", "швеция": "SE",
    "switzerland": "CH", "швейцария": "CH",
    "italy": "IT", "италия": "IT",
    "spain": "ES", "испания": "ES",
    "austria": "AT", "австрия": "AT",
    "belgium": "BE", "бельгия": "BE",
    "czechia": "CZ", "czech": "CZ", "чехия": "CZ",
    "hong kong": "HK", "hongkong": "HK", "гонконг": "HK",
    "korea": "KR", "south korea": "KR", "корея": "KR",
    "taiwan": "TW", "тайвань": "TW",
    "australia": "AU", "австралия": "AU",
    "india": "IN", "индия": "IN",
    "ukraine": "UA", "украина": "UA",
    "hungary": "HU", "венгрия": "HU",
    "romania": "RO", "румыния": "RO",
    "bulgaria": "BG", "болгария": "BG",
    "serbia": "RS", "сербия": "RS",
    "slovakia": "SK", "словакия": "SK",
    "lithuania": "LT", "литва": "LT",
    "latvia": "LV", "латвия": "LV",
    "estonia": "EE", "эстония": "EE",
    "ireland": "IE", "ирландия": "IE",
    "portugal": "PT", "португалия": "PT",
    "greece": "GR", "греция": "GR",
    "norway": "NO", "норвегия": "NO",
    "denmark": "DK", "дания": "DK",
    "mexico": "MX", "мексика": "MX",
    "brazil": "BR", "бразилия": "BR",
    "argentina": "AR", "аргентина": "AR",
    "israel": "IL", "израиль": "IL",
    "uae": "AE", "emirates": "AE", "оаэ": "AE",
    "thailand": "TH", "тайланд": "TH", "таиланд": "TH",
    "vietnam": "VN", "вьетнам": "VN",
    "indonesia": "ID", "индонезия": "ID",
    "malaysia": "MY", "малайзия": "MY",
}

# ====================== ПАРСИНГ ======================
def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", errors="ignore")


def parse_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    if "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    if scheme == "socks":
        line = "socks5://" + line.split("://", 1)[1]
    if scheme not in SUPPORTED_SCHEMES and not line.lower().startswith("socks5://"):
        return None
    return line


def get_scheme(proxy_line: str) -> str:
    s = proxy_line.split("://", 1)[0].lower()
    if s == "hy2":
        return "hysteria2"
    if s == "socks":
        return "socks5"
    return s


def extract_host_port(proxy_line: str) -> tuple[str | None, int]:
    scheme = get_scheme(proxy_line)
    if scheme == "vmess":
        try:
            payload = proxy_line.split("://", 1)[1].strip().split("#")[0]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
            host = data.get("add") or data.get("host")
            port = int(data.get("port", 443))
            if host:
                return host, port
        except Exception:
            pass
    try:
        clean = proxy_line.split("#", 1)[0]
        p = urlsplit(clean)
        host = p.hostname
        port = p.port
        if host:
            if not port:
                port = 443 if scheme in ("vless", "trojan", "hysteria2", "https", "tuic", "vmess") else 80
            return host, port
    except Exception:
        pass
    return None, 0


def detect_country(proxy_line: str) -> str:
    text = proxy_line.lower()
    if "#" in proxy_line:
        remark = unquote(proxy_line.split("#", 1)[1]).lower()
        m = re.search(r"(?:^|[\s\[\(\-_])([a-z]{2})(?:$|[\s\]\)\-_])", remark)
        if m and m.group(1).upper() in COUNTRY_DATA:
            return m.group(1).upper()
        for name, code in COUNTRY_MAP.items():
            if name in remark:
                return code
    m = re.search(r"[#\[\-_/\s]([a-z]{2})[#\]\-_/\s]", text)
    if m and m.group(1).upper() in COUNTRY_DATA:
        return m.group(1).upper()
    for name, code in COUNTRY_MAP.items():
        if name in text:
            return code
    return "UNKNOWN"


def parse_vless_params(proxy_line: str) -> dict:
    res = {"security": "", "sni": "", "is_reality": False}
    try:
        if not proxy_line.lower().startswith("vless://"):
            return res
        clean = proxy_line.split("#", 1)[0]
        qs = parse_qs(urlsplit(clean).query)
        security = (qs.get("security") or [""])[0].lower()
        sni = (qs.get("sni") or qs.get("host") or [""])[0].lower()
        res["security"] = security
        res["sni"] = sni
        res["is_reality"] = security == "reality" or "pbk=" in proxy_line.lower()
    except Exception:
        pass
    return res


def format_clean_proxy(proxy_line: str, country_code: str) -> str:
    info = COUNTRY_DATA.get(country_code, COUNTRY_DATA["UNKNOWN"])
    name = f"{info[1]} {info[0]}"
    scheme = get_scheme(proxy_line)

    if scheme == "vmess":
        try:
            prefix, payload = proxy_line.split("://", 1)
            payload_clean = payload.strip().split("#")[0]
            payload_padded = payload_clean + "=" * ((4 - len(payload_clean) % 4) % 4)
            data = json.loads(base64.b64decode(payload_padded).decode("utf-8", errors="ignore"))
            data["ps"] = name
            new_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            new_payload = base64.b64encode(new_json.encode("utf-8")).decode("ascii")
            return f"{prefix}://{new_payload}"
        except Exception:
            return proxy_line

    base = proxy_line.split("#", 1)[0]
    return f"{base}#{quote(name)}"


# ====================== XRAY CONFIG GENERATORS ======================
def b64decode_urlsafe(s: str) -> bytes:
    s = s.strip()
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def make_xray_config(proxy_line: str, local_port: int) -> dict | None:
    """Возвращает полный config xray или None, если протокол не поддерживаем."""
    scheme = get_scheme(proxy_line)
    try:
        if scheme == "vless":
            return _config_vless(proxy_line, local_port)
        if scheme == "vmess":
            return _config_vmess(proxy_line, local_port)
        if scheme == "trojan":
            return _config_trojan(proxy_line, local_port)
        if scheme == "ss":
            return _config_ss(proxy_line, local_port)
    except Exception:
        return None
    return None


def _base_inbound(local_port: int) -> dict:
    return {
        "port": local_port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"udp": True, "auth": "noauth"},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def _config_vless(line: str, local_port: int) -> dict | None:
    clean = line.split("#", 1)[0]
    u = urlparse(clean)
    host = u.hostname
    port = u.port or 443
    uuid_ = u.username
    if not host or not uuid_:
        return None

    qs = parse_qs(u.query)
    security = (qs.get("security") or ["none"])[0].lower()
    network = (qs.get("type") or ["tcp"])[0].lower()
    sni = (qs.get("sni") or qs.get("host") or [host])[0]
    fp = (qs.get("fp") or ["chrome"])[0]
    flow = (qs.get("flow") or [""])[0]
    path = (qs.get("path") or ["/"])[0]
    host_header = (qs.get("host") or [sni])[0]
    pbk = (qs.get("pbk") or [""])[0]
    sid = (qs.get("sid") or [""])[0]
    spx = (qs.get("spx") or [""])[0]

    stream: dict = {"network": network}
    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "show": False,
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": spx or "",
        }
    elif security in ("tls", "xtls"):
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": sni,
            "allowInsecure": True,
            "fingerprint": fp,
        }
    else:
        stream["security"] = "none"

    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": path.lstrip("/")}

    user = {"id": uuid_, "encryption": "none"}
    if flow:
        user["flow"] = flow

    return {
        "log": {"loglevel": "none"},
        "inbounds": [_base_inbound(local_port)],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [user],
                }]
            },
            "streamSettings": stream,
        }],
    }


def _config_vmess(line: str, local_port: int) -> dict | None:
    payload = line.split("://", 1)[1].strip().split("#")[0]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
    host = data.get("add") or data.get("host")
    port = int(data.get("port", 443))
    uuid_ = data.get("id")
    if not host or not uuid_:
        return None

    network = (data.get("net") or "tcp").lower()
    tls = (data.get("tls") or "").lower()
    sni = data.get("sni") or data.get("host") or host
    path = data.get("path") or "/"
    host_header = data.get("host") or sni
    aid = int(data.get("aid") or data.get("alterId") or 0)

    stream: dict = {"network": network}
    if tls in ("tls", "reality"):
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
    else:
        stream["security"] = "none"

    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": path.lstrip("/")}

    return {
        "log": {"loglevel": "none"},
        "inbounds": [_base_inbound(local_port)],
        "outbounds": [{
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid_,
                        "alterId": aid,
                        "security": data.get("scy") or "auto",
                    }],
                }]
            },
            "streamSettings": stream,
        }],
    }


def _config_trojan(line: str, local_port: int) -> dict | None:
    clean = line.split("#", 1)[0]
    u = urlparse(clean)
    host = u.hostname
    port = u.port or 443
    password = unquote(u.username or "")
    if not host or not password:
        return None

    qs = parse_qs(u.query)
    sni = (qs.get("sni") or qs.get("peer") or [host])[0]
    network = (qs.get("type") or ["tcp"])[0].lower()
    path = (qs.get("path") or ["/"])[0]
    host_header = (qs.get("host") or [sni])[0]
    fp = (qs.get("fp") or ["chrome"])[0]
    security = (qs.get("security") or ["tls"])[0].lower()

    stream: dict = {"network": network}
    if security == "reality":
        pbk = (qs.get("pbk") or [""])[0]
        sid = (qs.get("sid") or [""])[0]
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
        }
    else:
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": sni,
            "allowInsecure": True,
            "fingerprint": fp,
        }

    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": path.lstrip("/")}

    return {
        "log": {"loglevel": "none"},
        "inbounds": [_base_inbound(local_port)],
        "outbounds": [{
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password,
                }]
            },
            "streamSettings": stream,
        }],
    }


def _config_ss(line: str, local_port: int) -> dict | None:
    # ss://base64(method:password)@host:port  или ss://method:password@host:port
    clean = line.split("#", 1)[0]
    u = urlparse(clean)
    host = u.hostname
    port = u.port
    if not host or not port:
        return None

    userinfo = u.username or ""
    if u.password:
        method = unquote(userinfo)
        password = unquote(u.password)
    else:
        try:
            decoded = b64decode_urlsafe(userinfo).decode("utf-8", errors="ignore")
            if ":" in decoded:
                method, password = decoded.split(":", 1)
            else:
                return None
        except Exception:
            return None

    return {
        "log": {"loglevel": "none"},
        "inbounds": [_base_inbound(local_port)],
        "outbounds": [{
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }]
            },
        }],
    }


# ====================== ПРОВЕРКИ ======================
async def resolve_to_ip(host: str) -> str:
    if not host:
        return ""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return host


async def tcp_check(host: str, port: int) -> float | None:
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return (time.monotonic() - started) * 1000
    except Exception:
        return None


def xray_test_sync(proxy_line: str, local_port: int) -> float | None:
    """Синхронная проверка через xray. Возвращает latency ms или None."""
    cfg = make_xray_config(proxy_line, local_port)
    if not cfg:
        return None

    conf_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            conf_path = f.name

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", conf_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        time.sleep(0.35)  # даём xray подняться

        if proc.poll() is not None:
            return None

        started = time.monotonic()
        # проверяем через gstatic
        curl = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--connect-timeout", "4", "--max-time", str(int(XRAY_TIMEOUT)),
                "-x", f"socks5h://127.0.0.1:{local_port}",
                "http://www.gstatic.com/generate_204",
            ],
            capture_output=True,
            text=True,
        )
        code = (curl.stdout or "").strip()
        if code == "204":
            return (time.monotonic() - started) * 1000
        return None
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if conf_path and os.path.exists(conf_path):
            try:
                os.unlink(conf_path)
            except Exception:
                pass


async def check_one_tcp(proxy_line: str, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        host, port = extract_host_port(proxy_line)
        if not host or not port:
            return None
        latency = await tcp_check(host, port)
        if latency is None:
            return None
        ip = await resolve_to_ip(host)
        country = detect_country(proxy_line)
        scheme = get_scheme(proxy_line)
        vless_info = parse_vless_params(proxy_line) if scheme == "vless" else {}
        return {
            "proxy": format_clean_proxy(proxy_line, country),
            "raw": proxy_line,
            "ip": ip,
            "country": country,
            "scheme": scheme,
            "latency_ms": int(latency),
            "is_reality": vless_info.get("is_reality", False),
            "sni": vless_info.get("sni", ""),
            "xray_ok": False,
        }


async def check_one_xray(item: dict, port_queue: asyncio.Queue) -> dict | None:
    local_port = await port_queue.get()
    try:
        loop = asyncio.get_running_loop()
        latency = await loop.run_in_executor(
            None, xray_test_sync, item["raw"], local_port
        )
        if latency is None:
            return None
        item = dict(item)
        item["latency_ms"] = int(latency)
        item["xray_ok"] = True
        item["proxy"] = format_clean_proxy(item["raw"], item["country"])
        return item
    finally:
        await port_queue.put(local_port)


# ====================== ФИЛЬТРЫ ======================
def smart_filter(items: list[dict], max_per_country=MAX_PER_COUNTRY, max_total=MAX_TOTAL, unique_ip=True) -> list[dict]:
    items = sorted(items, key=lambda x: x["latency_ms"])
    seen_ips: set[str] = set()
    country_counts: dict[str, int] = defaultdict(int)
    result = []
    for item in items:
        if len(result) >= max_total:
            break
        ip, country = item["ip"], item["country"]
        if unique_ip and ip and ip in seen_ips:
            continue
        if country_counts[country] >= max_per_country:
            continue
        if unique_ip and ip:
            seen_ips.add(ip)
        country_counts[country] += 1
        result.append(item)
    return result


def smart_filter_white(items: list[dict]) -> list[dict]:
    vless_items = [i for i in items if i["scheme"] == "vless"]

    def prio(it: dict):
        is_reality = 0 if it.get("is_reality") else 1
        sni = (it.get("sni") or "").lower()
        good = 0 if sni in GOOD_SNI else 1
        ru = 0 if any(x in sni for x in ("vk.com", "yandex", "ya.ru", "mail.ru", "ok.ru", "userapi")) else 1
        return (is_reality, ru, good, it["latency_ms"])

    vless_items.sort(key=prio)
    ip_counts: dict[str, int] = defaultdict(int)
    country_counts: dict[str, int] = defaultdict(int)
    result = []
    for item in vless_items:
        if len(result) >= WHITE_MAX_TOTAL:
            break
        ip, country = item["ip"], item["country"]
        if ip_counts[ip] >= WHITE_MAX_PER_IP:
            continue
        if country_counts[country] >= WHITE_MAX_PER_COUNTRY:
            continue
        ip_counts[ip] += 1
        country_counts[country] += 1
        result.append(item)
    return result


def write_list(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [i["proxy"] for i in items]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# ====================== MAIN ======================
async def main_async() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_proto = OUT_DIR / "by_protocol"
    by_proto.mkdir(exist_ok=True)

    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}] Source: {SOURCE_URL}")
    print(f"TCP concurrency={CONCURRENCY}, Xray workers={XRAY_WORKERS}")

    # ---- download ----
    try:
        text = await asyncio.to_thread(fetch_url, SOURCE_URL)
    except Exception as e:
        print(f"Ошибка скачивания: {e}")
        return 1

    try:
        cleaned = text.strip().replace("\n", "").replace("\r", "")
        cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
        decoded = base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")
        if "://" in decoded:
            text = decoded
            print("Подписка декодирована из base64")
    except Exception:
        pass

    seen = set()
    configs = []
    for line in text.splitlines():
        p = parse_line(line)
        if p and p not in seen:
            seen.add(p)
            configs.append(p)
    print(f"Уникальных конфигов: {len(configs)}")
    if not configs:
        return 0

    # ---- Stage 1: TCP ----
    print("Стадия 1: TCP проверка...")
    sem = asyncio.Semaphore(CONCURRENCY)
    tcp_results = await asyncio.gather(*[check_one_tcp(c, sem) for c in configs])
    tcp_alive = [r for r in tcp_results if r]
    tcp_alive.sort(key=lambda x: x["latency_ms"])
    print(f"TCP живых: {len(tcp_alive)}")

    # берём лучших кандидатов на xray
    candidates = tcp_alive[:MAX_XRAY_CANDIDATES]
    print(f"На Xray проверку: {len(candidates)}")

    # ---- Stage 2: Xray ----
    xray_ok = []
    if candidates:
        # проверяем, есть ли xray
        try:
            subprocess.run([XRAY_BIN, "version"], capture_output=True, check=True)
        except Exception:
            print("Xray не найден, пропускаем стадию 2")
            xray_ok = candidates  # fallback — считаем TCP достаточным
        else:
            print("Стадия 2: Xray + gstatic...")
            port_queue: asyncio.Queue = asyncio.Queue()
            base_port = 11000
            for i in range(XRAY_WORKERS):
                await port_queue.put(base_port + i)

            sem_x = asyncio.Semaphore(XRAY_WORKERS)

            async def worker(item):
                async with sem_x:
                    return await check_one_xray(item, port_queue)

            results = await asyncio.gather(*[worker(it) for it in candidates])
            xray_ok = [r for r in results if r]
            print(f"Xray рабочих: {len(xray_ok)}")

    if not xray_ok:
        xray_ok = tcp_alive  # если xray ничего не дал — используем TCP

    final = xray_ok
    final.sort(key=lambda x: x["latency_ms"])

    # ---- запись ----
    main_list = smart_filter(final)
    write_list(OUT_DIR / "all.txt", main_list)
    write_list(OUT_DIR / "working_proxies.txt", main_list)
    print(f"Основной список: {len(main_list)}")

    white = smart_filter_white(final)
    write_list(OUT_DIR / "white_checked.txt", white)
    print(f"White list: {len(white)}")

    by_scheme: dict[str, list] = defaultdict(list)
    for it in final:
        by_scheme[it["scheme"]].append(it)

    for scheme, items in by_scheme.items():
        filtered = smart_filter(items)
        write_list(by_proto / f"{scheme}.txt", filtered)
        write_list(OUT_DIR / f"{scheme}.txt", filtered)
        if filtered:
            print(f"  {scheme}.txt → {len(filtered)}")

    print("Готово.")
    return 0


def main():
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())

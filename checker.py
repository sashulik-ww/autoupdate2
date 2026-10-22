from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
)
TIMEOUT = float(os.getenv("TIMEOUT", "5"))
REQUIRE_SPB = os.getenv("REQUIRE_SPB", "false").lower() == "true"
OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

GEO_URL = "http://ip-api.com/json/?fields=status,message,countryCode,regionName,city,query"

SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "ss", "ssr", "hysteria2", "hy2", "tuic", "socks5", "http", "https")

# Красивые названия и флаги стран
COUNTRY_DATA = {
    "DE": ("Germany", "🇩🇪"),
    "NL": ("Netherlands", "🇳🇱"),
    "US": ("United States", "🇺🇸"),
    "FR": ("France", "🇫🇷"),
    "GB": ("United Kingdom", "🇬🇧"),
    "SG": ("Singapore", "🇸🇬"),
    "CA": ("Canada", "🇨🇦"),
    "JP": ("Japan", "🇯🇵"),
    "FI": ("Finland", "🇫🇮"),
    "PL": ("Poland", "🇵🇱"),
    "RU": ("Russia", "🇷🇺"),
    "TR": ("Turkey", "🇹🇷"),
    "KZ": ("Kazakhstan", "🇰🇿"),
    "SE": ("Sweden", "🇸🇪"),
    "CH": ("Switzerland", "🇨🇭"),
    "IT": ("Italy", "🇮🇹"),
    "ES": ("Spain", "🇪🇸"),
    "UNKNOWN": ("Server", "🌐")
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
}


def parse_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" not in line:
        return None
    scheme = line.split("://")[0].lower()
    return line if scheme in SUPPORTED_SCHEMES else None


def extract_host_port(proxy_line: str) -> tuple[str | None, int]:
    scheme = proxy_line.split("://")[0].lower()
    if scheme == "vmess":
        try:
            payload = proxy_line.split("://", 1)[1].strip()
            payload += "=" * ((4 - len(payload) % 4) % 4)
            decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            host = data.get("add")
            port = int(data.get("port", 443))
            if host:
                return host, port
        except Exception:
            pass

    try:
        parts = urlsplit(proxy_line)
        host = parts.hostname
        port = parts.port
        if host:
            if not port:
                port = 443 if scheme in ("vless", "trojan", "hysteria2", "hy2", "https", "tuic") else 80
            return host, port
    except Exception:
        pass
    return None, 0


async def resolve_to_ip(host: str) -> str:
    if not host:
        return ""
    try:
        socket.inet_aton(host)
        return host
    except socket.error:
        try:
            loop = asyncio.get_running_loop()
            info = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            if info:
                return info[0][4][0]
        except Exception:
            pass
    return host


def detect_country(proxy_line: str) -> str:
    text_lower = proxy_line.lower()
    match = re.search(r'[#\[\-_/\s]([a-z]{2})[#\]\-_/\s]', text_lower)
    if match:
        code = match.group(1).upper()
        if code in COUNTRY_DATA or len(code) == 2:
            return code
    for name, code in COUNTRY_MAP.items():
        if name in text_lower:
            return code
    return "UNKNOWN"


def format_clean_proxy(proxy_line: str, country_code: str) -> str:
    info = COUNTRY_DATA.get(country_code, COUNTRY_DATA["UNKNOWN"])
    clean_name = f"{info[1]} {info[0]}"
    scheme = proxy_line.split("://")[0].lower()
    
    if scheme == "vmess":
        try:
            prefix, payload = proxy_line.split("://", 1)
            payload_clean = payload.strip().split("#")[0]
            payload_padded = payload_clean + "=" * ((4 - len(payload_clean) % 4) % 4)
            decoded = base64.b64decode(payload_padded).decode("utf-8", errors="ignore")
            data = json.loads(decoded)
            data["ps"] = clean_name
            new_json = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
            new_payload = base64.b64encode(new_json.encode("utf-8")).decode("utf-8")
            return f"{prefix}://{new_payload}"
        except Exception:
            return proxy_line
    else:
        base_part = proxy_line.split("#", 1)[0]
        return f"{base_part}#{quote(clean_name)}"


async def check_proxy(proxy_line: str) -> dict | None:
    try:
        host, port = extract_host_port(proxy_line)
        if not host or not port:
            return None

        started = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        
        latency = int((time.monotonic() - started) * 1000)
        resolved_ip = await resolve_to_ip(host)
        country = detect_country(proxy_line)
        cleaned_proxy = format_clean_proxy(proxy_line, country)

        return {
            "proxy": cleaned_proxy,
            "ip": resolved_ip,
            "country": country,
            "latency_ms": latency,
        }
    except Exception:
        return None


def smart_filter(working_list: list[dict], max_per_country: int = 4, max_total: int = 250) -> list[str]:
    seen_ips = set()
    country_counts = {}
    filtered_proxies = []

    for item in working_list:
        if len(filtered_proxies) >= max_total:
            break
        ip = item["ip"]
        proxy_line = item["proxy"]
        country = item["country"]

        if ip in seen_ips:
            continue

        count = country_counts.get(country, 0)
        if count < max_per_country:
            seen_ips.add(ip)
            country_counts[country] = count + 1
            filtered_proxies.append(proxy_line)

    return filtered_proxies


def smart_filter_white(working_list: list[dict], max_per_ip: int = 2, max_per_country: int = 5, max_total: int = 450) -> list[str]:
    white_friendly_schemes = ("vless", "trojan", "hysteria2", "hy2", "vmess")
    ip_counts = {}
    country_counts = {}
    filtered_proxies = []

    for item in working_list:
        if len(filtered_proxies) >= max_total:
            break
        proxy_line = item["proxy"]
        scheme = proxy_line.split("://")[0].lower()
        
        if scheme not in white_friendly_schemes:
            continue

        ip = item["ip"]
        country = item["country"]

        ip_count = ip_counts.get(ip, 0)
        country_count = country_counts.get(country, 0)

        if ip_count < max_per_ip and country_count < max_per_country:
            ip_counts[ip] = ip_count + 1
            country_counts[country] = country_count + 1
            filtered_proxies.append(proxy_line)

    return filtered_proxies


async def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    import aiohttp
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        try:
            async with session.get(SOURCE_URL) as r:
                r.raise_for_status()
                text = await r.text()
        except Exception as e:
            print(f"ОШИБКА скачивания: {e}")
            return 1

    try:
        cleaned_text = text.strip()
        cleaned_text += "=" * ((4 - len(cleaned_text) % 4) % 4)
        decoded_bytes = base64.b64decode(cleaned_text, validate=True)
        text = decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:
        pass

    seen_configs: set[str] = set()
    configs = []
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed and parsed not in seen_configs:
            seen_configs.add(parsed)

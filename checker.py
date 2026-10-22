#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import socket
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit
import urllib.request

# ====================== НАСТРОЙКИ ======================
SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
)
TIMEOUT = float(os.getenv("TIMEOUT", "8"))
CONCURRENCY = int(os.getenv("CONCURRENCY", "200"))
OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

# Основные списки
MAX_PER_COUNTRY = 4
MAX_TOTAL = 250

# White list
WHITE_MAX_PER_IP = 2
WHITE_MAX_PER_COUNTRY = 5
WHITE_MAX_TOTAL = 450

SUPPORTED_SCHEMES = (
    "vless", "vmess", "trojan", "ss", "ssr",
    "hysteria2", "hy2", "tuic", "socks5", "http", "https"
)

# Хорошие SNI для белых списков (приоритет у российских)
GOOD_SNI = {
    # Российские (высший приоритет)
    "vk.com", "www.vk.com", "m.vk.com",
    "yandex.ru", "ya.ru", "www.yandex.ru",
    "mail.ru", "www.mail.ru",
    "ok.ru", "www.ok.ru",
    "userapi.com", "api.vk.com",
    # Другие часто работающие
    "google.com", "www.google.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "cloudflare.com", "www.cloudflare.com",
    "github.com", "www.github.com",
    "discord.com", "www.discord.com",
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
}


# ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======================
def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=45) as response:
        return response.read().decode("utf-8", errors="ignore")


def parse_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    if "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    if scheme == "socks":
        line = "socks5://" + line.split("://", 1)[1]
        scheme = "socks5"
    return line if scheme in SUPPORTED_SCHEMES else None


def extract_host_port(proxy_line: str) -> tuple[str | None, int]:
    scheme = proxy_line.split("://", 1)[0].lower()

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
        parts = urlsplit(clean)
        host = parts.hostname
        port = parts.port
        if host:
            if not port:
                port = 443 if scheme in ("vless", "trojan", "hysteria2", "hy2", "https", "tuic", "vmess") else 80
            return host, port
    except Exception:
        pass
    return None, 0


def get_scheme(proxy_line: str) -> str:
    scheme = proxy_line.split("://", 1)[0].lower()
    if scheme == "hy2":
        return "hysteria2"
    if scheme == "socks":
        return "socks5"
    return scheme


def detect_country(proxy_line: str) -> str:
    text = proxy_line.lower()
    if "#" in proxy_line:
        remark = unquote(proxy_line.split("#", 1)[1]).lower()
        m = re.search(r"(?:^|[\s\[\(\-_])([a-z]{2})(?:$|[\s\]\)\-_])", remark)
        if m:
            code = m.group(1).upper()
            if code in COUNTRY_DATA:
                return code
        for name, code in COUNTRY_MAP.items():
            if name in remark:
                return code

    m = re.search(r"[#\[\-_/\s]([a-z]{2})[#\]\-_/\s]", text)
    if m:
        code = m.group(1).upper()
        if code in COUNTRY_DATA:
            return code
    for name, code in COUNTRY_MAP.items():
        if name in text:
            return code
    return "UNKNOWN"


def parse_vless_params(proxy_line: str) -> dict:
    """Достаём security, sni и другие параметры из VLESS-ссылки"""
    result = {"security": "", "sni": "", "is_reality": False}
    try:
        if not proxy_line.lower().startswith("vless://"):
            return result
        clean = proxy_line.split("#", 1)[0]
        parts = urlsplit(clean)
        qs = parse_qs(parts.query)

        security = (qs.get("security") or [""])[0].lower()
        sni = (qs.get("sni") or qs.get("host") or [""])[0].lower()

        result["security"] = security
        result["sni"] = sni
        result["is_reality"] = security == "reality" or "pbk=" in proxy_line.lower()
    except Exception:
        pass
    return result


def format_clean_proxy(proxy_line: str, country_code: str, latency_ms: int | None = None) -> str:
    info = COUNTRY_DATA.get(country_code, COUNTRY_DATA["UNKNOWN"])
    name = f"{info[1]} {info[0]}"
    if latency_ms is not None:
        name = f"{name} | {latency_ms}ms"

    scheme = proxy_line.split("://", 1)[0].lower()

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


async def check_proxy(proxy_line: str, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        try:
            host, port = extract_host_port(proxy_line)
            if not host or not port:
                return None

            started = time.monotonic()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=TIMEOUT,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            latency = int((time.monotonic() - started) * 1000)
            resolved_ip = await resolve_to_ip(host)
            country = detect_country(proxy_line)
            scheme = get_scheme(proxy_line)
            cleaned = format_clean_proxy(proxy_line, country, latency)

            vless_info = parse_vless_params(proxy_line) if scheme == "vless" else {}

            return {
                "proxy": cleaned,
                "raw": proxy_line,
                "ip": resolved_ip,
                "country": country,
                "scheme": scheme,
                "latency_ms": latency,
                "is_reality": vless_info.get("is_reality", False),
                "sni": vless_info.get("sni", ""),
                "security": vless_info.get("security", ""),
            }
        except Exception:
            return None


# ====================== ФИЛЬТРАЦИЯ ======================
def smart_filter(
    items: list[dict],
    max_per_country: int = MAX_PER_COUNTRY,
    max_total: int = MAX_TOTAL,
    unique_ip: bool = True,
) -> list[dict]:
    items = sorted(items, key=lambda x: x["latency_ms"])
    seen_ips: set[str] = set()
    country_counts: dict[str, int] = defaultdict(int)
    result: list[dict] = []

    for item in items:
        if len(result) >= max_total:
            break
        ip = item["ip"]
        country = item["country"]

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
    """
    White list:
    - Только VLESS
    - Приоритет: Reality + хороший/российский SNI
    - Потом обычный Reality
    - Обычный VLESS (без Reality) — в самый конец (можно отключить)
    """
    # Оставляем только VLESS
    vless_items = [i for i in items if i["scheme"] == "vless"]

    def priority(item: dict) -> tuple:
        is_reality = 0 if item.get("is_reality") else 1
        sni = (item.get("sni") or "").lower()
        has_good_sni = 0 if sni in GOOD_SNI else 1
        # Российские SNI ещё выше
        is_ru_sni = 0 if any(x in sni for x in ("vk.com", "yandex", "ya.ru", "mail.ru", "ok.ru", "userapi")) else 1
        return (is_reality, is_ru_sni, has_good_sni, item["latency_ms"])

    vless_items.sort(key=priority)

    ip_counts: dict[str, int] = defaultdict(int)
    country_counts: dict[str, int] = defaultdict(int)
    result: list[dict] = []

    for item in vless_items:
        if len(result) >= WHITE_MAX_TOTAL:
            break

        # Можно раскомментировать, если хочешь ТОЛЬКО Reality:
        # if not item.get("is_reality"):
        #     continue

        ip = item["ip"]
        country = item["country"]

        if ip_counts[ip] >= WHITE_MAX_PER_IP:
            continue
        if country_counts[country] >= WHITE_MAX_PER_COUNTRY:
            continue

        ip_counts[ip] += 1
        country_counts[country] += 1
        result.append(item)

    return result


# ====================== ЗАПИСЬ ======================
def write_list(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [item["proxy"] for item in items]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# ====================== MAIN ======================
async def main_async() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_proto_dir = OUT_DIR / "by_protocol"
    by_proto_dir.mkdir(parents=True, exist_ok=True)

    print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}] Source: {SOURCE_URL}")
    print(f"Timeout={TIMEOUT}s  Concurrency={CONCURRENCY}")

    print("Скачивание списка...")
    try:
        text = await asyncio.to_thread(fetch_url, SOURCE_URL)
    except Exception as e:
        print(f"ОШИБКА скачивания: {e}")
        return 1

    # Пробуем base64
    try:
        cleaned = text.strip().replace("\n", "").replace("\r", "")
        cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
        decoded = base64.b64decode(cleaned, validate=False)
        decoded_text = decoded.decode("utf-8", errors="ignore")
        if "://" in decoded_text:
            text = decoded_text
            print("Подписка декодирована из base64")
    except Exception:
        pass

    seen: set[str] = set()
    configs: list[str] = []
    for line in text.splitlines():
        p = parse_line(line)
        if p and p not in seen:
            seen.add(p)
            configs.append(p)

    print(f"Уникальных конфигов: {len(configs)}")
    if not configs:
        print("Список пуст")
        return 0

    print("Запуск проверки...")
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_proxy(cfg, sem) for cfg in configs]

    working: list[dict] = []
    chunk_size = 300
    for i in range(0, len(tasks), chunk_size):
        chunk = tasks[i:i + chunk_size]
        results = await asyncio.gather(*chunk)
        for res in results:
            if res:
                working.append(res)
        print(f"  проверено {min(i + chunk_size, len(tasks))}/{len(tasks)} | живых: {len(working)}")

    working.sort(key=lambda x: x["latency_ms"])
    print(f"Всего рабочих: {len(working)}")

    if not working:
        print("Нет рабочих серверов")
        return 0

    # ===== Основной список =====
    main_list = smart_filter(working)
    write_list(OUT_DIR / "all.txt", main_list)
    write_list(OUT_DIR / "working_proxies.txt", main_list)
    print(f"Основной список: {len(main_list)}")

    # ===== White list (VLESS Reality приоритет) =====
    white_list = smart_filter_white(working)
    write_list(OUT_DIR / "white_checked.txt", white_list)
    print(f"White list (VLESS приоритет Reality + SNI): {len(white_list)}")

    # ===== По протоколам =====
    by_scheme: dict[str, list[dict]] = defaultdict(list)
    for item in working:
        by_scheme[item["scheme"]].append(item)

    for scheme, items in by_scheme.items():
        filtered = smart_filter(items)
        write_list(by_proto_dir / f"{scheme}.txt", filtered)
        # Также в корень для совместимости
        write_list(OUT_DIR / f"{scheme}.txt", filtered)
        if filtered:
            print(f"  {scheme}.txt → {len(filtered)}")

    print("Готово.")
    return 0


def main():
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())

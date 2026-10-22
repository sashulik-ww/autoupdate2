from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
)
TIMEOUT = float(os.getenv("TIMEOUT", "5"))  # Таймаут на TCP-соединение
REQUIRE_SPB = os.getenv("REQUIRE_SPB", "true").lower() == "true"
OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

GEO_URL = "http://ip-api.com/json/?fields=status,message,countryCode,regionName,city,query"

# Поддерживаемые протоколы для v2rayNG
SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "ss", "ssr", "hysteria2", "hy2", "tuic", "socks5", "http", "https")


def parse_line(line: str) -> str | None:
    """
    Парсит строку. Поддерживает как ссылки вида vless://, trojan://, так и старые http://.
    Возвращает чистую оригинальную строку конфига или None, если формат неверный.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    
    # Проверяем, есть ли разделитель схемы (://)
    if "://" not in line:
        return None
    
    scheme = line.split("://")[0].lower()
    if scheme in SUPPORTED_SCHEMES:
        return line
    return None


def is_spb(geo: dict) -> bool:
    place = f"{geo.get('city', '')} {geo.get('regionName', '')}".lower()
    return geo.get("countryCode") == "RU" and "petersburg" in place


async def check_tcp_port(proxy_line: str) -> dict | None:
    """
    Быстрая и надежная проверка доступности хоста и порта через TCP-сокет.
    Это универсальный метод, который работает для vless, trojan, vmess и т.д.,
    не требуя поднятия тяжелого туннеля на каждый узел.
    """
    try:
        # Извлекаем хост и порт из строки конфига
        # Для ссылок вида protocol://user@host:port/path...
        parts = urlsplit(proxy_line)
        host = parts.hostname
        port = parts.port
        
        if not host:
            return None
        if not port:
            # Дефолтные порты для защищенных протоколов
            port = 443 if parts.scheme in ("vless", "trojan", "hysteria2", "hy2", "https") else 80

        started = time.monotonic()
        
        # Асинхронное открытие TCP-соединения
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        
        latency = int((time.monotonic() - started) * 1000)
        return {
            "proxy": proxy_line,
            "latency_ms": latency,
        }
    except Exception:
        return None


async def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    import aiohttp
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        # 1. Проверка геолокации runner-а
        try:
            async with session.get(GEO_URL) as r:
                geo = await r.json(content_type=None)
        except Exception as e:
            geo = {}
            print(f"Не удалось определить геолокацию: {e}")
        
        print(f"Runner: {geo.get('query')} — {geo.get('city')}, {geo.get('regionName')}, {geo.get('countryCode')}")
        if REQUIRE_SPB and not is_spb(geo):
            print("ОШИБКА: runner не в Санкт-Петербурге, проверка не имеет смысла. "
                  "Поставь REQUIRE_SPB=false в check.yml, чтобы отключить эту защиту.")
            return 2

        # 2. Загружаем список из источника
        try:
            async with session.get(SOURCE_URL) as r:
                r.raise_for_status()
                text = await r.text()
        except Exception as e:
            print(f"ОШИБКА: не удалось скачать список: {e}")
            return 1

    # Если файл зашифрован в Base64 (стандарт для некоторых подписок)
    try:
        decoded_bytes = base64.b64decode(text.strip(), validate=True)
        text = decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:
        pass  - # Значит, это обычный текст со списком строк

    # 3. Парсим и убираем дубликаты
    seen: set[str] = set()
    configs = []
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed and parsed not in seen:
            seen.add(parsed)
            configs.append(parsed)
            
    print(f"В исходном списке найдено {len(configs)} уникальных конфигураций для v2rayNG.")

    # 4. Проверяем доступность серверов параллельно
    print(f"Запуск проверки (таймаут: {TIMEOUT}с)...")
    tasks = [check_tcp_port(cfg) for cfg in configs]
    working = []
    
    # Выполняем пачками, чтобы не перегружать сеть
    chunk_size = 100
    for i in range(0, len(tasks), chunk_size):
        chunk = tasks[i:i + chunk_size]
        results = await asyncio.gather(*chunk)
        for res in results:
            if res:
                working.append(res)
        print(f"  проверено {min(i + chunk_size, len(tasks))}/{len(tasks)}, рабочих: {len(working)}")

    # Сортируем по отклику (пинг)
    working.sort(key=lambda r: r["latency_ms"])
    print(f"Готово: рабочих конфигураций {len(working)} из {len(configs)}")

    # 5. Сохраняем результаты в папку results/
    (OUT_DIR / "working_proxies.txt").write_text(
        "".join(r["proxy"] + "\n" for r in working), encoding="utf-8"
    )
    
    (OUT_DIR / "working_proxies.json").write_text(
        json.dumps(
            {
                "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "runner": {k: geo.get(k) for k in ("query", "city", "regionName", "countryCode")},
                "source": SOURCE_URL,
                "total_checked": len(configs),
                "working_count": len(working),
                "proxies": working,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

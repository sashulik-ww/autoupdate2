#!/usr/bin/env python3
"""
Проверка работоспособности прокси из публичного списка.

ВАЖНО: прокси проверяются «оттуда, где запущен скрипт». Чтобы результат
означал «работает из Санкт-Петербурга», запускать его нужно на машине в СПб
(self-hosted runner). Перед проверкой скрипт определяет геолокацию своего IP
и останавливается, если это не СПб (REQUIRE_SPB=true).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

import aiohttp

SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt",
)
# Формат: url или url|ожидаемый_статус, через запятую.
# Прокси должен пройти ВСЕ тесты.
TEST_URLS_RAW = os.getenv(
    "TEST_URLS", "http://www.gstatic.com/generate_204|204,https://ya.ru"
)
CONCURRENCY = int(os.getenv("CONCURRENCY", "200"))
TIMEOUT = float(os.getenv("TIMEOUT", "10"))  # секунд на один запрос
REQUIRE_SPB = os.getenv("REQUIRE_SPB", "true").lower() == "true"
OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

GEO_URL = "http://ip-api.com/json/?fields=status,message,countryCode,regionName,city,query"


def parse_tests(raw: str) -> list[tuple[str, int | None]]:
    tests = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        url, _, status = item.partition("|")
        tests.append((url.strip(), int(status) if status.strip() else None))
    return tests


TESTS = parse_tests(TEST_URLS_RAW)


def parse_line(line: str):
    """'http://[user:pass@]ip:port#label' -> (чистый proxy-url, label) или None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        parts = urlsplit(line)
        if parts.scheme not in ("http", "https") or not parts.hostname or not parts.port:
            return None
        return f"{parts.scheme}://{parts.netloc}", unquote(parts.fragment)
    except ValueError:
        return None


def is_spb(geo: dict) -> bool:
    place = f"{geo.get('city', '')} {geo.get('regionName', '')}".lower()
    return geo.get("countryCode") == "RU" and "petersburg" in place


async def check_one(sem: asyncio.Semaphore, proxy: str, label: str):
    async with sem:
        timeout = aiohttp.ClientTimeout(total=TIMEOUT)
        started = time.monotonic()
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for url, expected in TESTS:
                    async with session.get(url, proxy=proxy, allow_redirects=False) as resp:
                        await resp.read()
                        ok = resp.status == expected if expected else resp.status < 400
                        if not ok:
                            return None
        except Exception:
            return None
        return {
            "proxy": proxy,
            "label": label,
            "latency_ms": int((time.monotonic() - started) * 1000),
        }


async def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        # 1. Где мы находимся
        try:
            async with session.get(GEO_URL) as r:
                geo = await r.json(content_type=None)
        except Exception as e:
            geo = {}
            print(f"Не удалось определить геолокацию: {e}")
        print(f"Runner: {geo.get('query')} — {geo.get('city')}, {geo.get('regionName')}, {geo.get('countryCode')}")
        if REQUIRE_SPB and not is_spb(geo):
            print("ОШИБКА: runner не в Санкт-Петербурге, проверка не имеет смысла. "
                  "Поставь REQUIRE_SPB=false, чтобы отключить эту защиту.")
            return 2

        # 2. Загружаем список
        try:
            async with session.get(SOURCE_URL) as r:
                r.raise_for_status()
                text = await r.text()
        except Exception as e:
            print(f"ОШИБКА: не удалось скачать список: {e}")
            return 1

    # 3. Парсим и убираем дубли
    seen: dict[str, str] = {}
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed and parsed[0] not in seen:
            seen[parsed[0]] = parsed[1]
    print(f"В списке {len(seen)} уникальных http(s)-прокси. Тесты: {[t[0] for t in TESTS]}")

    # 4. Проверяем
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [asyncio.create_task(check_one(sem, p, l)) for p, l in seen.items()]
    working, done = [], 0
    for fut in asyncio.as_completed(tasks):
        res = await fut
        done += 1
        if res:
            working.append(res)
        if done % 500 == 0:
            print(f"  проверено {done}/{len(tasks)}, рабочих {len(working)}", flush=True)
    working.sort(key=lambda r: r["latency_ms"])
    print(f"Готово: рабочих {len(working)} из {len(tasks)}")

    # 5. Сохраняем
    (OUT_DIR / "working_proxies.txt").write_text(
        "".join(r["proxy"] + "\n" for r in working), encoding="utf-8"
    )
    (OUT_DIR / "working_proxies.json").write_text(
        json.dumps(
            {
                "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "runner": {k: geo.get(k) for k in ("query", "city", "regionName", "countryCode")},
                "source": SOURCE_URL,
                "tests": [t[0] for t in TESTS],
                "total_checked": len(tasks),
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

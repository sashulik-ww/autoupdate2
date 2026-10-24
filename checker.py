#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
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
XRAY_WORKERS = int(os.getenv("XRAY_WORKERS", "6"))
SB_WORKERS = int(os.getenv("SB_WORKERS", "6"))
XRAY_TIMEOUT = float(os.getenv("XRAY_TIMEOUT", "9"))
CORE_RATIO = float(os.getenv("CORE_RATIO", "0.90"))

OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

MAX_PER_COUNTRY = 30
MAX_TOTAL_PER_PROTOCOL = 400
MAX_TOTAL_HYSTERIA2 = 500
MAX_TOTAL_ALL = 650
WHITE_MAX_PER_IP = 3
WHITE_MAX_PER_COUNTRY = 25
WHITE_MAX_TOTAL = 400
RU_MAX_PER_IP = 2
RU_MAX_TOTAL = 250

# http/https не поддерживаются v2rayNG — не в общие файлы
EXCLUDE_FROM_GENERAL = {"http", "https"}
# ss/socks режем до \~20% мест
LOW_PRIORITY_SCHEMES = {"ss", "socks5", "socks"}

XRAY_BIN = os.getenv("XRAY_BIN", "xray")
SINGBOX_BIN = os.getenv("SINGBOX_BIN", "sing-box")

SUPPORTED_SCHEMES = (
    "vless", "vmess", "trojan", "ss", "ssr",
    "hysteria2", "hy2", "tuic", "socks5", "http", "https",
)
CORE_SUPPORTED = {"vless", "vmess", "trojan", "ss", "hysteria2"}

GOOD_SNI = {
    "vk.com", "www.vk.com", "m.vk.com",
    "yandex.ru", "ya.ru", "www.yandex.ru",
    "mail.ru", "www.mail.ru", "ok.ru", "www.ok.ru",
    "userapi.com", "api.vk.com",
    "google.com", "www.google.com", "microsoft.com",
    "apple.com", "cloudflare.com", "github.com", "discord.com",
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
    "PH": ("Philippines", "🇵🇭"), "NZ": ("New Zealand", "🇳🇿"),
    "ZA": ("South Africa", "🇿🇦"), "CN": ("China", "🇨🇳"),
    "UNKNOWN": ("Server", "🌐"),
}

# ====================== УТИЛИТЫ ======================
def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
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
        scheme = "socks5"
    return line if scheme in SUPPORTED_SCHEMES else None


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
        p = urlsplit(proxy_line.split("#", 1)[0])
        host, port = p.hostname, p.port
        if host:
            if not port:
                port = 443 if scheme in ("vless", "trojan", "hysteria2", "https", "tuic", "vmess") else 80
            return host, port
    except Exception:
        pass
    return None, 0


def parse_vless_params(proxy_line: str) -> dict:
    res = {"security": "", "sni": "", "is_reality": False}
    try:
        if not proxy_line.lower().startswith("vless://"):
            return res
        qs = parse_qs(urlsplit(proxy_line.split("#", 1)[0]).query)
        security = (qs.get("security") or [""])[0].lower()
        sni = (qs.get("sni") or qs.get("host") or [""])[0].lower()
        res["security"] = security
        res["sni"] = sni
        res["is_reality"] = security == "reality" or "pbk=" in proxy_line.lower()
    except Exception:
        pass
    return res


def format_name(country_code: str, city: str = "") -> str:
    info = COUNTRY_DATA.get(country_code, COUNTRY_DATA["UNKNOWN"])
    flag, country = info[1], info[0]
    if city and city.lower() not in ("", "unknown", "null"):
        return f"{flag} {country}, {city}"
    return f"{flag} {country}"


def format_clean_proxy(proxy_line: str, country_code: str, city: str = "") -> str:
    name = format_name(country_code, city)
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


def geo_lookup_batch(ips: list[str]) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    if not ips:
        return result
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            body = json.dumps(
                [{"query": ip, "fields": "status,countryCode,city,query"} for ip in chunk]
            ).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
            for item in data:
                if item.get("status") == "success":
                    ip = item.get("query", "")
                    code = (item.get("countryCode") or "UNKNOWN").upper()
                    city = item.get("city") or ""
                    result[ip] = (code, city)
        except Exception as e:
            print(f"Geo error: {e}")
        time.sleep(1.1)
    return result


def b64decode_urlsafe(s: str) -> bytes:
    s = s.strip() + "=" * ((4 - len(s.strip()) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def host_port_key(proxy_line: str) -> str:
    host, port = extract_host_port(proxy_line)
    if host and port:
        return f"{host.lower()}:{port}"
    return ""


def base_link(proxy_line: str) -> str:
    return proxy_line.split("#", 1)[0].strip()


# ====================== XRAY ======================
def _xray_inbound(port: int) -> dict:
    return {
        "port": port, "listen": "127.0.0.1", "protocol": "socks",
        "settings": {"udp": True, "auth": "noauth"},
    }


def make_xray_config(proxy_line: str, local_port: int) -> dict | None:
    scheme = get_scheme(proxy_line)
    try:
        if scheme == "vless":
            return _xray_vless(proxy_line, local_port)
        if scheme == "vmess":
            return _xray_vmess(proxy_line, local_port)
        if scheme == "trojan":
            return _xray_trojan(proxy_line, local_port)
        if scheme == "ss":
            return _xray_ss(proxy_line, local_port)
    except Exception:
        return None
    return None


def _xray_vless(line: str, port: int) -> dict | None:
    u = urlparse(line.split("#", 1)[0])
    host, p, uuid_ = u.hostname, u.port or 443, u.username
    if not host or not uuid_:
        return None
    qs = parse_qs(u.query)
    security = (qs.get("security") or ["none"])[0].lower()
    network = (qs.get("type") or ["tcp"])[0].lower()
    sni = (qs.get("sni") or qs.get("host") or [host])[0]
    fp = (qs.get("fp") or ["chrome"])[0]
    flow = (qs.get("flow") or [""])[0]
    path = (qs.get("path") or ["/"])[0]
    host_h = (qs.get("host") or [sni])[0]
    pbk, sid = (qs.get("pbk") or [""])[0], (qs.get("sid") or [""])[0]
    stream: dict = {"network": network}
    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": fp,
            "publicKey": pbk, "shortId": sid, "spiderX": "",
        }
    elif security in ("tls", "xtls"):
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True, "fingerprint": fp}
    else:
        stream["security"] = "none"
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": path.lstrip("/")}
    user = {"id": uuid_, "encryption": "none"}
    if flow:
        user["flow"] = flow
    return {
        "log": {"loglevel": "none"},
        "inbounds": [_xray_inbound(port)],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": p, "users": [user]}]},
            "streamSettings": stream,
        }],
    }


def _xray_vmess(line: str, port: int) -> dict | None:
    payload = line.split("://", 1)[1].strip().split("#")[0]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
    host = data.get("add") or data.get("host")
    p = int(data.get("port", 443))
    uuid_ = data.get("id")
    if not host or not uuid_:
        return None
    network = (data.get("net") or "tcp").lower()
    tls = (data.get("tls") or "").lower()
    sni = data.get("sni") or data.get("host") or host
    path = data.get("path") or "/"
    host_h = data.get("host") or sni
    stream: dict = {"network": network}
    if tls:
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
    else:
        stream["security"] = "none"
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": path.lstrip("/")}
    return {
        "log": {"loglevel": "none"},
        "inbounds": [_xray_inbound(port)],
        "outbounds": [{
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": host, "port": p,
                "users": [{"id": uuid_, "alterId": int(data.get("aid") or 0),
                           "security": data.get("scy") or "auto"}],
            }]},
            "streamSettings": stream,
        }],
    }


def _xray_trojan(line: str, port: int) -> dict | None:
    u = urlparse(line.split("#", 1)[0])
    host, p = u.hostname, u.port or 443
    password = unquote(u.username or "")
    if not host or not password:
        return None
    qs = parse_qs(u.query)
    sni = (qs.get("sni") or qs.get("peer") or [host])[0]
    network = (qs.get("type") or ["tcp"])[0].lower()
    path = (qs.get("path") or ["/"])[0]
    host_h = (qs.get("host") or [sni])[0]
    fp = (qs.get("fp") or ["chrome"])[0]
    security = (qs.get("security") or ["tls"])[0].lower()
    stream: dict = {"network": network}
    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": fp,
            "publicKey": (qs.get("pbk") or [""])[0],
            "shortId": (qs.get("sid") or [""])[0],
        }
    else:
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True, "fingerprint": fp}
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": path.lstrip("/")}
    return {
        "log": {"loglevel": "none"},
        "inbounds": [_xray_inbound(port)],
        "outbounds": [{
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": p, "password": password}]},
            "streamSettings": stream,
        }],
    }


def _xray_ss(line: str, port: int) -> dict | None:
    u = urlparse(line.split("#", 1)[0])
    host, p = u.hostname, u.port
    if not host or not p:
        return None
    userinfo = u.username or ""
    if u.password:
        method, password = unquote(userinfo), unquote(u.password)
    else:
        try:
            decoded = b64decode_urlsafe(userinfo).decode("utf-8", errors="ignore")
            method, password = decoded.split(":", 1)
        except Exception:
            return None
    return {
        "log": {"loglevel": "none"},
        "inbounds": [_xray_inbound(port)],
        "outbounds": [{
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": host, "port": p, "method": method, "password": password,
            }]},
        }],
    }


# ====================== SING-BOX ======================
def make_singbox_config(proxy_line: str, local_port: int) -> dict | None:
    scheme = get_scheme(proxy_line)
    try:
        outbound = None
        if scheme == "vless":
            outbound = _sb_vless(proxy_line)
        elif scheme == "vmess":
            outbound = _sb_vmess(proxy_line)
        elif scheme == "trojan":
            outbound = _sb_trojan(proxy_line)
        elif scheme == "ss":
            outbound = _sb_ss(proxy_line)
        elif scheme == "hysteria2":
            outbound = _sb_hy2(proxy_line)
        if not outbound:
            return None
        return {
            "log": {"level": "panic"},
            "inbounds": [{
                "type": "socks", "tag": "in",
                "listen": "127.0.0.1", "listen_port": local_port,
            }],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        }
    except Exception:
        return None


def _sb_vless(line: str) -> dict | None:
    u = urlparse(line.split("#", 1)[0])
    host, port, uuid_ = u.hostname, u.port or 443, u.username
    if not host or not uuid_:
        return None
    qs = parse_qs(u.query)
    security = (qs.get("security") or ["none"])[0].lower()
    network = (qs.get("type") or ["tcp"])[0].lower()
    sni = (qs.get("sni") or qs.get("host") or [host])[0]
    fp = (qs.get("fp") or ["chrome"])[0]
    flow = (qs.get("flow") or [""])[0]
    path = (qs.get("path") or ["/"])[0]
    pbk, sid = (qs.get("pbk") or [""])[0], (qs.get("sid") or [""])[0]
    ob: dict = {"type": "vless", "tag": "out", "server": host, "server_port": port, "uuid": uuid_}
    if flow:
        ob["flow"] = flow
    if security == "reality":
        ob["tls"] = {
            "enabled": True, "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fp},
            "reality": {"enabled": True, "public_key": pbk, "short_id": sid},
        }
    elif security in ("tls", "xtls"):
        ob["tls"] = {"enabled": True, "server_name": sni, "insecure": True,
                     "utls": {"enabled": True, "fingerprint": fp}}
    if network == "ws":
        ob["transport"] = {"type": "ws", "path": path,
                           "headers": {"Host": (qs.get("host") or [sni])[0]}}
    elif network == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": path.lstrip("/")}
    return ob


def _sb_vmess(line: str) -> dict | None:
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
    ob: dict = {
        "type": "vmess", "tag": "out", "server": host, "server_port": port,
        "uuid": uuid_, "security": data.get("scy") or "auto",
        "alter_id": int(data.get("aid") or 0),
    }
    if tls:
        ob["tls"] = {"enabled": True, "server_name": sni, "insecure": True}
    if network == "ws":
        ob["transport"] = {"type": "ws", "path": path,
                           "headers": {"Host": data.get("host") or sni}}
    elif network == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": path.lstrip("/")}
    return ob


def _sb_trojan(line: str) -> dict | None:
    u = urlparse(line.split("#", 1)[0])
    host, port = u.hostname, u.port or 443
    password = unquote(u.username or "")
    if not host or not password:
        return None
    qs = parse_qs(u.query)
    sni = (qs.get("sni") or qs.get("peer") or [host])[0]
    network = (qs.get("type") or ["tcp"])[0].lower()
    path = (qs.get("path") or ["/"])[0]
    fp = (qs.get("fp") or ["chrome"])[0]
    ob: dict = {
        "type": "trojan", "tag": "out",
        "server": host, "server_port": port, "password": password,
        "tls": {"enabled": True, "server_name": sni, "insecure": True,
                "utls": {"enabled": True, "fingerprint": fp}},
    }
    if network == "ws":
        ob["transport"] = {"type": "ws", "path": path,
                           "headers": {"Host": (qs.get("host") or [sni])[0]}}
    elif network == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": path.lstrip("/")}
    return ob


def _sb_ss(line: str) -> dict | None:
    u = urlparse(line.split("#", 1)[0])
    host, port = u.hostname, u.port
    if not host or not port:
        return None
    userinfo = u.username or ""
    if u.password:
        method, password = unquote(userinfo), unquote(u.password)
    else:
        try:
            decoded = b64decode_urlsafe(userinfo).decode("utf-8", errors="ignore")
            method, password = decoded.split(":", 1)
        except Exception:
            return None
    return {
        "type": "shadowsocks", "tag": "out",
        "server": host, "server_port": port,
        "method": method, "password": password,
    }


def _sb_hy2(line: str) -> dict | None:
    u = urlparse(line.split("#", 1)[0])
    host, port = u.hostname, u.port or 443
    password = unquote(u.username or "")
    if not host or not password:
        return None
    qs = parse_qs(u.query)
    sni = (qs.get("sni") or [host])[0]
    insecure = (qs.get("insecure") or ["0"])[0] in ("1", "true")
    return {
        "type": "hysteria2", "tag": "out",
        "server": host, "server_port": port, "password": password,
        "tls": {"enabled": True, "server_name": sni, "insecure": insecure},
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


def _run_core_test(bin_name: str, cfg: dict, local_port: int) -> float | None:
    conf_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            conf_path = f.name
        proc = subprocess.Popen(
            [bin_name, "run", "-c", conf_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        time.sleep(0.45)
        if proc.poll() is not None:
            return None
        started = time.monotonic()
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", "4", "--max-time", str(int(XRAY_TIMEOUT)),
             "-x", f"socks5h://127.0.0.1:{local_port}",
             "http://www.gstatic.com/generate_204"],
            capture_output=True, text=True,
        )
        if (r.stdout or "").strip() == "204":
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


def core_test_sync(proxy_line: str, local_port: int, use_singbox: bool) -> float | None:
    if use_singbox:
        cfg = make_singbox_config(proxy_line, local_port)
        if not cfg:
            return None
        return _run_core_test(SINGBOX_BIN, cfg, local_port)
    cfg = make_xray_config(proxy_line, local_port)
    if not cfg:
        return None
    return _run_core_test(XRAY_BIN, cfg, local_port)


async def check_tcp(proxy_line: str, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        host, port = extract_host_port(proxy_line)
        if not host or not port:
            return None
        lat = await tcp_check(host, port)
        if lat is None:
            return None
        ip = await resolve_to_ip(host)
        scheme = get_scheme(proxy_line)
        vinfo = parse_vless_params(proxy_line) if scheme == "vless" else {}
        return {
            "raw": proxy_line, "ip": ip, "scheme": scheme,
            "latency_ms": int(lat),
            "is_reality": vinfo.get("is_reality", False),
            "sni": vinfo.get("sni", ""),
            "core_ok": False,
            "country": "UNKNOWN", "city": "",
        }


async def check_core(item: dict, port_q: asyncio.Queue, use_singbox: bool) -> dict | None:
    port = await port_q.get()
    try:
        loop = asyncio.get_running_loop()
        lat = await loop.run_in_executor(
            None, core_test_sync, item["raw"], port, use_singbox
        )
        if lat is None:
            return None
        item = dict(item)
        item["latency_ms"] = int(lat)
        item["core_ok"] = True
        return item
    finally:
        await port_q.put(port)


# ====================== ФИЛЬТРЫ ======================
def smart_filter(
    items,
    max_per_country=MAX_PER_COUNTRY,
    max_total=MAX_TOTAL_PER_PROTOCOL,
    unique_ip=True,
    general=False,
):
    """
    general=True → общие файлы (all, working, xray_all, russia):
      - без http/https
      - ss/socks ≤ 20%
      - hysteria2 в приоритете
    Сортировка всегда по скорости (после приоритета протокола).
    """
    def sort_key(x):
        scheme = x.get("scheme", "")
        if scheme == "hysteria2":
            prio = 0
        elif scheme in LOW_PRIORITY_SCHEMES:
            prio = 2
        else:
            prio = 1
        return (prio, x["latency_ms"])

    items = sorted(items, key=sort_key)
    seen_ips: set[str] = set()
    seen_hostports: set[str] = set()
    seen_links: set[str] = set()
    country_counts: dict[str, int] = defaultdict(int)
    low_prio_count = 0
    max_low_prio = max(1, int(max_total * 0.20))
    out = []

    for it in items:
        if len(out) >= max_total:
            break

        scheme = it.get("scheme", "")
        if general and scheme in EXCLUDE_FROM_GENERAL:
            continue

        ip = (it.get("ip") or "").strip()
        country = it.get("country", "UNKNOWN")
        raw = it.get("raw") or it.get("proxy") or ""
        hp = host_port_key(raw)
        base = base_link(raw)

        if unique_ip and ip and ip in seen_ips:
            continue
        if hp and hp in seen_hostports:
            continue
        if base and base in seen_links:
            continue
        if country_counts[country] >= max_per_country:
            continue

        if general and scheme in LOW_PRIORITY_SCHEMES:
            if low_prio_count >= max_low_prio:
                continue
            low_prio_count += 1

        if unique_ip and ip:
            seen_ips.add(ip)
        if hp:
            seen_hostports.add(hp)
        if base:
            seen_links.add(base)
        country_counts[country] += 1
        out.append(it)

    return out


def smart_filter_white(items):
    vless = [i for i in items if i["scheme"] == "vless"]

    def prio(it):
        reality = 0 if it.get("is_reality") else 1
        sni = (it.get("sni") or "").lower()
        good = 0 if sni in GOOD_SNI else 1
        ru = 0 if any(x in sni for x in ("vk.com", "yandex", "ya.ru", "mail.ru", "ok.ru", "userapi")) else 1
        return (reality, ru, good, it["latency_ms"])

    vless.sort(key=prio)
    ip_c, country_c = defaultdict(int), defaultdict(int)
    seen_hp, seen_links, out = set(), set(), []
    for it in vless:
        if len(out) >= WHITE_MAX_TOTAL:
            break
        ip = (it.get("ip") or "").strip()
        country = it.get("country", "UNKNOWN")
        raw = it.get("raw") or ""
        hp, base = host_port_key(raw), base_link(raw)
        if ip_c[ip] >= WHITE_MAX_PER_IP:
            continue
        if hp and hp in seen_hp:
            continue
        if base and base in seen_links:
            continue
        if country_c[country] >= WHITE_MAX_PER_COUNTRY:
            continue
        ip_c[ip] += 1
        if hp:
            seen_hp.add(hp)
        if base:
            seen_links.add(base)
        country_c[country] += 1
        out.append(it)
    return out


def smart_filter_russia(items):
    ru = [i for i in items if i.get("country") == "RU"]
    ru = [i for i in ru if i.get("scheme") not in EXCLUDE_FROM_GENERAL]
    ru.sort(key=lambda x: x["latency_ms"])
    ip_c, seen_hp, seen_links, out = defaultdict(int), set(), set(), []
    for it in ru:
        if len(out) >= RU_MAX_TOTAL:
            break
        ip = (it.get("ip") or "").strip()
        raw = it.get("raw") or ""
        hp, base = host_port_key(raw), base_link(raw)
        if ip_c[ip] >= RU_MAX_PER_IP:
            continue
        if hp and hp in seen_hp:
            continue
        if base and base in seen_links:
            continue
        ip_c[ip] += 1
        if hp:
            seen_hp.add(hp)
        if base:
            seen_links.add(base)
        out.append(it)
    return out


def write_list(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [it["proxy"] for it in items]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# ====================== MAIN ======================
async def main_async() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_proto = OUT_DIR / "by_protocol"
    by_proto.mkdir(exist_ok=True)

    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}] Source: {SOURCE_URL}")
    print(f"CORE_RATIO={CORE_RATIO}")

    try:
        text = await asyncio.to_thread(fetch_url, SOURCE_URL)
    except Exception as e:
        print(f"Download error: {e}")
        return 1

    try:
        cleaned = text.strip().replace("\n", "").replace("\r", "")
        cleaned += "=" * ((4 - len(cleaned) % 4) % 4)
        decoded = base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")
        if "://" in decoded:
            text = decoded
            print("Base64 decoded")
    except Exception:
        pass

    seen, configs = set(), []
    for line in text.splitlines():
        p = parse_line(line)
        if p and p not in seen:
            seen.add(p)
            configs.append(p)
    print(f"Configs: {len(configs)}")
    if not configs:
        return 0

    print("Stage 1: TCP...")
    sem = asyncio.Semaphore(CONCURRENCY)
    tcp_res = await asyncio.gather(*[check_tcp(c, sem) for c in configs])
    tcp_alive = sorted([r for r in tcp_res if r], key=lambda x: x["latency_ms"])
    print(f"TCP alive: {len(tcp_alive)}")

    core_pool = [x for x in tcp_alive if x["scheme"] in CORE_SUPPORTED]
    take = max(1, int(len(core_pool) * CORE_RATIO))
    candidates = core_pool[:take]
    print(f"Core candidates ({int(CORE_RATIO * 100)}%): {len(candidates)}")

    has_xray = subprocess.run([XRAY_BIN, "version"], capture_output=True).returncode == 0
    has_sb = subprocess.run([SINGBOX_BIN, "version"], capture_output=True).returncode == 0
    print(f"xray={has_xray}, sing-box={has_sb}")

    core_ok: list[dict] = []

    async def run_core_stage(use_sb: bool, workers: int, label: str):
        nonlocal core_ok
        if not candidates:
            return
        print(f"Stage: {label}...")
        port_q: asyncio.Queue = asyncio.Queue()
        base = 12000 if use_sb else 11000
        for i in range(workers):
            await port_q.put(base + i)
        sem_c = asyncio.Semaphore(workers)

        async def worker(it):
            async with sem_c:
                return await check_core(it, port_q, use_sb)

        results = await asyncio.gather(*[worker(it) for it in candidates])
        ok = [r for r in results if r]
        print(f"{label} OK: {len(ok)}")
        by_raw = {x["raw"]: x for x in core_ok}
        for r in ok:
            prev = by_raw.get(r["raw"])
            if not prev or r["latency_ms"] < prev["latency_ms"]:
                by_raw[r["raw"]] = r
        core_ok = list(by_raw.values())

    if has_sb:
        await run_core_stage(True, SB_WORKERS, "sing-box")
    if has_xray:
        await run_core_stage(False, XRAY_WORKERS, "xray")

    final_map = {x["raw"]: x for x in core_ok}
    for item in tcp_alive:
        if item["scheme"] not in CORE_SUPPORTED and item["raw"] not in final_map:
            final_map[item["raw"]] = item
    final = sorted(final_map.values(), key=lambda x: x["latency_ms"])
    print(f"Final pool: {len(final)}")

    print("GeoIP...")
    unique_ips = list({it["ip"] for it in final if it["ip"]})
    geo = await asyncio.to_thread(geo_lookup_batch, unique_ips)
    for it in final:
        code, city = geo.get(it["ip"], ("UNKNOWN", ""))
        it["country"] = code if code in COUNTRY_DATA else "UNKNOWN"
        it["city"] = city
        it["proxy"] = format_clean_proxy(it["raw"], it["country"], it["city"])

    # xray_all — прошедшие core, без http/https, дедуп, ss режем
    core_all = smart_filter(core_ok, max_total=MAX_TOTAL_ALL, general=True)
    write_list(OUT_DIR / "xray_all.txt", core_all)
    print(f"xray_all.txt: {len(core_all)}")

    main_list = smart_filter(final, max_total=MAX_TOTAL_ALL, general=True)
    write_list(OUT_DIR / "all.txt", main_list)
    write_list(OUT_DIR / "working_proxies.txt", main_list)
    print(f"all.txt: {len(main_list)}")

    white = smart_filter_white(final)
    write_list(OUT_DIR / "white_checked.txt", white)
    print(f"white_checked.txt: {len(white)}")

    russia = smart_filter_russia(final)
    write_list(OUT_DIR / "russia.txt", russia)
    print(f"russia.txt: {len(russia)}")

    by_scheme: dict[str, list] = defaultdict(list)
    for it in final:
        by_scheme[it["scheme"]].append(it)

    for scheme, items in by_scheme.items():
        limit = MAX_TOTAL_HYSTERIA2 if scheme == "hysteria2" else MAX_TOTAL_PER_PROTOCOL
        filtered = smart_filter(items, max_total=limit, general=False)
        write_list(by_proto / f"{scheme}.txt", filtered)
        write_list(OUT_DIR / f"{scheme}.txt", filtered)
        if filtered:
            print(f"  {scheme}.txt → {len(filtered)}")

    print("Done.")
    return 0


def main():
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main()) 

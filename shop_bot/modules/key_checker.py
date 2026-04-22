import socket
import time
import requests
import re
import logging
import os
import json
import tempfile
import subprocess
import threading
import concurrent.futures
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# ─── Список источников конфигов ───────────────────────────────────────────────
VLESS_SOURCES = [
    # Основной источник (igareck) — прямо + через зеркало
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://ghproxy.net/https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    # FreeProxyList (nikita29a) — прямо
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/2.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/3.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/4.txt",
    # FreeProxyList (nikita29a) — через зеркало ghproxy.net (РФ fallback)
    "https://ghproxy.net/https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt",
    "https://ghproxy.net/https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/2.txt",
    "https://ghproxy.net/https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/3.txt",
    "https://ghproxy.net/https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/4.txt",
]

# URL для проверки реального VPN-соединения.
# connectivitycheck.gstatic.com недоступен в РФ → подходит как тест "обхода".
TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
TEST_URL_FALLBACK = "https://www.google.com"
TEST_EXPECTED_STATUS = (200, 204, 301, 302)

# Диапазон 21000-29999 = 9000 слотов
_port_counter_lock = threading.Lock()
_port_counter = 21000
_PORT_MIN = 21000
_PORT_MAX = 29999

# Сколько лучших ссылок пушить на сервер
MAX_LINKS_TO_PUSH = 10
# Порог пинга: ссылки с пингом выше этого считаются плохими (мс)
MAX_PING_MS = 800


def _get_next_port() -> int:
    global _port_counter
    with _port_counter_lock:
        port = _port_counter
        _port_counter = _PORT_MIN + (_port_counter - _PORT_MIN + 1) % (_PORT_MAX - _PORT_MIN + 1)
        return port


def _find_xray_binary() -> str | None:
    candidates = [
        "xray",
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        "/app/xray",
        "./xray",
    ]
    for c in candidates:
        try:
            result = subprocess.run([c, "version"], capture_output=True, timeout=3)
            if result.returncode == 0:
                return c
        except Exception:
            continue
    return None


XRAY_BINARY = _find_xray_binary()


def parse_vless_host_port(link: str):
    pattern = r'vless://[^@]+@([^:?#\s/]+):(\d+)'
    match = re.search(pattern, link)
    if match:
        return match.group(1), int(match.group(2))
    return None, None


def _parse_vless_to_xray_config(link: str, socks_port: int) -> dict | None:
    try:
        m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\??([^#]*)', link)
        if not m:
            return None

        uuid = m.group(1)
        host = m.group(2)
        port = int(m.group(3))
        raw_params = m.group(4)

        params = {}
        for part in raw_params.split('&'):
            if '=' in part:
                k, v = part.split('=', 1)
                params[k] = unquote(v)

        flow = params.get('flow', '')
        network = params.get('type', 'tcp')
        security = params.get('security', 'none')
        sni = params.get('sni', host)
        fp = params.get('fp', 'chrome')
        pbk = params.get('pbk', '')
        sid = params.get('sid', '')
        alpn = params.get('alpn', '')
        insecure = params.get('insecure', '0') in ('1', 'true')
        ws_path = params.get('path', '/')
        ws_host = params.get('host', host)
        grpc_service = params.get('serviceName', params.get('spx', ''))

        stream: dict = {"network": network}

        if security == 'reality':
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": pbk,
                "shortId": sid,
                "spiderX": params.get('spx', '/'),
            }
        elif security == 'tls':
            stream["security"] = "tls"
            tls_cfg: dict = {"serverName": sni, "allowInsecure": insecure}
            if alpn:
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(',')]
            stream["tlsSettings"] = tls_cfg
        else:
            stream["security"] = "none"

        if network == 'ws':
            stream["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
        elif network == 'grpc':
            stream["grpcSettings"] = {
                "serviceName": grpc_service,
                "multiMode": params.get('mode', 'gun') == 'multi',
            }

        user: dict = {"id": uuid, "encryption": "none"}
        if flow:
            user["flow"] = flow

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": socks_port,
                "protocol": "socks",
                "listen": "127.0.0.1",
                "settings": {"auth": "noauth", "udp": False},
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": stream,
            }],
        }
    except Exception as e:
        logger.debug(f"VLESS parse error: {e}")
        return None


def _test_link_via_xray(link: str, idx: int) -> tuple[str | None, float]:
    socks_port = _get_next_port() + (idx % 200)
    xray_proc = None
    cfg_file = None

    try:
        config = _parse_vless_to_xray_config(link, socks_port)
        if not config:
            return None, 999999

        fd, cfg_path = tempfile.mkstemp(suffix='.json', prefix='xray_cfg_')
        cfg_file = cfg_path
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f)

        xray_proc = subprocess.Popen(
            [XRAY_BINARY, 'run', '-c', cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(1.2)

        if xray_proc.poll() is not None:
            return None, 999999

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        start = time.time()
        try:
            resp = requests.get(TEST_URL, proxies=proxies, timeout=6, allow_redirects=True)
            latency = (time.time() - start) * 1000
            if resp.status_code in TEST_EXPECTED_STATUS:
                return link, latency
        except requests.exceptions.ConnectionError:
            try:
                resp = requests.get(TEST_URL_FALLBACK, proxies=proxies, timeout=6, allow_redirects=True)
                latency = (time.time() - start) * 1000
                if resp.status_code in TEST_EXPECTED_STATUS:
                    return link, latency
            except Exception:
                pass
        except Exception:
            pass

        return None, 999999

    except Exception as e:
        logger.debug(f"xray test error: {e}")
        return None, 999999
    finally:
        if xray_proc and xray_proc.poll() is None:
            try:
                xray_proc.terminate()
                xray_proc.wait(timeout=2)
            except Exception:
                try:
                    xray_proc.kill()
                except Exception:
                    pass
        if cfg_file and os.path.exists(cfg_file):
            try:
                os.unlink(cfg_file)
            except Exception:
                pass


def check_tcp_ping(host: str, port: int, timeout: int = 3) -> float | None:
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        latency = (time.time() - start) * 1000
        sock.close()
        return latency
    except Exception:
        return None


def _test_link_tcp_fallback(link: str, _idx: int) -> tuple[str | None, float]:
    host, port = parse_vless_host_port(link)
    if not host or not port:
        return None, 999999
    ping = check_tcp_ping(host, port, timeout=2)
    return (link, ping) if ping is not None else (None, 999999)


def _fetch_links_from_sources() -> list[str]:
    all_links: list[str] = []
    seen_keys: set[str] = set()

    for url in VLESS_SOURCES:
        try:
            resp = requests.get(url, timeout=8)
            resp.raise_for_status()
            lines = [
                line.strip()
                for line in resp.text.splitlines()
                if line.strip().startswith('vless://')
            ]
            lines = [l for l in lines if 'type=xhttp' not in l]

            added = 0
            for link in lines:
                m = re.match(r'vless://([^@]+)@([^:]+):(\d+)', link)
                if m:
                    key = f"{m.group(1)}@{m.group(2)}:{m.group(3)}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        all_links.append(link)
                        added += 1
            logger.info(f"Source [{url.split('/')[-1]}]: +{added} unique links")
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")

    logger.info(f"Total unique VLESS links: {len(all_links)}")
    return all_links


def update_server_garant_link(local_only: bool = False) -> list[dict] | None:
    """
    Скачивает VLESS конфиги из всех источников, тестирует параллельно
    через xray-core (реальный VPN) и возвращает список лучших линков.
    Fallback на TCP ping если xray не найден.

    Возвращает list[{"link": str, "ping_ms": float}] или None при ошибке.
    """
    # RAM расчёт: xray процесс ~40 МБ × 200 воркеров = ~8 ГБ (из 10 ГБ).
    # TCP fallback — только сокеты, 500 потоков ≈ ~200 МБ.
    if XRAY_BINARY:
        test_fn = _test_link_via_xray
        mode = f"xray real VPN test ({XRAY_BINARY})"
        max_workers = 200  # ~40 МБ × 200 = ~8 ГБ RAM
    else:
        test_fn = _test_link_tcp_fallback
        mode = "TCP ping (fallback)"
        max_workers = 500
        logger.warning("xray not found — falling back to TCP ping")

    logger.info(f"Mode: {mode}")

    try:
        lines = _fetch_links_from_sources()
        if not lines:
            logger.warning("No VLESS links fetched.")
            return None

        working_count = 0

        # БАГ-ФИКС: enumerate даёт (idx, link), а test_fn ожидает (link, idx).
        def _run_test(args):
            idx, link = args
            return test_fn(link, idx)  # правильный порядок

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(_run_test, enumerate(lines)))

        # Собираем все рабочие ссылки и сортируем по latency
        working: list[tuple[float, str]] = []
        for link, ping in results:
            if link:
                working_count += 1
                working.append((ping, link))

        working.sort(key=lambda x: x[0])  # лучшие (min latency) первые

        if working:
            # Дедупликация по host:port и обрезка до MAX_LINKS_TO_PUSH
            seen_hostport: set[str] = set()
            top_links: list[dict] = []
            for ping_ms, raw_link in working:
                base_link = raw_link.split('#')[0]
                m = re.match(r'vless://[^@]+@([^:]+):(\d+)', base_link)
                hostport = f"{m.group(1)}:{m.group(2)}" if m else base_link[:50]
                if hostport in seen_hostport:
                    continue
                seen_hostport.add(hostport)
                # Формируем человекочитаемую метку по порядку
                rank = len(top_links) + 1
                link_with_name = f"{base_link}#🛡️ Обход Гарант {rank}"
                top_links.append({"link": link_with_name, "ping_ms": round(ping_ms, 1)})
                if len(top_links) >= MAX_LINKS_TO_PUSH:
                    break

            logger.info(
                f"Done [{mode}]. Tested: {len(lines)}, "
                f"Working: {working_count}, Top-{len(top_links)} best: {top_links[0]['ping_ms']:.0f}ms"
            )
            return top_links
        else:
            logger.warning(f"No working links out of {len(lines)} [{mode}].")
            return None

    except Exception as e:
        logger.error(f"update_server_garant_link error: {e}", exc_info=True)
        return None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logger.info(f"xray binary: {XRAY_BINARY or 'NOT FOUND (TCP fallback)'}")
    top = update_server_garant_link()
    print(f"\n{'='*60}")
    if top:
        for i, item in enumerate(top, 1):
            print(f"#{i} [{item['ping_ms']:.0f}ms] {item['link']}")
    else:
        print("No working links found.")
    print('='*60)

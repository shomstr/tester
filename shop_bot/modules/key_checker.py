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
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)

# ─── Список источников конфигов ───────────────────────────────────────────────
VLESS_SOURCES = [
    # Основной источник (igareck) — белые списки для России
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    # FreeProxyList (nikita29a) — Reality / Hysteria2
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/2.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/3.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/4.txt",
    # mehdirzfx агрегатор
    "https://raw.githubusercontent.com/mehdirzfx/v2ray-sub/main/vless.txt",
    "https://raw.githubusercontent.com/mehdirzfx/v2ray-sub/main/reality.txt",
]

# URL для проверки реального VPN-соединения.
# connectivitycheck.gstatic.com недоступен в РФ → подходит как тест "обхода".
TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
TEST_URL_FALLBACK = "https://www.google.com"
TEST_EXPECTED_STATUS = (200, 204, 301, 302)  # любой ответ = VPN работает

# Порты SOCKS5 для xray (каждый воркер занимает свой).
# Диапазон 21000-29999 = 9000 слотов, хватает на 200 одновременных воркеров
# с запасом (каждый держит порт ~8 секунд → оборот за ~7.2 мин).
_port_counter_lock = threading.Lock()
_port_counter = 21000
_PORT_MIN = 21000
_PORT_MAX = 29999


def _get_next_port() -> int:
    """Атомарно выдаёт следующий порт из диапазона _PORT_MIN.._PORT_MAX."""
    global _port_counter
    with _port_counter_lock:
        port = _port_counter
        _port_counter = _PORT_MIN + (_port_counter - _PORT_MIN + 1) % (_PORT_MAX - _PORT_MIN + 1)
        return port


def _find_xray_binary() -> str | None:
    """Ищет xray в PATH и в предсказуемых местах."""
    candidates = [
        "xray",
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        "/app/xray",
        "./xray",
    ]
    for c in candidates:
        try:
            result = subprocess.run(
                [c, "version"], capture_output=True, timeout=3
            )
            if result.returncode == 0:
                return c
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            continue
    return None


XRAY_BINARY = _find_xray_binary()


# ─── Парсинг VLESS ссылки ────────────────────────────────────────────────────

def parse_vless_host_port(link: str):
    """Извлекает host и port из vless:// ссылки."""
    pattern = r'vless://[^@]+@([^:?#\s/]+):(\d+)'
    match = re.search(pattern, link)
    if match:
        return match.group(1), int(match.group(2))
    return None, None


def _parse_vless_to_xray_config(link: str, socks_port: int) -> dict | None:
    """
    Парсит vless:// ссылку в словарь конфигурации xray.
    Поддерживает: tcp/reality, tcp/tls, ws/tls, grpc/reality.
    """
    try:
        # vless://UUID@HOST:PORT?params#name
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
        # ws
        ws_path = params.get('path', '/')
        ws_host = params.get('host', host)
        # grpc
        grpc_service = params.get('serviceName', params.get('spx', ''))

        # --- stream settings ---
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
            tls_cfg: dict = {
                "serverName": sni,
                "allowInsecure": insecure,
            }
            if alpn:
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(',')]
            stream["tlsSettings"] = tls_cfg
        else:
            stream["security"] = "none"

        if network == 'ws':
            stream["wsSettings"] = {
                "path": ws_path,
                "headers": {"Host": ws_host},
            }
        elif network == 'grpc':
            stream["grpcSettings"] = {
                "serviceName": grpc_service,
                "multiMode": params.get('mode', 'gun') == 'multi',
            }
        elif network == 'tcp':
            stream["tcpSettings"] = {}

        # --- outbound user ---
        user: dict = {"id": uuid, "encryption": "none"}
        if flow:
            user["flow"] = flow

        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": socks_port,
                "protocol": "socks",
                "listen": "127.0.0.1",
                "settings": {"auth": "noauth", "udp": False},
            }],
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
        return config
    except Exception as e:
        logger.debug(f"Failed to parse VLESS link: {e}")
        return None


# ─── Тестирование через xray ─────────────────────────────────────────────────

def _test_link_via_xray(link: str, idx: int) -> tuple[str | None, float]:
    """
    Запускает xray на временном SOCKS5 порту и проверяет реальное
    VPN-соединение через HTTP-запрос к TEST_URL.
    Возвращает (link, latency_ms) или (None, 999999).
    """
    socks_port = _get_next_port()
    xray_proc = None
    cfg_file = None

    try:
        config = _parse_vless_to_xray_config(link, socks_port)
        if not config:
            return None, 999999

        # Пишем конфиг во временный файл
        fd, cfg_path = tempfile.mkstemp(suffix='.json', prefix='xray_cfg_')
        cfg_file = cfg_path
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f)

        # Запускаем xray
        xray_proc = subprocess.Popen(
            [XRAY_BINARY, 'run', '-c', cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Ждём инициализации (xray запускается ~0.5-1 сек)
        time.sleep(1.2)

        if xray_proc.poll() is not None:
            # xray уже упал — конфиг невалидный или порт занят
            return None, 999999

        # Делаем HTTP запрос через SOCKS5 прокси
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        start = time.time()
        try:
            resp = requests.get(
                TEST_URL,
                proxies=proxies,
                timeout=6,
                allow_redirects=True,
            )
            latency = (time.time() - start) * 1000
            if resp.status_code in TEST_EXPECTED_STATUS:
                return link, latency
        except requests.exceptions.ConnectionError:
            # Попробуем fallback URL
            try:
                resp = requests.get(
                    TEST_URL_FALLBACK,
                    proxies=proxies,
                    timeout=6,
                    allow_redirects=True,
                )
                latency = (time.time() - start) * 1000
                if resp.status_code in TEST_EXPECTED_STATUS:
                    return link, latency
            except Exception:
                pass
        except Exception:
            pass

        return None, 999999

    except Exception as e:
        logger.debug(f"xray test error for {link[:60]}: {e}")
        return None, 999999
    finally:
        # Убиваем xray процесс
        if xray_proc and xray_proc.poll() is None:
            try:
                xray_proc.terminate()
                xray_proc.wait(timeout=2)
            except Exception:
                try:
                    xray_proc.kill()
                except Exception:
                    pass
        # Удаляем временный конфиг
        if cfg_file and os.path.exists(cfg_file):
            try:
                os.unlink(cfg_file)
            except Exception:
                pass


# ─── Fallback: TCP ping ────────────────────────────────────────────────────--

def check_tcp_ping(host: str, port: int, timeout: int = 3) -> float | None:
    """TCP ping — fallback если xray недоступен."""
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        latency = (time.time() - start) * 1000
        sock.close()
        return latency
    except Exception:
        return None


def _test_link_tcp_fallback(link: str, _idx: int) -> tuple[str | None, float]:
    """Fallback тест через простой TCP ping (без реальной проверки VPN)."""
    host, port = parse_vless_host_port(link)
    if not host or not port:
        return None, 999999
    ping = check_tcp_ping(host, port, timeout=2)
    if ping is not None:
        return link, ping
    return None, 999999


# ─── Загрузка ссылок из всех источников ──────────────────────────────────────

def _fetch_links_from_sources() -> list[str]:
    """
    Скачивает VLESS ссылки из всех источников (VLESS_SOURCES).
    Возвращает дедуплицированный список (по host:port+uuid).
    Фильтрует: только vless://, без xhttp (плохо поддерживается клиентами).
    """
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
            # Фильтруем xhttp (не поддерживается большинством клиентов)
            lines = [l for l in lines if 'type=xhttp' not in l]

            added = 0
            for link in lines:
                # Дедупликация по uuid@host:port (без параметров и имени)
                m = re.match(r'vless://([^@]+)@([^:]+):(\d+)', link)
                if m:
                    key = f"{m.group(1)}@{m.group(2)}:{m.group(3)}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        all_links.append(link)
                        added += 1
            logger.info(f"Source [{url.split('/')[-1]}]: +{added} unique links")
        except Exception as e:
            logger.warning(f"Failed to fetch from {url}: {e}")

    logger.info(f"Total unique VLESS links fetched: {len(all_links)}")
    return all_links


# ─── Главная функция ──────────────────────────────────────────────────────────

def update_server_garant_link(local_only: bool = False) -> str | None:
    """
    Скачивает VLESS конфиги из всех источников, тестирует их параллельно
    через xray-core (реальное VPN соединение) и возвращает лучший линк.

    Если GARANT_API_URL задан и local_only=False — запрашивает у внешнего API.
    Если xray не найден — делает fallback на TCP ping.
    """
    if not local_only:
        api_url = os.getenv("GARANT_API_URL")
        if api_url:
            logger.info(f"Fetching Server Garant link from API: {api_url}")
            try:
                target_url = api_url if api_url.endswith('/') else api_url + '/'
                response = requests.get(target_url, timeout=15)
                response.raise_for_status()
                data = response.json()
                if "link" in data and data["link"]:
                    return data["link"]
                else:
                    logger.warning(f"Invalid response from API: {response.text}")
                    return None
            except Exception as e:
                logger.error(f"Failed to fetch from API: {e}", exc_info=True)
                return None

    # Выбираем стратегию тестирования.
    # RAM расчёт: xray процесс ~40 МБ × 200 воркеров = ~8 ГБ (из 10 ГБ).
    # TCP fallback — только сокеты, 500 потоков ≈ ~200 МБ.
    if XRAY_BINARY:
        test_fn = _test_link_via_xray
        mode = "xray (real VPN test)"
        max_workers = 200  # ~40 МБ × 200 = ~8 ГБ RAM
    else:
        test_fn = _test_link_tcp_fallback
        mode = "TCP ping (fallback, xray not found)"
        max_workers = 500
        logger.warning("xray binary not found! Falling back to TCP ping only.")

    logger.info(f"Starting VPN link check. Mode: {mode}")

    try:
        lines = _fetch_links_from_sources()
        if not lines:
            logger.warning("No VLESS links fetched from any source.")
            return None

        best_link = None
        min_ping = 999999.0
        working_count = 0

        def _test_with_idx(args):
            idx, link = args
            return test_fn(link, idx)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(
                executor.map(_test_with_idx, enumerate(lines))
            )

        for link, ping in results:
            if link:
                working_count += 1
                if ping < min_ping:
                    min_ping = ping
                    clean_link = link.split('#')[0]
                    best_link = f"{clean_link}#🛡️ Обход Гарант"

        if best_link:
            logger.info(
                f"Check done [{mode}]. "
                f"Tested: {len(lines)}, Working: {working_count}, "
                f"Best latency: {min_ping:.0f}ms"
            )
        else:
            logger.warning(
                f"No working links found out of {len(lines)} tested [{mode}]."
            )

        return best_link

    except Exception as e:
        logger.error(f"Failed in update_server_garant_link: {e}", exc_info=True)
        return None


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    if XRAY_BINARY:
        logger.info(f"xray binary found: {XRAY_BINARY}")
    else:
        logger.warning("xray binary NOT found — TCP fallback mode")

    best = update_server_garant_link(local_only=True)
    print(f"\n{'='*60}")
    print(f"Best link: {best}")
    print(f"{'='*60}")

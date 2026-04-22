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
    # Основной источник (igareck) — белые списки для России
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    # FreeProxyList (nikita29a) — Reality / Hysteria2
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/2.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/3.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/4.txt",
]

# ─── URL для проверки реального VPN-соединения ───────────────────────────────
# Тестируем Telegram API — он заблокирован в РФ, значит если ответ есть → VPN работает.
# Любой HTTP-ответ (даже 404) означает что мы прошли через VPN.
TEST_URLS = [
    "https://api.telegram.org",          # Telegram API (заблокирован в РФ)
    "https://core.telegram.org",         # Telegram core docs (заблокирован в РФ)
    "https://t.me",                      # Telegram web
]
TEST_EXPECTED_STATUS = (200, 301, 302, 403, 404, 429)  # любой ответ = VPN работает

# ─── Параметры отбора ссылок ─────────────────────────────────────────────────
MAX_LINKS_TO_PUSH = 10           # Максимум ссылок в пуле
MAX_PER_COUNTRY = 3              # Не более N ссылок одной страны (разнообразие)
PING_RATIO_THRESHOLD = 2.5       # Ссылки с пингом > best_ping × 2.5 отбрасываем

# ─── Порты SOCKS5 для xray ───────────────────────────────────────────────────
# Диапазон 21000-29999 = 9000 слотов
# 250 одновременных воркеров × ~8 сек/тест = оборот 72 сек, слотов хватает.
_port_counter_lock = threading.Lock()
_port_counter = 21000
_PORT_MIN = 21000
_PORT_MAX = 29999


def _get_next_port() -> int:
    global _port_counter
    with _port_counter_lock:
        port = _port_counter
        _port_counter = _PORT_MIN + (_port_counter - _PORT_MIN + 1) % (_PORT_MAX - _PORT_MIN + 1)
        return port


# ─── GeoIP: определяем страну по IP ─────────────────────────────────────────

# Кэш: ip → (country_code, flag_emoji)
_geoip_cache: dict[str, tuple[str, str]] = {}
_geoip_lock = threading.Lock()

# Таблица флагов для топ-стран (ISO 3166-1 alpha-2)
_FLAG_MAP: dict[str, str] = {
    "RU": "🇷🇺", "DE": "🇩🇪", "NL": "🇳🇱", "FI": "🇫🇮",
    "FR": "🇫🇷", "AT": "🇦🇹", "EE": "🇪🇪", "LT": "🇱🇹",
    "PL": "🇵🇱", "SE": "🇸🇪", "NO": "🇳🇴", "CH": "🇨🇭",
    "GB": "🇬🇧", "US": "🇺🇸", "JP": "🇯🇵", "SG": "🇸🇬",
    "HK": "🇭🇰", "KR": "🇰🇷", "UA": "🇺🇦", "CZ": "🇨🇿",
    "TR": "🇹🇷", "LV": "🇱🇻", "BE": "🇧🇪", "ES": "🇪🇸",
    "IT": "🇮🇹", "CA": "🇨🇦", "AU": "🇦🇺",
}


def _iso_to_flag(cc: str) -> str:
    """Конвертирует ISO 3166-1 alpha-2 в флаг emoji. Работает для любого кода."""
    if not cc or len(cc) != 2:
        return "🌐"
    # Каждая буква кода → региональный индикатор (U+1F1E6 = 'A')
    return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + \
           chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))


def _get_country(ip: str) -> tuple[str, str]:
    """
    Определяет страну по IP-адресу через ip-api.com (бесплатно, без ключа).
    Возвращает (country_code, flag_emoji).
    Кэшируем результаты чтобы не дёргать API многократно.
    """
    with _geoip_lock:
        if ip in _geoip_cache:
            return _geoip_cache[ip]

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode",
            timeout=4
        )
        data = resp.json()
        cc = data.get("countryCode", "??").upper()
        flag = _iso_to_flag(cc)
        result = (cc, flag)
    except Exception:
        result = ("??", "🌐")

    with _geoip_lock:
        _geoip_cache[ip] = result

    return result


def _resolve_host_to_ip(host: str) -> str | None:
    """Резолвим hostname в IP (для GeoIP). Если уже IP — возвращаем как есть."""
    # Проверяем что это уже IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ─── Поиск xray binary ───────────────────────────────────────────────────────

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


# ─── Парсинг VLESS ссылки ─────────────────────────────────────────────────---

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


# ─── Тестирование через xray + Telegram ──────────────────────────────────────

def _test_link_via_xray(link: str, idx: int) -> tuple[str | None, float]:
    """
    Запускает xray как SOCKS5 прокси и через него проверяет доступность
    Telegram API (заблокирован в РФ → реальный тест обхода блокировок).
    Возвращает (link, latency_ms) или (None, 999999).
    """
    socks_port = _get_next_port()
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

        # Ждём инициализации xray (~1 сек)
        time.sleep(1.2)

        if xray_proc.poll() is not None:
            # xray упал → невалидный конфиг или порт занят
            return None, 999999

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }

        # Пробуем каждый тестовый URL по очереди
        start = time.time()
        for test_url in TEST_URLS:
            try:
                resp = requests.get(
                    test_url,
                    proxies=proxies,
                    timeout=6,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                latency = (time.time() - start) * 1000
                if resp.status_code in TEST_EXPECTED_STATUS:
                    return link, latency
            except requests.exceptions.ProxyError:
                # SOCKS прокси не смог подключиться — сразу выходим
                break
            except Exception:
                continue

        return None, 999999

    except Exception as e:
        logger.debug(f"xray test error idx={idx}: {e}")
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


# ─── TCP Fallback ─────────────────────────────────────────────────────────---

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


# ─── Загрузка ссылок ─────────────────────────────────────────────────────────

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
            # Фильтруем xhttp — плохо поддерживается клиентами
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


# ─── Отбор топ-N с географическим разнообразием ──────────────────────────────

def _select_diverse_top(
    working: list[tuple[float, str]],
    max_total: int = MAX_LINKS_TO_PUSH,
    max_per_country: int = MAX_PER_COUNTRY,
    ping_ratio: float = PING_RATIO_THRESHOLD,
) -> list[dict]:
    """
    Принимает список (ping_ms, link) отсортированных по пингу (лучший первый).
    Возвращает до max_total ссылок с ограничением max_per_country на страну.
    Ссылки с пингом > best_ping * ping_ratio отбрасываются.
    Каждой ссылке добавляется флаг страны через GeoIP.
    """
    if not working:
        return []

    best_ping = working[0][0]
    ping_cutoff = best_ping * ping_ratio

    result: list[dict] = []
    country_count: dict[str, int] = {}
    seen_hostport: set[str] = set()

    # Предварительно резолвим все IP параллельно (GeoIP тоже параллельно)
    # Собираем уникальные хосты из отфильтрованных
    candidate_links = [(p, l) for p, l in working if p <= ping_cutoff]

    # Параллельный GeoIP для всех уникальных хостов
    hosts_to_resolve: dict[str, str | None] = {}
    unique_hosts: set[str] = set()
    for _, link in candidate_links:
        m = re.match(r'vless://[^@]+@([^:]+):\d+', link)
        if m:
            unique_hosts.add(m.group(1))

    def _resolve_and_geo(host: str) -> tuple[str, str, str]:
        """(host, country_code, flag)"""
        ip = _resolve_host_to_ip(host)
        if not ip:
            return host, "??", "🌐"
        cc, flag = _get_country(ip)
        return host, cc, flag

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(unique_hosts) or 1)) as ex:
        geo_results = list(ex.map(_resolve_and_geo, unique_hosts))

    host_geo: dict[str, tuple[str, str]] = {
        host: (cc, flag) for host, cc, flag in geo_results
    }

    for ping_ms, raw_link in candidate_links:
        if len(result) >= max_total:
            break

        base_link = raw_link.split('#')[0]
        m = re.match(r'vless://[^@]+@([^:]+):(\d+)', base_link)
        if not m:
            continue

        host = m.group(1)
        hostport = f"{host}:{m.group(2)}"
        if hostport in seen_hostport:
            continue
        seen_hostport.add(hostport)

        cc, flag = host_geo.get(host, ("??", "🌐"))

        # Лимит по стране
        if country_count.get(cc, 0) >= max_per_country:
            continue
        country_count[cc] = country_count.get(cc, 0) + 1

        rank = len(result) + 1
        name = f"🛡️ Обход Гарант {rank} {flag}"
        link_with_name = f"{base_link}#{name}"

        result.append({
            "link": link_with_name,
            "ping_ms": round(ping_ms, 1),
            "country": cc,
            "flag": flag,
        })

    return result


# ─── Главная функция ─────────────────────────────────────────────────────────

def update_server_garant_link(local_only: bool = False) -> list[dict] | None:
    """
    Скачивает VLESS конфиги из всех источников, тестирует параллельно
    через xray → Telegram API (реальный тест обхода блокировок).
    Возвращает список до 10 лучших ссылок с географическим разнообразием.

    Каждый элемент: {"link": str, "ping_ms": float, "country": str, "flag": str}
    """
    # ─── Выбор стратегии и лимиты RAM ────────────────────────────────────────
    # Тестер: 11 ГБ доступно
    # xray процесс: ~40 МБ × 250 воркеров = ~10 ГБ (1 ГБ — OS/Python)
    # TCP fallback: сокеты ~0.3 МБ × 600 = ~180 МБ
    if XRAY_BINARY:
        test_fn = _test_link_via_xray
        mode = f"xray+Telegram ({XRAY_BINARY})"
        max_workers = 250  # 40МБ × 250 = 10ГБ RAM
    else:
        test_fn = _test_link_tcp_fallback
        mode = "TCP ping (fallback, xray not found)"
        max_workers = 600
        logger.warning("xray not found — falling back to TCP ping!")

    logger.info(f"Starting check. Mode: {mode}")

    try:
        lines = _fetch_links_from_sources()
        if not lines:
            logger.warning("No VLESS links fetched.")
            return None

        def _run_test(args):
            idx, link = args
            return test_fn(link, idx)  # правильный порядок!

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            raw_results = list(executor.map(_run_test, enumerate(lines)))

        working: list[tuple[float, str]] = [
            (ping, link)
            for link, ping in raw_results
            if link is not None
        ]
        working.sort(key=lambda x: x[0])  # лучший пинг первый

        if not working:
            logger.warning(f"No working links out of {len(lines)} [{mode}].")
            return None

        top = _select_diverse_top(working)

        if top:
            logger.info(
                f"Done [{mode}]. Tested: {len(lines)}, Working: {len(working)}, "
                f"Top-{len(top)}: best={top[0]['ping_ms']:.0f}ms "
                f"countries={set(t['country'] for t in top)}"
            )
        else:
            logger.warning("No links passed diversity filter.")

        return top if top else None

    except Exception as e:
        logger.error(f"update_server_garant_link error: {e}", exc_info=True)
        return None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logger.info(f"xray binary: {XRAY_BINARY or 'NOT FOUND (TCP fallback)'}")

    top = update_server_garant_link(local_only=True)
    print(f"\n{'='*60}")
    if top:
        for item in top:
            print(f"  {item['flag']} {item['country']} [{item['ping_ms']:.0f}ms] {item['link'][:90]}")
    else:
        print("No working links found.")
    print('='*60)

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
from queue import Queue
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# ─── КОНФИГУРАЦИЯ ────────────────────────────────────────────────────────────
VLESS_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/2.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/3.txt",
    "https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/4.txt",
]

TARGET_ACTIVE_COUNT = 10     # Сколько серверов держать в Активе
MAX_STRESS_WORKERS = 25      # Одновременные тесты для резерва (чтобы не забить канал)
STRESS_TEST_DURATION = 60    # Секунд загрузки для прохождения стресс-теста

# ─── ПОРТЫ И GEOIP ───────────────────────────────────────────────────────────
_port_counter_lock = threading.Lock()
_port_counter = 21000

def _get_next_port() -> int:
    global _port_counter
    with _port_counter_lock:
        port = _port_counter
        _port_counter = 21000 + (_port_counter - 21000 + 1) % 8000
        return port

def _iso_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2: return "🌐"
    return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))

def _get_country(ip: str) -> tuple[str, str]:
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=4)
        cc = resp.json().get("countryCode", "??").upper()
        return cc, _iso_to_flag(cc)
    except:
        return "??", "🌐"

# ─── ФУНКЦИИ XRAY ────────────────────────────────────────────────────────────
def _find_xray_binary() -> str | None:
    for c in ["xray", "/usr/local/bin/xray", "/usr/bin/xray", "/app/xray", "./xray"]:
        try:
            if subprocess.run([c, "version"], capture_output=True, timeout=3).returncode == 0: 
                return c
        except: continue
    return None

XRAY_BINARY = _find_xray_binary()

def _parse_vless_to_xray_config(link: str, socks_port: int) -> dict | None:
    """Парсер ссылки в конфиг (полная версия)"""
    try:
        m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\??([^#]*)', link)
        if not m: return None

        uuid, host, port, raw_params = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        params = dict(part.split('=', 1) for part in raw_params.split('&') if '=' in part)
        params = {k: unquote(v) for k, v in params.items()}

        network = params.get('type', 'tcp')
        security = params.get('security', 'none')
        sni = params.get('sni', host)

        stream = {"network": network}
        if security == 'reality':
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": sni, "fingerprint": params.get('fp', 'chrome'),
                "publicKey": params.get('pbk', ''), "shortId": params.get('sid', ''),
                "spiderX": params.get('spx', '/')
            }
        elif security == 'tls':
            stream["security"] = "tls"
            tls_cfg = {"serverName": sni, "allowInsecure": params.get('insecure', '0') in ('1', 'true')}
            if params.get('alpn'): tls_cfg["alpn"] = [a.strip() for a in params.get('alpn').split(',')]
            stream["tlsSettings"] = tls_cfg
        else:
            stream["security"] = "none"

        if network == 'ws': stream["wsSettings"] = {"path": params.get('path', '/'), "headers": {"Host": params.get('host', host)}}
        elif network == 'grpc': stream["grpcSettings"] = {"serviceName": params.get('serviceName', params.get('spx', '')), "multiMode": params.get('mode', 'gun') == 'multi'}

        user = {"id": uuid, "encryption": "none"}
        if params.get('flow'): user["flow"] = params.get('flow')

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": socks_port, "protocol": "socks", "listen": "127.0.0.1", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}, "streamSettings": stream}]
        }
    except Exception as e:
        logger.debug(f"Ошибка парсинга VLESS: {e}")
        return None

# ─── КЛАСС ПРОКСИ (УПРАВЛЕНИЕ ПРОЦЕССОМ) ─────────────────────────────────────
class ProxyInstance:
    def __init__(self, link: str):
        self.raw_link = link
        self.base_link = link.split('#')[0]
        self.port = _get_next_port()
        self.process = None
        self.cfg_file = None
        
        m = re.match(r'vless://[^@]+@([^:]+):(\d+)', self.base_link)
        self.host = m.group(1) if m else "unknown"
        self.cc, self.flag = "??", "🌐"
        self.ping_ms = 999.0

    def start(self) -> bool:
        config = _parse_vless_to_xray_config(self.base_link, self.port)
        if not config: return False
        
        fd, self.cfg_file = tempfile.mkstemp(suffix='.json', prefix='xray_cfg_')
        with os.fdopen(fd, 'w') as f: json.dump(config, f)
        
        self.process = subprocess.Popen([XRAY_BINARY, 'run', '-c', self.cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        return self.process.poll() is None

    def stop(self):
        if self.process:
            try: self.process.terminate(); self.process.wait(timeout=2)
            except: 
                try: self.process.kill()
                except: pass
        if self.cfg_file and os.path.exists(self.cfg_file):
            try: os.unlink(self.cfg_file)
            except: pass

    def get_proxies_dict(self):
        return {"http": f"socks5h://127.0.0.1:{self.port}", "https": f"socks5h://127.0.0.1:{self.port}"}

# ─── БАЛАНСИРОВЩИК ───────────────────────────────────────────────────────────
class GarantBalancer:
    def __init__(self):
        self.active_pool: list[ProxyInstance] = []
        self.reserve_pool: list[ProxyInstance] = []
        self.untested_queue = Queue()
        self.lock = threading.Lock()
        self.seen_hosts = set()

    def run_scraper(self):
        while True:
            logger.info("[Scraper] Запуск сбора ссылок...")
            new_count = 0
            for url in VLESS_SOURCES:
                try:
                    resp = requests.get(url, timeout=10)
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.startswith('vless://') and 'type=xhttp' not in line:
                            m = re.match(r'vless://[^@]+@([^:]+):(\d+)', line)
                            if m and m.group(1) not in self.seen_hosts:
                                self.seen_hosts.add(m.group(1))
                                self.untested_queue.put(line)
                                new_count += 1
                except Exception as e:
                    logger.warning(f"Ошибка парсинга {url}: {e}")
            
            logger.info(f"[Scraper] В очередь добавлено {new_count} новых хостов.")
            time.sleep(600) # Раз в 10 минут

    def _stress_test_worker(self):
        while True:
            link = self.untested_queue.get()
            instance = ProxyInstance(link)
            
            if not instance.start():
                instance.stop()
                self.untested_queue.task_done()
                continue
                
            # Стресс-тест
            test_url = "https://speed.hetzner.de/100MB.bin" 
            start_time = time.time()
            is_stable = False
            
            try:
                with requests.get(test_url, proxies=instance.get_proxies_dict(), stream=True, timeout=8) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=16384):
                        if not chunk: break
                        if time.time() - start_time >= STRESS_TEST_DURATION:
                            is_stable = True
                            break
            except Exception:
                pass
            
            if is_stable:
                try: ip = socket.gethostbyname(instance.host)
                except: ip = "127.0.0.1"
                instance.cc, instance.flag = _get_country(ip)
                instance.ping_ms = (time.time() - start_time) * 1000 / STRESS_TEST_DURATION 
                
                with self.lock:
                    self.reserve_pool.append(instance)
                logger.info(f"✅ Успех (Резерв+): {instance.flag} {instance.cc} | {instance.host}")
            else:
                instance.stop()
                
            self.untested_queue.task_done()

    def run_health_watcher(self):
        while True:
            with self.lock:
                alive_active = []
                for p in self.active_pool:
                    try:
                        start = time.time()
                        # Легкий Health Check
                        requests.get("https://api.telegram.org", proxies=p.get_proxies_dict(), timeout=4)
                        p.ping_ms = (time.time() - start) * 1000
                        alive_active.append(p)
                    except:
                        logger.warning(f"❌ Сервер упал: {p.host}. Удаляем из Актива.")
                        p.stop()
                
                self.active_pool = alive_active
                
                # Добираем из резерва
                while len(self.active_pool) < TARGET_ACTIVE_COUNT and self.reserve_pool:
                    new_server = self.reserve_pool.pop(0)
                    self.active_pool.append(new_server)
                    logger.info(f"🔄 Восполнение Актива: добавлен {new_server.host} из резерва.")
                    
            time.sleep(10)

    def get_api_payload(self) -> list[dict]:
        with self.lock:
            if not self.active_pool: return []
            
            pool = sorted(self.active_pool, key=lambda x: x.ping_ms)
            result = []
            for i, p in enumerate(pool, 1):
                name = f"🛡️ Обход Гарант {i} {p.flag}"
                result.append({
                    "link": f"{p.base_link}#{name}",
                    "ping_ms": round(p.ping_ms, 1),
                    "country": p.cc,
                    "flag": p.flag,
                })
            return result

    def start(self):
        threading.Thread(target=self.run_scraper, daemon=True).start()
        for _ in range(MAX_STRESS_WORKERS):
            threading.Thread(target=self._stress_test_worker, daemon=True).start()
        threading.Thread(target=self.run_health_watcher, daemon=True).start()
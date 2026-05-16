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
import random
import concurrent.futures
from queue import Queue
from urllib.parse import unquote, parse_qs

logger = logging.getLogger(__name__)

# ==================== КОНФИГУРАЦИЯ ====================
VLESS_SOURCES = [
    # Основные русские (приоритет)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",

    # Часто обновляемые и качественные
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",  
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",

    # Новые источники для большего количества вариаций
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
]

TARGET_ACTIVE_COUNT = 10
MAX_RESERVE_COUNT = 25
MAX_STRESS_WORKERS = 40
STRESS_TEST_DURATION = 22

# Снижено до 8 Mbps: идеально для стабильного пула. Хватит для YouTube 1080p и Telegram
MIN_ACCEPTABLE_SPEED_MBPS = 8   

SUPER_SPEED_MBPS = 85
SUPER_LOW_PING_MS = 280

# =====================================================

_port_counter_lock = threading.Lock()
_port_counter = 21000

def _get_next_port() -> int:
    global _port_counter
    with _port_counter_lock:
        port = _port_counter
        _port_counter = 21000 + (_port_counter - 21000 + 1) % 8000
        return port

def _iso_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))

def _get_country(ip: str) -> tuple[str, str]:
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        cc = resp.json().get("countryCode", "??").upper()
        return cc, _iso_to_flag(cc)
    except:
        return "??", "🌐"

def _find_xray_binary() -> str | None:
    paths = ["xray", "/usr/local/bin/xray", "/usr/bin/xray", "/app/xray", "./xray"]
    for c in paths:
        try:
            if subprocess.run([c, "version"], capture_output=True, timeout=3).returncode == 0:
                return c
        except:
            continue
    return None

XRAY_BINARY = _find_xray_binary()

# ==================== ПАРСЕР VLESS ====================
def _parse_vless_to_xray_config(link: str, socks_port: int) -> dict | None:
    try:
        link = link.split('#')[0].strip()
        if not link.startswith('vless://'):
            return None

        m = re.match(r'vless://([^@]+)@([^:]+):(\d+)(?:\?(.*))?', link)
        if not m:
            return None

        uuid, host, port_str, query = m.groups()
        port = int(port_str)
        params = parse_qs(query) if query else {}

        def get_param(key, default=None):
            val = params.get(key, [default])
            return unquote(str(val[0])) if val and val[0] is not None else default

        security = get_param('security', 'none')
        network = get_param('type', 'tcp')
        sni = get_param('sni') or get_param('host') or host

        stream = {"network": network}

        if security == 'reality':
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": sni,
                "fingerprint": get_param('fp', 'chrome'),
                "publicKey": get_param('pbk', ''),
                "shortId": get_param('sid', ''),
                "spiderX": get_param('spx', '/')
            }
        elif security in ('tls', 'xtls'):
            stream["security"] = "tls"
            tls_cfg = {"serverName": sni, "allowInsecure": True}
            if alpn := get_param('alpn'):
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(',')]
            stream["tlsSettings"] = tls_cfg

        if network == 'ws':
            stream["wsSettings"] = {
                "path": get_param('path', '/'),
                "headers": {"Host": get_param('host', host)}
            }
        elif network == 'grpc':
            stream["grpcSettings"] = {
                "serviceName": get_param('serviceName') or get_param('spx', ''),
            }
        elif network in ('xhttp', 'httpupgrade'):
            stream["httpSettings"] = {"path": get_param('path', '/'), "host": get_param('host', host)}

        user = {"id": uuid, "encryption": "none"}
        if flow := get_param('flow'):
            user["flow"] = flow

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": socks_port, "protocol": "socks", "listen": "127.0.0.1", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}, "streamSettings": stream}]
        }
    except Exception as e:
        logger.debug(f"Parse error: {e}")
        return None


class ProxyInstance:
    def __init__(self, link: str):
        self.raw_link = link
        self.base_link = link.split('#')[0]
        self.port = _get_next_port()
        self.process = None
        self.cfg_file = None
        self.stop_event = threading.Event()
        
        m = re.search(r'@([^:]+):(\d+)', self.base_link)
        self.host = m.group(1) if m else "unknown"
        self.cc, self.flag = "??", "🌐"
        self.ping_ms = 999.0
        self.speed_mbps = 0.0
        self.is_super = False
        self.last_success = time.time()

    def start(self) -> bool:
        config = _parse_vless_to_xray_config(self.base_link, self.port)
        if not config:
            return False
        
        fd, self.cfg_file = tempfile.mkstemp(suffix='.json', prefix='xray_')
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f)
        
        self.process = subprocess.Popen([XRAY_BINARY, 'run', '-c', self.cfg_file],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.2)
        if self.process.poll() is None:
            threading.Thread(target=self._background_load_loop, daemon=True).start()
            return True
        return False

    def _background_load_loop(self):
        urls = [
            "https://speed.hetzner.de/100MB.bin",
            "https://sabnzbd.org/tests/internetspeed/20MB.bin",
            "https://proof.ovh.net/files/10Mb.dat"
        ]
        while not self.stop_event.is_set():
            try:
                url = random.choice(urls)
                with requests.get(url, proxies=self.get_proxies_dict(), stream=True, timeout=12) as r:
                    if r.status_code == 200:
                        for chunk in r.iter_content(32*1024):
                            if self.stop_event.is_set():
                                break
                            if chunk:
                                time.sleep(0.5) 
            except Exception:
                time.sleep(2)

    def stop(self):
        self.stop_event.set()
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(2)
            except:
                pass
        if self.cfg_file and os.path.exists(self.cfg_file):
            try:
                os.unlink(self.cfg_file)
            except:
                pass

    def get_proxies_dict(self):
        return {"http": f"socks5h://127.0.0.1:{self.port}", "https": f"socks5h://127.0.0.1:{self.port}"}


class GarantBalancer:
    def __init__(self):
        self.active_pool: list[ProxyInstance] = []
        self.reserve_pool: list[ProxyInstance] = []
        self.untested_queue = Queue()
        self.lock = threading.Lock()
        self.seen_hosts = set()
        self.max_queue_size = 1500

    def run_scraper(self):
        while True:
            new_count = 0
            for url in VLESS_SOURCES:
                try:
                    resp = requests.get(url, timeout=15)
                    resp.raise_for_status()
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if not line.startswith('vless://'):
                            continue

                        m = re.search(r'@([^:]+):(\d+)', line)
                        if not m:
                            continue
                        key = f"{m.group(1)}:{m.group(2)}"

                        if key not in self.seen_hosts:
                            self.seen_hosts.add(key)
                            self.untested_queue.put(line)
                            new_count += 1
                except Exception as e:
                    logger.warning(f"Source {url} error: {e}")

            logger.info(f"[Scraper] Добавлено {new_count} новых. Очередь: {self.untested_queue.qsize()}")
            time.sleep(480)

    def _stress_test_worker(self):
        test_urls = ["https://speed.hetzner.de/100MB.bin", "https://sabnzbd.org/tests/internetspeed/20MB.bin"]
        while True:
            link = self.untested_queue.get()

            with self.lock:
                if len(self.reserve_pool) >= MAX_RESERVE_COUNT:
                    self.untested_queue.task_done()
                    time.sleep(2)
                    continue

            instance = ProxyInstance(link)
            if not instance.start():
                instance.stop()
                self.untested_queue.task_done()
                continue

            test_url = random.choice(test_urls)
            start = time.time()
            downloaded = 0

            try:
                with requests.get(test_url, proxies=instance.get_proxies_dict(), stream=True, timeout=18) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(128*1024):
                        if not chunk: break
                        downloaded += len(chunk)
                        if time.time() - start > STRESS_TEST_DURATION:
                            break
            except:
                pass

            elapsed = time.time() - start
            speed = (downloaded / elapsed / 125000) if elapsed > 3 and downloaded > 0 else 0

            if speed >= MIN_ACCEPTABLE_SPEED_MBPS:
                try:
                    ip = socket.gethostbyname(instance.host)
                    instance.cc, instance.flag = _get_country(ip)
                except:
                    pass

                instance.speed_mbps = speed
                instance.ping_ms = (time.time() - start) * 1000 / STRESS_TEST_DURATION
                instance.is_super = speed >= SUPER_SPEED_MBPS and instance.ping_ms <= SUPER_LOW_PING_MS
                instance.last_success = time.time()

                with self.lock:
                    if len(self.reserve_pool) < MAX_RESERVE_COUNT:
                        self.reserve_pool.append(instance)
                        mark = "⚡ " if instance.is_super else ""
                        logger.info(f"✅ {mark}Гарант+ {instance.flag} {instance.cc} | {speed:.1f} Mbps | {instance.host}")
                    else:
                        worst = min(self.reserve_pool, key=lambda x: x.speed_mbps)
                        if speed > worst.speed_mbps + 5:
                            self.reserve_pool.remove(worst)
                            worst.stop()
                            self.reserve_pool.append(instance)
                        else:
                            instance.stop()
            else:
                instance.stop()

            self.untested_queue.task_done()

    def _check_single_proxy(self, p: ProxyInstance) -> tuple[ProxyInstance, bool]:
        """Функция для параллельной проверки одного прокси"""
        try:
            # Используем безопасный эндпоинт Cloudflare. Быстро и без банов.
            resp = requests.get("http://cp.cloudflare.com/generate_204", 
                                proxies=p.get_proxies_dict(), 
                                timeout=8)
            
            if resp.status_code == 204:
                return p, True
            return p, False
        except:
            return p, False

    def run_health_watcher(self):
        while True:
            with self.lock:
                active = list(self.active_pool)
                reserve = list(self.reserve_pool)

            all_to_check = active + reserve
            alive_proxies = []
            dead_proxies = []

            # Параллельная проверка всего активного пула
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(all_to_check) or 1) as executor:
                results = executor.map(self._check_single_proxy, all_to_check)

            for p, is_alive in results:
                if is_alive:
                    alive_proxies.append(p)
                else:
                    dead_proxies.append(p)

            for p in dead_proxies:
                logger.warning(f"❌ Упал и удален: {p.host}")
                p.stop()

            with self.lock:
                # Очищаем мертвых из пула
                self.active_pool = [p for p in alive_proxies if p in self.active_pool]
                self.reserve_pool = [p for p in alive_proxies if p in self.reserve_pool]

                # Заполнение актива из резерва
                while len(self.active_pool) < TARGET_ACTIVE_COUNT and self.reserve_pool:
                    best = max(self.reserve_pool, key=lambda x: (x.speed_mbps, -x.ping_ms))
                    self.reserve_pool.remove(best)
                    self.active_pool.append(best)
                    logger.info(f"🔄 В актив: {best.host} ({best.speed_mbps:.1f} Mbps)")

                # Ротация
                if len(self.active_pool) == TARGET_ACTIVE_COUNT and self.reserve_pool:
                    worst_a = min(self.active_pool, key=lambda x: x.speed_mbps)
                    best_r = max(self.reserve_pool, key=lambda x: x.speed_mbps)
                    if best_r.speed_mbps > worst_a.speed_mbps * 1.45:
                        self.active_pool.remove(worst_a)
                        worst_a.stop()
                        self.reserve_pool.remove(best_r)
                        self.active_pool.append(best_r)
                        logger.info(f"♻️ Ротация: {worst_a.speed_mbps:.1f} → {best_r.speed_mbps:.1f}")

            time.sleep(25)

    def get_api_payload(self) -> list[dict]:
        with self.lock:
            if not self.active_pool:
                return []
            pool = sorted(self.active_pool, key=lambda x: x.ping_ms)
            random.shuffle(pool)
            return [{
                "link": f"{p.base_link}#{'⚡ Супер Гарант' if p.is_super else '🛡️ Обход Гарант'} {i+1} {p.flag}",
                "ping_ms": round(p.ping_ms, 1),
                "country": p.cc,
                "flag": p.flag,
                "is_super": p.is_super
            } for i, p in enumerate(pool)]

    def start(self):
        threading.Thread(target=self.run_scraper, daemon=True).start()
        for _ in range(MAX_STRESS_WORKERS):
            threading.Thread(target=self._stress_test_worker, daemon=True).start()
        threading.Thread(target=self.run_health_watcher, daemon=True).start()
        logger.info("🚀 Garant Balancer v2 (Parallel Ready) запущен")


# ====================== MAIN ======================
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    if not XRAY_BINARY:
        logger.error("❌ Xray не найден!")
        exit(1)

    balancer = GarantBalancer()
    balancer.start()

    # Имитация работы основного потока
    while True:
        time.sleep(60)
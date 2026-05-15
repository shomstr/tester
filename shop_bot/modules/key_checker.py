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
from queue import Queue
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# ─── КОНФИГУРАЦИЯ ────────────────────────────────────────────────────────────
VLESS_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/main/vpn-lte/best_keys.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/main/vpn-lte/good_keys.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/main/vpn-lte/subscriptions/1sub.txt",
    "https://raw.githubusercontent.com/BioniSec/vless-freesub/main/sub",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/main/vless",
    "https://raw.githubusercontent.com/Lexiie/allfree/main/vless",
    "https://raw.githubusercontent.com/ImanMontajabi/v2ray-custom-config/main/vless",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/VLESS_RAW.txt"
]

TARGET_ACTIVE_COUNT = 10
MAX_RESERVE_COUNT = 15
MAX_STRESS_WORKERS = 20
STRESS_TEST_DURATION = 35
MIN_ACCEPTABLE_SPEED_MBPS = 40

# Пороги для "Супер Гарант ⚡"
SUPER_SPEED_MBPS = 100
SUPER_LOW_PING_MS = 200

# ─── ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ───────────────────────────────────────────────
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
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=4)
        cc = resp.json().get("countryCode", "??").upper()
        return cc, _iso_to_flag(cc)
    except:
        return "??", "🌐"

def _find_xray_binary() -> str | None:
    for c in ["xray", "/usr/local/bin/xray", "/usr/bin/xray", "/app/xray", "./xray"]:
        try:
            if subprocess.run([c, "version"], capture_output=True, timeout=3).returncode == 0:
                return c
        except:
            continue
    return None

XRAY_BINARY = _find_xray_binary()


def _parse_vless_to_xray_config(link: str, socks_port: int) -> dict | None:
    """Парсер VLESS ссылки в конфиг Xray"""
    try:
        m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\??([^#]*)', link)
        if not m:
            return None

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
                "serverName": sni,
                "fingerprint": params.get('fp', 'chrome'),
                "publicKey": params.get('pbk', ''),
                "shortId": params.get('sid', ''),
                "spiderX": params.get('spx', '/')
            }
        elif security == 'tls':
            stream["security"] = "tls"
            tls_cfg = {"serverName": sni, "allowInsecure": params.get('insecure', '0') in ('1', 'true')}
            if params.get('alpn'):
                tls_cfg["alpn"] = [a.strip() for a in params.get('alpn').split(',')]
            stream["tlsSettings"] = tls_cfg

        if network == 'ws':
            stream["wsSettings"] = {"path": params.get('path', '/'), "headers": {"Host": params.get('host', host)}}
        elif network == 'grpc':
            stream["grpcSettings"] = {
                "serviceName": params.get('serviceName', params.get('spx', '')),
                "multiMode": params.get('mode', 'gun') == 'multi'
            }

        user = {"id": uuid, "encryption": "none"}
        if params.get('flow'):
            user["flow"] = params.get('flow')

        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": socks_port, "protocol": "socks", "listen": "127.0.0.1", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}, "streamSettings": stream}]
        }
    except Exception as e:
        logger.debug(f"Ошибка парсинга VLESS: {e}")
        return None


# ─── КЛАСС ПРОКСИ ───────────────────────────────────────────────────────────
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
        self.speed_mbps = 0.0
        self.is_super = False

    def start(self) -> bool:
        config = _parse_vless_to_xray_config(self.base_link, self.port)
        if not config:
            return False
        
        fd, self.cfg_file = tempfile.mkstemp(suffix='.json', prefix='xray_cfg_')
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f)
        
        self.process = subprocess.Popen([XRAY_BINARY, 'run', '-c', self.cfg_file],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        return self.process.poll() is None

    def stop(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                try:
                    self.process.kill()
                except:
                    pass
        if self.cfg_file and os.path.exists(self.cfg_file):
            try:
                os.unlink(self.cfg_file)
            except:
                pass

    def get_proxies_dict(self):
        return {"http": f"socks5h://127.0.0.1:{self.port}", "https": f"socks5h://127.0.0.1:{self.port}"}


# ─── ГЛАВНЫЙ БАЛАНСИРОВЩИК ─────────────────────────────────────────────────
class GarantBalancer:
    def __init__(self):
        self.active_pool: list[ProxyInstance] = []
        self.reserve_pool: list[ProxyInstance] = []
        self.untested_queue = Queue()
        self.lock = threading.Lock()
        self.seen_hosts = set()
        self.max_queue_size = 1800

    def run_scraper(self):
        while True:
            logger.info("[Scraper] Запуск сбора ссылок...")
            new_count = 0
            for url in VLESS_SOURCES:
                try:
                    resp = requests.get(url, timeout=12)
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if not line.startswith('vless://') or 'type=xhttp' in line:
                            continue

                        m = re.match(r'vless://[^@]+@([^:]+):(\d+)', line)
                        if not m:
                            continue
                        hostport = f"{m.group(1)}:{m.group(2)}"
                        
                        if hostport not in self.seen_hosts:
                            self.seen_hosts.add(hostport)
                            self.untested_queue.put(line)
                            new_count += 1
                except Exception as e:
                    logger.warning(f"Ошибка парсинга {url}: {e}")

            logger.info(f"[Scraper] В очередь добавлено {new_count} новых хостов. В очереди: {self.untested_queue.qsize()}")

            while self.untested_queue.qsize() > self.max_queue_size:
                try:
                    self.untested_queue.get_nowait()
                    self.untested_queue.task_done()
                except:
                    break

            time.sleep(600)

    def _stress_test_worker(self):
        test_urls = [
            "https://speed.hetzner.de/100MB.bin",
            "https://speed.hetzner.de/1GB.bin",
            "https://sabnzbd.org/tests/internetspeed/20MB.bin"
        ]
        while True:
            link = self.untested_queue.get()
            
            # Don't test if reserve is already full to save CPU
            with self.lock:
                if len(self.reserve_pool) >= MAX_RESERVE_COUNT:
                    self.untested_queue.task_done()
                    time.sleep(5)
                    continue

            instance = ProxyInstance(link)
            if not instance.start():
                instance.stop()
                self.untested_queue.task_done()
                continue

            test_url = random.choice(test_urls)
            start_time = time.time()
            downloaded = 0
            is_stable = False

            try:
                with requests.get(test_url, proxies=instance.get_proxies_dict(), stream=True, timeout=12) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=131072):
                        if not chunk:
                            is_stable = True  # File fully downloaded, so it is stable
                            break
                        downloaded += len(chunk)
                        elapsed = time.time() - start_time
                        
                        if elapsed >= STRESS_TEST_DURATION:
                            is_stable = True
                            break
                        
                        # Fast fail for very slow connections after 12 seconds
                        if elapsed > 12 and (downloaded / elapsed / 125000) < 15:
                            break
            except Exception:
                pass

            elapsed = time.time() - start_time
            if downloaded > 0 and elapsed > 0:
                speed_mbps = (downloaded / elapsed) / 125000
                instance.speed_mbps = speed_mbps
                
                if is_stable and speed_mbps >= MIN_ACCEPTABLE_SPEED_MBPS:
                    try:
                        ip = socket.gethostbyname(instance.host)
                        instance.cc, instance.flag = _get_country(ip)
                    except:
                        pass
                    
                    instance.ping_ms = (time.time() - start_time) * 1000 / STRESS_TEST_DURATION
                    instance.is_super = (speed_mbps >= SUPER_SPEED_MBPS and instance.ping_ms <= SUPER_LOW_PING_MS)
                    
                    added = False
                    with self.lock:
                        if len(self.reserve_pool) < MAX_RESERVE_COUNT:
                            self.reserve_pool.append(instance)
                            added = True
                        else:
                            worst_reserve = min(self.reserve_pool, key=lambda x: x.speed_mbps)
                            if speed_mbps > worst_reserve.speed_mbps:
                                self.reserve_pool.remove(worst_reserve)
                                worst_reserve.stop()
                                self.reserve_pool.append(instance)
                                added = True
                                
                    if added:
                        super_mark = "⚡ " if instance.is_super else ""
                        logger.info(f"✅ {super_mark}Гарант+ {instance.flag} {instance.cc} | {speed_mbps:.1f} Mbps | {instance.host}")
                    else:
                        instance.stop()
                else:
                    instance.stop()
            else:
                instance.stop()
                
            self.untested_queue.task_done()

    def run_health_watcher(self):
        while True:
            with self.lock:
                current_active = list(self.active_pool)
                current_reserve = list(self.reserve_pool)

            alive_active = []
            for p in current_active:
                try:
                    start = time.time()
                    requests.get("https://api.telegram.org", proxies=p.get_proxies_dict(), timeout=5)
                    p.ping_ms = (time.time() - start) * 1000
                    
                    # Periodic load simulation (Telegram Media Upload equivalent)
                    # 1 in 4 chance every 20 seconds to run a 5-second download burst
                    if random.random() < 0.25:
                        with requests.get("https://speed.hetzner.de/100MB.bin", proxies=p.get_proxies_dict(), stream=True, timeout=8) as r:
                            r.raise_for_status()
                            downloaded = 0
                            t0 = time.time()
                            for chunk in r.iter_content(chunk_size=65536):
                                if not chunk: break
                                downloaded += len(chunk)
                                if time.time() - t0 > 5:
                                    break
                            if downloaded < 2_000_000: # Needs to download at least ~3.2 Mbps sustained
                                raise Exception("Connection dropped/slow under media load")

                    alive_active.append(p)
                except Exception as e:
                    logger.warning(f"❌ Сервер упал под нагрузкой: {p.host} ({e})")
                    p.stop()
            
            with self.lock:
                # Keep active ones that survived, dropping those that failed
                self.active_pool = [p for p in alive_active if p in self.active_pool]

                # Refill active pool from reserve
                while len(self.active_pool) < TARGET_ACTIVE_COUNT and self.reserve_pool:
                    best_reserve = max(self.reserve_pool, key=lambda x: x.speed_mbps)
                    self.reserve_pool.remove(best_reserve)
                    self.active_pool.append(best_reserve)
                    logger.info(f"🔄 Добавлен в актив из резерва: {best_reserve.host} ({best_reserve.speed_mbps:.1f} Mbps)")
                
                # Smart balancing: periodically replace the worst active with a much better reserve
                if len(self.active_pool) == TARGET_ACTIVE_COUNT and self.reserve_pool:
                    worst_active = min(self.active_pool, key=lambda x: x.speed_mbps)
                    best_reserve = max(self.reserve_pool, key=lambda x: x.speed_mbps)
                    if best_reserve.speed_mbps > worst_active.speed_mbps * 1.5:  # 50% better
                        logger.info(f"♻️ Ротация: Замена {worst_active.host} ({worst_active.speed_mbps:.1f} Mbps) на {best_reserve.host} ({best_reserve.speed_mbps:.1f} Mbps)")
                        self.active_pool.remove(worst_active)
                        worst_active.stop()
                        self.reserve_pool.remove(best_reserve)
                        self.active_pool.append(best_reserve)
            
            time.sleep(20)

    def get_api_payload(self) -> list[dict]:
        with self.lock:
            if not self.active_pool:
                return []
            
            pool = sorted(self.active_pool, key=lambda x: x.ping_ms)
            random.shuffle(pool)

            result = []
            for i, p in enumerate(pool, 1):
                if p.is_super:
                    name = f"⚡ Супер Гарант {i} {p.flag}"
                else:
                    name = f"🛡️ Обход Гарант {i} {p.flag}"
                
                result.append({
                    "link": f"{p.base_link}#{name}",
                    "ping_ms": round(p.ping_ms, 1),
                    "country": p.cc,
                    "flag": p.flag,
                    "is_super": p.is_super
                })
            return result

    def start(self):
        threading.Thread(target=self.run_scraper, daemon=True).start()
        for _ in range(MAX_STRESS_WORKERS):
            threading.Thread(target=self._stress_test_worker, daemon=True).start()
        threading.Thread(target=self.run_health_watcher, daemon=True).start()
        logger.info("🚀 Garant Balancer с ⚡ Супер Гарант запущен")


# Запуск
if __name__ == "__main__":
    balancer = GarantBalancer()
    balancer.start()
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Остановка тестера...")
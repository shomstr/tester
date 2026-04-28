import sys
import codecs
import time
import requests
import traceback
import logging
import os
import urllib3
from shop_bot.modules.key_checker import GarantBalancer, XRAY_BINARY

# Отключаем предупреждения сертификатов
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Исправление кодировки консоли (для Windows)
if hasattr(sys.stdout, 'encoding') and sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try: sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    except: pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Конфигурация API
SERVER_IP = os.getenv("TARGET_SERVER", "72.56.100.12")
PORT = os.getenv("TARGET_PORT", "443")
API_URL = f"https://{SERVER_IP}:{PORT}/api/update_garant"
TESTER_ID = os.getenv("TESTER_NAME", socket.gethostname() if hasattr(socket, 'gethostname') else "unknown-tester")

def reporter_loop():
    logger.info("="*60)
    logger.info("🚀 ТЕСТЕР ОБХОД-ГАРАНТ (STATEFUL) ЗАПУЩЕН")
    logger.info(f"🎯 Главный сервер для отправки: {API_URL}")
    logger.info(f"📡 Xray Binary: {XRAY_BINARY}")
    logger.info("="*60)

    if not XRAY_BINARY:
        logger.error("❌ Xray не найден! Тестер не может работать.")
        sys.exit(1)

    # Инициализируем и запускаем фоновые потоки
    balancer = GarantBalancer()
    balancer.start()

    while True:
        try:
            payload_links = balancer.get_api_payload()
            
            if payload_links:
                logger.info(f"Отправляем {len(payload_links)} активных серверов от [{TESTER_ID}] на {API_URL}...")
                
                payload = {
                    "tester_id": TESTER_ID,
                    "link": payload_links[0]["link"],  # Совместимость с прошлой логикой
                    "links": payload_links,             # Топ-10 массив
                }
                
                response = requests.post(API_URL, json=payload, timeout=10, verify=False)
                
                if response.status_code == 200:
                    logger.info("✅ Успешно обновлено на сервере!")
                else:
                    logger.error(f"❌ Ошибка отправки: HTTP {response.status_code} - {response.text}")
            else:
                logger.warning("Ожидание серверов... (Пулы пусты, идет стресс-тест)")

        except Exception as e:
            logger.error(f"❌ Критическая ошибка в цикле: {e}")
            traceback.print_exc()

        # Ожидание перед следующей отправкой отчета на основной сервер
        time.sleep(180) 

if __name__ == "__main__":
    import socket
    reporter_loop()
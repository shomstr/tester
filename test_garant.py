import sys
import codecs
import time
import requests
import traceback
import os
from shop_bot.modules.key_checker import update_server_garant_link

# Override stdout to handle cp1251 problems in Windows terminal
if hasattr(sys.stdout, 'encoding') and sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    except Exception:
        pass

# The target server URL where the main shop_bot is running.
# Если есть домен (например hestiagate.ru), то лучше писать его вместо IP.
SERVER_IP = os.getenv("TARGET_SERVER", "72.56.100.12")
# Nginx слушает 443 порт и сам перекидывает на 1488 внутрь докера:
PORT = os.getenv("TARGET_PORT", "443")
API_URL = f"https://{SERVER_IP}:{PORT}/api/update_garant"

def push_loop():
    print("="*60)
    print(f"🚀 ТЕСТЕР ОБХОД-ГАРАНТ ЗАПУЩЕН")
    print(f"🎯 Главный сервер для отправки: {API_URL}")
    print("="*60)
    
    # Отключаем предупреждения InsecureRequestWarning, если стучимся по IP вместо домена
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # We use local_only=True so it fetches correctly within the checker script logic
    while True:
        print(f"\n[{time.strftime('%H:%M:%S')}] Начало проверки серверов...")
        try:
            best_link = update_server_garant_link(local_only=True)
            if best_link:
                import socket
                tester_id = os.getenv("TESTER_NAME", socket.gethostname())
                print(f"[{time.strftime('%H:%M:%S')}] Найден лучший сервер. Отправляем от имени {tester_id} на {API_URL}...")
                response = requests.post(
                    API_URL, 
                    json={"link": best_link, "tester_id": tester_id},
                    timeout=10,
                    verify=False  # разрешаем игнорировать ошибку сертификата при обращении по IP
                )
                if response.status_code == 200:
                    print(f"✅ Успешно обновлено на сервере! (ответ: {response.text})")
                else:
                    print(f"❌ Ошибка отправки на сервер: HTTP {response.status_code} - {response.text}")
            else:
                print("❌ Не найдено ни одного рабочего сервера.")
        except Exception as e:
            print(f"❌ Критическая ошибка в цикле:")
            traceback.print_exc()
            
        print("\nОжидание 3 минуты перед следующей проверкой...")
        time.sleep(180)

if __name__ == "__main__":
    push_loop()

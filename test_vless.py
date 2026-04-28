import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def run_standard_vless_test():
    logger.info("Запуск стандартного (stateless) тестирования VLESS...")
    # Здесь можно разместить логику проверки обычных конфигов (не Garant)
    pass

if __name__ == "__main__":
    run_standard_vless_test()
FROM python:3.10-slim

WORKDIR /app

# Устанавливаем только то, что реально нужно для чекера и API
RUN pip install --no-cache-dir flask requests

# Копируем исходники проекта (только папку src, чтобы ничего лишнего)
COPY . /app

# Проставляем PYTHONPATH, чтобы импорты 'shop_bot' из папки src не ломались
ENV PYTHONPATH="/app"

# Отключаем буферизацию Python, чтобы логи 바로 появлялись в docker logs
ENV PYTHONUNBUFFERED=1

# Порт, на котором работает локальный Flask сервер
EXPOSE 8080

# Запускаем наш чекер-API
CMD ["python", "test_garant.py"]

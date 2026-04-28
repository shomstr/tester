FROM docker.io/library/python:3.10-slim

WORKDIR /app

# Системные утилиты для скачивания xray + curl для healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем xray-core (linux amd64)
RUN XRAY_VERSION=$(wget -qO- https://api.github.com/repos/XTLS/Xray-core/releases/latest \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/') \
    && echo "Installing xray v${XRAY_VERSION}" \
    && wget -q "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
         -O /tmp/xray.zip \
    && unzip -q /tmp/xray.zip xray -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm /tmp/xray.zip \
    && xray version

# Python зависимости
RUN pip install --no-cache-dir flask requests pysocks

# Копируем исходники проекта
COPY . /app

# PYTHONPATH чтобы импорты 'shop_bot' работали
ENV PYTHONPATH="/app"

# Отключаем буферизацию Python
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "test_garant.py"]
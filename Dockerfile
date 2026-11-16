# syntax=docker/dockerfile:1

FROM python:3.14-slim

WORKDIR /app

# curl нужен для установки acme.sh, cron — для автоматического продления сертификатов
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl cron \
    && rm -rf /var/lib/apt/lists/*

# Копируем requirements.txt и устанавливаем зависимости
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Копируем остальные файлы проекта
COPY . .


# Команда запуска приложения
CMD ["python3", "app.py"]
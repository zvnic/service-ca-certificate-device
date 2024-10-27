# Используем официальный образ Python
FROM python:3.12-slim

# Устанавливаем необходимые пакеты
RUN apt-get update && apt-get install -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем все файлы приложения в контейнер
COPY ./ /app

# Установка зависимостей из requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Скрипт для генерации корневого сертификата и ключа
RUN python generate_ca.py

# Запускаем приложение
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

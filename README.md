
# Сервис генерации сертификатов и ключей

Cервис для генерации закрытого ключа и сертификата устройства, подписанного корневым сертификатом CA. Пользователь вводит ID устройства на веб-странице, после чего сервис создаёт и возвращает сгенерированные сертификаты и ключи. Полученные данные можно загрузить на устройство для дальнейшего безопасного взаимодействия.

## Функциональность

1. **Ввод ID устройства**: На главной странице можно ввести ID устройства.
2. **Генерация ключей и сертификатов**: Сервис создаёт закрытый ключ, запрос на подпись сертификата (CSR) и подписывает сертификат, используя корневой сертификат CA.
3. **Отображение и загрузка ключей и сертификатов**: После генерации ключей и сертификатов они отображаются на странице и доступны для скачивания.

## Установка и запуск сервиса

### Предварительные требования

- Установленный [Docker](https://www.docker.com/) и [Docker Compose](https://docs.docker.com/compose/).
- Файл `requirements.txt` с перечисленными зависимостями, включая `fastapi`, `uvicorn`, `cryptography`, `aiofiles` и `jinja2`.

### Шаги для запуска

1. **Склонируйте или создайте структуру проекта** с файлами `Dockerfile`, `docker-compose.yml`, `main.py`, `generate_ca.py`, а также папками `templates` и `static`.

2. **Dockerfile**: Убедитесь, что `Dockerfile` имеет следующий код, чтобы автоматически устанавливать зависимости из `requirements.txt`:

   ```dockerfile
   # Используем официальный образ Python
   FROM python:3.12-slim

   # Устанавливаем необходимые пакеты
   RUN apt-get update && apt-get install -y --no-install-recommends \
       && apt-get clean \
       && rm -rf /var/lib/apt/lists/*

   # Устанавливаем рабочую директорию
   WORKDIR /app

   # Копируем файлы приложения в контейнер
   COPY . /app

   # Установка зависимостей из requirements.txt
   RUN pip install --no-cache-dir -r requirements.txt

   # Скрипт для генерации корневого сертификата и ключа
   RUN python generate_ca.py

   # Запускаем приложение
   CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
   ```

3. **Файл `docker-compose.yml`**: Добавьте следующее содержимое:

   ```yaml
   version: '3.8'

   services:
     cert_service:
       build: .
       ports:
         - "7770:8000"
       volumes:
         - ./data:/app/data  # Директория для хранения сертификатов и ключей
   ```

4. **Запуск сервиса**: В командной строке выполните следующие команды:

   ```bash
   docker-compose build --no-cache
   docker-compose up
   ```

5. **Доступ к веб-интерфейсу**: Откройте браузер и перейдите по адресу `http://localhost:7770`. Вы увидите веб-форму для ввода `ID устройства`.

## Использование веб-интерфейса

1. **Главная страница**: Введите уникальный `ID устройства` и нажмите кнопку "Получить ключи и сертификат".
2. **Результаты**: Сервис сгенерирует ключи и сертификаты. Вы увидите:
   - **Закрытый ключ устройства**: В виде текста и ссылкой для скачивания.
   - **Сертификат устройства**: В виде текста и ссылкой для скачивания.
   - **Корневой сертификат CA**: В виде текста и ссылкой для скачивания.
3. **Скачивание файлов**: Нажмите на соответствующие ссылки, чтобы скачать закрытый ключ и сертификаты в формате `.pem`.

## Основные эндпоинты API

- `GET /` — Отображает форму для ввода ID устройства.
- `POST /api/generate_certificate` — Генерирует ключ и сертификат для введённого ID устройства.
- `GET /api/ca_certificate` — Вывод сертификата удостоверяющего центра.

## Пример использования API с помощью `curl`

Для тестирования API без веб-интерфейса можно использовать команду `curl`:

```bash
curl -X POST http://localhost:7770/api/generate_certificate -d "device_id=device_12345"
```

## Структура файлов и папок

```
.
├── Dockerfile
├── docker-compose.yml
├── main.py           # Код FastAPI приложения
├── generate_ca.py    # Скрипт для генерации корневого сертификата
├── requirements.txt  # Список зависимостей
├── templates         # HTML-шаблоны
│   ├── form.html
│   └── result.html
└── static            # Папка для сохранения сгенерированных сертификатов и ключей
```

## Заключение

Этот сервис предоставляет удобный способ генерации и управления ключами и сертификатами для устройств. Он полезен для обеспечения безопасного взаимодействия с устройствами, позволяя каждому устройству иметь уникальные ключи и сертификат, подписанный доверенным корневым CA.

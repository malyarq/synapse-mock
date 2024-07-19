# Используем базовый образ Python
FROM python:3.9-slim

# Установка зависимостей приложения
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Создание директории приложения внутри контейнера
WORKDIR /app

# Копирование всех файлов приложения в контейнер
COPY . .

# Установка зависимостей Python
RUN pip install --no-cache-dir -r requirements.txt

# Определение переменной окружения для Flask
ENV FLASK_APP main.py

# Открываем порт
EXPOSE 5000

# Команда для запуска Flask приложения в контейнере
CMD ["flask", "run", "--host=0.0.0.0"]

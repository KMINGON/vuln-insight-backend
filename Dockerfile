FROM python:3.12-slim

WORKDIR /app

# 시스템 패키지 (lxml 등 빌드용)
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 전체 복사
COPY . .

# 패키지 import 위해
ENV PYTHONPATH=/app

# 기본은 API 서버 실행
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

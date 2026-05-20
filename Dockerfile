FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    KERAS_BACKEND=torch \
    CUDA_VISIBLE_DEVICES=-1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and artifacts
COPY src/ /app/src/
COPY config/ /app/config/
COPY models/ /app/models/
COPY scripts/ /app/scripts/

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "relay.app:app", "--host", "0.0.0.0", "--port", "8000"]

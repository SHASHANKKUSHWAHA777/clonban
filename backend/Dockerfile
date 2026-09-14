FROM python:3.11-slim

# System deps needed by androguard, imagehash/Pillow, ssdeep, weasyprint (PDF)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libfuzzy-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    zlib1g-dev \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for running analysis (least privilege, since APKs are untrusted input)
RUN useradd -m -u 1000 analyzer

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /storage/apks /storage/reports /storage/tmp && \
    chown -R analyzer:analyzer /storage /app

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && chown analyzer:analyzer /usr/local/bin/docker-entrypoint.sh

USER analyzer

ENV PYTHONPATH=/app

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
FROM python:3.11-slim

# Install iptables (needed for IP blocking)
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Audit log directory
RUN mkdir -p /var/log/detector

EXPOSE 8080

CMD ["python", "main.py"]

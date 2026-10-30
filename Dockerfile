FROM python:3.11-slim

# Install Nmap + NSE scripts + Python deps in ONE layer (Debian slim has full nmap scripts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Use PORT env Render provides
CMD gunicorn --bind 0.0.0.0:$PORT ultron:app

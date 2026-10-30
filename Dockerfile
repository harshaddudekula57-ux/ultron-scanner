FROM python:3.11-slim

# Install Nmap + all NSE scripts (Debian package includes vulners)
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 10000
CMD gunicorn --bind 0.0.0.0:$PORT ultron:app

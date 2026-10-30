# Use Alpine Linux (super small and fast)
FROM alpine:3.19

# Install Python, pip, and Nmap directly from Alpine's official repository (takes 5 seconds)
RUN apk add --no-cache python3 py3-pip nmap

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy the rest of your code
COPY . .

# Run with Gunicorn
EXPOSE 10000
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "ultron:app"]

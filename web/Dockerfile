FROM python:3.11-slim

# ping is needed for the intentionally-vulnerable network diagnostics tool
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p instance static/uploads

EXPOSE 5000
CMD ["python", "app.py"]

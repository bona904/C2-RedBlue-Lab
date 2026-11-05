FROM python:3.10-slim

RUN apt-get update && apt-get install -y libpcap-dev tcpdump && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY traffic_analyzer/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

COPY . .

WORKDIR /app/traffic_analyzer

CMD ["python", "app.py"]
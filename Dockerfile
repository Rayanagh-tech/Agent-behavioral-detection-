FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY secres ./secres
COPY config ./config
COPY server.py agent.py ./
CMD ["python", "server.py"]

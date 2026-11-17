FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY detector_engine.py .

CMD ["python", "-u", "detector_engine.py"]

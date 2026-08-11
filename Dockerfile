FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir aiohttp flask PyNaCl
COPY voice_farm.py .
CMD ["python", "voice_farm.py"]

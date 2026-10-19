FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 app
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY detectors.py proxy.py mock_llm.py ./
USER 10001
EXPOSE 8090
CMD ["uvicorn", "proxy:app", "--host", "0.0.0.0", "--port", "8090"]

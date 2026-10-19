FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src

ENV CLEARPASS_SERVER=""
ENV CLEARPASS_CLIENT_ID=""
ENV CLEARPASS_CLIENT_SECRET=""
ENV CLEARPASS_API_TOKEN=""
ENV CLEARPASS_VERIFY_SSL="True"

CMD ["python", "src/main.py"]

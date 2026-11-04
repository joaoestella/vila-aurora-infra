FROM python:3.12-slim
RUN pip install --no-cache-dir flask paho-mqtt psycopg2-binary pyotp cryptography scikit-learn numpy psutil requests dkimpy dnspython
WORKDIR /app
COPY common /app/common
ENV PYTHONPATH=/app:/app/common PYTHONUNBUFFERED=1

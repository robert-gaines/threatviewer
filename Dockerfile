
FROM python:3.12.9-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80

ENV FLASK_APP=app.py

CMD ["gunicorn", "-c", "gunicorn_config.py", "app:app"]
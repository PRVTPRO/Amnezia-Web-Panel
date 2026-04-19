FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /tmp/requirements.txt
RUN python - <<'PY'
from pathlib import Path
src = Path('/tmp/requirements.txt').read_bytes()
try:
    txt = src.decode('utf-16')
except UnicodeDecodeError:
    txt = src.decode('utf-8')
Path('/tmp/requirements.utf8.txt').write_text(txt, encoding='utf-8')
PY
RUN pip install --no-cache-dir -r /tmp/requirements.utf8.txt

COPY . /app

EXPOSE 5000

CMD ["python", "app.py"]
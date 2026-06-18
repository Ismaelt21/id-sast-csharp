FROM python:3.11-windowsservercore-ltsc2022

WORKDIR C:/app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

SHELL ["powershell", "-NoProfile", "-Command"]

COPY requirements.txt .
RUN python -m pip install --upgrade pip; python -m pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "id_sast_csharp.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

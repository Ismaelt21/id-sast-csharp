FROM mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2022 AS bridge-builder

WORKDIR C:/src
SHELL ["powershell", "-NoProfile", "-Command"]

COPY roslyn_bridge/ ./roslyn_bridge/

RUN dotnet publish .\roslyn_bridge\RoslynBridge.csproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishReadyToRun=false `
    -o C:\out\roslyn_bridge\bin\Release\net8.0\win-x64


FROM python:3.11-windowsservercore-ltsc2022

WORKDIR C:/app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV ROSLYN_BRIDGE_EXE=C:\app\roslyn_bridge\bin\Release\net8.0\win-x64\RoslynBridge.exe

SHELL ["powershell", "-NoProfile", "-Command"]

COPY requirements.txt ./
RUN python -m pip install --upgrade pip; python -m pip install --no-cache-dir -r requirements.txt

COPY . ./
COPY --from=bridge-builder C:/out/roslyn_bridge C:/app/roslyn_bridge

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "id_sast_csharp.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

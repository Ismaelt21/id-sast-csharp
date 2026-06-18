# id-sast-csharp

Microservicio de analisis estatico para C# basado en Roslyn, organizado con tres capas de entrada:

- API HTTP
- CLI local
- Core compartido

El objetivo del proyecto es analizar codigo C# de forma real, detectar vulnerabilidades, generar reportes y exponer el resultado tanto por API como por consola.

## Caracteristicas

- Analisis real de proyectos C# con Roslyn Bridge
- Deteccion de vulnerabilidades por taint analysis, patrones y reglas de framework
- Reportes JSON, HTML y SARIF
- API con `POST /scan` y `GET /scan/{id}`
- CLI para ejecucion local
- Persistencia preparada para MongoDB Atlas
- Dockerizacion pensada para Windows containers por el uso de `RoslynBridge.exe`

## Estructura

- `src/id_sast_csharp/api`: endpoints HTTP
- `src/id_sast_csharp/cli`: comandos de consola
- `src/id_sast_csharp/core`: logica compartida del analisis
- `src/id_sast_csharp/infrastructure`: configuracion, MongoDB, reportes y bridge
- `tests`: pruebas unitarias e integracion
- `tests/samples`: proyectos de ejemplo para validacion

## Requisitos

- Python 3.11+
- `pip`
- Windows, si vas a ejecutar el bridge actual de Roslyn
- Acceso a MongoDB Atlas si vas a activar persistencia

## Instalacion

### 1. Crear entorno virtual

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 2. Instalar dependencias

```powershell
pip install -e .
```

## Configuracion

Renombra `.env.example` a `.env` y ajusta tus valores.

Variables importantes:

- `USE_PERSISTENCE`: activa o desactiva persistencia
- `MONGODB_URI`: URI de MongoDB Atlas
- `MONGODB_DB_NAME`: nombre de la base de datos
- `REPORTS_DIR`: carpeta de salida de reportes
- `GOOGLE_GEMINI_API_KEY`: opcional, para analisis asistido por IA

Ejemplo minimo:

```env
APP_NAME=id-sast-csharp
ENVIRONMENT=development
USE_PERSISTENCE=true
MONGODB_URI=mongodb+srv://usuario:password@cluster.mongodb.net/?appName=Cluster
MONGODB_DB_NAME=id_sast_csharp
```

## Uso de la API

### Levantar el servidor

```powershell
python -m uvicorn id_sast_csharp.api.app:app --host 0.0.0.0 --port 8000
```

### Endpoints principales

- `GET /health`
- `GET /version`
- `POST /scan`
- `GET /scan/{id}`

### Ejemplo de `POST /scan`

```bash
curl -X POST "http://localhost:8000/scan" ^
  -H "Content-Type: application/json" ^
  -d "{\"project_path\":\"C:\\\\ruta\\\\al\\\\proyecto\",\"use_ai\":false,\"persist\":false,\"json_only\":true}"
```

### Ejemplo de `GET /scan/{id}`

```bash
curl "http://localhost:8000/scan/tu-scan-id"
```

## Uso de la CLI

### Ver ayuda

```powershell
python -m id_sast_csharp.cli.main --help
```

### Escanear un proyecto

```powershell
python -m id_sast_csharp.cli.main scan tests\samples\demo --no-ai --json-only
```

### Activar persistencia

```powershell
python -m id_sast_csharp.cli.main scan tests\samples\demo --persist --json-only
```

### Comandos disponibles

- `scan`: analiza un proyecto C#
- `rules`: consulta reglas
- `analysis`: consulta estadisticas de analisis
- `mongo`: muestra estado de MongoDB

## Prueba rapida

El proyecto incluye pruebas de integracion reales sobre el proyecto demo:

```powershell
pytest -q tests\integration\test_scan_api.py tests\integration\test_scan_get_api.py
```

## Docker

Este proyecto usa `RoslynBridge.exe`, asi que la imagen debe construirse como contenedor de Windows.

### Levantar con Docker

```powershell
docker compose up --build
```

El `docker-compose.yml` usa la URI de Mongo Atlas desde `.env`.

Notas importantes:

- No se levanta Mongo local
- La conexion a Atlas debe funcionar desde tu red
- Si Atlas no responde, el analisis sigue funcionando y la persistencia queda desactivada

## Resultado del analisis

El endpoint y la CLI devuelven:

- `scan_id`
- `status`
- `project_name`
- `files_scanned`
- `findings_count`
- conteos por severidad
- `framework`
- rutas de reportes
- lista normalizada de hallazgos
- reporte completo en `report`

## Desarrollo

### Ejecutar pruebas

```powershell
pytest
```

### Formato del proyecto

- Python con estructura `src/`
- Paquetes y scripts en `src/id_sast_csharp`
- Adaptador hacia el motor legado en `cli/`, `core/` y `database/`

## Notas

- El motor actual depende del bridge de Roslyn compilado en Windows.
- La persistencia en MongoDB Atlas es opcional y no bloquea el escaneo.
- Para subir a GitHub, evita commitear `.env` y usa solo `.env.example`.

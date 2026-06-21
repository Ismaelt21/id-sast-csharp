# id-sast-csharp

Microservicio SAST para analisis estatico de aplicaciones C# basado en Roslyn y organizado con tres capas de entrada:

- API HTTP
- CLI local
- Core compartido

El objetivo del proyecto es analizar codigo C# de forma real, detectar vulnerabilidades, aplicar enriquecimiento semantico asistido por IA y generar reportes en formatos utiles para desarrollo seguro y DevSecOps.

## Que resuelve

- Analisis estatico real de proyectos C# con Roslyn Bridge
- Deteccion de vulnerabilidades por taint analysis, reglas de framework y patrones inseguros
- Enriquecimiento opcional con Gemini para reducir falsos positivos
- Generacion de reportes JSON, HTML y SARIF
- Exposicion por API y por CLI
- Persistencia preparada para MongoDB Atlas

## Estado actual del repo

Este repositorio ya incluye:

- `POST /scan`
- `GET /scan/{id}`
- CLI funcional para ejecucion local
- Reporte HTML operativo
- Integracion con Gemini mediante `google.genai`
- `.gitignore` ajustado para excluir artefactos generados

## Estructura principal

- `src/id_sast_csharp/api`: endpoints HTTP y arranque de la API
- `src/id_sast_csharp/cli`: comandos de consola
- `src/id_sast_csharp/core`: logica compartida del analisis
- `core`: motor legado reutilizado por el microservicio
- `database`: acceso y persistencia
- `reports`: generacion de reportes JSON, HTML y SARIF
- `roslyn_bridge`: puente compilado en .NET para el analisis profundo
- `rules`: reglas de deteccion
- `samples`: ejemplos para pruebas
- `tests`: pruebas unitarias e integracion
- `docs`: documentacion tecnica
- `scripts`: utilidades de mantenimiento

## Requisitos

- Python 3.11 o superior
- `pip`
- Windows para ejecutar el bridge actual de Roslyn
- Acceso a MongoDB Atlas si activas persistencia
- Clave de Gemini si activas analisis asistido por IA

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

Renombra `.env.example` a `.env` y ajusta los valores de acuerdo con tu entorno.

Variables mas importantes:

- `USE_PERSISTENCE`: activa o desactiva persistencia
- `MONGODB_URI`: URI de MongoDB Atlas
- `MONGODB_DB_NAME`: nombre de la base de datos
- `REPORTS_DIR`: carpeta de salida de reportes
- `GOOGLE_GEMINI_API_KEY`: clave opcional para IA
- `GEMINI_MODEL`: modelo Gemini a utilizar
- `USE_GEMINI`: habilita o deshabilita IA

Ejemplo minimo:

```env
APP_NAME=id-sast-csharp
ENVIRONMENT=development
USE_PERSISTENCE=true
MONGODB_URI=mongodb+srv://usuario:password@cluster.mongodb.net/?appName=Cluster
MONGODB_DB_NAME=id_sast_csharp
USE_GEMINI=true
GOOGLE_GEMINI_API_KEY=tu_clave
GEMINI_MODEL=gemini-2.5-flash
```

## API HTTP

### Levantar el servidor

```powershell
python -m uvicorn id_sast_csharp.api.app:app --host 0.0.0.0 --port 8000
```

### Endpoints

- `GET /health`
- `GET /version`
- `POST /scan`
- `GET /scan/{id}`

### `POST /scan`

Ejemplo:

```bash
curl -X POST "http://localhost:8000/scan" ^
  -H "Content-Type: application/json" ^
  -d "{\"project_path\":\"C:\\\\ruta\\\\al\\\\proyecto\",\"use_ai\":true,\"persist\":false,\"json_only\":true}"
```

### `GET /scan/{id}`

```bash
curl "http://localhost:8000/scan/tu-scan-id"
```

## CLI

### Ayuda

```powershell
python -m id_sast_csharp.cli.main --help
```

### Analizar un proyecto

```powershell
python -m id_sast_csharp.cli.main scan tests\samples\demo --no-ai --json-only
```

### Analizar con IA

```powershell
python -m id_sast_csharp.cli.main scan tests\samples\demo --use-ai --json-only
```

### Generar HTML

```powershell
python -m id_sast_csharp.cli.main scan tests\samples\demo --html-only --output-directory reports\output
```

### Persistencia

```powershell
python -m id_sast_csharp.cli.main scan tests\samples\demo --persist --json-only
```

### Comandos disponibles

- `scan`: analiza un proyecto C#
- `rules`: consulta reglas
- `analysis`: consulta estadisticas de analisis
- `mongo`: muestra estado de MongoDB

## Reportes

El motor puede producir:

- JSON estructurado para integracion
- HTML para visualizacion
- SARIF para integracion con herramientas de seguridad

Los reportes HTML se escriben en `reports/output/` cuando la ejecucion lo solicita.

## IA con Gemini

El analisis asistido por IA usa `google.genai` y esta orientado a:

- reducir falsos positivos
- enriquecer descripciones
- sugerir remediaciones concretas
- mantener salida JSON estable para el pipeline

Notas:

- Si Gemini no esta disponible, el analisis sigue funcionando.
- El pipeline mantiene fallback seguro cuando la respuesta de IA no es valida.

## Docker

El proyecto usa `RoslynBridge.exe`, por lo que la imagen debe construirse como contenedor de Windows.

### Levantar con Docker

```powershell
docker compose up --build
```

Notas:

- No se levanta Mongo local
- La conexion a Atlas debe funcionar desde tu red
- Si Atlas falla, el analisis sigue funcionando y la persistencia queda desactivada

## Pruebas

### Pruebas de integracion

```powershell
pytest -q tests\integration\test_scan_api.py tests\integration\test_scan_get_api.py
```

### Suite completa

```powershell
pytest
```

## Flujo recomendado

1. Ejecuta primero el scan por CLI sobre `tests/samples/demo`
2. Verifica el JSON de salida o el HTML generado
3. Expone el resultado por API si necesitas integrarlo con frontend o automatizacion
4. Activa persistencia solo cuando MongoDB Atlas este configurado correctamente
5. Habilita Gemini cuando quieras reducir falsos positivos y enriquecer el reporte

## Notas tecnicas

- El bridge actual depende de Windows y de la compilacion de Roslyn.
- La persistencia con MongoDB Atlas es opcional y no bloquea el escaneo.
- Los artefactos generados como `logs/`, `bin/`, `obj/` y `publish/` ya estan excluidos por `.gitignore`.
- Si vas a subir a GitHub, evita versionar `.env` y usa solo `.env.example`.

## Licencia

Proyecto academico y de investigacion para el desarrollo de la tesis.

# id-sast-csharp

Microservicio SAST para análisis estático de aplicaciones C# basado en Roslyn y organizado en tres capas de entrada:

- API HTTP
- CLI local
- Core compartido

El objetivo del proyecto es analizar código C# de forma real, detectar vulnerabilidades, aplicar enriquecimiento semántico asistido por IA y generar reportes en formatos útiles para desarrollo seguro y DevSecOps.

## Qué resuelve

- Análisis estático real de proyectos C# con Roslyn Bridge
- Detección de vulnerabilidades mediante taint analysis, reglas de framework y patrones inseguros
- Enriquecimiento opcional con Gemini para reducir falsos positivos
- Generación de reportes en JSON, HTML y SARIF
- Exposición por API y por CLI
- Persistencia preparada para MongoDB Atlas

## Estado actual del repositorio

Este repositorio ya incluye:

- `POST /scan`
- `GET /scan/{id}`
- CLI funcional para ejecución local
- Reporte HTML operativo
- Integración con Gemini mediante `google.genai`
- `.gitignore` ajustado para excluir artefactos generados

## Estructura principal

- `src/id_sast_csharp/api`: endpoints HTTP y arranque de la API
- `src/id_sast_csharp/cli`: comandos de consola
- `src/id_sast_csharp/core`: lógica compartida del análisis
- `core`: motor legado reutilizado por el microservicio
- `database`: acceso y persistencia
- `reports`: generación de reportes JSON, HTML y SARIF
- `roslyn_bridge`: puente compilado en .NET para el análisis profundo
- `rules`: reglas de detección
- `samples`: ejemplos para pruebas
- `tests`: pruebas unitarias e integración
- `docs`: documentación técnica
- `scripts`: utilidades de mantenimiento

## Requisitos

- Python 3.11 o superior
- `pip`
- Windows para ejecutar el bridge actual de Roslyn
- Acceso a MongoDB Atlas si se activa persistencia
- Clave de Gemini si se activa el análisis asistido por IA
- `aiohttp` y `google-genai` se instalan automáticamente con `pip install -e .`, ya que el cliente del bridge y el de Gemini los usan directamente

## Instalación

### 1. Crear entorno virtual

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 2. Instalar dependencias

```powershell
pip install -e .[test]
```

Si ya tenías un entorno creado antes de este cambio y te faltaba `aiohttp` o `google-genai`, reinstala las dependencias con el mismo comando anterior. No es necesario instalarlas manualmente.

### 3. Reconstruir el Roslyn Bridge

```powershell
.\scripts\build_roslyn_bridge.ps1 -Clean
```

Este script limpia `bin/`, `obj/`, `logs/`, `.appdata/`, `.dotnet/` y `NuGet/` dentro de `roslyn_bridge`, finaliza el proceso `RoslynBridge` si está activo y vuelve a publicar el ejecutable.

## Configuración

Renombra `.env.example` a `.env` y ajusta los valores de acuerdo con tu entorno.

Variables más importantes:

- `USE_PERSISTENCE`: activa o desactiva la persistencia
- `MONGODB_URI`: URI de MongoDB Atlas
- `MONGODB_DB_NAME`: nombre de la base de datos
- `REPORTS_DIR`: carpeta de salida de reportes
- `GOOGLE_GEMINI_API_KEY`: clave opcional para IA
- `GEMINI_MODEL`: modelo de Gemini a utilizar
- `USE_GEMINI`: habilita o deshabilita la IA

Ejemplo mínimo:

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

Nota: en modo `--html-only` el CLI sigue preservando el resultado estructurado del scan en memoria, de modo que el resumen no quede vacío.

### Persistencia

```powershell
python -m id_sast_csharp.cli.main scan tests\samples\demo --persist --json-only
```

### Comandos disponibles

- `scan`: analiza un proyecto C#
- `rules`: consulta reglas
- `analysis`: consulta estadísticas de análisis
- `mongo`: muestra el estado de MongoDB

## Reportes

El motor puede producir:

- JSON estructurado para integración
- HTML para visualización
- SARIF para integración con herramientas de seguridad

Los reportes HTML se escriben en `reports/output/` cuando la ejecución lo solicita.

## IA con Gemini

El análisis asistido por IA usa `google.genai` y está orientado a:

- reducir falsos positivos
- enriquecer descripciones
- sugerir remediaciones concretas
- mantener una salida JSON estable para el pipeline
- actuar de forma conservadora: Gemini ya no elimina hallazgos reales por sugerencia de falso positivo

Notas:

- Si Gemini no está disponible, el análisis sigue funcionando.
- El pipeline mantiene un fallback seguro cuando la respuesta de la IA no es válida.

## Docker

La imagen Docker es multi-stage y compila `RoslynBridge.exe` durante el build, por lo que no depende de un ejecutable precompilado en el host.
El proyecto sigue usando un contenedor de Windows debido a la dependencia del bridge.

### Levantar con Docker

```powershell
docker compose up --build
```

La imagen queda orientada a la API por defecto, pero el mismo contenedor también puede ejecutar la CLI si se sobrescribe el `command` al levantarlo.

Notas:

- No se levanta una instancia local de Mongo.
- La conexión a Atlas debe funcionar desde tu red.
- Si Atlas falla, el análisis sigue funcionando y la persistencia queda desactivada.
- `tests/` sigue excluido del contexto de Docker para mantener la imagen más liviana; si quieres analizar samples del repositorio, hazlo desde tu entorno local.

## Pruebas

### Pruebas de integración

```powershell
pytest -q tests\integration\test_scan_api.py tests\integration\test_scan_get_api.py
```

### Suite completa

```powershell
pytest
```

## Flujo recomendado

1. Ejecuta primero el scan por CLI sobre `tests/samples/demo`.
2. Verifica el JSON de salida o el HTML generado.
3. Expone el resultado por API si necesitas integrarlo con un frontend o con automatización.
4. Activa la persistencia solo cuando MongoDB Atlas esté configurado correctamente.
5. Habilita Gemini cuando quieras reducir falsos positivos y enriquecer el reporte.

## Notas técnicas

- El bridge actual depende de Windows y de la compilación de Roslyn.
- La persistencia con MongoDB Atlas es opcional y no bloquea el escaneo.
- Los artefactos generados, como `logs/`, `bin/`, `obj/` y `publish/`, ya están excluidos por `.gitignore`.
- Si vas a subir el proyecto a GitHub, evita versionar `.env` y usa únicamente `.env.example`.

## Licencia

Proyecto académico y de investigación para el desarrollo de la tesis.
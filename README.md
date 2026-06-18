# id-sast-csharp

Microservicio de analisis estatico para C# con tres capas de entrada:

- API HTTP
- CLI local
- Core compartido

## Estructura

- `src/id_sast_csharp/api`: endpoints HTTP
- `src/id_sast_csharp/cli`: comandos de consola
- `src/id_sast_csharp/core`: logica de analisis compartida
- `src/id_sast_csharp/infrastructure`: MongoDB, Roslyn, reportes y configuracion

## Arranque

La base de este repo esta preparada para que la API y la CLI consuman el mismo nucleo de analisis.
La integracion con tu motor actual se conecta desde `src/id_sast_csharp/core/services/csharp_sast_service.py`.

## Docker

Este proyecto usa `RoslynBridge.exe`, asi que la imagen debe construirse como contenedor de Windows.

Levanta la API con:

```bash
docker compose up --build
```

El `docker-compose.yml` usa la URI de Mongo Atlas desde `.env` y solo sobreescribe las rutas internas del contenedor.
Antes de ejecutarlo, asegúrate de que `MONGODB_URI` sea valida y accesible desde tu red.

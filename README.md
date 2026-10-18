# Aegis-Web3 Core — Hardening MVP

Base de ingeniería para auditoría de contratos Solidity. Incluye API FastAPI, dashboard responsive, adaptador a Slither real, hash SHA-256 de evidencia, aprobación humana explícita, cabeceras básicas de seguridad, pruebas y CI.

## Estado honesto
Este paquete es un MVP, **no un producto listo para producción**. No incluye autenticación multiusuario, persistencia de auditorías, worker aislado, Foundry fuzzing, corpus de benchmark, agente IA, Soroban ni anclaje Stellar. El historial vive en memoria y se pierde al reiniciar. La aprobación es demostrativa y no debe autorizar producción.

## Ejecutar
```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e '.[dev]'
uvicorn app.main:app --reload
```
Abre http://127.0.0.1:8000 y la API en http://127.0.0.1:8000/docs. Instala Slither en un entorno aislado siguiendo su documentación oficial; el proyecto no lo instala automáticamente.

## Validación
```bash
ruff check app tests
pytest
```

## Controles incluidos
- Slither invocado sin `shell=True`, sobre una copia temporal y con timeout.
- Extensión Solidity y tamaño máximo validados.
- Confirmación de autorización de laboratorio.
- Cabeceras HTTP y CORS configurable.
- SHA-256 del código y del registro de evidencia.
- Resultados inconclusos no pueden aprobarse.
- Ningún parche ni despliegue automático.

## Hitos antes de producción
1. Ejecutar CI y conservar resultados reales.
2. Añadir autenticación, autorización por proyecto y base de datos con migraciones.
3. Ejecutar el analizador en workers aislados y limitados.
4. Crear corpus etiquetado y medir precision/recall por categoría.
5. Añadir Foundry fuzzing, invariantes y regresión.
6. Añadir informes reproducibles, firma y almacenamiento append-only.
7. Vincular aprobaciones a identidades autenticadas y separación de funciones.
8. Añadir adaptador Soroban/Rust y pruebas de testnet.
9. Completar revisión externa y pilotos antes de afirmar producción.

## No confundir
- `health.status=ok` solo indica que responde la API.
- `tool_unavailable`, `engine_error` y `timeout` son inconclusos.
- SHA-256 permite verificar integridad respecto de un hash, no corrección del análisis.

## Mejoras de la iteración 0.3

- Persistencia SQLite para ejecuciones y revisiones.
- Registro de eventos con encadenamiento SHA-256 para detectar alteraciones si se conserva un hash de referencia confiable.
- Las decisiones de revisión no se sobrescriben mediante la API.
- Pruebas de persistencia, evidencia encadenada y rechazo de una segunda decisión.
- La suite local se ejecutó en el entorno de desarrollo: 8 pruebas aprobadas. Esto no significa que el CI remoto ya haya pasado.

**Límite importante:** el endpoint de aprobación sigue sin autenticar la identidad del revisor. No exponer esta API públicamente ni usar la aprobación como control de producción hasta implementar autenticación y autorización reales.

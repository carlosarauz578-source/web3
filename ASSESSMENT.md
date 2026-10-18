# Evaluación basada en evidencia — Aegis-Web3 Core MVP 0.3

Fecha: 2026-10-18. Alcance: código de este paquete y ocho pruebas automatizadas ejecutadas localmente. No equivale a auditoría externa ni a autorización de producción.

## Puntuación del paquete de ingeniería: 70/100

Esta nota mide la preparación del MVP y los controles presentes en el artefacto; no mide la seguridad total de un producto desplegado, la demanda comercial ni la calidad de detección en contratos reales.

| Área | Peso | Nota | Evidencia / limitación |
|---|---:|---:|---|
| Valor y relevancia | 10 | 8/10 | Problema y usuario objetivo definidos; falta validar demanda con pilotos. |
| Arquitectura y modularidad | 15 | 12/15 | API, adaptador y persistencia separados funcionalmente; falta separar workers y servicios. |
| Seguridad del sistema | 15 | 10/15 | Validación, límite de tamaño, timeout, no usa shell=True, cabeceras y CORS configurable; falta autenticación, sandbox fuerte y pentest. |
| Eficacia de auditoría | 15 | 9/15 | Integración real con Slither cuando está instalado y estado explícito si no está disponible; falta corpus de benchmark y medición precision/recall. |
| Pruebas y reproducibilidad | 10 | 8/10 | Ocho pruebas locales aprobadas; CI configurado pero no confirmado en GitHub, falta fuzzing e invariantes. |
| Gobernanza humana | 10 | 8/10 | Decisión registrada, inconclusos bloqueados, decisión no sobrescribible y evento encadenado; falta identidad autenticada y separación real de funciones. |
| Interfaz y experiencia | 10 | 8/10 | Dashboard responsive, estados explícitos y distinción de motor no disponible; falta evaluación externa de usabilidad y accesibilidad. |
| Integración de ecosistemas | 5 | 3/5 | Adaptador Solidity/Slither preparado; Foundry y Soroban aún no implementados. |
| Documentación y trazabilidad | 5 | 3/5 | Política, README, hash de artefacto y cadena de eventos; falta almacenamiento externo confiable y firma digital. |
| Adopción y viabilidad | 5 | 1/5 | No hay pilotos, métricas de uso ni validación de costos. |
| **Total** | **100** | **70/100** | **Puntuación del paquete de ingeniería, no certificación de producción.** |

## Resultados de prueba local

`PYTHONPATH=. pytest -q` → 8 pruebas aprobadas en el entorno usado para construir el paquete. Las pruebas cubren cabeceras, health, confirmación de autorización, extensión admitida, hash determinista, comportamiento sin Slither, persistencia SQLite, y cadena de eventos/decisión no sobrescribible.

No se afirma que Slither esté instalado ni que se haya analizado un corpus real. La prueba del flujo de auditoría usa un doble de prueba para verificar API y persistencia, no para medir detección de vulnerabilidades.

## Bloqueos para avanzar hacia 90/100

- [ ] Autenticación y autorización por proyecto/rol, con sesiones seguras.
- [ ] Ejecutores de análisis aislados (contenedor efímero, límites CPU/RAM/procesos, filesystem temporal y red bloqueada por defecto).
- [ ] Migraciones, backups y prueba de recuperación de base de datos.
- [ ] Corpus de contratos etiquetados y métricas por clase de vulnerabilidad.
- [ ] Foundry fuzzing, invariant testing y regresión.
- [ ] Firma digital o almacenamiento externo de evidencia con retención verificable.
- [ ] Adaptador Soroban/Rust probado en entorno local/testnet.
- [ ] CI remoto verde, análisis de dependencias y escaneo de secretos.
- [ ] Revisión externa y pilotos con métricas de utilidad y costo.

# Estadísticas del escaneo — Contentsquare

## Resumen de las 12 horas de escaneo

- **Endpoints analizados**: 181 únicos
- **Peticiones totales**: ~10.000
- **Renovaciones de token**: 47 veces (cada ~10 min)
- **Rate limit respetado**: 1 req/seg
- **Fase IDOR/BOLA**: 40+ payloads por endpoint
- **Fase XSS**: 30+ payloads modernos
- **Fase Race Condition**: 10 hilos × 5 iteraciones

## Resultado

**0 vulnerabilidades explotables**

## Conclusión

La API de Contentsquare está excelentemente blindada. Requiere análisis dinámico (emulador + Frida) para avanzar.

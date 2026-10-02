# Contentsquare — Análisis de Bug Bounty

**Fecha**: Octubre 2026
**Programa**: Contentsquare Bug Bounty (YesWeHack)
**Duración**: ~16 horas
**Resultado**: 0 vulnerabilidades explotables (API blindada)

## Scope

- `*.contentsquare.com`
- `mobile-production.content-square.net`
- `m.csqtrk.net`, `s.contentsquare.net`
- SDK Android

## Metodología

### 1. Reconocimiento
- Extracción de 181 endpoints únicos desde Burp Suite
- Análisis de JWT (RS256, claims vinculados a accountId)
- Análisis de respuestas HTTP

### 2. Pruebas IDOR/BOLA
- Cuentas de prueba: 2 propias
- 40+ payloads por endpoint
- Resultado: **Todos bloqueados con 403 JWT_PROJECT_UNAUTHORIZED**

### 3. XSS
- 30+ payloads modernos (2025-2026)
- Resultado: **Respuestas JSON, sin ejecución posible**

### 4. Race Condition
- 10 hilos × 5 iteraciones
- Resultado: **Sin efecto explotable**

### 5. Reversing SDK Android
- Análisis del AAR `com.contentsquare.android.internal:core:4.44.1`
- Endpoint encontrado: `mobile-production.content-square.net/android/config/v2/{appId}.json`
- **Limitación**: `appId` no obtenible sin análisis dinámico (emulador + Frida)

## Conclusión

API **excelentemente blindada**. Contentsquare tiene un equipo de seguridad de élite.

## Aprendizajes

- Uso profesional de Burp Suite (Match/Replace, Intruder, Repeater)
- Análisis de bytecode con `javap`
- Reversing de APKs/AARs con `apktool`, `jadx`
- Construcción de scripts Python para bug bounty
- Auto-refresh de tokens JWT

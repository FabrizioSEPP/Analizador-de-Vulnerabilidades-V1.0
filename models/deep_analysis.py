import re
import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, List, Optional

import requests
from bs4 import BeautifulSoup

from models.i18n import t


CABECERAS_SEGURIDAD: Dict[str, Dict[str, str]] = {
    "Content-Security-Policy": {
        "nivel": "alta",
        "explicacion": t("Define los origenes permitidos para mitigar XSS. Su ausencia permite inyectar scripts maliciosos."),
        "remediacion": t("Definir una politica CSP estricta (default-src 'self')."),
        "owasp": "A01",
    },
    "X-Frame-Options": {
        "nivel": "media",
        "explicacion": t("Protege contra clickjacking impidiendo cargar la pagina en iframes de terceros."),
        "remediacion": t("Agregar: X-Frame-Options: DENY o SAMEORIGIN."),
        "owasp": "A01",
    },
    "X-Content-Type-Options": {
        "nivel": "baja",
        "explicacion": t("Evita que el navegador haga MIME-sniffing e interprete archivos como scripts."),
        "remediacion": t("Agregar: X-Content-Type-Options: nosniff."),
        "owasp": "A02",
    },
    "Strict-Transport-Security": {
        "nivel": "alta",
        "explicacion": t("Fuerza conexiones HTTPS. Su ausencia permite ataques de downgrade a HTTP."),
        "remediacion": t("Agregar: Strict-Transport-Security: max-age=31536000."),
        "owasp": "A02",
    },
    "Referrer-Policy": {
        "nivel": "baja",
        "explicacion": t("Controla que informacion se envia como referencia al navegar a otros sitios."),
        "remediacion": t("Agregar: Referrer-Policy: no-referrer."),
        "owasp": "A02",
    },
}


def _normalizar_cabeceras(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def _check_https(dominio: str, puerto: int = 443) -> Dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((dominio, puerto), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valido": True,
                    "emisor": cert.get("issuer", ""),
                    "expira": cert.get("notAfter", "desconocido"),
                    "tls_version": getattr(ssock, "version", lambda: "desconocida")(),
                }
    except ssl.SSLCertVerificationError as e:
        return {"valido": False, "error": f"Certificado no confiable: {str(e)[:100]}"}
    except ssl.SSLError as e:
        return {"valido": False, "error": f"Error SSL: {str(e)[:100]}"}
    except Exception as e:
        return {"valido": False, "error": f"No se pudo conectar: {str(e)[:100]}"}


def analizar_profundamente(url: str) -> Dict:
    parsed = urlparse(url)
    dominio = parsed.hostname or url
    hallazgos = []
    score = 0

    if parsed.scheme != "https":
        hallazgos.append({
            "tipo": "conexion_no_segura", "descripcion": t("El sitio no usa HTTPS"),
            "detalle": t("Los datos viajan sin cifrar y pueden ser interceptados."),
            "severidad": "alta", "remediacion": t("Implementar certificado SSL/TLS y redirigir todo el trafico a HTTPS."),
            "owasp": "A02",
        })
        score += 25
    else:
        cert = _check_https(dominio)
        if not cert.get("valido"):
            hallazgos.append({
                "tipo": "certificado_ssl", "descripcion": t("Problema con el certificado SSL/TLS"),
                "detalle": cert.get("error", t("Certificado no valido")),
                "severidad": "alta", "remediacion": t("Instalar un certificado SSL valido de una CA confiable."),
                "owasp": "A02",
            })
            score += 25
        else:
            tls_version = cert.get("tls_version", "")
            if tls_version and tls_version not in ("TLSv1.2", "TLSv1.3"):
                hallazgos.append({
                    "tipo": "tls_antiguo", "descripcion": t("Version de TLS antigua ({})").format(tls_version),
                    "detalle": t("Las versiones anteriores a TLS 1.2 tienen vulnerabilidades conocidas."),
                    "severidad": "alta", "remediacion": t("Deshabilitar TLS 1.0/1.1 y SSL y forzar TLS 1.2 o 1.3."),
                    "owasp": "A02",
                })
                score += 20

    try:
        respuesta = requests.get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "es-ES,es;q=0.9",
            },
            timeout=5, allow_redirects=True,
        )
        headers = _normalizar_cabeceras(respuesta.headers)

        if respuesta.status_code >= 500:
            hallazgos.append({
                "tipo": "error_servidor", "descripcion": t("Error del servidor (HTTP {})").format(respuesta.status_code),
                "detalle": t("El servidor devuelve errores 5xx."),
                "severidad": "media", "remediacion": t("Revisar los logs del servidor."),
                "owasp": "A09",
            })
            score += 15
        elif respuesta.status_code >= 400:
            hallazgos.append({
                "tipo": "error_cliente", "descripcion": t("Error HTTP {}").format(respuesta.status_code),
                "detalle": t("La pagina devuelve un error de cliente."),
                "severidad": "baja", "remediacion": t("Verificar la URL."),
                "owasp": "A05",
            })
            score += 5

        for cabecera, info in CABECERAS_SEGURIDAD.items():
            if cabecera.lower() not in headers:
                hallazgos.append({
                    "tipo": "cabecera_faltante", "descripcion": t("Cabecera de seguridad faltante: {}").format(cabecera),
                    "detalle": info["explicacion"],
                    "severidad": info["nivel"], "remediacion": info["remediacion"],
                    "owasp": info["owasp"],
                })
                extra = 20 if info["nivel"] == "alta" else (12 if info["nivel"] == "media" else 5)
                score += extra

        server = headers.get("server")
        powered_by = headers.get("x-powered-by")
        if server or powered_by:
            info_tecnica = []
            if server: info_tecnica.append(f"Server: {server}")
            if powered_by: info_tecnica.append(f"X-Powered-By: {powered_by}")
            hallazgos.append({
                "tipo": "info_expuesta", "descripcion": t("Tecnologia del servidor expuesta"),
                "detalle": t("Revelar software y version permite buscar vulnerabilidades."),
                "severidad": "baja", "remediacion": t("Ocultar Server y X-Powered-By."),
                "owasp": "A02",
            })
            score += 5

        try:
            set_cookie = respuesta.raw.headers.get_all("Set-Cookie") or []
        except Exception:
            set_cookie = []
        cookies_inseguras = []
        for c in set_cookie or []:
            marca = c.upper()
            nombre = c.split(";")[0].strip() if c else "cookie"
            if "SECURE" not in marca: cookies_inseguras.append(f"{nombre}: falta Secure")
            if "HTTPONLY" not in marca: cookies_inseguras.append(f"{nombre}: falta HttpOnly")
        if cookies_inseguras:
            hallazgos.append({
                "tipo": "cookies_inseguras", "descripcion": t("{} cookie(s) sin flags de seguridad").format(len(cookies_inseguras)),
                "detalle": "; ".join(cookies_inseguras) + ". " + t("Sin Secure se envian por HTTP y sin HttpOnly quedan expuestas."),
                "severidad": "media", "remediacion": t("Configurar cookies con Secure, HttpOnly y SameSite."),
                "owasp": "A08",
            })
            score += 12

        acao = headers.get("access-control-allow-origin")
        if acao and acao.strip() == "*":
            hallazgos.append({
                "tipo": "cors_abierto", "descripcion": t("CORS con Access-Control-Allow-Origin: *"),
                "detalle": t("Permite que cualquier sitio lea respuestas, facilitando robo de datos."),
                "severidad": "media", "remediacion": t("Restringir CORS a dominios confiables."),
                "owasp": "A01",
            })
            score += 12

        if "text/html" in respuesta.headers.get("content-type", "") or "<html" in respuesta.text.lower():
            sopa = BeautifulSoup(respuesta.text, "html.parser")
            formularios_get = sum(1 for f in sopa.find_all("form")
                                  if f.get("method", "get").lower() == "get"
                                  and f.find("input", {"type": ["password", "email", "text"]}))
            if formularios_get > 0:
                hallazgos.append({
                    "tipo": "formulario_inseguro", "descripcion": t("{} formulario(s) usan GET para datos").format(formularios_get),
                    "detalle": t("Los datos viajan en la URL y quedan en historial y logs."),
                    "severidad": "media", "remediacion": t("Usar POST para formularios con datos sensibles."),
                    "owasp": "A01",
                })
                score += 12

            iframes = sopa.find_all("iframe")
            iframes_ocultos = [i for i in iframes
                               if i.get("height") in ("0", "1") or i.get("width") in ("0", "1")
                               or (i.get("style") and "display:none" in i.get("style", ""))]
            if iframes_ocultos:
                hallazgos.append({
                    "tipo": "iframe_oculto", "descripcion": t("{} iframe(s) ocultos detectados").format(len(iframes_ocultos)),
                    "detalle": t("Iframes ocultos son senal de clickjacking o contenido malicioso."),
                    "severidad": "alta", "remediacion": t("Revisar origen de iframes y aplicar X-Frame-Options."),
                    "owasp": "A01",
                })
                score += 25

    except requests.exceptions.SSLError:
        hallazgos.append({
            "tipo": "ssl_init", "descripcion": t("Error de certificado SSL"), "detalle": t("Certificado invalido."),
            "severidad": "alta", "remediacion": t("Verificar certificado SSL."), "owasp": "A02",
        })
        score += 25
    except requests.exceptions.ConnectionError:
        hallazgos.append({
            "tipo": "no_accesible", "descripcion": t("No se pudo conectar al sitio"),
            "detalle": t("El servidor no respondio."), "severidad": "media",
            "remediacion": t("Verificar disponibilidad."), "owasp": "A05",
        })
        score += 15
    except requests.exceptions.Timeout:
        hallazgos.append({
            "tipo": "timeout", "descripcion": t("Tiempo de espera agotado"),
            "detalle": t("Timeout en la peticion."), "severidad": "baja",
            "remediacion": t("Revisar rendimiento del servidor."), "owasp": "A05",
        })
        score += 5
    except Exception as e:
        hallazgos.append({
            "tipo": "error_general", "descripcion": t("Error al analizar la URL"),
            "detalle": str(e)[:150], "severidad": "media",
            "remediacion": t("Verificar la sintaxis de la URL."), "owasp": "A05",
        })
        score += 10

    score = min(100, score)
    nivel = "critica" if score >= 85 else "alta" if score >= 60 else "media" if score >= 30 else "baja"
    return {
        "url": url, "dominio": dominio, "score_vulnerabilidad": score,
        "nivel_vulnerabilidad": nivel, "total_errores": len(hallazgos),
        "errores": hallazgos,
    }

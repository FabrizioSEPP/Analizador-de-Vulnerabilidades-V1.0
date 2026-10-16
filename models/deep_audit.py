"""Auditoría profunda: crawler + comprobaciones por página y por servicio.

Reutiliza `analizar_profundamente` (cabeceras, cookies, HTTPS, formularios) en
cada página descubierta y añade comprobaciones globales: fingerprint de
tecnología, métodos HTTP, archivos expuestos, CSP débil y robots.txt.
"""

import re
from urllib.parse import urljoin

from models.crawler import rastrear
from models.deep_analysis import analizar_profundamente, _normalizar_cabeceras
from models.http_utils import hacer_peticion
from models.i18n import t, es_o_en

# ruta -> (severidad, validador, descripcion, owasp)
ARCHIVOS_SENSIBLES = {
    ".env": ("alta", lambda r: "=" in r.text and "<html" not in r.text.lower() and len(r.text) > 10,
             t("Archivo de variables de entorno expuesto"), "A05"),
    ".git/config": ("alta", lambda r: "[core]" in r.text,
                    t("Repositorio Git expuesto"), "A05"),
    ".git/HEAD": ("alta", lambda r: r.text.strip().startswith("ref:"),
                  t("Metadatos de Git expuestos"), "A05"),
    "phpinfo.php": ("media", lambda r: "phpinfo()" in r.text.lower() or "php version" in r.text.lower(),
                    t("Página phpinfo() expuesta"), "A05"),
    "server-status": ("media", lambda r: "server status" in r.text.lower(),
                      t("Estado del servidor expuesto"), "A02"),
    "web.config": ("media", lambda r: "<configuration" in r.text.lower(),
                   t("web.config expuesto"), "A05"),
    ".DS_Store": ("baja", lambda r: r.content[:4] == b"\x00\x00\x00\x01",
                  t("Archivo .DS_Store expuesto"), "A05"),
    "backup.zip": ("alta", lambda r: r.content[:2] == b"PK",
                   t("Backup comprimido accesible"), "A05"),
    "wp-config.php.bak": ("alta", lambda r: "db_password" in r.text.lower() or "define(" in r.text,
                          t("Copia de wp-config expuesta"), "A05"),
    "config.php.bak": ("alta", lambda r: "password" in r.text.lower() and "<html" not in r.text.lower(),
                       t("Copia de configuración expuesta"), "A05"),
}

FIRMAS_TECNOLOGIA = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Joomla": ["joomla", "/components/com_"],
    "Drupal": ["drupal", "sites/default/files"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Laravel": ["laravel_session", "laravel"],
    "Ruby on Rails": ["_rails", "rails"],
    "React": ["_reactroot", "react-dom", "data-reactroot"],
    "Angular": ["ng-version", "angular"],
    "Vue.js": ["vue.js", "vue@", "__vue__"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "PHP": ["phpsessid", ".php"],
    "ASP.NET": ["__viewstate", "aspnet", "asp.net"],
    "Express": ["x-powered-by: express"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["microsoft-iis"],
}

PESOS_SEVERIDAD = {"critica": 40, "alta": 25, "media": 12, "baja": 5, "info": 2}


def _detectar_tecnologia(headers: dict, html: str, cookies: str) -> list:
    texto = f"{html}\n{headers}\n{cookies}".lower()
    return sorted({nombre for nombre, pistas in FIRMAS_TECNOLOGIA.items()
                   if any(pista in texto for pista in pistas)})


def _analizar_csp(headers: dict) -> list:
    csp = headers.get("content-security-policy")
    if not csp:
        return []
    debilidades = [p for p in ("unsafe-inline", "unsafe-eval") if p in csp.lower()]
    if "*" in csp:
        debilidades.append(t("comodín *"))
    if not debilidades:
        return []
    return [{
        "tipo": "csp_debil", "descripcion": t("Content-Security-Policy débil"),
        "detalle": t("Permite: ") + ", ".join(debilidades) + ". " + t("Facilita la ejecución de scripts inyectados."),
        "severidad": "media", "remediacion": t("Eliminar unsafe-inline/unsafe-eval y comodines de la CSP."),
        "owasp": "A03",
    }]


def _probar_metodos(url: str) -> list:
    hallazgos = []
    resp, _, _ = hacer_peticion(url, timeout=6, method="OPTIONS")
    if resp is not None:
        allow = (resp.headers.get("Allow") or resp.headers.get("allow") or "").upper()
        peligrosos = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow]
        if peligrosos:
            hallazgos.append({
                "tipo": "metodos_http_peligrosos",
                "descripcion": t("Métodos HTTP habilitados: {}").format(", ".join(peligrosos)),
                "detalle": t("Allow: {}. PUT/DELETE permiten modificar recursos.").format(allow.strip()),
                "severidad": "media",
                "remediacion": t("Deshabilitar los métodos HTTP que no sean necesarios."),
                "owasp": "A05",
            })

    resp_t, _, _ = hacer_peticion(url, timeout=6, method="TRACE")
    if resp_t is not None and resp_t.status_code == 200 and "TRACE" in resp_t.text.upper():
        hallazgos.append({
            "tipo": "trace_habilitado", "descripcion": t("Método TRACE habilitado"),
            "detalle": t("TRACE devuelve la petición y puede facilitar Cross-Site Tracing (XST)."),
            "severidad": "baja", "remediacion": t("Deshabilitar TRACE en el servidor."),
            "owasp": "A05",
        })
    return hallazgos


def _probar_archivos(base: str) -> list:
    hallazgos = []
    for ruta, (severidad, valida, descripcion, owasp) in ARCHIVOS_SENSIBLES.items():
        url = urljoin(base.rstrip("/") + "/", ruta)
        resp, _, _ = hacer_peticion(url, timeout=6)
        if resp is None or resp.status_code != 200:
            continue
        try:
            if not valida(resp):
                continue
        except Exception:
            continue
        hallazgos.append({
            "tipo": "archivo_expuesto", "descripcion": f"{descripcion}: /{ruta}",
            "detalle": t("Accesible en {} (HTTP {}).").format(url, resp.status_code),
            "severidad": severidad,
            "remediacion": t("Eliminar o restringir el acceso a este recurso."),
            "owasp": owasp,
        })
    return hallazgos


def _leer_robots(base: str) -> list:
    url = urljoin(base.rstrip("/") + "/", "robots.txt")
    resp, _, _ = hacer_peticion(url, timeout=6)
    if resp is None or resp.status_code != 200:
        return []
    rutas = sorted({r for r in re.findall(r"(?im)^\s*disallow:\s*(\S+)", resp.text) if r and r != "/"})
    if not rutas:
        return []
    return [{
        "tipo": "robots_revela_rutas",
        "descripcion": t("robots.txt revela {} ruta(s)").format(len(rutas)),
        "detalle": t("Rutas: ") + ", ".join(rutas[:15]),
        "severidad": "info",
        "remediacion": t("No listar rutas sensibles en robots.txt; protégelas con autenticación."),
        "owasp": "A05",
    }]


def _dedupe(errores: list) -> list:
    vistos = {}
    for e in errores:
        clave = (e.get("tipo"), e.get("descripcion"))
        if clave in vistos:
            if e.get("pagina"):
                vistos[clave].setdefault("_paginas", set()).add(e["pagina"])
            continue
        copia = dict(e)
        if copia.get("pagina"):
            copia["_paginas"] = {copia["pagina"]}
        vistos[clave] = copia

    resultado = []
    for e in vistos.values():
        paginas = e.pop("_paginas", set())
        if len(paginas) > 1:
            e["detalle"] = f"{e.get('detalle', '')} (presente en {len(paginas)} páginas)"
        resultado.append(e)
    return resultado


def _calcular_score(errores: list) -> int:
    total = sum(PESOS_SEVERIDAD.get(str(e.get("severidad", "")).lower(), 0) for e in errores)
    return min(100, round(total))


def auditoria_profunda(url: str, max_paginas: int = 15, profundidad: int = 2, callback=None) -> dict:
    if callback:
        callback(0.03, t("Rastreando el sitio..."))
    crawl = rastrear(url, max_paginas=max_paginas, profundidad=profundidad)

    errores = []
    paginas = []
    total = max(len(crawl["paginas"]), 1)

    for i, pagina in enumerate(crawl["paginas"]):
        if callback:
            callback(0.08 + (i / total) * 0.6, t("Analizando {}").format(pagina['url']))
        info = {"url": pagina["url"], "status": pagina["status"],
                "titulo": pagina.get("titulo", ""), "hallazgos": 0}
        if pagina["status"] == 0:
            info["nota"] = pagina.get("error", "sin respuesta")
            paginas.append(info)
            continue
        try:
            deep = analizar_profundamente(pagina["url"])
        except Exception:
            deep = {"errores": []}
        for encontrado in deep.get("errores", []):
            copia = dict(encontrado)
            copia["pagina"] = pagina["url"]
            errores.append(copia)
        info["hallazgos"] = len(deep.get("errores", []))
        paginas.append(info)

    if callback:
        callback(0.72, t("Comprobaciones profundas del servicio..."))

    base = crawl["url"]
    errores.extend(_leer_robots(base))
    errores.extend(_probar_archivos(base))
    errores.extend(_probar_metodos(base))

    tecnologias = []
    resp, _, error = hacer_peticion(base, timeout=8)
    if resp is not None and not error:
        headers = _normalizar_cabeceras(resp.headers)
        errores.extend(_analizar_csp(headers))
        tecnologias = _detectar_tecnologia(headers, resp.text, str(resp.headers.get("Set-Cookie", "")))
        if tecnologias:
            errores.append({
                "tipo": "tecnologia_expuesta",
                "descripcion": t("Tecnología detectada: ") + ", ".join(tecnologias),
                "detalle": t("Conocer el stack facilita buscar vulnerabilidades conocidas de esas versiones."),
                "severidad": "baja",
                "remediacion": t("Ocultar versiones/firmas y mantener todos los componentes actualizados."),
                "owasp": "A05",
            })

    if callback:
        callback(0.92, t("Consolidando hallazgos..."))

    errores = _dedupe(errores)
    score = _calcular_score(errores)
    nivel = "critica" if score >= 85 else "alta" if score >= 60 else "media" if score >= 30 else "baja"

    return {
        "url": url, "host": crawl.get("host", ""),
        "paginas": paginas, "total_paginas": len(crawl["paginas"]),
        "errores": errores, "total_errores": len(errores),
        "score_vulnerabilidad": score, "nivel_vulnerabilidad": nivel,
        "tecnologias": tecnologias,
        "resumen": {
            "paginas": len(crawl["paginas"]),
            "formularios": sum(len(p.get("formularios", [])) for p in crawl["paginas"]),
            "enlaces": sum(len(p.get("enlaces", [])) for p in crawl["paginas"]),
        },
    }

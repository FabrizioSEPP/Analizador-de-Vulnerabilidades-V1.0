"""Descubrimiento de endpoints de API (para SPAs y apps con frontend JS).

Dos vías:
  1. Estática: analiza el HTML y los .js enlazados buscando rutas de API
     (fetch/axios/URLs con /api,/rest,/graphql,/v1...) y campos JSON.
  2. Navegador (opcional, Playwright): carga la página, ejecuta JS y captura
     las peticiones XHR/fetch reales (URL, método, query y cuerpo JSON).
"""

import json
import re
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from models.http_utils import hacer_peticion

MAX_SCRIPTS = 6
MAX_ENDPOINTS = 25

_RE_RUTA_API = re.compile(
    r"""["'`](/[A-Za-z0-9_\-./]*(?:api|rest|graphql|v[0-9]|json)[A-Za-z0-9_\-./?=&%]*)["'`]"""
)
_RE_FETCH = re.compile(
    r"""(fetch|axios(?:\.(get|post|put|delete|patch))?)\s*\(\s*["'`]([^"'`]+)["'`]"""
)
_RE_METHOD = re.compile(r"""method\s*:\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]""", re.IGNORECASE)
_RE_JSON_OBJ = re.compile(r",\s*\{([^{}]{1,400})\}")


def _mismo_host(a: str, b: str) -> bool:
    return urlparse(a).hostname == urlparse(b).hostname


def _texto_js(url: str, html: str) -> str:
    """Concatena el HTML con el contenido de los .js enlazados (mismo host)."""
    partes = [html]
    try:
        sopa = BeautifulSoup(html, "html.parser")
    except Exception:
        return html
    fuentes = [s["src"] for s in sopa.find_all("script", src=True)][:MAX_SCRIPTS]
    for src in fuentes:
        absoluta = urljoin(url, src)
        if not absoluta.startswith(("http://", "https://")) or not _mismo_host(absoluta, url):
            continue
        resp, _, err = hacer_peticion(absoluta, timeout=8)
        if not err and resp is not None and resp.status_code == 200:
            partes.append(resp.text[:500000])
    return "\n".join(partes)


def _campos_json(texto: str, posicion: int) -> list:
    """Intenta leer los nombres de campo de un objeto JSON tras la URL."""
    trozo = texto[posicion:posicion + 400]
    m = _RE_JSON_OBJ.search(trozo)
    if not m:
        return []
    return re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:", m.group(1))[:10]


def descubrir_endpoints_js(url: str, html: str) -> list:
    """Endpoints de API encontrados de forma estática en el HTML/JS."""
    texto = _texto_js(url, html)
    candidatos = {}

    for m in _RE_FETCH.finditer(texto):
        funcion, verbo, ruta = m.group(1), m.group(2), m.group(3)
        metodo = (verbo or "GET").upper()
        if not verbo:
            mm = _RE_METHOD.search(texto[m.end():m.end() + 300])
            if mm:
                metodo = mm.group(1).upper()
        candidatos[(ruta, metodo)] = _campos_json(texto, m.end())

    for m in _RE_RUTA_API.finditer(texto):
        candidatos.setdefault((m.group(1), "GET"), [])

    endpoints = []
    for (ruta, metodo), campos in list(candidatos.items())[:MAX_ENDPOINTS]:
        absoluta = urljoin(url, ruta)
        if not absoluta.startswith(("http://", "https://")) or not _mismo_host(absoluta, url):
            continue
        u = urlparse(absoluta)
        params = {k: (v[0] if v else "") for k, v in parse_qs(u.query).items()}
        endpoints.append({
            "url": f"{u.scheme}://{u.netloc}{u.path}",
            "method": metodo.upper(),
            "params": params,
            "campos": campos,
        })
    return endpoints


def navegador_disponible() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as p:
            navegador = p.chromium.launch(headless=True)
            navegador.close()
        return True
    except Exception:
        return False


def descubrir_endpoints_navegador(url: str, timeout_ms: int = 15000) -> list:
    """Carga la página en un navegador headless y captura peticiones XHR/fetch."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return []

    capturadas = []
    try:
        with sync_playwright() as p:
            navegador = p.chromium.launch(headless=True)
            pagina = navegador.new_page()
            pagina.on("request", lambda r: capturadas.append(r)
                      if r.resource_type in ("xhr", "fetch") else None)
            pagina.goto(url, timeout=timeout_ms, wait_until="networkidle")
            pagina.wait_for_timeout(1500)
            navegador.close()
    except Exception:
        return []

    host = urlparse(url).hostname
    endpoints = {}
    for req in capturadas:
        u = urlparse(req.url)
        if u.hostname != host:
            continue
        params = {k: (v[0] if v else "") for k, v in parse_qs(u.query).items()}
        campos = []
        if req.method.upper() in ("POST", "PUT", "PATCH") and req.post_data:
            try:
                cuerpo = json.loads(req.post_data)
                if isinstance(cuerpo, dict):
                    campos = list(cuerpo.keys())[:10]
            except Exception:
                pass
        base = f"{u.scheme}://{u.netloc}{u.path}"
        endpoints[(base, req.method.upper())] = {
            "url": base, "method": req.method.upper(), "params": params, "campos": campos,
        }
    return list(endpoints.values())[:MAX_ENDPOINTS]

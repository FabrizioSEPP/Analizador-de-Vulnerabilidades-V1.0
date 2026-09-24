"""Descubrimiento de puntos de inyección en la página objetivo.

A partir de la URL indicada, extrae parámetros de:
  - la propia URL (query string),
  - los enlaces del mismo host que llevan parámetros,
  - los formularios (GET y POST), incluyendo sus campos ocultos,
  - cabeceras (User-Agent, Referer, X-Forwarded-For) si se habilita,
  - el cuerpo JSON del formulario (además del form-encoded) si se habilita.

Cada "objetivo" es un parámetro concreto de un endpoint, método HTTP y
"ubicación" (query | body | json | header).
"""

import re
from urllib.parse import urljoin, urlparse, urldefrag

from bs4 import BeautifulSoup

from models.http_utils import extraer_parametros, hacer_peticion

TIPOS_IGNORADOS = {"submit", "button", "image", "reset", "file"}
MAX_PARAMS_FORMULARIO = 10

# Cabeceras que se prueban como punto de inyección (muchas apps las registran
# o las usan en consultas).
CABECERAS_INYECTABLES = [
    ("User-Agent", "Mozilla/5.0 (compatible; VulnWeb)"),
    ("Referer", "https://referer.local/"),
    ("X-Forwarded-For", "127.0.0.1"),
]

# Campos que se envían como contexto pero no conviene inyectar (rompen la
# petición: CSRF, tokens de sesión, etc.).
_RE_NO_INYECTABLE = re.compile(
    r"(csrf|xsrf|token|nonce|captcha|authenticity|_method)", re.IGNORECASE
)


def _mismo_host(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).hostname == urlparse(url_b).hostname


def _agregar(objetivos: list, vistos: set, url: str, method: str, params: dict,
             param: str, origen: str, ubicacion: str = "query") -> None:
    clave = (url, method.upper(), ubicacion, param)
    if clave in vistos:
        return
    vistos.add(clave)
    valor = params.get(param)
    objetivos.append({
        "url": url,
        "method": method.upper(),
        "ubicacion": ubicacion,
        "params": dict(params),
        "param": param,
        "origen": origen,
        "valor_base": str(valor) if valor not in (None, "") else "1",
    })


def listar_paginas(url: str, limite: int = 15) -> list:
    """URLs del mismo host a revisitar (para el análisis de segundo orden)."""
    paginas, vistos = [], set()

    def _add(u: str):
        u = urldefrag(u)[0]
        if u not in vistos:
            vistos.add(u)
            paginas.append(u)

    _add(url)
    resp, _, err = hacer_peticion(url, timeout=8)
    if err or resp is None:
        return paginas
    try:
        sopa = BeautifulSoup(resp.text, "html.parser")
    except Exception:
        return paginas
    for a in sopa.find_all("a", href=True):
        if len(paginas) >= limite:
            break
        enlace = urldefrag(urljoin(url, a["href"]))[0]
        if enlace.startswith(("http://", "https://")) and _mismo_host(enlace, url):
            _add(enlace)
    return paginas[:limite]


def _campos_formulario(form) -> dict:
    campos = {}
    for campo in form.find_all(["input", "select", "textarea"]):
        nombre = campo.get("name")
        if not nombre:
            continue
        tipo = (campo.get("type") or "").lower()
        if tipo in TIPOS_IGNORADOS:
            continue

        if campo.name == "select":
            opcion = campo.find("option")
            if opcion is not None:
                valor = opcion.get("value")
                if valor is None:
                    valor = opcion.get_text(strip=True)
            else:
                valor = "1"
        elif campo.name == "textarea":
            valor = campo.get_text() or "1"
        else:
            valor = campo.get("value")

        campos[nombre] = str(valor) if valor not in (None, "") else "1"
    return campos


def descubrir_objetivos(url: str, probar_cabeceras: bool = False,
                        probar_json: bool = True, probar_apis: bool = True,
                        usar_navegador: bool = False) -> tuple[list, dict]:
    """Devuelve (objetivos, info_de_descubrimiento)."""
    objetivos: list = []
    vistos: set = set()
    url = urldefrag(url)[0]  # los fragmentos (#...) no se envían al servidor
    info = {"pagina_leida": False, "formularios": 0, "enlaces_con_params": 0,
            "cabeceras": 0, "endpoints_api": 0, "mensaje": ""}

    # 1) Parámetros ya presentes en la URL
    params_url = extraer_parametros(url)
    for param in params_url:
        _agregar(objetivos, vistos, url.split("?")[0], "GET", params_url, param, "url")

    # 1b) Cabeceras como punto de inyección
    if probar_cabeceras:
        for cabecera, base in CABECERAS_INYECTABLES:
            _agregar(objetivos, vistos, url, "GET", {cabecera: base}, cabecera, "cabecera",
                     ubicacion="header")
            info["cabeceras"] += 1

    # 2) Contenido de la página: enlaces y formularios
    response, _, error = hacer_peticion(url, timeout=8)
    if error or response is None:
        if not objetivos:
            info["mensaje"] = f"No se pudo leer la página: {error}"
        return objetivos, info
    info["pagina_leida"] = True

    content_type = (response.headers.get("Content-Type") or "").lower()
    if "html" not in content_type and "<html" not in response.text[:3000].lower():
        if not objetivos:
            info["mensaje"] = "El contenido no es HTML; solo se analizan los parámetros de la URL."
        return objetivos, info

    sopa = BeautifulSoup(response.text, "html.parser")

    # 2a) Enlaces del mismo host con parámetros
    for enlace_tag in sopa.find_all("a", href=True):
        enlace = urldefrag(urljoin(url, enlace_tag["href"]))[0]
        if not enlace.startswith(("http://", "https://")) or not _mismo_host(enlace, url):
            continue
        params = extraer_parametros(enlace)
        if not params:
            continue
        info["enlaces_con_params"] += 1
        base = enlace.split("?")[0]
        for param in params:
            if _RE_NO_INYECTABLE.search(param):
                continue
            _agregar(objetivos, vistos, base, "GET", params, param, "enlace")

    # 2b) Formularios (GET y POST)
    for form in sopa.find_all("form"):
        method = (form.get("method") or "get").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        action = urldefrag(urljoin(url, form.get("action") or url))[0]
        if not _mismo_host(action, url):
            continue

        campos = _campos_formulario(form)
        if not campos:
            continue
        info["formularios"] += 1

        if method == "POST":
            for param in list(campos)[:MAX_PARAMS_FORMULARIO]:
                if _RE_NO_INYECTABLE.search(param):
                    continue
                _agregar(objetivos, vistos, action, "POST", campos, param, "formulario",
                         ubicacion="body")
                if probar_json:
                    # Muchas APIs aceptan el mismo formulario como JSON.
                    _agregar(objetivos, vistos, action, "POST", campos, param, "formulario-json",
                             ubicacion="json")
        else:
            params_get = {**extraer_parametros(action), **campos}
            base = action.split("?")[0]
            for param in list(params_get)[:MAX_PARAMS_FORMULARIO]:
                if _RE_NO_INYECTABLE.search(param):
                    continue
                _agregar(objetivos, vistos, base, "GET", params_get, param, "formulario")

    # 3) Endpoints de API (SPA): análisis estático del JS y, opcional, navegador.
    if probar_apis:
        try:
            from models.api_discovery import descubrir_endpoints_js, descubrir_endpoints_navegador
            endpoints = descubrir_endpoints_js(url, response.text)
            if usar_navegador:
                endpoints += descubrir_endpoints_navegador(url)
        except Exception:
            endpoints = []

        for ep in endpoints:
            for param in list(ep.get("params", {}))[:MAX_PARAMS_FORMULARIO]:
                if _RE_NO_INYECTABLE.search(param):
                    continue
                _agregar(objetivos, vistos, ep["url"], ep["method"], ep["params"], param, "api")
            if ep["method"] in ("POST", "PUT", "PATCH") and ep.get("campos"):
                cuerpo = {c: "1" for c in ep["campos"]}
                for param in list(cuerpo)[:MAX_PARAMS_FORMULARIO]:
                    if _RE_NO_INYECTABLE.search(param):
                        continue
                    _agregar(objetivos, vistos, ep["url"], ep["method"], cuerpo, param,
                             "api-json", ubicacion="json")
        info["endpoints_api"] = len(endpoints)

    return objetivos, info

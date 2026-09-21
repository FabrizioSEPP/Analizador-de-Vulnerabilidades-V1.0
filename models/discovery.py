"""Descubrimiento de puntos de inyección en la página objetivo.

A partir de la URL indicada, extrae parámetros de:
  - la propia URL (query string),
  - los enlaces del mismo host que llevan parámetros,
  - los formularios (GET y POST), incluyendo sus campos ocultos.

Cada "objetivo" es un parámetro concreto de un endpoint y método HTTP.
"""

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from models.http_utils import extraer_parametros, hacer_peticion

TIPOS_IGNORADOS = {"submit", "button", "image", "reset", "file"}
MAX_PARAMS_FORMULARIO = 10

# Campos que se envían como contexto pero no conviene inyectar (rompen la
# petición: CSRF, tokens de sesión, etc.).
_RE_NO_INYECTABLE = re.compile(
    r"(csrf|xsrf|token|nonce|captcha|authenticity|_method)", re.IGNORECASE
)


def _mismo_host(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).hostname == urlparse(url_b).hostname


def _agregar(objetivos: list, vistos: set, url: str, method: str,
             params: dict, param: str, origen: str) -> None:
    clave = (url, method.upper(), param)
    if clave in vistos:
        return
    vistos.add(clave)
    valor = params.get(param)
    objetivos.append({
        "url": url,
        "method": method.upper(),
        "params": dict(params),
        "param": param,
        "origen": origen,
        "valor_base": str(valor) if valor not in (None, "") else "1",
    })


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


def descubrir_objetivos(url: str) -> tuple[list, dict]:
    """Devuelve (objetivos, info_de_descubrimiento)."""
    objetivos: list = []
    vistos: set = set()
    info = {"pagina_leida": False, "formularios": 0, "enlaces_con_params": 0, "mensaje": ""}

    # 1) Parámetros ya presentes en la URL
    params_url = extraer_parametros(url)
    for param in params_url:
        _agregar(objetivos, vistos, url.split("?")[0], "GET", params_url, param, "url")

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
            info["mensaje"] = "El contenido no es HTML; solo se pueden analizar los parámetros de la URL."
        return objetivos, info

    sopa = BeautifulSoup(response.text, "html.parser")

    # 2a) Enlaces del mismo host con parámetros
    for enlace_tag in sopa.find_all("a", href=True):
        enlace = urljoin(url, enlace_tag["href"])
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
        action = urljoin(url, form.get("action") or url)
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
                _agregar(objetivos, vistos, action, "POST", campos, param, "formulario")
        else:
            params_get = {**extraer_parametros(action), **campos}
            base = action.split("?")[0]
            for param in list(params_get)[:MAX_PARAMS_FORMULARIO]:
                if _RE_NO_INYECTABLE.search(param):
                    continue
                _agregar(objetivos, vistos, base, "GET", params_get, param, "formulario")

    return objetivos, info

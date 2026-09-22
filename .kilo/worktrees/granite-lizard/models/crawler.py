"""Rastreo ligero del sitio: sigue enlaces del mismo host hasta cierta
profundidad y recoge enlaces, formularios y recursos por página."""

from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from models.http_utils import hacer_peticion

EXTENSIONES_NO_RASTREABLES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".css", ".js", ".json", ".xml", ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".woff", ".woff2", ".ttf", ".eot",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)


def _clave(url: str) -> str:
    base, _ = urldefrag(url)
    return base.rstrip("/") or base


def _es_no_rastreable(url: str) -> bool:
    ruta = urlparse(url).path.lower()
    return any(ruta.endswith(ext) for ext in EXTENSIONES_NO_RASTREABLES)


def rastrear(url: str, max_paginas: int = 15, profundidad: int = 2) -> dict:
    host = urlparse(url).hostname
    cola = deque([(_clave(url), 0)])
    vistos = set()
    paginas = []

    while cola and len(paginas) < max_paginas:
        actual, nivel = cola.popleft()
        if actual in vistos:
            continue
        vistos.add(actual)

        response, _, error = hacer_peticion(actual, timeout=8)
        pagina = {
            "url": actual, "nivel": nivel, "status": 0, "error": error,
            "titulo": "", "enlaces": [], "formularios": [], "recursos": [],
        }

        if response is None:
            paginas.append(pagina)
            continue

        pagina["status"] = response.status_code
        content_type = (response.headers.get("Content-Type") or "").lower()
        if "html" in content_type or "xml" in content_type:
            sopa = BeautifulSoup(response.text, "html.parser")
            if sopa.title and sopa.title.string:
                pagina["titulo"] = sopa.title.string.strip()[:120]

            for enlace_tag in sopa.find_all("a", href=True):
                enlace = _clave(urljoin(actual, enlace_tag["href"]))
                if not enlace.startswith(("http://", "https://")):
                    continue
                if urlparse(enlace).hostname != host:
                    continue
                pagina["enlaces"].append(enlace)
                if nivel < profundidad and not _es_no_rastreable(enlace) and enlace not in vistos:
                    cola.append((enlace, nivel + 1))

            for form in sopa.find_all("form"):
                pagina["formularios"].append({
                    "action": urljoin(actual, form.get("action") or actual),
                    "method": (form.get("method") or "get").upper(),
                })

            for script in sopa.find_all("script", src=True):
                pagina["recursos"].append(urljoin(actual, script["src"]))

        paginas.append(pagina)

    return {
        "url": url, "host": host, "paginas": paginas,
        "total": len(paginas), "profundidad": profundidad, "max_paginas": max_paginas,
    }

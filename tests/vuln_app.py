"""Servidor HTTP local DELIBERADAMENTE vulnerable. SOLO PARA PRUEBAS LOCALES.

Simula una aplicación con:
  - /buscar?id=1  -> inyección error-based, boolean-based y time-based
  - /login (POST) -> inyección error-based en el campo `usuario`
  - /estatico     -> página que YA contiene texto tipo SQL (para probar que no
                     se reporta como falsa vulnerabilidad)
  - /seguro       -> parámetro no vulnerable
  - /tiempo       -> solo inyección basada en tiempo

Uso:  python tests/vuln_app.py   (imprime la URL y queda escuchando)
NO usar en producción ni exponer a Internet.
"""

import html as _html
import json
import random
import secrets
import string
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MENSAJE_MYSQL = (
    "<html><body>You have an error in your SQL syntax; check the manual that "
    "corresponds to your MySQL server version for the right syntax to use near '' "
    "at line 1</body></html>"
)

PAGINA_SPA = """<!doctype html><html><head><title>SPA</title></head><body>
<div id="app"></div>
<script>
fetch('/api/productos?id=1').then(function(r){ return r.json(); });
axios.post('/api/login', {usuario: 'admin', clave: 'secreto'});
</script>
</body></html>"""

PAGINA_INICIO = """<!doctype html><html><head><title>Vuln App</title></head><body>
<h1>Vuln App</h1>
<a href="/buscar?id=1">Buscar producto</a>
<form action="/login" method="post">
  <input name="usuario" value="admin">
  <button type="submit">Entrar</button>
</form>
</body></html>"""

PAGINA_ESTATICA = (
    "<html><body><h1>Documentación</h1>"
    "<p>Esta guía explica PostgreSQL y también menciona sql syntax como ejemplo.</p>"
    + "<p>contenido de relleno</p>" * 200 + "</body></html>"
)

PAGINA_SEGURA = "<html><body><h1>Página segura</h1><p>sin parámetros dinámicos</p></body></html>"


def _pagina_resultados(n: int) -> str:
    return "<html><body><h1>Resultados</h1>" + "<p>producto</p>" * n + "</body></html>"


PAGINA_NORMAL = _pagina_resultados(3)
PAGINA_RESULTADOS = _pagina_resultados(40)
PAGINA_VACIA = "<html><body><h1>Sin resultados</h1></body></html>"


def _pagina_dinamica() -> str:
    """Página NO vulnerable pero muy volátil: palabras aleatorias en cada
    petición (no se pueden "limpiar" como un token). Debe producir cable de
    ruido suficiente para descartar el análisis booleano."""
    palabras = " ".join(
        "".join(secrets.choice(string.ascii_lowercase) for _ in range(5))
        for _ in range(60)
    )
    return f"<html><body><h1>Panel dinámico</h1><p>{palabras}</p></body></html>"

_TOKENS_FALSO = ["1=2", "1'='2", "a'='b", "1!=1", "false", "x'='x"]
_TOKENS_VERDADERO = ["1=1", "1'='1", "a'='a", "1!=0", "true", "2>1", "x'!='x"]
_TOKENS_SLEEP = ["sleep", "benchmark", "waitfor", "pg_sleep"]


def _respuesta_buscar(valor: str) -> str:
    lower = valor.lower()
    if any(t in lower for t in _TOKENS_FALSO):
        return PAGINA_VACIA
    if any(t in lower for t in _TOKENS_VERDADERO):
        return PAGINA_RESULTADOS
    if "'" in valor or '"' in valor:
        return MENSAJE_MYSQL
    return PAGINA_NORMAL


def _respuesta_union(valor: str) -> str:
    """Vulnerable a UNION: la consulta tiene 2 columnas. Si se inyecta una
    función de versión, se refleja (permite probar la extracción de datos)."""
    lower = valor.lower()
    if "union select" in lower:
        parte = lower.split("union select", 1)[1]
        for marca in ("--", "#", "/*"):
            if marca in parte:
                parte = parte.split(marca)[0]
        columnas = [c.strip() for c in parte.split(",") if c.strip()]
        if len(columnas) == 2:
            if "version()" in parte or "sqlite_version()" in parte:
                return ("<html><body><h1>Resultados</h1><p>8.0.31-MySQL</p>"
                        + "<p>producto</p>" * 20 + "</body></html>")
            return PAGINA_RESULTADOS
        return ("<html><body>The used SELECT statements have a different number "
                "of columns</body></html>")
    if "'" in valor or '"' in valor:
        return MENSAJE_MYSQL
    return PAGINA_NORMAL


_PATRONES_ATAQUE = ["'", '"', " or ", " and ", "union", "select", "--", "sleep", "/*", ";"]


def _respuesta_error200(valor: str) -> str:
    """Vulnerable: filtra el error SQL pero con HTTP 200 (típico en producción).
    Union-vulnerable con 2 columnas; el error de columnas también va en un 200."""
    lower = valor.lower()
    if "union select" in lower:
        if lower.count("null") == 2:
            return PAGINA_RESULTADOS
        return ("<html><body>The used SELECT statements have a different number "
                "of columns</body></html>")
    if "'" in valor or '"' in valor:
        return MENSAJE_MYSQL
    return PAGINA_NORMAL


def _pagina_reflectante(valor: str) -> str:
    """Refleja la entrada (como un buscador) SIN SQL. Trampa clásica: el eco
    cambia el tamaño y puede confundir a un escáner poco cuidadoso."""
    relleno = "<p>resultados de búsqueda relevantes</p>" * 6
    return f"<html><body><h1>Buscador</h1>{relleno}<p>Consulta: {_html.escape(valor)}</p></body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, cuerpo: str, status: int = 200, extra: dict | None = None):
        data = cuerpo.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for clave, valor in (extra or {}).items():
            self.send_header(clave, valor)
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj, status: int = 200):
        import json
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        valor = parse_qs(u.query).get("id", [""])[0]
        try:
            if u.path in ("/", ""):
                self._send(PAGINA_INICIO)
            elif u.path == "/buscar":
                self._send(_respuesta_buscar(valor))
            elif u.path == "/estatico":
                self._send(PAGINA_ESTATICA)
            elif u.path == "/seguro":
                self._send(PAGINA_SEGURA)
            elif u.path == "/dinamico":
                self._send(_pagina_dinamica())
            elif u.path == "/union":
                self._send(_respuesta_union(valor))
            elif u.path == "/auth":
                if self.headers.get("X-Token") != "secreto":
                    self._send("<html><body>No autorizado</body></html>", 403)
                else:
                    self._send(_respuesta_buscar(valor))
            elif u.path == "/waf":
                self._send("<html><body>Request blocked by Cloudflare (ray id abc123)</body></html>", 429)
            elif u.path == "/reflectante":
                self._send(_pagina_reflectante(valor))
            elif u.path == "/error500":
                # Falla SIEMPRE (como un endpoint roto): no debe reportarse.
                self._send("<html><body>Internal Server Error</body></html>", 500)
            elif u.path == "/estado":
                # Rechaza entradas "sospechosas" cambiando el estado (200 -> 404).
                sospechoso = any(t in valor.lower() for t in
                                 ["'", '"', " or ", " and ", "--", "union", "sleep", "select"])
                if sospechoso:
                    self._send("<html><body>No encontrado</body></html>", 404)
                else:
                    self._send(PAGINA_NORMAL)
            elif u.path == "/lento":
                # Servidor lento de forma natural (sin SQL): no debe dar time-based.
                time.sleep(random.uniform(0.2, 0.6))
                self._send(PAGINA_NORMAL)
            elif u.path == "/lento_aleatorio":
                # "Tarpit": a veces tarda de forma aleatoria (sin SQL). Trampa dura
                # para el time-based.
                if random.random() < 0.35:
                    time.sleep(random.uniform(3.0, 4.0))
                self._send(PAGINA_NORMAL)
            elif u.path == "/json":
                self._send_json({"eco": valor, "items": ["uno", "dos", "tres"]})
            elif u.path == "/error200":
                self._send(_respuesta_error200(valor))
            elif u.path == "/waf_agresivo":
                if any(p in valor.lower() for p in _PATRONES_ATAQUE):
                    self._send("<html><body>Request blocked by Cloudflare "
                               "(WAF) ray id abc123</body></html>", 403)
                else:
                    self._send(PAGINA_NORMAL)
            elif u.path == "/spa":
                self._send(PAGINA_SPA)
            elif u.path == "/api/productos":
                self._send(_respuesta_buscar(valor))
            elif u.path == "/cabecera":
                # Vulnerable vía cabecera User-Agent.
                ua = self.headers.get("User-Agent", "")
                if "'" in ua or '"' in ua:
                    self._send(MENSAJE_MYSQL)
                else:
                    self._send(PAGINA_NORMAL)
            elif u.path == "/bloqueo_falso":
                # 403 con cabecera 'Server: cloudflare' (como CUALQUIER sitio tras
                # Cloudflare) pero SIN señales de WAF en el cuerpo: no es bloqueo.
                self._send("<html><body>Acceso denegado a este recurso</body></html>",
                           403, extra={"Server": "cloudflare"})
            elif u.path == "/waf_falso":
                # WAF "trampa": no bloquea, pero ante entradas sospechosas
                # devuelve contenido ALEATORIO con HTTP 200.
                if any(p in valor.lower() for p in _PATRONES_ATAQUE):
                    self._send(_pagina_dinamica())
                else:
                    self._send(PAGINA_NORMAL)
            elif u.path == "/tiempo":
                if any(t in valor.lower() for t in _TOKENS_SLEEP):
                    time.sleep(5)
                self._send(PAGINA_SEGURA)
            else:
                self._send("<html><body>404</body></html>", 404)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(n).decode("utf-8", "ignore")
        datos = parse_qs(cuerpo)
        try:
            if u.path in ("/api_json", "/api/login"):
                # API que acepta JSON en el cuerpo y es vulnerable en `usuario`.
                try:
                    cuerpo_json = json.loads(cuerpo or "{}")
                except Exception:
                    cuerpo_json = {}
                usuario = str(cuerpo_json.get("usuario", ""))
                if "'" in usuario or '"' in usuario:
                    self._send(MENSAJE_MYSQL)
                else:
                    self._send(PAGINA_SEGURA)
            elif u.path == "/login":
                usuario = datos.get("usuario", [""])[0]
                if "'" in usuario or '"' in usuario:
                    self._send(MENSAJE_MYSQL)
                else:
                    self._send(PAGINA_SEGURA)
            else:
                self._send("<html><body>404</body></html>", 404)
        except (BrokenPipeError, ConnectionResetError):
            pass


def crear_servidor() -> tuple:
    """Devuelve (servidor, puerto) escuchando en 127.0.0.1."""
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    return servidor, servidor.server_address[1]


if __name__ == "__main__":
    srv, puerto = crear_servidor()
    print(f"Servidor vulnerable de prueba en http://127.0.0.1:{puerto}")
    print("Ctrl+C para detener.")
    srv.serve_forever()

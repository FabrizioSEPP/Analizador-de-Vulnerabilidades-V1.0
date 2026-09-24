"""Pruebas del escáner SQLi contra un servidor local deliberadamente vulnerable.

Ejecutar desde la raíz del proyecto:   python tests/test_sqli.py
"""

import os
import sys
import threading
import time
from urllib.parse import urlparse

_AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _AQUI)                                   # para importar vuln_app
sys.path.insert(0, os.path.dirname(_AQUI))                  # raíz, para models

from vuln_app import crear_servidor                          # noqa: E402
from models.sqli_model import SQLiModel                      # noqa: E402
from models.discovery import descubrir_objetivos             # noqa: E402

resultados = []


def comprobar(nombre, condicion, detalle=""):
    resultados.append((nombre, bool(condicion), detalle))
    print(f"  [{'PASS' if condicion else 'FAIL'}] {nombre}" + (f"  {detalle}" if detalle else ""))


def objetivo(url, param, method="GET", params=None, origen="url", valor_base="1"):
    return {"url": url, "method": method, "params": params or {},
            "param": param, "origen": origen, "valor_base": valor_base}


def main():
    srv, puerto = crear_servidor()
    hilo = threading.Thread(target=srv.serve_forever, daemon=True)
    hilo.start()
    BASE = f"http://127.0.0.1:{puerto}"
    print(f"Servidor vulnerable de prueba: {BASE}\n")

    modelo = SQLiModel(timeout=5, time_threshold=2.0, time_runs=3)
    modelo_rapido = SQLiModel(timeout=5, time_threshold=2.0, time_runs=1)

    # 1) error-based en parámetro vulnerable (GET)
    h = modelo._error_based(objetivo(f"{BASE}/buscar", "id"))
    comprobar("error-based detecta GET vulnerable", len(h) == 1 and h[0]["motor_sugerido"] == "MySQL",
              f"hallazgos={len(h)} motor={h[0]['motor_sugerido'] if h else '-'}")

    # 2) error-based NO debe marcar una página con texto SQL legítimo (línea base)
    h = modelo._error_based(objetivo(f"{BASE}/estatico", "id"))
    comprobar("error-based no da falso positivo en página con 'PostgreSQL'/'sql syntax'", h == [],
              f"hallazgos={len(h)}")

    # 3) error-based NO debe marcar un parámetro seguro
    h = modelo._error_based(objetivo(f"{BASE}/seguro", "id"))
    comprobar("error-based no da falso positivo en parámetro seguro", h == [], f"hallazgos={len(h)}")

    # 4) boolean-based en parámetro vulnerable
    t0 = time.time()
    h = modelo._boolean_based(objetivo(f"{BASE}/buscar", "id"))
    comprobar("boolean-based detecta parámetro vulnerable",
              len(h) == 1 and h[0]["tipo"] == "boolean-based blind",
              f"hallazgos={len(h)} indicadores={h[0]['indicadores'] if h else '-'} ({time.time()-t0:.2f}s)")

    # 5) boolean-based NO debe marcar un parámetro seguro
    h = modelo._boolean_based(objetivo(f"{BASE}/seguro", "id"))
    comprobar("boolean-based no da falso positivo en parámetro seguro", h == [], f"hallazgos={len(h)}")

    # 5b) boolean-based NO debe marcar una página volátil (contenido aleatorio)
    h = modelo._boolean_based(objetivo(f"{BASE}/dinamico", "id"))
    comprobar("boolean-based no da falso positivo en página volátil", h == [], f"hallazgos={len(h)}")

    # 6) time-based (se ejecuta una sola vez para no tardar)
    t0 = time.time()
    h = modelo_rapido._time_based(objetivo(f"{BASE}/tiempo", "id"))
    comprobar("time-based detecta retardo inducido",
              len(h) == 1 and h[0]["ratio"] > 3,
              f"hallazgos={len(h)} ratio={h[0]['ratio'] if h else '-'} ({time.time()-t0:.2f}s)")

    # 6b) UNION-based: enumera el número de columnas correcto
    h = modelo._union_based(objetivo(f"{BASE}/union", "id"))
    comprobar("UNION-based detecta el número de columnas",
              len(h) == 1 and h[0].get("columnas") == 2,
              f"hallazgos={len(h)} columnas={h[0].get('columnas') if h else '-'}")

    # 6c) cabeceras personalizadas (objetivo con sesión)
    sin = modelo._error_based(objetivo(f"{BASE}/auth", "id"))
    con = SQLiModel(timeout=5, headers={"X-Token": "secreto"})._error_based(objetivo(f"{BASE}/auth", "id"))
    comprobar("cabeceras personalizadas permiten analizar objetivo autenticado",
              sin == [] and len(con) == 1,
              f"sin_header={len(sin)} con_header={len(con)}")

    # 6d) WAF / rate-limit: detecta y aborta sin falsos positivos
    m_waf = SQLiModel(timeout=5)
    h = m_waf._error_based(objetivo(f"{BASE}/waf", "id"))
    comprobar("detecta bloqueo WAF/rate-limit y aborta",
              h == [] and m_waf._bloqueado is True,
              f"hallazgos={len(h)} bloqueado={m_waf._bloqueado}")

    # 6e) comando de reproducción en el hallazgo
    h = modelo._error_based(objetivo(f"{BASE}/buscar", "id"))
    comprobar("el hallazgo incluye comando de reproducción (curl)",
              bool(h) and str(h[0].get("reproducir", "")).startswith("curl"),
              f"reproducir={h[0].get('reproducir') if h else '-'}")

    # 6f) error SQL filtrado con HTTP 200 (debe detectarse igualmente)
    h = modelo._error_based(objetivo(f"{BASE}/error200", "id"))
    comprobar("error-based detecta error SQL con HTTP 200",
              len(h) == 1 and h[0]["codigo_http"] == 200,
              f"hallazgos={len(h)} http={h[0]['codigo_http'] if h else '-'}")

    # 6g) UNION con errores en HTTP 200 (firma ANSI: distinto nº de columnas)
    h = modelo._union_based(objetivo(f"{BASE}/error200", "id"))
    comprobar("UNION-based usa la firma ANSI (error en HTTP 200) y acierta columnas",
              len(h) == 1 and h[0].get("columnas") == 2,
              f"hallazgos={len(h)} columnas={h[0].get('columnas') if h else '-'}")

    # 6h) WAF agresivo (bloquea): el escáner aborta sin falsos positivos
    m_wa = SQLiModel(timeout=5)
    h = m_wa._error_based(objetivo(f"{BASE}/waf_agresivo", "id"))
    comprobar("WAF agresivo: bloquea y el escáner aborta sin hallazgos",
              h == [] and m_wa._bloqueado is True,
              f"hallazgos={len(h)} bloqueado={m_wa._bloqueado}")

    # 6i) WAF con contenido falso aleatorio: la reproducibilidad lo descarta
    h = modelo._boolean_based(objetivo(f"{BASE}/waf_falso", "id"))
    comprobar("WAF con contenido aleatorio: no se reporta como boolean-based",
              h == [], f"hallazgos={len(h)}")

    # 6j) inyección en cabecera (User-Agent)
    obj_h = {"url": f"{BASE}/cabecera", "method": "GET", "ubicacion": "header",
             "params": {"User-Agent": "Mozilla/5.0"}, "param": "User-Agent",
             "origen": "cabecera", "valor_base": "Mozilla/5.0"}
    h = modelo._error_based(obj_h)
    comprobar("error-based detecta inyección en cabecera (User-Agent)",
              len(h) == 1, f"hallazgos={len(h)}")

    # 6k) inyección en cuerpo JSON (API)
    obj_j = {"url": f"{BASE}/api_json", "method": "POST", "ubicacion": "json",
             "params": {"usuario": "admin"}, "param": "usuario",
             "origen": "formulario-json", "valor_base": "admin"}
    h = modelo._error_based(obj_j)
    comprobar("error-based detecta inyección en cuerpo JSON",
              len(h) == 1, f"hallazgos={len(h)}")

    # 6l) extracción de datos vía UNION (versión del motor)
    h = modelo._union_based(objetivo(f"{BASE}/union", "id"))
    comprobar("UNION-based extrae la versión del motor",
              len(h) == 1 and bool(h[0].get("datos_extraidos", {}).get("version")),
              f"datos={h[0].get('datos_extraidos') if h else '-'}")

    # 6m) descubrimiento de APIs (SPA) por análisis del JavaScript
    objs, _ = descubrir_objetivos(f"{BASE}/spa")
    combos = {(o["param"], o["method"], o.get("ubicacion")) for o in objs}
    comprobar("descubre endpoints de API desde JS (query y JSON)",
              ("id", "GET", "query") in combos and ("usuario", "POST", "json") in combos,
              f"objetivos={sorted(combos)}")

    # 6n) analizar la SPA detecta inyecciones en su API
    res = modelo.analizar(f"{BASE}/spa")
    comprobar("analyze() sobre SPA detecta inyecciones en la API",
              res["vulnerable"] and len(res["hallazgos"]) >= 2,
              f"vulnerable={res['vulnerable']} hallazgos={len(res['hallazgos'])}")

    # 6o) descubrimiento con navegador headless (si Playwright está disponible)
    from models.api_discovery import navegador_disponible, descubrir_endpoints_navegador
    if navegador_disponible():
        eps = descubrir_endpoints_navegador(f"{BASE}/spa")
        rutas = {(urlparse(e["url"]).path, e["method"]) for e in eps}
        comprobar("navegador headless captura las peticiones XHR/fetch de la SPA",
                  any(p == "/api/productos" for p, _ in rutas),
                  f"endpoints={sorted(rutas)}")
    else:
        print("  [SKIP] navegador headless no disponible (playwright install chromium)")

    # 7) error-based en formulario POST (modelo nuevo: el presupuesto es por instancia)
    m_post = SQLiModel(timeout=5)
    h = m_post._error_based(objetivo(f"{BASE}/login", "usuario", method="POST",
                                     params={"usuario": "admin"}, origen="formulario", valor_base="admin"))
    comprobar("error-based detecta formulario POST vulnerable",
              len(h) == 1 and h[0]["metodo"] == "POST",
              f"hallazgos={len(h)} metodo={h[0]['metodo'] if h else '-'}")

    # 8) descubrimiento: enlaces GET + formularios POST
    objs, info = descubrir_objetivos(f"{BASE}/")
    combos = {(o["param"], o["method"]) for o in objs}
    comprobar("descubre parámetros GET y formularios POST",
              ("id", "GET") in combos and ("usuario", "POST") in combos,
              f"objetivos={sorted(combos)}")

    # 9) extremo a extremo con analizar()
    t0 = time.time()
    res = modelo_rapido.analizar(f"{BASE}/")
    metodos = {h.get("metodo") for h in res["hallazgos"]}
    comprobar("analyze() extremo a extremo marca la página como vulnerable",
              res["vulnerable"] and len(res["hallazgos"]) >= 2 and "GET" in metodos and "POST" in metodos,
              f"vulnerable={res['vulnerable']} hallazgos={len(res['hallazgos'])} metodos={sorted(metodos)} ({time.time()-t0:.2f}s)")

    srv.shutdown()

    print("\n==== RESUMEN ====")
    fallos = [n for n, ok, _ in resultados if not ok]
    print(f"  {len(resultados) - len(fallos)}/{len(resultados)} pruebas superadas")
    for n in fallos:
        print("  FALLA:", n)
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())

"""Pruebas del escáner SQLi contra una app con base de datos SQLite REAL.

La app (`vuln_sqlite_app.py`) concatena la entrada en consultas reales, así que
los errores, el comportamiento booleano y las respuestas son auténticos (no
simulados).

Ejecutar desde la raíz:   python tests/test_sqli_real_db.py
"""

import os
import sys
import threading
import time

_AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _AQUI)
sys.path.insert(0, os.path.dirname(_AQUI))

from vuln_sqlite_app import crear_servidor                      # noqa: E402
from models.sqli_model import SQLiModel                         # noqa: E402
from models.discovery import descubrir_objetivos                # noqa: E402

resultados = []


def comprobar(nombre, condicion, detalle=""):
    resultados.append((nombre, bool(condicion), detalle))
    print(f"  [{'PASS' if condicion else 'FAIL'}] {nombre}" + (f"  {detalle}" if detalle else ""))


def objetivo(url, param, method="GET", params=None, origen="url", valor_base="1"):
    return {"url": url, "method": method, "params": params or {},
            "param": param, "origen": origen, "valor_base": valor_base}


def main():
    srv, puerto = crear_servidor()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    BASE = f"http://127.0.0.1:{puerto}"
    print(f"App SQLite real: {BASE}\n")
    modelo = SQLiModel(timeout=8, time_threshold=2.0, time_runs=1)

    # 1) error-based sobre SQLite real (error auténtico del motor)
    h = modelo._error_based(objetivo(f"{BASE}/producto", "nombre", valor_base="producto1"))
    comprobar("error-based detecta SQLite real (error del motor)",
              len(h) == 1 and "SQLite" in h[0]["motor_sugerido"],
              f"hallazgos={len(h)} motor={h[0]['motor_sugerido'] if h else '-'} payload={h[0]['payload'] if h else '-'}")

    # 2) boolean-based sobre SQLite real (1 fila vs 25 filas)
    t0 = time.time()
    h = modelo._boolean_based(objetivo(f"{BASE}/producto", "nombre", valor_base="producto1"))
    comprobar("boolean-based detecta diferencia real TRUE/FALSE",
              len(h) == 1,
              f"hallazgos={len(h)} indicadores={h[0]['indicadores'] if h else '-'} ({time.time()-t0:.2f}s)")

    # 3) error-based en formulario POST real (login)
    h = modelo._error_based(objetivo(f"{BASE}/login", "usuario", method="POST",
                                     params={"usuario": "admin", "clave": "secreto"},
                                     origen="formulario", valor_base="admin"))
    comprobar("error-based detecta formulario POST real",
              len(h) == 1 and h[0]["metodo"] == "POST",
              f"hallazgos={len(h)}")

    # 3c) extracción de datos vía UNION en SQLite real (versión del motor)
    h = modelo._union_based(objetivo(f"{BASE}/producto", "nombre", valor_base="producto1"))
    comprobar("UNION-based extrae datos en SQLite real",
              len(h) == 1 and bool((h[0].get("datos_extraidos") or {}).get("version")),
              f"datos={h[0].get('datos_extraidos') if h else '-'}")

    # 3b) time-based en SQLite real (SQLite no tiene SLEEP: CTE recursiva)
    t0 = time.time()
    h = modelo._time_based(objetivo(f"{BASE}/producto", "nombre", valor_base="producto1"))
    comprobar("time-based detecta retardo real en SQLite (CTE recursiva)",
              len(h) == 1 and "SQLite" in h[0].get("motor_sugerido", ""),
              f"hallazgos={len(h)} motor={h[0].get('motor_sugerido') if h else '-'} ({time.time()-t0:.1f}s)")

    # 4) falsos positivos: endpoint de eco (mucho HTML, poco texto, sin SQL)
    he = modelo._error_based(objetivo(f"{BASE}/eco", "q"))
    hb = modelo._boolean_based(objetivo(f"{BASE}/eco", "q"))
    comprobar("sin falso positivo en endpoint de eco",
              he == [] and hb == [],
              f"error={len(he)} boolean={len(hb)}")

    # 5) descubrimiento + extremo a extremo
    objs, _ = descubrir_objetivos(f"{BASE}/")
    combos = {(o["param"], o["method"]) for o in objs}
    res = modelo.analizar(f"{BASE}/")
    metodos = {h.get("metodo") for h in res["hallazgos"]}
    comprobar("descubre y detecta en GET y POST reales",
              ("nombre", "GET") in combos and ("usuario", "POST") in combos
              and res["vulnerable"] and "GET" in metodos and "POST" in metodos,
              f"objetivos={sorted(combos)} vulnerable={res['vulnerable']} hallazgos={len(res['hallazgos'])} metodos={sorted(metodos)}")

    srv.shutdown()

    print("\n==== RESUMEN ====")
    fallos = [n for n, ok, _ in resultados if not ok]
    print(f"  {len(resultados) - len(fallos)}/{len(resultados)} pruebas superadas")
    for n in fallos:
        print("  FALLA:", n)
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())

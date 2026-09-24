"""Escaneo SQLi contra URLs REALES de Internet (opt-in, requiere red).

IMPORTANTE
----------
Solo escanea objetivos de esta lista, que son:
  * sitios públicos VULNERABLES POR DISEÑO (para practicar), y
  * sitios benignos (para comprobar que NO hay falsos positivos).
NO lo uses contra sitios de terceros sin autorización: es ilegal.

Además usa un "modo cortés": payloads reducidos, 2 puntos por objetivo y sin
pruebas basadas en tiempo (SLEEP) contra terceros.

Ejecutar:  python tests/scan_real_targets.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models.sqli_model as sm                       # noqa: E402
from models.discovery import descubrir_objetivos     # noqa: E402

# Modo cortés: subconjunto de payloads
sm.SQLI_PAYLOADS_ERROR = ["'", '"', "1'", "' OR '1'='1", "' OR 1=1--", "1' AND 1=1--", "1;--", "') OR ('1'='1"]
sm.SQLI_PAYLOADS_BOOLEAN_TRUE = ["' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "1) OR 1=1)--", "' OR 2>1--"]
sm.SQLI_PAYLOADS_BOOLEAN_FALSE = ["' AND '1'='2", "1 AND 1=2", "' AND 1=2--", "1) AND 1=2)--", "' AND 1!=1--"]

modelo = sm.SQLiModel(timeout=10, time_runs=1)

# (url, esperado)  esperado: "vulnerable" | "limpio"
TARGETS = [
    ("https://example.com/", "limpio"),
    ("https://httpbin.org/get?x=1", "limpio"),
    ("http://demo.testfire.net/search.jsp?query=1", "vulnerable (puede estar parcheado)"),
    ("http://demo.testfire.net/login.jsp", "vulnerable (puede estar parcheado)"),
    ("http://testasp.vulnweb.com/", "vulnerable (puede estar parcheado)"),
    ("https://ginandjuice.shop/catalog/product?productId=1", "vulnerable (puede estar parcheado)"),
    ("http://zero.webappsecurity.com/search.html?searchTerm=1", "vulnerable (puede estar parcheado)"),
]

print("Escaneo de objetivos públicos (solo lectura + payloads reducidos)\n")
resumen = []

for url, esperado in TARGETS:
    print("=" * 78)
    print(f"TARGET: {url}\n  esperado: {esperado}")
    try:
        objs, info = descubrir_objetivos(url)
    except Exception as e:
        print(f"  discovery error: {type(e).__name__}: {e}")
        resumen.append((url, esperado, "sin acceso", 0))
        continue

    if not objs:
        print("  sin puntos de inyección descubiertos")
        resumen.append((url, esperado, "sin puntos", 0))
        continue

    hallazgos = 0
    t0 = time.time()
    for o in objs[:2]:
        he = modelo._error_based(o)
        hb = modelo._boolean_based(o)
        for h in he:
            hallazgos += 1
            print(f"  [ERROR]   {o['param']} [{o['method']}] payload={h['payload']!r} motor={h['motor_sugerido']} conf={h['confianza']}")
        for h in hb:
            hallazgos += 1
            print(f"  [BOOLEAN] {o['param']} [{o['method']}] conf={h['confianza']} indicadores={h['indicadores']}")
    if hallazgos == 0:
        print(f"  sin hallazgos ({time.time()-t0:.1f}s) -> OK si el objetivo está parcheado/limpio")
    resumen.append((url, esperado, "escaneado", hallazgos))

print("\n" + "=" * 78)
print("RESUMEN")
for url, esperado, estado, n in resumen:
    print(f"  {n:>2} hallazgo(s) | {estado:<10} | {url}")

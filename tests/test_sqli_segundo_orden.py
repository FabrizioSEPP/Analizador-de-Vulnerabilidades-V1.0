"""Prueba del detector heurístico de SQLi de SEGUNDO ORDEN.

- SQLite real: un comentario se guarda y luego se usa SIN parametrizar en
  /listar => la inyección almacenada dispara un error en otra página.
- Servidor simulado sin almacenamiento => no debe dar falso positivo.

Ejecutar desde la raíz:   python tests/test_sqli_segundo_orden.py
"""

import os
import sys
import threading

_AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _AQUI)
sys.path.insert(0, os.path.dirname(_AQUI))

from vuln_sqlite_app import crear_servidor as crear_real      # noqa: E402
from vuln_app import crear_servidor as crear_simulado         # noqa: E402
from models.sqli_model import SQLiModel                       # noqa: E402

resultados = []


def comprobar(nombre, condicion, detalle=""):
    resultados.append((nombre, bool(condicion), detalle))
    print(f"  [{'PASS' if condicion else 'FAIL'}] {nombre}" + (f"  {detalle}" if detalle else ""))


def main():
    # 1) SQLite real (vulnerable a segundo orden)
    srv, puerto = crear_real()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    BASE = f"http://127.0.0.1:{puerto}"
    print(f"App SQLite real (2º orden): {BASE}\n")

    modelo = SQLiModel(timeout=8, time_runs=1)
    res = modelo.analizar_segundo_orden(f"{BASE}/")
    h = res["hallazgos"][0] if res["hallazgos"] else {}
    comprobar("segundo orden: detecta inyección almacenada (SQLite real)",
              res["vulnerable"] and h.get("tipo") == "second-order",
              f"tipo={h.get('tipo')} disparo={h.get('pagina_disparo')} payload={h.get('payload')!r}")

    # 2) Integración dentro de analizar()
    res2 = SQLiModel(timeout=8, time_runs=1, max_objetivos=3, segundo_orden=True,
                     max_peticiones=20000).analizar(f"{BASE}/")
    tipos = {x["tipo"] for x in res2["hallazgos"]}
    comprobar("segundo orden integrado en analizar()",
              "second-order" in tipos,
              f"tipos={sorted(tipos)}")
    srv.shutdown()

    # 3) Servidor simulado sin almacenamiento => sin falso positivo
    srv2, puerto2 = crear_simulado()
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    BASE2 = f"http://127.0.0.1:{puerto2}"
    print(f"\nServidor simulado (sin almacenamiento): {BASE2}\n")
    res3 = SQLiModel(timeout=6, time_runs=1).analizar_segundo_orden(f"{BASE2}/")
    comprobar("segundo orden: sin falso positivo cuando no hay almacenamiento",
              res3["vulnerable"] is False, f"vulnerable={res3['vulnerable']}")
    srv2.shutdown()

    print("\n==== RESUMEN ====")
    fallos = [n for n, ok, _ in resultados if not ok]
    print(f"  {len(resultados) - len(fallos)}/{len(resultados)} pruebas superadas")
    for n in fallos:
        print("  FALLA:", n)
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())

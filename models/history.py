"""Persistencia del historial de análisis en Supabase.

Traduce el resultado de cada módulo a las columnas de `scans` /
`scan_findings`. Si Supabase no está configurado, no hace nada (la app sigue
funcionando de forma efímera).
"""

from models import db


def guardar(modulo: str, url: str, resultado: dict, username: str):
    if not username or not db.esta_configurado():
        return None

    try:
        score = nivel = None
        detalle = resultado.get("detalle", "")
        hallazgos: list = []
        resumen: dict = {}

        if modulo == "sqli":
            from models.metrics import calcular_metricas_sqli
            m = calcular_metricas_sqli(resultado)
            score, nivel = m["cvss_promedio"], m["riesgo_global"]
            hallazgos = m["hallazgos_con_cvss"]
            resumen = {
                "vulnerable": resultado.get("vulnerable"),
                "puntos": len(resultado.get("objetivos", [])),
                "confianza_promedio": m["confianza_promedio"],
            }

        elif modulo == "load":
            from models.metrics import calcular_metricas_load
            m = calcular_metricas_load(resultado)
            score, nivel = m["grado_pgi"], m["salud_global"]
            resumen = {
                "capacidad": m["capacidad"],
                "tasa_error_max": m["tasa_error_max"],
                "p95_max": m["p95_max"],
            }
            hallazgos = []

        elif modulo == "audit":
            from models.risk_score import security_score, classification
            hallazgos = resultado.get("hallazgos", [])
            score = security_score(hallazgos)
            nivel = classification(score)
            resumen = {
                "score_maximo": resultado.get("score_maximo"),
                "tecnologias": (resultado.get("deep_analysis") or {}).get("tecnologias", []),
                "paginas": (resultado.get("deep_analysis") or {}).get("total_paginas"),
            }

        elif modulo == "port":
            puertos = resultado.get("puertos", [])
            hallazgos = [{
                "tipo": "puerto_abierto",
                "descripcion": f"Puerto {p.get('puerto')} abierto ({p.get('servicio', 'desconocido')})",
                "severidad": "info",
                "metodo": p.get("protocolo"),
                "evidencia": f"{resultado.get('ip', '')}:{p.get('puerto')}",
            } for p in puertos]
            resumen = {"host": resultado.get("host"), "ip": resultado.get("ip")}

        total = len(hallazgos)
        return db.guardar_scan(
            username=username, modulo=modulo, url=url,
            score=score, nivel=nivel, total_hallazgos=total,
            detalle=detalle, resumen=resumen, hallazgos=hallazgos,
        )
    except Exception:
        # Nunca debe romper el análisis si falla la persistencia.
        return None


def recientes(username: str, limite: int = 10) -> list:
    return db.listar_scans(username, limite)


def detalle(scan_id: str) -> list:
    return db.obtener_hallazgos(scan_id)

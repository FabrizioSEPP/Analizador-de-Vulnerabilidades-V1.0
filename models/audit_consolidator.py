from datetime import datetime
from models.deep_analysis import analizar_profundamente


SEVERIDAD_PONDERADA = {"critica": 95, "alta": 75, "media": 55, "baja": 25, "info": 10}

OWASP_MAP = {
    "A01": "Broken Access Control", "A02": "Configuracion de Seguridad Incorrecta",
    "A03": "Inyeccion", "A04": "Diseño Inseguro", "A05": "Vulnerabilidades Desactualizadas",
    "A06": "Fallas de Integridad", "A07": "Fallas de Autenticacion",
    "A08": "Fallos de Seguridad de Datos", "A09": "Fallas en Registro y Monitoreo",
    "A10": "SSRF",
}


def _normalizar_severidad(sev: str) -> str:
    if isinstance(sev, str):
        s = sev.strip().lower()
        aliases = {
            "critica": "critica", "critico": "critica", "crítico": "critica", "crítica": "critica",
            "alta": "alta", "alto": "alta",
            "media": "media", "medio": "media",
            "baja": "baja", "bajo": "baja",
            "info": "info", "informativa": "info",
        }
        return aliases.get(s, s)
    return "media"


def _clasificar_severidad(hallazgo: dict, owasp: str) -> str:
    if "severidad" in hallazgo and isinstance(hallazgo.get("severidad"), str):
        sev = _normalizar_severidad(hallazgo["severidad"])
        if sev in ("critica", "alta", "media", "baja", "info"):
            return sev
    score = hallazgo.get("score_riesgo", hallazgo.get("severidad_score", 50))
    if isinstance(score, str):
        score = float(score) if score.replace(".", "", 1).isdigit() else 50
    if score >= 85: return "critica"
    elif score >= 65: return "alta"
    elif score >= 40: return "media"
    else: return "baja"


def _mapear_owasp(modulo: str, hallazgo: dict) -> str:
    mapping = {
        "error-based": "A03", "boolean": "A03", "time-based": "A03", "sqli": "A03",
        "inyeccion": "A03", "sql_injection": "A03",
        "profundo": "A02", "analisis": "A02", "deep": "A02",
        "phishing": "A07", "ddos": "A04", "saturacion": "A04",
        "ssl": "A02", "tls": "A02", "certificado": "A02",
        "cabecera": "A02", "header": "A02", "configuracion": "A02",
        "cookie": "A08", "cors": "A01", "iframe": "A01",
        "puertos": "A02", "ips": "A02",
    }
    for clave in mapping:
        if clave in modulo.lower():
            return mapping[clave]
    return "A02"


def consolidar_auditoria(resultados: dict, deep_result: dict | None = None) -> dict:
    hallazgos_consolidados = []
    modulo_nombre = resultados.get("modulo", "unknown")
    error_list = resultados.get("errores", resultados.get("hallazgos", []))

    for e in error_list:
        if isinstance(e, dict):
            owasp_propio = e.get("owasp")
            owasp = owasp_propio if owasp_propio else _mapear_owasp(modulo_nombre, e)
            severidad = _clasificar_severidad(e, owasp)
            score = e.get("score_riesgo", e.get("severidad_score", SEVERIDAD_PONDERADA.get(severidad, 50)))
            hallazgos_consolidados.append({
                "modulo": modulo_nombre,
                "descripcion": e.get("descripcion", e.get("tipo", "Hallazgo")),
                "evidencia": e.get("detalle", e.get("evidencia", "")),
                "severidad": severidad,
                "score": round(score, 1) if isinstance(score, (int, float)) else SEVERIDAD_PONDERADA.get(severidad, 50),
                "owasp": owasp,
                "owasp_nombre": OWASP_MAP.get(owasp, "Desconocido"),
                "explicacion": e.get("explicacion", e.get("detalle", "")),
                "remediacion": e.get("remediacion", e.get("explicacion", "")),
                "tipo": e.get("tipo", modulo_nombre),
            })

    if deep_result is None:
        deep_result = analizar_profundamente(resultados.get("url", "")) if resultados.get("url") else None
    if deep_result:
        for e in deep_result.get("errores", []):
            owasp = e.get("owasp", "A02")
            severidad = _clasificar_severidad(e, owasp)
            score = SEVERIDAD_PONDERADA.get(severidad, 50)
            hallazgos_consolidados.append({
                "modulo": "analisis_profundo",
                "descripcion": e.get("descripcion", ""),
                "evidencia": e.get("detalle", ""),
                "severidad": severidad, "score": score,
                "owasp": owasp, "owasp_nombre": OWASP_MAP.get(owasp, "Desconocido"),
                "explicacion": e.get("explicacion", ""), "remediacion": e.get("remediacion", ""),
                "tipo": e.get("tipo", ""),
            })

    scores = [h["score"] for h in hallazgos_consolidados]
    return {
        "url": resultados.get("url", ""),
        "fecha": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "total_hallazgos": len(hallazgos_consolidados),
        "score_promedio": round(sum(scores) / len(scores), 1) if scores else 0,
        "score_maximo": max(scores) if scores else 0,
        "resumen_por_severidad": {
            "critica": sum(1 for h in hallazgos_consolidados if h["severidad"] == "critica"),
            "alta": sum(1 for h in hallazgos_consolidados if h["severidad"] == "alta"),
            "media": sum(1 for h in hallazgos_consolidados if h["severidad"] == "media"),
            "baja": sum(1 for h in hallazgos_consolidados if h["severidad"] == "baja"),
        },
        "hallazgos": hallazgos_consolidados,
        "deep_analysis": deep_result,
    }

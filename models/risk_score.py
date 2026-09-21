import unicodedata

SEVERITY_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]
SEVERITY_PENALTY = {"CRÍTICO": 30, "ALTO": 20, "MEDIO": 10, "BAJO": 5, "INFO": 0}
SEVERITY_WEIGHT = {"CRÍTICO": 10, "ALTO": 8, "MEDIO": 5, "BAJO": 2, "INFO": 0}

# Aliases en cualquier combinación de mayúsculas/acentos que usan los modelos
# ("critica", "Crítica", "CRÍTICO", "high", ...) unificados a las claves canónicas.
_SEVERITY_ALIASES = {
    "critico": "CRÍTICO", "critica": "CRÍTICO", "critical": "CRÍTICO", "crit": "CRÍTICO",
    "alto": "ALTO", "alta": "ALTO", "high": "ALTO",
    "medio": "MEDIO", "media": "MEDIO", "medium": "MEDIO",
    "bajo": "BAJO", "baja": "BAJO", "low": "BAJO",
    "info": "INFO", "informativa": "INFO", "informational": "INFO",
}


def normalize_severity(sev) -> str:
    """Devuelve una de las claves canónicas de SEVERITY_ORDER."""
    if sev is None:
        return "INFO"
    texto = str(sev).strip().lower()
    texto = "".join(
        c for c in unicodedata.normalize("NFKD", texto) if not unicodedata.combining(c)
    )
    return _SEVERITY_ALIASES.get(texto, "INFO")


def security_score(hallazgos: list) -> int:
    if not hallazgos:
        return 100
    total_penalty = 0
    for h in hallazgos:
        sev = normalize_severity(h.get("nivel_riesgo", h.get("severidad", "INFO")))
        penalty = SEVERITY_PENALTY.get(sev, 0)
        weight = SEVERITY_WEIGHT.get(sev, 0)
        cvss = h.get("cvss", 0)
        if isinstance(cvss, (int, float)) and cvss > 0:
            impact = (cvss / 10) * 100
            total_penalty += max(penalty, weight, min(impact, penalty + weight))
        else:
            total_penalty += max(penalty, weight)
    score = max(0, min(100, round(100 - total_penalty)))
    return score


def classification(score: int) -> str:
    if score >= 90: return "EXCELENTE"
    if score >= 75: return "BUENA"
    if score >= 55: return "ATENCIÓN"
    if score >= 35: return "RIESGO"
    return "CRÍTICA"


def exposure_level(score: int) -> str:
    if score >= 90: return "BAJO"
    if score >= 75: return "MODERADO"
    if score >= 55: return "ELEVADO"
    return "ALTO"


def count_by_severity(hallazgos: list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for h in hallazgos:
        sev = normalize_severity(h.get("nivel_riesgo", h.get("severidad", "INFO")))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def to_summary(hallazgos: list) -> dict:
    score = security_score(hallazgos)
    counts = count_by_severity(hallazgos)
    return {
        "security_score": score,
        "classification": classification(score),
        "exposure": exposure_level(score),
        "controls_evaluated": {"total": len(hallazgos), "passed": len(hallazgos) - counts["CRÍTICO"] - counts["ALTO"], "failed": counts["CRÍTICO"] + counts["ALTO"], "na": 0},
        "critical": counts["CRÍTICO"], "high": counts["ALTO"],
        "medium": counts["MEDIO"], "low": counts["BAJO"], "info": counts["INFO"],
    }

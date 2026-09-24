import math

SEVERITY_COLORS = {"Crítica": "#d32f2f", "Alta": "#f57c00", "Media": "#fbc02d", "Baja": "#388e3c", "Info": "#1976d2"}

# Vectores CVSS v3.1 base por técnica de inyección SQL. La confianza del
# hallazgo se reporta por separado y no forma parte del estándar CVSS.
_DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_VECTORS = {
    "error-based": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "boolean-based blind": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "time-based blind": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "union-based": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss_base_from_vector(vector: str) -> float:
    """Base Score oficial de CVSS v3.1 calculado a partir del vector."""
    metricas = {}
    for parte in vector.split("/")[1:]:
        if ":" in parte:
            clave, valor = parte.split(":", 1)
            metricas[clave] = valor
    try:
        scope_cambiado = metricas.get("S") == "C"
        iss = 1 - (
            (1 - _CIA[metricas["C"]])
            * (1 - _CIA[metricas["I"]])
            * (1 - _CIA[metricas["A"]])
        )
        if scope_cambiado:
            impacto = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impacto = 6.42 * iss
        pr = (_PR_C if scope_cambiado else _PR_U)[metricas["PR"]]
        explotabilidad = 8.22 * _AV[metricas["AV"]] * _AC[metricas["AC"]] * pr * _UI[metricas["UI"]]
        if impacto <= 0:
            return 0.0
        if scope_cambiado:
            base = min(1.08 * (impacto + explotabilidad), 10.0)
        else:
            base = min(impacto + explotabilidad, 10.0)
        return math.ceil(base * 10) / 10
    except (KeyError, TypeError):
        return 0.0


def cvss_score(hallazgo: dict) -> float:
    vector = CVSS_VECTORS.get(hallazgo.get("tipo", ""), _DEFAULT_VECTOR)
    return cvss_base_from_vector(vector)


def nivel_riesgo(cvss: float) -> str:
    if cvss >= 8.0:
        return "Crítica"
    elif cvss >= 6.0:
        return "Alta"
    elif cvss >= 3.0:
        return "Media"
    elif cvss > 0:
        return "Baja"
    return "Info"


def recomendacion(hallazgo: dict, cvss: float) -> str:
    tipo = hallazgo.get("tipo", "")
    parametro = hallazgo.get("parametro", "")
    severidad = nivel_riesgo(cvss)
    if cvss >= 8.0:
        return (
            f"🚨 [CRÍTICO] El parámetro '{parametro}' presenta inyección SQL {severidad.lower()} "
            f"({cvss}/10). Aplicar parche inmediato: usar consultas parametrizadas "
            f"(prepared statements), validar entradas con whitelist, y desplegar WAF. "
            f"No aplique correcciones temporales sin análisis profundo."
        )
    elif cvss >= 6.0:
        return (
            f"⚠️ [ALTA] Inyección SQL {severidad.lower()} en '{parametro}' (CVSS {cvss}/10). "
            f"Priorizar en el ciclo de parches actual: migra a queries parametrizadas, "
            f"aplica escape de entradas y monitorea logs de acceso."
        )
    elif cvss >= 3.0:
        return (
            f"📋 [MEDIA] Indicio de inyección SQL en '{parametro}' (CVSS {cvss}/10). "
            f"Validar con pruebas manuales y aplicar validación de entradas. "
            f"Planificar corrección en la siguiente sprint."
        )
    else:
        return (
            f"ℹ️ [BAJA] Hallazgo menor en '{parametro}' (CVSS {cvss}/10). "
            f"Documentar y revisar en revisión de seguridad periódica."
        )


def cvss_vector(tipo: str, confianza: float = 0) -> str:
    return CVSS_VECTORS.get(tipo, _DEFAULT_VECTOR)


def calcular_metricas_sqli(resultado: dict) -> dict:
    hallazgos = resultado.get("hallazgos", [])
    if not hallazgos:
        return {
            "cvss_promedio": 0.0, "riesgo_global": "Sin hallazgos", "total_hallazgos": 0,
            "por_tipo": {}, "por_severidad": {}, "por_parametro": {},
            "confianza_promedio": 0.0, "cobertura_vectores": 0.0,
            "recomendaciones": [], "hallazgos_con_cvss": [],
        }

    cvss_list = []
    hallazgos_con_cvss = []
    por_tipo = {}
    por_severidad = {}
    por_parametro = {}
    tipos_probados = set()
    severidades_encontradas = set()

    for h in hallazgos:
        cvss = cvss_score(h)
        nivel = nivel_riesgo(cvss)
        rec = recomendacion(h, cvss)
        expl = h.get("explicacion", "")
        if not expl:
            expl = _generar_explicacion_basica(h, cvss)

        h_cvss = dict(h)
        h_cvss["cvss"] = cvss
        h_cvss["nivel_riesgo"] = nivel
        h_cvss["vector_cvss"] = cvss_vector(h.get("tipo", ""), h.get("confianza", 0))
        h_cvss["recomendacion"] = rec
        h_cvss["explicacion"] = expl
        hallazgos_con_cvss.append(h_cvss)

        cvss_list.append(cvss)
        tipo = h.get("tipo", "unknown")
        por_tipo[tipo] = por_tipo.get(tipo, 0) + 1
        tipos_probados.add(tipo)
        sev = nivel
        por_severidad[sev] = por_severidad.get(sev, 0) + 1
        severidades_encontradas.add(sev)
        param = h.get("parametro", "unknown")
        por_parametro[param] = por_parametro.get(param, 0) + 1

    cvss_promedio = round(sum(cvss_list) / len(cvss_list), 2) if cvss_list else 0.0
    confianza_promedio = round(sum(h.get("confianza", 0) for h in hallazgos) / len(hallazgos), 1)
    total_vectores = 4
    cobertura = (len(tipos_probados) / total_vectores) * 100
    riesgo_global = "Crítica" if cvss_promedio >= 8.0 else "Alta" if cvss_promedio >= 6.0 else "Media" if cvss_promedio >= 3.0 else "Baja"

    recomendaciones = []
    for h in hallazgos:
        cvss_val = cvss_score(h)
        rec = recomendacion(h, cvss_val)
        already = any(rec[:40] in r for r in recomendaciones)
        if not already:
            recomendaciones.append(rec)

    return {
        "cvss_promedio": cvss_promedio, "riesgo_global": riesgo_global,
        "total_hallazgos": len(hallazgos), "por_tipo": por_tipo, "por_severidad": por_severidad,
        "por_parametro": por_parametro, "confianza_promedio": confianza_promedio,
        "cobertura_vectores": cobertura, "recomendaciones": recomendaciones,
        "hallazgos_con_cvss": hallazgos_con_cvss,
    }


def _generar_explicacion_basica(hallazgo: dict, cvss: float) -> str:
    tipo = hallazgo.get("tipo", "")
    param = hallazgo.get("parametro", "")
    nivel = nivel_riesgo(cvss)
    return (
        f"El parámetro '{param}' presenta una posible inyección SQL ({tipo}) "
        f"con nivel de riesgo {nivel} (CVSS {cvss}/10). "
        f"Se recomienda aplicar consultas parametrizadas y validación de entradas."
    )


def calcular_metricas_load(resultado: dict) -> dict:
    niveles = resultado.get("niveles", [])
    if not niveles:
        return {
            "capacidad": 0, "salud_global": "Sin datos", "latencia_base": 0,
            "tasa_error_max": 0, "p95_max": 0, "grado_pgi": 0,
            "por_tipo_error": {}, "volatilidad_max": 0, "recomendaciones": [],
        }

    capacidad = resultado.get("capacidad_estimada", 0)
    latencia_base = resultado.get("latencia_base", 0)
    tasa_error_max = max(n.get("tasa_error", 0) for n in niveles)
    p95_max = max(n.get("latencia_p95", 0) for n in niveles)

    volatilidad_max = max(
        (abs(n.get("latencia_promedio", 0) - n.get("latencia_base", 0.001)) / max(n.get("latencia_base", 0.001), 0.0001))
        for n in niveles
    )

    tipo_error_total = {}
    for n in niveles:
        for key in ["errores_timeout", "errores_conexion", "errores_4xx", "errores_5xx", "errores_otros"]:
            val = n.get(key, 0)
            if val > 0:
                label = key.replace("errores_", "")
                tipo_error_total[label] = tipo_error_total.get(label, 0) + val

    pgi = 100.0
    if tasa_error_max > 10:
        pgi -= (tasa_error_max - 10) * 5
    if p95_max > latencia_base * 2:
        if latencia_base > 0:
            pgi -= min(30, (p95_max - latencia_base * 2) / latencia_base * 20)
        else:
            pgi -= 30
    if volatilidad_max > 1.0:
        pgi -= min(20, (volatilidad_max - 1.0) * 20)
    pgi = max(0, min(100, round(pgi, 1)))

    salud = "Excelente" if pgi >= 90 else "Buena" if pgi >= 75 else "Degradada" if pgi >= 50 else "Crítica"

    recomendaciones = []
    if pgi >= 90:
        recomendaciones.append("✅ Rendimiento óptimo. Mantener monitoreo continuo y planificar escalado proactivo.")
    elif pgi >= 75:
        recomendaciones.append("⚠️ Rendimiento aceptable. Considerar optimización de queries y añadir caching.")
    elif pgi >= 50:
        recomendaciones.append("🔶 Degradación detectada. Implementar rate limiting, balanceo de carga y optimización de DB.")
    else:
        recomendaciones.append("🚨 Rendimiento crítico. Escalar infraestructura inmediatamente, revisar queries lentas y caché.")

    if tipo_error_total.get("timeout", 0) > 0:
        recomendaciones.append(f"⏱️ {tipo_error_total['timeout']} timeouts detectados. Revisar timeouts del servidor y slow queries.")
    if tipo_error_total.get("5xx", 0) > 0:
        recomendaciones.append(f"🔴 {tipo_error_total['5xx']} errores 5xx. Investigar errores del servidor.")
    if tipo_error_total.get("connection", 0) > 0:
        recomendaciones.append(f"🔌 {tipo_error_total['connection']} errores de conexión. Verificar límites del servidor.")

    return {
        "capacidad": capacidad, "salud_global": salud, "latencia_base": latencia_base,
        "tasa_error_max": tasa_error_max, "p95_max": p95_max, "grado_pgi": pgi,
        "por_tipo_error": tipo_error_total, "volatilidad_max": volatilidad_max,
        "recomendaciones": recomendaciones,
    }

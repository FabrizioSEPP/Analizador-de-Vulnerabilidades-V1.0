"""Informe ejecutivo de seguridad a partir del historial de análisis.

El módulo concentra tres responsabilidades:

1. `construir_informe`: agrega los scans y sus hallazgos en una estructura
   pensada para gerencia (KPIs, riesgo, plan de acción y anexos).
2. `informe_markdown`: exportación editable del mismo informe.
3. `informe_pdf`: versión imprimible con portada, tablas y pie de página.

No depende de Streamlit salvo por `models.i18n`; así puede probarse y
reutilizarse desde otros puntos de la aplicación.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape as _xml

from models.i18n import es_o_en, t
from models.risk_score import SEVERITY_ORDER, classification, normalize_severity

# --------------------------------------------------------------------- catálogos
_SEV_COLOR = {
    "CRÍTICO": "#DC2626",
    "ALTO": "#EA580C",
    "MEDIO": "#D97706",
    "BAJO": "#0284C7",
    "INFO": "#64748B",
}

_SEV_EN = {
    "CRÍTICO": "Critical", "ALTO": "High", "MEDIO": "Medium",
    "BAJO": "Low", "INFO": "Info",
}

_CLASIF_EN = {
    "EXCELENTE": "Excellent", "BUENA": "Good", "ATENCIÓN": "Needs attention",
    "RIESGO": "Risk", "CRÍTICA": "Critical",
}

_CLASIF_TEXTO = {
    "EXCELENTE": (
        "una postura sólida, con controles razonablemente maduros",
        "a solid posture with reasonably mature controls",
    ),
    "BUENA": (
        "una postura aceptable, con mejoras puntuales pendientes",
        "an acceptable posture with minor improvements pending",
    ),
    "ATENCIÓN": (
        "una postura que requiere atención y un plan de remediación activo",
        "a posture that needs attention and an active remediation plan",
    ),
    "RIESGO": (
        "un nivel de riesgo elevado que exige acciones a corto plazo",
        "a high risk level that requires short-term action",
    ),
    "CRÍTICA": (
        "un nivel de riesgo crítico que requiere contención inmediata",
        "a critical risk level that requires immediate containment",
    ),
}

_MODULOS = {
    "sqli": (
        "Inyección SQL", "SQL Injection",
        "Pruebas de inyección SQL sobre parámetros, formularios y APIs.",
        "SQL injection testing on parameters, forms and APIs.",
    ),
    "audit": (
        "Auditoría web", "Web audit",
        "Revisión de configuraciones, cabeceras y superficie expuesta.",
        "Review of configurations, headers and exposed surface.",
    ),
    "load": (
        "Prueba de carga", "Load test",
        "Evaluación de estabilidad y rendimiento bajo concurrencia.",
        "Stability and performance evaluation under concurrency.",
    ),
    "port": (
        "Escaneo de puertos", "Port scan",
        "Identificación de servicios expuestos y su nivel de riesgo.",
        "Identification of exposed services and risk level.",
    ),
}

_MODULOS_DESC = {
    clave: (desc_es, desc_en) for clave, (_es, _en, desc_es, desc_en) in _MODULOS.items()
}


def _e(es: str, en: str) -> str:
    return es_o_en(es, en)


def _texto(valor, defecto: str = "") -> str:
    if valor is None:
        return defecto
    texto = str(valor).strip()
    return texto or defecto


def _numero(valor) -> float | None:
    try:
        numero = float(valor)
    except (TypeError, ValueError):
        return None
    return numero if numero == numero else None  # descarta NaN


def _fecha(valor) -> str:
    return _texto(valor, "—").replace("T", " ")[:16]


def _fmt_numero(valor: float | None, decimales: int = 1) -> str:
    if valor is None:
        return "—"
    numero = round(valor, decimales)
    return str(int(numero)) if numero == int(numero) else f"{numero:.{decimales}f}"


def _etiqueta_sev(sev: str) -> str:
    return _e(sev.capitalize(), _SEV_EN.get(sev, sev))


def _etiqueta_clasif(clasif: str) -> str:
    if clasif in ("SIN DATOS", "NO DATA"):
        return _e("Sin datos", "No data")
    return _e(clasif.capitalize(), _CLASIF_EN.get(clasif, clasif.capitalize()))


def etiqueta_clasificacion(clasif: str) -> str:
    """Versión pública para la vista del informe."""
    return _etiqueta_clasif(clasif)


def etiqueta_severidad(severidad: str) -> str:
    """Nombre visible de una severidad canónica (CRÍTICO -> Crítico/Critical)."""
    return _etiqueta_sev(severidad)


def etiqueta_modulo(clave: str) -> str:
    """Nombre visible de un módulo del historial."""
    return _etiqueta_modulo(clave)


def _etiqueta_modulo(clave: str) -> str:
    datos = _MODULOS.get(clave)
    return _e(datos[0], datos[1]) if datos else _texto(clave, _e("Otro", "Other"))


def _descripcion_modulo(clave: str) -> str:
    datos = _MODULOS_DESC.get(clave)
    return _e(datos[0], datos[1]) if datos else ""


# ------------------------------------------------------------------- agregación
def construir_informe(registros: list, obtener_detalle=None) -> dict:
    """Agrega el historial en un informe ejecutivo listo para renderizar.

    `obtener_detalle` permite inyectar la fuente de hallazgos (por defecto
    `history.detalle`) y facilita las pruebas sin base de datos.
    """
    registros = [r for r in (registros or []) if isinstance(r, dict)]
    if obtener_detalle is None:
        from models import history
        obtener_detalle = history.detalle

    analisis: list[dict] = []
    hallazgos: list[dict] = []

    for registro in registros:
        scan_id = registro.get("id")
        detalles = []
        if scan_id is not None:
            try:
                detalles = [h for h in (obtener_detalle(scan_id) or []) if isinstance(h, dict)]
            except Exception:
                detalles = []

        objetivo = _texto(registro.get("url"), _e("Objetivo sin URL", "Target without URL"))
        modulo = _texto(registro.get("modulo"), "otro")
        for hallazgo in detalles:
            severidad = normalize_severity(
                hallazgo.get("nivel_riesgo") or hallazgo.get("severidad")
            )
            hallazgos.append({
                "objetivo": objetivo,
                "modulo": modulo,
                "hallazgo": t(_texto(
                    hallazgo.get("descripcion") or hallazgo.get("tipo") or hallazgo.get("nombre"),
                    _e("Hallazgo sin descripción", "Unnamed finding"),
                )),
                "severidad": severidad,
                "owasp": _texto(hallazgo.get("owasp"), "—"),
                "cvss": _numero(hallazgo.get("cvss")),
                "remediacion": t(_texto(
                    hallazgo.get("remediacion") or hallazgo.get("recomendacion")
                )),
                "evidencia": _texto(hallazgo.get("evidencia")),
                "tipo": _texto(hallazgo.get("tipo")),
            })

        analisis.append({
            "id": scan_id,
            "fecha": _texto(registro.get("created_at")),
            "modulo": modulo,
            "objetivo": objetivo,
            "hallazgos": int(registro.get("total_hallazgos") or 0),
            "nivel": _texto(registro.get("nivel")),
            "score": _numero(registro.get("score")),
        })

    # Agrupa hallazgos repetidos (mismo objetivo, severidad, texto y control)
    # para que la tabla ejecutiva sea legible sin perder el detalle técnico.
    grupos: "OrderedDict[tuple, dict]" = OrderedDict()
    for hallazgo in hallazgos:
        clave = (
            hallazgo["objetivo"], hallazgo["severidad"],
            hallazgo["hallazgo"], hallazgo["owasp"],
        )
        grupo = grupos.get(clave)
        if grupo is None:
            grupo = dict(hallazgo)
            grupo["veces"] = 0
            grupos[clave] = grupo
        grupo["veces"] += 1
        if hallazgo["cvss"] is not None:
            grupo["cvss"] = max(grupo["cvss"] or 0, hallazgo["cvss"])
        if not grupo["remediacion"]:
            grupo["remediacion"] = hallazgo["remediacion"]
        if not grupo["evidencia"]:
            grupo["evidencia"] = hallazgo["evidencia"]

    agregados = sorted(
        grupos.values(),
        key=lambda h: (
            SEVERITY_ORDER.index(h["severidad"]) if h["severidad"] in SEVERITY_ORDER else 99,
            -(h["cvss"] or 0),
            -h["veces"],
            h["objetivo"],
        ),
    )

    conteo = {sev: 0 for sev in SEVERITY_ORDER}
    for hallazgo in hallazgos:
        conteo[hallazgo["severidad"]] = conteo.get(hallazgo["severidad"], 0) + 1

    total_registrado = sum(item["hallazgos"] for item in analisis)
    total_hallazgos = max(total_registrado, len(hallazgos))
    sin_detalle = max(0, total_registrado - len(hallazgos))

    puntuaciones = [item["score"] for item in analisis if item["score"] is not None]
    score = round(sum(puntuaciones) / len(puntuaciones)) if puntuaciones else None
    clasif = classification(score) if score is not None else _e("SIN DATOS", "NO DATA")

    fechas = sorted(item["fecha"] for item in analisis if item["fecha"])
    periodo = (fechas[0][:10], fechas[-1][:10]) if fechas else ("—", "—")

    # Activos: el primero de cada URL es el análisis más reciente (el historial
    # llega ordenado de más nuevo a más viejo).
    objetivos: "OrderedDict[str, dict]" = OrderedDict()
    for item in analisis:
        url = item["objetivo"]
        activo = objetivos.get(url)
        if activo is None:
            activo = {
                "objetivo": url,
                "ultimo": item["fecha"],
                "modulo": item["modulo"],
                "hallazgos": 0,
                "nivel": item["nivel"],
                "score": item["score"],
            }
            objetivos[url] = activo
        activo["hallazgos"] += item["hallazgos"]
        if not activo["nivel"]:
            activo["nivel"] = item["nivel"]
        if activo["score"] is None:
            activo["score"] = item["score"]

    modulos = Counter(item["modulo"] for item in analisis)
    peor_severidad = next((sev for sev in SEVERITY_ORDER if conteo.get(sev)), None)

    informe = {
        "generado": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "periodo": periodo,
        "analisis": analisis,
        "objetivos": list(objetivos.values()),
        "hallazgos": agregados,
        "conteo": conteo,
        "total_hallazgos": total_hallazgos,
        "detalle_total": len(hallazgos),
        "sin_detalle": sin_detalle,
        "score": score,
        "clasificacion": clasif,
        "peor_severidad": peor_severidad,
        "modulos": [
            {
                "clave": clave,
                "cantidad": cantidad,
                "descripcion": _descripcion_modulo(clave),
            }
            for clave, cantidad in modulos.most_common()
        ],
    }
    informe["resumen"] = _resumen_ejecutivo(informe)
    informe["recomendacion"] = _recomendacion_ejecutiva(informe)
    informe["plan"] = _plan_accion(informe)
    return informe


def _resumen_ejecutivo(informe: dict) -> str:
    desde, hasta = informe["periodo"]
    analisis = len(informe["analisis"])
    objetivos = len(informe["objetivos"])
    conteo = informe["conteo"]
    total = informe["total_hallazgos"]

    if desde == "—" and hasta == "—":
        periodo = _e("durante el periodo analizado", "during the analyzed period")
    elif desde == hasta:
        periodo = _e(f"durante el {desde}", f"during {desde}")
    else:
        periodo = _e(f"durante el periodo {desde} — {hasta}", f"during the period {desde} — {hasta}")

    if informe["score"] is not None:
        score = informe["score"]
        clasif = informe["clasificacion"]
        interpretacion = _e(*_CLASIF_TEXTO.get(clasif, ("", "")))
        texto_score = _e(
            f" La puntuación media de seguridad es {score}/100 ({_etiqueta_clasif(clasif)}), "
            f"lo que indica {interpretacion}.",
            f" The average security score is {score}/100 ({_etiqueta_clasif(clasif)}), "
            f"which indicates {interpretacion}.",
        )
    else:
        texto_score = _e(
            " No hay puntuaciones de seguridad registradas para este periodo.",
            " No security scores were recorded for this period.",
        )

    texto = _e(
        f"{periodo.capitalize()} se analizaron {objetivos} objetivo(s) mediante {analisis} "
        f"análisis de seguridad. Se registraron {total} hallazgo(s): "
        f"{conteo.get('CRÍTICO', 0)} crítico(s), {conteo.get('ALTO', 0)} alto(s), "
        f"{conteo.get('MEDIO', 0)} medio(s), {conteo.get('BAJO', 0)} bajo(s) y "
        f"{conteo.get('INFO', 0)} informativo(s).",
        f"{periodo.capitalize()}, {objetivos} target(s) were analyzed through {analisis} "
        f"security assessments. A total of {total} finding(s) were recorded: "
        f"{conteo.get('CRÍTICO', 0)} critical, {conteo.get('ALTO', 0)} high, "
        f"{conteo.get('MEDIO', 0)} medium, {conteo.get('BAJO', 0)} low and "
        f"{conteo.get('INFO', 0)} informational.",
    )
    return texto + texto_score


def _recomendacion_ejecutiva(informe: dict) -> str:
    conteo = informe["conteo"]
    criticos = conteo.get("CRÍTICO", 0)
    altos = conteo.get("ALTO", 0)

    if criticos:
        return _e(
            f"Priorizar de inmediato la remediación de los {criticos} hallazgo(s) "
            "críticos, asignando responsable y fecha de compromiso. Los hallazgos "
            "altos deben atenderse en un plazo máximo de 30 días.",
            f"Immediately prioritize remediation of the {criticos} critical finding(s), "
            "assigning an owner and target date. High findings should be addressed "
            "within 30 days.",
        )
    if altos:
        return _e(
            f"No se identificaron hallazgos críticos. Atender los {altos} hallazgo(s) "
            "altos en un plazo máximo de 30 días y programar una revalidación.",
            f"No critical findings were identified. Address the {altos} high finding(s) "
            "within 30 days and schedule a revalidation.",
        )
    if informe["total_hallazgos"]:
        return _e(
            "No se identificaron hallazgos críticos ni altos. Mantener el monitoreo "
            "periódico y cerrar los hallazgos medios y bajos según su prioridad.",
            "No critical or high findings were identified. Keep periodic monitoring "
            "and close medium and low findings according to priority.",
        )
    return _e(
        "No se registraron hallazgos en el periodo. Mantener las revisiones "
        "periódicas para sostener el nivel de seguridad observado.",
        "No findings were recorded in the period. Keep periodic reviews to sustain "
        "the observed security level.",
    )


def _plan_accion(informe: dict) -> list[dict]:
    plan: list[dict] = []
    vistos: set[str] = set()

    for hallazgo in informe["hallazgos"]:
        if hallazgo["severidad"] not in ("CRÍTICO", "ALTO"):
            continue
        clave = hallazgo["hallazgo"].lower()
        if clave in vistos:
            continue
        vistos.add(clave)
        plazo = _e("7 días", "7 days") if hallazgo["severidad"] == "CRÍTICO" else _e("30 días", "30 days")
        accion = hallazgo["hallazgo"]
        if hallazgo["remediacion"]:
            accion = f"{accion}: {hallazgo['remediacion']}"
        elif hallazgo["owasp"] and hallazgo["owasp"] != "—":
            accion = f"{accion} ({hallazgo['owasp']})"
        plan.append({
            "prioridad": _etiqueta_sev(hallazgo["severidad"]),
            "accion": accion,
            "plazo": plazo,
            "severidad": hallazgo["severidad"],
        })
        if len(plan) >= 5:
            break

    plan.append({
        "prioridad": _e("Gobierno", "Governance"),
        "accion": _e(
            "Asignar responsable y fecha compromiso a cada hallazgo, y revalidar "
            "con un nuevo análisis después de aplicar las correcciones.",
            "Assign an owner and target date to each finding, and revalidate with a "
            "new assessment after applying the fixes.",
        ),
        "plazo": _e("Continuo", "Ongoing"),
        "severidad": "INFO",
    })
    return plan


# --------------------------------------------------------------------- Markdown
def _md_celda(valor) -> str:
    return _texto(valor, "—").replace("|", "\\|").replace("\n", " ")


def informe_markdown(informe: dict) -> str:
    """Genera el informe completo en Markdown (editable y versionable)."""
    conteo = informe["conteo"]
    desde, hasta = informe["periodo"]
    lineas = [
        f"# {_e('Informe ejecutivo de seguridad web', 'Web security executive report')}",
        "",
        f"**{_e('Generado', 'Generated')}:** {informe['generado']}  ",
        f"**{_e('Periodo analizado', 'Assessment period')}:** {desde} — {hasta}  ",
        f"**{_e('Objetivos', 'Targets')}:** {len(informe['objetivos'])} · "
        f"**{_e('Análisis', 'Assessments')}:** {len(informe['analisis'])}",
        "",
        "---",
        "",
        f"## 1. {_e('Resumen ejecutivo', 'Executive summary')}",
        "",
        informe["resumen"],
        "",
        f"> **{_e('Recomendación', 'Recommendation')}:** {informe['recomendacion']}",
        "",
        f"## 2. {_e('Indicadores clave', 'Key indicators')}",
        "",
        f"| {_e('Indicador', 'Indicator')} | {_e('Valor', 'Value')} |",
        "| --- | ---: |",
        f"| {_e('Análisis incluidos', 'Assessments included')} | {len(informe['analisis'])} |",
        f"| {_e('Objetivos distintos', 'Distinct targets')} | {len(informe['objetivos'])} |",
        f"| {_e('Hallazgos registrados', 'Recorded findings')} | {informe['total_hallazgos']} |",
        f"| {_e('Críticos', 'Critical')} | {conteo.get('CRÍTICO', 0)} |",
        f"| {_e('Altos', 'High')} | {conteo.get('ALTO', 0)} |",
        f"| {_e('Medios', 'Medium')} | {conteo.get('MEDIO', 0)} |",
        f"| {_e('Bajos', 'Low')} | {conteo.get('BAJO', 0)} |",
        f"| {_e('Informativos', 'Informational')} | {conteo.get('INFO', 0)} |",
        f"| {_e('Puntuación media', 'Average score')} | "
        f"{_fmt_numero(informe['score']) if informe['score'] is not None else '—'} / 100 |",
        f"| {_e('Clasificación', 'Classification')} | {_etiqueta_clasif(informe['clasificacion'])} |",
        "",
        f"## 3. {_e('Distribución por severidad', 'Severity distribution')}",
        "",
        f"| {_e('Severidad', 'Severity')} | {_e('Hallazgos', 'Findings')} | "
        f"{_e('Porcentaje', 'Percentage')} |",
        "| --- | ---: | ---: |",
    ]

    total = informe["total_hallazgos"] or 1
    for severidad in SEVERITY_ORDER:
        cantidad = conteo.get(severidad, 0)
        lineas.append(
            f"| {_etiqueta_sev(severidad)} | {cantidad} | {cantidad * 100 / total:.0f}% |"
        )

    lineas += ["", f"## 4. {_e('Hallazgos prioritarios', 'Priority findings')}", ""]

    if informe["hallazgos"]:
        lineas += [
            f"| {_e('Severidad', 'Severity')} | {_e('Objetivo', 'Target')} | "
            f"{_e('Hallazgo', 'Finding')} | OWASP | CVSS | {_e('Veces', 'Times')} |",
            "| --- | --- | --- | --- | ---: | ---: |",
        ]
        for hallazgo in informe["hallazgos"]:
            lineas.append(
                f"| {_etiqueta_sev(hallazgo['severidad'])} "
                f"| {_md_celda(hallazgo['objetivo'])} "
                f"| {_md_celda(hallazgo['hallazgo'])} "
                f"| {_md_celda(hallazgo['owasp'])} "
                f"| {_fmt_numero(hallazgo['cvss']) if hallazgo['cvss'] is not None else '—'} "
                f"| {hallazgo['veces']} |"
            )
    else:
        lineas.append(_e(
            "No hay detalle individual de hallazgos para este periodo.",
            "No individual finding detail is available for this period.",
        ))

    if informe["sin_detalle"]:
        lineas += [
            "",
            _e(
                f"> Nota: {informe['sin_detalle']} hallazgo(s) figuran en el resumen "
                "de los análisis pero no tienen detalle individual almacenado.",
                f"> Note: {informe['sin_detalle']} finding(s) appear in the assessment "
                "summary but have no stored individual detail.",
            ),
        ]

    lineas += ["", f"## 5. {_e('Plan de acción recomendado', 'Recommended action plan')}", ""]
    for numero, item in enumerate(informe["plan"], start=1):
        lineas.append(
            f"{numero}. **[{item['prioridad']}]** {item['accion']} "
            f"— _{_e('plazo', 'timeframe')}: {item['plazo']}_"
        )

    lineas += [
        "",
        f"## 6. {_e('Alcance y metodología', 'Scope and methodology')}",
        "",
        _e(
            "Las pruebas se ejecutaron exclusivamente sobre sistemas autorizados, "
            "con un enfoque de pentesting ético y sin acciones destructivas. "
            "Los resultados reflejan los análisis guardados en el periodo indicado "
            "y no garantizan la ausencia de vulnerabilidades no detectadas.",
            "Assessments were run exclusively against authorized systems, following an "
            "ethical pentesting approach without destructive actions. Results reflect "
            "the assessments stored during the reported period and do not guarantee "
            "the absence of undetected vulnerabilities.",
        ),
        "",
    ]
    for modulo in informe["modulos"]:
        lineas.append(
            f"- **{_etiqueta_modulo(modulo['clave'])}** "
            f"({modulo['cantidad']}): {modulo['descripcion']}"
        )

    lineas += ["", f"## 7. {_e('Anexo: análisis incluidos', 'Appendix: included assessments')}", ""]
    if informe["analisis"]:
        lineas += [
            f"| {_e('Fecha', 'Date')} | {_e('Módulo', 'Module')} | "
            f"{_e('Objetivo', 'Target')} | {_e('Hallazgos', 'Findings')} | "
            f"{_e('Nivel', 'Level')} | Score |",
            "| --- | --- | --- | ---: | --- | ---: |",
        ]
        for item in informe["analisis"]:
            lineas.append(
                f"| {_md_celda(_fecha(item['fecha']))} "
                f"| {_etiqueta_modulo(item['modulo'])} "
                f"| {_md_celda(item['objetivo'])} "
                f"| {item['hallazgos']} "
                f"| {_md_celda(item['nivel'])} "
                f"| {_fmt_numero(item['score']) if item['score'] is not None else '—'} |"
            )
    else:
        lineas.append(_e("Sin análisis en el periodo.", "No assessments in the period."))

    lineas += [
        "",
        "---",
        "",
        _e(
            "*Documento confidencial. Distribuir únicamente a las partes autorizadas.*",
            "*Confidential document. Distribute only to authorized parties.*",
        ),
        "",
    ]
    return "\n".join(lineas)


# --------------------------------------------------------------------------- PDF
def _pdf_estilos():
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()
    azul = colors.HexColor("#2563EB")
    oscuro = colors.HexColor("#0F172A")
    gris = colors.HexColor("#64748B")
    return {
        "titulo": ParagraphStyle(
            "Titulo", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=21, leading=25, textColor=oscuro, spaceAfter=4,
        ),
        "subtitulo": ParagraphStyle(
            "Subtitulo", parent=base["Normal"], fontName="Helvetica",
            fontSize=10, leading=14, textColor=gris,
        ),
        "seccion": ParagraphStyle(
            "Seccion", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=13, leading=16, textColor=azul, spaceBefore=14, spaceAfter=6,
        ),
        "cuerpo": ParagraphStyle(
            "Cuerpo", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=14, textColor=colors.HexColor("#334155"),
        ),
        "nota": ParagraphStyle(
            "Nota", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=11, textColor=gris,
        ),
        "tabla": ParagraphStyle(
            "Tabla", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=10.5, textColor=colors.HexColor("#1E293B"),
        ),
        "tabla_centro": ParagraphStyle(
            "TablaCentro", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=10.5, textColor=colors.HexColor("#1E293B"), alignment=1,
        ),
    }


def _pdf_parrafo(texto, estilo):
    from reportlab.platypus import Paragraph
    return Paragraph(
        _xml(_texto(texto, "—")).replace("\n", "<br/>"),
        estilo,
    )


def _pdf_tabla(headers, rows, widths, estilos, aligns=None, first_col_colors=None):
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    data = [[str(h) for h in headers]]
    for fila in rows:
        data.append([
            celda if hasattr(celda, "wrap") else _pdf_parrafo(celda, estilos["tabla"])
            for celda in fila
        ])

    tabla = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    estilo = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F2A52")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    for indice in range(1, len(data)):
        if indice % 2 == 0:
            estilo.append(("BACKGROUND", (0, indice), (-1, indice), colors.HexColor("#F1F5F9")))
    if aligns:
        for columna, alineacion in aligns.items():
            estilo.append(("ALIGN", (columna, 1), (columna, -1), alineacion))
    if first_col_colors:
        for indice, color in enumerate(first_col_colors, start=1):
            if color:
                estilo.append(("BACKGROUND", (0, indice), (0, indice), colors.HexColor(color)))
    tabla.setStyle(TableStyle(estilo))
    return tabla


def _pdf_meta(informe: dict, estilos):
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Table, TableStyle

    desde, hasta = informe["periodo"]
    filas = [
        [
            Paragraph(
                f'<font color="#64748B">{_e("Generado", "Generated")}</font><br/>'
                f'<b>{_xml(informe["generado"])}</b>',
                estilos["tabla"],
            ),
            Paragraph(
                f'<font color="#64748B">{_e("Periodo analizado", "Assessment period")}</font><br/>'
                f'<b>{_xml(desde)} — {_xml(hasta)}</b>',
                estilos["tabla"],
            ),
            Paragraph(
                f'<font color="#64748B">{_e("Clasificación", "Classification")}</font><br/>'
                f'<b>{_xml(_etiqueta_clasif(informe["clasificacion"]))}</b>',
                estilos["tabla"],
            ),
        ]
    ]
    tabla = Table(filas, colWidths=[5.6 * cm, 6.2 * cm, 5.2 * cm], hAlign="LEFT")
    tabla.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
    ]))
    return tabla


def _pdf_kpis(informe: dict, estilos):
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Table, TableStyle

    conteo = informe["conteo"]
    tarjetas = [
        (_e("Análisis", "Assessments"), str(len(informe["analisis"]))),
        (_e("Objetivos", "Targets"), str(len(informe["objetivos"]))),
        (_e("Hallazgos", "Findings"), str(informe["total_hallazgos"])),
        (_e("Críticos", "Critical"), str(conteo.get("CRÍTICO", 0))),
        (_e("Altos", "High"), str(conteo.get("ALTO", 0))),
        (
            _e("Puntuación media", "Average score"),
            f"{_fmt_numero(informe['score'])}/100" if informe["score"] is not None else "—",
        ),
    ]

    filas = []
    for indice in range(0, len(tarjetas), 3):
        celdas = []
        for etiqueta, valor in tarjetas[indice:indice + 3]:
            celdas.append(Paragraph(
                f'<font size="7" color="#64748B">{_xml(etiqueta.upper())}</font><br/>'
                f'<font size="16" color="#0F172A"><b>{_xml(valor)}</b></font>',
                estilos["tabla"],
            ))
        filas.append(celdas)

    tabla = Table(filas, colWidths=[5.8 * cm] * 3, hAlign="LEFT")
    estilo = [
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]
    tabla.setStyle(TableStyle(estilo))
    return tabla


def _pdf_numero_paginas(canvas_class, titulo: str):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm

    class NumberedCanvas(canvas_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._estados = []

        def showPage(self):
            self._estados.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._estados)
            for estado in self._estados:
                self.__dict__.update(estado)
                self._pie(total, titulo)
                super().showPage()
            super().save()

        def _pie(self, total, titulo_reporte):
            self.saveState()
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(2 * cm, 1.45 * cm, A4[0] - 2 * cm, 1.45 * cm)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(2 * cm, 1.1 * cm, titulo_reporte)
            self.drawRightString(
                A4[0] - 2 * cm, 1.1 * cm,
                _e(f"Página {self._pageNumber} de {total}",
                   f"Page {self._pageNumber} of {total}"),
            )
            self.restoreState()

    return NumberedCanvas


def informe_pdf(informe: dict) -> bytes:
    """Genera el informe ejecutivo en PDF (A4, listo para imprimir)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas as pdfcanvas
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    estilos = _pdf_estilos()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=1.7 * cm, bottomMargin=1.9 * cm,
        title=_e("Informe ejecutivo de seguridad web", "Web security executive report"),
        author="Analizador de Vulnerabilidades Web",
        subject=_e("Resumen ejecutivo y plan de acción", "Executive summary and action plan"),
    )

    titulo = _e(
        "Informe ejecutivo de seguridad web",
        "Web security executive report",
    )
    subtitulo = _e(
        "Resumen para gerencia · Hallazgos priorizados · Plan de acción",
        "Management summary · Prioritized findings · Action plan",
    )
    historia = [
        Paragraph(_xml(titulo), estilos["titulo"]),
        Paragraph(_xml(subtitulo), estilos["subtitulo"]),
        Spacer(1, 6),
        Table(
            [[Paragraph(
                f'<font color="#FFFFFF">{_e("CONFIDENCIAL", "CONFIDENTIAL")}</font>',
                estilos["nota"],
            )]],
            colWidths=[17 * cm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F2A52")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]),
        ),
        Spacer(1, 8),
        _pdf_meta(informe, estilos),
        Spacer(1, 10),
        _pdf_kpis(informe, estilos),
        Paragraph(_e("1. Resumen ejecutivo", "1. Executive summary"), estilos["seccion"]),
        Paragraph(_xml(informe["resumen"]), estilos["cuerpo"]),
        Spacer(1, 7),
        Table(
            [[Paragraph(
                f'<b>{_e("Recomendación", "Recommendation")}:</b> '
                f'{_xml(informe["recomendacion"])}',
                estilos["cuerpo"],
            )]],
            colWidths=[17 * cm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#93C5FD")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]),
        ),
    ]

    # 2. Distribución por severidad
    historia += [
        Paragraph(_e("2. Distribución por severidad", "2. Severity distribution"), estilos["seccion"]),
    ]
    total = informe["total_hallazgos"] or 1
    filas_sev = []
    for severidad in SEVERITY_ORDER:
        cantidad = informe["conteo"].get(severidad, 0)
        filas_sev.append([
            Paragraph(
                f'<font color="#FFFFFF"><b>{_xml(_etiqueta_sev(severidad))}</b></font>',
                estilos["tabla"],
            ),
            Paragraph(str(cantidad), estilos["tabla_centro"]),
            Paragraph(f"{cantidad * 100 / total:.0f}%", estilos["tabla_centro"]),
        ])
    tabla_sev = _pdf_tabla(
        [_e("Severidad", "Severity"), _e("Hallazgos", "Findings"), _e("Porcentaje", "Percentage")],
        filas_sev,
        [6.2 * cm, 4.2 * cm, 4.2 * cm],
        estilos,
        aligns={1: "CENTER", 2: "CENTER"},
        first_col_colors=[_SEV_COLOR[sev] for sev in SEVERITY_ORDER],
    )
    historia += [tabla_sev, Spacer(1, 4)]

    if informe["sin_detalle"]:
        historia.append(Paragraph(
            _xml(_e(
                f"Nota: {informe['sin_detalle']} hallazgo(s) figuran en el resumen de los "
                "análisis pero no tienen detalle individual almacenado.",
                f"Note: {informe['sin_detalle']} finding(s) appear in the assessment summary "
                "but have no stored individual detail.",
            )),
            estilos["nota"],
        ))

    # 3. Hallazgos prioritarios
    historia += [
        Paragraph(_e("3. Hallazgos prioritarios", "3. Priority findings"), estilos["seccion"]),
    ]
    if informe["hallazgos"]:
        filas_hallazgos = []
        for hallazgo in informe["hallazgos"][:40]:
            filas_hallazgos.append([
                Paragraph(
                    f'<font color="#FFFFFF"><b>{_xml(_etiqueta_sev(hallazgo["severidad"]))}</b></font>',
                    estilos["tabla"],
                ),
                _texto(hallazgo["objetivo"]),
                _texto(hallazgo["hallazgo"]),
                _texto(hallazgo["owasp"]),
                _fmt_numero(hallazgo["cvss"]) if hallazgo["cvss"] is not None else "—",
                str(hallazgo["veces"]),
            ])
        tabla_hallazgos = _pdf_tabla(
            [
                _e("Severidad", "Severity"), _e("Objetivo", "Target"),
                _e("Hallazgo", "Finding"), "OWASP", "CVSS", _e("Veces", "Times"),
            ],
            filas_hallazgos,
            [2.0 * cm, 3.4 * cm, 6.4 * cm, 2.2 * cm, 1.3 * cm, 1.3 * cm],
            estilos,
            aligns={4: "CENTER", 5: "CENTER"},
            first_col_colors=[_SEV_COLOR[h["severidad"]] for h in informe["hallazgos"][:40]],
        )
        historia.append(tabla_hallazgos)
        if len(informe["hallazgos"]) > 40:
            historia.append(Paragraph(
                _xml(_e(
                    "Se muestran los 40 hallazgos de mayor prioridad. El detalle completo "
                    "está disponible en la exportación Markdown y en el historial.",
                    "The 40 highest-priority findings are shown. Full detail is available "
                    "in the Markdown export and in the history.",
                )),
                estilos["nota"],
            ))
    else:
        historia.append(Paragraph(
            _xml(_e(
                "No hay detalle individual de hallazgos para este periodo.",
                "No individual finding detail is available for this period.",
            )),
            estilos["cuerpo"],
        ))

    # 4. Plan de acción
    historia.append(Paragraph(
        _e("4. Plan de acción recomendado", "4. Recommended action plan"),
        estilos["seccion"],
    ))
    filas_plan = []
    for numero, item in enumerate(informe["plan"], start=1):
        filas_plan.append([
            Paragraph(str(numero), estilos["tabla_centro"]),
            Paragraph(
                f'<font color="{_SEV_COLOR.get(item["severidad"], "#334155")}">'
                f'<b>{_xml(item["prioridad"])}</b></font>',
                estilos["tabla"],
            ),
            _texto(item["accion"]),
            _texto(item["plazo"]),
        ])
    historia.append(_pdf_tabla(
        ["#", _e("Prioridad", "Priority"), _e("Acción", "Action"), _e("Plazo", "Timeframe")],
        filas_plan,
        [0.9 * cm, 2.4 * cm, 10.9 * cm, 2.8 * cm],
        estilos,
        aligns={0: "CENTER"},
    ))

    # 5. Alcance y metodología
    historia += [
        Paragraph(_e("5. Alcance y metodología", "5. Scope and methodology"), estilos["seccion"]),
        Paragraph(_xml(_e(
            "Las pruebas se ejecutaron exclusivamente sobre sistemas autorizados, con un "
            "enfoque de pentesting ético y sin acciones destructivas. Los resultados "
            "reflejan los análisis guardados en el periodo indicado y no garantizan la "
            "ausencia de vulnerabilidades no detectadas.",
            "Assessments were run exclusively against authorized systems, following an "
            "ethical pentesting approach without destructive actions. Results reflect "
            "the assessments stored during the reported period and do not guarantee the "
            "absence of undetected vulnerabilities.",
        )), estilos["cuerpo"]),
        Spacer(1, 4),
    ]
    for modulo in informe["modulos"]:
        historia.append(Paragraph(
            f'<b>{_xml(_etiqueta_modulo(modulo["clave"]))}</b> '
            f'({modulo["cantidad"]}): {_xml(modulo["descripcion"])}',
            estilos["cuerpo"],
        ))
    if not informe["modulos"]:
        historia.append(Paragraph(
            _xml(_e("Sin módulos registrados.", "No modules recorded.")),
            estilos["cuerpo"],
        ))

    # 6. Anexo de análisis
    historia.append(Paragraph(
        _e("6. Anexo: análisis incluidos", "6. Appendix: included assessments"),
        estilos["seccion"],
    ))
    if informe["analisis"]:
        filas_anexo = [[
            _fecha(item["fecha"]),
            _etiqueta_modulo(item["modulo"]),
            _texto(item["objetivo"]),
            str(item["hallazgos"]),
            _texto(item["nivel"]),
            _fmt_numero(item["score"]) if item["score"] is not None else "—",
        ] for item in informe["analisis"][:60]]
        historia.append(_pdf_tabla(
            [
                _e("Fecha", "Date"), _e("Módulo", "Module"), _e("Objetivo", "Target"),
                _e("Hallazgos", "Findings"), _e("Nivel", "Level"), "Score",
            ],
            filas_anexo,
            [2.5 * cm, 2.6 * cm, 5.7 * cm, 1.7 * cm, 2.6 * cm, 1.4 * cm],
            estilos,
            aligns={3: "CENTER", 5: "CENTER"},
        ))
        if len(informe["analisis"]) > 60:
            historia.append(Paragraph(
                _xml(_e(
                    "Se listan los 60 análisis más recientes.",
                    "The 60 most recent assessments are listed.",
                )),
                estilos["nota"],
            ))
    else:
        historia.append(Paragraph(
            _xml(_e("Sin análisis en el periodo.", "No assessments in the period.")),
            estilos["cuerpo"],
        ))

    historia += [
        Spacer(1, 14),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1")),
        Spacer(1, 4),
        Paragraph(_xml(_e(
            "Documento confidencial. Distribuir únicamente a las partes autorizadas.",
            "Confidential document. Distribute only to authorized parties.",
        )), estilos["nota"]),
    ]

    canvas_final = _pdf_numero_paginas(
        pdfcanvas.Canvas,
        _e("Informe ejecutivo de seguridad web · Confidencial",
           "Web security executive report · Confidential"),
    )
    doc.build(historia, canvasmaker=canvas_final)
    return buffer.getvalue()


# --------------------------------------------------------------------- utilidades
def nombre_informe(informe: dict, extension: str) -> str:
    """Nombre de archivo estable y ordenable por fecha de generación."""
    fecha = _texto(informe.get("generado"), datetime.now().strftime("%Y-%m-%d %H:%M"))
    sello = fecha.replace("-", "").replace(":", "").replace(" ", "_")[:13]
    return f"informe_ejecutivo_seguridad_{sello}.{extension.lstrip('.')}"

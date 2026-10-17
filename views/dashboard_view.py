import plotly.graph_objects as go
import pandas as pd
import streamlit as st
import html as _html
from views.components import ui_sqli_options
from models.i18n import t, es_o_en

from models import history
from models.metrics import nivel_riesgo
from models.load_model import DURACION_MAXIMA_POR_NIVEL
from models.report_builder import (
    construir_informe, etiqueta_clasificacion, etiqueta_modulo, etiqueta_severidad,
    informe_markdown, informe_pdf, nombre_informe,
)
from views.components import (
    colores_actuales, kpi_grid, section_header, tabla,
    ui_audit_options, ui_authorization_check, ui_internal_network_toggle,
    ui_theme_selector,
)
from models.port_scanner import PESO_NIVEL
from models.risk_score import normalize_severity

_SEV_KEY = {"Crítica": "crit", "Alta": "high", "Media": "med", "Baja": "low", "Info": "info"}
_NIVEL_COLOR = {"alto": "crit", "medio": "med", "bajo": "ok"}


def _sev_color(nivel: str, c: dict) -> str:
    return c.get(_SEV_KEY.get(nivel, "info"), c["info"])


def _tema(fig: go.Figure) -> go.Figure:
    """Aplica el tema visual según la preferencia (claro / oscuro / sistema)."""
    c = colores_actuales()
    fig.update_layout(
        template=c["template"],
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, Segoe UI, sans-serif", size=12, color=c["text"]),
        title=dict(font=dict(size=15, color=c["text"]), x=0.02, xanchor="left"),
        margin=dict(t=54, b=36, l=48, r=24),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11, color=c["muted"])),
        hoverlabel=dict(bgcolor=c["text"], bordercolor=c["grid"], font=dict(color=c["text"])),
    )
    fig.update_xaxes(gridcolor=c["grid"], zerolinecolor=c["grid"], linecolor=c["grid"],
                     tickfont=dict(color=c["muted"]))
    fig.update_yaxes(gridcolor=c["grid"], zerolinecolor=c["grid"], linecolor=c["grid"],
                     tickfont=dict(color=c["muted"]))
    return fig


def _tema_carga(fig: go.Figure, leyenda_inferior: bool = False) -> go.Figure:
    fig = _tema(fig)
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6edf7"),
        title=dict(font=dict(color="#e6edf7")),
        margin=dict(t=82, b=104 if leyenda_inferior else 40, l=48, r=24),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf7"),
            **({"orientation": "h", "yanchor": "top", "y": -0.25,
                "xanchor": "center", "x": 0.5} if leyenda_inferior else {}),
        ),
    )
    fig.update_xaxes(
        gridcolor="#12305a", zerolinecolor="#12305a", linecolor="#12305a",
        tickfont=dict(color="#e6edf7"), title_font=dict(color="#e6edf7"),
    )
    fig.update_yaxes(
        gridcolor="#12305a", zerolinecolor="#12305a", linecolor="#12305a",
        tickfont=dict(color="#e6edf7"), title_font=dict(color="#e6edf7"),
    )
    fig.update_traces(
        selector={"type": "indicator"},
        title={"text": es_o_en("Grado de salud (PGI)", "Health score (PGI)"),
               "font": {"size": 14, "color": "#e6edf7"}},
        number={"font": {"color": "#e6edf7"}},
        gauge={"axis": {
            "tickcolor": "#e6edf7", "tickfont": {"color": "#e6edf7"},
        }, "bordercolor": "#12305a"},
    )
    return fig


def grafico_severidad_donub(por_severidad: dict) -> go.Figure:
    c = colores_actuales()
    claves = list(por_severidad.keys())
    labels = [t(str(clave)) for clave in claves]
    values = list(por_severidad.values())
    colors = [_sev_color(clave, c) for clave in claves]
    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, marker=dict(colors=colors), hole=0.55,
        textinfo="label+percent", textfont=dict(size=11),
    )])
    fig.update_layout(title=es_o_en("Distribución de severidad", "Severity distribution"), showlegend=False)
    return _tema(fig)


def grafico_confianza_por_parametro(hallazgos: list) -> go.Figure:
    c = colores_actuales()
    data = []
    for h in hallazgos:
        data.append({
            "parámetro": h.get("parametro", ""),
            "confianza": h.get("confianza", 0),
            "tipo": h.get("tipo", ""),
        })
    df = pd.DataFrame(data)
    fig = go.Figure()
    for tipo in df["tipo"].unique():
        subset = df[df["tipo"] == tipo]
        media = subset["confianza"].mean()
        color = c["crit"] if media >= 80 else c["high"] if media >= 60 else c["med"] if media >= 40 else c["ok"]
        fig.add_trace(go.Bar(
            x=subset["parámetro"], y=subset["confianza"],
            name=tipo, marker_color=color, marker_line_width=0,
            hovertemplate=(
                es_o_en("Parámetro", "Parameter") + ": %{x}<br>"
                + es_o_en("Confianza", "Confidence") + ": %{y}%<extra></extra>"
            ),
        ))
    fig.update_layout(title=es_o_en("Confianza por parámetro", "Confidence by parameter"), barmode="group",
                      yaxis_title=es_o_en("Confianza (%)", "Confidence (%)"),
                      xaxis_title=es_o_en("Parámetro", "Parameter"))
    return _tema(fig)


def grafico_radar_cobertura(hallazgos: list) -> go.Figure:
    c = colores_actuales()
    tipos = ["error-based", "boolean-based blind", "time-based blind", "union-based"]
    valores = [1 if any(h.get("tipo") == t for h in hallazgos) else 0 for t in tipos]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=valores + [valores[0]], theta=tipos + [tipos[0]],
        fill="toself", fillcolor="rgba(99, 102, 241, 0.25)",
        line=dict(color=c["primary"], width=2), name=es_o_en("Cobertura", "Coverage"),
    ))
    fig.update_layout(
        title=es_o_en("Cobertura de vectores de ataque", "Attack vector coverage"),
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(visible=True, range=[0, 1.2], tickvals=[0, 1],
                            gridcolor=c["grid"], linecolor=c["grid"]),
            angularaxis=dict(gridcolor=c["grid"], linecolor=c["grid"]),
        ),
        showlegend=False,
    )
    return _tema(fig)


def grafico_risk_matrix(hallazgos_con_cvss: list) -> go.Figure:
    c = colores_actuales()
    data = []
    for h in hallazgos_con_cvss:
        cvss = h.get("cvss", 0)
        data.append({
            "x": cvss, "y": min(10, cvss + 0.5),
            "param": h.get("parametro", ""), "nivel": nivel_riesgo(cvss),
        })
    df = pd.DataFrame(data)
    fig = go.Figure()
    for nivel in ["Crítica", "Alta", "Media", "Baja", "Info"]:
        subset = df[df["nivel"] == nivel]
        if subset.empty:
            continue
        fig.add_trace(go.Scatter(
            x=subset["x"], y=subset["y"], mode="markers+text",
            marker=dict(size=15, color=_sev_color(nivel, c), symbol="x",
                        line=dict(width=2, color=c["text"])),
            text=subset["param"], textposition="top center", name=es_o_en(nivel, _nivel_en(nivel)),
            textfont=dict(size=10, color=c["muted"]),
        ))
    fig.add_shape(type="rect", x0=3, x1=10, y0=3, y1=10, line=dict(width=0),
                  fillcolor="rgba(239,68,68,0.06)")
    fig.add_shape(type="rect", x0=6, x1=10, y0=6, y1=10, line=dict(width=0),
                  fillcolor="rgba(249,115,22,0.06)")
    fig.update_layout(title=t("Matriz de riesgo (Likelihood vs Impact)"),
                      xaxis_title=t("Likelihood (CVSS Base)"), yaxis_title=t("Impact"),
                      xaxis=dict(range=[0, 11], dtick=2), yaxis=dict(range=[0, 11], dtick=2))
    return _tema(fig)


def _nivel_en(nivel: str) -> str:
    return {
        "Crítica": "Critical", "Alta": "High", "Media": "Medium",
        "Baja": "Low", "Info": "Info",
    }.get(nivel, nivel)


def grafico_gauge_riesgo(cvss_promedio: float, riesgo_global: str) -> go.Figure:
    c = colores_actuales()
    color = _sev_color(riesgo_global, c)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=cvss_promedio,
        number=dict(font=dict(size=34, color=c["text"])),
        title={"text": es_o_en("Riesgo global (CVSS)", "Overall risk (CVSS)"), "font": {"size": 14, "color": c["muted"]}},
        gauge={
            "axis": {"range": [0, 10], "dtick": 2, "tickcolor": c["muted"]},
            "bar": {"color": color, "thickness": 0.72},
            "bgcolor": "rgba(0,0,0,0)", "borderwidth": 1, "bordercolor": c["grid"],
            "steps": [
                {"range": [0, 3], "color": "rgba(52, 211, 153, 0.14)"},
                {"range": [3, 6], "color": "rgba(251, 191, 36, 0.14)"},
                {"range": [6, 8], "color": "rgba(251, 146, 60, 0.14)"},
                {"range": [8, 10], "color": "rgba(248, 113, 113, 0.16)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.85, "value": cvss_promedio},
        },
    ))
    return _tema(fig)


def grafico_latencia_percentiles(niveles: list) -> go.Figure:
    c = colores_actuales()
    df = pd.DataFrame(niveles)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_base"], mode="lines+markers", name=t("Base"), line=dict(color=c["muted"], dash="dash")))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p50"], mode="lines+markers", name="p50", line=dict(color=c["ok"])))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p90"], mode="lines+markers", name="p90", line=dict(color=c["med"])))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p95"], mode="lines+markers", name="p95", line=dict(color=c["high"])))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p99"], mode="lines+markers", name="p99", line=dict(color=c["crit"], width=3)))
    fig.update_layout(
        title=es_o_en("Latencia por percentil vs concurrencia", "Latency by percentile vs concurrency"),
        xaxis_title=es_o_en("Concurrencia (peticiones simultáneas)", "Concurrency (simultaneous requests)"),
        yaxis_title=es_o_en("Latencia (s)", "Latency (s)"),
        legend=dict(orientation="h", yanchor="top", y=-0.25, xanchor="center", x=0.5),
    )
    return _tema_carga(fig, leyenda_inferior=True)


def grafico_throughput(niveles: list) -> go.Figure:
    c = colores_actuales()
    df = pd.DataFrame(niveles)
    df["throughput"] = df["peticiones_totales"] / max(DURACION_MAXIMA_POR_NIVEL, 1)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=df["concurrencia"], y=df["throughput"], marker_color=c["primary"], marker_line_width=0))
    fig.update_layout(title=es_o_en("Throughput (peticiones/segundo) por nivel",    "Throughput (requests/second) per level"),
    xaxis_title=es_o_en("Concurrencia", "Concurrency"),
    yaxis_title=es_o_en("Peticiones / segundo", "Requests / second"))
    return _tema_carga(fig)


def grafico_error_pie(tipo_error: dict) -> go.Figure:
    c = colores_actuales()
    if not tipo_error:
        return _tema_carga(go.Figure())
    fig = go.Figure(data=[go.Pie(
        labels=list(tipo_error.keys()), values=list(tipo_error.values()),
        marker=dict(colors=[c["crit"], c["high"], c["med"], c["ok"], c["muted"]]), hole=0.55,
        textinfo="label+percent", textfont=dict(size=11),
    )])
    fig.update_layout(title=es_o_en("Distribución de errores", "Error distribution"), showlegend=False)
    return _tema_carga(fig)


def grafico_gauge_pgi(pgi: float, salud: str) -> go.Figure:
    c = colores_actuales()
    color = {"Excelente": c["ok"], "Buena": c["low"], "Degradada": c["high"], "Crítica": c["crit"]}.get(salud, c["muted"])
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=pgi,
        number=dict(font=dict(size=34, color=c["text"])),
        title={"text": es_o_en("Grado de salud (PGI)", "Health score (PGI)"), "font": {"size": 14, "color": c["muted"]}},
        gauge={
            "axis": {"range": [0, 100], "dtick": 20, "tickcolor": c["muted"]},
            "bar": {"color": color, "thickness": 0.72},
            "bgcolor": "rgba(0,0,0,0)", "borderwidth": 1, "bordercolor": c["grid"],
            "steps": [
                {"range": [75, 100], "color": "rgba(52, 211, 153, 0.14)"},
                {"range": [50, 75], "color": "rgba(56, 189, 248, 0.14)"},
                {"range": [25, 50], "color": "rgba(251, 146, 60, 0.14)"},
                {"range": [0, 25], "color": "rgba(248, 113, 113, 0.16)"},
            ],
        },
    ))
    return _tema_carga(fig)


def grafico_barra_estado(niveles: list) -> go.Figure:
    c = colores_actuales()
    df = pd.DataFrame(niveles)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=df["concurrencia"], y=df["tasa_error"], name=es_o_en("Tasa de error %", "Error rate %"), marker_color=c["crit"], marker_line_width=0))
    fig.add_trace(go.Bar(
        x=df["concurrencia"],
        y=df.get("errores", df["peticiones_totales"] * 0.01),
        name=es_o_en("Errores (nº)", "Errors (count)"), marker_color=c["high"], marker_line_width=0, visible="legendonly",
    ))
    fig.update_layout(title=es_o_en("Tasa de error por nivel de concurrencia", "Error rate per concurrency level"),
                      xaxis_title=es_o_en("Concurrencia", "Concurrency"), yaxis_title="%",
                      legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0))
    return _tema_carga(fig)


def mostrar_dashboard(registros: list, supabase_configurado: bool):
    registros = [item for item in (registros or []) if item.get("modulo") != "sqli"]
    etiquetas_modulo = {
        "load": t("Prueba de Carga"),
        "audit": t("Auditoría Unificada"),
        "port": t("Escaneo de Puertos"),
    }
    objetivos = {str(item.get("url", "")).strip() for item in registros if item.get("url")}
    modulos = {item.get("modulo") for item in registros if item.get("modulo")}
    total_hallazgos = sum(int(item.get("total_hallazgos") or 0) for item in registros)

    section_header(
        t("Resumen de seguridad"),
        t("Actividad reciente y resultados registrados"),
        "🛡️",
    )
    kpi_grid([
        {"label": t("Análisis recientes"), "value": len(registros), "sub": t("Hasta 10 registros"), "color": "primary"},
        {"label": t("Hallazgos registrados"), "value": total_hallazgos, "color": "high"},
        {"label": t("Objetivos analizados"), "value": len(objetivos), "color": "low"},
        {"label": t("Módulos con actividad"), "value": len(modulos), "color": "ok"},
    ])

    columna_actividad, columna_modulos = st.columns([1.4, 1])
    with columna_actividad:
        section_header(t("Evolución de actividad"), t("Análisis guardados por fecha"), "📈")
        actividad = pd.DataFrame([
            {"fecha": pd.to_datetime(item.get("created_at"), errors="coerce", utc=True)}
            for item in registros
        ]).dropna()
        if not actividad.empty:
            actividad = actividad.sort_values("fecha")
            actividad["día"] = actividad["fecha"].dt.strftime("%d %b")
            diario = actividad.groupby("día", sort=False).size().reset_index(name="análisis")
            figura_actividad = go.Figure(go.Scatter(
                x=diario["día"], y=diario["análisis"], mode="lines+markers",
                line=dict(color="#22d3ee", width=3),
                marker=dict(color="#22d3ee", size=8),
                fill="tozeroy", fillcolor="rgba(34,211,238,0.10)",
                hovertemplate="%{x}<br>" + t("Análisis: %{y}") + "<extra></extra>",
            ))
            figura_actividad.update_layout(
                title=t("Análisis por día"), yaxis_title=t("Análisis"),
                xaxis_title="", showlegend=False, height=300,
            )
            st.plotly_chart(_tema(figura_actividad), use_container_width=True)
        else:
            st.info(t("Todavía no hay fechas de análisis para mostrar."))

    with columna_modulos:
        section_header(t("Actividad por módulo"), t("Distribución de análisis guardados"), "◉")
        conteo_modulos = {}
        for item in registros:
            modulo = item.get("modulo", "")
            etiqueta = etiquetas_modulo.get(modulo, modulo or t("Otro"))
            conteo_modulos[etiqueta] = conteo_modulos.get(etiqueta, 0) + 1
        if conteo_modulos:
            paleta = {t("Prueba de Carga"): "#22c55e", t("Auditoría Unificada"): "#22d3ee",
                      t("Escaneo de Puertos"): "#3b82f6"}
            figura_modulos = go.Figure(data=[go.Pie(
                labels=list(conteo_modulos), values=list(conteo_modulos.values()),
                hole=0.64,
                marker=dict(colors=[paleta.get(nombre, "#64748b") for nombre in conteo_modulos]),
                textinfo="label+percent", textfont=dict(color=colores_actuales()["text"]),
            )])
            figura_modulos.update_layout(
                showlegend=False, height=300,
                annotations=[dict(
                    text=f"{len(registros)}<br><span style='font-size:11px'>{t('análisis')}</span>",
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=20, color=colores_actuales()["text"]),
                )],
                margin=dict(t=24, b=20, l=12, r=12),
            )
            st.plotly_chart(_tema(figura_modulos), use_container_width=True)
        else:
            st.info(t("La distribución aparecerá cuando haya análisis registrados."))

    section_header(t("Historial de auditorías"), t("Últimos análisis guardados"), "🗂️")
    if registros:
        filas = [{
            t("Fecha"): str(item.get("created_at", "")).replace("T", " ")[:16],
            t("Módulo"): etiquetas_modulo.get(item.get("modulo"), item.get("modulo", "")),
            t("Objetivo"): item.get("url", ""),
            t("Hallazgos"): int(item.get("total_hallazgos") or 0),
            t("Nivel"): item.get("nivel") or "—",
        } for item in registros]
        tabla(pd.DataFrame(filas))
    else:
        st.info(t("No hay análisis guardados todavía. El historial aparecerá aquí al completar un análisis."))

    estado_datos = t("Configurado") if supabase_configurado else t("No configurado")
    st.caption(t("Almacenamiento de historial: Supabase {}.").format(estado_datos))


# ------------------------------------------------------- informe ejecutivo
_CAMPOS_INFORME = ("id", "modulo", "url", "score", "nivel", "total_hallazgos", "created_at")


@st.cache_data(ttl=90, show_spinner=False)
def _informe_cache(firma: tuple, idioma: str) -> dict:
    """Construye (y cachea) el informe a partir de una firma serializable."""
    registros = [dict(zip(_CAMPOS_INFORME, fila)) for fila in firma]
    return construir_informe(registros)


@st.cache_data(ttl=90, show_spinner=False)
def _pdf_cache(firma: tuple, idioma: str) -> bytes:
    """Evita regenerar el PDF en cada rerun de Streamlit."""
    return informe_pdf(_informe_cache(firma, idioma))


def _mostrar_reporte_ejecutivo(registros: list):
    """Vista previa del informe ejecutivo y sus exportaciones PDF/Markdown."""
    idioma = st.session_state.get("idioma", "es")
    firma = tuple(tuple(r.get(c) for c in _CAMPOS_INFORME) for r in registros)
    try:
        informe = _informe_cache(firma, idioma)
    except Exception as exc:  # nunca romper la sección por un fallo de datos
        st.error(es_o_en("No se pudo construir el informe: ", "Could not build the report: ") + str(exc))
        return

    conteo = informe["conteo"]
    score = informe["score"]
    kpi_grid([
        {"label": es_o_en("Análisis incluidos", "Assessments included"),
         "value": len(informe["analisis"]), "color": "primary"},
        {"label": es_o_en("Objetivos", "Targets"),
         "value": len(informe["objetivos"]), "color": "low"},
        {"label": es_o_en("Hallazgos", "Findings"),
         "value": informe["total_hallazgos"], "color": "high"},
        {"label": es_o_en("Críticos", "Critical"),
         "value": conteo.get("CRÍTICO", 0), "color": "crit"},
        {"label": es_o_en("Altos", "High"),
         "value": conteo.get("ALTO", 0), "color": "high"},
        {"label": es_o_en("Puntuación media", "Average score"),
         "value": f"{score}/100" if score is not None else "—",
         "sub": etiqueta_clasificacion(informe["clasificacion"]), "color": "ok"},
    ])

    st.markdown(
        '<div style="background:var(--surface);border:1px solid var(--border);'
        'border-left:4px solid var(--primary-2);border-radius:12px;'
        'padding:16px 18px;margin:10px 0 14px;color:var(--text);'
        'font-size:.9rem;line-height:1.6">'
        f'<div>{_html.escape(informe["resumen"])}</div>'
        f'<div style="margin-top:10px;color:var(--muted)">'
        f'<b>{es_o_en("Recomendación", "Recommendation")}:</b> '
        f'{_html.escape(informe["recomendacion"])}</div></div>',
        unsafe_allow_html=True,
    )

    # Exportaciones. El PDF se arma en memoria; si reportlab falla, la vista
    # sigue disponible y se avisa al usuario.
    pdf_bytes = None
    try:
        pdf_bytes = _pdf_cache(firma, idioma)
    except Exception as exc:
        st.warning(es_o_en(
            f"No se pudo generar el PDF: {exc}. Las demás exportaciones siguen disponibles.",
            f"Could not generate the PDF: {exc}. Other exports remain available.",
        ))
    markdown_bytes = informe_markdown(informe).encode("utf-8")
    csv_bytes = pd.DataFrame([{
        es_o_en("Fecha", "Date"): item["fecha"],
        es_o_en("Módulo", "Module"): etiqueta_modulo(item["modulo"]),
        es_o_en("Objetivo", "Target"): item["objetivo"],
        es_o_en("Hallazgos", "Findings"): item["hallazgos"],
        es_o_en("Nivel", "Level"): item["nivel"],
        "Score": item["score"] if item["score"] is not None else "",
    } for item in informe["analisis"]]).to_csv(index=False).encode("utf-8-sig")

    col_pdf, col_md, col_csv = st.columns(3)
    with col_pdf:
        st.download_button(
            "⬇️ " + es_o_en("Descargar PDF", "Download PDF"),
            data=pdf_bytes or b"",
            file_name=nombre_informe(informe, "pdf"),
            mime="application/pdf",
            use_container_width=True,
            type="primary",
            key="report_pdf",
            disabled=pdf_bytes is None,
        )
    with col_md:
        st.download_button(
            "⬇️ " + es_o_en("Descargar Markdown", "Download Markdown"),
            data=markdown_bytes,
            file_name=nombre_informe(informe, "md"),
            mime="text/markdown",
            use_container_width=True,
            key="report_md",
        )
    with col_csv:
        st.download_button(
            "⬇️ " + es_o_en("Descargar CSV", "Download CSV"),
            data=csv_bytes,
            file_name="reporte_vulnweb.csv",
            mime="text/csv",
            use_container_width=True,
            key="report_csv",
        )
    st.caption(es_o_en(
        "El PDF incluye portada, resumen ejecutivo, indicadores, distribución, "
        "hallazgos priorizados, plan de acción y anexos. El Markdown contiene "
        "el detalle completo y puede editarse.",
        "The PDF includes a cover, executive summary, indicators, distribution, "
        "prioritized findings, action plan and appendices. The Markdown contains "
        "the full detail and can be edited.",
    ))

    col_sev, col_plan = st.columns([1, 1.5])
    with col_sev:
        section_header(
            es_o_en("Distribución por severidad", "Severity distribution"),
            es_o_en("Peso de cada nivel sobre el total", "Share of each level"),
            "📊",
        )
        total = informe["total_hallazgos"] or 1
        tabla(pd.DataFrame([{
            es_o_en("Severidad", "Severity"): etiqueta_severidad(sev),
            es_o_en("Hallazgos", "Findings"): cantidad,
            "%": f"{cantidad * 100 / total:.0f}%",
        } for sev, cantidad in conteo.items()]))

    with col_plan:
        section_header(
            es_o_en("Plan de acción recomendado", "Recommended action plan"),
            es_o_en("Prioridades y plazos sugeridos", "Suggested priorities and timeframes"),
            "🎯",
        )
        for numero, item in enumerate(informe["plan"], start=1):
            st.markdown(
                f"**{numero}. [{item['prioridad']}]** {item['accion']}  \n"
                f"_{es_o_en('Plazo', 'Timeframe')}: {item['plazo']}_"
            )

    section_header(
        es_o_en("Hallazgos prioritarios", "Priority findings"),
        es_o_en("Agrupados por objetivo, severidad y control", "Grouped by target, severity and control"),
        "🔎",
    )
    if informe["hallazgos"]:
        visibles = informe["hallazgos"][:25]
        tabla(pd.DataFrame([{
            es_o_en("Severidad", "Severity"): etiqueta_severidad(h["severidad"]),
            es_o_en("Objetivo", "Target"): h["objetivo"],
            es_o_en("Hallazgo", "Finding"): h["hallazgo"],
            "OWASP": h["owasp"],
            "CVSS": h["cvss"] if h["cvss"] is not None else "—",
            es_o_en("Veces", "Times"): h["veces"],
            es_o_en("Remediación", "Remediation"): h["remediacion"] or "—",
        } for h in visibles]))
        restantes = len(informe["hallazgos"]) - len(visibles)
        st.caption(es_o_en(
            f"Mostrando {len(visibles)} de {len(informe['hallazgos'])} hallazgos agrupados."
            + (" El PDF incluye 40 y el Markdown el detalle completo." if restantes else ""),
            f"Showing {len(visibles)} of {len(informe['hallazgos'])} grouped findings."
            + (" The PDF includes 40 and the Markdown the full detail." if restantes else ""),
        ))
    else:
        st.info(es_o_en(
            "No hay detalle individual de hallazgos para este periodo.",
            "No individual finding detail is available for this period.",
        ))

    with st.expander(es_o_en("Alcance, metodología y anexo de análisis", "Scope, methodology and assessment appendix")):
        st.markdown(es_o_en(
            "Las pruebas se ejecutaron exclusivamente sobre sistemas autorizados, con un "
            "enfoque de pentesting ético y sin acciones destructivas. Los resultados "
            "reflejan los análisis guardados en el periodo indicado y no garantizan la "
            "ausencia de vulnerabilidades no detectadas.",
            "Assessments were run exclusively against authorized systems, following an "
            "ethical pentesting approach without destructive actions. Results reflect "
            "the assessments stored during the reported period and do not guarantee the "
            "absence of undetected vulnerabilities.",
        ))
        for modulo in informe["modulos"]:
            st.markdown(
                f"- **{etiqueta_modulo(modulo['clave'])}** ({modulo['cantidad']}): "
                f"{modulo['descripcion']}"
            )

        section_header(
            es_o_en("Objetivos analizados", "Analyzed targets"),
            es_o_en("Último análisis y hallazgos acumulados", "Latest assessment and accumulated findings"),
            "🌐",
        )
        tabla(pd.DataFrame([{
            es_o_en("Objetivo", "Target"): item["objetivo"],
            es_o_en("Último análisis", "Latest assessment"): str(item["ultimo"]).replace("T", " ")[:16],
            es_o_en("Módulo", "Module"): etiqueta_modulo(item["modulo"]),
            es_o_en("Hallazgos", "Findings"): item["hallazgos"],
            es_o_en("Nivel", "Level"): item["nivel"] or "—",
            "Score": item["score"] if item["score"] is not None else "—",
        } for item in informe["objetivos"]]))

        section_header(
            es_o_en("Análisis incluidos", "Included assessments"),
            es_o_en("Trazabilidad del informe", "Report traceability"),
            "🗂️",
        )
        tabla(pd.DataFrame([{
            es_o_en("Fecha", "Date"): str(item["fecha"]).replace("T", " ")[:16],
            es_o_en("Módulo", "Module"): etiqueta_modulo(item["modulo"]),
            es_o_en("Objetivo", "Target"): item["objetivo"],
            es_o_en("Hallazgos", "Findings"): item["hallazgos"],
            es_o_en("Nivel", "Level"): item["nivel"] or "—",
            "Score": item["score"] if item["score"] is not None else "—",
        } for item in informe["analisis"]]))


def mostrar_seccion(seccion: str, registros: list, supabase_configurado: bool):
    nombres = {
        "vulnerabilities": t("Vulnerabilidades"),
        "assets": t("Activos"),
        "monitoring": t("Monitoreo"),
        "reports": t("Reportes"),
        "settings": t("Configuración"),
    }
    if seccion not in nombres:
        st.info(t("Selecciona una sección del menú."))
        return

    if seccion != "reports":
        registros = [item for item in (registros or []) if item.get("modulo") != "sqli"]
    else:
        registros = list(registros or [])
    subtitulos = {
        "reports": t("Informe ejecutivo, plan de acción y exportaciones"),
    }
    section_header(
        nombres[seccion],
        subtitulos.get(seccion, t("Datos disponibles del historial de análisis")),
        "◈",
    )

    if seccion == "vulnerabilities":
        filas = []
        for registro in registros:
            scan_id = registro.get("id")
            for hallazgo in history.detalle(scan_id) if scan_id else []:
                filas.append({
                    "Fecha": str(registro.get("created_at", "")).replace("T", " ")[:16],
                    "Objetivo": registro.get("url", ""),
                    "Módulo": etiqueta_modulo(registro.get("modulo", "")),
                    "Hallazgo": t(str(hallazgo.get("descripcion") or hallazgo.get("tipo") or t("Hallazgo"))),
                    "Severidad": hallazgo.get("severidad") or hallazgo.get("nivel_riesgo") or "INFO",
                    "OWASP": hallazgo.get("owasp") or "—",
                })
        if filas:
            df_hallazgos = pd.DataFrame(filas)
            kpi_grid([
                {"label": t("Hallazgos"), "value": len(filas), "color": "high"},
                {"label": t("Críticos"), "value": sum(normalize_severity(f) == "CRÍTICO" for f in df_hallazgos["Severidad"]), "color": "crit"},
                {"label": t("Altos"), "value": sum(normalize_severity(f) == "ALTO" for f in df_hallazgos["Severidad"]), "color": "high"},
            ])
            tabla(df_hallazgos)
        else:
            st.info(t("No hay vulnerabilidades guardadas en los análisis recientes."))

    elif seccion == "assets":
        activos = {}
        for registro in registros:
            objetivo = str(registro.get("url") or "").strip()
            if objetivo and objetivo not in activos:
                activos[objetivo] = {
                    "Objetivo": objetivo,
                    "Último análisis": str(registro.get("created_at", "")).replace("T", " ")[:16],
                    "Módulo": etiqueta_modulo(registro.get("modulo", "")),
                    "Hallazgos": int(registro.get("total_hallazgos") or 0),
                }
        if activos:
            kpi_grid([
                {"label": t("Objetivos registrados"), "value": len(activos), "color": "low"},
                {"label": t("Registros revisados"), "value": len(registros), "color": "primary"},
            ])
            tabla(pd.DataFrame(list(activos.values())))
        else:
            st.info(t("Los objetivos aparecerán aquí después de guardar un análisis."))

    elif seccion == "monitoring":
        import plotly.graph_objects as go

        if not registros:
            st.info(t("No hay actividad de análisis registrada todavía."))
        else:
            df = pd.DataFrame([{
                "fecha": r.get("created_at"),
                "modulo": r.get("modulo") or "—",
                "url": r.get("url") or "",
                "hallazgos": int(r.get("total_hallazgos") or 0),
            } for r in registros])
            df["fecha"] = pd.to_datetime(df["fecha"], errors="coerce", utc=True)
            ultima = df["fecha"].max()
            ultima_txt = ultima.strftime("%Y-%m-%d %H:%M UTC") if pd.notna(ultima) else "—"
            kpi_grid([
                {"label": t("Análisis registrados"), "value": len(df), "color": "primary"},
                {"label": t("Objetivos distintos"), "value": int(df["url"].nunique()), "color": "low"},
                {"label": t("Hallazgos totales"), "value": int(df["hallazgos"].sum()), "color": "high"},
                {"label": t("Módulos con actividad"), "value": int(df["modulo"].nunique()), "color": "ok"},
                {"label": t("Última actividad"), "value": ultima_txt, "color": "low"},
            ])

            nombres_modulo = {"load": t("Carga"), "audit": t("Auditoría"), "port": t("Puertos")}

            def _estilo(figura):
                figura.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#e6edf7"), height=260,
                    margin=dict(t=10, b=10, l=10, r=10),
                )
                return figura

            col_modulo, col_dia = st.columns(2)
            with col_modulo:
                section_header(t("Actividad por módulo"), t("Análisis guardados"), "📊")
                por_modulo = df.groupby("modulo").size()
                st.plotly_chart(_estilo(go.Figure(go.Bar(
                    x=[nombres_modulo.get(m, m) for m in por_modulo.index],
                    y=list(por_modulo.values), marker_color="#22d3ee",
                ))), use_container_width=True)
            with col_dia:
                section_header(t("Actividad por día"), t("Análisis por fecha"), "📈")
                con_fecha = df.dropna(subset=["fecha"])
                if con_fecha.empty:
                    st.info(t("Sin fechas disponibles."))
                else:
                    por_dia = con_fecha.groupby(con_fecha["fecha"].dt.strftime("%Y-%m-%d")).size()
                    st.plotly_chart(_estilo(go.Figure(go.Bar(
                        x=list(por_dia.index), y=list(por_dia.values), marker_color="#22c55e",
                    ))), use_container_width=True)

            section_header(t("Últimos análisis"), t("Detalle de la actividad registrada"), "🕒")
            tabla(pd.DataFrame([{
                t("Fecha"): str(r.get("created_at", "")).replace("T", " ")[:16],
                t("Módulo"): nombres_modulo.get(r.get("modulo"), r.get("modulo", "")),
                t("Objetivo"): r.get("url", ""),
                t("Hallazgos"): int(r.get("total_hallazgos") or 0),
            } for r in registros]))
            st.caption(t("La actividad refleja análisis guardados; no es monitoreo en tiempo real."))

    elif seccion == "reports":
        if registros:
            _mostrar_reporte_ejecutivo(registros)
        else:
            st.info(t("No hay análisis guardados para generar un reporte."))

    elif seccion == "settings":
        columna_opciones, columna_apariencia = st.columns([1.4, 1])
        with columna_opciones:
            section_header(t("Autorización"), t("Condiciones previas de análisis"), "🔐")
            ui_authorization_check(st.session_state.get("autorizado", False))
            section_header(t("Red y auditoría"), t("Preferencias de esta sesión"), "⚙️")
            ui_internal_network_toggle()
            section_header(t("Opciones de inyección SQL"), t("Parámetros del escáner de inyección"), "🔧")
            ui_sqli_options()
            ui_audit_options()
        with columna_apariencia:
            section_header(t("Apariencia y almacenamiento"), t("Estado actual"), "🎨")
            ui_theme_selector()
            estado_datos = t("Conectado") if supabase_configurado else t("No configurado")
            st.markdown(
                f'<div style="background:#0b1a33;border:1px solid #12305a;'
                f'border-radius:8px;padding:14px;color:#e6edf7">'
                f'<div style="color:#9bb0c8;font-size:12px">{t("Historial de análisis")}</div>'
                f'<div style="font-weight:700;margin-top:7px">Supabase: {estado_datos}</div></div>',
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------- puertos
def grafico_gauge_seguridad(score: int) -> go.Figure:
    """Gauge 0-100 con el nivel de seguridad del host según sus puertos expuestos."""
    c = colores_actuales()
    color = c["ok"] if score >= 75 else c["med"] if score >= 50 else c["high"] if score >= 25 else c["crit"]
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number=dict(font=dict(size=34, color=c["text"])),
        title={"text": es_o_en("Nivel de seguridad de la página", "Site security level"),
               "font": {"size": 14, "color": c["muted"]}},
        gauge={
            "axis": {"range": [0, 100], "dtick": 20, "tickcolor": c["muted"]},
            "bar": {"color": color, "thickness": 0.72},
            "bgcolor": "rgba(0,0,0,0)", "borderwidth": 1, "bordercolor": c["grid"],
            "steps": [
                {"range": [75, 100], "color": "rgba(52, 211, 153, 0.14)"},
                {"range": [50, 75], "color": "rgba(56, 189, 248, 0.14)"},
                {"range": [25, 50], "color": "rgba(251, 146, 60, 0.14)"},
                {"range": [0, 25], "color": "rgba(248, 113, 113, 0.16)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.85, "value": score},
        },
    ))
    return _tema(fig)


def grafico_puertos_por_nivel(conteo: dict) -> go.Figure:
    """Donut con el reparto de puertos abiertos por nivel de riesgo."""
    c = colores_actuales()
    etiquetas = {
        "alto": es_o_en("Riesgo alto", "High risk"),
        "medio": es_o_en("Riesgo medio", "Medium risk"),
        "bajo": es_o_en("Riesgo bajo", "Low risk"),
    }
    niveles = [n for n in ("alto", "medio", "bajo") if conteo.get(n)]
    fig = go.Figure(data=[go.Pie(
        labels=[etiquetas[n] for n in niveles],
        values=[conteo[n] for n in niveles],
        marker=dict(colors=[c[_NIVEL_COLOR[n]] for n in niveles]),
        hole=0.55, textinfo="label+percent", textfont=dict(size=11),
    )])
    fig.update_layout(title=es_o_en("Puertos por nivel de riesgo", "Ports by risk level"),
                      showlegend=False)
    return _tema(fig)


def grafico_riesgo_por_puerto(amenazas: list) -> go.Figure:
    """Barras horizontales: cuánto descuenta cada puerto abierto en la puntuación."""
    c = colores_actuales()
    etiquetas = {
        "alto": es_o_en("Alto", "High"), "medio": es_o_en("Medio", "Medium"),
        "bajo": es_o_en("Bajo", "Low"),
    }
    filas = sorted(amenazas, key=lambda a: PESO_NIVEL.get(a["nivel"], PESO_NIVEL["medio"]))
    fig = go.Figure(go.Bar(
        y=[f"{a['puerto']}/{a['protocolo']} · {a['servicio']}" for a in filas],
        x=[PESO_NIVEL.get(a["nivel"], PESO_NIVEL["medio"]) for a in filas],
        orientation="h",
        marker_color=[c[_NIVEL_COLOR.get(a["nivel"], "info")] for a in filas],
        marker_line_width=0,
        text=[etiquetas.get(a["nivel"], a["nivel"]) for a in filas],
        textposition="outside",
        hovertemplate="%{y}<br>" + es_o_en("Puntos descontados", "Points deducted") + ": -%{x}<extra></extra>",
    ))
    fig.update_layout(
        title=es_o_en("Impacto de cada puerto en la puntuación", "Per-port impact on the score"),
        xaxis_title=es_o_en("Puntos descontados", "Points deducted"),
        yaxis_title=es_o_en("Puerto · servicio", "Port · service"),
        xaxis=dict(range=[0, max(PESO_NIVEL.values()) * 1.35]),
        yaxis=dict(automargin=True),
    )
    return _tema(fig)

import plotly.graph_objects as go
import pandas as pd
import streamlit as st

from models import history
from models.metrics import nivel_riesgo
from models.load_model import DURACION_MAXIMA_POR_NIVEL
from views.components import (
    colores_actuales, kpi_grid, section_header, tabla,
    ui_audit_options, ui_authorization_check, ui_internal_network_toggle,
    ui_theme_selector,
)

_SEV_KEY = {"Crítica": "crit", "Alta": "high", "Media": "med", "Baja": "low", "Info": "info"}


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
        title={"text": "Grado de salud (PGI)", "font": {"size": 14, "color": "#e6edf7"}},
        number={"font": {"color": "#e6edf7"}},
        gauge={"axis": {
            "tickcolor": "#e6edf7", "tickfont": {"color": "#e6edf7"},
        }, "bordercolor": "#12305a"},
    )
    return fig


def grafico_severidad_donub(por_severidad: dict) -> go.Figure:
    c = colores_actuales()
    labels = list(por_severidad.keys())
    values = list(por_severidad.values())
    colors = [_sev_color(l, c) for l in labels]
    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, marker=dict(colors=colors), hole=0.55,
        textinfo="label+percent", textfont=dict(size=11),
    )])
    fig.update_layout(title="Distribución de severidad", showlegend=False)
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
        ))
    fig.update_layout(title="Confianza por parámetro", barmode="group",
                      yaxis_title="Confianza (%)", xaxis_title="Parámetro")
    return _tema(fig)


def grafico_radar_cobertura(hallazgos: list) -> go.Figure:
    c = colores_actuales()
    tipos = ["error-based", "boolean-based blind", "time-based blind", "union-based"]
    valores = [1 if any(h.get("tipo") == t for h in hallazgos) else 0 for t in tipos]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=valores + [valores[0]], theta=tipos + [tipos[0]],
        fill="toself", fillcolor="rgba(99, 102, 241, 0.25)",
        line=dict(color=c["primary"], width=2), name="Cobertura",
    ))
    fig.update_layout(
        title="Cobertura de vectores de ataque",
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
            text=subset["param"], textposition="top center", name=nivel,
            textfont=dict(size=10, color=c["muted"]),
        ))
    fig.add_shape(type="rect", x0=3, x1=10, y0=3, y1=10, line=dict(width=0),
                  fillcolor="rgba(239,68,68,0.06)")
    fig.add_shape(type="rect", x0=6, x1=10, y0=6, y1=10, line=dict(width=0),
                  fillcolor="rgba(249,115,22,0.06)")
    fig.update_layout(title="Matriz de riesgo (Likelihood vs Impact)",
                      xaxis_title="Likelihood (CVSS Base)", yaxis_title="Impact",
                      xaxis=dict(range=[0, 11], dtick=2), yaxis=dict(range=[0, 11], dtick=2))
    return _tema(fig)


def grafico_gauge_riesgo(cvss_promedio: float, riesgo_global: str) -> go.Figure:
    c = colores_actuales()
    color = _sev_color(riesgo_global, c)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=cvss_promedio,
        number=dict(font=dict(size=34, color=c["text"])),
        title={"text": "Riesgo global (CVSS)", "font": {"size": 14, "color": c["muted"]}},
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
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_base"], mode="lines+markers", name="Base", line=dict(color=c["muted"], dash="dash")))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p50"], mode="lines+markers", name="p50", line=dict(color=c["ok"])))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p90"], mode="lines+markers", name="p90", line=dict(color=c["med"])))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p95"], mode="lines+markers", name="p95", line=dict(color=c["high"])))
    fig.add_trace(go.Scatter(x=df["concurrencia"], y=df["latencia_p99"], mode="lines+markers", name="p99", line=dict(color=c["crit"], width=3)))
    fig.update_layout(
        title="Latencia por percentil vs concurrencia",
        xaxis_title="Concurrencia (peticiones simultáneas)", yaxis_title="Latencia (s)",
        legend=dict(orientation="h", yanchor="top", y=-0.25, xanchor="center", x=0.5),
    )
    return _tema_carga(fig, leyenda_inferior=True)


def grafico_throughput(niveles: list) -> go.Figure:
    c = colores_actuales()
    df = pd.DataFrame(niveles)
    df["throughput"] = df["peticiones_totales"] / max(DURACION_MAXIMA_POR_NIVEL, 1)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=df["concurrencia"], y=df["throughput"], marker_color=c["primary"], marker_line_width=0))
    fig.update_layout(title="Throughput (peticiones/segundo) por nivel",
                      xaxis_title="Concurrencia", yaxis_title="Peticiones / segundo")
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
    fig.update_layout(title="Distribución de errores", showlegend=False)
    return _tema_carga(fig)


def grafico_gauge_pgi(pgi: float, salud: str) -> go.Figure:
    c = colores_actuales()
    color = {"Excelente": c["ok"], "Buena": c["low"], "Degradada": c["high"], "Crítica": c["crit"]}.get(salud, c["muted"])
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=pgi,
        number=dict(font=dict(size=34, color=c["text"])),
        title={"text": "Grado de salud (PGI)", "font": {"size": 14, "color": c["muted"]}},
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
    fig.add_trace(go.Bar(x=df["concurrencia"], y=df["tasa_error"], name="Tasa de error %", marker_color=c["crit"], marker_line_width=0))
    fig.add_trace(go.Bar(
        x=df["concurrencia"],
        y=df.get("errores", df["peticiones_totales"] * 0.01),
        name="Errores (nº)", marker_color=c["high"], marker_line_width=0, visible="legendonly",
    ))
    fig.update_layout(title="Tasa de error por nivel de concurrencia",
                      xaxis_title="Concurrencia", yaxis_title="%",
                      legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0))
    return _tema_carga(fig)


def mostrar_dashboard(registros: list, supabase_configurado: bool):
    registros = [item for item in (registros or []) if item.get("modulo") != "sqli"]
    etiquetas_modulo = {
        "load": "Prueba de Carga",
        "audit": "Auditoría Unificada",
        "port": "Escaneo de Puertos",
    }
    objetivos = {str(item.get("url", "")).strip() for item in registros if item.get("url")}
    modulos = {item.get("modulo") for item in registros if item.get("modulo")}
    total_hallazgos = sum(int(item.get("total_hallazgos") or 0) for item in registros)

    section_header(
        "Resumen de seguridad",
        "Actividad reciente y resultados registrados",
        "🛡️",
    )
    kpi_grid([
        {"label": "Análisis recientes", "value": len(registros), "sub": "Hasta 10 registros", "color": "primary"},
        {"label": "Hallazgos registrados", "value": total_hallazgos, "color": "high"},
        {"label": "Objetivos analizados", "value": len(objetivos), "color": "low"},
        {"label": "Módulos con actividad", "value": len(modulos), "color": "ok"},
    ])

    columna_actividad, columna_modulos = st.columns([1.4, 1])
    with columna_actividad:
        section_header("Evolución de actividad", "Análisis guardados por fecha", "📈")
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
                hovertemplate="%{x}<br>Análisis: %{y}<extra></extra>",
            ))
            figura_actividad.update_layout(
                title="Análisis por día", yaxis_title="Análisis",
                xaxis_title="", showlegend=False, height=300,
            )
            st.plotly_chart(_tema(figura_actividad), use_container_width=True)
        else:
            st.info("Todavía no hay fechas de análisis para mostrar.")

    with columna_modulos:
        section_header("Actividad por módulo", "Distribución de análisis guardados", "◉")
        conteo_modulos = {}
        for item in registros:
            modulo = item.get("modulo", "")
            etiqueta = etiquetas_modulo.get(modulo, modulo or "Otro")
            conteo_modulos[etiqueta] = conteo_modulos.get(etiqueta, 0) + 1
        if conteo_modulos:
            paleta = {"Prueba de Carga": "#22c55e", "Auditoría Unificada": "#22d3ee",
                      "Escaneo de Puertos": "#3b82f6"}
            figura_modulos = go.Figure(data=[go.Pie(
                labels=list(conteo_modulos), values=list(conteo_modulos.values()),
                hole=0.64,
                marker=dict(colors=[paleta.get(nombre, "#64748b") for nombre in conteo_modulos]),
                textinfo="label+percent", textfont=dict(color=colores_actuales()["text"]),
            )])
            figura_modulos.update_layout(
                showlegend=False, height=300,
                annotations=[dict(
                    text=f"{len(registros)}<br><span style='font-size:11px'>análisis</span>",
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=20, color=colores_actuales()["text"]),
                )],
                margin=dict(t=24, b=20, l=12, r=12),
            )
            st.plotly_chart(_tema(figura_modulos), use_container_width=True)
        else:
            st.info("La distribución aparecerá cuando haya análisis registrados.")

    section_header("Historial de auditorías", "Últimos análisis guardados", "🗂️")
    if registros:
        filas = [{
            "Fecha": str(item.get("created_at", "")).replace("T", " ")[:16],
            "Módulo": etiquetas_modulo.get(item.get("modulo"), item.get("modulo", "")),
            "Objetivo": item.get("url", ""),
            "Hallazgos": int(item.get("total_hallazgos") or 0),
            "Nivel": item.get("nivel") or "—",
        } for item in registros]
        tabla(pd.DataFrame(filas))
    else:
        st.info("No hay análisis guardados todavía. El historial aparecerá aquí al completar un análisis.")

    estado_datos = "Configurado" if supabase_configurado else "No configurado"
    st.caption(f"Almacenamiento de historial: Supabase {estado_datos}.")


def mostrar_seccion(seccion: str, registros: list, supabase_configurado: bool):
    nombres = {
        "vulnerabilities": "Vulnerabilidades",
        "assets": "Activos",
        "monitoring": "Monitoreo",
        "reports": "Reportes",
        "settings": "Configuración",
    }
    if seccion not in nombres:
        st.info("Selecciona una sección del menú.")
        return

    registros = [item for item in (registros or []) if item.get("modulo") != "sqli"]
    section_header(nombres[seccion], "Datos disponibles del historial de análisis", "◈")

    if seccion == "vulnerabilities":
        filas = []
        for registro in registros:
            scan_id = registro.get("id")
            for hallazgo in history.detalle(scan_id) if scan_id else []:
                filas.append({
                    "Fecha": str(registro.get("created_at", "")).replace("T", " ")[:16],
                    "Objetivo": registro.get("url", ""),
                    "Módulo": registro.get("modulo", ""),
                    "Hallazgo": hallazgo.get("descripcion") or hallazgo.get("tipo") or "Hallazgo",
                    "Severidad": hallazgo.get("severidad") or hallazgo.get("nivel_riesgo") or "INFO",
                    "OWASP": hallazgo.get("owasp") or "—",
                })
        if filas:
            df_hallazgos = pd.DataFrame(filas)
            kpi_grid([
                {"label": "Hallazgos", "value": len(filas), "color": "high"},
                {"label": "Críticos", "value": sum(normalize_severity(f) == "CRÍTICO" for f in df_hallazgos["Severidad"]), "color": "crit"},
                {"label": "Altos", "value": sum(normalize_severity(f) == "ALTO" for f in df_hallazgos["Severidad"]), "color": "high"},
            ])
            tabla(df_hallazgos)
        else:
            st.info("No hay vulnerabilidades guardadas en los análisis recientes.")

    elif seccion == "assets":
        activos = {}
        for registro in registros:
            objetivo = str(registro.get("url") or "").strip()
            if objetivo and objetivo not in activos:
                activos[objetivo] = {
                    "Objetivo": objetivo,
                    "Último análisis": str(registro.get("created_at", "")).replace("T", " ")[:16],
                    "Módulo": registro.get("modulo", ""),
                    "Hallazgos": int(registro.get("total_hallazgos") or 0),
                }
        if activos:
            kpi_grid([
                {"label": "Objetivos registrados", "value": len(activos), "color": "low"},
                {"label": "Registros revisados", "value": len(registros), "color": "primary"},
            ])
            tabla(pd.DataFrame(list(activos.values())))
        else:
            st.info("Los objetivos aparecerán aquí después de guardar un análisis.")

    elif seccion == "monitoring":
        if registros:
            fechas = pd.to_datetime(
                [registro.get("created_at") for registro in registros],
                errors="coerce", utc=True,
            ).dropna().sort_values()
            última_fecha = fechas.max().strftime("%Y-%m-%d %H:%M UTC") if not fechas.empty else "Fecha no disponible"
            módulos = {registro.get("modulo") for registro in registros if registro.get("modulo")}
            kpi_grid([
                {"label": "Análisis registrados", "value": len(registros), "color": "primary"},
                {"label": "Módulos con actividad", "value": len(módulos), "color": "ok"},
                {"label": "Actividad más reciente", "value": última_fecha, "color": "low"},
            ])
            tabla(pd.DataFrame([{
                "Fecha": str(registro.get("created_at", "")).replace("T", " ")[:16],
                "Módulo": registro.get("modulo", ""),
                "Objetivo": registro.get("url", ""),
                "Hallazgos": int(registro.get("total_hallazgos") or 0),
            } for registro in registros]))
            st.caption("La actividad refleja análisis guardados; no representa monitoreo en tiempo real.")
        else:
            st.info("No hay actividad de análisis registrada todavía.")

    elif seccion == "reports":
        if registros:
            informe = pd.DataFrame([{
                "fecha": registro.get("created_at", ""),
                "modulo": registro.get("modulo", ""),
                "objetivo": registro.get("url", ""),
                "hallazgos": int(registro.get("total_hallazgos") or 0),
                "nivel": registro.get("nivel") or "",
                "score": registro.get("score") if registro.get("score") is not None else "",
            } for registro in registros])
            st.download_button(
                "Descargar CSV",
                data=informe.to_csv(index=False).encode("utf-8-sig"),
                file_name="reporte_vulnweb.csv",
                mime="text/csv",
                key="download_vulnweb_report",
            )
            tabla(informe)
        else:
            st.info("No hay análisis guardados para generar un reporte.")

    elif seccion == "settings":
        columna_opciones, columna_apariencia = st.columns([1.4, 1])
        with columna_opciones:
            section_header("Autorización", "Condiciones previas de análisis", "🔐")
            ui_authorization_check(st.session_state.get("autorizado", False))
            section_header("Red y auditoría", "Preferencias de esta sesión", "⚙️")
            ui_internal_network_toggle()
            ui_audit_options()
        with columna_apariencia:
            section_header("Apariencia y almacenamiento", "Estado actual", "🎨")
            ui_theme_selector()
            estado_datos = "Conectado" if supabase_configurado else "No configurado"
            st.markdown(
                f'<div style="background:#0b1a33;border:1px solid #12305a;'
                f'border-radius:8px;padding:14px;color:#e6edf7">'
                f'<div style="color:#9bb0c8;font-size:12px">Historial de análisis</div>'
                f'<div style="font-weight:700;margin-top:7px">Supabase: {estado_datos}</div></div>',
                unsafe_allow_html=True,
            )

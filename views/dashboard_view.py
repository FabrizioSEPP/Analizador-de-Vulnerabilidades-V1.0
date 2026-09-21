import plotly.graph_objects as go
import pandas as pd

from models.metrics import nivel_riesgo
from models.load_model import DURACION_MAXIMA_POR_NIVEL
from views.components import colores_actuales

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
    tipos = ["error-based", "boolean-based blind", "time-based blind"]
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
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0),
    )
    return _tema(fig)


def grafico_throughput(niveles: list) -> go.Figure:
    c = colores_actuales()
    df = pd.DataFrame(niveles)
    df["throughput"] = df["peticiones_totales"] / max(DURACION_MAXIMA_POR_NIVEL, 1)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=df["concurrencia"], y=df["throughput"], marker_color=c["primary"], marker_line_width=0))
    fig.update_layout(title="Throughput (peticiones/segundo) por nivel",
                      xaxis_title="Concurrencia", yaxis_title="Peticiones / segundo")
    return _tema(fig)


def grafico_error_pie(tipo_error: dict) -> go.Figure:
    c = colores_actuales()
    if not tipo_error:
        return _tema(go.Figure())
    fig = go.Figure(data=[go.Pie(
        labels=list(tipo_error.keys()), values=list(tipo_error.values()),
        marker=dict(colors=[c["crit"], c["high"], c["med"], c["ok"], c["muted"]]), hole=0.55,
        textinfo="label+percent", textfont=dict(size=11),
    )])
    fig.update_layout(title="Distribución de errores", showlegend=False)
    return _tema(fig)


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
    return _tema(fig)


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
    return _tema(fig)

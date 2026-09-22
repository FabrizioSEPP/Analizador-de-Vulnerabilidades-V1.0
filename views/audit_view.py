import html as _html

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from models.risk_score import (
    security_score, classification, exposure_level, to_summary, normalize_severity,
)
from models.phishing_ml import detectar_phishing
from models.remediation import get_remediation
from views.components import (
    kpi_grid, section_header, tabla, color_severidad, colores_actuales,
)

_SEV_ICONS = {
    "CRÍTICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🔵", "INFO": "⚪",
}


def mostrar(resultado: dict):
    section_header(
        "Auditoría Unificada",
        "Rastreo del sitio, análisis profundo del servicio y detección de phishing",
        "🛡️",
    )

    url = resultado.get("url", "")
    hallazgos = resultado.get("hallazgos", [])
    c = colores_actuales()
    sc = security_score(hallazgos)
    cls = classification(sc)
    exp = exposure_level(sc)
    summary = to_summary(hallazgos)
    color_score = c["ok"] if sc >= 75 else c["med"] if sc >= 55 else c["crit"]

    st.markdown(f"""
    <div style="background:linear-gradient(120deg,var(--hero-1),var(--hero-2));
                border:1px solid var(--border);border-radius:16px;padding:16px 20px;margin-bottom:16px;
                display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
        <div>
            <div style="font-size:.95rem;font-weight:700;color:var(--text);">
                Auditoría de seguridad · <span style="color:var(--primary);word-break:break-all;">{_html.escape(url)}</span>
            </div>
            <div style="font-size:.75rem;color:var(--muted);margin-top:5px;">
                {len(hallazgos)} hallazgo(s) · {summary['critical']} críticos · {summary['high']} altos
            </div>
        </div>
        <div style="font-size:1.05rem;font-weight:800;color:{color_score};">{sc}/100 · {cls}</div>
    </div>
    """, unsafe_allow_html=True)

    cards = [
        {"label": "Security score", "value": f"{sc}/100", "color": "ok" if sc >= 75 else "med" if sc >= 55 else "crit"},
        {"label": "Exposición", "value": exp, "color": "low"},
        {"label": "Críticos", "value": str(summary["critical"]), "color": "crit"},
        {"label": "Altos", "value": str(summary["high"]), "color": "high"},
        {"label": "Medios", "value": str(summary["medium"]), "color": "med"},
        {"label": "Totales", "value": str(len(hallazgos)), "color": "primary"},
    ]
    kpi_grid(cards)

    if hallazgos:
        section_header("Hallazgos por severidad", "Agrupados y con remediación OWASP sugerida", "🔎")
        for sev in ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]:
            sev_hallazgos = [h for h in hallazgos
                             if normalize_severity(h.get("nivel_riesgo", h.get("severidad", "INFO"))) == sev]
            if not sev_hallazgos:
                continue
            color = color_severidad(sev)
            icon = _SEV_ICONS[sev]
            with st.expander(f"{icon} {sev} ({len(sev_hallazgos)})", expanded=False):
                for h in sev_hallazgos:
                    mod = h.get("modulo", "unknown")
                    rem = get_remediation(mod)
                    st.markdown(f"""
                    <div class="finding" style="--f-color:{color}">
                        <div class="finding-head">{icon} {_html.escape(str(h.get('descripcion', 'Hallazgo')))}</div>
                        <div class="finding-meta">{_html.escape(str(mod))} · OWASP {_html.escape(str(h.get('owasp', '?')))}</div>
                        <div class="finding-body">{_html.escape(str(h.get('explicacion', h.get('evidencia', ''))))}</div>
                        <div class="finding-rem"><b>Remediación:</b> {rem.get('what', '')} — <i>{rem.get('where', '')}</i></div>
                    </div>
                    """, unsafe_allow_html=True)

    prof = resultado.get("deep_analysis") or {}
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### 🔬 Análisis profundo")
        st.markdown(f"**Score:** {prof.get('score_vulnerabilidad', 0)}/100 ({prof.get('nivel_vulnerabilidad', 'N/A')})")
        st.markdown(f"**Páginas rastreadas:** {prof.get('total_paginas', 0)}")
        st.markdown(f"**Hallazgos:** {prof.get('total_errores', 0)}")
    with col2:
        phish = resultado.get("phishing")
        if not phish:
            phish = detectar_phishing(url) if url else {"resultado": "N/A", "score_riesgo": 0}
        phish_res = phish.get("resultado", "N/A")
        icono = "🎯" if phish_res == "PHISHING" else "✅" if phish_res == "LEGITIMA" else "❓"
        st.markdown("#### 🎯 Detección de phishing (ML)")
        st.markdown(f"**Resultado:** {icono} {phish_res}")
        st.markdown(f"**Score de riesgo:** {phish.get('score_riesgo', 0)}%")
        st.markdown(f"**Confianza del modelo:** {phish.get('confianza', 0)}%")

    tecnologias = prof.get("tecnologias") or []
    paginas = prof.get("paginas") or []
    if tecnologias or paginas:
        if tecnologias:
            pills = "".join(f'<span class="pill pill-mode" style="margin-right:6px;">{_html.escape(t)}</span>' for t in tecnologias)
            st.markdown(f'<div style="margin:14px 0 6px;"><b>🧬 Tecnologías detectadas:</b> {pills}</div>', unsafe_allow_html=True)
        if paginas:
            with st.expander(f"🌐 Páginas rastreadas ({len(paginas)})", expanded=False):
                tabla(pd.DataFrame([
                    {"URL": p.get("url", ""), "HTTP": p.get("status", 0),
                     "Título": p.get("titulo", ""), "Hallazgos": p.get("hallazgos", "")}
                    for p in paginas
                ]))

    if hallazgos:
        section_header("Distribución de severidad", "Reparto de hallazgos por criticidad", "📊")
        sev_counts = {}
        for h in hallazgos:
            sev = normalize_severity(h.get("nivel_riesgo", h.get("severidad", "INFO")))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        labels = [s for s in ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"] if s in sev_counts]
        fig = go.Figure(data=[go.Pie(
            labels=labels, values=[sev_counts[s] for s in labels],
            marker=dict(colors=[color_severidad(s) for s in labels]), hole=0.55,
            textinfo="label+percent",
        )])
        fig.update_layout(
            template=c["template"], paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, Segoe UI, sans-serif", color=c["text"]),
            title=dict(text="Distribución de hallazgos", font=dict(size=15, color=c["text"]), x=0.02, xanchor="left"),
            margin=dict(t=54, b=24, l=24, r=24), showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)


def mostrar_solo_sql(resultado: dict):
    from views.sqli_view import mostrar as mostrar_sqli
    mostrar_sqli(resultado)

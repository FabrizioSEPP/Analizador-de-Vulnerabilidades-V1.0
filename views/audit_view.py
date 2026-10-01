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
from models.i18n import t, es_o_en

_SEV_ICONS = {
    "CRÍTICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🔵", "INFO": "⚪",
}


def mostrar(resultado: dict):
    section_header(
        es_o_en("Auditoría Unificada", "Unified Audit"),
        es_o_en("Rastreo del sitio, análisis profundo del servicio y detección de phishing",
                "Site crawling, deep service analysis and phishing detection"),
        "🛡️",
    )

    url = resultado.get("url", "")
    hallazgos = resultado.get("hallazgos", [])
    c = colores_actuales()
    sc = security_score(hallazgos)
    cls = t(classification(sc))
    exp = t(exposure_level(sc))
    summary = to_summary(hallazgos)
    color_score = c["ok"] if sc >= 75 else c["med"] if sc >= 55 else c["crit"]

    st.markdown(f"""
    <div style="background:linear-gradient(120deg,var(--hero-1),var(--hero-2));
                border:1px solid var(--border);border-radius:16px;padding:16px 20px;margin-bottom:16px;
                display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
        <div>
            <div style="font-size:.95rem;font-weight:700;color:var(--text);">
                {_html.escape(es_o_en("Auditoría de seguridad", "Security audit"))} · <span style="color:var(--primary);word-break:break-all;">{_html.escape(url)}</span>
            </div>
            <div style="font-size:.75rem;color:var(--muted);margin-top:5px;">
                {len(hallazgos)} {es_o_en("hallazgo(s)", "finding(s)")} · {summary['critical']} {es_o_en("críticos", "critical")} · {summary['high']} {es_o_en("altos", "high")}
            </div>
        </div>
        <div style="font-size:1.05rem;font-weight:800;color:{color_score};">{sc}/100 · {cls}</div>
    </div>
    """, unsafe_allow_html=True)

    cards = [
        {"label": es_o_en("Security score", "Security score"), "value": f"{sc}/100", "color": "ok" if sc >= 75 else "med" if sc >= 55 else "crit"},
        {"label": es_o_en("Exposición", "Exposure"), "value": exp, "color": "low"},
        {"label": es_o_en("Críticos", "Critical"), "value": str(summary["critical"]), "color": "crit"},
        {"label": es_o_en("Altos", "High"), "value": str(summary["high"]), "color": "high"},
        {"label": es_o_en("Medios", "Medium"), "value": str(summary["medium"]), "color": "med"},
        {"label": es_o_en("Totales", "Total"), "value": str(len(hallazgos)), "color": "primary"},
    ]
    kpi_grid(cards)

    if hallazgos:
        section_header(es_o_en("Hallazgos por severidad", "Findings by severity"),
                       es_o_en("Agrupados y con remediación OWASP sugerida",
                               "Grouped with suggested OWASP remediation"), "🔎")
        for sev in ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]:
            sev_hallazgos = [h for h in hallazgos
                             if normalize_severity(h.get("nivel_riesgo", h.get("severidad", "INFO"))) == sev]
            if not sev_hallazgos:
                continue
            color = color_severidad(sev)
            icon = _SEV_ICONS[sev]
            with st.expander(f"{icon} {t(sev)} ({len(sev_hallazgos)})", expanded=False):
                for h in sev_hallazgos:
                    mod = h.get("modulo", "unknown")
                    rem = get_remediation(mod)
                    st.markdown(f"""
                    <div class="finding" style="--f-color:{color}">
                        <div class="finding-head">{icon} {_html.escape(str(t(str(h.get('descripcion', t('Hallazgo'))))))}</div>
                        <div class="finding-meta">{_html.escape(str(mod))} · OWASP {_html.escape(str(h.get('owasp', '?')))}</div>
                        <div class="finding-body">{_html.escape(str(t(str(h.get('explicacion', h.get('evidencia', ''))))))}</div>
                        <div class="finding-rem"><b>{t('Remediación:')}</b> {t(str(rem.get('what', '')))} — <i>{t(str(rem.get('where', '')))}</i></div>
                    </div>
                    """, unsafe_allow_html=True)

    prof = resultado.get("deep_analysis") or {}
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"#### 🔬 {t('Análisis profundo')}")
        st.markdown(f"**{t('Score:')}** {prof.get('score_vulnerabilidad', 0)}/100 ({t(str(prof.get('nivel_vulnerabilidad', 'N/A')))})")
        st.markdown(f"**{t('Páginas rastreadas:')}** {prof.get('total_paginas', 0)}")
        st.markdown(f"**{t('Hallazgos:')}** {prof.get('total_errores', 0)}")
    with col2:
        phish = resultado.get("phishing")
        if not phish:
            phish = detectar_phishing(url) if url else {"resultado": "N/A", "score_riesgo": 0}
        phish_res = phish.get("resultado", "N/A")
        icono = "🎯" if phish_res == "PHISHING" else "✅" if phish_res == "LEGITIMA" else "❓"
        st.markdown(f"#### 🎯 {t('Detección de phishing (ML)')}")
        st.markdown(f"**{t('Resultado:')}** {icono} {t(str(phish_res))}")
        st.markdown(f"**{t('Score de riesgo:')}** {phish.get('score_riesgo', 0)}%")
        st.markdown(f"**{t('Confianza del modelo:')}** {phish.get('confianza', 0)}%")

    tecnologias = prof.get("tecnologias") or []
    paginas = prof.get("paginas") or []
    if tecnologias or paginas:
        if tecnologias:
            pills = "".join(f'<span class="pill pill-mode" style="margin-right:6px;">{_html.escape(tec)}</span>' for tec in tecnologias)
            st.markdown(f'<div style="margin:14px 0 6px;"><b>🧬 {t("Tecnologías detectadas:")}</b> {pills}</div>', unsafe_allow_html=True)
        if paginas:
            with st.expander(t("🌐 Páginas rastreadas ({}):").format(len(paginas)), expanded=False):
                tabla(pd.DataFrame([
                    {t("URL"): p.get("url", ""), "HTTP": p.get("status", 0),
                     t("Título"): p.get("titulo", ""), t("Hallazgos"): p.get("hallazgos", "")}
                    for p in paginas
                ]))

    if hallazgos:
        section_header(es_o_en("Distribución de severidad", "Severity distribution"),
                       es_o_en("Reparto de hallazgos por criticidad", "Breakdown of findings by criticality"), "📊")
        sev_counts = {}
        for h in hallazgos:
            sev = normalize_severity(h.get("nivel_riesgo", h.get("severidad", "INFO")))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        labels = [s for s in ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"] if s in sev_counts]
        fig = go.Figure(data=[go.Pie(
            labels=[t(s) for s in labels], values=[sev_counts[s] for s in labels],
            marker=dict(colors=[color_severidad(s) for s in labels]), hole=0.55,
            textinfo="label+percent",
        )])
        fig.update_layout(
            template=c["template"], paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, Segoe UI, sans-serif", color=c["text"]),
            title=dict(text=t("Distribución de hallazgos"), font=dict(size=15, color=c["text"]), x=0.02, xanchor="left"),
            margin=dict(t=54, b=24, l=24, r=24), showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)


def mostrar_solo_sql(resultado: dict):
    from views.sqli_view import mostrar as mostrar_sqli
    mostrar_sqli(resultado)

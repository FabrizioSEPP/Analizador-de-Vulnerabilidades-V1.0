import html as _html
import re as _re
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from models.risk_score import (
    security_score, classification, exposure_level, to_summary, normalize_severity,
)
from models.phishing_ml import detectar_phishing
from models.remediation import get_remediation
from models.port_scanner import (
    puntuacion_seguridad, nivel_general, resumen_por_nivel,
    generar_reporte_markdown, generar_reporte_pdf, EMOJI_NIVEL, ETIQUETA_NIVEL,
)
from views.components import (
    kpi_grid, section_header, tabla, aviso, color_severidad, colores_actuales,
)
from views.dashboard_view import (
    grafico_gauge_seguridad, grafico_puertos_por_nivel, grafico_riesgo_por_puerto,
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


# --------------------------------------------------------------------- puertos
_NIVEL_COLOR_TOKEN = {"alto": "crit", "medio": "med", "bajo": "ok"}


def mostrar_puertos(resultado: dict, amenazas: list):
    """Dashboard del escaneo de puertos: nivel de seguridad, gráficos, detalle y descarga del informe."""
    section_header(
        es_o_en("Escaneo de puertos", "Port scanning"),
        es_o_en("Servicios expuestos en el host y nivel de seguridad de la página",
                "Exposed services on the host and site security level"),
        "🔌",
    )

    c = colores_actuales()
    host = str(resultado.get("host", ""))
    ip = str(resultado.get("ip", ""))
    rango = str(resultado.get("rango", "1-1024"))
    amenazas = amenazas or []
    total = int(resultado.get("total_puertos", len(amenazas)))
    score = puntuacion_seguridad(amenazas)
    nivel = nivel_general(amenazas)
    color_score = c["ok"] if score >= 75 else c["med"] if score >= 50 else c["crit"]

    st.markdown(f"""
    <div style="background:linear-gradient(120deg,var(--hero-1),var(--hero-2));
                border:1px solid var(--border);border-radius:16px;padding:16px 20px;margin-bottom:16px;
                display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
        <div>
            <div style="font-size:.95rem;font-weight:700;color:var(--text);">
                {es_o_en("Análisis de puertos", "Port analysis")} · <span style="color:var(--primary);word-break:break-all;">{_html.escape(host)}</span>
            </div>
            <div style="font-size:.75rem;color:var(--muted);margin-top:5px;">
                IP {_html.escape(ip)} · {es_o_en("Rango", "Range")} {_html.escape(rango)} ·
                {total} {es_o_en("puerto(s) abierto(s)", "open port(s)")}
            </div>
        </div>
        <div style="font-size:1.05rem;font-weight:800;color:{color_score};">{score}/100 · {EMOJI_NIVEL[nivel]} {ETIQUETA_NIVEL[nivel]}</div>
    </div>
    """, unsafe_allow_html=True)

    cards = [
        {"label": es_o_en("Puertos abiertos", "Open ports"), "value": total,
         "color": _NIVEL_COLOR_TOKEN[nivel] if amenazas else "ok"},
        {"label": es_o_en("Riesgo general", "Overall risk"),
         "value": f"{EMOJI_NIVEL[nivel]} {ETIQUETA_NIVEL[nivel]}", "color": _NIVEL_COLOR_TOKEN[nivel]},
        {"label": es_o_en("Puntuación de seguridad", "Security score"), "value": f"{score}/100",
         "color": "ok" if score >= 75 else "med" if score >= 50 else "crit"},
        {"label": es_o_en("Rango escaneado", "Scanned range"), "value": rango, "color": "primary"},
    ]
    kpi_grid(cards)

    if amenazas:
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(grafico_gauge_seguridad(score), use_container_width=True)
        with col2:
            st.plotly_chart(grafico_puertos_por_nivel(resumen_por_nivel(amenazas)), use_container_width=True)
        st.plotly_chart(grafico_riesgo_por_puerto(amenazas), use_container_width=True)

        section_header(es_o_en("Detalle de puertos abiertos", "Open port details"),
                       es_o_en("Clasificación de riesgo y recomendaciones por servicio",
                               "Risk classification and recommendations per service"), "🔎")
        tabla(pd.DataFrame([
            {
                es_o_en("Puerto", "Port"): f"{a['puerto']}/{a['protocolo']}",
                es_o_en("Servicio", "Service"): a["servicio"],
                es_o_en("Nivel", "Level"): f"{EMOJI_NIVEL[a['nivel']]} {ETIQUETA_NIVEL[a['nivel']]}",
                es_o_en("Hallazgo", "Finding"): a["nombre"],
            }
            for a in amenazas
        ]))

        for a in amenazas:
            with st.expander(
                f"{EMOJI_NIVEL[a['nivel']]} {a['puerto']}/{a['protocolo']} · {a['servicio']} — {a['nombre']}",
                expanded=False,
            ):
                st.markdown(f"**{es_o_en('Amenaza:', 'Threat:')}** {a['amenaza']}")
                st.markdown(f"**{es_o_en('Recomendaciones:', 'Recommendations:')}**")
                for rec in a["recomendaciones"]:
                    st.markdown(f"- {rec}")
    else:
        st.plotly_chart(grafico_gauge_seguridad(score), use_container_width=True)
        aviso("success", es_o_en("No se encontraron puertos abiertos en el rango escaneado.",
                                 "No open ports found in the scanned range."))

    _bloque_descarga(resultado, amenazas)


def _bloque_descarga(resultado: dict, amenazas: list):
    """Selector de formato (.md / .pdf) + botón de descarga del informe de puertos."""
    section_header(es_o_en("Descargar informe", "Download report"),
                   es_o_en("Elige el formato y guárdalo para compartir con el equipo",
                           "Choose the format and save it to share with your team"), "📥")

    formato = st.segmented_control(
        es_o_en("Formato", "Format"),
        options=["Markdown", "PDF"],
        default="Markdown",
        key="port_scan_formato",
    )
    formato = formato or "Markdown"

    if formato == "PDF":
        try:
            datos = generar_reporte_pdf(resultado, amenazas)
            mime, ext = "application/pdf", ".pdf"
        except ImportError:
            aviso("warning", es_o_en(
                "Falta la librería `reportlab` para generar PDF. Instálala con "
                "`pip install reportlab` o descarga el informe en Markdown.",
                "The `reportlab` library is missing, so PDF cannot be generated. "
                "Install it with `pip install reportlab` or download the report as Markdown."))
            datos = generar_reporte_markdown(resultado, amenazas).encode("utf-8")
            mime, ext = "text/markdown", ".md"
    else:
        datos = generar_reporte_markdown(resultado, amenazas).encode("utf-8")
        mime, ext = "text/markdown", ".md"

    host_seg = _re.sub(r"[^A-Za-z0-9._-]", "_", str(resultado.get("host", "target"))) or "target"
    fecha = datetime.now().strftime("%Y%m%d-%H%M")
    st.download_button(
        label=f"⬇️ {es_o_en('Descargar informe', 'Download report')} ({ext})",
        data=datos,
        file_name=f"informe_puertos_{host_seg}_{fecha}{ext}",
        mime=mime,
        type="primary",
        key="port_scan_descarga",
    )

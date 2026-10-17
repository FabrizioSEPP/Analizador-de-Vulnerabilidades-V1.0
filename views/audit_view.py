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
from models.i18n import t, es_o_en
from models.port_scanner import (
    puntuacion_seguridad, nivel_general, resumen_por_nivel,
    generar_reporte_markdown, generar_reporte_pdf, EMOJI_NIVEL, ETIQUETA_NIVEL,
    localizar_amenazas,
)
from views.components import (
    kpi_grid, section_header, tabla, aviso, color_severidad, colores_actuales,
)
from views.dashboard_view import (
    grafico_gauge_seguridad, grafico_puertos_por_nivel, grafico_riesgo_por_puerto,
)

_SEV_ICONS = {
    "CRÍTICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🔵", "INFO": "⚪",
}


def mostrar_inicio(url: str, autorizado: bool, modo: str, historial: list):
    etiquetas_modo = {
        "load": t("Prueba de Carga"),
        "audit": t("Auditoría Unificada"),
        "port": t("Escaneo de Puertos"),
    }
    ultima_auditoria = next(
        (item for item in historial if item.get("modulo") == "audit"), None
    )
    ultima_fecha = (
        str(ultima_auditoria.get("created_at", "")).replace("T", " ")[:16]
        if ultima_auditoria else t("Sin auditorías registradas")
    )
    estado = t("Autorizado") if autorizado else t("Pendiente")
    color_estado = "#22c55e" if autorizado else "#facc15"
    tipo_analisis = t("Completo") if modo == "audit" else t(etiquetas_modo.get(modo, "Completo"))

    st.markdown(
        '<div style="display:flex;align-items:center;gap:18px;margin:24px 0 28px">'
        '<span data-testid="stIconMaterial" translate="no" style="font-family:\'Material Symbols Rounded\';'
        'font-size:58px;font-weight:400;font-feature-settings:\'liga\';color:#22d3ee;line-height:1">shield</span>'
        f'<div><div style="font-size:28px;font-weight:700;color:#e6edf7">{t("Auditoría Unificada")}</div>'
        f'<div style="font-size:14px;color:#9bb0c8;margin-top:5px">'
        f'{t("Rastreo del sitio, análisis profundo del servicio y detección de phishing")}</div></div>'
        '<div style="margin-left:auto;border:1px solid #087c9b;border-radius:999px;'
        'padding:8px 13px;color:#22d3ee;font-size:12px;font-weight:700;white-space:nowrap">'
        f'◉ {t("OWASP + Otros")}</div></div>',
        unsafe_allow_html=True,
    )
    resumen = st.columns([1.7, 0.8, 0.9, 1.1])
    with resumen[0]:
        st.markdown(
            '<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
            'border-radius:8px;padding:16px">'
            f'<div style="color:#9bb0c8;font-size:12px">{t("Objetivo de auditoría")}</div>'
            f'<div style="color:#e6edf7;font-weight:600;margin-top:10px;word-break:break-all">'
            f'{_html.escape(url) if url else t("Ingresa un objetivo en la barra superior")}</div></div>',
            unsafe_allow_html=True,
        )
    with resumen[1]:
        st.markdown(
            '<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
            'border-radius:8px;padding:16px">'
            f'<div style="color:#9bb0c8;font-size:12px">{t("Autorización")}</div>'
            f'<div style="color:{color_estado};font-weight:700;margin-top:10px">● {estado}</div></div>',
            unsafe_allow_html=True,
        )
    with resumen[2]:
        st.markdown(
            "<style>.st-key-audit-analysis-type-card {background:#0b1a33; "
            "border:1px solid #12305a; border-radius:8px; padding:12px 14px; "
            "min-height:82px;} "
            ".st-key-audit-analysis-type-card [data-baseweb='select'] > div {"
            "background:#10274b; border-color:#12305a;}</style>",
            unsafe_allow_html=True,
        )
        with st.container(key="audit-analysis-type-card"):
            st.markdown(
                f'<div style="color:#9bb0c8;font-size:12px;margin-bottom:4px">{t("Tipo de análisis")}</div>',
                unsafe_allow_html=True,
            )
            st.selectbox(
                t("Tipo de análisis"),
                options=[tipo_analisis],
                index=0,
                key="audit_analysis_type",
                label_visibility="collapsed",
            )
    with resumen[3]:
        st.markdown(
            '<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
            'border-radius:8px;padding:16px">'
            f'<div style="color:#9bb0c8;font-size:12px">{t("Última auditoría")}</div>'
            f'<div style="color:#e6edf7;font-weight:600;margin-top:10px">{_html.escape(ultima_fecha)}</div></div>',
            unsafe_allow_html=True,
        )

    section_header(t("Módulos de análisis"), t("Herramientas disponibles para el objetivo"), "🧭")
    st.markdown(
        """
        <style>
        .st-key-audit-card-load, .st-key-audit-card-audit, .st-key-audit-card-port {
            min-height: 238px;
            padding: 16px 18px 10px;
            margin: 8px 0 14px;
            background: linear-gradient(145deg, #0b1a33, #08172d);
            border: 1px solid #12305a;
            border-radius: 12px;
        }
        .st-key-audit-card-load { border-left: 3px solid #22c55e; }
        .st-key-audit-card-audit { border-left: 3px solid #22d3ee; }
        .st-key-audit-card-port { border-left: 3px solid #38bdf8; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    modulos = [
        {
            "modo": "load", "icono": "bolt", "titulo": t("Prueba de Carga"),
            "descripcion": t("Evalúa latencia, capacidad y comportamiento bajo concurrencia."),
            "detalle": t("Simulación de usuarios y carga"),
            "color": "#22c55e",
        },
        {
            "modo": "audit", "icono": "shield", "titulo": t("Auditoría Unificada"),
            "descripcion": t("Rastrea el sitio y analiza exposición, configuración y phishing."),
            "detalle": t("Rastreo, detección y recomendaciones"),
            "color": "#22d3ee",
        },
        {
            "modo": "port", "icono": "hub", "titulo": t("Escaneo de Puertos"),
            "descripcion": t("Detecta puertos TCP abiertos y servicios expuestos."),
            "detalle": t("Identificación de servicios y puertos"),
            "color": "#38bdf8",
        },
    ]
    columnas = st.columns(2)
    for indice, modulo in enumerate(modulos):
        columna = columnas[indice % 2]
        with columna:
            with st.container(key=f"audit-card-{modulo['modo']}"):
                st.markdown(
                    f'<div style="display:flex;align-items:center;gap:16px;min-height:112px">'
                    f'<div style="width:58px;height:58px;flex:0 0 58px;display:grid;place-items:center;'
                    f'border:1px solid {modulo["color"]};border-radius:50%;'
                    f'background:rgba(6,13,31,.55)">'
                    f'<span data-testid="stIconMaterial" translate="no" style="font-family:\'Material Symbols Rounded\';'
                    f'font-size:32px;font-feature-settings:\'liga\';color:{modulo["color"]}">'
                    f'{modulo["icono"]}</span></div>'
                    f'<div><div style="font-size:18px;font-weight:700;color:#e6edf7">{modulo["titulo"]}</div>'
                    f'<div style="font-size:13px;color:#9bb0c8;margin-top:7px;line-height:1.45">{modulo["descripcion"]}</div></div>'
                    '</div>',
                    unsafe_allow_html=True,
                )
                columna_detalle, columna_configurar = st.columns([1.3, 1], vertical_alignment="center")
                with columna_detalle:
                    st.markdown(
                        f'<div style="font-size:12px;color:#9bb0c8">◈ {modulo["detalle"]}</div>',
                        unsafe_allow_html=True,
                    )
                with columna_configurar:
                    if st.button(t("Configurar →"), key=f"audit_module_{modulo['modo']}", use_container_width=True):
                        st.session_state["selected_mode"] = modulo["modo"]
                        st.session_state["app_view"] = "dashboard"
                        st.rerun()


def mostrar(resultado: dict):
    url = resultado.get("url", "")
    hallazgos = resultado.get("hallazgos", [])
    c = colores_actuales()
    sc = security_score(hallazgos)
    cls = classification(sc)
    exp = exposure_level(sc)
    summary = to_summary(hallazgos)
    score_color = c["ok"] if sc >= 90 else c["med"] if sc >= 55 else c["crit"]
    fecha = str(resultado.get("fecha") or t("Fecha no disponible"))
    autorizado = st.session_state.get("autorizado", False)
    estado = t("Autorizado") if autorizado else t("Completado")
    color_estado = "#22c55e" if autorizado else "#22d3ee"

    st.markdown(
        '<div style="display:flex;align-items:center;gap:16px;margin:16px 0 22px">'
        '<span data-testid="stIconMaterial" translate="no" style="font-family:\'Material Symbols Rounded\';'
        'font-size:60px;font-weight:400;font-feature-settings:\'liga\';color:#22d3ee;line-height:1">shield</span>'
        f'<div><div style="font-size:26px;font-weight:700;color:#e6edf7">{t("Auditoría Unificada")}</div>'
        f'<div style="font-size:13px;color:#9bb0c8;margin-top:4px">'
        f'{t("Rastreo del sitio, análisis profundo del servicio y detección de phishing")}</div></div>'
        '<div style="margin-left:auto;border:1px solid #087c9b;border-radius:999px;'
        'padding:8px 13px;color:#22d3ee;font-size:12px;font-weight:700;white-space:nowrap">'
        f'◉ {t("OWASP + Otros")}</div></div>',
        unsafe_allow_html=True,
    )

    metadatos = st.columns([2.4, 1, 1, 1.35])
    valores_metadata = [
        ("target", t("Objetivo de auditoría"), url or t("Objetivo no disponible"), "link"),
        ("mode", t("Modo de análisis"), t("Auditoría Unificada"), "layers"),
        ("status", t("Estado"), estado, "verified_user"),
        ("date", t("Última auditoría"), fecha, "event"),
    ]
    for indice, (clave, etiqueta, valor, icono) in enumerate(valores_metadata):
        with metadatos[indice]:
            color_valor = color_estado if clave == "status" else "#e6edf7"
            subtitulo = (
                f"{len(hallazgos)} {t('hallazgos')} · {summary['critical']} {t('críticos')} · "
                f"{summary['high']} {t('altos')}"
                if clave == "target" else valor
            )
            st.markdown(
                f'<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
                f'border-radius:8px;padding:13px 14px">'
                f'<div style="display:flex;align-items:center;gap:7px;font-size:12px;color:#9bb0c8">'
                f'<span data-testid="stIconMaterial" translate="no" style="font-family:\'Material Symbols Rounded\';'
                f'font-size:18px;font-feature-settings:\'liga\';color:#38bdf8">{icono}</span>{etiqueta}</div>'
                f'<div style="font-size:14px;font-weight:650;color:{color_valor};margin-top:8px;'
                f'word-break:break-word">{_html.escape(str(valor))}</div>'
                f'{f"<div style=\"font-size:11px;color:#9bb0c8;margin-top:4px\">{_html.escape(subtitulo)}</div>" if clave == "target" else ""}'
                '</div>',
                unsafe_allow_html=True,
            )

    st.markdown(
        """
        <style>
        .st-key-audit-score-card {
            background:linear-gradient(145deg,#0b1a33,#08172d);
            border:1px solid #12305a;border-left:3px solid #22d3ee;
            border-radius:8px;padding:8px 12px 14px;min-height:212px;
        }
        .audit-severity-card {
            min-height:94px;padding:14px 12px;background:#0b1a33;
            border:1px solid #12305a;border-radius:8px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    columna_score, *columnas_severidad = st.columns([1.55, 1, 1, 1, 1, 1.1], vertical_alignment="center")
    with columna_score:
        with st.container(key="audit-score-card"):
            st.markdown(
                f'<div style="font-size:12px;font-weight:700;color:#9bb0c8;margin:8px 0 0 8px">'
                f'{es_o_en("PUNTUACIÓN DE SEGURIDAD", "SECURITY SCORE")}</div>',
                unsafe_allow_html=True,
            )
            figura_score = go.Figure(go.Indicator(
                mode="gauge+number",
                value=sc,
                number={"suffix": f"<br><span style='font-size:11px'>{t('de 100')}</span>", "font": {"size": 30, "color": "#e6edf7"}},
                gauge={
                    "axis": {"range": [0, 100], "showticklabels": False, "ticks": ""},
                    "bar": {"color": score_color, "thickness": 0.28},
                    "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
                    "steps": [
                        {"range": [0, 55], "color": "rgba(248,113,113,.12)"},
                        {"range": [55, 75], "color": "rgba(250,204,21,.12)"},
                        {"range": [75, 100], "color": "rgba(34,211,238,.12)"},
                    ],
                },
            ))
            figura_score.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=172, margin=dict(t=4, b=0, l=16, r=16),
                font=dict(color="#e6edf7"),
            )
            st.plotly_chart(figura_score, use_container_width=True, config={"displayModeBar": False})
            st.markdown(
                f'<div style="text-align:center;font-size:12px;color:{score_color};font-weight:700">'
                f'{_html.escape(t(cls))} · {t("EXPOSICIÓN")} {_html.escape(t(exp))}</div>',
                unsafe_allow_html=True,
            )

    severidades = [
        (t("Críticas"), summary["critical"], "#fb7185", "✕"),
        (t("Altas"), summary["high"], "#f97316", "△"),
        (t("Medias"), summary["medium"], "#facc15", "▲"),
        (t("Bajas"), summary["low"], "#22d3ee", "ⓘ"),
        (t("Informativas"), summary["info"], "#94a3b8", "ⓘ"),
    ]
    for columna, (etiqueta, cantidad, color, icono) in zip(columnas_severidad, severidades):
        with columna:
            st.markdown(
                f'<div class="audit-severity-card">'
                f'<div style="display:flex;align-items:center;gap:8px;color:{color};font-size:13px;font-weight:650">'
                f'<span style="width:25px;height:25px;display:grid;place-items:center;border:1px solid {color};'
                f'border-radius:50%">{icono}</span>{etiqueta}</div>'
                f'<div style="font-size:25px;font-weight:750;color:{color};margin-top:14px">{cantidad}</div></div>',
                unsafe_allow_html=True,
            )

    if hallazgos:
        section_header(t("Matriz de inspección técnica"), t("Hallazgos detectados y acciones sugeridas"), "🔎")
        filas_matriz = []
        for hallazgo in hallazgos:
            severidad = normalize_severity(
                hallazgo.get("nivel_riesgo", hallazgo.get("severidad", "INFO"))
            )
            modulo = hallazgo.get("modulo", "unknown")
            remediacion = hallazgo.get("remediacion") or get_remediation(modulo).get("what", "—")
            filas_matriz.append({
                t("Control"): t(str(hallazgo.get("descripcion", hallazgo.get("tipo", t("Hallazgo"))))),
                t("Estado"): t("Detectado"),
                t("Severidad"): t(severidad),
                t("Evidencia"): t(str(hallazgo.get("evidencia", "—"))),
                t("Impacto"): t(str(hallazgo.get("explicacion", "—"))),
                t("Acción"): t(str(remediacion)),
            })
        tabla(pd.DataFrame(filas_matriz))

        section_header(t("Detalle y remediación"), t("Evidencia técnica agrupada por severidad OWASP"), "🧰")
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
                    <div style="background:#0b1a33;border:1px solid #12305a;border-left:3px solid {color};
                                border-radius:8px;padding:16px;margin:10px 0;color:#e6edf7">
                        <div style="font-weight:700">{icon} {_html.escape(t(str(h.get('descripcion', t('Hallazgo')))))}</div>
                        <div style="font-size:12px;color:#9bb0c8;margin:6px 0">{_html.escape(str(mod))} · OWASP {_html.escape(str(h.get('owasp', '?')))}</div>
                        <div style="line-height:1.5">{_html.escape(t(str(h.get('explicacion', h.get('evidencia', '')))))}</div>
                        <div style="margin-top:10px"><b>{t("Remediación:")}</b> {_html.escape(str(rem.get('what', '')))} — <i>{_html.escape(str(rem.get('where', '')))}</i></div>
                    </div>
                    """, unsafe_allow_html=True)

    prof = resultado.get("deep_analysis") or {}
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"#### 🔬 {t('Análisis profundo')}")
        st.markdown(f"**{t('Score')}:** {prof.get('score_vulnerabilidad', 0)}/100 ({t(str(prof.get('nivel_vulnerabilidad', 'N/A')))})")
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
            with st.expander(t("Páginas rastreadas ({})").format(len(paginas)), expanded=False):
                tabla(pd.DataFrame([
                    {"URL": p.get("url", ""), "HTTP": p.get("status", 0),
                     t("Título"): p.get("titulo", ""), t("Hallazgos"): p.get("hallazgos", "")}
                    for p in paginas
                ]))

    if hallazgos:
        section_header(t("Distribución de severidad"), t("Reparto de hallazgos por criticidad"), "📊")
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
_NIVEL_EN = {"alto": "High risk", "medio": "Medium risk", "bajo": "Low risk"}


def _etiqueta_nivel(nivel: str) -> str:
    return es_o_en(ETIQUETA_NIVEL.get(nivel, nivel), _NIVEL_EN.get(nivel, nivel))


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
    amenazas = localizar_amenazas(amenazas or [])
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
        <div style="font-size:1.05rem;font-weight:800;color:{color_score};">{score}/100 · {EMOJI_NIVEL[nivel]} {_etiqueta_nivel(nivel)}</div>
    </div>
    """, unsafe_allow_html=True)

    cards = [
        {"label": es_o_en("Puertos abiertos", "Open ports"), "value": total,
         "color": _NIVEL_COLOR_TOKEN[nivel] if amenazas else "ok"},
        {"label": es_o_en("Riesgo general", "Overall risk"),
         "value": f"{EMOJI_NIVEL[nivel]} {_etiqueta_nivel(nivel)}", "color": _NIVEL_COLOR_TOKEN[nivel]},
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
                es_o_en("Nivel", "Level"): f"{EMOJI_NIVEL[a['nivel']]} {_etiqueta_nivel(a['nivel'])}",
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

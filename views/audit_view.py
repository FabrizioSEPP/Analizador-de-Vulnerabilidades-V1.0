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


def mostrar_inicio(url: str, autorizado: bool, modo: str, historial: list):
    etiquetas_modo = {
        "load": "Prueba de Carga",
        "audit": "Auditoría Unificada",
        "port": "Escaneo de Puertos",
    }
    ultima_auditoria = next(
        (item for item in historial if item.get("modulo") == "audit"), None
    )
    ultima_fecha = (
        str(ultima_auditoria.get("created_at", "")).replace("T", " ")[:16]
        if ultima_auditoria else "Sin auditorías registradas"
    )
    estado = "Autorizado" if autorizado else "Pendiente"
    color_estado = "#22c55e" if autorizado else "#facc15"
    tipo_analisis = "Completo" if modo == "audit" else etiquetas_modo.get(modo, "Completo")

    st.markdown(
        '<div style="display:flex;align-items:center;gap:18px;margin:24px 0 28px">'
        '<span data-testid="stIconMaterial" translate="no" style="font-family:\'Material Symbols Rounded\';'
        'font-size:58px;font-weight:400;font-feature-settings:\'liga\';color:#22d3ee;line-height:1">shield</span>'
        '<div><div style="font-size:28px;font-weight:700;color:#e6edf7">Auditoría Unificada</div>'
        '<div style="font-size:14px;color:#9bb0c8;margin-top:5px">'
        'Rastreo del sitio, análisis profundo del servicio y detección de phishing</div></div>'
        '<div style="margin-left:auto;border:1px solid #087c9b;border-radius:999px;'
        'padding:8px 13px;color:#22d3ee;font-size:12px;font-weight:700;white-space:nowrap">'
        '◉ OWASP + Otros</div></div>',
        unsafe_allow_html=True,
    )
    resumen = st.columns([1.7, 0.8, 0.9, 1.1])
    with resumen[0]:
        st.markdown(
            '<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
            'border-radius:8px;padding:16px">'
            '<div style="color:#9bb0c8;font-size:12px">Objetivo de auditoría</div>'
            f'<div style="color:#e6edf7;font-weight:600;margin-top:10px;word-break:break-all">'
            f'{_html.escape(url) if url else "Ingresa un objetivo en la barra superior"}</div></div>',
            unsafe_allow_html=True,
        )
    with resumen[1]:
        st.markdown(
            '<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
            'border-radius:8px;padding:16px">'
            '<div style="color:#9bb0c8;font-size:12px">Autorización</div>'
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
                '<div style="color:#9bb0c8;font-size:12px;margin-bottom:4px">Tipo de análisis</div>',
                unsafe_allow_html=True,
            )
            st.selectbox(
                "Tipo de análisis",
                options=[tipo_analisis],
                index=0,
                key="audit_analysis_type",
                label_visibility="collapsed",
            )
    with resumen[3]:
        st.markdown(
            '<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
            'border-radius:8px;padding:16px">'
            '<div style="color:#9bb0c8;font-size:12px">Última auditoría</div>'
            f'<div style="color:#e6edf7;font-weight:600;margin-top:10px">{_html.escape(ultima_fecha)}</div></div>',
            unsafe_allow_html=True,
        )

    section_header("Módulos de análisis", "Herramientas disponibles para el objetivo", "🧭")
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
            "modo": "load", "icono": "bolt", "titulo": "Prueba de Carga",
            "descripcion": "Evalúa latencia, capacidad y comportamiento bajo concurrencia.",
            "detalle": "Simulación de usuarios y carga",
            "color": "#22c55e",
        },
        {
            "modo": "audit", "icono": "shield", "titulo": "Auditoría Unificada",
            "descripcion": "Rastrea el sitio y analiza exposición, configuración y phishing.",
            "detalle": "Rastreo, detección y recomendaciones",
            "color": "#22d3ee",
        },
        {
            "modo": "port", "icono": "hub", "titulo": "Escaneo de Puertos",
            "descripcion": "Detecta puertos TCP abiertos y servicios expuestos.",
            "detalle": "Identificación de servicios y puertos",
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
                    if st.button("Configurar →", key=f"audit_module_{modulo['modo']}", use_container_width=True):
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
    fecha = str(resultado.get("fecha") or "Fecha no disponible")
    autorizado = st.session_state.get("autorizado", False)
    estado = "Autorizado" if autorizado else "Completado"
    color_estado = "#22c55e" if autorizado else "#22d3ee"

    st.markdown(
        '<div style="display:flex;align-items:center;gap:16px;margin:16px 0 22px">'
        '<span data-testid="stIconMaterial" translate="no" style="font-family:\'Material Symbols Rounded\';'
        'font-size:60px;font-weight:400;font-feature-settings:\'liga\';color:#22d3ee;line-height:1">shield</span>'
        '<div><div style="font-size:26px;font-weight:700;color:#e6edf7">Auditoría Unificada</div>'
        '<div style="font-size:13px;color:#9bb0c8;margin-top:4px">'
        'Rastreo del sitio, análisis profundo del servicio y detección de phishing</div></div>'
        '<div style="margin-left:auto;border:1px solid #087c9b;border-radius:999px;'
        'padding:8px 13px;color:#22d3ee;font-size:12px;font-weight:700;white-space:nowrap">'
        '◉ OWASP + Otros</div></div>',
        unsafe_allow_html=True,
    )

    metadatos = st.columns([2.4, 1, 1, 1.35])
    valores_metadata = [
        ("Objetivo de auditoría", url or "Objetivo no disponible", "link"),
        ("Modo de análisis", "Auditoría Unificada", "layers"),
        ("Estado", estado, "verified_user"),
        ("Última auditoría", fecha, "event"),
    ]
    for indice, (etiqueta, valor, icono) in enumerate(valores_metadata):
        with metadatos[indice]:
            color_valor = color_estado if etiqueta == "Estado" else "#e6edf7"
            subtitulo = (
                f"{len(hallazgos)} hallazgos · {summary['critical']} críticos · {summary['high']} altos"
                if etiqueta == "Objetivo de auditoría" else valor
            )
            st.markdown(
                f'<div style="min-height:82px;background:#0b1a33;border:1px solid #12305a;'
                f'border-radius:8px;padding:13px 14px">'
                f'<div style="display:flex;align-items:center;gap:7px;font-size:12px;color:#9bb0c8">'
                f'<span data-testid="stIconMaterial" translate="no" style="font-family:\'Material Symbols Rounded\';'
                f'font-size:18px;font-feature-settings:\'liga\';color:#38bdf8">{icono}</span>{etiqueta}</div>'
                f'<div style="font-size:14px;font-weight:650;color:{color_valor};margin-top:8px;'
                f'word-break:break-word">{_html.escape(str(valor))}</div>'
                f'{f"<div style=\"font-size:11px;color:#9bb0c8;margin-top:4px\">{_html.escape(subtitulo)}</div>" if etiqueta == "Objetivo de auditoría" else ""}'
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
                '<div style="font-size:12px;font-weight:700;color:#9bb0c8;margin:8px 0 0 8px">SECURITY SCORE</div>',
                unsafe_allow_html=True,
            )
            figura_score = go.Figure(go.Indicator(
                mode="gauge+number",
                value=sc,
                number={"suffix": "<br><span style='font-size:11px'>de 100</span>", "font": {"size": 30, "color": "#e6edf7"}},
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
                f'{_html.escape(cls)} · EXPOSICIÓN { _html.escape(exp) }</div>',
                unsafe_allow_html=True,
            )

    severidades = [
        ("Críticas", summary["critical"], "#fb7185", "✕"),
        ("Altas", summary["high"], "#f97316", "△"),
        ("Medias", summary["medium"], "#facc15", "▲"),
        ("Bajas", summary["low"], "#22d3ee", "ⓘ"),
        ("Informativas", summary["info"], "#94a3b8", "ⓘ"),
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
        section_header("Matriz de inspección técnica", "Hallazgos detectados y acciones sugeridas", "🔎")
        filas_matriz = []
        for hallazgo in hallazgos:
            severidad = normalize_severity(
                hallazgo.get("nivel_riesgo", hallazgo.get("severidad", "INFO"))
            )
            modulo = hallazgo.get("modulo", "unknown")
            remediacion = hallazgo.get("remediacion") or get_remediation(modulo).get("what", "—")
            filas_matriz.append({
                "Control": hallazgo.get("descripcion", hallazgo.get("tipo", "Hallazgo")),
                "Estado": "Detectado",
                "Severidad": severidad,
                "Evidencia": hallazgo.get("evidencia", "—"),
                "Impacto": hallazgo.get("explicacion", "—"),
                "Acción": remediacion,
            })
        tabla(pd.DataFrame(filas_matriz))

        section_header("Detalle y remediación", "Evidencia técnica agrupada por severidad OWASP", "🧰")
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
                    <div style="background:#0b1a33;border:1px solid #12305a;border-left:3px solid {color};
                                border-radius:8px;padding:16px;margin:10px 0;color:#e6edf7">
                        <div style="font-weight:700">{icon} {_html.escape(str(h.get('descripcion', 'Hallazgo')))}</div>
                        <div style="font-size:12px;color:#9bb0c8;margin:6px 0">{_html.escape(str(mod))} · OWASP {_html.escape(str(h.get('owasp', '?')))}</div>
                        <div style="line-height:1.5">{_html.escape(str(h.get('explicacion', h.get('evidencia', ''))))}</div>
                        <div style="margin-top:10px"><b>Remediación:</b> {_html.escape(str(rem.get('what', '')))} — <i>{_html.escape(str(rem.get('where', '')))}</i></div>
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

import streamlit as st
import pandas as pd

from models.metrics import calcular_metricas_sqli
from views.components import kpi_grid, section_header, aviso, tabla
from views.dashboard_view import (
    grafico_severidad_donub, grafico_confianza_por_parametro,
    grafico_radar_cobertura, grafico_risk_matrix,
    grafico_gauge_riesgo,
)


def mostrar(resultado: dict):
    section_header(
        "Escáner de Inyección SQL",
        "Hallazgos, puntuación CVSS y cobertura de vectores de ataque",
        "🔍",
    )

    metricas = calcular_metricas_sqli(resultado)
    objetivos = resultado.get("objetivos", [])
    cards = [
        {"label": "Puntos analizados", "value": len(objetivos), "color": "primary"},
        {"label": "Total hallazgos", "value": metricas["total_hallazgos"],
         "color": "crit" if metricas["total_hallazgos"] > 0 else "ok"},
        {"label": "CVSS promedio", "value": f'{metricas["cvss_promedio"]}/10',
         "color": "high" if metricas["cvss_promedio"] >= 6 else "ok"},
        {"label": "Riesgo global", "value": metricas["riesgo_global"],
         "color": "crit" if metricas["riesgo_global"] == "Crítica" else "high" if metricas["riesgo_global"] == "Alta" else "ok"},
        {"label": "Confianza media", "value": f'{metricas["confianza_promedio"]}%', "color": "low"},
        {"label": "Cobertura vectores", "value": f'{metricas["cobertura_vectores"]:.0f}%', "color": "primary"},
        {"label": "Parámetros afectados", "value": len(metricas["por_parametro"]), "color": "med"},
    ]
    kpi_grid(cards)

    if resultado.get("detalle"):
        aviso("info", resultado["detalle"])

    if resultado.get("diagnostico"):
        with st.expander("🧪 Diagnóstico (por qué se descartó u omitió algo)", expanded=False):
            for n in resultado["diagnostico"]:
                st.markdown(f"- {n}")

    if resultado["vulnerable"]:
        aviso("error", "🚨 **¡Vulnerabilidad de inyección SQL detectada!**")
    elif objetivos:
        aviso("success", "✅ **No se detectaron vulnerabilidades claras.**")
    else:
        aviso("warning", "⚠️ No se encontraron parámetros ni formularios que analizar en la página.")

    if objetivos:
        with st.expander(f"🔎 Puntos de inyección analizados ({len(objetivos)})", expanded=False):
            tabla(pd.DataFrame([
                {"Parámetro": o["param"], "Método": o["method"],
                 "Origen": o.get("origen", ""), "Endpoint": o["url"]}
                for o in objetivos
            ]))

    if metricas["hallazgos_con_cvss"]:
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            if metricas["por_severidad"]:
                st.plotly_chart(grafico_severidad_donub(metricas["por_severidad"]), use_container_width=True)
        with col_g2:
            st.plotly_chart(grafico_radar_cobertura(resultado["hallazgos"]), use_container_width=True)

        col_g3, col_g4 = st.columns(2)
        with col_g3:
            st.plotly_chart(grafico_gauge_riesgo(metricas["cvss_promedio"], metricas["riesgo_global"]), use_container_width=True)
        with col_g4:
            st.plotly_chart(grafico_confianza_por_parametro(metricas["hallazgos_con_cvss"]), use_container_width=True)

        section_header("Matriz de riesgo", "Relación entre probabilidad e impacto de cada hallazgo")
        st.plotly_chart(grafico_risk_matrix(metricas["hallazgos_con_cvss"]), use_container_width=True)

    _mostrar_hallazgos_detallados(metricas)

    if metricas["recomendaciones"]:
        section_header("Recomendaciones de remediación", "Priorizadas según la severidad CVSS", "📋")
        for rec in metricas["recomendaciones"]:
            st.markdown(rec)


def _mostrar_hallazgos_detallados(metricas: dict):
    if not metricas["hallazgos_con_cvss"]:
        st.markdown(
            '<div class="empty-state">✅ No hay hallazgos que detallar en este análisis.</div>',
            unsafe_allow_html=True,
        )
        return

    section_header("Vulnerabilidades detectadas", "Detalle técnico, evidencia y vector CVSS", "🧪")

    for i, h in enumerate(metricas["hallazgos_con_cvss"], 1):
        cvss = h.get("cvss", 0)
        nivel = h.get("nivel_riesgo", "")
        tipo_label = {
            "error-based": "Error-Based",
            "boolean-based blind": "Boolean-Based Blind",
            "time-based blind": "Time-Based Blind",
            "union-based": "UNION-Based",
        }.get(h.get("tipo", ""), h.get("tipo", ""))

        with st.expander(f"Hallazgo #{i} — {tipo_label} en `{h.get('parametro', '')}` · {nivel} · CVSS {cvss}", expanded=False):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Parámetro:** `{h.get('parametro', '')}`")
                st.markdown(f"**Tipo:** {tipo_label}")
                st.markdown(f"**Método:** {h.get('metodo', 'GET')}")
                if h.get("origen"):
                    st.markdown(f"**Origen:** {h.get('origen')}")
                if h.get("url_objetivo"):
                    st.markdown(f"**Endpoint:** `{h.get('url_objetivo')}`")
                st.markdown(f"**Severidad:** {nivel}")
                st.markdown(f"**CVSS:** {cvss}/10")
                st.markdown(f"**Confianza:** {h.get('confianza', 0)}%")
                st.markdown(f"**Vector CVSS:** `{h.get('vector_cvss', '')}`")
                motor = h.get("motor_sugerido", h.get("indicadores", "N/A"))
                st.markdown(f"**Motor sugerido:** {motor}")

            with col2:
                st.markdown("**💡 Explicación del hallazgo**")
                aviso("info", h.get("explicacion", "No disponible"))
                if h.get("payload"):
                    st.markdown(f"**Payload utilizado:** `{h.get('payload')}`")
                if h.get("evidencia"):
                    st.markdown(f"**Evidencia:** {h.get('evidencia')}")
                if h.get("codigo_http"):
                    st.markdown(f"**Código HTTP base:** {h.get('codigo_http')}")
                if h.get("datos_extraidos"):
                    st.markdown(f"**Datos extraídos:** `{h['datos_extraidos']}`")
                if h.get("reproducir"):
                    st.markdown("**Reproducir (curl):**")
                    st.code(h["reproducir"], language="bash")

    df_data = []
    for h in metricas["hallazgos_con_cvss"]:
        df_data.append({
            "Tipo": h.get("tipo", ""),
            "Parámetro": h.get("parametro", ""),
            "Método": h.get("metodo", "GET"),
            "CVSS": h.get("cvss", 0),
            "Nivel": h.get("nivel_riesgo", ""),
            "Confianza": f'{h.get("confianza", 0)}%',
            "Explicación": h.get("explicacion", "")[:200] + "...",
            "Motor": h.get("motor_sugerido", h.get("indicadores", "")),
        })
    tabla(pd.DataFrame(df_data))

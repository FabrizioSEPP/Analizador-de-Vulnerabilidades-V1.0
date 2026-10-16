import streamlit as st
import pandas as pd

from models.metrics import calcular_metricas_sqli
from views.components import kpi_grid, section_header, aviso, tabla
from views.dashboard_view import (
    grafico_severidad_donub, grafico_confianza_por_parametro,
    grafico_radar_cobertura, grafico_risk_matrix,
    grafico_gauge_riesgo,
)
from models.i18n import t, es_o_en


def mostrar(resultado: dict):
    section_header(
        es_o_en("Escáner de Inyección SQL", "SQL Injection Scanner"),
        es_o_en("Hallazgos, puntuación CVSS y cobertura de vectores de ataque",
                "Findings, CVSS score and attack vector coverage"),
        "🔍",
    )

    metricas = calcular_metricas_sqli(resultado)
    objetivos = resultado.get("objetivos", [])
    cards = [
        {"label": es_o_en("Puntos analizados", "Points analyzed"), "value": len(objetivos), "color": "primary"},
        {"label": es_o_en("Total hallazgos", "Total findings"), "value": metricas["total_hallazgos"],
         "color": "crit" if metricas["total_hallazgos"] > 0 else "ok"},
        {"label": es_o_en("CVSS promedio", "Average CVSS"), "value": f'{metricas["cvss_promedio"]}/10',
         "color": "high" if metricas["cvss_promedio"] >= 6 else "ok"},
        {"label": es_o_en("Riesgo global", "Overall risk"), "value": t(metricas["riesgo_global"]),
         "color": "crit" if metricas["riesgo_global"] == "Crítica" else "high" if metricas["riesgo_global"] == "Alta" else "ok"},
        {"label": es_o_en("Confianza media", "Average confidence"), "value": f'{metricas["confianza_promedio"]}%', "color": "low"},
        {"label": es_o_en("Cobertura vectores", "Vector coverage"), "value": f'{metricas["cobertura_vectores"]:.0f}%', "color": "primary"},
        {"label": es_o_en("Parámetros afectados", "Affected parameters"), "value": len(metricas["por_parametro"]), "color": "med"},
    ]
    kpi_grid(cards)

    if resultado.get("detalle"):
        aviso("info", t(resultado["detalle"]))

    if resultado.get("diagnostico"):
        with st.expander(es_o_en("🧪 Diagnóstico (por qué se descartó u omitió algo)",
                                  "🧪 Diagnostics (why something was skipped or omitted)"), expanded=False):
            for n in resultado["diagnostico"]:
                st.markdown(f"- {t(str(n))}")

    if resultado["vulnerable"]:
        aviso("error", "🚨 **" + es_o_en("¡Vulnerabilidad de inyección SQL detectada!",
                                         "SQL injection vulnerability detected!") + "**")
    elif objetivos:
        aviso("success", "✅ **" + es_o_en("No se detectaron vulnerabilidades claras.",
                                           "No clear vulnerabilities detected.") + "**")
    else:
        aviso("warning", "⚠️ " + es_o_en("No se encontraron parámetros ni formularios que analizar en la página.",
                                         "No parameters or forms to analyze were found on the page."))

    if objetivos:
        with st.expander(t("🔎 Puntos de inyección analizados ({}):").format(len(objetivos)), expanded=False):
            tabla(pd.DataFrame([
                {t("Parámetro"): o["param"], t("Método"): o["method"],
                 t("Origen"): o.get("origen", ""), t("Endpoint"): o["url"]}
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

        section_header(es_o_en("Matriz de riesgo", "Risk matrix"),
                       es_o_en("Relación entre probabilidad e impacto de cada hallazgo",
                               "Relationship between likelihood and impact of each finding"))
        st.plotly_chart(grafico_risk_matrix(metricas["hallazgos_con_cvss"]), use_container_width=True)

    _mostrar_hallazgos_detallados(metricas)

    if metricas["recomendaciones"]:
        section_header(es_o_en("Recomendaciones de remediación", "Remediation recommendations"),
                       es_o_en("Priorizadas según la severidad CVSS", "Prioritized by CVSS severity"), "📋")
        for rec in metricas["recomendaciones"]:
            st.markdown(t(rec))


def _mostrar_hallazgos_detallados(metricas: dict):
    if not metricas["hallazgos_con_cvss"]:
        st.markdown(
            '<div class="empty-state">%s</div>' % es_o_en("✅ No hay hallazgos que detallar en este análisis.",
                                                         "✅ No findings to detail in this analysis."),
            unsafe_allow_html=True,
        )
        return

    section_header(es_o_en("Vulnerabilidades detectadas", "Detected vulnerabilities"),
                   es_o_en("Detalle técnico, evidencia y vector CVSS",
                           "Technical detail, evidence and CVSS vector"), "🧪")

    for i, h in enumerate(metricas["hallazgos_con_cvss"], 1):
        cvss = h.get("cvss", 0)
        nivel = t(h.get("nivel_riesgo", ""))
        tipo_label = {
            "error-based": "Error-Based",
            "boolean-based blind": "Boolean-Based Blind",
            "time-based blind": "Time-Based Blind",
            "union-based": "UNION-Based",
        }.get(h.get("tipo", ""), h.get("tipo", ""))

        with st.expander(t("Hallazgo #{}").format(i) + f" — {tipo_label} en `{h.get('parametro', '')}` · {nivel} · CVSS {cvss}", expanded=False):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**{t('Parámetro')}:** `{h.get('parametro', '')}`")
                st.markdown(f"**{t('Tipo')}:** {tipo_label}")
                st.markdown(f"**{t('Método')}:** {h.get('metodo', 'GET')}")
                if h.get("origen"):
                    st.markdown(f"**{t('Origen')}:** {t(str(h.get('origen')))}")
                if h.get("url_objetivo"):
                    st.markdown(f"**{t('Endpoint')}:** `{h.get('url_objetivo')}`")
                st.markdown(f"**{t('Severidad')}:** {t(str(h.get('nivel_riesgo', '')))}")
                st.markdown(f"**{t('CVSS')}:** {cvss}/10")
                st.markdown(f"**{t('Confianza')}:** {h.get('confianza', 0)}%")
                st.markdown(f"**{t('Vector CVSS')}:** `{h.get('vector_cvss', '')}`")
                motor = h.get("motor_sugerido", h.get("indicadores", "N/A"))
                st.markdown(f"**{t('Motor sugerido')}:** {t(str(motor))}")

            with col2:
                st.markdown(f"**💡 {t('Explicación del hallazgo')}**")
                aviso("info", t(str(h.get("explicacion", t("No disponible")))))
                if h.get("payload"):
                    st.markdown(f"**{t('Payload utilizado')}:** `{h.get('payload')}`")
                if h.get("evidencia"):
                    st.markdown(f"**{t('Evidencia')}:** {t(str(h.get('evidencia')))}")
                if h.get("codigo_http"):
                    st.markdown(f"**{t('Código HTTP base')}:** {h.get('codigo_http')}")
                if h.get("datos_extraidos"):
                    st.markdown(f"**{t('Datos extraídos')}:** `{h['datos_extraidos']}`")
                if h.get("reproducir"):
                    st.markdown(f"**{t('Reproducir (curl):')}**")
                    st.code(h["reproducir"], language="bash")

    df_data = []
    for h in metricas["hallazgos_con_cvss"]:
        df_data.append({
            t("Tipo"): h.get("tipo", ""),
            t("Parámetro"): h.get("parametro", ""),
            t("Método"): h.get("metodo", "GET"),
            "CVSS": h.get("cvss", 0),
            t("Nivel"): t(str(h.get("nivel_riesgo", ""))),
            t("Confianza"): f'{h.get("confianza", 0)}%',
            t("Explicación"): t(str(h.get("explicacion", "")))[:200] + "...",
            t("Motor"): t(str(h.get("motor_sugerido", h.get("indicadores", "")))),
        })
    tabla(pd.DataFrame(df_data))

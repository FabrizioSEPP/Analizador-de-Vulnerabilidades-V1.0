import streamlit as st
import pandas as pd

from models.metrics import calcular_metricas_load
from views.components import kpi_grid, section_header, tabla
from views.dashboard_view import (
    grafico_latencia_percentiles, grafico_throughput,
    grafico_error_pie, grafico_gauge_pgi, grafico_barra_estado,
)
from models.i18n import t, es_o_en


def mostrar(resultado: dict):
    section_header(
        es_o_en("Prueba de Capacidad", "Capacity Test"),
        es_o_en("Latencia, throughput y grado de salud del sistema (PGI)",
                "Latency, throughput and system health score (PGI)"),
        "⚡",
    )

    metricas = calcular_metricas_load(resultado)
    cards = [
        {"label": es_o_en("Capacidad estimada", "Estimated capacity"),
         "value": f'{metricas["capacidad"]} {es_o_en("simultáneas", "concurrent")}',
         "color": "ok" if metricas["capacidad"] > 10 else "high"},
        {"label": es_o_en("Latencia base", "Baseline latency"), "value": f'{metricas["latencia_base"]:.4f}s', "color": "low"},
        {"label": es_o_en("Grado salud (PGI)", "Health score (PGI)"), "value": f'{metricas["grado_pgi"]}/100',
         "color": "ok" if metricas["grado_pgi"] >= 75 else "high" if metricas["grado_pgi"] >= 50 else "crit"},
        {"label": es_o_en("Salud global", "Overall health"), "value": t(str(metricas["salud_global"])),
         "color": "ok" if metricas["salud_global"] in ["Excelente", "Buena"] else "high" if metricas["salud_global"] == "Degradada" else "crit"},
        {"label": es_o_en("Tasa error máx", "Max error rate"), "value": f'{metricas["tasa_error_max"]:.2f}%',
         "color": "crit" if metricas["tasa_error_max"] > 5 else "ok"},
        {"label": es_o_en("Volatilidad máx", "Max volatility"), "value": f'{metricas["volatilidad_max"]:.2f}',
         "color": "med" if metricas["volatilidad_max"] > 0.5 else "ok"},
    ]
    kpi_grid(cards)

    if resultado["niveles"]:
        col_l1, col_l2 = st.columns(2)
        with col_l1:
            st.plotly_chart(grafico_latencia_percentiles(resultado["niveles"]), use_container_width=True)
        with col_l2:
            st.plotly_chart(grafico_gauge_pgi(metricas["grado_pgi"], metricas["salud_global"]), use_container_width=True)
            salud = metricas["salud_global"]
            if salud in ("Excelente", "Buena"):
                fondo_badge, texto_badge = "#166534", "#dcfce7"
            elif salud in ("Aceptable", "Degradada"):
                fondo_badge, texto_badge = "#854d0e", "#fef3c7"
            else:
                fondo_badge, texto_badge = "#991b1b", "#fee2e2"
            st.markdown(
                f'<div style="text-align:center;margin-top:8px">'
                f'<span style="display:inline-block;background:{fondo_badge};'
                f'color:{texto_badge};padding:6px 16px;border-radius:999px;'
                f'font-weight:600">{t(salud)}</span></div>',
                unsafe_allow_html=True,
            )

        col_l3, col_l4 = st.columns(2)
        with col_l3:
            st.plotly_chart(grafico_throughput(resultado["niveles"]), use_container_width=True)
        with col_l4:
            if metricas["por_tipo_error"]:
                st.plotly_chart(grafico_error_pie(metricas["por_tipo_error"]), use_container_width=True)

        st.plotly_chart(grafico_barra_estado(resultado["niveles"]), use_container_width=True)

    section_header(es_o_en("Resumen de niveles", "Levels summary"),
                   es_o_en("Métricas por nivel de concurrencia", "Metrics per concurrency level"))
    if resultado["niveles"]:
        tabla(pd.DataFrame(resultado["niveles"]))
    else:
        st.markdown(
            '<div class="empty-state">%s</div>' % es_o_en("No hay datos de niveles para mostrar.",
                                                         "No level data to show."),
            unsafe_allow_html=True,
        )

    salud = metricas["salud_global"]
    if salud in ("Excelente", "Buena"):
        resumen_salud = es_o_en(
            "El sistema mantuvo un buen rendimiento durante la prueba.",
            "The system maintained good performance during the test.",
        )
    elif salud in ("Degradada", "Crítica"):
        resumen_salud = es_o_en(
            "El sistema mostró señales de degradación durante la prueba.",
            "The system showed signs of degradation during the test.",
        )
    else:
        resumen_salud = es_o_en(
            "El sistema mantuvo un rendimiento aceptable durante la prueba.",
            "The system maintained acceptable performance during the test.",
        )
    resumen_errores = es_o_en(
        "No se detectaron errores críticos." if metricas["tasa_error_max"] < 5
        else "Se detectaron errores durante la prueba.",
        "No critical errors were detected." if metricas["tasa_error_max"] < 5
        else "Errors were detected during the test.",
    )
    st.markdown(
        '<div style="background:#0b1a33;border:1px solid #12305a;'
        'border-radius:14px;padding:18px 20px;color:#e6edf7">'
        '<div style="font-size:18px;font-weight:700;margin-bottom:10px">'
        f'<span style="color:#22d3ee">✦</span> {t("Conclusión")}</div>'
        '<ul style="margin:0;padding-left:22px">'
        f'<li>✅ {t("Prueba completada")}</li>'
        f'<li>{resumen_salud}</li>'
        f'<li>{resumen_errores}</li>'
        '</ul></div>',
        unsafe_allow_html=True,
    )
    st.button(t("Ver detalles →"), key="load_view_details_placeholder")

    if metricas["recomendaciones"]:
        section_header(es_o_en("Recomendaciones de rendimiento", "Performance recommendations"),
                       es_o_en("Acciones sugeridas según el estado del sistema",
                               "Suggested actions based on system health"), "📋")
        for rec in metricas["recomendaciones"]:
            st.markdown(t(str(rec)))

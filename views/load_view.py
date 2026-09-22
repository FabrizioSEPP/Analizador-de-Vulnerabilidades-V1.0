import streamlit as st
import pandas as pd

from models.metrics import calcular_metricas_load
from views.components import kpi_grid, section_header, tabla
from views.dashboard_view import (
    grafico_latencia_percentiles, grafico_throughput,
    grafico_error_pie, grafico_gauge_pgi, grafico_barra_estado,
)


def mostrar(resultado: dict):
    section_header(
        "Prueba de Capacidad",
        "Latencia, throughput y grado de salud del sistema (PGI)",
        "⚡",
    )

    metricas = calcular_metricas_load(resultado)
    cards = [
        {"label": "Capacidad estimada", "value": f'{metricas["capacidad"]} simultáneas',
         "color": "ok" if metricas["capacidad"] > 10 else "high"},
        {"label": "Latencia base", "value": f'{metricas["latencia_base"]:.4f}s', "color": "low"},
        {"label": "Grado salud (PGI)", "value": f'{metricas["grado_pgi"]}/100',
         "color": "ok" if metricas["grado_pgi"] >= 75 else "high" if metricas["grado_pgi"] >= 50 else "crit"},
        {"label": "Salud global", "value": metricas["salud_global"],
         "color": "ok" if metricas["salud_global"] in ["Excelente", "Buena"] else "high" if metricas["salud_global"] == "Degradada" else "crit"},
        {"label": "Tasa error máx", "value": f'{metricas["tasa_error_max"]:.2f}%',
         "color": "crit" if metricas["tasa_error_max"] > 5 else "ok"},
        {"label": "Volatilidad máx", "value": f'{metricas["volatilidad_max"]:.2f}',
         "color": "med" if metricas["volatilidad_max"] > 0.5 else "ok"},
    ]
    kpi_grid(cards)

    if resultado["niveles"]:
        col_l1, col_l2 = st.columns(2)
        with col_l1:
            st.plotly_chart(grafico_latencia_percentiles(resultado["niveles"]), use_container_width=True)
        with col_l2:
            st.plotly_chart(grafico_gauge_pgi(metricas["grado_pgi"], metricas["salud_global"]), use_container_width=True)

        col_l3, col_l4 = st.columns(2)
        with col_l3:
            st.plotly_chart(grafico_throughput(resultado["niveles"]), use_container_width=True)
        with col_l4:
            if metricas["por_tipo_error"]:
                st.plotly_chart(grafico_error_pie(metricas["por_tipo_error"]), use_container_width=True)

        st.plotly_chart(grafico_barra_estado(resultado["niveles"]), use_container_width=True)

    section_header("Resumen de niveles", "Métricas por nivel de concurrencia")
    if resultado["niveles"]:
        tabla(pd.DataFrame(resultado["niveles"]))
    else:
        st.markdown(
            '<div class="empty-state">No hay datos de niveles para mostrar.</div>',
            unsafe_allow_html=True,
        )

    if metricas["recomendaciones"]:
        section_header("Recomendaciones de rendimiento", "Acciones sugeridas según el estado del sistema", "📋")
        for rec in metricas["recomendaciones"]:
            st.markdown(rec)

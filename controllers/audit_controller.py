import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import time

from models import history
from models.http_utils import validar_url, normalizar_url
from models.deep_audit import auditoria_profunda
from models.phishing_ml import detectar_phishing
from models.audit_consolidator import consolidar_auditoria
from views.components import aviso, aviso_html
from views.audit_view import mostrar as mostrar_audit
from views.audit_view import mostrar_puertos
from models.i18n import t

RANGO_PUERTOS = "1-1024"


def ejecutar_audit_unificado(url_input: str):
    if not url_input.strip():
        aviso("warning", t("Por favor, ingresa una URL."))
        return

    url_input = normalizar_url(url_input)
    valida, msg = validar_url(url_input, permitir_privadas=st.session_state.get("permitir_privadas", False))
    if not valida:
        aviso("error", msg)
        return

    profundidad = st.session_state.get("crawl_profundidad", 2)
    max_paginas = st.session_state.get("crawl_max_paginas", 15)

    progress_bar = st.progress(0.0)
    status_text = st.empty()

    def callback(p, m):
        progress_bar.progress(min(max(p, 0.0), 1.0))
        status_text.markdown(aviso_html("info", m), unsafe_allow_html=True)

    callback(0.02, t("Iniciando auditoría profunda..."))
    try:
        profundo = auditoria_profunda(
            url_input, max_paginas=max_paginas, profundidad=profundidad, callback=callback
        )
    except Exception:
        profundo = {"url": url_input, "paginas": [], "errores": [], "total_errores": 0,
                    "score_vulnerabilidad": 0, "nivel_vulnerabilidad": "info", "tecnologias": []}

    callback(0.9, t("Detectando phishing..."))
    phishing = detectar_phishing(url_input)

    resultados = {"url": url_input, "modulo": "auditoria_unificada", "errores": profundo.get("errores", [])}
    auditoria = consolidar_auditoria(resultados, deep_result={})
    auditoria["phishing"] = phishing
    auditoria["deep_analysis"] = profundo
    auditoria["crawl"] = profundo

    history.guardar("audit", url_input, auditoria, st.session_state.get("current_user", ""))

    callback(1.0, t("Auditoría completada"))
    progress_bar.empty()
    status_text.empty()
    st.markdown("---")
    mostrar_audit(auditoria)


def ejecutar_port_scan(url_input: str):
    from models.port_scanner import analizar_objetivo as escanear, analizar_amenazas

    if not url_input.strip():
        aviso("warning", t("Por favor, ingresa una URL o dominio."))
        return

    progress_bar = st.progress(0.0)
    status_text = st.empty()

    try:
        progress_bar.progress(0.2, t("Resolviendo host..."))
        t_inicio = time.time()
        resultado = escanear(
            url_input, RANGO_PUERTOS,
            permitir_privadas=st.session_state.get("permitir_privadas", False),
        )
        duracion_escaneo = time.time() - t_inicio
        progress_bar.progress(0.8, t("Escaneando puertos..."))
        status_text.empty()
        progress_bar.progress(1.0, t("Escaneo completado"))

        resultado["rango"] = RANGO_PUERTOS
        resultado["amenazas"] = analizar_amenazas(resultado.get("puertos", []))
        history.guardar("port", url_input, resultado, st.session_state.get("current_user", ""))

        section_header(es_o_en("Puertos expuestos", "Exposed ports"),
                       es_o_en("Resultado del escaneo TCP (1-1024)", "TCP scan result (1-1024)"), "🔌")
        st.markdown(
            f"**Host:** {resultado['host']} · **IP:** {resultado['ip']} · "
            f"**{es_o_en('Puertos abiertos:', 'Open ports:')}** {resultado['total_puertos']}"
        )

        puertos = resultado.get("puertos", [])
        total_abiertos = int(resultado.get("total_puertos", len(puertos)))
        servicios = {str(p.get("servicio") or "desconocido") for p in puertos}
        if duracion_escaneo < 60:
            duracion_texto = f"{duracion_escaneo:.1f}s"
        else:
            minutos, segundos = divmod(int(duracion_escaneo), 60)
            duracion_texto = f"{minutos}m {segundos}s"

        metricas = st.columns(4)
        datos_metricas = [
            ("Puertos abiertos", total_abiertos, "#ef4444"),
            ("Servicios", len(servicios), "#22d3ee"),
            ("Estado", "Completado", "#22c55e"),
            ("Tiempo de escaneo", duracion_texto, "#22d3ee"),
        ]
        for columna, (etiqueta, valor, color) in zip(metricas, datos_metricas):
            with columna:
                valor_html = (
                    '<span style="display:inline-block;background:#166534;color:#dcfce7;'
                    'padding:3px 9px;border-radius:999px">Completado</span>'
                    if etiqueta == "Estado" else str(valor)
                )
                st.markdown(
                    f'<div style="background:#0b1a33;border:1px solid #12305a;'
                    f'border-radius:8px;padding:14px 16px;min-height:88px">'
                    f'<div style="color:#9fb3d1;font-size:13px">{etiqueta}</div>'
                    f'<div style="color:{color};font-size:22px;font-weight:700;'
                    f'margin-top:8px">{valor_html}</div></div>',
                    unsafe_allow_html=True,
                )

        st.divider()
        col_tabla, col_donut = st.columns([1.5, 1])

        with col_tabla:
            section_header("Puertos encontrados", "Servicios TCP detectados", "🔌")
            if puertos:
                tabla(pd.DataFrame(puertos))
            else:
                aviso("success", es_o_en("No se encontraron puertos abiertos en el rango escaneado.", "No open ports found in the scanned range."))

        with col_donut:
            section_header("Distribución de puertos", "Rango escaneado: 1-1024", "📊")
            figura = go.Figure(data=[go.Pie(
                labels=["Abiertos", "Cerrados"],
                values=[total_abiertos, max(0, 1024 - total_abiertos)],
                marker=dict(colors=["#22d3ee", "#12305a"]),
                hole=0.68,
                textinfo="none",
                sort=False,
            )])
            figura.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e6edf7"),
                showlegend=True,
                legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=0.9),
                height=260,
                margin=dict(t=10, b=10, l=10, r=10),
                annotations=[dict(
                    text=f"{total_abiertos}<br><span style='font-size:12px'>abiertos</span>",
                    x=0.5, y=0.5, showarrow=False, font=dict(size=20, color="#e6edf7"),
                )],
            )
            st.plotly_chart(figura, use_container_width=True)

        st.divider()
        col_terminal, col_recom = st.columns([1.5, 1])

        with col_terminal:
            section_header("Detalles del escaneo", "Salida TCP del objetivo", "📋")
            lineas_detalle = [
                f"Escaneo TCP: {resultado.get('host', url_input)} ({resultado.get('ip', 'IP no disponible')})",
                "PUERTO/PROTOCOLO  ESTADO    SERVICIO",
            ]
            lineas_detalle.extend(
                f"{puerto.get('puerto', '?')}/{puerto.get('protocolo', 'tcp')}               "
                f"{puerto.get('estado', 'desconocido')}  {puerto.get('servicio') or 'desconocido'}"
                for puerto in puertos
            )
            if not puertos:
                lineas_detalle.append("No se encontraron puertos abiertos.")
            st.markdown(
                "<style>div[data-testid='stCode'] pre {background:#0b1a33 !important; "
                "border:1px solid #12305a; border-radius:14px; color:#e6edf7;}</style>",
                unsafe_allow_html=True,
            )
            st.code("\n".join(lineas_detalle), language="bash")

        with col_recom:
            section_header("Recomendaciones", "Buenas prácticas de seguridad", "📋")
            st.markdown(
                "- Mantener únicamente los servicios necesarios.\n"
                "- Implementar reglas de firewall y filtrado.\n"
                "- Revisar periódicamente los servicios expuestos.\n"
                "- Aplicar actualizaciones y parches a los servicios."
            )
            st.button("Ver informe completo", use_container_width=True, key="port_scan_report_placeholder")

        progress_bar.empty()
        mostrar_puertos(resultado, resultado["amenazas"])
    except ValueError as e:
        aviso("error", str(e))
        progress_bar.empty()
        status_text.empty()
    except Exception as e:
        aviso("error", t("Error durante el escaneo: {}").format(e))
        progress_bar.empty()
        status_text.empty()

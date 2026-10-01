import streamlit as st
import pandas as pd

from models import history
from models.http_utils import validar_url, normalizar_url
from models.deep_audit import auditoria_profunda
from models.phishing_ml import detectar_phishing
from models.audit_consolidator import consolidar_auditoria
from views.components import aviso, aviso_html, tabla, section_header
from views.audit_view import mostrar as mostrar_audit
from models.i18n import t, es_o_en


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
    from models.port_scanner import analizar_objetivo as escanear

    if not url_input.strip():
        aviso("warning", t("Por favor, ingresa una URL o dominio."))
        return

    progress_bar = st.progress(0.0)
    status_text = st.empty()

    try:
        progress_bar.progress(0.2, t("Resolviendo host..."))
        resultado = escanear(
            url_input, "1-1024",
            permitir_privadas=st.session_state.get("permitir_privadas", False),
        )
        progress_bar.progress(0.8, t("Escaneando puertos..."))
        status_text.empty()
        progress_bar.progress(1.0, t("Escaneo completado"))

        history.guardar("port", url_input, resultado, st.session_state.get("current_user", ""))

        section_header(es_o_en("Puertos expuestos", "Exposed ports"),
                       es_o_en("Resultado del escaneo TCP (1-1024)", "TCP scan result (1-1024)"), "🔌")
        st.markdown(
            f"**Host:** {resultado['host']} · **IP:** {resultado['ip']} · "
            f"**{es_o_en('Puertos abiertos:', 'Open ports:')}** {resultado['total_puertos']}"
        )

        if resultado["puertos"]:
            tabla(pd.DataFrame(resultado["puertos"]))
        else:
            aviso("success", es_o_en("No se encontraron puertos abiertos en el rango escaneado.",
                                     "No open ports found in the scanned range."))

        progress_bar.empty()
    except ValueError as e:
        aviso("error", str(e))
        progress_bar.empty()
    except Exception as e:
        aviso("error", t("Error durante el escaneo: {}").format(e))
        progress_bar.empty()

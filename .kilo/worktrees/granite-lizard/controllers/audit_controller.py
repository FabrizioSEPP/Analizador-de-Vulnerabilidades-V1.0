import streamlit as st
import pandas as pd

from models.http_utils import validar_url, normalizar_url
from models.deep_audit import auditoria_profunda
from models.phishing_ml import detectar_phishing
from models.audit_consolidator import consolidar_auditoria
from views.components import aviso, tabla
from views.audit_view import mostrar as mostrar_audit


def ejecutar_audit_unificado(url_input: str):
    if not url_input.strip():
        aviso("warning", "Por favor, ingresa una URL.")
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
        status_text.info(m)

    callback(0.02, "Iniciando auditoría profunda...")
    try:
        profundo = auditoria_profunda(
            url_input, max_paginas=max_paginas, profundidad=profundidad, callback=callback
        )
    except Exception:
        profundo = {"url": url_input, "paginas": [], "errores": [], "total_errores": 0,
                    "score_vulnerabilidad": 0, "nivel_vulnerabilidad": "info", "tecnologias": []}

    callback(0.9, "Detectando phishing...")
    phishing = detectar_phishing(url_input)

    resultados = {"url": url_input, "modulo": "auditoria_unificada", "errores": profundo.get("errores", [])}
    auditoria = consolidar_auditoria(resultados, deep_result={})
    auditoria["phishing"] = phishing
    auditoria["deep_analysis"] = profundo
    auditoria["crawl"] = profundo

    callback(1.0, "Auditoría completada")
    progress_bar.empty()
    status_text.empty()
    st.markdown("---")
    mostrar_audit(auditoria)


def ejecutar_port_scan(url_input: str):
    from models.port_scanner import analizar_objetivo as escanear

    if not url_input.strip():
        aviso("warning", "Por favor, ingresa una URL o dominio.")
        return

    progress_bar = st.progress(0.0)
    status_text = st.empty()

    try:
        progress_bar.progress(0.2, "Resolviendo host...")
        resultado = escanear(
            url_input, "1-1024",
            permitir_privadas=st.session_state.get("permitir_privadas", False),
        )
        progress_bar.progress(0.8, "Escaneando puertos...")
        status_text.empty()
        progress_bar.progress(1.0, "Escaneo completado")

        st.markdown("### Puertos Expuestos")
        st.markdown("---")
        st.markdown(f"**Host:** {resultado['host']} | **IP:** {resultado['ip']} | **Puertos abiertos:** {resultado['total_puertos']}")

        if resultado["puertos"]:
            tabla(pd.DataFrame(resultado["puertos"]))
        else:
            aviso("success", "No se encontraron puertos abiertos en el rango escaneado.")

        progress_bar.empty()
    except ValueError as e:
        aviso("error", str(e))
        progress_bar.empty()
    except Exception as e:
        aviso("error", f"Error durante el escaneo: {e}")
        progress_bar.empty()

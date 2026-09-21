import streamlit as st

from models.sqli_model import SQLiModel
from models.metrics import calcular_metricas_sqli
from views.components import aviso
from views.sqli_view import mostrar as mostrar_sqli


def ejecutar(url_input: str):
    from models.http_utils import validar_url, normalizar_url

    if not url_input.strip():
        aviso("warning", "Por favor, ingresa una URL.")
        return

    url_input = normalizar_url(url_input)
    valida, msg = validar_url(url_input, permitir_privadas=st.session_state.get("permitir_privadas", False))
    if not valida:
        aviso("error", msg)
        return

    progress_bar = st.progress(0.0)
    status_text = st.empty()

    def sqli_callback(progreso, mensaje):
        progress_bar.progress(progreso)
        status_text.info(mensaje)

    scanner = SQLiModel()
    with st.spinner("Analizando vulnerabilidades..."):
        resultado = scanner.analizar(url_input, callback=sqli_callback)

    progress_bar.empty()
    status_text.empty()
    st.markdown("---")
    mostrar_sqli(resultado)

    metricas = calcular_metricas_sqli(resultado)
    if metricas["hallazgos_con_cvss"]:
        st.markdown("### 📝 Explicación de Vulnerabilidades")
        st.markdown("---")
        for h in metricas["hallazgos_con_cvss"]:
            st.markdown(f"**`{h['parametro']}`** — {h.get('nivel_riesgo', '')} (CVSS {h.get('cvss', 0)}):")
            st.markdown(h.get("explicacion", "Sin explicación disponible"))
            st.markdown("<br>", unsafe_allow_html=True)

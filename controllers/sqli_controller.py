import streamlit as st

from models import history
from models.sqli_model import SQLiModel
from views.components import aviso, aviso_html
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
        progress_bar.progress(min(max(progreso, 0.0), 1.0))
        status_text.markdown(aviso_html("info", mensaje), unsafe_allow_html=True)

    scanner = SQLiModel()
    with st.spinner("Analizando vulnerabilidades..."):
        resultado = scanner.analizar(url_input, callback=sqli_callback)

    history.guardar("sqli", url_input, resultado, st.session_state.get("current_user", ""))

    progress_bar.empty()
    status_text.empty()
    st.markdown("---")
    mostrar_sqli(resultado)

import streamlit as st

from models.load_model import LoadModel
from views.components import aviso
from views.load_view import mostrar as mostrar_load


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

    def load_callback(progreso, mensaje):
        progress_bar.progress(progreso)
        status_text.info(mensaje)

    tester = LoadModel()
    with st.spinner("Ejecutando prueba de carga..."):
        resultado = tester.analizar(url_input, callback=load_callback)

    progress_bar.empty()
    status_text.empty()
    st.markdown("---")
    mostrar_load(resultado)

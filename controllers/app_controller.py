import streamlit as st
from controllers.sqli_controller import ejecutar as ejecutar_sqli
from controllers.load_controller import ejecutar as ejecutar_load
from controllers.audit_controller import ejecutar_audit_unificado, ejecutar_port_scan
from models.auth_model import logout
from views.components import (
    ui_sidebar, ui_authorization_check, ui_url_input_sidebar,
    ui_navigation_buttons, ui_execute_button, ui_internal_network_toggle,
    ui_audit_options, ui_theme_selector, hero_header, aviso, css_tema, CSS_STYLES,
)
from views.login_view import mostrar as mostrar_login


def run():
    st.set_page_config(page_title="Analizador de Vulnerabilidades Web", layout="wide")

    # El tema debe fijarse antes de inyectar el CSS.
    st.session_state.setdefault("tema", "sistema")
    st.session_state.setdefault("current_user", "")
    st.session_state.setdefault("permitir_privadas", False)
    st.session_state.setdefault("crawl_profundidad", 2)
    st.session_state.setdefault("crawl_max_paginas", 15)

    st.markdown(CSS_STYLES + css_tema(), unsafe_allow_html=True)

    if not st.session_state.get("logged_in", False):
        mostrar_login()
        return

    user = st.session_state.get("current_user", "")
    with st.sidebar:
        ui_sidebar()
        ui_theme_selector()
        st.markdown("---")
        st.markdown(f"👤 **{user}**")
        if st.button("🚪 Cerrar Sesión", use_container_width=True, key="logout_btn"):
            logout()
        st.markdown("---")
        autorizado = ui_authorization_check(False)
        ui_internal_network_toggle()
        ui_audit_options()
        url_input = ui_url_input_sidebar(st.session_state.get("sidebar_url", ""))
        selected_mode = ui_navigation_buttons(
            st.session_state.get("selected_mode", "sqli"), autorizado
        )
        ejecutar = ui_execute_button(autorizado, url_input)

    hero_header(url_input, selected_mode, autorizado)

    if ejecutar and autorizado and url_input.strip():
        _dispatch(selected_mode, url_input.strip())
    elif not autorizado:
        aviso("info", "🔒 Confirma tu autorización en la barra lateral para comenzar el análisis.")
    elif not url_input.strip():
        aviso("warning", "Ingresa una URL en la barra lateral para comenzar.")


def _dispatch(mode: str, url: str):
    if mode == "sqli":
        ejecutar_sqli(url)
    elif mode == "load":
        ejecutar_load(url)
    elif mode == "audit":
        ejecutar_audit_unificado(url)
    elif mode == "port":
        ejecutar_port_scan(url)

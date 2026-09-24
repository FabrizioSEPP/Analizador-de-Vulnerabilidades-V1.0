import streamlit as st
from controllers.sqli_controller import ejecutar as ejecutar_sqli
from controllers.load_controller import ejecutar as ejecutar_load
from controllers.audit_controller import ejecutar_audit_unificado, ejecutar_port_scan
from models import db
from models.auth_model import logout
from views.components import (
    ui_sidebar, ui_authorization_check, ui_url_input_sidebar,
    ui_navigation_buttons, ui_execute_button, ui_internal_network_toggle,
    ui_audit_options, ui_sqli_options, ui_theme_selector, hero_header, aviso,
    css_tema, CSS_STYLES,
)
from views.login_view import mostrar as mostrar_login
from views.history_view import mostrar_historial


def run():
    st.set_page_config(page_title="Analizador de Vulnerabilidades Web", layout="wide")

    # El tema debe fijarse antes de inyectar el CSS.
    st.session_state.setdefault("tema", "sistema")
    st.session_state.setdefault("current_user", "")
    st.session_state.setdefault("permitir_privadas", False)
    st.session_state.setdefault("crawl_profundidad", 2)
    st.session_state.setdefault("crawl_max_paginas", 15)
    # Opciones del escáner SQLi INTEGRADAS por defecto: basta pulsar
    # "Ejecutar análisis" en modo Inyección SQL; no hace falta abrir el panel.
    _OPCIONES_SQLI = {
        "sqli_headers": "",              # cookies/Authorization: no se puede adivinar
        "sqli_pausa": 0.0,
        "sqli_max_objetivos": 8,         # menos puntos = más rápido
        "sqli_tiempo_maximo": 600,       # tope de tiempo (0 = sin límite)
        "sqli_max_peticiones": 4000,
        "sqli_probar_cabeceras": True,   # User-Agent, Referer, X-Forwarded-For
        "sqli_probar_json": True,        # cuerpo JSON (APIs/SPA)
        "sqli_extraer": True,            # extracción UNION (versión/BD/usuario/tablas)
        "sqli_probar_apis": True,        # endpoints de API desde el JS
        "sqli_usar_navegador": True,     # navegador headless si Playwright está
        "sqli_confirmar": True,          # confirmación estricta (menos falsos positivos)
        "sqli_abortar_waf": False,       # NO detenerse ante bloqueos (más cobertura)
        "sqli_segundo_orden": False,     # intrusivo: requiere activación explícita
    }
    # v4: se aplican aunque la sesión ya existiera (para que tome efecto ya).
    if st.session_state.get("_opciones_sqli_v") != 4:
        st.session_state.update(_OPCIONES_SQLI)
        st.session_state["_opciones_sqli_v"] = 4

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
        st.caption("🗄️ Supabase conectado" if db.esta_configurado() else "⚠️ Supabase sin configurar")
        if st.button("🚪 Cerrar Sesión", use_container_width=True, key="logout_btn"):
            logout()
        st.markdown("---")
        autorizado = ui_authorization_check(False)
        ui_internal_network_toggle()
        ui_sqli_options()
        ui_audit_options()
        mostrar_historial(user)
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

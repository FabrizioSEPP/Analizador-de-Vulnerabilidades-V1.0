from html import escape

import streamlit as st
from controllers.load_controller import ejecutar as ejecutar_load
from controllers.sqli_controller import ejecutar as ejecutar_sqli
from controllers.audit_controller import ejecutar_audit_unificado, ejecutar_port_scan
from models import db, history
from models.auth_model import logout
from views.components import (
    ui_sidebar, ui_authorization_check, ui_url_input_sidebar,
    ui_navigation_buttons, ui_execute_button, ui_internal_network_toggle,
    ui_audit_options, ui_sqli_options, ui_theme_selector, ui_language_selector,
    ui_ayuda_rapida, ui_guia,
    hero_header,
    aviso,
    css_tema, CSS_STYLES,
)
from models.i18n import t, es_o_en
from views.login_view import mostrar as mostrar_login
from views.history_view import mostrar_historial
from views.dashboard_view import mostrar_dashboard, mostrar_seccion
from views.audit_view import mostrar_inicio as mostrar_inicio_auditoria


_AJUSTES_PERSISTENTES = (
    "permitir_privadas",
    "crawl_profundidad",
    "crawl_max_paginas",
    "tema",
    "sqli_headers",
    "sqli_pausa",
    "sqli_max_objetivos",
    "sqli_tiempo_maximo",
    "sqli_max_peticiones",
    "sqli_probar_cabeceras",
    "sqli_probar_json",
    "sqli_extraer",
    "sqli_probar_apis",
    "sqli_usar_navegador",
    "sqli_segundo_orden",
    "sqli_confirmar",
    "sqli_abortar_waf",
)


def _sincronizar_ajustes():
    """Streamlit borra el valor de un widget cuando su pantalla no se dibuja.
    Estos ajustes viven en Configuracion: se guardan aparte y se restauran."""
    guardado = st.session_state.setdefault("_ajustes_guardados", {})
    for clave in _AJUSTES_PERSISTENTES:
        if clave in st.session_state:
            guardado[clave] = st.session_state[clave]
        elif clave in guardado:
            st.session_state[clave] = guardado[clave]


def run():
    st.set_page_config(page_title=t("Corporativa Matheus | Ciberseguridad"), layout="wide")
    _sincronizar_ajustes()

    # El idioma debe fijarse antes de inyectar el CSS.
    st.session_state.setdefault("idioma", "es")
    st.session_state.setdefault("tema", "sistema")
    st.session_state.setdefault("current_user", "")
    st.session_state.setdefault("permitir_privadas", False)
    st.session_state.setdefault("crawl_profundidad", 2)
    st.session_state.setdefault("crawl_max_paginas", 15)
    st.session_state.setdefault("app_view", "dashboard")
    # Bandera de recarga diferida: se enciende al pulsar un módulo o la
    # autorización, y se consume al FINAL de run() (ver más abajo).
    st.session_state["_recargar"] = False
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
        autorizado = st.session_state.get("autorizado", False)
        selected_mode = ui_navigation_buttons(
            st.session_state.get("selected_mode", "sqli"), autorizado
        )
        ui_ayuda_rapida()
        mostrar_historial(user)
        with st.container(key="sidebar-theme-compact"):
            ui_language_selector()
        st.markdown(
            '<div class="sidebar-system-status">'
            '<span class="sidebar-system-status-dot"></span>'
            f'<span>{t("Sistema activo - Todos los módulos operativos")}</span></div>',
            unsafe_allow_html=True,
        )
        supabase_configurado = db.esta_configurado()
        with st.container(key="sidebar-user-card"):
            st.markdown(
                '<div class="sidebar-profile-head">'
                '<div class="sidebar-profile-avatar">👤</div>'
                '<div><div class="sidebar-profile-name">'
                f'{escape(user or "Usuario")}'
                '</div><div class="sidebar-profile-role">Sesión local</div></div></div>'
                f'<div class="sidebar-profile-database">'
                f'<span class="sidebar-profile-dot {"online" if supabase_configurado else "offline"}"></span>'
                f'{"Supabase conectado" if supabase_configurado else "Supabase no configurado"}</div>',
                unsafe_allow_html=True,
            )
            if st.button("Cerrar Sesión", use_container_width=True, key="logout_btn"):
                logout()

    with st.container(key="main-toolbar"):
        toolbar_columns = st.columns([6, 2, 1.8, 0.55], vertical_alignment="center")
        with toolbar_columns[0]:
            url_input = ui_url_input_sidebar(st.session_state.get("sidebar_url", ""))
        with toolbar_columns[1]:
            ejecutar = ui_execute_button(autorizado, url_input, "▶ Ejecutar análisis")
        with toolbar_columns[2]:
            st.markdown(
                '<div class="system-status"><span class="system-status-dot"></span>'
                '<span>' + t("Sistema activo") + '</span></div>',
                unsafe_allow_html=True,
            )
        with toolbar_columns[3]:
            if st.button(
                " ", icon=":material/account_circle:",
                help="Abrir configuración de perfil", key="toolbar_profile",
                use_container_width=True,
            ):
                st.session_state["app_view"] = "settings"
                st.rerun()

    ui_guia()

    if ejecutar and autorizado and url_input.strip():
        hero_header(url_input, selected_mode, autorizado)
        _dispatch(selected_mode, url_input.strip())
    else:
        if not autorizado and st.session_state.get("app_view") == "dashboard":
            aviso("info", t("🔒 Ve a Configuración para confirmar la autorización y ajustar los permisos de red."))
        registros = history.recientes(user, limite=50 if st.session_state.get("app_view") in ("monitoring", "reports", "assets") else 10)
        if st.session_state.get("app_view") == "audit":
            mostrar_inicio_auditoria(url_input, autorizado, selected_mode, registros)
        elif st.session_state.get("app_view") == "dashboard":
            mostrar_dashboard(registros, db.esta_configurado())
        else:
            mostrar_seccion(
                st.session_state["app_view"], registros, db.esta_configurado()
            )

    # Recarga diferida: se consume al final, cuando ya se dibujo todo.
    if st.session_state.get("_recargar", False):
        st.session_state["_recargar"] = False
        st.rerun()


def _dispatch(mode: str, url: str):
    if mode == "sqli":
        ejecutar_sqli(url)
    elif mode == "load":
        ejecutar_load(url)
    elif mode == "audit":
        ejecutar_audit_unificado(url)
    elif mode == "port":
        ejecutar_port_scan(url)

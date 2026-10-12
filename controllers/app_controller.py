from html import escape

import streamlit as st
from controllers.load_controller import ejecutar as ejecutar_load
from controllers.audit_controller import ejecutar_audit_unificado, ejecutar_port_scan
from models import db, history
from models.auth_model import logout
from views.components import (
    ui_sidebar, ui_url_input_sidebar, ui_execute_button,
    hero_header, aviso,
    css_tema, CSS_STYLES,
)
from views.login_view import mostrar as mostrar_login
from views.history_view import mostrar_historial
from views.dashboard_view import mostrar_dashboard, mostrar_seccion
from views.audit_view import mostrar_inicio as mostrar_inicio_auditoria


def run():
    st.set_page_config(page_title="Corporativa Matheus | Ciberseguridad", layout="wide")

    # El tema debe fijarse antes de inyectar el CSS.
    st.session_state.setdefault("tema", "sistema")
    st.session_state.setdefault("current_user", "")
    st.session_state.setdefault("permitir_privadas", False)
    st.session_state.setdefault("crawl_profundidad", 2)
    st.session_state.setdefault("crawl_max_paginas", 15)
    st.session_state.setdefault("app_view", "dashboard")
    st.markdown(CSS_STYLES + css_tema(), unsafe_allow_html=True)

    st.session_state["logged_in"] = True
    st.session_state["current_user"] = "local"
    if not st.session_state.get("logged_in", False):
        mostrar_login()
        return

    user = st.session_state.get("current_user", "")
    with st.sidebar:
        ui_sidebar()
        autorizado = st.session_state.get("autorizado", False)
        modo_actual = st.session_state.get("selected_mode", "audit")
        if modo_actual not in {"load", "audit", "port"}:
            modo_actual = "audit"
            st.session_state["selected_mode"] = modo_actual
        selected_mode = modo_actual
        pagina_actual = st.session_state.get("app_view", "dashboard")
        autorizado = st.session_state.get("autorizado", False)
        mostrar_historial(user)
        st.markdown(
            '<div class="sidebar-system-status">'
            '<span class="sidebar-system-status-dot"></span>'
            '<div><div>Sistema activo</div>'
            '<div class="sidebar-system-status-sub">Todos los módulos operativos</div></div></div>',
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
                '<span>Sistema activo</span></div>',
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

    if ejecutar and autorizado and url_input.strip():
        hero_header(url_input, selected_mode, autorizado)
        _dispatch(selected_mode, url_input.strip())
    else:
        if not autorizado and st.session_state.get("app_view") == "dashboard":
            aviso("info", "🔒 Ve a Configuración para confirmar la autorización y ajustar los permisos de red.")
        registros = history.recientes(user, limite=10)
        if st.session_state.get("app_view") == "audit":
            mostrar_inicio_auditoria(url_input, autorizado, selected_mode, registros)
        elif st.session_state.get("app_view") == "dashboard":
            mostrar_dashboard(registros, db.esta_configurado())
        else:
            mostrar_seccion(
                st.session_state["app_view"], registros, db.esta_configurado()
            )


def _dispatch(mode: str, url: str):
    if mode == "load":
        ejecutar_load(url)
    elif mode == "audit":
        ejecutar_audit_unificado(url)
    elif mode == "port":
        ejecutar_port_scan(url)

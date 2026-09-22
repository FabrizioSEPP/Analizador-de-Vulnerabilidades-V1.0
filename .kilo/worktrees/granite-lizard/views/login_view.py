import streamlit as st
from models.auth_model import register, login
from views.components import aviso, ui_theme_selector

MIN_PASSWORD = 8

CSS_LOGIN = """
<style>
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background: linear-gradient(160deg, var(--card-1), var(--card-2));
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 34px 30px;
        box-shadow: var(--shadow);
    }
    .login-badge {
        width: 62px; height: 62px; margin: 0 auto 14px; border-radius: 18px;
        display: grid; place-items: center; font-size: 1.9rem;
        background: linear-gradient(135deg, rgba(99,102,241,.35), rgba(124,58,237,.25));
        border: 1px solid rgba(129,140,248,.5);
        box-shadow: 0 10px 30px rgba(99,102,241,.25);
    }
    .login-title {
        text-align: center; font-size: 1.42rem; font-weight: 800; letter-spacing: -.02em;
        background: linear-gradient(90deg, #6366F1, #8B5CF6, #D946EF);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    }
    .login-subtitle { text-align: center; font-size: .82rem; color: var(--muted); margin-top: 5px; }
    .login-note { text-align: center; font-size: .74rem; color: var(--muted-2); margin-top: 6px; }
    .login-footer { text-align: center; font-size: .74rem; color: var(--muted-2); margin-top: 18px; }
</style>
"""


def mostrar():
    st.markdown(CSS_LOGIN, unsafe_allow_html=True)

    _, centro, _ = st.columns([1, 1.25, 1])
    with centro:
        with st.container(border=True):
            st.markdown('<div class="login-badge">🛡️</div>', unsafe_allow_html=True)
            st.markdown('<div class="login-title">Analizador de Vulnerabilidades Web</div>', unsafe_allow_html=True)
            st.markdown('<div class="login-subtitle">Pentesting ético · CVSS · PGI · OWASP</div>', unsafe_allow_html=True)
            st.markdown('<div class="login-note">Accede para auditar tus propios sistemas</div>', unsafe_allow_html=True)
            st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

            tab_reg, tab_login = st.tabs(["🔑 Iniciar Sesión", "📝 Crear Cuenta"])

            with tab_login:
                with st.form("login_form", border=False):
                    l_user = st.text_input(
                        "👤 Usuario", key="login_user",
                        placeholder="tu_usuario", label_visibility="collapsed",
                    )
                    l_pass = st.text_input(
                        "🔑 Contraseña", type="password", key="login_pass",
                        placeholder="Contraseña", label_visibility="collapsed",
                    )
                    submitted = st.form_submit_button(
                        "Entrar", type="primary", use_container_width=True,
                    )
                    if submitted:
                        ok, msg = login(l_user, l_pass)
                        if ok:
                            st.session_state.current_user = l_user
                            st.session_state.logged_in = True
                            st.rerun()
                        else:
                            aviso("error", msg)

            with tab_reg:
                with st.form("register_form", border=False):
                    r_user = st.text_input(
                        "👤 Nombre de usuario", key="reg_user",
                        placeholder="mi_usuario", label_visibility="collapsed",
                    )
                    r_pass = st.text_input(
                        "🔑 Crear contraseña", type="password", key="reg_pass",
                        placeholder=f"mínimo {MIN_PASSWORD} caracteres", label_visibility="collapsed",
                    )
                    r_pass2 = st.text_input(
                        "🔑 Repetir contraseña", type="password", key="reg_pass2",
                        placeholder="repetir contraseña", label_visibility="collapsed",
                    )
                    reg_submitted = st.form_submit_button(
                        "Crear cuenta", type="primary", use_container_width=True,
                    )
                    if reg_submitted:
                        if not r_user or not r_pass:
                            aviso("error", "Todos los campos son obligatorios.")
                        elif len(r_user) < 3:
                            aviso("error", "El usuario debe tener al menos 3 caracteres.")
                        elif len(r_pass) < MIN_PASSWORD:
                            aviso("error", f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres.")
                        elif r_pass != r_pass2:
                            aviso("error", "Las contraseñas no coinciden.")
                        else:
                            ok, msg = register(r_user, r_pass)
                            if ok:
                                aviso("success", msg)
                                st.session_state.current_user = r_user
                                st.session_state.logged_in = True
                                st.rerun()
                            else:
                                aviso("error", msg)

            st.markdown(
                '<hr style="border:none;border-top:1px solid var(--border);margin:14px 0 6px;">',
                unsafe_allow_html=True,
            )
            ui_theme_selector()

    st.markdown(
        '<div class="login-footer">© 2026 — Herramienta de pentesting ético. Uso responsable.</div>',
        unsafe_allow_html=True,
    )

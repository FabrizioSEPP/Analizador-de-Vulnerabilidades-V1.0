import html as _html
import re

import streamlit as st

from models.i18n import t, columna, valor

# ---------------------------------------------------------------------------
# Motor de temas. Dos paletas (clara/oscura) con los mismos nombres de token;
# el CSS se escribe una sola vez con var(--token). "Sistema" usa
# prefers-color-scheme, así que reacciona en vivo al SO del usuario.
# ---------------------------------------------------------------------------
_PALETA_OSCURA = {
    "bg": "#060d1f",
    "glow_1": "rgba(34,211,238,0.20)",
    "glow_2": "rgba(37,99,235,0.12)",
    "surface": "#0b1a33",
    "surface_2": "#10274b",
    "surface_3": "#12305a",
    "border": "#12305a",
    "border_soft": "rgba(34,211,238,0.18)",
    "text": "#e6edf7",
    "muted": "#9bb0c8",
    "muted_2": "#7b93b4",
    "primary": "#2563eb",
    "primary_2": "#22d3ee",
    "crit": "#F87171", "high": "#FB923C", "med": "#FBBF24",
    "low": "#38BDF8", "info": "#94A3B8", "ok": "#34D399",
    "shadow": "0 14px 40px rgba(10, 20, 36, 0.45)",
    "shadow_sm": "0 8px 22px rgba(34, 211, 238, 0.12)",
    "sidebar_1": "#081425", "sidebar_2": "#0a1b32",
    "hero_1": "rgba(11,26,51,0.95)", "hero_2": "rgba(8,18,34,0.94)",
    "card_1": "rgba(11,26,51,0.96)", "card_2": "rgba(9,21,41,0.96)",
    "primary_color": "#2563eb",
    "background_color": "#060d1f",
    "secondary_background_color": "#0b1a33",
    "text_color": "#e6edf7",
    "font": "'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif",
    "radius": "14px",
    "radius-sm": "12px",
}

_PALETA_CLARA = {
    "bg": "#edf5ff",
    "glow_1": "rgba(34,211,238,0.12)",
    "glow_2": "rgba(37,99,235,0.10)",
    "surface": "#f8fbff",
    "surface_2": "#edf5ff",
    "surface_3": "#dfeeff",
    "border": "#c5d8ee",
    "border_soft": "rgba(18,48,90,0.10)",
    "text": "#10213f",
    "muted": "#597399",
    "muted_2": "#7790b1",
    "primary": "#2563eb",
    "primary_2": "#22d3ee",
    "crit": "#DC2626", "high": "#EA580C", "med": "#D97706",
    "low": "#0284C7", "info": "#64748B", "ok": "#059669",
    "shadow": "0 14px 40px rgba(15,33,63,0.10)",
    "shadow_sm": "0 8px 22px rgba(15,33,63,0.08)",
    "sidebar_1": "#f7fbff", "sidebar_2": "#edf5ff",
    "hero_1": "#f8fbff", "hero_2": "#edf5ff",
    "card_1": "#ffffff", "card_2": "#f3f9ff",
    "primary_color": "#2563eb",
    "background_color": "#edf5ff",
    "secondary_background_color": "#f8fbff",
    "text_color": "#10213f",
    "font": "'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif",
    "radius": "14px",
    "radius-sm": "12px",
}


def _css_vars(paleta: dict, color_scheme: str) -> str:
    tokens = "".join(f"--{k.replace('_', '-')}:{v};" for k, v in paleta.items())
    return f":root{{color-scheme:{color_scheme};{tokens}}}"


def css_tema(modo: str | None = None) -> str:
    modo = modo or st.session_state.get("tema", "sistema")
    if modo == "claro":
        return f"<style>{_css_vars(_PALETA_CLARA, 'light')}</style>"
    if modo == "oscuro":
        return f"<style>{_css_vars(_PALETA_OSCURA, 'dark')}</style>"
    return (
        "<style>"
        + _css_vars(_PALETA_CLARA, "light")
        + f"@media (prefers-color-scheme: dark){{{_css_vars(_PALETA_OSCURA, 'dark')}}}"
        + "</style>"
    )


# Colores concretos para gráficos Plotly (no admiten variables CSS).
_COLORES_GRAFICO = {
    "claro": {"text": "#334155", "muted": "#64748B", "grid": "rgba(100,116,139,0.18)",
              "crit": "#DC2626", "high": "#EA580C", "med": "#D97706", "low": "#0284C7",
              "info": "#64748B", "ok": "#059669", "primary": "#6366F1", "template": "plotly_white"},
    "oscuro": {"text": "#C7D2E5", "muted": "#94A3B8", "grid": "rgba(148,163,184,0.12)",
               "crit": "#F87171", "high": "#FB923C", "med": "#FBBF24", "low": "#38BDF8",
               "info": "#94A3B8", "ok": "#34D399", "primary": "#818CF8", "template": "plotly_dark"},
    "sistema": {"text": "#8A97AC", "muted": "#8A97AC", "grid": "rgba(148,163,184,0.20)",
                "crit": "#EF4444", "high": "#F97316", "med": "#EAB308", "low": "#0EA5E9",
                "info": "#94A3B8", "ok": "#10B981", "primary": "#818CF8", "template": "none"},
}


def tema_actual() -> str:
    return st.session_state.get("tema", "sistema")


def colores_actuales() -> dict:
    return _COLORES_GRAFICO.get(tema_actual(), _COLORES_GRAFICO["sistema"])


def color_severidad(nivel_normalizado: str) -> str:
    """Mapea CRÍTICO/ALTO/... al color de gráfico del tema actual."""
    c = colores_actuales()
    return {
        "CRÍTICO": c["crit"], "ALTO": c["high"], "MEDIO": c["med"],
        "BAJO": c["low"], "INFO": c["info"],
    }.get(nivel_normalizado, c["info"])


# ---------------------------------------------------------------------------
CSS_STYLES = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');

    html, body, [class*="css"], .stApp, input, textarea, button {
        font-family: 'Inter', sans-serif !important;
    }
    h1, h2, h3, h4, h5, h6, .brand-title { font-weight: 700 !important; }

    .stApp {
        background:
            radial-gradient(720px 440px at 100% 0%, rgba(15, 42, 82, 0.24), transparent 68%),
            #060d1f;
    }

    header[data-testid="stHeader"] { background: transparent; }

    div[data-testid="stAppViewContainer"] > .main .block-container,
    .block-container { padding-top: 1.1rem; padding-bottom: 3.5rem; max-width: 1320px; }

    /* ------------------------------------------------------------- Sidebar
       Streamlit aplica el color con CSS-in-JS (no variables), así que hay que
       forzarlo con !important y dejar transparentes los contenedores internos. */
    div[data-testid="stSidebar"],
    section[data-testid="stSidebar"],
    .stSidebar {
        background: #08142b !important;
        border-right: 1px solid #12305a !important;
    }
    div[data-testid="stSidebar"] > div,
    div[data-testid="stSidebarContent"],
    div[data-testid="stSidebarHeader"],
    div[data-testid="stSidebarUserContent"],
    div[data-testid="stSidebarNav"] {
        background: transparent !important;
    }
    div[data-testid="stSidebar"] hr { border-color: var(--border); margin: 14px 0; }
    div[data-testid="stSidebarCollapseButton"] button,
    div[data-testid="stSidebarCollapseButton"] svg {
        color: var(--muted) !important;
        fill: var(--muted) !important;
    }
    /* Texto del sidebar con los tokens del tema (nativos usan colores horneados) */
    div[data-testid="stSidebar"] p,
    div[data-testid="stSidebar"] label,
    div[data-testid="stSidebar"] span,
    div[data-testid="stSidebar"] li,
    div[data-testid="stSidebar"] summary,
    div[data-testid="stSidebar"] h1,
    div[data-testid="stSidebar"] h2,
    div[data-testid="stSidebar"] h3,
    div[data-testid="stSidebar"] h4 {
        color: var(--text) !important;
        -webkit-text-fill-color: var(--text) !important;
    }
    div[data-testid="stSidebar"] [data-testid="stCaptionContainer"],
    div[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
        color: var(--muted) !important;
        -webkit-text-fill-color: var(--muted) !important;
    }

    /* ------------------------------------------------------------- Botones */
    .stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
        border-radius: 14px;
        border: 1px solid rgba(34, 211, 238, 0.35);
        background: var(--surface-2);
        color: var(--text);
        font-weight: 600;
        box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.12), 0 8px 18px rgba(34, 211, 238, 0.08);
        transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease, background .2s ease;
    }
    .stButton > button:hover, .stFormSubmitButton > button:hover {
        border-color: rgba(34, 211, 238, 0.8);
        transform: translateY(-2px);
        box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.18), 0 0 18px rgba(34, 211, 238, 0.18);
    }
    .stButton > button:focus-visible, .stFormSubmitButton > button:focus-visible {
        box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.25) !important;
    }
    .stButton > button[kind="primary"],
    button[data-testid="baseButton-primary"],
    .stFormSubmitButton > button[kind="primary"] {
        background: linear-gradient(135deg, #2563eb 0%, #22d3ee 100%);
        border: 1px solid rgba(34, 211, 238, 0.6);
        color: #ffffff;
    }
    .stButton > button[kind="primary"]:hover { filter: brightness(1.08); }
    .stButton > button:disabled { opacity: .45; cursor: not-allowed; transform: none; }
    .st-key-execute_btn .stButton > button {
        border-radius: 12px !important;
        background: linear-gradient(110deg, #2563eb 0%, #22d3ee 100%) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
    }
    .st-key-execute_btn .stButton > button:hover {
        box-shadow: 0 0 18px rgba(34, 211, 238, 0.28), 0 0 30px rgba(37, 99, 235, 0.16) !important;
    }

    div[data-testid="stSidebar"] .stButton > button,
    div[data-testid="stSidebar"] [role="menuitem"],
    div[data-testid="stSidebar"] a {
        border-radius: 10px !important;
    }
    div[data-testid="stSidebar"] .stButton > button { text-align: left; justify-content: flex-start; }
    div[data-testid="stSidebar"] .stButton > button[kind="primary"],
    div[data-testid="stSidebar"] [aria-current="page"],
    div[data-testid="stSidebar"] [role="radio"][aria-checked="true"] {
        background: #12305a !important;
        border: 1px solid rgba(34, 211, 238, 0.42) !important;
        box-shadow: 0 0 12px rgba(34, 211, 238, 0.10) !important;
    }
    div[data-testid="stSidebar"] .st-key-nav_sqli .stButton > button[kind="primary"],
    div[data-testid="stSidebar"] .st-key-nav_load .stButton > button[kind="primary"],
    div[data-testid="stSidebar"] .st-key-nav_audit .stButton > button[kind="primary"],
    div[data-testid="stSidebar"] .st-key-nav_port .stButton > button[kind="primary"] {
        background: #12305a !important;
        border: 1px solid rgba(34, 211, 238, 0.42) !important;
        box-shadow: 0 0 12px rgba(34, 211, 238, 0.10) !important;
    }
    div[data-testid="stSidebar"] button[data-key="logout_btn"] {
        background: transparent;
        border: 1px solid rgba(220, 38, 38, 0.5);
        color: var(--crit);
    }
    div[data-testid="stSidebar"] button[data-key="logout_btn"]:hover {
        background: rgba(220, 38, 38, 0.12);
        border-color: var(--crit);
    }

    /* ------------------------------------------ Inputs (nativos BaseWeb)
       BaseWeb fija los colores según el tema base y usa -webkit-text-fill-color;
       por eso hay que forzarlos con !important para que sigan al tema elegido. */
    div[data-testid="stTextInput"] input,
    div[data-testid="stNumberInput"] input,
    div[data-testid="stTextArea"] textarea,
    div[data-baseweb="input"] input,
    div[data-baseweb="base-input"] input {
        background: var(--surface-2) !important;
        color: var(--text) !important;
        -webkit-text-fill-color: var(--text) !important;
        caret-color: var(--text) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-sm) !important;
    }
    div[data-testid="stTextInput"] input::placeholder,
    div[data-testid="stNumberInput"] input::placeholder,
    div[data-testid="stTextArea"] textarea::placeholder,
    div[data-baseweb="input"] input::placeholder {
        color: var(--muted) !important;
        -webkit-text-fill-color: var(--muted) !important;
        opacity: 1 !important;
    }
    div[data-testid="stTextInput"] input:focus,
    div[data-testid="stNumberInput"] input:focus {
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25) !important;
    }
    div[data-testid="stSidebar"] .st-key-sidebar_url input,
    div[data-testid="stSidebar"] .st-key-sidebar_url div[data-testid="stTextInputRootElement"],
    div[data-testid="stSidebar"] .st-key-sidebar_url div[data-baseweb="input"] {
        background: #0b1a33 !important;
        border: 1px solid #12305a !important;
        border-radius: 12px !important;
    }
    div[data-testid="stSidebar"] .st-key-sidebar_url:focus-within div[data-testid="stTextInputRootElement"],
    div[data-testid="stSidebar"] .st-key-sidebar_url:focus-within div[data-baseweb="input"],
    div[data-testid="stSidebar"] .st-key-sidebar_url input:focus {
        border-color: #22d3ee !important;
        box-shadow: 0 0 0 2px rgba(34, 211, 238, 0.18) !important;
    }
    /* Contenedor y adornos (borde/fondo + botón de ver contraseña) */
    div[data-baseweb="input"],
    div[data-baseweb="base-input"],
    div[data-baseweb="textarea"],
    div[data-testid="stTextInputRootElement"] {
        background: var(--surface-2) !important;
        border-color: var(--border) !important;
        border-radius: var(--radius-sm) !important;
    }
    div[data-testid="stTextInput"] button,
    button[data-testid="stTextInputRevealPassword"] {
        background: transparent !important;
        color: var(--muted) !important;
    }
    div[data-testid="stTextInput"] button svg,
    button[data-testid="stTextInputRevealPassword"] svg {
        fill: var(--muted) !important;
        color: var(--muted) !important;
    }

    /* ------------------------- Etiquetas y textos de widgets nativos */
    div[data-testid="stWidgetLabel"] p,
    div[data-testid="stWidgetLabel"] label,
    label[data-testid="stWidgetLabel"],
    div[data-testid="stRadio"] p,
    div[data-testid="stRadio"] label,
    div[data-testid="stCheckbox"] p,
    div[data-testid="stCheckbox"] label,
    div[data-testid="stSlider"] p,
    div[data-testid="stSelectbox"] p,
    div[data-testid="stSelectbox"] label {
        color: var(--text) !important;
        -webkit-text-fill-color: var(--text) !important;
        opacity: 1 !important;
    }
    div[data-testid="stCaptionContainer"],
    div[data-testid="stCaptionContainer"] p {
        color: var(--muted) !important;
        -webkit-text-fill-color: var(--muted) !important;
        opacity: 1 !important;
    }
    div[data-testid="stRadio"] [role="radiogroup"] label > div:first-child,
    div[data-testid="stRadio"] label > div:first-child,
    div[data-testid="stRadio"] [role="radio"],
    div[data-baseweb="radio"] > div:first-child {
        border-color: var(--muted) !important;
    }
    div[data-testid="stCheckbox"] label > div:first-child,
    div[data-testid="stCheckbox"] [role="checkbox"],
    div[data-baseweb="checkbox"] > div:first-child {
        border-color: var(--muted) !important;
    }
    input[type="checkbox"], input[type="radio"] { accent-color: #22d3ee !important; }
    div[data-testid="stCheckbox"] [role="checkbox"][aria-checked="true"],
    div[data-testid="stRadio"] [role="radio"][aria-checked="true"],
    div[data-baseweb="checkbox"] [role="checkbox"][aria-checked="true"],
    div[data-baseweb="radio"] [role="radio"][aria-checked="true"] {
        background-color: #22d3ee !important;
        border-color: #22d3ee !important;
    }
    /* Pestañas — Streamlit 1.63 usa React Aria: <div role="tab">, no <button>.
       La inactiva se atenúa con opacidad, por eso hay que forzarla. */
    div[data-testid="stTabs"] [role="tab"],
    div[data-testid="stTabs"] [role="tab"] *,
    div[data-testid="stTabs"] button[role="tab"],
    div[data-testid="stTabs"] button[role="tab"] * {
        opacity: 1 !important;
    }
    div[data-testid="stTabs"] [role="tab"],
    div[data-testid="stTabs"] [role="tab"] p,
    div[data-testid="stTabs"] [role="tab"] div,
    div[data-testid="stTabs"] button[role="tab"],
    div[data-testid="stTabs"] button[role="tab"] p {
        color: var(--muted) !important;
        -webkit-text-fill-color: var(--muted) !important;
    }
    div[data-testid="stTabs"] [role="tab"][aria-selected="true"],
    div[data-testid="stTabs"] [role="tab"][aria-selected="true"] p,
    div[data-testid="stTabs"] [role="tab"][aria-selected="true"] div,
    div[data-testid="stTabs"] button[role="tab"][aria-selected="true"],
    div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] p {
        color: var(--primary) !important;
        -webkit-text-fill-color: var(--primary) !important;
    }
    /* Expander */
    div[data-testid="stExpander"] summary,
    div[data-testid="stExpander"] summary p,
    div[data-testid="stExpander"] summary span,
    div[data-testid="stExpander"] summary div {
        color: var(--text) !important;
        -webkit-text-fill-color: var(--text) !important;
    }
    /* Selects desplegables */
    div[data-baseweb="select"] > div {
        background: var(--surface-2) !important;
        border-color: var(--border) !important;
        color: var(--text) !important;
    }
    div[data-baseweb="menu"] li,
    div[data-baseweb="popover"] li {
        color: var(--text) !important;
    }

    /* --------------------------------------------- Expander / tabs / tabla */
    div[data-testid="stExpander"] {
        border: 1px solid #12305a !important;
        border-radius: 12px !important;
        background: #0b1a33 !important;
        overflow: hidden;
    }
    div[data-testid="stExpander"] > details,
    div[data-testid="stExpander"] details > div { background: #0b1a33 !important; }
    div[data-testid="stExpander"] summary:hover { color: var(--primary); }
    div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }

    div[data-testid="stAlert"] {
        border-radius: var(--radius-sm);
        border: 1px solid var(--border);
        background: var(--surface-2);
        color: var(--text);
    }
    div[data-testid="stPlotlyChart"] { border-radius: var(--radius); }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #060d1f; }
    ::-webkit-scrollbar-thumb { background: #12305a; border-radius: 8px; }
    ::-webkit-scrollbar-thumb:hover { background: #12305a; }

    /* ------------------------------------------------- Componentes propios */
    .app-hero {
        display: flex; justify-content: space-between; align-items: center;
        gap: 18px; flex-wrap: wrap;
        background: linear-gradient(90deg, #0b1a33 0%, #0f2a52 100%);
        border: 1px solid rgba(34, 211, 238, 0.28); border-radius: 14px;
        padding: 18px 22px; box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.10), 0 10px 26px rgba(34, 211, 238, 0.12); margin-bottom: 18px;
    }
    .hero-title {
        font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em;
        color: var(--text);
    }
    .hero-sub { font-size: 0.82rem; color: var(--muted); margin-top: 4px; }
    .hero-right { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .pill {
        font-size: 0.75rem; font-weight: 600; padding: 6px 12px; border-radius: 999px;
        border: 1px solid var(--border); background: transparent; color: var(--muted);
        max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .pill-mode { color: #22d3ee; border-color: rgba(34, 211, 238, 0.55); }
    .pill-ok { color: #22c55e; border-color: rgba(34, 197, 94, 0.55); }
    .pill-warn { color: #facc15; border-color: rgba(250, 204, 21, 0.55); }
    .pill-target { color: var(--low); border-color: rgba(14, 165, 233, 0.35); background: transparent; }

    .section-head { display: flex; gap: 12px; align-items: flex-start; margin: 26px 0 14px; }
    .section-bar {
        width: 4px; border-radius: 4px; align-self: stretch; min-height: 34px;
        background: linear-gradient(180deg, var(--primary-2), #7C3AED);
    }
    .section-title { font-size: 1.08rem; font-weight: 700; color: var(--text); letter-spacing: -0.01em; }
    .section-sub { font-size: 0.8rem; color: var(--muted); margin-top: 2px; }

    .kpi-grid {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(168px, 1fr));
        gap: 12px; margin: 6px 0 8px;
    }
    .kpi-card {
        position: relative;
        background: linear-gradient(180deg, var(--card-1), var(--card-2));
        border: 1px solid rgba(34, 211, 238, 0.28);
        border-left: 3px solid var(--accent, var(--primary)); border-radius: 14px;
        padding: 14px 16px; overflow: hidden;
        box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.06), 0 8px 20px rgba(34, 211, 238, 0.08);
        transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
    }
    .kpi-card::before {
        content: ""; position: absolute; top: 0; bottom: 0; left: 0;
        display: none;
    }
    .kpi-card:hover {
        transform: translateY(-2px); border-top-color: var(--primary);
        border-right-color: var(--primary); border-bottom-color: var(--primary);
        border-color: rgba(34, 211, 238, 0.75);
        box-shadow: 0 0 18px rgba(34, 211, 238, 0.2), var(--shadow-sm);
    }
    .kpi-label {
        font-size: 0.68rem; font-weight: 700; letter-spacing: 0.09em;
        text-transform: uppercase; color: var(--muted-2);
    }
    .kpi-value {
        font-size: 1.55rem; font-weight: 800; margin-top: 6px;
        color: var(--accent, var(--text)); letter-spacing: -0.02em;
    }
    .kpi-sub { font-size: 0.72rem; color: var(--muted); margin-top: 2px; }

    .finding {
        background: linear-gradient(180deg, var(--card-1), var(--card-2));
        border: 1px solid var(--border); border-left: 3px solid var(--f-color, var(--primary));
        border-radius: 14px; padding: 12px 15px; margin-bottom: 9px;
        transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
    }
    .finding:hover {
        transform: translateY(-2px);
        border-color: rgba(34, 211, 238, 0.75);
        box-shadow: 0 0 18px rgba(34, 211, 238, 0.2);
    }
    .finding-head { font-weight: 700; font-size: 0.9rem; color: var(--text); }
    .finding-meta { font-size: 0.72rem; color: var(--muted-2); margin-top: 3px; }
    .finding-body { font-size: 0.82rem; color: var(--text); opacity: 0.9; margin-top: 8px; line-height: 1.55; }
    .finding-rem {
        font-size: 0.78rem; color: var(--muted); margin-top: 7px;
        padding-top: 8px; border-top: 1px dashed var(--border);
    }

    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }
    .brand-badge {
        width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center;
        font-size: 1.1rem; font-weight: 800; color: #e6edf7;
        background: linear-gradient(135deg, rgba(34, 211, 238, 0.28), rgba(37, 99, 235, 0.28));
        border: 1px solid rgba(34, 211, 238, 0.5);
    }
    .brand-title { font-size: 1.02rem; font-weight: 800; color: var(--text); letter-spacing: -0.01em; }
    .brand-sub { font-size: 0.72rem; color: var(--muted); }
    .soc-sidebar-nav { display: grid; gap: 4px; margin: 16px 0 18px; }
    .soc-nav-item {
        padding: 8px 12px; border: 1px solid transparent; border-radius: 10px;
        color: var(--muted); font-size: 0.84rem; font-weight: 600;
        transition: background .2s ease, color .2s ease;
    }
    .soc-nav-item:hover {
        color: var(--text); background: #12305a;
    }
    .soc-nav-item-active {
        color: var(--text); background: #12305a;
        border-color: rgba(34, 211, 238, 0.42);
        box-shadow: 0 0 12px rgba(34, 211, 238, 0.10);
    }
    .st-key-sidebar-user-card {
        padding: 12px; margin-top: 14px;
        background: #0b1a33; border: 1px solid #12305a; border-radius: 12px;
    }
    .st-key-sidebar-user-card [data-testid="stMarkdownContainer"] p { margin-bottom: 6px; }
    .st-key-sidebar-user-card [data-testid="stCaptionContainer"] { margin-bottom: 8px; }
    .st-key-sidebar-theme-compact { margin-top: 8px; }
    .st-key-sidebar-theme-compact .side-label { margin: 4px 0 4px; }
    .st-key-sidebar-theme-compact [role="radiogroup"] { gap: 4px; }
    .sidebar-system-status {
        display: flex; align-items: center; gap: 8px; margin-top: 10px; padding: 10px 12px;
        color: #d3fbe5; background: rgba(34, 197, 94, 0.12);
        border: 1px solid rgba(34, 197, 94, 0.35); border-radius: 10px;
        font-size: 0.76rem; font-weight: 600; line-height: 1.4;
    }
    .sidebar-system-status-dot {
        width: 8px; height: 8px; flex: 0 0 8px; border-radius: 50%;
        background: #22c55e; box-shadow: 0 0 8px rgba(34, 197, 94, 0.6);
    }
    .st-key-main-toolbar {
        padding: 14px 18px; margin-bottom: 18px;
        background: #0b1a33; border: 1px solid #12305a; border-radius: 14px;
    }
    .system-status {
        display: flex; align-items: center; justify-content: flex-end; gap: 8px;
        width: fit-content; min-height: 38px; margin-left: auto; padding: 0 12px;
        color: var(--text); font-size: 0.82rem; font-weight: 600; white-space: nowrap;
        border: 1px solid rgba(34, 197, 94, 0.48); border-radius: 999px;
        background: transparent;
    }
    .system-status-dot {
        width: 9px; height: 9px; flex: 0 0 9px; border-radius: 50%;
        background: #22c55e; box-shadow: 0 0 10px rgba(34, 197, 94, 0.6);
    }
    .status-box {
        margin-top: 12px; padding: 10px 12px; border-radius: 12px;
        background: rgba(34, 197, 94, 0.12); border: 1px solid rgba(34, 197, 94, 0.35);
        color: #d3fbe5; font-size: 0.76rem; font-weight: 600; line-height: 1.4;
    }

    .side-label {
        font-size: 0.68rem; font-weight: 700; letter-spacing: 0.1em;
        text-transform: uppercase; color: var(--muted-2); margin: 4px 0 8px;
    }

    .empty-state {
        text-align: center; padding: 26px 18px; border: 1px dashed var(--border);
        border-radius: var(--radius); color: var(--muted); background: var(--surface);
    }

    /* Avisos propios (no dependen del tema nativo de Streamlit) */
    .aviso {
        display: flex; gap: 10px; align-items: flex-start;
        padding: 12px 15px; margin: 10px 0; border-radius: var(--radius-sm);
        border: 1px solid var(--border); background: var(--surface-2);
        color: var(--text); font-size: 0.88rem; line-height: 1.5;
    }
    .aviso-ic { line-height: 1.4; }
    .aviso-info { border-left: 4px solid var(--primary); }
    .aviso-success { border-left: 4px solid var(--ok); }
    .aviso-warning { border-left: 4px solid var(--med); }
    .aviso-error { border-left: 4px solid var(--crit); }

    /* Tablas propias (varían con el tema; st.dataframe no siempre lo hace) */
    .table-wrap {
        overflow-x: auto; border: 1px solid var(--border);
        border-radius: var(--radius); background: var(--surface);
    }
    table.data-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
    table.data-table th {
        text-align: left; padding: 10px 14px; background: var(--surface-2); color: var(--muted);
        font-size: 0.7rem; letter-spacing: 0.06em; text-transform: uppercase;
        border-bottom: 1px solid var(--border); white-space: nowrap;
    }
    table.data-table td {
        padding: 10px 14px; border-bottom: 1px solid var(--border-soft);
        color: var(--text); vertical-align: top;
    }
    table.data-table tr:last-child td { border-bottom: none; }
    table.data-table tr:hover td { background: var(--surface-2); }
</style>
"""


# --------------------------------------------------------------------------- internos
def _md_inline(texto) -> str:
    texto = _html.escape(str(texto))
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", texto)


def _kpi_card(card: dict) -> str:
    color = card.get("color", "primary")
    accent = color if str(color).startswith("#") else f"var(--{color})"
    sub = card.get("sub", "")
    sub_html = f'<div class="kpi-sub">{_html.escape(str(sub))}</div>' if sub else ""
    return (
        f'<div class="kpi-card" style="--accent:{accent}">'
        f'<div class="kpi-label">{_html.escape(str(card["label"]))}</div>'
        f'<div class="kpi-value">{_html.escape(str(card["value"]))}</div>'
        f'{sub_html}</div>'
    )


# --------------------------------------------------------------------- públicos
def kpi_grid(cards: list):
    """Cuadrícula responsive de KPIs. `color` puede ser un token semántico
    ("crit", "high", "ok", "primary", ...) o un hex concreto."""
    if not cards:
        return
    st.markdown(f'<div class="kpi-grid">{"".join(_kpi_card(c) for c in cards)}</div>',
                unsafe_allow_html=True)


def section_header(titulo: str, subtitulo: str = "", icono: str = ""):
    sub = f'<div class="section-sub">{_html.escape(subtitulo)}</div>' if subtitulo else ""
    icono_html = f"{icono} " if icono else ""
    st.markdown(
        f'<div class="section-head"><div class="section-bar"></div>'
        f'<div><div class="section-title">{icono_html}{_html.escape(titulo)}</div>{sub}</div></div>',
        unsafe_allow_html=True,
    )


def hero_header(url: str = "", modo: str = "", autorizado: bool = False):
    from models.i18n import es_o_en
    modos = {
        "sqli": es_o_en("Inyección SQL", "SQL Injection"),
        "load": es_o_en("Prueba de Carga", "Load Test"),
        "audit": es_o_en("Auditoría Unificada", "Unified Audit"),
        "port": es_o_en("Escaneo de Puertos", "Port Scan"),
    }
    modo_label = modos.get(modo, "—")
    estado = es_o_en("Autorizado", "Authorized") if autorizado else es_o_en("Sin autorización", "Not authorized")
    clase = "ok" if autorizado else "warn"
    objetivo = _html.escape(url) if url else es_o_en("sin objetivo", "no target")
    st.markdown(
        f'<div class="app-hero">'
        f'<div><div class="hero-title">🛡️ {es_o_en("Analizador de Vulnerabilidades Web", "Web Vulnerability Analyzer")}</div>'
        f'<div class="hero-sub">Pentesting ético · CVSS · PGI · OWASP</div></div>'
        f'<div class="hero-right">'
        f'<span class="pill pill-mode">🧭 {modo_label}</span>'
        f'<span class="pill pill-{clase}">● {estado}</span>'
        f'<span class="pill pill-target" title="{objetivo}">🎯 {objetivo}</span>'
        f'</div></div>',
        unsafe_allow_html=True,
    )


_AVISO_ICONOS = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "⛔"}


def aviso_html(tipo: str, mensaje: str) -> str:
    """HTML del aviso, para usar también dentro de `st.empty()`."""
    icono = _AVISO_ICONOS.get(tipo, "ℹ️")
    return (
        f'<div class="aviso aviso-{tipo}">'
        f'<span class="aviso-ic">{icono}</span>'
        f'<span>{_md_inline(mensaje)}</span></div>'
    )


def aviso(tipo: str, mensaje: str):
    """Mensaje con estilo propio que respeta el tema (info/success/warning/error)."""
    st.markdown(aviso_html(tipo, mensaje), unsafe_allow_html=True)


def tabla(df):
    """Tabla HTML propia: se adapta al tema claro/oscuro (st.dataframe no siempre)."""
    if df is None or len(df) == 0:
        st.markdown('<div class="empty-state">%s</div>' % t("Sin datos para mostrar."), unsafe_allow_html=True)
        return
    cabeceras = "".join(f"<th>{_html.escape(columna(str(c)))}</th>" for c in df.columns)
    filas = []
    for _, fila in df.iterrows():
        celdas = "".join(f"<td>{_html.escape(valor(v))}</td>" for v in fila.tolist())
        filas.append(f"<tr>{celdas}</tr>")
    st.markdown(
        f'<div class="table-wrap"><table class="data-table">'
        f'<thead><tr>{cabeceras}</tr></thead><tbody>{"".join(filas)}</tbody>'
        f'</table></div>',
        unsafe_allow_html=True,
    )


def ui_language_selector():
    st.markdown('<div class="side-label">🌐 Idioma / Language</div>', unsafe_allow_html=True)
    st.radio(
        "Idioma",
        options=["es", "en"],
        format_func=lambda k: "ES Español" if k == "es" else "EN English",
        key="idioma",
        horizontal=True,
        label_visibility="collapsed",
    )
    return st.session_state.get("idioma", "es")


def ui_theme_selector():
    st.markdown('<div class="side-label">🎨 %s</div>' % t("Tema"), unsafe_allow_html=True)
    st.radio(
        "Tema",
        options=["sistema", "claro", "oscuro"],
        format_func=lambda k: {"sistema": t("🖥️ Sistema"), "claro": t("☀️ Claro"), "oscuro": t("🌙 Oscuro")}[k],
        key="tema",
        horizontal=True,
        label_visibility="collapsed",
    )
    return st.session_state.get("tema", "sistema")


def ui_sidebar():
    st.markdown(
        '<div class="brand">'
        '<div class="brand-badge">🛡️</div>'
        '<div><div class="brand-title">VulnWeb</div>'
        '<div class="brand-sub">Ethical Pentest Suite</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="soc-sidebar-nav">'
        '<div class="soc-nav-item">🏠 Dashboard</div>'
        '<div class="soc-nav-item soc-nav-item-active">🛡️ Auditorías</div>'
        '<div class="soc-nav-item">⚠️ Vulnerabilidades</div>'
        '<div class="soc-nav-item">🗄️ Activos</div>'
        '<div class="soc-nav-item">👁️ Monitoreo</div>'
        '<div class="soc-nav-item">📄 Reportes</div>'
        '<div class="soc-nav-item">⚙️ Configuración</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def ui_authorization_check(autorizado: bool) -> bool:
    with st.expander(t("⚠️ Condiciones de uso"), expanded=False):
        st.markdown(
            f"""
            - {t("Solo usa esta herramienta contra sistemas que **poseas** o contra los "
                  "cuales tengas **autorización escrita explícita**.")}
            - {t("Escanear sistemas de terceros sin permiso puede ser **ilegal**.")}
            - {t("La prueba de carga tiene un techo máximo de concurrencia (50) para evitar "
                  "convertirte en una herramienta de denegación de servicio (DoS).")}
            """
        )
        if st.button(t("✅ Confirmar autorización"), type="primary", use_container_width=True, key="auth_btn"):
            st.session_state.autorizado = True
            st.rerun()
    return st.session_state.get("autorizado", False)


def ui_url_input_sidebar(current_url: str) -> str:
    st.markdown('<div class="side-label">🎯 %s</div>' % t("Objetivo"), unsafe_allow_html=True)
    return st.text_input(
        t("URL objetivo"),
        value=current_url,
        placeholder=t("ejemplo.com:8080 o https://dominio/ruta"),
        label_visibility="collapsed",
        key="sidebar_url",
    )


def ui_navigation_buttons(current_mode: str, autorizado: bool) -> str:
    from models.i18n import es_o_en
    st.markdown('<div class="side-label">🧭 %s</div>' % t("Módulos de análisis"), unsafe_allow_html=True)
    st.markdown(
        """
        <style>
        .st-key-nav_sqli .stButton > button,
        .st-key-nav_load .stButton > button,
        .st-key-nav_audit .stButton > button,
        .st-key-nav_port .stButton > button {
            min-height: 76px;
            white-space: normal;
            border-width: 2px;
            border-style: solid;
            border-radius: 12px;
            justify-content: center;
            transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
        }
        .st-key-nav_sqli .stButton > button:hover,
        .st-key-nav_load .stButton > button:hover,
        .st-key-nav_audit .stButton > button:hover,
        .st-key-nav_port .stButton > button:hover {
            transform: translateY(-2px);
            border-color: rgba(34, 211, 238, 0.9) !important;
            box-shadow: 0 0 18px rgba(34, 211, 238, 0.28) !important;
        }
        .st-key-nav_sqli .stButton > button {
            border-color: #3b82f6;
            background: rgba(59, 130, 246, 0.10);
        }
        .st-key-nav_load .stButton > button {
            border-color: #22c55e;
            background: rgba(34, 197, 94, 0.10);
        }
        .st-key-nav_audit .stButton > button {
            border-color: #a855f7;
            background: rgba(168, 85, 247, 0.10);
        }
        .st-key-nav_port .stButton > button {
            border-color: #06b6d4;
            background: rgba(6, 182, 212, 0.10);
        }
        .st-key-nav_sqli .stButton > button[kind="primary"],
        .st-key-nav_load .stButton > button[kind="primary"],
        .st-key-nav_audit .stButton > button[kind="primary"],
        .st-key-nav_port .stButton > button[kind="primary"] {
            color: var(--text);
        }
        .st-key-nav_sqli .stButton > button[kind="primary"] {
            background: rgba(59, 130, 246, 0.24);
            box-shadow: inset 0 0 0 1px #3b82f6, 0 0 18px rgba(59, 130, 246, 0.45);
        }
        .st-key-nav_load .stButton > button[kind="primary"] {
            background: rgba(34, 197, 94, 0.24);
            box-shadow: inset 0 0 0 1px #22c55e, 0 0 18px rgba(34, 197, 94, 0.45);
        }
        .st-key-nav_audit .stButton > button[kind="primary"] {
            background: rgba(168, 85, 247, 0.24);
            box-shadow: inset 0 0 0 1px #a855f7, 0 0 18px rgba(168, 85, 247, 0.45);
        }
        .st-key-nav_port .stButton > button[kind="primary"] {
            background: rgba(6, 182, 212, 0.24);
            box-shadow: inset 0 0 0 1px #06b6d4, 0 0 18px rgba(6, 182, 212, 0.45);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    cols = st.columns(2)
    labels = [
        (f"🔍 {es_o_en('Inyección SQL', 'SQL Injection')}", "sqli"),
        (f"⚡ {es_o_en('Carga', 'Load')}", "load"),
        (f"🛡️ {es_o_en('Auditoría', 'Audit')}", "audit"),
        (f"🔌 {es_o_en('Puertos', 'Ports')}", "port"),
    ]
    for i, (label, mode_key) in enumerate(labels):
        with cols[i % 2]:
            kwargs = dict(
                label=label, use_container_width=True,
                disabled=not autorizado, key=f"nav_{mode_key}",
            )
            if current_mode == mode_key:
                kwargs["type"] = "primary"
            if st.button(**kwargs):
                if autorizado:
                    st.session_state.selected_mode = mode_key
                    st.rerun()
    return st.session_state.get("selected_mode", current_mode)


def ui_execute_button(autorizado: bool, url_input: str):
    disabled = not autorizado or not url_input.strip()
    return st.button(
        f"▶ {t('Ejecutar análisis')}",
        type="primary", use_container_width=True,
        disabled=disabled, key="execute_btn",
    )


def ui_internal_network_toggle() -> bool:
    return st.checkbox(
        t("🌐 Permitir red interna (localhost / privadas)"),
        key="permitir_privadas",
        help=t("Necesario para laboratorios locales (DVWA, Juice Shop). "
               "Déjalo desactivado para uso normal."),
    )


def parse_headers(texto: str) -> dict:
    """Convierte 'Nombre: valor' por línea en un diccionario de cabeceras."""
    headers = {}
    for linea in (texto or "").splitlines():
        if ":" in linea:
            clave, valor = linea.split(":", 1)
            if clave.strip():
                headers[clave.strip()] = valor.strip()
    return headers


def ui_sqli_options():
    """Opciones del escáner SQLi: cabeceras de sesión, cortesía y presupuesto."""
    with st.expander(t("🔧 Opciones de inyección SQL"), expanded=False):
        st.text_area(
            t("Cabeceras extra (una por línea: `Nombre: valor`)"),
            key="sqli_headers", height=90,
            placeholder="Cookie: sesion=abc123\nAuthorization: Bearer ...",
            help=t("Necesario para objetivos que requieren sesión o autenticación."),
        )
        st.slider(
            t("Pausa entre peticiones (s)"), min_value=0.0, max_value=1.0,
            step=0.1, key="sqli_pausa",
            help=t("Modo cortés: retardo entre peticiones para no saturar el objetivo."),
        )
        st.number_input(
            t("Máximo de puntos a analizar"), min_value=1, max_value=50,
            step=1, key="sqli_max_objetivos",
            help=t("Menos puntos = análisis más rápido."),
        )
        st.number_input(
            t("Tiempo máximo (s)"), min_value=0, max_value=7200,
            step=60, key="sqli_tiempo_maximo",
            help=t("Detiene el análisis al alcanzarlo. 0 = sin límite."),
        )
        st.number_input(
            t("Máximo de peticiones"), min_value=50, max_value=50000,
            step=50, key="sqli_max_peticiones",
            help=t("Límite de seguridad; al alcanzarlo se detiene el análisis."),
        )
        st.checkbox(
            t("Probar cabeceras (User-Agent, Referer, X-Forwarded-For)"),
            key="sqli_probar_cabeceras",
            help=t("Algunas apps registran o usan estas cabeceras en consultas SQL."),
        )
        st.checkbox(
            t("Probar cuerpo JSON (APIs / SPA)"),
            key="sqli_probar_json",
            help=t("Envía los campos del formulario también como JSON."),
        )
        st.checkbox(
            t("Extraer datos (versión, BD, usuario, tablas) al detectar UNION"),
            key="sqli_extraer",
            help=t("Prueba de extracción acotada para evidenciar impacto."),
        )
        st.checkbox(
            t("Descubrir endpoints de API (JS / SPA)"),
            key="sqli_probar_apis",
            help=t("Analiza el JavaScript en busca de rutas /api, /rest, etc."),
        )
        st.checkbox(
            t("Usar navegador headless (SPA con JS)"),
            key="sqli_usar_navegador",
            help=t("Requiere Playwright instalado (`playwright install chromium`)."),
        )
        st.checkbox(
            t("Probar SQLi de segundo orden (intrusivo: escribe datos)"),
            key="sqli_segundo_orden",
            help=t("Inyecta en formularios y luego revisa otras páginas buscando errores SQL. "
                   "Heurístico y MODIFICA datos del objetivo; úsalo solo con autorización."),
        )
        st.checkbox(
            t("Confirmación estricta (menos falsos positivos)"),
            key="sqli_confirmar",
            help=t("Desactívalo si el objetivo es inestable y crees que se están perdiendo hallazgos."),
        )
        st.checkbox(
            t("Detener ante WAF / rate-limit"),
            key="sqli_abortar_waf",
            help=t("Si se desactiva, sigue probando aunque el objetivo devuelva bloqueos."),
        )
    return (
        parse_headers(st.session_state.get("sqli_headers", "")),
        st.session_state.get("sqli_pausa", 0.0),
        int(st.session_state.get("sqli_max_peticiones", 1500)),
    )


def ui_audit_options():
    with st.expander(t("⚙️ Opciones de auditoría profunda"), expanded=False):
        st.slider(
            t("Profundidad de rastreo"), min_value=0, max_value=3,
            key="crawl_profundidad",
            help=t("0 = solo la página indicada. 2 = sigue enlaces hasta 2 niveles."),
        )
        st.slider(
            t("Máximo de páginas"), min_value=1, max_value=50,
            key="crawl_max_paginas",
            help=t("Límite de páginas a analizar en profundidad."),
        )
    return (
        st.session_state.get("crawl_profundidad", 2),
        st.session_state.get("crawl_max_paginas", 15),
    )

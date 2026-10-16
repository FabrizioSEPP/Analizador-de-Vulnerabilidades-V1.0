import html as _html
import re

import streamlit as st
from models.i18n import t, es_o_en, columna, valor

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
    c = colores_actuales()
    return {
        "CRÍTICO": c["crit"], "ALTO": c["high"], "MEDIO": c["med"],
        "BAJO": c["low"], "INFO": c["info"],
    }.get(nivel_normalizado, c["info"])


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
    div[data-testid="stSidebar"] [data-testid="stExpander"] {
        border: 1px solid #35445d !important;
        border-radius: 14px !important;
        background: rgba(8, 20, 43, 0.72) !important;
        overflow: hidden;
        margin: 8px 0 12px;
    }
    div[data-testid="stSidebar"] [data-testid="stExpander"] summary {
        min-height: 62px;
        padding: 12px 16px !important;
    }
    div[data-testid="stSidebar"] [data-testid="stExpander"] summary p {
        font-size: 0.98rem !important;
        font-weight: 600 !important;
    }
    div[data-testid="stSidebar"] [data-testid="stCheckbox"] {
        margin: 12px 0 16px;
    }
    .st-key-sidebar-user-card {
        padding: 14px 12px 8px;
        margin-top: 10px;
        background: linear-gradient(145deg, #0b1a33, #0a1830);
        border: 1px solid #12305a;
        border-radius: 8px;
    }
    .sidebar-profile-head {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 14px;
    }
    .st-key-page_dashboard .stButton > button,
    .st-key-page_audit .stButton > button,
    .st-key-page_vulnerabilities .stButton > button,
    .st-key-page_assets .stButton > button,
    .st-key-page_monitoring .stButton > button,
    .st-key-page_reports .stButton > button,
    .st-key-page_settings .stButton > button {
        min-height: 36px !important;
        justify-content: flex-start !important;
        padding: 0 10px !important;
        border: 1px solid transparent !important;
        border-radius: 8px !important;
        background: transparent !important;
        box-shadow: none !important;
        color: #9bb0c8 !important;
        text-align: left !important;
        transform: none !important;
        font-size: 0.8rem !important;
    }
    .st-key-page_dashboard,
    .st-key-page_audit,
    .st-key-page_vulnerabilities,
    .st-key-page_assets,
    .st-key-page_monitoring,
    .st-key-page_reports,
    .st-key-page_settings {
        margin-bottom: -8px !important;
    }
    .st-key-page_dashboard .stButton > button:hover,
    .st-key-page_audit .stButton > button:hover,
    .st-key-page_vulnerabilities .stButton > button:hover,
    .st-key-page_assets .stButton > button:hover,
    .st-key-page_monitoring .stButton > button:hover,
    .st-key-page_reports .stButton > button:hover,
    .st-key-page_settings .stButton > button:hover {
        background: rgba(34, 211, 238, 0.08) !important;
        border-color: rgba(34, 211, 238, 0.22) !important;
        color: #e6edf7 !important;
    }
    .st-key-page_dashboard .stButton > button[kind="primary"],
    .st-key-page_audit .stButton > button[kind="primary"],
    .st-key-page_vulnerabilities .stButton > button[kind="primary"],
    .st-key-page_assets .stButton > button[kind="primary"],
    .st-key-page_monitoring .stButton > button[kind="primary"],
    .st-key-page_reports .stButton > button[kind="primary"],
    .st-key-page_settings .stButton > button[kind="primary"] {
        background: #0d345d !important;
        border-color: #075985 !important;
        box-shadow: inset 0 0 0 1px rgba(34, 211, 238, 0.12) !important;
        color: #e6edf7 !important;
    }
    .st-key-page_dashboard .stButton > button > div,
    .st-key-page_audit .stButton > button > div,
    .st-key-page_vulnerabilities .stButton > button > div,
    .st-key-page_assets .stButton > button > div,
    .st-key-page_monitoring .stButton > button > div,
    .st-key-page_reports .stButton > button > div,
    .st-key-page_settings .stButton > button > div {
        width: 100% !important;
        justify-content: flex-start !important;
    }
    .st-key-page_dashboard .stButton > button p,
    .st-key-page_audit .stButton > button p,
    .st-key-page_vulnerabilities .stButton > button p,
    .st-key-page_assets .stButton > button p,
    .st-key-page_monitoring .stButton > button p,
    .st-key-page_reports .stButton > button p,
    .st-key-page_settings .stButton > button p {
        width: 100%;
        text-align: left !important;
    }
    .st-key-page_dashboard [data-testid="stIconMaterial"],
    .st-key-page_audit [data-testid="stIconMaterial"],
    .st-key-page_vulnerabilities [data-testid="stIconMaterial"],
    .st-key-page_assets [data-testid="stIconMaterial"],
    .st-key-page_monitoring [data-testid="stIconMaterial"],
    .st-key-page_reports [data-testid="stIconMaterial"],
    .st-key-page_settings [data-testid="stIconMaterial"] {
        color: #38bdf8 !important;
    }
    .st-key-page_dashboard button[kind="primary"] [data-testid="stIconMaterial"],
    .st-key-page_audit button[kind="primary"] [data-testid="stIconMaterial"],
    .st-key-page_vulnerabilities button[kind="primary"] [data-testid="stIconMaterial"],
    .st-key-page_assets button[kind="primary"] [data-testid="stIconMaterial"],
    .st-key-page_monitoring button[kind="primary"] [data-testid="stIconMaterial"],
    .st-key-page_reports button[kind="primary"] [data-testid="stIconMaterial"],
    .st-key-page_settings button[kind="primary"] [data-testid="stIconMaterial"] {
        color: #67e8f9 !important;
    }
    .sidebar-profile-avatar {
        width: 44px;
        height: 44px;
        flex: 0 0 44px;
        display: grid;
        place-items: center;
        border: 1px solid rgba(34, 211, 238, 0.45);
        border-radius: 50%;
        background: #10274b;
        font-size: 21px;
    }
    }
    .sidebar-profile-name {
        color: #e6edf7;
        font-size: 1rem;
        font-weight: 700;
        overflow-wrap: anywhere;
    }
    .sidebar-profile-role {
        margin-top: 3px;
        color: #9bb0c8;
        font-size: 0.76rem;
    }
    .sidebar-profile-database {
        display: flex;
        align-items: center;
        gap: 8px;
        min-height: 26px;
        color: #9bb0c8;
        font-size: 0.8rem;
    }
    .sidebar-profile-dot {
        width: 8px;
        height: 8px;
        flex: 0 0 8px;
        border-radius: 50%;
    }
    .sidebar-profile-dot.online { background: #22c55e; }
    .sidebar-profile-dot.offline { background: #facc15; }
    .st-key-sidebar-user-card [data-testid="stMarkdownContainer"] p {
        margin-bottom: 0;
    }
    .st-key-logout_btn { margin: 10px 0 2px; }
    .st-key-logout_btn .stButton > button {
        min-height: 58px;
        border-radius: 20px;
        background: #132f55 !important;
        border: 1px solid #087c9b !important;
        color: #e6edf7 !important;
        box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.12), 0 6px 16px rgba(0, 0, 0, 0.18);
        font-size: 1rem;
    }
    .st-key-logout_btn .stButton > button:hover {
        background: #183b68 !important;
        border-color: #22d3ee !important;
        transform: translateY(-1px);
    }
    .st-key-sidebar-theme-compact { margin: 8px 0 16px; }
    .st-key-sidebar-theme-compact .side-label {
        margin: 0 0 14px;
        letter-spacing: 0.12em;
    }
    .st-key-sidebar-theme-compact [role="radiogroup"] {
        display: flex;
        flex-direction: row;
        align-items: center;
        justify-content: flex-start;
        gap: 14px;
        flex-wrap: wrap;
    }
    .sidebar-system-status {
        display: flex;
        align-items: center;
        gap: 9px;
        margin: 10px 2px 6px;
        padding: 10px 11px;
        background: #0b1a33;
        border: 1px solid #12305a;
        border-radius: 8px;
        color: #22c55e;
        font-size: 0.78rem;
        font-weight: 600;
    }
    .sidebar-system-status-sub {
        margin-top: 3px;
        color: #9bb0c8;
        font-size: 0.66rem;
        font-weight: 400;
    }
    .sidebar-system-status-dot {
        width: 9px;
        height: 9px;
        flex: 0 0 9px;
        border-radius: 50%;
        background: #22c55e;
        box-shadow: 0 0 10px rgba(34, 197, 94, 0.55);
    }

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
    .stButton > button[kind="primary"],
    button[data-testid="baseButton-primary"],
    .stFormSubmitButton > button[kind="primary"] {
        background: linear-gradient(135deg, #2563eb 0%, #22d3ee 100%);
        border: 1px solid rgba(34, 211, 238, 0.6);
        color: #ffffff;
    }

    div[data-testid="stTextInput"] input,
    div[data-testid="stNumberInput"] input,
    div[data-testid="stTextArea"] textarea,
    div[data-baseweb="input"] input,
    div[data-baseweb="base-input"] input {
        background: var(--surface-2) !important;
        color: var(--text) !important;
        -webkit-text-fill-color: var(--text) !important;
        border: 1px solid var(--border) !important;
        border-radius: var(--radius-sm) !important;
    }
    
    .app-hero {
        display: flex; justify-content: space-between; align-items: center;
        gap: 18px; flex-wrap: wrap;
        background: linear-gradient(90deg, #0b1a33 0%, #0f2a52 100%);
        border: 1px solid rgba(34, 211, 238, 0.28); border-radius: 14px;
        padding: 18px 22px; margin-bottom: 18px;
    }
    .hero-title { font-size: 1.5rem; font-weight: 700; color: var(--text); }
    .hero-sub { font-size: 0.82rem; color: var(--muted); margin-top: 4px; }
    .hero-right { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .pill {
        font-size: 0.75rem; font-weight: 600; padding: 6px 12px; border-radius: 999px;
        border: 1px solid var(--border); background: transparent; color: var(--muted);
    }
    .pill-mode { color: #22d3ee; border-color: rgba(34, 211, 238, 0.55); }
    .pill-ok { color: #22c55e; border-color: rgba(34, 197, 94, 0.55); }
    .pill-warn { color: #facc15; border-color: rgba(250, 204, 21, 0.55); }
    .pill-target { color: var(--low); border-color: rgba(14, 165, 233, 0.35); }

    .section-head { display: flex; gap: 12px; align-items: flex-start; margin: 26px 0 14px; }
    .section-bar {
        width: 4px; border-radius: 4px; align-self: stretch; min-height: 34px;
        background: linear-gradient(180deg, var(--primary-2), #7C3AED);
    }
    .section-title { font-size: 1.08rem; font-weight: 700; color: var(--text); }
    .section-sub { font-size: 0.8rem; color: var(--muted); margin-top: 2px; }

    .kpi-grid {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(168px, 1fr));
        gap: 12px; margin: 6px 0 8px;
    }
    .kpi-card {
        background: linear-gradient(180deg, var(--card-1), var(--card-2));
        border: 1px solid rgba(34, 211, 238, 0.28);
        border-left: 3px solid var(--accent, var(--primary)); border-radius: 14px;
        padding: 14px 16px;
    }
    .kpi-label { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; color: var(--muted-2); }
    .kpi-value { font-size: 1.55rem; font-weight: 800; margin-top: 6px; color: var(--accent, var(--text)); }

    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }
    .brand-badge {
        width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center;
        font-size: 1.1rem; font-weight: 800; color: #e6edf7;
        background: linear-gradient(135deg, rgba(34, 211, 238, 0.28), rgba(37, 99, 235, 0.28));
        border: 1px solid rgba(34, 211, 238, 0.5);
    }
    .brand-badge [data-testid="stIconMaterial"] {
        font-family: "Material Symbols Rounded";
        font-size: 30px;
        font-weight: 400;
        font-feature-settings: "liga";
        color: #22d3ee;
        line-height: 1;
    }
    .brand-title {
        font-size: 0.86rem;
        font-weight: 800;
        color: var(--text);
        white-space: nowrap;
    }
    .brand-sub { font-size: 0.64rem; color: var(--muted); white-space: nowrap; }
    
    .soc-sidebar-nav { display: grid; gap: 4px; margin: 16px 0 18px; }
    .soc-nav-item {
        padding: 8px 12px; border: 1px solid transparent; border-radius: 10px;
        color: var(--muted); font-size: 0.84rem; font-weight: 600;
    }
    .soc-nav-item:hover { color: var(--text); background: #12305a; }
    .soc-nav-item-active {
        color: var(--text); background: #12305a;
        border-color: rgba(34, 211, 238, 0.42);
    }
    .side-label {
        font-size: 0.68rem; font-weight: 700; letter-spacing: 0.1em;
        text-transform: uppercase; color: var(--muted-2); margin: 4px 0 8px;
    }
    .aviso {
        display: flex; gap: 10px; align-items: flex-start;
        padding: 12px 15px; margin: 10px 0; border-radius: var(--radius-sm);
        border: 1px solid var(--border); background: var(--surface-2);
        color: var(--text); font-size: 0.88rem;
    }
    .table-wrap {
        overflow-x: auto; border: 1px solid var(--border);
        border-radius: var(--radius); background: var(--surface);
    }
    table.data-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
    table.data-table th {
        text-align: left; padding: 10px 14px; background: var(--surface-2); color: var(--muted);
        font-size: 0.7rem; text-transform: uppercase; border-bottom: 1px solid var(--border);
    }
    table.data-table td {
        padding: 10px 14px; border-bottom: 1px solid var(--border-soft); color: var(--text);
    }
</style>
"""


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


def kpi_grid(cards: list):
    if not cards:
        return
    st.markdown(f'<div class="kpi-grid">{"".join(_kpi_card(c) for c in cards)}</div>',
                unsafe_allow_html=True)


def section_header(titulo: str, subtitulo: str = "", icono: str = ""):
    sub = f'<div class="section-sub">{_html.escape(subtitulo)}</div>' if subtitulo else ""
    st.markdown(
        f'<div class="section-head"><div class="section-bar"></div>'
        f'<div><div class="section-title">{_html.escape(titulo)}</div>{sub}</div></div>',
        unsafe_allow_html=True,
    )


def hero_header(url: str = "", modo: str = "", autorizado: bool = False):
    modos = {
        "sqli": "Inyección SQL", "load": "Prueba de Carga",
        "audit": "Auditoría Unificada", "port": "Escaneo de Puertos",
    }
    modo_label = modos.get(modo, "—")
    estado = "Autorizado" if autorizado else "Sin autorización"
    clase = "ok" if autorizado else "warn"
    objetivo = _html.escape(url) if url else "sin objetivo"
    st.markdown(
        f'<div class="app-hero">'
        f'<div><div class="hero-title">Analizador de Vulnerabilidades Web</div>'
        f'<div class="hero-sub">Pentesting ético | CVSS | PGI | OWASP</div></div>'
        f'<div class="hero-right">'
        f'<span class="pill pill-mode">Modo: {modo_label}</span>'
        f'<span class="pill pill-{clase}">Estado: {estado}</span>'
        f'<span class="pill pill-target" title="{objetivo}">Objetivo: {objetivo}</span>'
        f'</div></div>',
        unsafe_allow_html=True,
    )


_AVISO_ICONOS = {"info": "i", "success": "+", "warning": "!", "error": "X"}


def aviso_html(tipo: str, mensaje: str) -> str:
    return (
        f'<div class="aviso aviso-{tipo}">'
        f'<span>{_md_inline(mensaje)}</span></div>'
    )


def aviso(tipo: str, mensaje: str):
    st.markdown(aviso_html(tipo, mensaje), unsafe_allow_html=True)


def tabla(df):
    if df is None or len(df) == 0:
        st.markdown('<div class="empty-state">Sin datos para mostrar.</div>', unsafe_allow_html=True)
        return
    cabeceras = "".join(f"<th>{_html.escape(str(c))}</th>" for c in df.columns)
    filas = []
    for _, fila in df.iterrows():
        celdas = "".join(f"<td>{_html.escape(str(v))}</td>" for v in fila.tolist())
        filas.append(f"<tr>{celdas}</tr>")
    st.markdown(
        f'<div class="table-wrap"><table class="data-table">'
        f'<thead><tr>{cabeceras}</tr></thead><tbody>{"".join(filas)}</tbody>'
        f'</table></div>',
        unsafe_allow_html=True,
    )


def ui_theme_selector():
    st.markdown('<div class="side-label">Tema visual</div>', unsafe_allow_html=True)
    st.radio(
        "Tema",
        options=["sistema", "claro", "oscuro"],
        format_func=lambda k: {"sistema": "Sistema", "claro": "Claro", "oscuro": "Oscuro"}[k],
        key="tema",
        horizontal=True,
        label_visibility="collapsed",
    )
    return st.session_state.get("tema", "sistema")


def ui_sidebar():
    st.markdown(
        '<div class="brand">'
        '<div class="brand-badge"><span data-testid="stIconMaterial" translate="no">shield</span></div>'
        '<div><div class="brand-title">Corporativa Matheus</div>'
        '<div class="brand-sub">Plataforma de Ciberseguridad</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    pagina_actual = st.session_state.get("app_view", "dashboard")
    paginas = [
        ("dashboard", "Dashboard", ":material/home:"),
        ("audit", "Auditorías", ":material/shield:"),
        ("vulnerabilities", "Vulnerabilidades", ":material/warning:"),
        ("assets", "Activos", ":material/inventory_2:"),
        ("monitoring", "Monitoreo", ":material/monitor_heart:"),
        ("reports", "Reportes", ":material/description:"),
        ("settings", "Configuración", ":material/settings:"),
    ]
    for pagina, etiqueta, icono in paginas:
        argumentos = {
            "label": etiqueta,
            "icon": icono,
            "use_container_width": True,
            "key": f"page_{pagina}",
        }
        if pagina == pagina_actual:
            argumentos["type"] = "primary"
        if st.button(**argumentos):
            st.session_state["app_view"] = pagina
            st.rerun()


def ui_authorization_check(autorizado: bool) -> bool:
    with st.expander("Condiciones de uso", expanded=True):
        st.markdown(
            """
- Solo usa esta herramienta contra sistemas que poseas o contra los
  cuales tengas autorización escrita explícita.
- Escanear sistemas de terceros sin permiso puede ser ilegal.
- La prueba de carga tiene un techo máximo de concurrencia (50) para evitar
  convertirte en una herramienta de denegación de servicio (DoS).
            """
        )
        if st.button("Confirmar autorización", type="primary", use_container_width=True, key="auth_btn"):
            st.session_state.autorizado = True
            st.rerun()
    return st.session_state.get("autorizado", False)


def ui_url_input_sidebar(current_url: str) -> str:
    st.markdown('<div class="side-label">Objetivo</div>', unsafe_allow_html=True)
    return st.text_input(
        "URL objetivo",
        value=current_url,
        icon=":material/search:",
        placeholder="ejemplo.com:8080 o https://dominio/ruta",
        label_visibility="collapsed",
        key="sidebar_url",
    )


def ui_navigation_buttons(current_mode: str, autorizado: bool) -> str:
    st.markdown('<div class="side-label">Modos de analisis</div>', unsafe_allow_html=True)
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
        .st-key-nav_sqli .stButton > button {
            border-color: #f59e0b;
            background: rgba(245, 158, 11, 0.10);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    cols = st.columns(2)
    labels = [
        ("🔍 Inyección SQL", "sqli"),
        ("⚡ Prueba de Carga", "load"),
        ("🛡️ Auditoría Unificada", "audit"),
        ("🔌 Escaneo de Puertos", "port"),
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


def ui_execute_button(autorizado: bool, url_input: str, label: str = "▶ Ejecutar análisis"):
    disabled = not autorizado or not url_input.strip()
    return st.button(
        label,
        type="primary", use_container_width=True,
        disabled=disabled, key="execute_btn",
    )


def ui_internal_network_toggle() -> bool:
    return st.checkbox(
        "Permitir red interna (localhost / privadas)",
        key="permitir_privadas",
        help="Necesario para laboratorios locales (DVWA, Juice Shop). "
             "Dejalo desactivado para uso normal.",
    )


def parse_headers(texto: str) -> dict:
    headers = {}
    for linea in (texto or "").splitlines():
        if ":" in linea:
            clave, valor = linea.split(":", 1)
            if clave.strip():
                headers[clave.strip()] = valor.strip()
    return headers


def ui_sqli_options():
    """Opciones de inyección: cabeceras de sesión, cortesía y presupuesto."""
    valores_iniciales = {
        "sqli_headers": "",
        "sqli_pausa": 0.0,
        "sqli_max_objetivos": 8,
        "sqli_tiempo_maximo": 600,
        "sqli_max_peticiones": 4000,
        "sqli_probar_cabeceras": True,
        "sqli_probar_json": True,
        "sqli_extraer": True,
        "sqli_probar_apis": True,
        "sqli_usar_navegador": True,
        "sqli_segundo_orden": False,
        "sqli_confirmar": True,
        "sqli_abortar_waf": False,
    }
    for opcion, valor in valores_iniciales.items():
        st.session_state.setdefault(opcion, valor)

    with st.expander("Opciones de inyección", expanded=True):
        st.text_area(
            "Cabeceras extra (una por línea: `Nombre: valor`)",
            key="sqli_headers", height=90,
            placeholder="Cookie: sesion=abc123\nAuthorization: Bearer ...",
            help="Necesario para objetivos que requieren sesión o autenticación.",
        )
        st.slider(
            "Pausa entre peticiones (s)", min_value=0.0, max_value=1.0,
            step=0.1, key="sqli_pausa",
            help="Modo cortés: retardo entre peticiones para no saturar el objetivo.",
        )
        st.number_input(
            "Máximo de puntos a analizar", min_value=1, max_value=50,
            step=1, key="sqli_max_objetivos",
            help="Menos puntos = análisis más rápido.",
        )
        st.number_input(
            "Tiempo máximo (s)", min_value=0, max_value=7200,
            step=60, key="sqli_tiempo_maximo",
            help="Detiene el análisis al alcanzarlo. 0 = sin límite.",
        )
        st.number_input(
            "Máximo de peticiones", min_value=50, max_value=50000,
            step=50, key="sqli_max_peticiones",
            help="Límite de seguridad; al alcanzarlo se detiene el análisis.",
        )
        st.checkbox(
            "Probar cabeceras (User-Agent, Referer, X-Forwarded-For)",
            key="sqli_probar_cabeceras",
            help="Algunas apps registran o usan estas cabeceras en consultas.",
        )
        st.checkbox(
            "Probar cuerpo JSON (APIs / SPA)",
            key="sqli_probar_json",
            help="Envía los campos del formulario también como JSON.",
        )
        st.checkbox(
            "Extraer datos (versión, BD, usuario, tablas) al detectar UNION",
            key="sqli_extraer",
            help="Prueba de extracción acotada para evidenciar impacto.",
        )
        st.checkbox(
            "Descubrir endpoints de API (JS / SPA)",
            key="sqli_probar_apis",
            help="Analiza el JavaScript en busca de rutas /api, /rest, etc.",
        )
        st.checkbox(
            "Usar navegador headless (SPA con JS)",
            key="sqli_usar_navegador",
            help="Requiere Playwright instalado.",
        )
        st.checkbox(
            "Probar análisis de segundo orden (intrusivo: escribe datos)",
            key="sqli_segundo_orden",
            help="Inyecta en formularios y luego revisa otras páginas buscando errores.",
        )
        st.checkbox(
            "Confirmación estricta (menos falsos positivos)",
            key="sqli_confirmar",
            help="Desactívalo si el objetivo es inestable.",
        )
        st.checkbox(
            "Detener ante WAF / rate-limit",
            key="sqli_abortar_waf",
            help="Si se desactiva, sigue probando aunque el objetivo devuelva bloqueos.",
        )
    return (
        parse_headers(st.session_state.get("sqli_headers", "")),
        st.session_state.get("sqli_pausa", 0.0),
        int(st.session_state.get("sqli_max_peticiones", 1500)),
    )


def ui_audit_options():
    with st.expander("Opciones de auditoría profunda", expanded=True):
        st.slider(
            "Profundidad de rastreo", min_value=0, max_value=3,
            key="crawl_profundidad",
            help="0 = solo la página indicada. 2 = sigue enlaces hasta 2 niveles.",
        )
        st.slider(
            "Máximo de páginas", min_value=1, max_value=50,
            key="crawl_max_paginas",
            help="Límite de páginas a analizar en profundidad.",
        )
    return (
        st.session_state.get("crawl_profundidad", 2),
        st.session_state.get("crawl_max_paginas", 15),
    )


# --- Agregado desde main: ayuda, guia e idioma ---
def _ayuda_modulo_activo(modo: str, modo_label: str):
    """Popover con la explicación del módulo activo, junto a su banner."""
    from models.i18n import es_o_en
    from views.help_view import ayuda_modulo

    with st.popover(
        f"❔ {modo_label}",
        key=f"ayuda_modulo_{modo}",
        width="stretch",
        help=es_o_en("Qué responde este módulo y qué te entrega",
                     "What this module answers and what you get"),
    ):
        ayuda_modulo(modo)

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

def ui_ayuda_rapida():
    """Guía corta en la barra lateral: los pasos, sin salir de la vista."""
    from views.help_view import ayuda_rapida
    with st.popover(
        f"❓ {t('Ayuda y guía de uso')}",
        key="nav_ayuda",
        width="stretch",
        help=t("Resumen de los pasos para empezar."),
    ):
        ayuda_rapida()

def ui_guia():
    """Guía completa, en el área principal: mapa, paso a paso y referencia."""
    from models.i18n import es_o_en
    from views.help_view import guia
    sufijo = es_o_en(" · ¿qué módulo necesito?", " · which module do I need?")
    with st.expander(f"🧭 {t('Guía de uso')}{sufijo}", expanded=False):
        guia()

def _selector_nivel(clave: str) -> str:
    """Interruptor Básico / Avanzado dentro de un panel de opciones.

    No cambia ningún valor: solo decide qué controles se dibujan. Los que no se
    dibujan conservan su valor en `session_state`, así que el análisis es
    idéntico en ambos niveles.
    """
    from models.i18n import es_o_en
    etiquetas = {
        "basico": es_o_en("🟢 Básicas (recomendado)", "🟢 Basic (recommended)"),
        "avanzado": es_o_en("🔧 Avanzadas", "🔧 Advanced"),
    }
    return st.radio(
        es_o_en("Nivel de detalle", "Detail level"),
        options=["basico", "avanzado"],
        format_func=lambda k: etiquetas[k],
        horizontal=True, index=0,
        key=f"nivel_{clave}",
        label_visibility="collapsed",
    )

CSS_AYUDA_EXTRA = ':root{--primary-2:#22d3ee;--surface:#0b1a33;--surface-2:#0f2140;--border:#12305a;--border-soft:#12305a;--muted:#9bb0c8;--muted-2:#7f93b0;--text:#e6edf7;--crit:#ef4444;--radius:14px;--radius-sm:8px;--background-color:#050b1a;}\n/* Guía de uso: mapa de módulos, instructivo y referencia de opciones */\n    .help-intro {\n        font-size: .82rem; line-height: 1.55; color: var(--muted);\n        margin: 4px 0 12px;\n    }\n    .help-grid {\n        display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));\n        /* grid-auto-rows: 1fr iguala la altura de todas las filas, para que las\n           cuatro tarjetas queden simétricas aunque el texto sea de largo distinto. */\n        grid-auto-rows: 1fr;\n        gap: 14px; margin: 6px 0 4px;\n    }\n    @media (max-width: 1250px) { .help-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }\n    @media (max-width: 640px)  { .help-grid { grid-template-columns: 1fr; } }\n    .help-card {\n        display: flex; flex-direction: column; gap: 9px;\n        min-height: 300px; padding: 17px 16px;\n        border: 1px solid var(--border); border-radius: var(--radius);\n        background: var(--surface);\n    }\n    .help-card-icon { font-size: 1.5rem; line-height: 1; }\n    .help-card-title { font-size: .95rem; font-weight: 700; color: var(--text); }\n    .help-card-pregunta {\n        font-size: .85rem; font-weight: 600; line-height: 1.45; color: var(--primary-2);\n    }\n    .help-card-desc { font-size: .78rem; line-height: 1.55; color: var(--muted); flex: 1; }\n    .help-card-entrega {\n        font-size: .77rem; line-height: 1.5; color: var(--muted);\n        padding: 9px 11px; border-radius: var(--radius-sm);\n        background: var(--surface-2); border: 1px solid var(--border-soft);\n    }\n    .help-card-entrega b { color: var(--text); font-weight: 700; }\n    .help-card-foot {\n        font-size: .73rem; line-height: 1.45; color: var(--muted-2);\n        padding-top: 10px; border-top: 1px solid var(--border-soft);\n    }\n\n    /* Popover de ayuda de un módulo */\n    .help-pop-title { font-size: .9rem; font-weight: 700; color: var(--text); margin-bottom: 6px; }\n    .help-pop-body { font-size: .78rem; line-height: 1.55; color: var(--muted); margin-top: 8px; }\n    .help-pop-entrega {\n        font-size: .77rem; line-height: 1.5; color: var(--muted); margin-top: 9px;\n        padding: 8px 10px; border-radius: var(--radius-sm);\n        background: var(--surface-2); border: 1px solid var(--border-soft);\n    }\n    .help-pop-entrega b { color: var(--text); font-weight: 700; }\n    .help-pop-foot {\n        font-size: .73rem; line-height: 1.45; color: var(--muted-2);\n        margin-top: 9px; padding-top: 8px; border-top: 1px solid var(--border-soft);\n    }\n\n    /* Instructivo paso a paso */\n    .step-list { display: flex; flex-direction: column; gap: 8px; margin: 4px 0; }\n    .step {\n        display: flex; gap: 12px; align-items: flex-start;\n        padding: 12px 14px; border: 1px solid var(--border-soft);\n        border-radius: var(--radius-sm); background: var(--surface);\n    }\n    .step-num {\n        flex: 0 0 25px; width: 25px; height: 25px; border-radius: 50%;\n        display: grid; place-items: center;\n        font-size: .72rem; font-weight: 800; color: var(--background-color);\n        background: var(--primary-2);\n    }\n    .step-title { font-size: .86rem; font-weight: 700; color: var(--text); }\n    .step-desc { font-size: .79rem; line-height: 1.55; color: var(--muted); }\n\n    /* Referencia de opciones, agrupada por intención */\n    .opt-group { margin: 16px 0 4px; }\n    .opt-group:first-child { margin-top: 4px; }\n    .opt-group-title {\n        font-size: .82rem; font-weight: 700; color: var(--text);\n        padding-bottom: 7px; margin-bottom: 4px;\n        border-bottom: 1px solid var(--border);\n    }\n    .opt-row {\n        display: flex; gap: 16px; align-items: baseline;\n        padding: 9px 2px; border-bottom: 1px dashed var(--border-soft);\n    }\n    .opt-row:last-child { border-bottom: none; }\n    .opt-name {\n        flex: 0 0 210px; font-size: .78rem; font-weight: 600; color: var(--primary-2);\n    }\n    .opt-what { flex: 1; font-size: .79rem; line-height: 1.55; color: var(--muted); }\n    @media (max-width: 900px) {\n        .opt-row { flex-direction: column; gap: 3px; }\n        .opt-name { flex: 1; }\n    }\n    .opt-group-warn {\n        padding: 12px 14px; border-radius: var(--radius-sm);\n        border: 1px solid rgba(220, 38, 38, .38); background: rgba(220, 38, 38, .08);\n    }\n    .opt-group-warn .opt-group-title { color: var(--crit); border-bottom-color: rgba(220, 38, 38, .28); }\n    .opt-group-warn .opt-what { color: var(--text); }\n\n    /* Nota neutral: módulos sin panel de opciones */\n    .opt-nota {\n        padding: 12px 14px; border-radius: var(--radius-sm);\n        border: 1px dashed var(--border);\n        background: var(--surface-2);\n    }\n    .opt-nota .opt-group-title {\n        color: var(--muted); border-bottom: none;\n        padding-bottom: 0; margin-bottom: 2px;\n    }\n    .opt-nota .opt-what { color: var(--muted); }\n\n    /* Botón de guía rápida de la barra lateral */\n    .st-key-nav_ayuda .stButton > button {\n        font-weight: 600; font-size: .78rem;\n        border-radius: 999px; border-style: solid; border-width: 1px;\n        border-color: var(--border); background: var(--surface-2);\n    }\n    .st-key-nav_ayuda .stButton > button:hover {\n        border-color: var(--primary-2) !important;\n        box-shadow: 0 0 14px rgba(34, 211, 238, .22) !important;\n    }\n\n    /* Botón de ayuda del módulo activo, junto al banner */\n    .st-key-ayuda_modulo_sqli .stButton > button,\n    .st-key-ayuda_modulo_load .stButton > button,\n    .st-key-ayuda_modulo_audit .stButton > button,\n    .st-key-ayuda_modulo_port .stButton > button {\n        font-weight: 600; font-size: .78rem; color: var(--muted);\n        border-radius: 999px; border-style: solid; border-width: 1px;\n        border-color: var(--border); background: transparent;\n        margin-top: 0;\n    }\n    .st-key-ayuda_modulo_sqli .stButton > button:hover,\n    .st-key-ayuda_modulo_load .stButton > button:hover,\n    .st-key-ayuda_modulo_audit .stButton > button:hover,\n    .st-key-ayuda_modulo_port .stButton > button:hover {\n        color: var(--primary-2); border-color: var(--primary-2) !important;\n        box-shadow: 0 0 14px rgba(34, 211, 238, .22) !important;\n    }'
CSS_STYLES = CSS_STYLES + "<style>" + CSS_AYUDA_EXTRA + "</style>"

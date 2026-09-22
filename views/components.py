import html as _html
import re

import streamlit as st

# ---------------------------------------------------------------------------
# Motor de temas. Dos paletas (clara/oscura) con los mismos nombres de token;
# el CSS se escribe una sola vez con var(--token). "Sistema" usa
# prefers-color-scheme, así que reacciona en vivo al SO del usuario.
# ---------------------------------------------------------------------------
_PALETA_OSCURA = {
    "bg": "#0B1220",
    "glow_1": "rgba(99,102,241,0.18)",
    "glow_2": "rgba(56,189,248,0.10)",
    "surface": "#121A2B",
    "surface_2": "#182338",
    "surface_3": "#1E2A44",
    "border": "#243049",
    "border_soft": "rgba(148,163,184,0.14)",
    "text": "#E6EAF2",
    "muted": "#93A1B8",
    "muted_2": "#6B7A93",
    "primary": "#6366F1",
    "primary_2": "#818CF8",
    "crit": "#F87171", "high": "#FB923C", "med": "#FBBF24",
    "low": "#38BDF8", "info": "#94A3B8", "ok": "#34D399",
    "shadow": "0 14px 40px rgba(2,6,23,0.45)",
    "shadow_sm": "0 8px 22px rgba(2,6,23,0.35)",
    "sidebar_1": "#0E1729", "sidebar_2": "#0A0F1D",
    "hero_1": "rgba(30,41,70,0.95)", "hero_2": "rgba(17,24,42,0.92)",
    "card_1": "rgba(24,35,56,0.90)", "card_2": "rgba(18,26,43,0.90)",
    "primary_color": "#6366F1",
    "background_color": "#0B1220",
    "secondary_background_color": "#121A2B",
    "text_color": "#E6EAF2",
    "font": "'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif",
}

_PALETA_CLARA = {
    "bg": "#F4F6FB",
    "glow_1": "rgba(99,102,241,0.12)",
    "glow_2": "rgba(56,189,248,0.10)",
    "surface": "#FFFFFF",
    "surface_2": "#F1F5F9",
    "surface_3": "#E9EEF6",
    "border": "#E2E8F0",
    "border_soft": "rgba(15,23,42,0.08)",
    "text": "#1E293B",
    "muted": "#64748B",
    "muted_2": "#94A3B8",
    "primary": "#6366F1",
    "primary_2": "#818CF8",
    "crit": "#DC2626", "high": "#EA580C", "med": "#D97706",
    "low": "#0284C7", "info": "#64748B", "ok": "#059669",
    "shadow": "0 14px 40px rgba(15,23,42,0.10)",
    "shadow_sm": "0 8px 22px rgba(15,23,42,0.08)",
    "sidebar_1": "#FFFFFF", "sidebar_2": "#F1F5F9",
    "hero_1": "#FFFFFF", "hero_2": "#F8FAFC",
    "card_1": "#FFFFFF", "card_2": "#F8FAFC",
    "primary_color": "#6366F1",
    "background_color": "#F4F6FB",
    "secondary_background_color": "#FFFFFF",
    "text_color": "#1E293B",
    "font": "'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif",
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
    html, body, [class*="css"], .stApp, input, textarea, button {
        font-family: var(--font) !important;
    }

    .stApp {
        background:
            radial-gradient(1100px 520px at 12% -12%, var(--glow-1), transparent 60%),
            radial-gradient(900px 520px at 95% 0%, var(--glow-2), transparent 55%),
            var(--bg);
    }

    header[data-testid="stHeader"] { background: transparent; }

    div[data-testid="stAppViewContainer"] > .main .block-container,
    .block-container { padding-top: 1.1rem; padding-bottom: 3.5rem; max-width: 1320px; }

    /* ------------------------------------------------------------- Sidebar */
    div[data-testid="stSidebar"] {
        background: linear-gradient(180deg, var(--sidebar-1) 0%, var(--sidebar-2) 100%);
        border-right: 1px solid var(--border);
    }
    div[data-testid="stSidebar"] hr { border-color: var(--border); margin: 14px 0; }

    /* ------------------------------------------------------------- Botones */
    .stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
        border-radius: var(--radius-sm);
        border: 1px solid var(--border);
        background: var(--surface-2);
        color: var(--text);
        font-weight: 600;
        transition: transform .15s ease, border-color .15s ease, box-shadow .15s ease, background .15s ease;
    }
    .stButton > button:hover, .stFormSubmitButton > button:hover {
        border-color: var(--primary);
        transform: translateY(-1px);
        box-shadow: var(--shadow-sm);
    }
    .stButton > button:focus-visible, .stFormSubmitButton > button:focus-visible {
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.4) !important;
    }
    .stButton > button[kind="primary"],
    button[data-testid="baseButton-primary"],
    .stFormSubmitButton > button[kind="primary"] {
        background: linear-gradient(135deg, var(--primary) 0%, #7C3AED 100%);
        border: 1px solid transparent;
        color: #fff;
    }
    .stButton > button[kind="primary"]:hover { filter: brightness(1.08); }
    .stButton > button:disabled { opacity: .45; cursor: not-allowed; transform: none; }

    div[data-testid="stSidebar"] .stButton > button { text-align: left; justify-content: flex-start; }
    div[data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, rgba(99, 102, 241, 0.22), rgba(124, 58, 237, 0.14));
        border: 1px solid rgba(129, 140, 248, 0.55);
        box-shadow: inset 3px 0 0 var(--primary-2);
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
        border: 1px solid var(--border) !important;
        border-radius: var(--radius) !important;
        background: linear-gradient(180deg, var(--card-1), var(--card-2)) !important;
        overflow: hidden;
    }
    div[data-testid="stExpander"] summary:hover { color: var(--primary); }
    div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }

    div[data-testid="stAlert"] {
        border-radius: var(--radius-sm);
        border: 1px solid var(--border);
        background: var(--surface-2);
        color: var(--text);
    }
    div[data-testid="stPlotlyChart"] { border-radius: var(--radius); }

    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 8px; border: 2px solid var(--bg); }
    ::-webkit-scrollbar-thumb:hover { background: var(--muted-2); }

    /* ------------------------------------------------- Componentes propios */
    .app-hero {
        display: flex; justify-content: space-between; align-items: center;
        gap: 18px; flex-wrap: wrap;
        background: linear-gradient(120deg, var(--hero-1), var(--hero-2));
        border: 1px solid var(--border); border-radius: var(--radius);
        padding: 18px 22px; box-shadow: var(--shadow); margin-bottom: 18px;
    }
    .hero-title {
        font-size: 1.5rem; font-weight: 800; letter-spacing: -0.02em;
        background: linear-gradient(90deg, #6366F1, #8B5CF6, #D946EF);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    }
    .hero-sub { font-size: 0.82rem; color: var(--muted); margin-top: 4px; }
    .hero-right { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .pill {
        font-size: 0.75rem; font-weight: 600; padding: 6px 12px; border-radius: 999px;
        border: 1px solid var(--border); background: var(--surface-2); color: var(--muted);
        max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .pill-mode { color: var(--primary); border-color: rgba(99, 102, 241, 0.4); background: rgba(99, 102, 241, 0.12); }
    .pill-ok { color: var(--ok); border-color: rgba(16, 185, 129, 0.4); background: rgba(16, 185, 129, 0.12); }
    .pill-warn { color: var(--med); border-color: rgba(234, 179, 8, 0.4); background: rgba(234, 179, 8, 0.12); }
    .pill-target { color: var(--low); border-color: rgba(14, 165, 233, 0.35); background: rgba(14, 165, 233, 0.10); }

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
        border: 1px solid var(--border); border-radius: var(--radius-sm);
        padding: 14px 16px; overflow: hidden;
        transition: transform .15s ease, border-color .15s ease, box-shadow .15s ease;
    }
    .kpi-card::before {
        content: ""; position: absolute; top: 0; bottom: 0; left: 0;
        width: 4px; background: var(--accent, var(--primary));
    }
    .kpi-card:hover { transform: translateY(-2px); border-color: var(--primary); box-shadow: var(--shadow-sm); }
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
        border: 1px solid var(--border); border-left: 4px solid var(--f-color, var(--primary));
        border-radius: 12px; padding: 12px 15px; margin-bottom: 9px;
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
        font-size: 1.3rem;
        background: linear-gradient(135deg, rgba(99, 102, 241, 0.35), rgba(124, 58, 237, 0.25));
        border: 1px solid rgba(129, 140, 248, 0.45);
    }
    .brand-title { font-size: 1.02rem; font-weight: 800; color: var(--text); letter-spacing: -0.01em; }
    .brand-sub { font-size: 0.72rem; color: var(--muted); }

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
        f'<div><div class="hero-title">🛡️ Analizador de Vulnerabilidades Web</div>'
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
    st.markdown('<div class="side-label">🎨 Tema</div>', unsafe_allow_html=True)
    st.radio(
        "Tema",
        options=["sistema", "claro", "oscuro"],
        format_func=lambda k: {"sistema": "🖥️ Sistema", "claro": "☀️ Claro", "oscuro": "🌙 Oscuro"}[k],
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


def ui_authorization_check(autorizado: bool) -> bool:
    with st.expander("⚠️ Condiciones de uso", expanded=False):
        st.markdown(
            """
            - Solo usa esta herramienta contra sistemas que **poseas** o contra los
              cuales tengas **autorización escrita explícita**.
            - Escanear sistemas de terceros sin permiso puede ser **ilegal**.
            - La prueba de carga tiene un techo máximo de concurrencia (50) para evitar
              convertirte en una herramienta de denegación de servicio (DoS).
            """
        )
        if st.button("✅ Confirmar autorización", type="primary", use_container_width=True, key="auth_btn"):
            st.session_state.autorizado = True
            st.rerun()
    return st.session_state.get("autorizado", False)


def ui_url_input_sidebar(current_url: str) -> str:
    st.markdown('<div class="side-label">🎯 Objetivo</div>', unsafe_allow_html=True)
    return st.text_input(
        "URL objetivo",
        value=current_url,
        placeholder="ejemplo.com:8080 o https://dominio/ruta",
        label_visibility="collapsed",
        key="sidebar_url",
    )


def ui_navigation_buttons(current_mode: str, autorizado: bool) -> str:
    st.markdown('<div class="side-label">🧭 Módulos de análisis</div>', unsafe_allow_html=True)
    cols = st.columns(2)
    labels = [
        ("🔍 Inyección SQL", "sqli"),
        ("⚡ Carga", "load"),
        ("🛡️ Auditoría", "audit"),
        ("🔌 Puertos", "port"),
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
        "▶  Ejecutar análisis",
        type="primary", use_container_width=True,
        disabled=disabled, key="execute_btn",
    )


def ui_internal_network_toggle() -> bool:
    return st.checkbox(
        "🌐 Permitir red interna (localhost / privadas)",
        key="permitir_privadas",
        help="Necesario para laboratorios locales (DVWA, Juice Shop). "
             "Déjalo desactivado para uso normal.",
    )


def ui_audit_options():
    with st.expander("⚙️ Opciones de auditoría profunda", expanded=False):
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

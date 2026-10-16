"""Guía de uso de la aplicación: mapa de módulos, instructivo y referencia de
opciones avanzadas.

Pensado para clientes que abren la herramienta por primera vez. La regla de
escritura es: primero la **pregunta** que el cliente quiere responder ("¿alguien
puede robar mi base de datos?"), y después el **término técnico** ("detección de
inyección SQL"). Al revés no funciona: nadie elige un módulo por su nombre
técnico.

El texto se guarda como pareja ES/EN y se elige con `es_o_en()`, en vez de
`t()`, porque estas cadenas son largas y dependen entre sí (comparten palabras);
el diccionario de `models/i18n.py`, basado en literales, se rompería al tocar
una coma.
"""

import html as _html

import streamlit as st
from models.i18n import t

from models.i18n import es_o_en


def _b(par: tuple) -> str:
    """Elige el texto ES o EN de una pareja."""
    return es_o_en(par[0], par[1])


# --------------------------------------------------------------------- módulos
# "pregunta" es lo que el cliente quiere saber. "detalle" y "entrega" son la
# traducción técnica. "cuando" evita que el cliente elija mal.
MODULOS = [
    {
        "id": "sqli",
        "icono": "🔍",
        "titulo": ("Inyección SQL", "SQL Injection"),
        "pregunta": (
            "¿Alguien podría leer, modificar o borrar los datos de mi base de datos "
            "desde la web?",
            "Could someone read, modify or delete my database data through the web?",
        ),
        "detalle": (
            "Prueba cada parámetro, formulario y API de la página con técnicas "
            "reales: errores, booleano, tiempo y UNION.",
            "Tests every parameter, form and API with real techniques: error-based, "
            "boolean-based, time-based and UNION.",
        ),
        "entrega": (
            "Hallazgos con puntuación CVSS, evidencia y un comando para reproducirlo",
            "Findings with a CVSS score, evidence and a command to reproduce them",
        ),
        "cuando": (
            "Es el módulo principal de una auditoría. Empieza por aquí.",
            "This is the core module of an audit. Start here.",
        ),
    },
    {
        "id": "load",
        "icono": "⚡",
        "titulo": ("Prueba de Carga", "Load Test"),
        "pregunta": (
            "¿Mi sitio aguanta cuando entran muchos usuarios a la vez?",
            "Can my site hold up when many users arrive at once?",
        ),
        "detalle": (
            "Sube la concurrencia en escalones (hasta 50 peticiones simultáneas) y "
            "mide en qué punto el servicio se degrada.",
            "Ramps up concurrency in steps (up to 50 simultaneous requests) and "
            "measures where the service degrades.",
        ),
        "entrega": (
            "Grado de Salud del Sistema (PGI), percentiles de latencia y throughput",
            "Performance Grade Index (PGI), latency percentiles and throughput",
        ),
        "cuando": (
            "Antes de una campaña, un lanzamiento o una fecha de alto tráfico.",
            "Before a campaign, a launch or a high-traffic date.",
        ),
    },
    {
        "id": "audit",
        "icono": "🛡️",
        "titulo": ("Auditoría Unificada", "Unified Audit"),
        "pregunta": (
            "¿Qué tan expuesta está mi web en general?",
            "How exposed is my website overall?",
        ),
        "detalle": (
            "Recorre el sitio y revisa HTTPS, cabeceras, cookies, formularios, "
            "tecnologías, archivos expuestos y directivas CSP.",
            "Crawls the site and reviews HTTPS, headers, cookies, forms, "
            "technologies, exposed files and CSP directives.",
        ),
        "entrega": (
            "Security Score de 0 a 100, hallazgos por severidad y remediación OWASP",
            "A Security Score from 0 to 100, findings by severity and OWASP remediation",
        ),
        "cuando": (
            "Para una vista panorámica y para reportar a un jefe o a un cliente.",
            "For an overall picture and to report to a manager or a client.",
        ),
    },
    {
        "id": "port",
        "icono": "🔌",
        "titulo": ("Escaneo de Puertos", "Port Scan"),
        "pregunta": (
            "¿Qué servicios quedan accesibles desde internet en mi servidor?",
            "Which services stay reachable from the internet on my server?",
        ),
        "detalle": (
            "Recorre los puertos TCP del 1 al 1024 e identifica el servicio de cada "
            "puerto abierto.",
            "Scans TCP ports 1 to 1024 and identifies the service behind each open port.",
        ),
        "entrega": (
            "Lista de puertos abiertos con su servicio correspondiente",
            "A list of open ports with the matching service",
        ),
        "cuando": (
            "Para confirmar que no haya paneles de administración ni servicios "
            "innecesarios expuestos.",
            "To confirm no admin panels or unnecessary services are exposed.",
        ),
    },
]

MODULO_POR_ID = {m["id"]: m for m in MODULOS}


# ------------------------------------------------------------------ instructivo
PASOS = [
    (
        "Inicia sesión",
        "Entra con tu cuenta. Si no tienes una, créala en la pestaña «Crear Cuenta» "
        "de la pantalla de acceso.",
        "Sign in",
        "Log in with your account. If you do not have one, create it on the "
        "«Create Account» tab of the login screen.",
    ),
    (
        "Confirma la autorización",
        "Abre «Condiciones de uso» en la barra lateral y pulsa «Confirmar "
        "autorización». Es obligatorio: solo se permite auditar sistemas propios o "
        "con permiso escrito.",
        "Confirm authorization",
        "Open «Terms of Use» in the sidebar and press «Confirm authorization». It is "
        "mandatory: you may only audit your own systems or systems you have written "
        "permission for.",
    ),
    (
        "Escribe la URL objetivo",
        "No hace falta que incluya parámetros: la herramienta descubre los de la "
        "página y los de sus formularios.",
        "Enter the target URL",
        "It does not need to include parameters: the tool discovers the ones in the "
        "page and in its forms.",
    ),
    (
        "Elige el módulo",
        "Selecciona en «Módulos de análisis» el que responde a tu pregunta. Si no "
        "sabes cuál, vuelve al mapa de módulos.",
        "Choose a module",
        "Pick the one that answers your question in «Analysis modules». If you are "
        "unsure, go back to the module map.",
    ),
    (
        "Ajusta las opciones (opcional)",
        "En nivel Básico solo aparecen las tres opciones que suelen importar. Cambia "
        "a Avanzado para ver todas.",
        "Adjust the options (optional)",
        "At Basic level only the three options that usually matter are shown. Switch "
        "to Advanced to see them all.",
    ),
    (
        "Ejecuta y lee el resultado",
        "Pulsa «Ejecutar análisis». Verás el progreso en vivo y, al terminar, el "
        "panel con el detalle de cada hallazgo.",
        "Run it and read the result",
        "Press «Run analysis». You will see live progress and, when it finishes, the "
        "panel with the detail of every finding.",
    ),
]


# --------------------------------------------------- referencia por intención
# Un cliente no busca "sqli_abortar_waf", busca "mi web tiene un WAF". Por eso
# las opciones se agrupan por lo que quieren conseguir, no por nombre técnico.
GRUPOS_OPCIONES = [
    {
        "titulo": ("Quiero que termine más rápido", "I want it to finish faster"),
        "icono": "⚡",
        "opciones": [
            (
                "Máximo de puntos a analizar",
                "Maximum points to analyse",
                "Cuántos parámetros se prueban en total. Menos puntos, análisis más rápido.",
                "How many parameters are tested in total. Fewer points, faster analysis.",
            ),
            (
                "Pausa entre peticiones",
                "Pause between requests",
                "Retardo entre peticiones. Modo cortés: no satura el objetivo.",
                "Delay between requests. Courteous mode: it does not flood the target.",
            ),
            (
                "Tiempo máximo",
                "Maximum time",
                "Detiene el análisis al alcanzarlo. 0 significa sin límite.",
                "Stops the analysis when reached. 0 means no limit.",
            ),
            (
                "Máximo de peticiones",
                "Maximum requests",
                "Límite de seguridad: si se agota, el análisis se detiene.",
                "Safety limit: if it runs out, the analysis stops.",
            ),
        ],
    },
    {
        "titulo": ("Quiero encontrar más hallazgos", "I want to find more findings"),
        "icono": "🔍",
        "opciones": [
            (
                "Probar cabeceras",
                "Test headers",
                "User-Agent, Referer y X-Forwarded-For. Algunas aplicaciones los usan "
                "en consultas SQL.",
                "User-Agent, Referer and X-Forwarded-For. Some applications use them "
                "in SQL queries.",
            ),
            (
                "Probar cuerpo JSON",
                "Test JSON body",
                "Envía los campos del formulario también como JSON, para APIs y SPAs.",
                "Sends the form fields as JSON too, for APIs and SPAs.",
            ),
            (
                "Descubrir endpoints de API",
                "Discover API endpoints",
                "Analiza el JavaScript en busca de rutas /api, /rest y similares.",
                "Analyses the JavaScript looking for /api, /rest and similar routes.",
            ),
            (
                "Usar navegador headless",
                "Use headless browser",
                "Captura las peticiones reales de una web que se construye con "
                "JavaScript. Requiere Playwright instalado.",
                "Captures the real requests of a JavaScript-driven site. Requires "
                "Playwright to be installed.",
            ),
            (
                "Extraer datos con UNION",
                "Extract data with UNION",
                "Al detectar una UNION, intenta obtener la versión del motor para "
                "evidenciar el impacto real.",
                "On detecting a UNION, tries to retrieve the engine version to prove "
                "the real impact.",
            ),
        ],
    },
    {
        "titulo": ("Mi objetivo tiene sesión o está protegido", "My target needs a session or is protected"),
        "icono": "🔒",
        "opciones": [
            (
                "Cabeceras extra",
                "Extra headers",
                "Cookie o Authorization, una por línea, para analizar objetivos que "
                "requieren sesión iniciada.",
                "Cookie or Authorization, one per line, to analyse targets that need "
                "a signed-in session.",
            ),
            (
                "Confirmación estricta",
                "Strict confirmation",
                "Repite cada hallazgo para descartar falsos positivos. Actívalo si el "
                "objetivo es inestable y te parece que pierdes detecciones.",
                "Repeats every finding to rule out false positives. Turn it off if the "
                "target is unstable and you think detections are being lost.",
            ),
            (
                "Detener ante WAF",
                "Stop on WAF",
                "Se detiene cuando el objetivo responde con un bloqueo. Si lo "
                "desactivas, sigue probando.",
                "Stops when the target answers with a block. If you turn it off, it "
                "keeps testing.",
            ),
            (
                "Permitir red interna",
                "Allow internal network",
                "Necesario solo para laboratorios locales (DVWA, Juice Shop). "
                "Desactívalo en uso normal: es lo que bloquea ataques SSRF.",
                "Needed only for local labs (DVWA, Juice Shop). Turn it off for normal "
                "use: it is what blocks SSRF attacks.",
            ),
        ],
    },
    {
        "titulo": ("Quiero revisar más sitio (Auditoría)", "I want to scan more of the site (Audit)"),
        "icono": "🕸️",
        "opciones": [
            (
                "Profundidad de rastreo",
                "Crawl depth",
                "Cuántos niveles de enlaces sigue. 0 analiza solo la página indicada.",
                "How many link levels it follows. 0 analyses only the given page.",
            ),
            (
                "Máximo de páginas",
                "Maximum pages",
                "Límite de páginas a analizar en profundidad.",
                "Limit of pages analysed in depth.",
            ),
        ],
    },
]

AVISO_INTRUSIVO = (
    "Probar SQLi de segundo orden",
    "Inyecta en formularios y luego revisa otras páginas buscando errores SQL "
    "disparados más tarde. Es heurístico y MODIFICA datos del objetivo: solo actívalo "
    "con autorización expresa.",
    "Probing for second-order SQL injection",
    "It injects into forms and then checks other pages looking for SQL errors fired "
    "later. It is heuristic and it MODIFIES data on the target: enable it only with "
    "express authorisation.",
)

# Dos de los cuatro módulos no tienen panel. Se dice tal cual en la referencia,
# para que un cliente no busque un ajuste que no existe.
NOTA_SIN_OPCIONES = (
    "Prueba de Carga y Escaneo de Puertos no tienen opciones configurables",
    "Trabajan con valores fijos: hasta 50 peticiones simultáneas en la prueba de "
    "carga, y los puertos TCP del 1 al 1024 en el escaneo. Los paneles de la barra "
    "lateral corresponden a Inyección SQL y a Auditoría Unificada.",
    "Load Test and Port Scan have no configurable options",
    "They run on fixed values: up to 50 simultaneous requests in the load test, and "
    "TCP ports 1 to 1024 in the scan. The panels in the sidebar belong to SQL "
    "Injection and Unified Audit.",
)


# ------------------------------------------------------------------ renderizado
def _tarjeta_html(m: dict) -> str:
    pie = f"{_b(m['cuando'])}"
    return (
        f'<div class="help-card">'
        f'<div class="help-card-icon">{m["icono"]}</div>'
        f'<div class="help-card-title">{_html.escape(_b(m["titulo"]))}</div>'
        f'<div class="help-card-pregunta">{_html.escape(_b(m["pregunta"]))}</div>'
        f'<div class="help-card-desc">{_html.escape(_b(m["detalle"]))}</div>'
        f'<div class="help-card-entrega"><b>'
        f'{es_o_en("Qué obtienes", "What you get")}:</b> '
        f'{_html.escape(_b(m["entrega"]))}</div>'
        f'<div class="help-card-foot">{_html.escape(pie)}</div>'
        f'</div>'
    )


def _pasos_html() -> str:
    filas = []
    for i, paso in enumerate(PASOS, start=1):
        filas.append(
            f'<div class="step">'
            f'<div class="step-num">{i}</div>'
            f'<div><div class="step-title">{_html.escape(_b((paso[0], paso[2])))}</div>'
            f'<div class="step-desc">{_html.escape(_b((paso[1], paso[3])))}</div></div>'
            f'</div>'
        )
    return f'<div class="step-list">{"".join(filas)}</div>'


def _opciones_html() -> str:
    bloques = [
        f'<div class="opt-group opt-nota">'
        f'<div class="opt-group-title">ℹ️ '
        f'{_html.escape(_b((NOTA_SIN_OPCIONES[0], NOTA_SIN_OPCIONES[2])))}</div>'
        f'<div class="opt-what">'
        f'{_html.escape(_b((NOTA_SIN_OPCIONES[1], NOTA_SIN_OPCIONES[3])))}</div>'
        f'</div>'
    ]
    for grupo in GRUPOS_OPCIONES:
        filas = []
        for op in grupo["opciones"]:
            filas.append(
                f'<div class="opt-row">'
                f'<div class="opt-name">{_html.escape(_b((op[0], op[1])))}</div>'
                f'<div class="opt-what">{_html.escape(_b((op[2], op[3])))}</div>'
                f'</div>'
            )
        bloques.append(
            f'<div class="opt-group">'
            f'<div class="opt-group-title">{grupo["icono"]} '
            f'{_html.escape(_b(grupo["titulo"]))}</div>'
            f'{"".join(filas)}</div>'
        )
    bloques.append(
        f'<div class="opt-group opt-group-warn">'
        f'<div class="opt-group-title">⚠️ {_html.escape(_b((AVISO_INTRUSIVO[0], AVISO_INTRUSIVO[2])))}</div>'
        f'<div class="opt-what">{_html.escape(_b((AVISO_INTRUSIVO[1], AVISO_INTRUSIVO[3])))}</div>'
        f'</div>'
    )
    return "".join(bloques)


def mapa_modulos():
    """Mapa de módulos: cuatro tarjetas con la misma estructura."""
    st.markdown(
        f'<div class="help-grid">{"".join(_tarjeta_html(m) for m in MODULOS)}</div>',
        unsafe_allow_html=True,
    )


def instructivo():
    """Pasos del uso, de principio a fin."""
    st.markdown(_pasos_html(), unsafe_allow_html=True)


def referencia_opciones():
    """Todas las opciones avanzadas, agrupadas por intención."""
    st.markdown(_opciones_html(), unsafe_allow_html=True)


def guia():
    """Guía completa: mapa, instructivo y referencia, en pestañas."""
    st.markdown(
        '<div class="help-intro">'
        + _html.escape(es_o_en(
            "Todo lo que necesitás para usar la herramienta. Empieza por el mapa si "
            "no sabes qué módulo elegir.",
            "Everything you need to use the tool. Start with the map if you are not "
            "sure which module to pick.",
        ))
        + "</div>",
        unsafe_allow_html=True,
    )
    tab_mapa, tab_pasos, tab_opciones = st.tabs([
        "🧭 " + es_o_en("Mapa de módulos", "Module map"),
        "📋 " + es_o_en("Paso a paso", "Step by step"),
        "⚙️ " + es_o_en("Opciones avanzadas", "Advanced options"),
    ])
    with tab_mapa:
        mapa_modulos()
    with tab_pasos:
        instructivo()
    with tab_opciones:
        referencia_opciones()


def ayuda_rapida():
    """Versión corta para la barra lateral: qué elegir y en qué orden."""
    st.markdown(_pasos_html(), unsafe_allow_html=True)
    st.markdown(
        '<div class="help-intro">'
        + _html.escape(es_o_en(
            "Abrí la guía completa para ver todas las opciones avanzadas.",
            "Open the full guide to see all the advanced options.",
        ))
        + "</div>",
        unsafe_allow_html=True,
    )


def ayuda_modulo(mode_id: str):
    """Explicación de un módulo concreto, para el popover de su botón."""
    m = MODULO_POR_ID.get(mode_id)
    if not m:
        return
    st.markdown(
        f'<div class="help-pop-title">{m["icono"]} {_html.escape(_b(m["titulo"]))}</div>'
        f'<div class="help-card-pregunta">{_html.escape(_b(m["pregunta"]))}</div>'
        f'<div class="help-pop-body">{_html.escape(_b(m["detalle"]))}</div>'
        f'<div class="help-pop-entrega"><b>'
        f'{es_o_en("Qué obtienes", "What you get")}:</b> '
        f'{_html.escape(_b(m["entrega"]))}</div>'
        f'<div class="help-pop-foot">{_html.escape(_b(m["cuando"]))}</div>',
        unsafe_allow_html=True,
    )
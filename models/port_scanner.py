import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from models.http_utils import es_objetivo_privado
from models.i18n import es_o_en


def extraer_host(url_o_dominio: str) -> str:
    texto = url_o_dominio.strip()
    if "://" not in texto:
        texto = "http://" + texto
    host = urlparse(texto).hostname
    if not host:
        raise ValueError(f"No se pudo interpretar la URL: {url_o_dominio}")
    return host


def obtener_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"No se pudo resolver {host}: {e}")


def _parsear_rango(rango_puertos: str) -> tuple[int, int]:
    """Acepta '80' (un puerto) o '1-1024' (rango). Valida límites."""
    rango = (rango_puertos or "").strip()
    try:
        if "-" in rango:
            partes = rango.split("-")
            if len(partes) != 2:
                raise ValueError
            inicio, fin = int(partes[0]), int(partes[1])
        else:
            inicio = fin = int(rango)
    except ValueError:
        raise ValueError(f"Rango de puertos inválido: {rango_puertos!r}")

    if not (1 <= inicio <= 65535 and 1 <= fin <= 65535) or inicio > fin:
        raise ValueError(f"Rango de puertos inválido: {rango_puertos!r}")
    return inicio, fin


def escanear_puertos_basicos(ip: str, rango_puertos: str = "1-1024") -> list:
    inicio, fin = _parsear_rango(rango_puertos)
    puertos_abiertos = []

    def verificar(puerto):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, puerto)) == 0:
                    try:
                        servicio = socket.getservbyport(puerto, "tcp")
                    except (OSError, ValueError):
                        servicio = "desconocido"
                    return {"puerto": puerto, "protocolo": "tcp", "estado": "abierto", "servicio": servicio}
        except (socket.error, OSError):
            pass
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        for resultado in executor.map(verificar, range(inicio, fin + 1)):
            if resultado:
                puertos_abiertos.append(resultado)
    return puertos_abiertos


def analizar_objetivo(url_o_dominio: str, rango_puertos: str = "1-1024", permitir_privadas: bool = False) -> dict:
    host = extraer_host(url_o_dominio)
    if not permitir_privadas and es_objetivo_privado(host):
        raise ValueError(
            "El objetivo apunta a una dirección interna o privada (posible SSRF). "
            "Activa 'Permitir red interna' en la barra lateral si es un objetivo de laboratorio."
        )
    ip = obtener_ip(host)
    puertos = escanear_puertos_basicos(ip, rango_puertos)
    return {
        "url_original": url_o_dominio, "host": host, "ip": ip,
        "puertos": puertos, "total_puertos": len(puertos),
    }


# =============================================================================
# CATÁLOGO DE AMENAZAS — qué significa cada puerto y qué hacer
# =============================================================================

CATALOGO = {
    21: {"nivel": "alto", "nombre": "Transferencia de archivos (FTP) sin cifrar",
         "amenaza": "Envía usuario y contraseña en texto plano; puede ser interceptado en la red.",
         "recomendaciones": ["Migrar a SFTP o FTPS.", "Cerrar el puerto si no se usa.", "Restringir por IP si es indispensable."]},
    23: {"nivel": "alto", "nombre": "Telnet sin cifrar",
         "amenaza": "Protocolo obsoleto, sin ningún tipo de cifrado.",
         "recomendaciones": ["Deshabilitar Telnet y usar SSH.", "Cerrar el puerto 23."]},
    445: {"nivel": "alto", "nombre": "Compartición de archivos Windows (SMB)",
          "amenaza": "Vector de entrada de ataques de ransomware conocidos (ej. WannaCry).",
          "recomendaciones": ["Bloquear el puerto 445 desde internet.", "Permitir SMB solo en red interna o VPN.", "Mantener el sistema parchado."]},
    1433: {"nivel": "alto", "nombre": "Base de datos SQL Server expuesta",
           "amenaza": "Permite intentos directos de fuerza bruta y robo de datos del negocio.",
           "recomendaciones": ["Cerrar el puerto al público.", "Aceptar conexiones solo desde el servidor de la app.", "Deshabilitar cuentas por defecto."]},
    3306: {"nivel": "alto", "nombre": "Base de datos MySQL expuesta",
           "amenaza": "Acceso directo a los datos del negocio desde cualquier parte de internet.",
           "recomendaciones": ["bind-address = 127.0.0.1", "Bloquear el puerto 3306 en el firewall.", "Permitir solo la IP del servidor de la app."]},
    5432: {"nivel": "alto", "nombre": "Base de datos PostgreSQL expuesta",
           "amenaza": "Mismo riesgo que MySQL: acceso directo a los datos del negocio.",
           "recomendaciones": ["Restringir listen_addresses a localhost.", "Ajustar pg_hba.conf.", "Cerrar el puerto 5432 al público."]},
    3389: {"nivel": "alto", "nombre": "Escritorio remoto (RDP) expuesto",
           "amenaza": "Uno de los puertos más atacados por fuerza bruta automatizada.",
           "recomendaciones": ["No exponer RDP a internet; usar VPN.", "Activar doble factor.", "Bloquear IPs tras varios intentos fallidos."]},
    5900: {"nivel": "alto", "nombre": "Control remoto VNC expuesto",
           "amenaza": "Muchas instalaciones quedan sin contraseña, dando control total del equipo.",
           "recomendaciones": ["Cerrar el puerto y usar VPN.", "Forzar contraseña fuerte y cifrado."]},
    6379: {"nivel": "alto", "nombre": "Caché Redis expuesta",
           "amenaza": "Redis no trae autenticación por defecto: acceso libre a los datos.",
           "recomendaciones": ["Escuchar solo en localhost.", "Activar requirepass.", "Bloquear el puerto 6379."]},
    27017: {"nivel": "alto", "nombre": "Base de datos MongoDB expuesta",
            "amenaza": "Causa de varias filtraciones masivas por instancias sin autenticación.",
            "recomendaciones": ["Activar autenticación.", "Restringir bindIp a red interna.", "Cerrar el puerto 27017."]},
    22: {"nivel": "medio", "nombre": "Acceso remoto SSH",
         "amenaza": "Seguro si está bien configurado, pero recibe intentos constantes de fuerza bruta.",
         "recomendaciones": ["Usar solo llaves SSH, no contraseña.", "Bloquear login directo como root.", "Instalar fail2ban.", "Restringir por IP si es posible."]},
    25: {"nivel": "medio", "nombre": "Correo saliente (SMTP)",
         "amenaza": "Mal configurado, puede usarse para enviar spam a nombre de la empresa.",
         "recomendaciones": ["Verificar que no sea open relay.", "Configurar SPF, DKIM y DMARC."]},
    53: {"nivel": "medio", "nombre": "Servidor DNS",
         "amenaza": "Un DNS con recursión abierta puede usarse para amplificar ataques DDoS a terceros.",
         "recomendaciones": ["Deshabilitar la recursión abierta.", "Limitar consultas a clientes autorizados."]},
    110: {"nivel": "medio", "nombre": "Correo entrante POP3 sin cifrar",
          "amenaza": "Transmite credenciales de correo en texto plano.",
          "recomendaciones": ["Usar POP3S (995).", "Cerrar el puerto 110."]},
    143: {"nivel": "medio", "nombre": "Correo entrante IMAP sin cifrar",
          "amenaza": "Transmite credenciales de correo en texto plano.",
          "recomendaciones": ["Usar IMAPS (993).", "Cerrar el puerto 143."]},
    8080: {"nivel": "medio", "nombre": "Servicio web alternativo (8080)",
           "amenaza": "Suele ser un panel de administración o entorno de pruebas olvidado abierto.",
           "recomendaciones": ["Confirmar qué corre ahí.", "Cerrarlo o protegerlo con contraseña y VPN si es interno."]},
    80: {"nivel": "bajo", "nombre": "Página web (HTTP)",
         "amenaza": "Normal, pero sin cifrado si no redirige a HTTPS.",
         "recomendaciones": ["Redirigir todo el tráfico a HTTPS."]},
    443: {"nivel": "bajo", "nombre": "Página web segura (HTTPS)",
          "amenaza": "Configuración esperada y correcta.",
          "recomendaciones": ["Mantener el certificado SSL vigente."]},
    993: {"nivel": "bajo", "nombre": "Correo entrante seguro (IMAPS)", "amenaza": "Configuración correcta.",
          "recomendaciones": ["Mantener el certificado vigente."]},
    995: {"nivel": "bajo", "nombre": "Correo entrante seguro (POP3S)", "amenaza": "Configuración correcta.",
          "recomendaciones": ["Mantener el certificado vigente."]},
}

ETIQUETA_NIVEL = {"alto": "Riesgo alto", "medio": "Riesgo medio", "bajo": "Riesgo bajo"}
ETIQUETA_NIVEL_EN = {"alto": "High risk", "medio": "Medium risk", "bajo": "Low risk"}
EMOJI_NIVEL = {"alto": "🔴", "medio": "🟡", "bajo": "🟢"}


def _nivel_texto(nivel: str) -> str:
    return es_o_en(ETIQUETA_NIVEL.get(nivel, nivel), ETIQUETA_NIVEL_EN.get(nivel, nivel))

# Traducción del catálogo anterior. Se guarda aparte para no duplicar la
# lógica de clasificación y poder mostrar el detalle en el idioma activo.
CATALOGO_EN = {
    21: {"nombre": "Unencrypted file transfer (FTP)",
         "amenaza": "Sends username and password in plain text; they can be intercepted on the network.",
         "recomendaciones": ["Migrate to SFTP or FTPS.", "Close the port if it is not used.", "Restrict by IP if strictly necessary."]},
    23: {"nombre": "Unencrypted Telnet",
         "amenaza": "Obsolete protocol with no encryption at all.",
         "recomendaciones": ["Disable Telnet and use SSH.", "Close port 23."]},
    445: {"nombre": "Windows file sharing (SMB)",
          "amenaza": "Entry vector for known ransomware attacks (e.g. WannaCry).",
          "recomendaciones": ["Block port 445 from the internet.", "Allow SMB only on the internal network or VPN.", "Keep the system patched."]},
    1433: {"nombre": "Exposed SQL Server database",
           "amenaza": "Allows direct brute-force attempts and theft of business data.",
           "recomendaciones": ["Close the port to the public.", "Accept connections only from the app server.", "Disable default accounts."]},
    3306: {"nombre": "Exposed MySQL database",
           "amenaza": "Direct access to business data from anywhere on the internet.",
           "recomendaciones": ["bind-address = 127.0.0.1", "Block port 3306 in the firewall.", "Allow only the app server IP."]},
    5432: {"nombre": "Exposed PostgreSQL database",
           "amenaza": "Same risk as MySQL: direct access to business data.",
           "recomendaciones": ["Restrict listen_addresses to localhost.", "Adjust pg_hba.conf.", "Close port 5432 to the public."]},
    3389: {"nombre": "Exposed Remote Desktop (RDP)",
           "amenaza": "One of the most targeted ports for automated brute force.",
           "recomendaciones": ["Do not expose RDP to the internet; use a VPN.", "Enable two-factor authentication.", "Block IPs after several failed attempts."]},
    5900: {"nombre": "Exposed VNC remote control",
           "amenaza": "Many installations are left without a password, giving full control of the machine.",
           "recomendaciones": ["Close the port and use a VPN.", "Enforce a strong password and encryption."]},
    6379: {"nombre": "Exposed Redis cache",
           "amenaza": "Redis has no authentication by default: free access to the data.",
           "recomendaciones": ["Listen only on localhost.", "Enable requirepass.", "Block port 6379."]},
    27017: {"nombre": "Exposed MongoDB database",
            "amenaza": "Cause of several massive leaks from instances without authentication.",
            "recomendaciones": ["Enable authentication.", "Restrict bindIp to the internal network.", "Close port 27017."]},
    22: {"nombre": "Remote access SSH",
         "amenaza": "Safe if properly configured, but it receives constant brute-force attempts.",
         "recomendaciones": ["Use SSH keys only, not passwords.", "Block direct root login.", "Install fail2ban.", "Restrict by IP if possible."]},
    25: {"nombre": "Outgoing mail (SMTP)",
         "amenaza": "If misconfigured, it can be used to send spam in the company's name.",
         "recomendaciones": ["Verify that it is not an open relay.", "Configure SPF, DKIM and DMARC."]},
    53: {"nombre": "DNS server",
         "amenaza": "A DNS server with open recursion can be used to amplify DDoS attacks against third parties.",
         "recomendaciones": ["Disable open recursion.", "Limit queries to authorized clients."]},
    110: {"nombre": "Unencrypted incoming mail POP3",
          "amenaza": "Transmits email credentials in plain text.",
          "recomendaciones": ["Use POP3S (995).", "Close port 110."]},
    143: {"nombre": "Unencrypted incoming mail IMAP",
          "amenaza": "Transmits email credentials in plain text.",
          "recomendaciones": ["Use IMAPS (993).", "Close port 143."]},
    8080: {"nombre": "Alternative web service (8080)",
           "amenaza": "Often an administration panel or a forgotten test environment left open.",
           "recomendaciones": ["Confirm what runs there.", "Close it or protect it with a password and VPN if it is internal."]},
    80: {"nombre": "Web page (HTTP)",
         "amenaza": "Normal, but unencrypted if it does not redirect to HTTPS.",
         "recomendaciones": ["Redirect all traffic to HTTPS."]},
    443: {"nombre": "Secure web page (HTTPS)",
          "amenaza": "Expected and correct configuration.",
          "recomendaciones": ["Keep the SSL certificate valid."]},
    993: {"nombre": "Secure incoming mail (IMAPS)",
          "amenaza": "Correct configuration.",
          "recomendaciones": ["Keep the certificate valid."]},
    995: {"nombre": "Secure incoming mail (POP3S)",
          "amenaza": "Correct configuration.",
          "recomendaciones": ["Keep the certificate valid."]},
}


def _ficha_inglesa(puerto: int, servicio: str = "") -> dict:
    ficha = CATALOGO_EN.get(puerto)
    if ficha:
        return ficha
    return {
        "nombre": f"Unusual service on port {puerto}" + (f" ({servicio})" if servicio else ""),
        "amenaza": "This is not a common web port; it may be an internal service unnecessarily reachable from outside.",
        "recomendaciones": [
            "Confirm with the technical team what service runs there.",
            "Close it if it is not required for the site.",
            "Restrict it to authorized IPs if needed.",
        ],
    }


def localizar_amenazas(amenazas: list) -> list:
    """Devuelve las fichas de puertos en el idioma activo."""
    from models.i18n import idioma
    if idioma() != "en":
        return amenazas
    salida = []
    for amenaza in amenazas:
        ficha = _ficha_inglesa(
            int(amenaza.get("puerto", 0)), str(amenaza.get("servicio", "")),
        )
        salida.append({**amenaza, **ficha})
    return salida


def _clasificar_uno(p: dict) -> dict:
    puerto = p["puerto"]
    ficha = CATALOGO.get(puerto)
    if ficha is None:
        ficha = {
            "nivel": "medio",
            "nombre": f"Servicio no habitual en el puerto {puerto}" + (f" ({p['servicio']})" if p.get("servicio") and p["servicio"] != "desconocido" else ""),
            "amenaza": "No es un puerto común en un sitio web; puede ser un servicio interno accesible desde fuera sin necesidad.",
            "recomendaciones": ["Identificar con el equipo técnico qué servicio corre ahí.", "Cerrarlo si no es necesario para el funcionamiento del sitio.", "Restringirlo a IPs autorizadas si es necesario."],
        }
    return {"puerto": puerto, "servicio": p.get("servicio", "desconocido"), "protocolo": p.get("protocolo", "tcp"), **ficha}


def analizar_amenazas(puertos_abiertos: list) -> list:
    """Clasifica cada puerto abierto (salida de escanear_puertos_basicos) en nivel de riesgo."""
    orden = {"alto": 0, "medio": 1, "bajo": 2}
    amenazas = [_clasificar_uno(p) for p in puertos_abiertos]
    return sorted(amenazas, key=lambda a: orden[a["nivel"]])


def nivel_general(amenazas: list) -> str:
    if any(a["nivel"] == "alto" for a in amenazas):
        return "alto"
    if any(a["nivel"] == "medio" for a in amenazas):
        return "medio"
    return "bajo"


# Puntos que descuenta cada puerto abierto de la puntuación de seguridad (0-100).
PESO_NIVEL = {"alto": 30, "medio": 12, "bajo": 3}


def puntuacion_seguridad(amenazas: list) -> int:
    """Nivel de seguridad del host según los puertos expuestos: 0 (crítico) a 100 (sin riesgo detectado)."""
    score = 100
    for a in amenazas:
        score -= PESO_NIVEL.get(a["nivel"], PESO_NIVEL["medio"])
    return max(0, score)


def resumen_por_nivel(amenazas: list) -> dict:
    """Recuento de puertos por nivel de riesgo (solo niveles presentes)."""
    resumen = {}
    for a in amenazas:
        resumen[a["nivel"]] = resumen.get(a["nivel"], 0) + 1
    return resumen


# =============================================================================
# REPORTE EN MARKDOWN
# =============================================================================

def generar_reporte_markdown(resultado: dict, amenazas: list, ruta_md: str = None) -> str:
    from datetime import datetime
    amenazas = localizar_amenazas(amenazas or [])
    nivel = nivel_general(amenazas)
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")

    L = [f"# {es_o_en('Informe de diagnóstico de seguridad web', 'Web security assessment report')}", ""]
    L += [f"**{es_o_en('Sitio analizado', 'Analyzed site')}:** `{resultado['host']}`  ",
          f"**{es_o_en('Dirección IP', 'IP address')}:** `{resultado['ip']}`  ",
          f"**{es_o_en('Fecha', 'Date')}:** {fecha}  ",
          f"**{es_o_en('Puertos abiertos', 'Open ports')}:** {resultado['total_puertos']}  ",
          f"**{es_o_en('Puntuación de seguridad', 'Security score')}:** {puntuacion_seguridad(amenazas)}/100  ",
          f"**{es_o_en('Nivel de riesgo general', 'Overall risk level')}:** {EMOJI_NIVEL[nivel]} **{_nivel_texto(nivel)}**",
          "", "---", "", f"## {es_o_en('Resumen de puertos encontrados', 'Open port summary')}", ""]

    if not amenazas:
        L.append(es_o_en("_No se encontraron puertos abiertos en el rango analizado._",
                         "_No open ports were found in the scanned range._"))
    else:
        L.append(f"| # | {es_o_en('Puerto', 'Port')} | {es_o_en('Servicio', 'Service')} | "
                 f"{es_o_en('Nivel', 'Level')} | {es_o_en('Hallazgo', 'Finding')} |")
        L.append("|---|--------|----------|-------|----------|")
        for i, a in enumerate(amenazas, 1):
            L.append(f"| {i} | {a['puerto']}/{a['protocolo']} | {a['servicio']} | "
                      f"{EMOJI_NIVEL[a['nivel']]} {_nivel_texto(a['nivel'])} | {a['nombre']} |")
        L += ["", "---", "", f"## {es_o_en('Detalle por puerto', 'Detail by port')}", ""]
        for i, a in enumerate(amenazas, 1):
            L.append(f"### {i}. {es_o_en('Puerto', 'Port')} {a['puerto']}/{a['protocolo']} ({a['servicio']}) — {a['nombre']}")
            L.append("")
            L.append(f"**{es_o_en('Nivel', 'Level')}:** {EMOJI_NIVEL[a['nivel']]} {_nivel_texto(a['nivel'])}")
            L.append("")
            L.append(f"**{es_o_en('Amenaza', 'Threat')}:** {a['amenaza']}")
            L.append("")
            L.append(f"**{es_o_en('Recomendaciones', 'Recommendations')}:**")
            L.append("")
            L += [f"- {r}" for r in a["recomendaciones"]]
            L.append("")

    L += ["---", "", f"_{es_o_en('Informe generado automáticamente por el Analizador de Vulnerabilidades Web.', 'Report automatically generated by the Web Vulnerability Analyzer.')}_  ",
          f"_{es_o_en('Comparta este documento con el equipo responsable de la infraestructura.', 'Share this document with the infrastructure team.')}_"]

    contenido = "\n".join(L)
    if ruta_md:
        with open(ruta_md, "w", encoding="utf-8") as f:
            f.write(contenido)
    return contenido


# =============================================================================
# REPORTE EN PDF
# =============================================================================

def generar_reporte_pdf(resultado: dict, amenazas: list, ruta_pdf: str = None) -> bytes:
    """
    Genera el informe en PDF. Si se pasa ruta_pdf, además lo guarda en disco.
    Siempre retorna los bytes (útil para botones de descarga en Streamlit/Flask).
    """
    from datetime import datetime
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        ListFlowable, ListItem, HRFlowable,
    )

    amenazas = localizar_amenazas(amenazas or [])

    COLOR_NIVEL_HEXSTR = {"alto": "#C3352F", "medio": "#B8781F", "bajo": "#1E8E5A"}
    COLOR_NIVEL_HEX = {k: colors.HexColor(v) for k, v in COLOR_NIVEL_HEXSTR.items()}
    COLOR_FONDO_NIVEL = {"alto": colors.HexColor("#FBEAEA"), "medio": colors.HexColor("#FBF1E2"), "bajo": colors.HexColor("#E8F6EF")}
    INK, MUTED_PDF = colors.HexColor("#1A2430"), colors.HexColor("#5C7085")

    base = getSampleStyleSheet()
    est = {
        "titulo": ParagraphStyle("titulo", parent=base["Title"], fontSize=20, textColor=INK, spaceAfter=2, alignment=TA_LEFT),
        "meta": ParagraphStyle("meta", parent=base["Normal"], fontSize=10, textColor=MUTED_PDF, spaceAfter=18),
        "seccion": ParagraphStyle("seccion", parent=base["Heading2"], fontSize=13, textColor=INK, spaceBefore=18, spaceAfter=10),
        "hallazgo_titulo": ParagraphStyle("hallazgo_titulo", parent=base["Normal"], fontSize=11.5, textColor=INK, leading=15, fontName="Helvetica-Bold"),
        "etiqueta": ParagraphStyle("etiqueta", parent=base["Normal"], fontSize=8.5, spaceAfter=6, fontName="Helvetica-Bold"),
        "cuerpo": ParagraphStyle("cuerpo", parent=base["Normal"], fontSize=10, textColor=INK, leading=14, spaceAfter=4),
        "sol_label": ParagraphStyle("sol_label", parent=base["Normal"], fontSize=9, textColor=MUTED_PDF, fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2),
        "item": ParagraphStyle("item", parent=base["Normal"], fontSize=9.5, textColor=INK, leading=13),
        "footer": ParagraphStyle("footer", parent=base["Normal"], fontSize=8.5, textColor=MUTED_PDF, leading=12),
        "banner_titulo": ParagraphStyle("banner_titulo", parent=base["Normal"], fontSize=13, fontName="Helvetica-Bold"),
    }

    nivel = nivel_general(amenazas)
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, leftMargin=2.2 * cm, rightMargin=2.2 * cm,
                             topMargin=2 * cm, bottomMargin=2 * cm,
                             title=f"{es_o_en('Informe de seguridad', 'Security report')} — {resultado['host']}")
    elementos = [
        Paragraph(es_o_en("Informe de diagnóstico de seguridad web", "Web security assessment report"), est["titulo"]),
        Paragraph(f"{resultado['host']} &nbsp;·&nbsp; IP {resultado['ip']} &nbsp;·&nbsp; {fecha} "
                   f"&nbsp;·&nbsp; {resultado['total_puertos']} {es_o_en('puertos abiertos', 'open ports')} "
                   f"&nbsp;·&nbsp; {es_o_en('Puntuación', 'Score')} {puntuacion_seguridad(amenazas)}/100", est["meta"]),
    ]

    banner = Table([[Paragraph(f"{es_o_en('Nivel de riesgo general', 'Overall risk level')}: {_nivel_texto(nivel)}", est["banner_titulo"])]], colWidths=[doc.width])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_FONDO_NIVEL[nivel]),
        ("TEXTCOLOR", (0, 0), (-1, -1), COLOR_NIVEL_HEX[nivel]),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEBEFORE", (0, 0), (0, -1), 3, COLOR_NIVEL_HEX[nivel]),
    ]))
    elementos += [banner, Spacer(1, 18), Paragraph(es_o_en("Hallazgos y recomendaciones", "Findings and recommendations"), est["seccion"])]

    if not amenazas:
        elementos.append(Paragraph(es_o_en("No se encontraron puertos abiertos en el rango analizado.",
                                           "No open ports were found in the scanned range."), est["cuerpo"]))
    else:
        for i, a in enumerate(amenazas, 1):
            fila_titulo = Table([[Paragraph(f"{i}. {es_o_en('Puerto', 'Port')} {a['puerto']}/{a['protocolo']} ({a['servicio']}) — {a['nombre']}", est["hallazgo_titulo"])]], colWidths=[doc.width])
            fila_titulo.setStyle(TableStyle([
                ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, COLOR_NIVEL_HEX[a["nivel"]]),
            ]))
            elementos.append(fila_titulo)

            etiqueta = Paragraph(f'<font color="{COLOR_NIVEL_HEXSTR[a["nivel"]]}">{_nivel_texto(a["nivel"]).upper()}</font>', est["etiqueta"])
            cuerpo = Table([[etiqueta], [Paragraph(f"<b>{es_o_en('Amenaza', 'Threat')}:</b> {a['amenaza']}", est["cuerpo"])],
                             [Paragraph(f"{es_o_en('Recomendaciones', 'Recommendations')}:", est["sol_label"])]], colWidths=[doc.width])
            cuerpo.setStyle(TableStyle([
                ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, COLOR_NIVEL_HEX[a["nivel"]]),
            ]))
            elementos.append(cuerpo)

            items = ListFlowable([ListItem(Paragraph(r, est["item"]), leftIndent=6) for r in a["recomendaciones"]],
                                  bulletType="bullet", start="•", leftIndent=18, bulletFontSize=8)
            items_tabla = Table([[items]], colWidths=[doc.width])
            items_tabla.setStyle(TableStyle([
                ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, COLOR_NIVEL_HEX[a["nivel"]]),
            ]))
            elementos += [items_tabla, Spacer(1, 8)]

    elementos += [Spacer(1, 10), HRFlowable(width="100%", color=colors.HexColor("#DDE5EC"), thickness=1), Spacer(1, 8),
                  Paragraph(es_o_en(
                      "Informe generado automáticamente por el Analizador de Vulnerabilidades Web. "
                      "Comparta este documento con el equipo responsable de la infraestructura.",
                      "Report automatically generated by the Web Vulnerability Analyzer. "
                      "Share this document with the infrastructure team.",
                  ), est["footer"])]

    doc.build(elementos)
    datos_pdf = buffer.getvalue()
    buffer.close()
    if ruta_pdf:
        with open(ruta_pdf, "wb") as f:
            f.write(datos_pdf)
    return datos_pdf

import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from models.http_utils import es_objetivo_privado


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
EMOJI_NIVEL = {"alto": "🔴", "medio": "🟡", "bajo": "🟢"}


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
    nivel = nivel_general(amenazas)
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")

    L = [f"# Informe de diagnóstico de seguridad web", ""]
    L += [f"**Sitio analizado:** `{resultado['host']}`  ",
          f"**Dirección IP:** `{resultado['ip']}`  ",
          f"**Fecha:** {fecha}  ",
          f"**Puertos abiertos:** {resultado['total_puertos']}  ",
          f"**Puntuación de seguridad:** {puntuacion_seguridad(amenazas)}/100  ",
          f"**Nivel de riesgo general:** {EMOJI_NIVEL[nivel]} **{ETIQUETA_NIVEL[nivel]}**",
          "", "---", "", "## Resumen de puertos encontrados", ""]

    if not amenazas:
        L.append("_No se encontraron puertos abiertos en el rango analizado._")
    else:
        L.append("| # | Puerto | Servicio | Nivel | Hallazgo |")
        L.append("|---|--------|----------|-------|----------|")
        for i, a in enumerate(amenazas, 1):
            L.append(f"| {i} | {a['puerto']}/{a['protocolo']} | {a['servicio']} | "
                      f"{EMOJI_NIVEL[a['nivel']]} {ETIQUETA_NIVEL[a['nivel']]} | {a['nombre']} |")
        L += ["", "---", "", "## Detalle por puerto", ""]
        for i, a in enumerate(amenazas, 1):
            L.append(f"### {i}. Puerto {a['puerto']}/{a['protocolo']} ({a['servicio']}) — {a['nombre']}")
            L.append("")
            L.append(f"**Nivel:** {EMOJI_NIVEL[a['nivel']]} {ETIQUETA_NIVEL[a['nivel']]}")
            L.append("")
            L.append(f"**Amenaza:** {a['amenaza']}")
            L.append("")
            L.append("**Recomendaciones:**")
            L.append("")
            L += [f"- {r}" for r in a["recomendaciones"]]
            L.append("")

    L += ["---", "", "_Informe generado automáticamente por el Analizador de Vulnerabilidades Web._  ",
          "_Comparta este documento con el equipo responsable de la infraestructura._"]

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
                             topMargin=2 * cm, bottomMargin=2 * cm, title=f"Informe de seguridad — {resultado['host']}")
    elementos = [
        Paragraph("Informe de diagnóstico de seguridad web", est["titulo"]),
        Paragraph(f"{resultado['host']} &nbsp;·&nbsp; IP {resultado['ip']} &nbsp;·&nbsp; {fecha} "
                   f"&nbsp;·&nbsp; {resultado['total_puertos']} puertos abiertos "
                   f"&nbsp;·&nbsp; Puntuación {puntuacion_seguridad(amenazas)}/100", est["meta"]),
    ]

    banner = Table([[Paragraph(f"Nivel de riesgo general: {ETIQUETA_NIVEL[nivel]}", est["banner_titulo"])]], colWidths=[doc.width])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_FONDO_NIVEL[nivel]),
        ("TEXTCOLOR", (0, 0), (-1, -1), COLOR_NIVEL_HEX[nivel]),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEBEFORE", (0, 0), (0, -1), 3, COLOR_NIVEL_HEX[nivel]),
    ]))
    elementos += [banner, Spacer(1, 18), Paragraph("Hallazgos y recomendaciones", est["seccion"])]

    if not amenazas:
        elementos.append(Paragraph("No se encontraron puertos abiertos en el rango analizado.", est["cuerpo"]))
    else:
        for i, a in enumerate(amenazas, 1):
            fila_titulo = Table([[Paragraph(f"{i}. Puerto {a['puerto']}/{a['protocolo']} ({a['servicio']}) — {a['nombre']}", est["hallazgo_titulo"])]], colWidths=[doc.width])
            fila_titulo.setStyle(TableStyle([
                ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, COLOR_NIVEL_HEX[a["nivel"]]),
            ]))
            elementos.append(fila_titulo)

            etiqueta = Paragraph(f'<font color="{COLOR_NIVEL_HEXSTR[a["nivel"]]}">{ETIQUETA_NIVEL[a["nivel"]].upper()}</font>', est["etiqueta"])
            cuerpo = Table([[etiqueta], [Paragraph(f"<b>Amenaza:</b> {a['amenaza']}", est["cuerpo"])],
                             [Paragraph("Recomendaciones:", est["sol_label"])]], colWidths=[doc.width])
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
                  Paragraph("Informe generado automáticamente por el Analizador de Vulnerabilidades Web. "
                            "Comparta este documento con el equipo responsable de la infraestructura.", est["footer"])]

    doc.build(elementos)
    datos_pdf = buffer.getvalue()
    buffer.close()
    if ruta_pdf:
        with open(ruta_pdf, "wb") as f:
            f.write(datos_pdf)
    return datos_pdf

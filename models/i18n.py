"""Traducción ES/EN de la interfaz.

El idioma activo se guarda en `st.session_state["idioma"]` ("es" | "en").
`t(texto, *args)` busca el texto español en _TRADUCCIONES y, si encuentra y el
idioma es "en", devuelve la versión inglés; si no, devuelve el texto original
(español) para que nada se rompa. Los `{}` del texto se formatean con *args.
"""

import re

import streamlit as st

# Prefijos decorativos (emoji/símbolos) que se ignoran al buscar traducción:
# "🚪 Cerrar Sesión" -> "Cerrar Sesión" (que sí está en el diccionario).
_PREFIJO_DECORATIVO = re.compile(r"^[\W_]+", re.UNICODE)

TRADUCCIONES = {
    # ------------------------------------------------------------- login
    "Configura tu base de datos en el archivo **.env** "
    "(`SUPABASE_URL` y `SUPABASE_KEY`) para poder iniciar sesión.":
    "Set up your database in the **.env** file "
    "(`SUPABASE_URL` and `SUPABASE_KEY`) to sign in.",
    "Base de datos no configurada": "Database not configured",
    "Usuario y contraseña son obligatorios.": "Username and password are required.",
    "El usuario debe tener al menos {} caracteres.": "Username must be at least {} characters long.",
    "La contraseña debe tener al menos {} caracteres.": "Password must be at least {} characters long.",
    "Las contraseñas no coinciden.": "Passwords do not match.",
    "El usuario ya existe.": "The username already exists.",
    "Registro exitoso. Ahora inicia sesión.": "Registration successful. Now sign in.",
    "Usuario o contraseña incorrectos.": "Incorrect username or password.",
    "Bienvenido, {}.": "Welcome, {}.",
    "Analizador de Vulnerabilidades Web": "Web Vulnerability Analyzer",
    "Pentesting ético · CVSS · PGI · OWASP": "Ethical pentesting · CVSS · PGI · OWASP",
    "Accede para auditar tus propios sistemas": "Sign in to audit your own systems",
    "Iniciar Sesión": "Sign In",
    "Crear Cuenta": "Create Account",
    "Nombre de usuario": "Username",
    "Crear contraseña": "Create password",
    "mínimo {} caracteres": "minimum {} characters",
    "repetir contraseña": "repeat password",
    "Usuario": "Username",
    "Contraseña": "Password",
    "👤 Usuario": "👤 Username",
    "🔑 Contraseña": "🔑 Password",
    "👤 Nombre de usuario": "👤 Username",
    "🔑 Crear contraseña": "🔑 Create password",
    "🔑 Repetir contraseña": "🔑 Repeat password",
    "Entrar": "Sign In",
    "Crear cuenta": "Create account",
    "Herramienta de pentesting ético. Uso responsable.":
    "Ethical pentesting tool. Use responsibly.",
    "Todos los campos son obligatorios.": "All fields are required.",

    # ---------------------------------------------------------- sidebar/app
    "Tema": "Theme",
    "🖥️ Sistema": "🖥️ System",
    "☀️ Claro": "☀️ Light",
    "🌙 Oscuro": "🌙 Dark",
    "VulnWeb": "VulnWeb",
    "Ethical Pentest Suite": "Ethical Pentest Suite",
    "Supabase conectado": "Supabase connected",
    "Supabase sin configurar": "Supabase not configured",
    "Cerrar Sesión": "Sign Out",
    "Condiciones de uso": "Terms of Use",
    "Autorizado": "Authorized",
    "Sin autorización": "Not authorized",
    "sin objetivo": "no target",
    "URL objetivo": "Target URL",
    "ejemplo.com:8080 o https://dominio/ruta": "example.com:8080 or https://domain/path",
    "Módulos de análisis": "Analysis Modules",
    "Inyección SQL": "SQL Injection",
    "Carga": "Load",
    "Auditoría": "Audit",
    "Puertos": "Ports",
    "Ejecutar análisis": "Run Analysis",
    "Permitir red interna (localhost / privadas)": "Allow internal network (localhost / private)",
    "Necesario para laboratorios locales (DVWA, Juice Shop). "
    "Déjalo desactivado para uso normal.": "Required for local labs (DVWA, Juice Shop). "
    "Leave it off for normal use.",
    "Ciclo de actualización": "Update loop",
    "historial": "history",
    "Historial reciente ({}):": "Recent history ({}):",
    "Operación completada": "Operation completed",
    "Confirmar autorización": "Confirm authorization",
    "Solo usa esta herramienta contra sistemas que **poseas** o contra los "
    "cuales tengas **autorización escrita explícita**.": "Only use this tool against systems you **own** "
    "or for which you have **explicit written authorization**.",
    "Escanear sistemas de terceros sin permiso puede ser **ilegal**.":
    "Scanning third-party systems without permission may be **illegal**.",
    "La prueba de carga tiene un techo máximo de concurrencia (50) para evitar "
    "convertirte en una herramienta de denegación de servicio (DoS).":
    "Load testing has a maximum concurrency cap (50) to prevent turning into a "
    "denial-of-service (DoS) tool.",
    "Sin datos para mostrar.": "No data to show.",
    "🔒 Confirma tu autorización en la barra lateral para comenzar el análisis.":
    "🔒 Confirm your authorization in the sidebar to start the analysis.",
    "Ingresa una URL en la barra lateral para comenzar.":
    "Enter a URL in the sidebar to get started.",
    "URL": "URL",
    "Método": "Method",
    "Origen": "Source",
    "Endpoint": "Endpoint",
    "Parámetro": "Parameter",
    "Accion correcta": "Correct action",
    "Accion": "Action",
    "Estado": "Status",

    # ------------------------------------------------------------ SQLi view
    "Escáner de Inyección SQL": "SQL Injection Scanner",
    "Hallazgos, puntuación CVSS y cobertura de vectores de ataque":
    "Findings, CVSS score and attack vector coverage",
    "Puntos analizados": "Points analyzed",
    "Total hallazgos": "Total findings",
    "CVSS promedio": "Average CVSS",
    "Riesgo global": "Overall risk",
    "Confianza media": "Average confidence",
    "Cobertura vectores": "Vector coverage",
    "Parámetros afectados": "Affected parameters",
    "Diagnóstico (por qué se descartó u omitió algo)":
    "Diagnostics (why something was skipped or omitted)",
    "¡Vulnerabilidad de inyección SQL detectada!": "SQL injection vulnerability detected!",
    "No se detectaron vulnerabilidades claras.": "No clear vulnerabilities detected.",
    "No se encontraron parámetros ni formularios que analizar en la página.":
    "No parameters or forms to analyze were found on the page.",
    "Puntos de inyección analizados ({}):": "Injection points analyzed ({}):",
    "Matriz de riesgo": "Risk matrix",
    "Relación entre probabilidad e impacto de cada hallazgo":
    "Relationship between likelihood and impact of each finding",
    "Recomendaciones de remediación": "Remediation recommendations",
    "Priorizadas según la severidad CVSS": "Prioritized by CVSS severity",
    "No hay hallazgos que detallar en este análisis.":
    "No findings to detail in this analysis.",
    "Vulnerabilidades detectadas": "Detected vulnerabilities",
    "Detalle técnico, evidencia y vector CVSS": "Technical detail, evidence and CVSS vector",
    "Tipo": "Type",
    "Severidad": "Severity",
    "CVSS": "CVSS",
    "Confianza": "Confidence",
    "Vector CVSS": "CVSS vector",
    "Motor sugerido": "Suggested engine",
    "Explicación del hallazgo": "Finding explanation",
    "No disponible": "Not available",
    "Payload utilizado": "Payload used",
    "Evidencia": "Evidence",
    "Código HTTP base": "HTTP base code",
    "Datos extraídos": "Extracted data",
    "Reproducir (curl):": "Reproduce (curl):",
    "Hallazgo #{}": "Finding #{}",
    "No hay hallazgos": "No findings",
    "Explicación": "Explanation",
    "Motor": "Engine",
    "Hallazgo menor en '{}' (CVSS {}/10). "\
    "Documentar y revisar en revisión de seguridad periódica.":
    "Minor finding in '{}' (CVSS {}/10). ",
    "Indicio de inyección SQL en '{}' (CVSS {}/10). ":
    "Possible SQL injection in '{}' (CVSS {}/10). ",
    "Inyección SQL {} en '{}' (CVSS {}/10). ": "SQL injection {} in '{}' (CVSS {}/10). ",
    "El parámetro '{}' presenta inyección SQL {} ":
    "The parameter '{}' presents an SQL injection {} ",

    # ----------------------------------------------------------- Audit view
    "Auditoría Unificada": "Unified Audit",
    "Rastreo del sitio, análisis profundo del servicio y detección de phishing":
    "Site crawling, deep service analysis and phishing detection",
    "Auditoría de seguridad": "Security audit",
    "hallazgo(s)": "finding(s)",
    "críticos": "critical",
    "altos": "high",
    "Security score": "Security score",
    "Exposición": "Exposure",
    "Críticos": "Critical",
    "Altos": "High",
    "Medios": "Medium",
    "Totales": "Total",
    "Hallazgos por severidad": "Findings by severity",
    "Agrupados y con remediación OWASP sugerida":
    "Grouped with suggested OWASP remediation",
    "Remediación:": "Remediation:",
    "Análisis profundo": "Deep analysis",
    "Score:": "Score:",
    "Páginas rastreadas:": "Pages crawled:",
    "Hallazgos:": "Findings:",
    "Detección de phishing (ML)": "Phishing detection (ML)",
    "Resultado:": "Result:",
    "Score de riesgo:": "Risk score:",
    "Confianza del modelo:": "Model confidence:",
    "Tecnologías detectadas:": "Detected technologies:",
    "Páginas rastreadas ({})": "Pages crawled ({})",
    "Título": "Title",
    "Distribución de severidad": "Severity distribution",
    "Reparto de hallazgos por criticidad": "Breakdown of findings by criticality",
    "Distribución de hallazgos": "Findings distribution",
    "Puertos expuestos": "Exposed ports",
    "Resultado del escaneo TCP (1-1024)": "TCP scan result (1-1024)",
    "Puertos abiertos:": "Open ports:",
    "No se encontraron puertos abiertos en el rango escaneado.":
    "No open ports found in the scanned range.",
    "Iniciando auditoría profunda...": "Starting deep audit...",
    "Detectando phishing...": "Detecting phishing...",
    "Auditoría completada": "Audit completed",
    "Rastreando el sitio...": "Crawling the site...",
    "Comprobaciones profundas del servicio...": "Deep service checks...",
    "Consolidando hallazgos...": "Consolidating findings...",
    "Analizando {}": "Analyzing {}",
    "Rutas:": "Paths:",
    "Permite:": "Allows:",
    "Accesible en {} (HTTP {}).": "Accessible at {} (HTTP {}).",

    # ----------------------------------------------------------- Load view
    "Prueba de Capacidad": "Capacity Test",
    "Latencia, throughput y grado de salud del sistema (PGI)":
    "Latency, throughput and system health score (PGI)",
    "Capacidad estimada": "Estimated capacity",
    "simultáneas": "concurrent",
    "Latencia base": "Baseline latency",
    "Grado salud (PGI)": "Health score (PGI)",
    "Salud global": "Overall health",
    "Tasa error máx": "Max error rate",
    "Volatilidad máx": "Max volatility",
    "Resumen de niveles": "Levels summary",
    "Métricas por nivel de concurrencia": "Metrics per concurrency level",
    "No hay datos de niveles para mostrar.": "No level data to show.",
    "Recomendaciones de rendimiento": "Performance recommendations",
    "Acciones sugeridas según el estado del sistema":
    "Suggested actions based on system health",
    "Ejecutando prueba de carga...": "Running load test...",
    "Concurrencia (peticiones simultáneas)": "Concurrency (simultaneous requests)",
    "Latencia (s)": "Latency (s)",
    "Peticiones / segundo": "Requests / second",
    "Distribución de errores": "Error distribution",
    "Grado de salud (PGI)": "Health score (PGI)",
    "Tasa de error por nivel de concurrencia": "Error rate per concurrency level",
    "Tasa de error %": "Error rate %",
    "Errores (nº)": "Errors (count)",
    "Riesgo global (CVSS)": "Overall risk (CVSS)",
    "Matriz de riesgo (Likelihood vs Impact)": "Risk matrix (Likelihood vs Impact)",
    "Confianza por parámetro": "Confidence by parameter",
    "Cobertura de vectores de ataque": "Attack vector coverage",
    "Distribución de severidad": "Severity distribution",
    "Latencia por percentil vs concurrencia": "Latency by percentile vs concurrency",
    "Throughput (peticiones/segundo) por nivel": "Throughput (requests/second) per level",
    "Rendimiento óptimo. Mantener monitoreo continuo y planificar escalado proactivo.":
    "Optimal performance. Keep continuous monitoring and plan proactive scaling.",
    "Rendimiento aceptable. Considerar optimización de queries y añadir caching.":
    "Acceptable performance. Consider query optimization and adding caching.",
    "Degradación detectada. Implementar rate limiting, balanceo de carga y optimización de DB.":
    "Degradation detected. Implement rate limiting, load balancing and DB optimization.",
    "Rendimiento crítico. Escalar infraestructura inmediatamente, revisar queries lentas y caché.":
    "Critical performance. Scale infrastructure immediately, review slow queries and cache.",
    "⏱️ {} timeouts detectados. Revisar timeouts del servidor y slow queries.":
    "⏱️ {} timeouts detected. Review server timeouts and slow queries.",
    "🔴 {} errores 5xx. Investigar errores del servidor.":
    "🔴 {} 5xx errors. Investigate server errors.",
    "🔌 {} errores de conexión. Verificar límites del servidor.":
    "🔌 {} connection errors. Verify server limits.",

    # ---------------------------------------------------------- SQLi opciones
    "Opciones de inyección SQL": "SQL injection options",
    "Cabeceras extra (una por línea: `Nombre: valor`)":
    "Extra headers (one per line: `Name: value`)",
    "Necesario para objetivos que requieren sesión o autenticación.":
    "Required for targets that need a session or authentication.",
    "Pausa entre peticiones (s)": "Pause between requests (s)",
    "Modo cortés: retardo entre peticiones para no saturar el objetivo.":
    "Polite mode: delay between requests to avoid overwhelming the target.",
    "Máximo de puntos a analizar": "Maximum points to analyze",
    "Menos puntos = análisis más rápido.": "Fewer points = faster analysis.",
    "Tiempo máximo (s)": "Maximum time (s)",
    "Detiene el análisis al alcanzarlo. 0 = sin límite.":
    "Stops the analysis when reached. 0 = no limit.",
    "Máximo de peticiones": "Maximum requests",
    "Límite de seguridad; al alcanzarlo se detiene el análisis.":
    "Safety limit; the analysis stops when reached.",
    "Probar cabeceras (User-Agent, Referer, X-Forwarded-For)":
    "Test headers (User-Agent, Referer, X-Forwarded-For)",
    "Algunas apps registran o usan estas cabeceras en consultas SQL.":
    "Some apps log or use these headers in SQL queries.",
    "Probar cuerpo JSON (APIs / SPA)": "Test JSON body (APIs / SPA)",
    "Envía los campos del formulario también como JSON.":
    "Sends form fields also as JSON.",
    "Extraer datos (versión, BD, usuario, tablas) al detectar UNION":
    "Extract data (version, DB, user, tables) when UNION is detected",
    "Prueba de extracción acotada para evidenciar impacto.":
    "Bounded extraction test to demonstrate impact.",
    "Descubrir endpoints de API (JS / SPA)": "Discover API endpoints (JS / SPA)",
    "Analiza el JavaScript en busca de rutas /api, /rest, etc.":
    "Analyzes JavaScript looking for routes like /api, /rest, etc.",
    "Usar navegador headless (SPA con JS)": "Use headless browser (SPA with JS)",
    "Requiere Playwright instalado (`playwright install chromium`).":
    "Requires Playwright installed (`playwright install chromium`).",
    "Probar SQLi de segundo orden (intrusivo: escribe datos)":
    "Test second-order SQLi (intrusive: writes data)",
    "Inyecta en formularios y luego revisa otras páginas buscando errores SQL. "
    "Heurístico y MODIFICA datos del objetivo; úsalo solo con autorización.":
    "Injects into forms and then checks other pages for SQL errors. "
    "Heuristic and MODIFIES target data; use only with authorization.",
    "Confirmación estricta (menos falsos positivos)":
    "Strict confirmation (fewer false positives)",
    "Desactívalo si el objetivo es inestable y crees que se están perdiendo hallazgos.":
    "Disable it if the target is unstable and you think findings are being missed.",
    "Detener ante WAF / rate-limit": "Stop on WAF / rate-limit",
    "Si se desactiva, sigue probando aunque el objetivo devuelva bloqueos.":
    "If disabled, keeps testing even if the target returns blocks.",

    # --------------------------------------------------------- Auditoría opts
    "Opciones de auditoría profunda": "Deep audit options",
    "Profundidad de rastreo": "Crawl depth",
    "0 = solo la página indicada. 2 = sigue enlaces hasta 2 niveles.":
    "0 = only the given page. 2 = follows links up to 2 levels.",
    "Máximo de páginas": "Maximum pages",
    "Límite de páginas a analizar en profundidad.":
    "Limit of pages to analyze in depth.",

    # ------------------------------------------------------------- Estado
    "Analizando vulnerabilidades...": "Analyzing vulnerabilities...",
    "Por favor, ingresa una URL.": "Please enter a URL.",
    "Por favor, ingresa una URL o dominio.": "Please enter a URL or domain.",
    "Resolviendo host...": "Resolving host...",
    "Escaneando puertos...": "Scanning ports...",
    "Escaneo completado": "Scan completed",
    "Error durante el escaneo: {}": "Error during scan: {}",
    "No se encontraron puertos abiertos.": "No open ports found.",
    "Puerto": "Port",
    "Servicio": "Service",
    "Version": "Version",  # comillas simplificadas
    "Banner": "Banner",
    "vulnerabilidad": "vulnerability",
    "Abrir": "Open",
    "Cerrado": "Closed",
    "abiertos": "open",
    "cerrados": "closed",
    "Filtrado": "Filtered",
    "EXCELENTE": "EXCELLENT",
    "BUENA": "GOOD",
    "ATENCIÓN": "ATTENTION",
    "RIESGO": "RISK",
    "CRÍTICA": "CRITICAL",
    "BAJO": "LOW",
    "MODERADO": "MODERATE",
    "ELEVADO": "ELEVATED",
    "ALTO": "HIGH",
    "MEDIO": "MEDIUM",
    "CRÍTICO": "CRITICAL",
    "Media": "Medium",
    "Baja": "Low",
    "Info": "Info",
    "Crítica": "Critical",
    "Alta": "High",
    "Filtrado": "Filtered",
    "Excelente": "Excellent",
    "Buena": "Good",
    "Degradada": "Degraded",
    "Sin datos": "No data",
    "Sin hallazgos": "No findings",
    "ERROR": "ERROR",
    "SOSPECHOSA": "SUSPICIOUS",
    "LEGITIMA": "LEGITIMATE",
    "PHISHING": "PHISHING",
    "sin respuesta": "no response",
    "sin estado": "no status",
    "procesado": "processed",
    "cancelado": "cancelled",
    "Hallazgo": "Finding",
    "Motivo": "Reason",
    "Aplicar": "Apply",
    "acciones": "actions",
    "correcto": "applied",
    "Omitir": "Skip",

    # --------------------------------------------------------- Remediación
    "Activar Strict Transport Security (HSTS).": "Enable Strict Transport Security (HSTS).",
    "Configuracion del servidor web / reverse proxy / CDN.":
    "Web server / reverse proxy / CDN configuration.",
    "Definir una Content Security Policy.": "Define a Content Security Policy.",
    "Impedir clickjacking (X-Frame-Options).": "Prevent clickjacking (X-Frame-Options).",
    "Prevenir MIME sniffing (X-Content-Type-Options).":
    "Prevent MIME sniffing (X-Content-Type-Options).",
    "Forzar HTTPS y redirigir trafico HTTP.": "Force HTTPS and redirect HTTP traffic.",
    "Servidor web / balanceador / CDN.": "Web server / load balancer / CDN.",
    "Habilitar TLS 1.2/1.3, deshabilitar obsoletos.":
    "Enable TLS 1.2/1.3, disable outdated protocols.",
    "Configuracion TLS del servidor.": "Server TLS configuration.",
    "usar sslscan o testssl.sh": "use sslscan or testssl.sh",
    "Configurar cookies con flags Secure, HttpOnly, SameSite.":
    "Configure cookies with Secure, HttpOnly, SameSite flags.",
    "Sesion/cookies del framework o WAF.": "Framework or WAF session/cookies.",
    "Usar consultas parametrizadas (prepared statements).":
    "Use parameterized queries (prepared statements).",
    "Codigo fuente de la aplicacion.": "Application source code.",
    "Re-ejecutar escaneo SQLi para confirmar mitigacion.":
    "Re-run the SQLi scan to confirm mitigation.",
    "Escape de salida + CSP estricta.": "Output escaping + strict CSP.",
    "Templates / frontend.": "Templates / frontend.",
    "Probar con payload: <script>alert(1)</script>":
    "Test with payload: <script>alert(1)</script>",
    "Implementar rate limiting y WAF.": "Implement rate limiting and a WAF.",
    "Servidor / CDN / WAF.": "Server / CDN / WAF.",
    "Enviar 50 peticiones/sec y verificar bloqueo": "Send 50 requests/sec and verify blocking",
    "Revisar la configuracion del control indicado.":
    "Review the configuration of the indicated control.",
    "Segun el control afectado.": "Depending on the affected control.",
    "Consultar documentacion del servidor/aplicacion.":
    "Check server/application documentation.",
    "Re-ejecutar auditoria o verificar manualmente.":
    "Re-run the audit or verify manually.",
    "Modelo ML no disponible": "ML model not available",
    "No se pudo interpretar la URL: {}": "Could not interpret the URL: {}",
    "No se pudo resolver {}: {}": "Could not resolve {}: {}",
    "Rango de puertos inválido: {}": "Invalid port range: {}",
    "desconocido": "unknown",
    "El objetivo apunta a una dirección interna o privada (posible SSRF). "
    "Activa 'Permitir red interna' en la barra lateral si es un objetivo de laboratorio.":
    "The target points to an internal or private address (possible SSRF). "
    "Enable 'Allow internal network' in the sidebar if it is a lab target.",

    # ------------------------------------------------- SQLi model / mensajes
    "Tiempo máximo alcanzado ({}s): análisis detenido.":
    "Maximum time reached ({}s): analysis stopped.",
    "Presupuesto de peticiones agotado ({}): análisis detenido.":
    "Request budget exhausted ({}): analysis stopped.",
    "WAF/rate-limit detectado (HTTP {}).": "WAF/rate-limit detected (HTTP {}).",
    "formulario(s)": "form(s)",
    "enlace(s) con parámetros": "link(s) with parameters",
    "parámetros de la URL": "URL parameters",
    "puntos detectados": "detected points",
    "Se analizaron {} punto(s) de inyección ({}) y se detectaron {} hallazgo(s).":
    "{} injection point(s) were analyzed ({}) and {} finding(s) were detected.",
    "No se detectaron signos claros de inyección SQL en {} punto(s) de inyección ({}).":
    "No clear SQL injection signs detected in {} injection point(s) ({}).",
    " Se limitó el análisis a {} parámetros.": " The analysis was limited to {} parameters.",
    " Se alcanzó el límite de {} peticiones (sube el máximo para continuar).":
    " The limit of {} requests was reached (raise the maximum to continue).",
    " Se alcanzó el tiempo máximo de {}s.": " The maximum time of {}s was reached.",
    " El objetivo bloqueó o limitó las peticiones (WAF/rate-limit): se detuvo el análisis.":
    " The target blocked or limited requests (WAF/rate-limit): analysis stopped.",
    "No se encontraron parámetros ni formularios que analizar.":
    "No parameters or forms to analyze were found.",
    "No hay formularios/endpoints de escritura donde inyectar.":
    "No write forms/endpoints to inject into.",
    "Tras inyectar en {}, la página {} devolvió un error SQL nuevo: {}.":
    "After injecting into {}, the page {} returned a new SQL error: {}.",
    "Posible SQLi de segundo orden: una inyección almacenada provoca un error SQL en otra página.":
    "Possible second-order SQLi: a stored injection causes an SQL error on another page.",
    "No se detectó SQLi de segundo orden (heurístico).":
    "No second-order SQLi detected (heuristic).",
    "error-based: el error SQL no se reprodujo al confirmar (posible falso negativo).":
    "error-based: the SQL error did not reproduce on confirmation (possible false negative).",
    "boolean: la página base devuelve 5xx (técnica omitida).":
    "boolean: baseline page returns 5xx (technique skipped).",
    "boolean: respuesta base muy pequeña (técnica omitida).":
    "boolean: baseline response too small (technique skipped).",
    "boolean: página demasiado volátil (ruido {}; técnica omitida). "
    "Si sospechas inyección, baja la exigencia de ruido o revisa manualmente.":
    "boolean: page too volatile (noise {}; technique skipped). "
    "If you suspect injection, lower the noise threshold or check manually.",
    "boolean: no se pudo confirmar (respuestas con error o nulas).":
    "boolean: could not confirm (error or null responses).",
    "boolean: respuestas inestables para el mismo payload (no confirmado).":
    "boolean: unstable responses for the same payload (not confirmed).",
    "UNION: candidato no confirmado (descartado).":
    "UNION: candidate not confirmed (discarded).",
    "time-based: el retardo no se reprodujo al confirmar (descartado).":
    "time-based: the delay did not reproduce on confirmation (discarded).",
    "Firmas SQL en {}: {}": "SQL signatures in {}: {}",
    "UNION SELECT con {} columnas altera la respuesta (similitud {}).":
    "UNION SELECT with {} columns alters the response (similarity {}).",
    "El contenido no es HTML; solo se analizan los parámetros de la URL.":
    "The content is not HTML; only URL parameters are analyzed.",
    "No se pudo leer la página: {}": "Could not read the page: {}",

    # ------------------------------------------------------- Load model
    "Error en la medición inicial": "Error in initial measurement",
    "No se pudo conectar a la URL: {}": "Could not connect to the URL: {}",
    "tasa de error {}% > 10%": "error rate {}% > 10%",
    "latencia {}s > 3x base ({}s)": "latency {}s > 3x baseline ({}s)",
    "p95 {}s > 4x base ({}s)": "p95 {}s > 4x baseline ({}s)",
    "volatilidad (CV) {} > 1.0": "volatility (CV) {} > 1.0",
    "Se detectó degradación en concurrencia {}: {}. "
    "Capacidad estable estimada: {} peticiones simultáneas.":
    "Degradation detected at concurrency {}: {}. "
    "Estimated stable capacity: {} simultaneous requests.",
    "El sistema soportó todas las pruebas hasta {} peticiones simultáneas sin degradación. "
    "La capacidad real podría estar por encima del techo de la herramienta.":
    "The system passed all tests up to {} simultaneous requests without degradation. "
    "The real capacity could be above the tool's ceiling.",
    "Prueba de carga completada": "Load test completed",

    # -------------------------------------------------------------- db/http
    "No se pudo crear el usuario: {}": "Could not create the user: {}",
    "Timeout: la solicitud tardó demasiado.": "Timeout: the request took too long.",
    "Error de conexión: no se pudo conectar al servidor.":
    "Connection error: could not connect to the server.",
    "Error de solicitud: {}": "Request error: {}",
    "Base de datos no configurada.": "Database not configured.",
    "🗄️ Modo local: los usuarios y el historial se guardan en "
    "`data/vulnweb.db` (SQLite). Configura Supabase en `.env` para usarla.":
    "🗄️ Local mode: users and history are stored in `data/vulnweb.db` (SQLite). "
    "Configure Supabase in `.env` to use it.",

    # ------------------------------------------- Análisis profundo / auditoría
    "Objetivo": "Target",
    "Hallazgos": "Findings",
    "Nivel": "Level",
    "Impact": "Impact",
    "Likelihood (CVSS Base)": "Likelihood (CVSS Base)",
    "El sitio no usa HTTPS": "The site does not use HTTPS",
    "Los datos viajan sin cifrar y pueden ser interceptados.":
    "The data travels unencrypted and can be intercepted.",
    "Fuerza conexiones HTTPS. Su ausencia permite ataques de downgrade a HTTP.":
    "Forces HTTPS connections. Its absence allows downgrade attacks to HTTP.",
    "Agregar: Strict-Transport-Security: max-age=31536000.":
    "Add: Strict-Transport-Security: max-age=31536000.",
    "Agregar: X-Frame-Options: DENY o SAMEORIGIN.":
    "Add: X-Frame-Options: DENY or SAMEORIGIN.",
    "Protege contra clickjacking impidiendo cargar la pagina en iframes de terceros.":
    "Protects against clickjacking by preventing the page from loading in third-party iframes.",
    "Agregar: X-Content-Type-Options: nosniff.": "Add: X-Content-Type-Options: nosniff.",
    "Evita que el navegador haga MIME-sniffing e interprete archivos como scripts.":
    "Prevents the browser from doing MIME-sniffing and interpreting files as scripts.",
    "Controla que informacion se envia como referencia al navegar a otros sitios.":
    "Controls what information is sent as a referrer when browsing to other sites.",
    "Agregar: Referrer-Policy: no-referrer.": "Add: Referrer-Policy: no-referrer.",
    "Define los origenes permitidos para mitigar XSS. Su ausencia permite inyectar scripts maliciosos.":
    "Defines the allowed sources to mitigate XSS. Its absence allows injecting malicious scripts.",
    "Definir una politica CSP estricta (default-src 'self').":
    "Define a strict CSP policy (default-src 'self').",
    "Implementar certificado SSL/TLS y redirigir todo el trafico a HTTPS.":
    "Deploy an SSL/TLS certificate and redirect all traffic to HTTPS.",
    "Problema con el certificado SSL/TLS": "Problem with the SSL/TLS certificate",
    "Certificado no valido": "Invalid certificate",
    "Instalar un certificado SSL valido de una CA confiable.":
    "Install a valid SSL certificate from a trusted CA.",
    "Version de TLS antigua ({})": "Outdated TLS version ({})",
    "Las versiones anteriores a TLS 1.2 tienen vulnerabilidades conocidas.":
    "Versions older than TLS 1.2 have known vulnerabilities.",
    "Deshabilitar TLS 1.0/1.1 y SSL y forzar TLS 1.2 o 1.3.":
    "Disable TLS 1.0/1.1 and SSL and force TLS 1.2 or 1.3.",
    "Error del servidor (HTTP {})": "Server error (HTTP {})",
    "El servidor devuelve errores 5xx.": "The server returns 5xx errors.",
    "Revisar los logs del servidor.": "Review the server logs.",
    "Error HTTP {}": "HTTP error {}",
    "La pagina devuelve un error de cliente.": "The page returns a client error.",
    "Verificar la URL.": "Check the URL.",
    "Cabecera de seguridad faltante: {}": "Missing security header: {}",
    "Tecnologia del servidor expuesta": "Exposed server technology",
    "Revelar software y version permite buscar vulnerabilidades.":
    "Disclosing software and version allows looking up vulnerabilities.",
    "Ocultar Server y X-Powered-By.": "Hide Server and X-Powered-By.",
    "{} cookie(s) sin flags de seguridad": "{} cookie(s) without security flags",
    "Sin Secure se envian por HTTP y sin HttpOnly quedan expuestas.":
    "Without Secure they are sent over HTTP and without HttpOnly they remain exposed.",
    "Configurar cookies con Secure, HttpOnly y SameSite.":
    "Configure cookies with Secure, HttpOnly and SameSite.",
    "CORS con Access-Control-Allow-Origin: *": "CORS with Access-Control-Allow-Origin: *",
    "Permite que cualquier sitio lea respuestas, facilitando robo de datos.":
    "Allows any site to read responses, making data theft easier.",
    "Restringir CORS a dominios confiables.": "Restrict CORS to trusted domains.",
    "{} formulario(s) usan GET para datos": "{} form(s) use GET for data",
    "Los datos viajan en la URL y quedan en historial y logs.":
    "The data travels in the URL and ends up in history and logs.",
    "Usar POST para formularios con datos sensibles.":
    "Use POST for forms with sensitive data.",
    "{} iframe(s) ocultos detectados": "{} hidden iframe(s) detected",
    "Iframes ocultos son senal de clickjacking o contenido malicioso.":
    "Hidden iframes are a sign of clickjacking or malicious content.",
    "Revisar origen de iframes y aplicar X-Frame-Options.":
    "Review the origin of the iframes and apply X-Frame-Options.",
    "Error de certificado SSL": "SSL certificate error",
    "Certificado invalido.": "Invalid certificate.",
    "Verificar certificado SSL.": "Verify the SSL certificate.",
    "No se pudo conectar al sitio": "Could not connect to the site",
    "El servidor no respondio.": "The server did not respond.",
    "Tiempo de espera agotado": "Timeout reached",
    "Timeout en la peticion.": "Timeout in the request.",
    "Revisar rendimiento del servidor.": "Review server performance.",
    "Error al analizar la URL": "Error analyzing the URL",
    "Verificar la sintaxis de la URL.": "Check the URL syntax.",
    "Verificar disponibilidad.": "Check availability.",
    "Cabecera de respuesta del servidor web.": "Web server response header.",
    "Archivo de variables de entorno expuesto": "Exposed environment variables file",
    "Repositorio Git expuesto": "Exposed Git repository",
    "Metadatos de Git expuestos": "Exposed Git metadata",
    "Página phpinfo() expuesta": "Exposed phpinfo() page",
    "Estado del servidor expuesto": "Exposed server status",
    "web.config expuesto": "Exposed web.config",
    "Archivo .DS_Store expuesto": "Exposed .DS_Store file",
    "Backup comprimido accesible": "Accessible compressed backup",
    "Copia de wp-config expuesta": "Exposed wp-config copy",
    "Copia de configuración expuesta": "Exposed configuration copy",
    "Eliminar o restringir el acceso a este recurso.":
    "Remove or restrict access to this resource.",
    "Content-Security-Policy débil": "Weak Content-Security-Policy",
    "comodín *": "wildcard *",
    "Permite: ": "Allows: ",
    "Facilita la ejecución de scripts inyectados.":
    "Makes it easier to run injected scripts.",
    "Eliminar unsafe-inline/unsafe-eval y comodines de la CSP.":
    "Remove unsafe-inline/unsafe-eval and wildcards from the CSP.",
    "Métodos HTTP habilitados: {}": "Enabled HTTP methods: {}",
    "Allow: {}. PUT/DELETE permiten modificar recursos.":
    "Allow: {}. PUT/DELETE allow modifying resources.",
    "Deshabilitar los métodos HTTP que no sean necesarios.":
    "Disable the HTTP methods that are not needed.",
    "Método TRACE habilitado": "TRACE method enabled",
    "TRACE devuelve la petición y puede facilitar Cross-Site Tracing (XST).":
    "TRACE echoes the request and can facilitate Cross-Site Tracing (XST).",
    "Deshabilitar TRACE en el servidor.": "Disable TRACE on the server.",
    "Accesible en {} (HTTP {}).": "Accessible at {} (HTTP {}).",
    "robots.txt revela {} ruta(s)": "robots.txt reveals {} path(s)",
    "Rutas: ": "Paths: ",
    "No listar rutas sensibles en robots.txt; protégelas con autenticación.":
    "Do not list sensitive paths in robots.txt; protect them with authentication.",
    "Tecnología detectada: ": "Detected technology: ",
    "Conocer el stack facilita buscar vulnerabilidades conocidas de esas versiones.":
    "Knowing the stack makes it easier to look up known vulnerabilities for those versions.",
    "Ocultar versiones/firmas y mantener todos los componentes actualizados.":
    "Hide versions/banners and keep all components updated.",
    "🌐 Páginas rastreadas ({}):": "🌐 Pages crawled ({}):",

    # --------------------------------------------------------- Validación URL
    "La URL no puede estar vacía.": "The URL cannot be empty.",
    "La URL debe usar http o https.": "The URL must use http or https.",
    "La URL no contiene un dominio válido.": "The URL does not contain a valid domain.",
    "La URL apunta a una dirección interna o privada (posible SSRF). "
    "Activa 'Permitir red interna' en la barra lateral si es un objetivo de laboratorio.":
    "The URL points to an internal or private address (possible SSRF). "
    "Enable 'Allow internal network' in the sidebar if it is a lab target.",
    "El usuario debe tener al menos 3 caracteres.":
    "The username must be at least 3 characters long.",
    "tu_usuario": "your_user",
    "mi_usuario": "my_user",
    "Puerto {} abierto ({})": "Port {} open ({})",
    "desconocido": "unknown",
    "Sistema activo": "System active",
    "Sistema activo - Todos los módulos operativos":
    "System active - All modules operational",

    # ------------------------------------------- Recomendaciones de métricas
    "🚨 [CRÍTICO] El parámetro '{}' presenta inyección SQL {} ({}/10). Aplicar parche "
    "inmediato: usar consultas parametrizadas (prepared statements), validar entradas con "
    "whitelist, y desplegar WAF. No aplique correcciones temporales sin análisis profundo.":
    "🚨 [CRITICAL] The parameter '{}' presents an SQL injection {} ({}/10). Apply an "
    "immediate patch: use parameterized queries (prepared statements), validate inputs with "
    "a whitelist, and deploy a WAF. Do not apply temporary fixes without a deep analysis.",
    "⚠️ [ALTA] Inyección SQL {} en '{}' (CVSS {}/10). Priorizar en el ciclo de parches "
    "actual: migra a queries parametrizadas, aplica escape de entradas y monitorea logs de acceso.":
    "⚠️ [HIGH] SQL injection {} in '{}' (CVSS {}/10). Prioritize in the current patch cycle: "
    "migrate to parameterized queries, escape inputs and monitor access logs.",
    "📋 [MEDIA] Indicio de inyección SQL en '{}' (CVSS {}/10). Validar con pruebas manuales "
    "y aplicar validación de entradas. Planificar corrección en la siguiente sprint.":
    "📋 [MEDIUM] Possible SQL injection in '{}' (CVSS {}/10). Validate with manual tests and "
    "apply input validation. Plan the fix for the next sprint.",
    "ℹ️ [BAJA] Hallazgo menor en '{}' (CVSS {}/10). Documentar y revisar en revisión de "
    "seguridad periódica.":
    "ℹ️ [LOW] Minor finding in '{}' (CVSS {}/10). Document it and review it in the periodic "
    "security review.",
    "El parámetro '{}' presenta una posible inyección SQL ({}) con nivel de riesgo {} "
    "(CVSS {}/10). Se recomienda aplicar consultas parametrizadas y validación de entradas.":
    "The parameter '{}' presents a possible SQL injection ({}) with risk level {} "
    "(CVSS {}/10). Parameterized queries and input validation are recommended.",
    "✅ Rendimiento óptimo. Mantener monitoreo continuo y planificar escalado proactivo.":
    "✅ Optimal performance. Keep continuous monitoring and plan proactive scaling.",
    "⚠️ Rendimiento aceptable. Considerar optimización de queries y añadir caching.":
    "⚠️ Acceptable performance. Consider query optimization and adding caching.",
    "🔶 Degradación detectada. Implementar rate limiting, balanceo de carga y optimización de DB.":
    "🔶 Degradation detected. Implement rate limiting, load balancing and DB optimization.",
    "🚨 Rendimiento crítico. Escalar infraestructura inmediatamente, revisar queries lentas y caché.":
    "🚨 Critical performance. Scale infrastructure immediately, review slow queries and cache.",
}


def _con_emoji(prefijo: str, texto: str) -> str:
    """Reinyecta el emoji del original si la traducción no lo lleva."""
    marca = prefijo.rstrip()
    if not marca or _PREFIJO_DECORATIVO.match(texto):
        return texto
    return f"{marca} {texto}"


# Conserva el emoji original también en inglés: "⚠️ Condiciones de uso" ->
# "⚠️ Terms of Use" (y no "Terms of Use").
for _clave, _valor in list(TRADUCCIONES.items()):
    _prefijo = _PREFIJO_DECORATIVO.match(_clave)
    if _prefijo:
        TRADUCCIONES[_clave] = _con_emoji(_prefijo.group(0), _valor)
del _clave, _valor, _prefijo


def idioma() -> str:
    """Devuelve el idioma activo de la sesión ("es" por defecto)."""
    return st.session_state.get("idioma", "es")


def _buscar(texto):
    """Busca la traducción exacta; si no, reintenta sin el emoji inicial.

    En ambos casos se conserva el emoji del texto original, de modo que el
    inglés mantiene los mismos iconos que el español.
    """
    if texto in TRADUCCIONES:
        return TRADUCCIONES[texto]
    if isinstance(texto, str):
        prefijo = _PREFIJO_DECORATIVO.match(texto)
        if prefijo:
            limpio = texto[prefijo.end():].strip()
            if limpio in TRADUCCIONES:
                return _con_emoji(prefijo.group(0), TRADUCCIONES[limpio])
    return None


def t(texto, *args):
    """Traduce `texto` a inglés si está activo y existe traducción."""
    if idioma() == "en":
        encontrada = _buscar(texto)
        texto_out = encontrada if encontrada is not None else texto
    else:
        texto_out = texto
    return texto_out.format(*args) if args else texto_out


def es_o_en(es: str, en: str) -> str:
    """Decisión directa es/en sin depender del diccionario."""
    return en if idioma() == "en" else es


# Cabeceras de tabla: las tablas se construyen con dicts whose keys are in
# Spanish, so the columns are renamed here when the interface is in English.
COLUMNAS_EN = {
    # carga / niveles
    "concurrencia": "Concurrency", "peticiones_totales": "Total requests",
    "errores": "Errors", "tasa_error": "Error rate (%)",
    "latencia_promedio": "Avg latency (s)", "latencia_base": "Baseline latency (s)",
    "latencia_p50": "p50 (s)", "latencia_p90": "p90 (s)",
    "latencia_p95": "p95 (s)", "latencia_p99": "p99 (s)",
    "errores_timeout": "Timeout errors", "errores_conexion": "Connection errors",
    "errores_4xx": "4xx errors", "tiempo_total": "Total time (s)",
    # puertos
    "puerto": "Port", "protocolo": "Protocol", "estado": "Status",
    "servicio": "Service", "total_puertos": "Total open ports",
    # genéricos
    "url": "URL", "url_objetivo": "Target URL", "ip": "IP", "host": "Host",
    "dominio": "Domain", "descripcion": "Description", "detalle": "Detail",
    "evidencia": "Evidence", "explicacion": "Explanation",
    "parametro": "Parameter", "parametros": "Parameters", "tipo": "Type",
    "confianza": "Confidence", "confianza_promedio": "Avg confidence",
    "severidad": "Severity", "nivel": "Level", "nivel_vulnerabilidad": "Vulnerability level",
    "metodo": "Method", "fecha": "Date", "modulo": "Module", "owasp": "OWASP",
    "remediacion": "Remediation", "score": "Score", "puntuacion": "Score",
    "total": "Total", "hallazgos": "Findings", "valor": "Value",
    "puntos": "Points", "paginas": "Pages", "enlaces": "Links",
    "tecnologias": "Technologies", "cabeceras": "Headers", "formularios": "Forms",
    "recursos": "Resources", "titulo": "Title", "estado_general": "Overall status",
    "vulnerable": "Vulnerable", "resumen": "Summary", "diagnostico": "Diagnosis",
}

# Valores de celda que son palabras en español (coincidencia exacta).
VALORES_EN = {
    "abierto": "open", "abiertos": "open", "cerrado": "closed",
    "desconocido": "unknown", "correcto": "OK", "procesado": "processed",
    "cancelado": "cancelled", "Crítica": "Critical", "critica": "Critical",
    "Alta": "High", "alta": "High", "Media": "Medium", "media": "Medium",
    "Baja": "Low", "baja": "Low", "Info": "Info", "info": "Info",
    "Excelente": "Excellent", "Buena": "Good", "Degradada": "Degraded",
    "Crítico": "Critical", "crítico": "Critical", "alto": "High", "medio": "Medium",
    "bajo": "Low", "informativa": "informational", "informativo": "informational",
    "Inyección SQL": "SQL Injection", "Auditoría": "Audit", "Carga": "Load",
    "Puertos": "Ports", " phishing": "phishing", "phishing": "phishing",
}


def columna(nombre: str) -> str:
    """Traduce el nombre de una columna de tabla (p. ej. 'puerto' -> 'Port')."""
    if idioma() == "en":
        return COLUMNAS_EN.get(str(nombre).strip(), nombre)
    return nombre


def valor(texto) -> str:
    """Traduce valores de celda que sean palabras conocidas en español."""
    texto = str(texto)
    if idioma() == "en":
        return VALORES_EN.get(texto.strip(), texto)
    return texto
# Analizador de Vulnerabilidades Web

Herramienta de **pentesting ético** para detectar Inyección SQL y evaluar capacidad ante saturación de peticiones. Incluye **dashboard profesional** con métricas CVSS, PGI (Performance Grade Index), matrices de riesgo, explicaciones de vulnerabilidades y visualizaciones interactivas.

> ⚠️ **Uso responsable**: solo contra sistemas propios o con autorización escrita explícita del propietario. Escanear sistemas de terceros sin permiso puede ser ilegal.

---

## Características principales

### 🔍 Escáner de Inyección SQL — Dashboard
- **Puntuación CVSS v3.1** calculada para cada hallazgo (0-10)
- **Matriz de riesgo** (Likelihood vs Impact) con clasificación visual
- **Distribución de severidad** (donut chart)
- **Cobertura de vectores de ataque** (radar chart): error-based, boolean-based, time-based
- **Nivel de confianza** por parámetro (bar chart agrupado)
- **Indicador gauge** de riesgo global
- **Explicación detallada** por cada vulnerabilidad detectada (qué se encontró, por qué es peligroso, cómo explotarlo)
- **Recomendaciones contextuales** con prioridad según severidad CVSS
- **Tabla detallada** de hallazgos con CVSS, nivel de riesgo y confianza

### 🛡️ Auditoría Unificada — Dashboard
- Security Score (0-100) y nivel de exposición
- Hallazgos agrupados por severidad con remediaciones OWASP
- Fingerprint de tecnologías detectadas
- **Páginas rastreadas** (crawler) con estado HTTP y nº de hallazgos
- Detección de phishing (ML)

### ⚡ Prueba de Capacidad — Dashboard
- **Grado de Salud del Sistema (PGI)** 0-100 con gauge visual
- **Latencia por percentiles** (p50, p90, p95, p99) vs concurrencia
- **Throughput** (peticiones/segundo) por nivel de concurrencia
- **Distribución de errores** (timeouts, conexión, 4xx, 5xx)
- **Tasa de error** por nivel (bar chart)
- **Recomendaciones** basadas en el grado de salud

---

## 1. Objetivo

Una app Streamlit con autenticación de usuarios donde:
1. El usuario crea una cuenta o inicia sesión (registro + login con PBKDF2-HMAC-SHA256 + salt).
2. Ingresa una URL objetivo en la barra lateral (cualquiera; no hace falta que incluya parámetros: la herramienta descubre los de la página y sus formularios).
3. Marca la casilla de autorización (obligatoria para desbloquear).
4. Selecciona el tipo de análisis mediante botones horizontales en la barra lateral: Inyección SQL, Carga, Auditoría Unificada o Escaneo de Puertos.
5. Ve el resultado en un **dashboard profesional** con gráficos interactivos, métricas CVSS/PGI/OWASP, explicaciones de vulnerabilidades y recomendaciones accionables.

---

## 2. Estructura de carpetas (Arquitectura MVC)

```
webvuln/
├── app.py                      # Entry point (llama al controlador principal)
├── requirements.txt
├── README.md
├── .env                        # Credenciales de Supabase (no se versiona)
│
├── models/                     # MODELO — Datos y lógica de negocio
│   ├── __init__.py
│   ├── http_utils.py           # Cliente HTTP compartido (GET/POST)
│   ├── discovery.py            # Descubre parámetros en enlaces y formularios (GET/POST)
│   ├── sqli_model.py           # Lógica de detección de Inyección SQL
│   ├── load_model.py           # Lógica de prueba de capacidad/saturación
│   ├── deep_analysis.py        # Análisis de una página (HTTPS, headers, cookies, formularios)
│   ├── crawler.py              # Rastreo del sitio (mismo host, profundidad configurable)
│   ├── deep_audit.py           # Auditoría profunda (fingerprint, métodos HTTP, archivos, CSP)
│   ├── phishing_ml.py          # Detección de phishing con ML
│   ├── audit_consolidator.py   # Consolidación de auditoría OWASP
│   ├── risk_score.py           # Puntuación de riesgo 0-100
│   ├── remediation.py          # Guías de remediación
│   ├── port_scanner.py         # Escaneo de puertos
│   ├── auth_model.py           # Autenticación PBKDF2 contra Supabase
│   ├── db.py                   # Cliente Supabase (service_role)
│   ├── history.py              # Persistencia de análisis y hallazgos
│   └── metrics.py              # Métricas CVSS y PGI
│
├── views/                      # VISTA — Presentación y UI
│   ├── __init__.py
│   ├── components.py           # Componentes reutilizables (sidebar, KPI, nav)
│   ├── sqli_view.py            # Dashboard SQLi + explicaciones de vulnerabilidades
│   ├── load_view.py            # Dashboard de Prueba de Capacidad
│   ├── audit_view.py           # Dashboard de Auditoría Unificada
│   ├── login_view.py           # Pantalla de acceso (login / registro)
│   ├── history_view.py         # Historial reciente en la barra lateral
│   └── dashboard_view.py       # Generadores de gráficos (Plotly)
│
└── controllers/                # CONTROLADOR — Orquestación Model↔View
    ├── __init__.py
    ├── app_controller.py       # Flujo principal (sidebar navigation)
    ├── sqli_controller.py      # Manejo de escáner SQLi
    ├── load_controller.py      # Manejo de prueba de carga
    └── audit_controller.py     # Auditoría unificada + escaneo de puertos
```

**Arquitectura MVC:**
- **Model** (`models/`): Contiene la lógica de negocio (escaneo SQLi, prueba de carga, métricas CVSS/PGI). Sin dependencias de UI.
- **View** (`views/`): Recibe datos del modelo y renderiza la interfaz (Streamlit, gráficos, tablas, explicaciones). Sin lógica de negocio.
- **Controller** (`controllers/`): Orquesta el flujo — maneja eventos de usuario, llama al modelo y pasa datos a la vista.

**UI:** Navegación mediante botones horizontales en la barra lateral (Sidebar) con selección visual del modo activo.

**Temas:** selector **🎨 Tema** disponible tanto en la **pantalla de acceso** como en la **barra lateral**, con tres opciones:
- **Sistema**: sigue la preferencia del sistema operativo en vivo (`prefers-color-scheme`).
- **Claro** y **Oscuro**: fuerzan la paleta.

Todo el diseño (fondos, superficies, bordes, textos, tarjetas, tablas, avisos, gráficos Plotly) se define con tokens CSS en `views/components.py`; cambiar de tema recolorea la interfaz completa sin recargar la app.

---

## 3. Dependencias

```
streamlit>=1.35
requests>=2.31
pandas>=2.0
plotly>=5.18
beautifulsoup4>=4.12
scikit-learn>=1.3
joblib>=1.3
numpy>=1.24,<2.3
```

Instalación:
```bash
pip install -r requirements.txt
```

---

## 4. Módulos — Modelo (`models/`)

### `models/http_utils.py`
Cliente HTTP compartido.
- `validar_url(url, permitir_privadas=False)` → valida esquema/dominio y bloquea objetivos internos/privados (SSRF) salvo autorización explícita.
- `hacer_peticion(url, params=None, timeout=8)` → GET sin excepciones. Retorna `(respuesta, tiempo, error)`.

### `models/discovery.py` — Descubrimiento de puntos de inyección
Dada una URL cualquiera (no hace falta que traiga parámetros), descarga la página y extrae:
- parámetros de la propia URL,
- parámetros de los enlaces del mismo host,
- campos de los **formularios GET y POST** (incluidos los ocultos; los tokens CSRF se envían como contexto pero no se inyectan).

Devuelve una lista de "objetivos" (`url`, `method`, `params`, `param`, `origen`) y un resumen del descubrimiento.

### `models/crawler.py` — Rastreo del sitio
Partiendo de una URL, sigue enlaces **del mismo host** hasta una profundidad configurable (0–3) y un máximo de páginas (1–50). Recoge enlaces, formularios y recursos por página; ignora recursos estáticos (imágenes, CSS, JS, etc.).

### `models/deep_audit.py` — Auditoría profunda
Orquesta el crawler + `analizar_profundamente` en cada página y añade comprobaciones globales:
- **Fingerprint de tecnología** (CMS, frameworks, servidor…).
- **Métodos HTTP** habilitados (PUT/DELETE/TRACE…) y TRACE.
- **Archivos expuestos** (`.env`, `.git/config`, `phpinfo.php`, `backup.zip`, backups…).
- **CSP débil** (`unsafe-inline`, `unsafe-eval`, comodines).
- **robots.txt** con rutas reveladas.
Los hallazgos repetidos entre páginas se deduplican y se agrega un *score* 0-100.

### `models/sqli_model.py` — Escáner de Inyección SQL
**Técnicas:** error-based, boolean-based blind, time-based blind, aplicadas a cada objetivo descubierto (GET o POST).
- Límite por defecto: **12 puntos de inyección** por análisis (configurable vía `SQLiModel(max_objetivos=N)`).
- Cada hallazgo indica parámetro, método HTTP, origen (URL/enlace/formulario) y endpoint.

Cada hallazgo incluye:
- `cvss`: Puntuación CVSS v3.1 (0-10)
- `nivel_riesgo`: Crítica / Alta / Media / Baja
- `explicacion`: Descripción detallada de la vulnerabilidad (qué se detectó, por qué es peligroso, cómo podría explotarse)
- `recomendacion`: Recomendación de remediación
- `vector_cvss`: Vector CVSS estándar

### `models/load_model.py` — Prueba de Capacidad
Rampa de concurrencia creciente con umbrales de degradación (tasa error >10%, latencia >3x base, p95 >4x base, volatilidad >1.0).

### `models/metrics.py` — Métricas Profesionales
- `cvss_score(hallazgo)` → puntuación CVSS (0-10)
- `nivel_riesgo(cvss)` → Crítica/Alta/Media/Baja
- `calcular_metricas_sqli(resultado)` → CVSS promedio, riesgo global, distribución, recomendaciones
- `calcular_metricas_load(resultado)` → PGI (0-100), salud global, distribución de errores

### `models/auth_model.py` — Autenticación de Usuarios
- `register(username, password)` → registra usuario con PBKDF2-HMAC-SHA256 + salt (200k iteraciones); migra automáticamente cuentas antiguas SHA-256 al iniciar sesión
- `login(username, password)` → verifica credenciales, retorna `(bool, mensaje)`
- `is_authenticated()` → verifica si hay sesión activa
- `logout()` → cierra sesión y limpia estado
- `get_current_user()` → retorna nombre del usuario actual
- Usuarios almacenados en Supabase (tabla `app_users`)

---

## 5. Módulos — Vista (`views/`)

### `views/login_view.py` — Pantalla de Acceso
Página centrada que se muestra antes de ingresar al sistema:
- **Tarjeta centrada** con fondo degradado oscuro y sombra profesional
- **Dos pestañas**: 📝 Crear Cuenta / 🔑 Iniciar Sesión
- Formularios con validación de campos, longitud y coincidencia de contraseñas
- Logo, título con gradiente y pie de página
- Mensajes de éxito/error con iconos

### `views/components.py`
Componentes reutilizables de UI:
- `kpi_grid(cards)` → cuadrícula de tarjetas KPI
- `ui_login()` → Formulario de registro/login (pestañas: Registrar + Entrar)
- `_ui_user_bar()` → Barra de usuario conectado + botón salir
- `ui_sidebar()` → Logo y título en la barra lateral
- `ui_authorization_check()` → Confirmación de autorización
- `ui_url_input_sidebar()` → Input de URL en la barra lateral
- `ui_navigation_buttons()` → Botones de navegación horizontales (SQLi, Carga, Auditoría, Puertos)
- `ui_execute_button()` → Botón de ejecución en la barra lateral

### `views/sqli_view.py`
Dashboard de Inyección SQL:
- KPIs (total hallazgos, CVSS promedio, riesgo global, confianza, cobertura)
- 5 gráficos Plotly (donut severidad, radar cobertura, gauge riesgo, bar confianza, matriz riesgo)
- **Vulnerabilidades detalladas** con:
  - Explicación técnica de cada hallazgo
  - Payload utilizado
  - Evidencia recolectada
  - Motor de base de datos sugerido
- Tabla resumen de hallazgos
- Recomendaciones de remediación

### `views/load_view.py`
Dashboard de Prueba de Capacidad:
- KPIs (capacidad, latencia base, PGI, salud global, tasa error)
- Gráficos: latencia por percentil, throughput, errores, gauge PGI
- Tabla resumen de niveles
- Recomendaciones de rendimiento

### `views/audit_view.py`
Dashboard de Auditoría Unificada:
- Security Score (0-100) con clasificación y nivel de exposición
- KPIs (críticos, altos, medios, totales)
- Hallazgos agrupados por severidad con remediaciones OWASP
- Análisis profundo (HTTPS/TLS/cabeceras)
- Detección de phishing (ML)
- Distribución de severidad (donut chart)

---

## 6. Módulos — Controlador (`controllers/`)

### `controllers/app_controller.py`
Flujo principal con autenticación y navegación en barra lateral:
1. **Login/Registro**: Si no hay sesión activa, muestra pestañas de Registrar y Entrar
2. **Sidebar autenticado**: Logo, usuario + salir, autorización, URL, botones de navegación horizontales, botón ejecutar
3. Delega al controlador correspondiente según modo seleccionado
4. 4 modos: SQLi, Carga, Auditoría, Puertos

### `controllers/sqli_controller.py`
Valida URL → ejecuta `SQLiModel.analizar()` → pasa resultado a `views.sqli_view.mostrar()`.

### `controllers/load_controller.py`
Valida URL → ejecuta `LoadModel.analizar()` → pasa resultado a `views.load_view.mostrar()`.

### `controllers/audit_controller.py`
- `ejecutar_audit_unificado(url)` → Rastreo + auditoría profunda de cada página + phishing ML + consolidación OWASP → `views.audit_view.mostrar()`. Profundidad y máximo de páginas configurables en la barra lateral (**⚙️ Opciones de auditoría profunda**).
- `ejecutar_port_scan(url)` → Escaneo de puertos → Tabla de resultados

---

## 7. Entry Point (`app.py`)

```python
from controllers.app_controller import run
run()
```

Ejecutar:
```bash
streamlit run app.py
```

---

## 8. Orden de construcción

- [x] **Paso 1:** `models/http_utils.py` — Cliente HTTP
- [x] **Paso 2:** `models/sqli_model.py` — Escáner SQLi con 3 técnicas + CVSS + explicaciones
- [x] **Paso 3:** `models/load_model.py` — Prueba de capacidad
- [x] **Paso 4:** `models/metrics.py` — Métricas CVSS/PGI
- [x] **Paso 5:** `models/auth_model.py` — Registro y login con PBKDF2
- [x] **Paso 6:** `models/deep_analysis.py` — Análisis profundo de URL
- [x] **Paso 7:** `models/phishing_ml.py` — Detección de phishing ML
- [x] **Paso 8:** `models/audit_consolidator.py` — Consolidación OWASP
- [x] **Paso 9:** `models/risk_score.py` + `models/remediation.py`
- [x] **Paso 10:** `models/port_scanner.py` — Escaneo de puertos
- [x] **Paso 11:** `views/dashboard_view.py` — Gráficos Plotly
- [x] **Paso 12:** `views/sqli_view.py` + `views/load_view.py` + `views/audit_view.py` — Dashboards con explicaciones
- [x] **Paso 13:** `views/components.py` — Componentes reutilizables (sidebar + login)
- [x] **Paso 14:** `controllers/` — Controladores (MVC)
- [x] **Paso 15:** `app.py` — Entry point delgado
- [ ] **Paso 16 (futuro):** JWT/autenticación avanzada, exportar reporte a PDF/HTML.

---

## 9. Cómo probarlo sin riesgo legal

No pruebes esto contra sitios reales sin permiso. Usa un entorno de práctica local con Docker:

```bash
# OWASP Juice Shop (tiene SQLi intencional)
docker run -d -p 3000:3000 bkimminich/juice-shop

# O DVWA (Damn Vulnerable Web Application)
docker run -d -p 80:80 vulnerables/web-dvwa
```

> Para analizar estos laboratorios en `localhost` activa **🌐 Permitir red interna** en la barra lateral. Por defecto la app bloquea objetivos privados para evitar SSRF.

---

## 10. Base de datos (Supabase + RLS)

La app persiste **usuarios** y el **historial de análisis con sus hallazgos** en Supabase. La base de datos es **obligatoria**: sin `SUPABASE_URL` / `SUPABASE_KEY` no se puede iniciar sesión.

### 10.1 Esquema

| Tabla | Contenido |
|---|---|
| `app_users` | Usuarios con hash **PBKDF2-HMAC-SHA256** + salt (login propio) |
| `scans` | Un registro por análisis: módulo, URL, score, nivel, total de hallazgos, resumen `jsonb`, fecha |
| `scan_findings` | Hallazgos individuales de cada análisis (tipo, parámetro, método, severidad, CVSS, evidencia, OWASP…) |

Índices: `scans(username, created_at desc)` y `scan_findings(scan_id)`.

### 10.2 Configuración

1. Rellena tus credenciales en el archivo **`.env`** de la raíz:
   ```env
   SUPABASE_URL=https://tu-proyecto.supabase.co
   SUPABASE_KEY=tu-service-role-key
   ```
   (También se admiten `st.secrets` / variables de entorno con los mismos nombres.)
2. `pip install -r requirements.txt` (incluye `supabase>=2.0` y `python-dotenv>=1.0`).
3. Arranca la app.

La barra lateral indica **🗄️ Supabase conectado**; si falta la configuración, muestra **⚠️ Supabase sin configurar** y el login avisa.

> ⚠️ Usa la clave **`service_role`** y **nunca** la expongas en el navegador. Vive solo en `.env`, que está en `.gitignore`.

### 10.3 RLS (Row Level Security)

El login es propio (PBKDF2), así que **no existe `auth.uid()`**. Por eso la política es:

- **RLS habilitada** en las tres tablas.
- **Sin políticas permisivas** para `anon` / `authenticated` → la API pública **no puede leer ni escribir nada**.
- El backend de Streamlit (servidor de confianza) usa la **`service_role`**, que omite RLS.

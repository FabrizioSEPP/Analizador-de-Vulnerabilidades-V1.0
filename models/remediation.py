REMEDIATIONS = {
    "hsts": {
        "what": "Activar Strict Transport Security (HSTS).",
        "where": "Configuracion del servidor web / reverse proxy / CDN.",
        "example": '# Nginx:\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        "verify": "curl -sI https://dominio | grep -i strict-transport-security",
    },
    "csp": {
        "what": "Definir una Content Security Policy.",
        "where": "Cabecera de respuesta del servidor web.",
        "example": "Content-Security-Policy: default-src 'self'; script-src 'self';",
        "verify": "curl -sI https://dominio | grep -i content-security-policy",
    },
    "xframe": {
        "what": "Impedir clickjacking (X-Frame-Options).",
        "where": "Cabecera de respuesta del servidor web.",
        "example": '# Nginx:\nadd_header X-Frame-Options "DENY" always;',
        "verify": "curl -sI https://dominio | grep -i x-frame-options",
    },
    "nosniff": {
        "what": "Prevenir MIME sniffing (X-Content-Type-Options).",
        "where": "Cabecera de respuesta del servidor web.",
        "example": 'add_header X-Content-Type-Options "nosniff" always;',
        "verify": "curl -sI https://dominio | grep -i x-content-type-options",
    },
    "https": {
        "what": "Forzar HTTPS y redirigir trafico HTTP.",
        "where": "Servidor web / balanceador / CDN.",
        "example": "# Nginx:\nserver {\n    listen 80;\n    server_name dominio.com;\n    return 301 https://$host$request_uri;\n}",
        "verify": "curl -sI http://dominio | head -n 5",
    },
    "tls": {
        "what": "Habilitar TLS 1.2/1.3, deshabilitar obsoletos.",
        "where": "Configuracion TLS del servidor.",
        "example": "# Nginx:\nssl_protocols TLSv1.2 TLSv1.3;",
        "verify": "usar sslscan o testssl.sh",
    },
    "cookie": {
        "what": "Configurar cookies con flags Secure, HttpOnly, SameSite.",
        "where": "Sesion/cookies del framework o WAF.",
        "example": "Set-Cookie: session=id; Secure; HttpOnly; SameSite=Strict;",
        "verify": "curl -sI https://dominio | grep -i set-cookie",
    },
    "sql_injection": {
        "what": "Usar consultas parametrizadas (prepared statements).",
        "where": "Codigo fuente de la aplicacion.",
        "example": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "verify": "Re-ejecutar escaneo SQLi para confirmar mitigacion.",
    },
    "xss": {
        "what": "Escape de salida + CSP estricta.",
        "where": "Templates / frontend.",
        "example": "Jinja: {{ variable | e }}  React: auto-escape por defecto",
        "verify": "Probar con payload: <script>alert(1)</script>",
    },
    "rate_limit": {
        "what": "Implementar rate limiting y WAF.",
        "where": "Servidor / CDN / WAF.",
        "example": "Nginx: limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;",
        "verify": "Enviar 50 peticiones/sec y verificar bloqueo",
    },
}


def get_remediation(rem_key: str) -> dict:
    key = rem_key.lower().replace(" ", "_").replace("-", "_")
    return REMEDIATIONS.get(key, REMEDIATIONS.get("rate_limit", {
        "what": "Revisar la configuracion del control indicado.",
        "where": "Segun el control afectado.",
        "example": "Consultar documentacion del servidor/aplicacion.",
        "verify": "Re-ejecutar auditoria o verificar manualmente.",
    }))

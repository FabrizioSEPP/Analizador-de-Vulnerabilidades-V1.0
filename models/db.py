"""Acceso a Supabase (PostgreSQL).

La app es un servidor de confianza: se conecta con la service_role, que omite
RLS. Las tablas tienen RLS habilitada y SIN políticas permisivas, de modo que
la clave pública (anon) no puede leer ni escribir nada directamente.

Configuración (en este orden):
  1. `.streamlit/secrets.toml`  -> SUPABASE_URL, SUPABASE_KEY
  2. Variables de entorno       -> SUPABASE_URL, SUPABASE_KEY
"""

import os

import streamlit as st

from models.i18n import t

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from supabase import create_client as _create_client
except Exception:  # dependencia no instalada
    _create_client = None

_cliente = None
_intentado = False


def _leer_config(clave: str):
    try:
        valor = st.secrets.get(clave)
        if valor:
            return valor
    except Exception:
        pass
    return os.environ.get(clave)


def _url_y_clave():
    url = _leer_config("SUPABASE_URL")
    key = _leer_config("SUPABASE_KEY") or _leer_config("SUPABASE_SERVICE_ROLE_KEY")
    return url, key


def get_client():
    """Devuelve el cliente Supabase o None si no está configurado."""
    global _cliente, _intentado
    if _cliente is not None:
        return _cliente
    if _intentado:
        return None
    _intentado = True

    if _create_client is None:
        return None
    url, key = _url_y_clave()
    if not url or not key:
        return None
    # Ignora los placeholders del .env de ejemplo.
    if "tu-proyecto" in url or "tu-service-role" in key:
        return None
    try:
        _cliente = _create_client(url, key)
    except Exception:
        _cliente = None
    return _cliente


def esta_configurado() -> bool:
    return get_client() is not None


def _local():
    """Módulo de base de datos local (SQLite), o None si no se puede usar."""
    try:
        from models import db_local
        return db_local
    except Exception:
        return None


def hay_base_datos() -> bool:
    """True si hay Supabase configurado O si se puede usar la base local."""
    return esta_configurado() or _local() is not None


def usando_base_local() -> bool:
    """True cuando se está usando SQLite local (Supabase no configurado)."""
    return get_client() is None and _local() is not None


# ------------------------------------------------------------------ usuarios
def obtener_usuario(username: str):
    cli = get_client()
    if cli is None:
        loc = _local()
        return loc.obtener_usuario(username) if loc else None
    if not username:
        return None
    try:
        res = (
            cli.table("app_users")
            .select("username,display_name,password,salt,algo,iteraciones")
            .eq("username", username.strip().lower())
            .limit(1)
            .execute()
        )
        return res.data[0] if res.data else None
    except Exception:
        return None


def crear_usuario(username: str, password_hash: str, salt: str,
                  iteraciones: int = 200_000, algo: str = "pbkdf2_sha256"):
    cli = get_client()
    if cli is None:
        loc = _local()
        if loc is None:
            return False, "Base de datos no configurada."
        return loc.crear_usuario(username, password_hash, salt, iteraciones, algo)
    try:
        cli.table("app_users").insert({
            "username": username.strip().lower(),
            "display_name": username.strip(),
            "password": password_hash,
            "salt": salt,
            "algo": algo,
            "iteraciones": iteraciones,
        }).execute()
        return True, ""
    except Exception as e:
        msg = str(e)
        if "duplicate key" in msg.lower() or "unique" in msg.lower() or "23505" in msg:
            return False, t("El usuario ya existe.")
        return False, t("No se pudo crear el usuario: {}").format(msg[:160])


def actualizar_credenciales(username: str, password_hash: str, salt: str,
                            iteraciones: int = 200_000, algo: str = "pbkdf2_sha256"):
    cli = get_client()
    if cli is None:
        loc = _local()
        if loc is not None:
            loc.actualizar_credenciales(username, password_hash, salt, iteraciones, algo)
            return True
        return False
    try:
        cli.table("app_users").update({
            "password": password_hash, "salt": salt,
            "algo": algo, "iteraciones": iteraciones,
        }).eq("username", username.strip().lower()).execute()
        return True
    except Exception:
        return False


def registrar_login(username: str):
    cli = get_client()
    if cli is None:
        loc = _local()
        if loc is not None:
            loc.registrar_login(username)
        return
    from datetime import datetime, timezone
    try:
        cli.table("app_users").update(
            {"last_login": datetime.now(timezone.utc).isoformat()}
        ).eq("username", username.strip().lower()).execute()
    except Exception:
        pass


# ------------------------------------------------------------------ escaneos
def _fila_hallazgo(scan_id: str, h: dict) -> dict:
    def primero(*claves):
        for k in claves:
            v = h.get(k)
            if v not in (None, ""):
                return v
        return None

    extra = {}
    for k in ("payload", "indicadores", "detalles", "firmas_detectadas",
              "diferencia_tamano_pct_max", "ratio", "consistencia", "origen",
              "url_objetivo", "codigo_http", "codigo_http_base", "modulo"):
        if h.get(k) not in (None, ""):
            extra[k] = h.get(k)

    return {
        "scan_id": scan_id,
        "tipo": primero("tipo"),
        "parametro": primero("parametro"),
        "metodo": primero("metodo"),
        "severidad": primero("nivel_riesgo", "severidad"),
        "cvss": h.get("cvss"),
        "confianza": h.get("confianza"),
        "descripcion": primero("descripcion", "descripcion_hallazgo"),
        "explicacion": primero("explicacion"),
        "remediacion": primero("recomendacion", "remediacion"),
        "evidencia": primero("evidencia", "detalle", "motivos"),
        "owasp": primero("owasp"),
        "motor": primero("motor_sugerido", "motor"),
        "extra": extra,
    }


def guardar_scan(username: str, modulo: str, url: str, score=None, nivel=None,
                 total_hallazgos: int = 0, detalle: str = "",
                 resumen: dict | None = None, hallazgos: list | None = None):
    """Inserta un scan y sus hallazgos. Devuelve el id del scan o None."""
    if not username:
        return None
    cli = get_client()
    if cli is None:
        loc = _local()
        if loc is None:
            return None
        filas = [_fila_hallazgo(None, h) for h in (hallazgos or []) if isinstance(h, dict)]
        return loc.guardar_scan(
            username=username, modulo=modulo, url=url, score=score, nivel=nivel,
            total_hallazgos=total_hallazgos, detalle=detalle, resumen=resumen,
            hallazgos=filas,
        )
    try:
        res = cli.table("scans").insert({
            "username": username.strip().lower(),
            "modulo": modulo,
            "url": url,
            "score": score,
            "nivel": nivel,
            "total_hallazgos": total_hallazgos,
            "detalle": detalle[:2000] if detalle else None,
            "resumen": resumen or {},
        }).execute()
        scan_id = res.data[0]["id"] if res.data else None

        if scan_id and hallazgos:
            filas = [_fila_hallazgo(scan_id, h) for h in hallazgos if isinstance(h, dict)]
            if filas:
                cli.table("scan_findings").insert(filas).execute()
        return scan_id
    except Exception:
        return None


def listar_scans(username: str, limite: int = 10) -> list:
    if not username:
        return []
    cli = get_client()
    if cli is None:
        loc = _local()
        return loc.listar_scans(username, limite) if loc else []
    try:
        res = (
            cli.table("scans")
            .select("id,modulo,url,score,nivel,total_hallazgos,created_at")
            .eq("username", username.strip().lower())
            .order("created_at", desc=True)
            .limit(limite)
            .execute()
        )
        return res.data or []
    except Exception:
        return []


def obtener_hallazgos(scan_id: str) -> list:
    if not scan_id:
        return []
    cli = get_client()
    if cli is None:
        loc = _local()
        return loc.obtener_hallazgos(scan_id) if loc else []
    try:
        res = (
            cli.table("scan_findings")
            .select("*").eq("scan_id", scan_id)
            .order("cvss", desc=True).execute()
        )
        return res.data or []
    except Exception:
        return []

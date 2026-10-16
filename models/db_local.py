"""Base de datos LOCAL (SQLite) para probar la app sin Supabase.

Se usa automáticamente cuando no hay `SUPABASE_URL` / `SUPABASE_KEY` en el
`.env`. Mantiene la misma API que `models/db.py` (usuarios e historial), de modo
que el resto de la app no cambia: si algún día se configura Supabase, la app
vuelve a usar PostgreSQL sin tocar nada.

El archivo se guarda en `data/vulnweb.db` (ignorado por git).
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

RUTA_DB = Path(__file__).resolve().parents[1] / "data" / "vulnweb.db"

_ESQUEMA = """
create table if not exists app_users (
    username      text primary key,
    display_name  text not null,
    password      text not null,
    salt          text not null,
    algo          text not null default 'pbkdf2_sha256',
    iteraciones   integer not null default 200000,
    last_login    text,
    created_at    text not null default (datetime('now'))
);

create table if not exists scans (
    id              integer primary key autoincrement,
    username        text not null,
    modulo          text not null,
    url             text not null,
    score           real,
    nivel           text,
    total_hallazgos integer not null default 0,
    detalle         text,
    resumen         text not null default '{}',
    created_at      text not null default (datetime('now'))
);

create index if not exists scans_user_idx on scans (username, created_at desc);

create table if not exists scan_findings (
    id          integer primary key autoincrement,
    scan_id     integer not null,
    tipo        text,
    parametro   text,
    metodo      text,
    severidad   text,
    cvss        real,
    confianza   real,
    descripcion text,
    explicacion text,
    remediacion text,
    evidencia   text,
    owasp       text,
    motor       text,
    extra       text not null default '{}',
    foreign key (scan_id) references scans (id) on delete cascade
);

create index if not exists scan_findings_scan_idx on scan_findings (scan_id, cvss desc);
"""


def ruta() -> Path:
    return RUTA_DB


def _conexion() -> sqlite3.Connection:
    RUTA_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(RUTA_DB, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.executescript(_ESQUEMA)
    return con


def disponible() -> bool:
    """Siempre True: el archivo local se crea bajo demanda."""
    return True


# ------------------------------------------------------------------ usuarios
def obtener_usuario(username: str):
    if not username:
        return None
    with _conexion() as con:
        fila = con.execute(
            "select username, display_name, password, salt, algo, iteraciones "
            "from app_users where username = ?",
            (username.strip().lower(),),
        ).fetchone()
    return dict(fila) if fila else None


def crear_usuario(username: str, password_hash: str, salt: str,
                  iteraciones: int = 200_000, algo: str = "pbkdf2_sha256"):
    clave = (username or "").strip().lower()
    if not clave:
        return False, "Falta el nombre de usuario."
    try:
        with _conexion() as con:
            con.execute(
                "insert into app_users (username, display_name, password, salt, algo, iteraciones) "
                "values (?, ?, ?, ?, ?, ?)",
                (clave, username.strip(), password_hash, salt, algo, iteraciones),
            )
        return True, ""
    except sqlite3.IntegrityError:
        return False, "El usuario ya existe."
    except Exception as e:  # pragma: no cover - fallo de disco/permisos
        return False, f"No se pudo crear el usuario: {str(e)[:160]}"


def actualizar_credenciales(username: str, password_hash: str, salt: str,
                            iteraciones: int = 200_000, algo: str = "pbkdf2_sha256"):
    with _conexion() as con:
        con.execute(
            "update app_users set password = ?, salt = ?, algo = ?, iteraciones = ? "
            "where username = ?",
            (password_hash, salt, algo, iteraciones, (username or "").strip().lower()),
        )


def registrar_login(username: str):
    with _conexion() as con:
        con.execute(
            "update app_users set last_login = ? where username = ?",
            (datetime.now(timezone.utc).isoformat(), (username or "").strip().lower()),
        )


# ------------------------------------------------------------------ escaneos
def guardar_scan(username: str, modulo: str, url: str, score=None, nivel=None,
                 total_hallazgos: int = 0, detalle: str = "",
                 resumen: dict | None = None, hallazgos: list | None = None) -> int | None:
    if not username:
        return None
    try:
        with _conexion() as con:
            cur = con.execute(
                "insert into scans (username, modulo, url, score, nivel, total_hallazgos, "
                "detalle, resumen) values (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    username.strip().lower(), modulo, url, score, nivel,
                    total_hallazgos, (detalle or "")[:2000] or None,
                    json.dumps(resumen or {}, ensure_ascii=False),
                ),
            )
            scan_id = cur.lastrowid
            filas = [f for f in (hallazgos or []) if isinstance(f, dict)]
            if scan_id and filas:
                con.executemany(
                    "insert into scan_findings (scan_id, tipo, parametro, metodo, severidad, "
                    "cvss, confianza, descripcion, explicacion, remediacion, evidencia, "
                    "owasp, motor, extra) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            scan_id, f.get("tipo"), f.get("parametro"), f.get("metodo"),
                            f.get("severidad"), f.get("cvss"), f.get("confianza"),
                            f.get("descripcion"), f.get("explicacion"), f.get("remediacion"),
                            f.get("evidencia"), f.get("owasp"), f.get("motor"),
                            json.dumps(f.get("extra") or {}, ensure_ascii=False),
                        )
                        for f in filas
                    ],
                )
        return scan_id
    except Exception:
        return None


def listar_scans(username: str, limite: int = 10) -> list:
    if not username:
        return []
    try:
        with _conexion() as con:
            filas = con.execute(
                "select id, modulo, url, score, nivel, total_hallazgos, created_at "
                "from scans where username = ? order by created_at desc, id desc limit ?",
                (username.strip().lower(), limite),
            ).fetchall()
        return [dict(f) for f in filas]
    except Exception:
        return []


def obtener_hallazgos(scan_id, limite: int = 200) -> list:
    try:
        with _conexion() as con:
            filas = con.execute(
                "select * from scan_findings where scan_id = ? order by cvss desc limit ?",
                (scan_id, limite),
            ).fetchall()
        return [dict(f) for f in filas]
    except Exception:
        return []

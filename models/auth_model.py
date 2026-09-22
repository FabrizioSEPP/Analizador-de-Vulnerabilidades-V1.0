import hashlib
import hmac
import secrets

import streamlit as st

from models import db

PBKDF2_ITERATIONS = 200_000
MIN_USERNAME = 3
MIN_PASSWORD = 8

SIN_BD = ("Base de datos no configurada. Define SUPABASE_URL y SUPABASE_KEY "
          "en el archivo .env.")


# ------------------------------------------------------------------ hashing
def _hash_pbkdf2(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    ).hex()


def _hash_legacy(password: str, salt: str) -> str:
    """Esquema antiguo (SHA-256 + salt); solo para cuentas migradas."""
    return hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()


def _hash(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    return _hash_pbkdf2(password, salt), salt


def _verificar(password: str, salt: str, guardado: str, algo: str) -> bool:
    if algo == "pbkdf2_sha256":
        return hmac.compare_digest(_hash_pbkdf2(password, salt), guardado)
    return hmac.compare_digest(_hash_legacy(password, salt), guardado)


def _validar(username: str, password: str) -> str:
    if not username or not password:
        return "Usuario y contraseña son obligatorios."
    if len(username) < MIN_USERNAME:
        return f"El usuario debe tener al menos {MIN_USERNAME} caracteres."
    if len(password) < MIN_PASSWORD:
        return f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres."
    return ""


# ------------------------------------------------------------------ registro
def register(username: str, password: str) -> tuple:
    error = _validar(username, password)
    if error:
        return False, error
    if not db.esta_configurado():
        return False, SIN_BD
    if db.obtener_usuario(username):
        return False, "El usuario ya existe."

    hashed, salt = _hash(password)
    ok, msg = db.crear_usuario(username, hashed, salt, PBKDF2_ITERATIONS)
    return (True, "Registro exitoso. Ahora inicia sesión.") if ok else (False, msg)


# --------------------------------------------------------------------- login
def login(username: str, password: str) -> tuple:
    if not username or not password:
        return False, "Usuario y contraseña son obligatorios."
    if not db.esta_configurado():
        return False, SIN_BD

    user = db.obtener_usuario(username)
    if not user:
        return False, "Usuario o contraseña incorrectos."

    salt = user.get("salt", "")
    guardado = user.get("password", "")
    algo = user.get("algo", "sha256")
    if not _verificar(password, salt, guardado, algo):
        return False, "Usuario o contraseña incorrectos."

    # Cuentas antiguas (SHA-256) se reapuntan a PBKDF2 al iniciar sesión.
    if algo != "pbkdf2_sha256":
        nuevo_hash, nueva_salt = _hash(password)
        db.actualizar_credenciales(username, nuevo_hash, nueva_salt, PBKDF2_ITERATIONS)

    db.registrar_login(username)
    return True, f"Bienvenido, {user.get('display_name') or username}."


# ------------------------------------------------------------------- sesión
def is_authenticated() -> bool:
    return st.session_state.get("logged_in", False)


def logout() -> None:
    st.session_state.clear()
    st.rerun()


def get_current_user() -> str:
    return st.session_state.get("current_user", "")

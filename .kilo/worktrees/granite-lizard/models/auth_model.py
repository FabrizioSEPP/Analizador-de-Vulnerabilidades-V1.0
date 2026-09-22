import hashlib
import hmac
import json
import os
import secrets
import streamlit as st

USERS_FILE = "users.json"

PBKDF2_ITERATIONS = 200_000
MIN_USERNAME = 3
MIN_PASSWORD = 8


def _hash_pbkdf2(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    ).hex()


def _hash_legacy(password: str, salt: str) -> str:
    """Esquema antiguo (SHA-256 + salt); solo para migrar usuarios existentes."""
    return hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()


def _hash(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    return _hash_pbkdf2(password, salt), salt


def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_users(users: dict) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def register(username: str, password: str) -> tuple:
    if not username or not password:
        return False, "Usuario y contraseña son obligatorios."
    if len(username) < MIN_USERNAME:
        return False, f"El usuario debe tener al menos {MIN_USERNAME} caracteres."
    if len(password) < MIN_PASSWORD:
        return False, f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres."
    users = _load_users()
    clave = username.lower()
    if clave in users:
        return False, "El usuario ya existe."
    hashed, salt = _hash(password)
    users[clave] = {
        "username": username,
        "password": hashed,
        "salt": salt,
        "algo": "pbkdf2_sha256",
        "iteraciones": PBKDF2_ITERATIONS,
    }
    _save_users(users)
    return True, "Registro exitoso. Ahora inicia sesión."


def login(username: str, password: str) -> tuple:
    if not username or not password:
        return False, "Usuario y contraseña son obligatorios."
    users = _load_users()
    clave = username.lower()
    user = users.get(clave)
    if not user:
        return False, "Usuario o contraseña incorrectos."

    salt = user.get("salt", "")
    guardado = user.get("password", "")

    if user.get("algo") == "pbkdf2_sha256":
        valido = hmac.compare_digest(_hash_pbkdf2(password, salt), guardado)
    else:
        # Usuario con el esquema antiguo: si la contraseña es correcta se
        # reapunta a PBKDF2 sin que el usuario tenga que hacer nada.
        valido = hmac.compare_digest(_hash_legacy(password, salt), guardado)
        if valido:
            nuevo_hash, nueva_salt = _hash(password)
            user.update({
                "password": nuevo_hash, "salt": nueva_salt,
                "algo": "pbkdf2_sha256", "iteraciones": PBKDF2_ITERATIONS,
            })
            users[clave] = user
            _save_users(users)

    if not valido:
        return False, "Usuario o contraseña incorrectos."
    return True, f"Bienvenido, {user['username']}."


def is_authenticated() -> bool:
    return st.session_state.get("logged_in", False)


def logout() -> None:
    st.session_state.clear()
    st.rerun()


def get_current_user() -> str:
    return st.session_state.get("current_user", "")

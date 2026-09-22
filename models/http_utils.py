import ipaddress
import socket
import threading
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

_local = threading.local()


def _get_session() -> requests.Session:
    """Devuelve una sesión por hilo. La sesión global compartida por los 50
    hilos del módulo de carga podía saturar el pool de conexiones."""
    session = getattr(_local, "session", None)
    if session is None:
        session = requests.Session()
        _local.session = session
    return session


def es_objetivo_privado(host: str) -> bool:
    """True si el host resuelve a loopback/red privada/reservada (riesgo SSRF)."""
    if not host:
        return True
    host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, ValueError):
            return False  # no resoluble: se deja pasar y fallará en la petición
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified or ip.is_multicast
    )


def normalizar_url(url: str) -> str:
    """Acepta cualquier entrada: 'ejemplo.com', 'host:8080/x', 'http://...'.

    Si no trae esquema se asume http:// (los servicios internos suelen ser HTTP).
    """
    url = (url or "").strip()
    if url and "://" not in url:
        url = "http://" + url
    return url


def validar_url(url: str, permitir_privadas: bool = False) -> tuple[bool, str]:
    if not url or not url.strip():
        return False, "La URL no puede estar vacía."

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False, "La URL debe usar http o https."

    if not parsed.netloc:
        return False, "La URL no contiene un dominio válido."

    if not permitir_privadas and es_objetivo_privado(parsed.hostname or ""):
        return False, (
            "La URL apunta a una dirección interna o privada (posible SSRF). "
            "Activa 'Permitir red interna' en la barra lateral si es un objetivo de laboratorio."
        )

    return True, ""


def extraer_parametros(url: str) -> dict:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] if v else "" for k, v in qs.items()}


def construir_url(url: str, param: str, valor: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [valor]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def construir_url_params(url: str, params: dict) -> str:
    """Fusiona un diccionario de parámetros en la query de la URL."""
    if not params:
        return url
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for clave, valor in params.items():
        qs[clave] = [valor]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def hacer_peticion(
    url: str,
    params: dict | None = None,
    timeout: int = 8,
    method: str = "GET",
    data: dict | None = None,
) -> tuple[requests.Response | None, float, str]:
    try:
        start = time.perf_counter()
        metodo = (method or "GET").upper()
        response = _get_session().request(
            metodo, url, params=params, data=data, timeout=timeout, allow_redirects=True
        )
        elapsed = time.perf_counter() - start
        return response, elapsed, ""
    except requests.exceptions.Timeout:
        return None, timeout, "Timeout: la solicitud tardó demasiado."
    except requests.exceptions.ConnectionError:
        return None, 0, "Error de conexión: no se pudo conectar al servidor."
    except requests.exceptions.RequestException as e:
        return None, 0, f"Error de solicitud: {e}"

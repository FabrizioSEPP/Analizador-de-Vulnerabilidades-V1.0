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

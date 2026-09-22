import os
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

ACORTADORES = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
               "is.gd", "buff.ly", "adf.ly", "tiny.cc", "lnkd.in"]

SOSPECHOSAS = ["login", "verify", "secure", "account", "update", "banking",
               "confirm", "password", "signin", "suspend", "alert", "unusual"]

# Ruta absoluta: el modelo se encuentra aunque la app se ejecute desde otro CWD.
MODELO_RUTA = str(Path(__file__).resolve().parents[1] / "modelo" / "modelo_rf.pkl")

_COLUMNS = [
    "longitud_url", "longitud_dominio", "usa_ip", "subdominios",
    "https", "guiones_dominio", "caracteres_especiales", "acortadores",
    "palabras_sospechosas", "numeros_url", "parametros", "slashes",
    "signos_puntuacion", "longitud_ruta", "fragmentos", "arroba",
    "iguales", "numeros_dominio", "clase",
]

_IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_ESPECIALES_RE = re.compile(r"[@_\-\.]")
_DIGITO_RE = re.compile(r"\d")
_SIGNOS_RE = re.compile(r"[?!]")


def _extraer_caracteristicas(url: str) -> list:
    parsed = urlparse(url)
    dominio = parsed.hostname or ""
    ruta = parsed.path or ""
    features = []
    features.append(len(url))
    features.append(len(dominio))
    features.append(1 if _IP_RE.match(dominio) else 0)
    features.append(max(0, len(dominio.split(".")) - 2) if dominio else 0)
    features.append(1 if parsed.scheme == "https" else 0)
    features.append(dominio.count("-"))
    features.append(len(_ESPECIALES_RE.findall(url)))
    features.append(1 if any(a in dominio for a in ACORTADORES) else 0)
    features.append(sum(1 for p in SOSPECHOSAS if p in url.lower()))
    features.append(len(_DIGITO_RE.findall(url)))
    features.append(url.count("?"))
    features.append(url.count("/"))
    features.append(len(_SIGNOS_RE.findall(url)))
    features.append(len(ruta))
    features.append(url.count("#"))
    features.append(1 if "@" in url else 0)
    features.append(url.count("="))
    features.append(1 if _DIGITO_RE.search(dominio) else 0)
    return features


def cargar_modelo() -> object:
    if os.path.exists(MODELO_RUTA):
        return joblib.load(MODELO_RUTA)
    return None


def entrenar_modelo() -> object:
    urls_legitimas = [
        "https://www.google.com", "https://www.github.com", "https://www.python.org",
        "https://www.wikipedia.org", "https://www.stackoverflow.com", "https://www.youtube.com",
        "https://www.amazon.com", "https://www.microsoft.com", "https://www.apple.com",
        "https://www.netflix.com", "https://www.spotify.com", "https://www.twitter.com",
        "https://www.facebook.com", "https://www.instagram.com", "https://www.linkedin.com",
        "https://www.reddit.com", "https://www.medium.com", "https://www.heroku.com",
        "https://www.digitalocean.com", "https://www.cloudflare.com",
    ]
    urls_phishing = [
        "http://192.168.1.1/login/verify-account.php", "http://bit.ly/2xKd93l",
        "http://secure-banking-login.com/update", "http://account-verify.xyz/signin",
        "http://10.0.0.1/admin/confirm.php?id=123", "http://login-secure.net/banking/password",
        "http://tinyurl.com/abc123xyz", "http://www.goog1e.com.suspicious-site.com/login",
        "http://alert-unusual-activity.com/verify", "http://suspend-account-now.com/confirm",
        "http://www.paypa1-secure.com/update", "http://signin-verify-account.net/banking",
        "http://192.168.0.100/admin/login.php", "http://secure-login-verify.com/password",
        "http://account-update-alert.xyz/confirm", "http://www.amazon-update-verify.com/login",
        "http://banking-secure-confirm.net/signin", "http://10.10.10.10/verify/account.php",
        "http://www.microsoft-secure.com/update", "http://login-alert-verify.com/banking",
    ]
    datos = []
    for url in urls_legitimas:
        datos.append(_extraer_caracteristicas(url) + [0])
    for url in urls_phishing:
        datos.append(_extraer_caracteristicas(url) + [1])
    df = pd.DataFrame(datos, columns=_COLUMNS)
    X = df.drop("clase", axis=1)
    y = df["clase"]
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    modelo = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    modelo.fit(X_train, y_train)
    precision = accuracy_score(y_test, modelo.predict(X_test))
    print(f"Precision del modelo phishing: {precision * 100:.2f}%")
    os.makedirs(os.path.dirname(MODELO_RUTA), exist_ok=True)
    joblib.dump(modelo, MODELO_RUTA)
    return modelo


def detectar_phishing(url: str) -> dict:
    modelo = cargar_modelo()
    if modelo is None:
        try:
            modelo = entrenar_modelo()
        except Exception:
            return {"resultado": "ERROR", "score_riesgo": 0, "confianza": 0,
                    "mensaje": "Modelo ML no disponible"}

    caracteristicas = _extraer_caracteristicas(url)
    # DataFrame con los mismos nombres de columna que se usaron al entrenar.
    entrada = pd.DataFrame([caracteristicas], columns=_COLUMNS[:-1])
    prediccion = int(modelo.predict(entrada)[0])
    probabilidades = modelo.predict_proba(entrada)[0]
    if len(probabilidades) > 1:
        score = round(float(probabilidades[1]) * 100, 2)
    else:
        score = 100.0 if prediccion == 1 else 0.0
    confianza = round(float(max(probabilidades)) * 100, 2)
    return {
        "url": url,
        "resultado": "PHISHING" if prediccion == 1 else "LEGITIMA",
        "score_riesgo": score,
        "confianza": confianza,
        "caracteristicas_clave": {
            "usa_ip": bool(caracteristicas[2]), "acortador": bool(caracteristicas[7]),
            "palabras_sospechosas": caracteristicas[8],
        },
    }

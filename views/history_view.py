"""Historial de análisis persistido en Supabase (barra lateral)."""

import streamlit as st

from models import history

_MODULO_LABEL = {
    "sqli": "🔍 Inyección SQL",
    "load": "⚡ Carga",
    "audit": "🛡️ Auditoría",
    "port": "🔌 Puertos",
}


def mostrar_historial(username: str):
    if not username:
        return
    try:
        items = history.recientes(username, limite=12)
    except Exception:
        items = []
    if not items:
        return

    with st.expander(f"🕘 Historial reciente ({len(items)})", expanded=False):
        for it in items:
            fecha = str(it.get("created_at", ""))[:16].replace("T", " ")
            modulo = _MODULO_LABEL.get(it.get("modulo", ""), it.get("modulo", ""))
            score = it.get("score")
            score_txt = f" · {score}" if score not in (None, "") else ""
            st.markdown(f"**{modulo}**{score_txt}")
            st.caption(f"{fecha} · {it.get('url', '')} · {it.get('total_hallazgos', 0)} hallazgo(s)")

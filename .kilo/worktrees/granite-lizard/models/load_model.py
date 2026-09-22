import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from models.http_utils import hacer_peticion


MAX_CONCURRENCIA = 50
DURACION_MAXIMA_POR_NIVEL = 8
NIVELES_CONCURRENCIA = [1, 2, 3, 5, 8, 10, 15, 20, 25, 30, 40, 50]
PORCENTILES = [50, 90, 95, 99]


class LoadModel:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    def analizar(self, url: str, callback=None) -> dict:
        total_niveles = len(NIVELES_CONCURRENCIA)
        niveles_resultado = []
        detenido_por_degradacion = False
        capacidad_estimada = 0
        ultimo_nivel_estable = 0

        if callback:
            callback(0.05, "Midiendo latencia base...")

        response_base, tiempo_base, error_base = hacer_peticion(url, timeout=self.timeout)

        if error_base or response_base is None:
            if callback:
                callback(1.0, "Error en la medición inicial")
            return {
                "url": url, "niveles": [], "capacidad_estimada": 0,
                "detenido_por_degradacion": False,
                "detalle": f"No se pudo conectar a la URL: {error_base}",
            }

        latencia_base = tiempo_base

        for i, concurrencia in enumerate(NIVELES_CONCURRENCIA):
            progreso = (i + 0.5) / (total_niveles + 1)
            if callback:
                callback(progreso, f"Nivel {i+1}/{total_niveles}: concurrencia={concurrencia}")

            resultados = self._ejecutar_nivel(url, concurrencia)

            total_peticiones = resultados["total"]
            errores = resultados["errores"]
            tasa_error = (errores / total_peticiones * 100) if total_peticiones > 0 else 100.0
            tiempos = resultados["tiempos"]
            latencia_promedio = sum(tiempos) / len(tiempos) if tiempos else 0

            percentiles = {}
            if tiempos:
                tiempos_ordenados = sorted(tiempos)
                for p in PORCENTILES:
                    idx = max(0, int(len(tiempos_ordenados) * p / 100) - 1)
                    percentiles[f"p{p}"] = round(tiempos_ordenados[idx], 4)

            nivel_info = {
                "concurrencia": concurrencia, "peticiones_totales": total_peticiones,
                "errores": errores, "tasa_error": round(tasa_error, 2),
                "latencia_promedio": round(latencia_promedio, 4),
                "latencia_base": round(latencia_base, 4),
                "latencia_p50": percentiles.get("p50", 0),
                "latencia_p90": percentiles.get("p90", 0),
                "latencia_p95": percentiles.get("p95", 0),
                "latencia_p99": percentiles.get("p99", 0),
            }

            errores_categorizados = resultados.get("errores_categorizados", {})
            if errores_categorizados:
                nivel_info["errores_timeout"] = errores_categorizados.get("timeout", 0)
                nivel_info["errores_conexion"] = errores_categorizados.get("connection", 0)
                nivel_info["errores_4xx"] = errores_categorizados.get("4xx", 0)
                nivel_info["errores_5xx"] = errores_categorizados.get("5xx", 0)
                nivel_info["errores_otros"] = errores_categorizados.get("other", 0)

            niveles_resultado.append(nivel_info)

            degradado_error = tasa_error > 10.0
            degradado_latencia = latencia_promedio > latencia_base * 3
            degradado_p95 = percentiles.get("p95", 0) > latencia_base * 4 if percentiles else False

            if total_peticiones >= 5:
                cv = (statistics.stdev(tiempos) / latencia_promedio) if latencia_promedio > 0 else 0
                degradado_volatilidad = cv > 1.0
            else:
                degradado_volatilidad = False

            if degradado_error or degradado_latencia or degradado_p95 or degradado_volatilidad:
                detenido_por_degradacion = True
                capacidad_estimada = ultimo_nivel_estable
                razon = []
                if degradado_error:
                    razon.append(f"tasa de error {round(tasa_error, 2)}% > 10%")
                if degradado_latencia:
                    razon.append(f"latencia {round(latencia_promedio, 4)}s > 3x base ({round(latencia_base, 4)}s)")
                if degradado_p95:
                    razon.append(f"p95 {percentiles.get('p95', 0)}s > 4x base ({round(latencia_base, 4)}s)")
                if degradado_volatilidad:
                    razon.append(f"volatilidad (CV) {round(cv, 2)} > 1.0")
                detalle = (
                    f"Se detectó degradación en concurrencia {concurrencia}: "
                    f"({' y '.join(razon)}). "
                    f"Capacidad estable estimada: {capacidad_estimada} peticiones simultáneas."
                )
                break
            else:
                ultimo_nivel_estable = concurrencia
                capacidad_estimada = concurrencia

        if not detenido_por_degradacion:
            detalle = (
                f"El sistema soportó todas las pruebas hasta {MAX_CONCURRENCIA} "
                f"peticiones simultáneas sin degradación. "
                f"La capacidad real podría estar por encima del techo de la herramienta."
            )

        if callback:
            callback(1.0, "Prueba de carga completada")

        return {
            "url": url, "niveles": niveles_resultado, "capacidad_estimada": capacidad_estimada,
            "detenido_por_degradacion": detenido_por_degradacion,
            "latencia_base": round(latencia_base, 4), "detalle": detalle,
        }

    def _clasificar_error(self, error_msg: str) -> str:
        error_lower = error_msg.lower()
        if "timeout" in error_lower or "tiempo" in error_lower or "expir" in error_lower:
            return "timeout"
        if "conexion" in error_lower or "connection" in error_lower or "no se pudo" in error_lower:
            return "connection"
        return "other"

    def _ejecutar_nivel(self, url: str, concurrencia: int) -> dict:
        resultados = {
            "total": 0, "errores": 0, "tiempo_total": 0.0, "tiempos": [],
            "errores_categorizados": {"timeout": 0, "connection": 0, "4xx": 0, "5xx": 0, "other": 0},
        }
        inicio = time.perf_counter()
        max_futures = concurrencia * max(DURACION_MAXIMA_POR_NIVEL, 4)

        with ThreadPoolExecutor(max_workers=concurrencia) as executor:
            futures = []
            while time.perf_counter() - inicio < DURACION_MAXIMA_POR_NIVEL and len(futures) < max_futures:
                futures.append(executor.submit(self._peticion_con_timing, url))
                time.sleep(random.uniform(0.001, 0.005))

            for future in as_completed(futures):
                self._registrar_resultado(resultados, future.result())

        return resultados

    def _peticion_con_timing(self, url: str) -> dict:
        start = time.perf_counter()
        response, _, error = hacer_peticion(url, None, self.timeout)
        return {"response": response, "tiempo": time.perf_counter() - start, "error": error}

    def _registrar_resultado(self, resultados: dict, resultado: dict):
        resultados["total"] += 1
        resultados["tiempo_total"] += resultado["tiempo"]
        resultados["tiempos"].append(resultado["tiempo"])

        if resultado["error"]:
            resultados["errores"] += 1
            categoria = self._clasificar_error(resultado["error"])
            resultados["errores_categorizados"][categoria] = resultados["errores_categorizados"].get(categoria, 0) + 1
            return

        if resultado["response"] is None:
            resultados["errores"] += 1
            resultados["errores_categorizados"]["connection"] = resultados["errores_categorizados"].get("connection", 0) + 1
            return

        status = resultado["response"].status_code
        if status >= 500:
            resultados["errores"] += 1
            resultados["errores_categorizados"]["5xx"] = resultados["errores_categorizados"].get("5xx", 0) + 1
        elif status >= 400:
            resultados["errores"] += 1
            resultados["errores_categorizados"]["4xx"] = resultados["errores_categorizados"].get("4xx", 0) + 1

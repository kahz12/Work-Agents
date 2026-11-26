from typing import Any, Dict, List, Optional

# {where} es "Línea N" o, si se conoce el archivo, "ruta/archivo.py:N".
_PRINCIPLE_TEMPLATES = {
    "OCP": "[DISEÑO OCP - {where}] Sustituye cadenas if/elif extensas por el patrón Estrategia (Strategy Pattern) o Polimorfismo.",
    "SRP": "[DISEÑO SRP - {where}] Divide la clase monolítica aplicando el principio de Responsabilidad Única.",
    "DIP": "[DISEÑO DIP - {where}] Inyecta las dependencias a través del constructor en lugar de instanciarlas internamente.",
    "GUARD": "[ARQUITECTURA - FAIL FAST - {where}] {msg}",
    "EXCEPTION-HYGIENE": "[FIABILIDAD - EXCEPCIONES - {where}] {msg}",
    "STATE-SAFETY": "[ESTADO Y PUREZA - {where}] {msg}",
    "DATA-CONTRACT": "[CONTRATO DE DATOS - {where}] {msg}",
}

# Solo es cierto si nada de lo analizado tiene recomendaciones.
EXCELLENT = (
    "[EXCELENTE] El código analizado cumple con métricas óptimas de mantenibilidad, "
    "fiabilidad, rendimiento y principios SOLID."
)


class RefactorSuggester:
    """
    Motor de recomendaciones de refactorización para mejorar mantenibilidad,
    fiabilidad arquitectónica y rendimiento Big-O / memoria / I/O.
    """

    @staticmethod
    def generate_recommendations(
        metrics: Dict[str, Any],
        solid_findings: List[Any],
        *,
        praise_if_clean: bool = True,
        location: Optional[str] = None,
    ) -> List[str]:
        """
        Sintetiza métricas, hallazgos SOLID/fiabilidad y hallazgos de rendimiento
        en recomendaciones concretas de refactorización.

        Sin recomendaciones devuelve EXCELLENT, salvo con praise_if_clean=False: quien combina
        varias llamadas (un análisis archivo por archivo) decide al final si el elogio procede.

        location es el archivo al que pertenecen métricas y hallazgos. Con él, cada recomendación
        dice dónde aplicarla ("app.py:12" en vez de "Línea 12"), lo que hace falta al juntar las
        de varios archivos. Sin él se conserva el formato por línea.
        """
        recs: List[str] = []
        scope = f" - {location}" if location else ""

        def where(line: Any) -> str:
            return f"{location}:{line}" if location else f"Línea {line}"

        # Evaluar la complejidad ciclomática media respecto al umbral estándar de testabilidad unitaria (5.0).
        avg_cc = metrics.get("avg_cyclomatic_complexity", 1.0)
        if avg_cc > 5.0:
            recs.append(
                f"[REFACTOR{scope}] La complejidad ciclomática promedio es alta ({avg_cc}). "
                "Aplica la técnica 'Extraer Método' (Extract Method) para descomponer funciones complejas."
            )

        # Evaluar la complejidad cognitiva media considerando la penalización acumulada por anidamiento profundo.
        avg_cog = metrics.get("avg_cognitive_complexity", 0.0)
        if avg_cog > 10.0:
            recs.append(
                f"[ARQUITECTURA - FAIL FAST{scope}] La complejidad cognitiva promedio es elevada ({avg_cog}). "
                "Reduce el anidamiento aplicando Cláusulas de Guarda (Guard Clauses) y descomposición funcional."
            )

        # Verificar densidad mínima de documentación en módulos con tamaño no trivial (> 50 líneas efectivas).
        comment_ratio = metrics.get("comment_ratio", 0.0)
        if comment_ratio < 5.0 and metrics.get("code_loc", 0) > 50:
            recs.append(
                f"[DOCUMENTACION{scope}] El ratio de documentación es inferior al 5%. "
                "Agrega docstrings a funciones y módulos principales para facilitar el mantenimiento futuro."
            )

        # Traducir cada hallazgo arquitectónico SOLID en una recomendación accionable según su categoría.
        for item in solid_findings:
            if len(item) == 4:
                line, principle, _, msg = item
                template = _PRINCIPLE_TEMPLATES.get(principle)
                if template:
                    recs.append(template.format(where=where(line), msg=msg))

        # Incorporar las alertas de eficiencia algorítmica, consumo de memoria y bloqueo del bucle asíncrono.
        for item in metrics.get("performance_findings", []):
            if len(item) == 4:
                line, category, level, msg = item
                if level == "ERROR":
                    continue
                recs.append(f"[{category} - {where(line)}] {msg}")

        if not recs and praise_if_clean:
            recs.append(EXCELLENT)

        return recs

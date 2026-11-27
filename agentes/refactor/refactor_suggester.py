from typing import Any, Dict, List, Optional

# One template per SOLID/reliability principle. {where} is "Line N" or, when the file is
# known, "path/to/file.py:N"; {msg} is the auditor's own message.
_PRINCIPLE_TEMPLATES = {
    "OCP": "[DESIGN OCP - {where}] Replace long if/elif chains with the Strategy pattern or polymorphism.",
    "SRP": "[DESIGN SRP - {where}] Split the monolithic class following the Single Responsibility Principle.",
    "DIP": "[DESIGN DIP - {where}] Inject dependencies through the constructor instead of instantiating them inside it.",
    "GUARD": "[ARCHITECTURE - FAIL FAST - {where}] {msg}",
    "EXCEPTION-HYGIENE": "[RELIABILITY - EXCEPTIONS - {where}] {msg}",
    "STATE-SAFETY": "[STATE AND PURITY - {where}] {msg}",
    "DATA-CONTRACT": "[DATA CONTRACT - {where}] {msg}",
}

# Only true when nothing analysed produced a recommendation; callers decide when that holds.
EXCELLENT = (
    "[EXCELLENT] The analysed code meets every maintainability, reliability, performance "
    "and SOLID threshold."
)


class RefactorSuggester:
    """
    Turns metrics and audit findings into concrete refactoring recommendations covering
    maintainability, reliability and Big-O / memory / I/O performance.
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
        Combine metrics, SOLID/reliability findings and performance findings into concrete
        refactoring recommendations.

        With nothing to recommend it returns [EXCELLENT], unless praise_if_clean=False: a caller
        that combines several calls (a file-by-file analysis) decides at the end whether the
        praise is deserved.

        location is the file the metrics and findings belong to. With it, each recommendation
        says where to apply it ("app.py:12" instead of "Line 12"), which matters once
        recommendations from several files are merged. Without it, the per-line form is kept.
        """
        recs: List[str] = []
        scope = f" - {location}" if location else ""

        def where(line: Any) -> str:
            return f"{location}:{line}" if location else f"Line {line}"

        # Average cyclomatic complexity above 5: functions with that many paths get hard to unit test.
        avg_cc = metrics.get("avg_cyclomatic_complexity", 1.0)
        if avg_cc > 5.0:
            recs.append(
                f"[REFACTOR{scope}] The average cyclomatic complexity is high ({avg_cc}). "
                "Use Extract Method to break complex functions down."
            )

        # Average cognitive complexity above 10: nesting makes the code hard to follow.
        avg_cog = metrics.get("avg_cognitive_complexity", 0.0)
        if avg_cog > 10.0:
            recs.append(
                f"[ARCHITECTURE - FAIL FAST{scope}] The average cognitive complexity is high ({avg_cog}). "
                "Reduce nesting with guard clauses and functional decomposition."
            )

        # Documentation density below 5%, only for modules big enough to matter (> 50 lines of code).
        comment_ratio = metrics.get("comment_ratio", 0.0)
        if comment_ratio < 5.0 and metrics.get("code_loc", 0) > 50:
            recs.append(
                f"[DOCUMENTATION{scope}] Less than 5% of the lines are documentation. "
                "Add docstrings to the main functions and modules to ease future maintenance."
            )

        # One actionable recommendation per SOLID/reliability finding, worded by principle.
        for item in solid_findings:
            if len(item) == 4:
                line, principle, _, msg = item
                template = _PRINCIPLE_TEMPLATES.get(principle)
                if template:
                    recs.append(template.format(where=where(line), msg=msg))

        # Performance findings (algorithmic cost, memory, blocking I/O) are passed through with their location.
        for item in metrics.get("performance_findings", []):
            if len(item) == 4:
                line, category, level, msg = item
                if level == "ERROR":
                    continue
                recs.append(f"[{category} - {where(line)}] {msg}")

        if not recs and praise_if_clean:
            recs.append(EXCELLENT)

        return recs

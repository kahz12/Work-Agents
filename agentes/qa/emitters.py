"""
Emisores de suites de pruebas unittest y pytest adversarias.

Cada objetivo (función, método o propiedad) se describe con un TargetSpec construido a partir del
plan de llamada de call_plan: qué argumentos pasar, cómo crear el objeto de un método, qué valores
son supuestos y qué no se sabe construir. Los emisores solo escriben los tests.
"""
from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

from .ast_inspector import NON_DET_CALLS, UnitTestGenerator, _regex_literal, accepts_none, validating_raises
from .call_plan import (
    KIND_SAMPLES,
    CallPlan,
    SampleContext,
    boundary_values,
    construction_assumed,
    import_header,
    instantiation_for,
    module_import,
    plan_call,
    receiver_for,
)
from .expected_values import Outcome, fallback_assertion, is_pure_binop, static_outcome, uses_nondeterminism
from .sample_values import first_invalid_argument

SOURCE_COMMENT = {
    "static": "Valor calculado a partir del cuerpo de la función.",
    "recorded": "Valor grabado al generar la suite: fija el comportamiento actual (test de caracterización).",
}
RAISES_COMMENT = {
    "static": "excepción deducida del cuerpo de la función con estos valores.",
    "recorded": "excepción grabada al generar la suite (test de caracterización).",
}
RECORDED_HEADER = [
    "# Los valores marcados como grabados se obtuvieron ejecutando el código al generar la suite.",
    "# Fijan el comportamiento actual: si hoy hay un fallo, el test lo da por bueno. Revísalos.",
]
# Lo que lanza Python cuando un valor de ejemplo supuesto no es del tipo que espera la función.
_MISFIT = "(TypeError, AttributeError)"
# Lo que lanza cuando procesa los datos de un doble de E/S (un MagicMock, un archivo vacío) como
# si fueran reales: json.loads(MagicMock) da TypeError; json.load de un archivo vacío, ValueError.
_FAKE_IO_MISFIT = "(TypeError, AttributeError, ValueError)"


class TargetSpec(NamedTuple):
    """
    Un objetivo de los tests. name identifica el objetivo en el nombre del test (func o
    Clase_metodo); call_target es lo que se llama (func, obj.metodo o Clase.metodo); setup, la
    expresión que crea obj, y setup_assumed, si se construye con valores supuestos; skip, por qué
    no se puede probar; access, "call" o "property" (se lee, no se llama).
    """

    name: str
    call_target: str
    label: str
    meta: Dict[str, Any]
    func_node: Optional[ast.AST]
    plan: CallPlan
    setup: Optional[str]
    setup_assumed: bool
    skip: Optional[str]
    access: str
    ctx: SampleContext

    @property
    def is_async(self) -> bool:
        """El objetivo es una corrutina: se llama con asyncio.run."""
        return bool(self.meta.get("is_async"))

    def call(self, args: Optional[str] = None) -> str:
        """Expresión que invoca el objetivo (con args, o con los del plan); las corrutinas, con asyncio.run."""
        if self.access == "property":
            return self.call_target
        expr = f"{self.call_target}({self.plan.arg_str if args is None else args})"
        return f"asyncio.run({expr})" if self.is_async else expr


_CLI_REASON = "Lee sys.argv o termina el proceso: pruébala por su línea de órdenes (subprocess o CliRunner)."
_ENDLESS_REASON = ("Entra en un bucle sin fin (while True sin break, return ni raise): pruébala con un "
                   "evento de parada o un número de vueltas.")


def _skip_reason(plan: CallPlan, meta: Dict[str, Any]) -> Optional[str]:
    """Por qué no se puede llamar al objetivo en un test unitario; None si se puede."""
    if meta.get("cli_entrypoint"):
        return _CLI_REASON
    if meta.get("endless_loop"):
        return _ENDLESS_REASON
    if not plan.missing:
        return None
    return f"Falta un valor de ejemplo para {', '.join(plan.missing)}: complétalo a mano."


def build_targets(visitor: UnitTestGenerator, ctx: SampleContext) -> List[TargetSpec]:
    """Un TargetSpec por función pública y por método o propiedad pública de cada clase pública."""
    specs: List[TargetSpec] = []
    for func_name, _, _ in visitor.functions:
        snapshot = ctx.snapshot()
        node = visitor.function_nodes.get(func_name)
        plan = plan_call(node, ctx)
        meta = visitor.function_meta.get(func_name, {})
        ctx.used_names.add(func_name)
        specs.append(TargetSpec(func_name, func_name, func_name, meta, node, plan, None, False,
                                _skip_reason(plan, meta), "call", ctx))
        _forget_if_skipped(specs[-1], ctx, snapshot)
    for cls_name, _, methods in visitor.classes:
        for m_name, _, _ in methods:
            snapshot = ctx.snapshot()
            key = f"{cls_name}.{m_name}"
            node = visitor.function_nodes.get(key)
            receiver = receiver_for(cls_name, m_name, ctx)
            plan = plan_call(node, ctx, skip_first=receiver.kind != "static")
            meta = visitor.function_meta.get(key, {})
            specs.append(TargetSpec(
                f"{cls_name}_{m_name}", receiver.target, key, meta, node, plan,
                receiver.setup, receiver.assumed, receiver.skip or _skip_reason(plan, meta),
                "property" if receiver.kind == "property" else "call", ctx,
            ))
            _forget_if_skipped(specs[-1], ctx, snapshot)
    return specs


def _forget_if_skipped(spec: TargetSpec, ctx: SampleContext,
                       snapshot: Tuple[Set[str], Set[str], Dict[str, Set[str]]]) -> None:
    """Un objetivo omitido no usa nada del módulo: lo que anotó al planificarlo no se importa."""
    if spec.skip:
        ctx.restore(snapshot)


def io_targets(io_calls: List[str]) -> List[str]:
    """Objetivos de patch para cada llamada de E/S detectada, sin repetir."""
    targets: List[str] = []
    for target in io_calls:
        if target and target not in targets:
            targets.append(target)
    return targets


def absorb_blocked(outcome: Optional[Outcome], targets: List[str]) -> Tuple[Optional[Outcome], List[str]]:
    """
    Al grabar, la función intentó escribir, borrar, lanzar un proceso o conectarse (quizá a
    través de otro módulo) y se bloqueó. No hay valor fiable que afirmar, pero el test debe
    sustituir esas llamadas para no hacerlas de verdad.
    """
    if outcome is None or outcome[0] != "blocked":
        return outcome, targets
    extra = [t for t in outcome[1].split(",") if t and t not in targets]
    return None, targets + extra


# Dobles de open(): un MagicMock devolvería otro MagicMock en read(), y el código que lee el
# archivo (un parser, un bucle de read()) no terminaría nunca. Se simula un archivo vacío.
_OPEN_TARGETS = frozenset({"builtins.open", "io.open"})


def patch_clause(targets: List[str], *, named: bool = False) -> str:
    """
    Construye la cláusula patch(...) de los dobles de E/S: autospec, o un archivo vacío para
    open(). Con named, cada doble queda en io_0, io_1...: para el test que comprueba si se llamó.
    """
    return ", ".join(
        (f'patch("{t}", new=mock_open(read_data=""))' if t in _OPEN_TARGETS else f'patch("{t}", autospec=True)')
        + (f" as io_{i}" if named else "")
        for i, t in enumerate(targets)
    )


def _uses_open_double(specs: List["TargetSpec"]) -> bool:
    return any(set(spec.meta.get("io_calls") or []) & _OPEN_TARGETS for spec in specs if not spec.skip)


def declared_raises(spec: TargetSpec, *, reachable: bool = False) -> List[Tuple[str, Optional[str]]]:
    """
    Las excepciones que lanza el objetivo y que la suite puede nombrar, con su mensaje; con
    reachable, también las de los helpers del módulo a los que llama. Las que define o importa el
    módulo se anotan para que la suite las importe.
    """
    raises = spec.meta.get("raises_reachable" if reachable else "raises") or spec.meta.get("raises") or []
    found = [(name, msg) for name, msg in raises if spec.ctx.exception_import(name) is not None]
    for name, _ in found:
        spec.ctx.use_exception(name)
    return found


class Rejection(NamedTuple):
    """
    Un test de entrada inválida: el argumento position recibe value y la función tiene que
    lanzar exceptions (un nombre o una tupla), con un mensaje que case con pattern si se conoce.
    """

    position: int
    value: str
    exceptions: str
    pattern: Optional[str]


def expected_rejection(spec: TargetSpec) -> Optional[Rejection]:
    """
    El test de entrada inválida, solo si la función valida el parámetro que recibe el valor hostil
    (un raise bajo un if que lo menciona, o un assert sobre él). Sin esa validación, exigir una
    excepción haría fallar el test con una función correcta: walk_files("../../etc/passwd")
    recorre una ruta relativa sin quejarse, y es lo que debe hacer.
    """
    invalid = first_invalid_argument(spec.plan.names)
    if invalid is None or spec.access == "property":
        return None
    index, value = invalid
    raises = [(name, msg) for name, msg in validating_raises(spec.func_node, spec.plan.names[index])
              if spec.ctx.exception_import(name) is not None]
    if not raises:
        return None
    names = list(dict.fromkeys(name for name, _ in raises))
    for name in names:
        spec.ctx.use_exception(name)
    # Un patrón solo si se conocen todos los mensajes y ninguno es vacío: cualquiera puede ser el que salte.
    messages = list(dict.fromkeys(msg for _, msg in raises if msg))
    pattern = None
    if len(messages) == 1 and all(msg for _, msg in raises):
        pattern = _regex_literal(messages[0])
    elif messages and all(msg for _, msg in raises):
        pattern = repr("|".join(re.escape(m) for m in messages))
    return Rejection(index, value, names[0] if len(names) == 1 else f"({', '.join(names)})", pattern)


def fallback_kind(spec: TargetSpec) -> Tuple[str, str]:
    """
    Qué se puede afirmar del valor sin conocerlo (fallback_assertion). Si algún argumento es la
    función de ejemplo, que devuelve None, lo que devuelve el objetivo puede ser lo que devuelva
    ella (interruptible(call) devuelve call()): el tipo anotado o que no sea None dejan de ser seguros.
    """
    kind, type_name = fallback_assertion(spec.func_node)  # type: ignore[arg-type]
    callable_sample = KIND_SAMPLES["callable"]
    if kind in ("isinstance", "not_none") and any(callable_sample in arg for arg in [*spec.plan.positional,
                                                                                      *spec.plan.keywords]):
        return "none", ""
    return kind, type_name


def io_assertion(spec: TargetSpec) -> str:
    """
    Qué se puede afirmar de un objetivo con la E/S sustituida y sin valor conocido: "called" si
    la hace en cualquier ejecución que acepte su entrada (se comprueba que delega en los dobles),
    "none" si nunca devuelve nada, y "" si nada es seguro (la E/S está en una rama, o el valor
    depende de los dobles).
    """
    if spec.meta.get("io_always"):
        return "called"
    if fallback_kind(spec)[0] == "is_none":
        return "none"
    return ""


def io_called_expr(targets: List[str]) -> str:
    """Expresión booleana que comprueba si se invocó alguno de los dobles de E/S."""
    return " or ".join(f"io_{i}.called" for i in range(len(targets)))


def recording_calls(visitor: UnitTestGenerator) -> Dict[str, str]:
    """Expresiones a grabar: funciones y métodos sin E/S ni resultados no deterministas."""
    calls: Dict[str, str] = {}
    for spec in build_targets(visitor, SampleContext(visitor.tree, visitor.project)):
        if spec.skip or spec.meta.get("io_calls") or uses_nondeterminism(spec.func_node, NON_DET_CALLS):  # type: ignore[arg-type]
            continue
        target = spec.call_target
        if spec.setup and target.startswith("obj."):
            target = f"({spec.setup}).{target[4:]}"
        calls[spec.name] = target if spec.access == "property" else f"{target}({spec.plan.arg_str})"
    return calls


def outcome_for(
    key: str,
    func_node: Optional[ast.AST],
    kept_args: List[str],
    samples: List[str],
    recorded: Optional[Dict[str, Outcome]],
) -> Tuple[Optional[Outcome], str]:
    """Determina el resultado esperado usando primero grabación y luego evaluación estática."""
    if recorded and key in recorded:
        return recorded[key], "recorded"
    outcome = static_outcome(func_node, kept_args, samples)  # type: ignore[arg-type]
    return (outcome, "static") if outcome else (None, "")


def _spec_outcome(spec: TargetSpec, recorded: Optional[Dict[str, Outcome]]) -> Tuple[Optional[Outcome], str]:
    """
    Resultado esperado del objetivo. Con valores supuestos, un TypeError o un AttributeError
    solo dice que el supuesto no encaja con la función, no cómo se comporta: no se afirma.
    """
    if spec.access == "property":
        outcome, source = (recorded[spec.name], "recorded") if recorded and spec.name in recorded else (None, "")
    else:
        outcome, source = outcome_for(spec.name, spec.func_node, spec.plan.static_names, spec.plan.static_values,
                                      recorded)
    if outcome is None or outcome[0] != "raises":
        return outcome, source
    if (spec.plan.assumed or spec.setup_assumed) and outcome[1] in ("TypeError", "AttributeError"):
        return None, ""
    return (outcome, source) if spec.ctx.use_exception(outcome[1]) else (None, "")


def is_float_literal(text: str) -> bool:
    """True si la expresión literal evaluada corresponde a un float."""
    try:
        return isinstance(ast.literal_eval(text), float)
    except (ValueError, SyntaxError):
        return False


# --- Bloques comunes a los dos emisores ----------------------------------------------------------

# Aislamiento de la suite: un test generado no sale a la red ni espera a la entrada estándar. Las
# llamadas de red que el análisis no ve (las hace otro módulo) fallan con OSError, como sin red,
# y quien lea la entrada estándar la encuentra vacía. Las conexiones locales siguen funcionando:
# en Windows, asyncio las usa para su bucle de eventos.
_ISOLATION_HELPERS = [
    '_QA_LOCAL_HOSTS = (None, "localhost", "127.0.0.1", "::1")',
    "_qa_real_connect = socket.socket.connect",
    "_qa_real_getaddrinfo = socket.getaddrinfo",
    "",
    "",
    "def _qa_local_connect(sock, address):",
    '    """Solo conexiones locales: un test generado no sale a la red."""',
    "    host = address[0] if isinstance(address, tuple) else None",
    "    if host not in _QA_LOCAL_HOSTS:",
    '        raise OSError(f"Red bloqueada en los tests generados: {address!r}")',
    "    return _qa_real_connect(sock, address)",
    "",
    "",
    "def _qa_local_getaddrinfo(host, *args, **kwargs):",
    '    """Solo nombres locales: sin red no se resuelve ningún otro."""',
    "    if host not in _QA_LOCAL_HOSTS:",
    '        raise socket.gaierror(f"Red bloqueada en los tests generados: {host!r}")',
    "    return _qa_real_getaddrinfo(host, *args, **kwargs)",
    "",
    "",
    "def _qa_empty_stdin():",
    "    return io.TextIOWrapper(io.BytesIO())",
    "",
    "",
    "# Segundos que puede durar cada test; 0 quita el límite.",
    "_QA_TIMEOUT = 10",
    "",
    "",
    "class _QaTimeout(BaseException):",
    '    """El test siguió corriendo tras omitirlo: se corta con algo que un except Exception no atrapa."""',
    "",
    "",
    "def _qa_time_limit(skip):",
    '    """',
    "    Arma el límite de tiempo del test y devuelve con qué desarmarlo. Al agotarse, skip omite el",
    "    test; si el código se traga esa excepción y sigue, a los dos segundos lo corta _QaTimeout.",
    "    Sin SIGALRM (Windows) o fuera del hilo principal no hay límite.",
    '    """',
    '    if not _QA_TIMEOUT or not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():',
    "        return lambda: None",
    "    fired = []",
    "",
    "    def _on_alarm(signum, frame):",
    "        fired.append(signum)",
    "        if len(fired) == 1:",
    '            skip(f"No terminó en {_QA_TIMEOUT} s con los valores de ejemplo: un bucle sin fin, una espera "',
    '                 "o una interfaz interactiva.")',
    '        raise _QaTimeout(f"No terminó en {_QA_TIMEOUT} s y el código se tragó la omisión.")',
    "",
    "    previous = signal.signal(signal.SIGALRM, _on_alarm)",
    "    signal.setitimer(signal.ITIMER_REAL, _QA_TIMEOUT, 2)",
    "",
    "    def disarm():",
    "        signal.setitimer(signal.ITIMER_REAL, 0)",
    "        signal.signal(signal.SIGALRM, previous)",
    "",
    "    return disarm",
]

def _setup_lines(spec: TargetSpec, ind: str, skip_call: str) -> List[str]:
    """Las líneas que crean obj. Si se construye con valores supuestos y no encajan, el test se omite."""
    if not spec.setup:
        return []
    if not spec.setup_assumed:
        return [f"{ind}obj = {spec.setup}"]
    return [
        f"{ind}# El objeto se crea con valores supuestos: si no encajan con la clase, el test se omite.",
        f"{ind}try:",
        f"{ind}    obj = {spec.setup}",
        f"{ind}except {_MISFIT} as exc:",
        f'{ind}    {skip_call}(f"No se pudo crear el objeto con valores supuestos: {{exc}}")',
    ]


def _call_lines(spec: TargetSpec, ind: str, statement: str, skip_call: str, fake_io: bool = False) -> List[str]:
    """
    La sentencia que llama al objetivo (result = f(...)). Si usa valores supuestos que no encajan
    con la función, o si con fake_io procesa los datos de los dobles de E/S y no le sirven, el
    test se omite: eso no dice nada de cómo se comporta con datos reales.
    """
    if fake_io:
        return [
            f"{ind}# Los dobles de E/S devuelven datos simulados: si la función no puede procesarlos, el test se omite.",
            f"{ind}try:",
            f"{ind}    {statement}",
            f"{ind}except {_FAKE_IO_MISFIT} as exc:",
            f'{ind}    {skip_call}(f"Los valores de ejemplo o los datos simulados de la E/S no encajan: {{exc}}")',
        ]
    if not spec.plan.assumed:
        return [f"{ind}{statement}"]
    names = ", ".join(spec.plan.assumed)
    return [
        f"{ind}# Valores de ejemplo supuestos para {names}: si no encajan con la función, el test se omite.",
        f"{ind}try:",
        f"{ind}    {statement}",
        f"{ind}except {_MISFIT} as exc:",
        f'{ind}    {skip_call}(f"Los valores supuestos para {names} no encajan con la función: {{exc}}")',
    ]


def _with_doubles(targets: List[str]) -> str:
    """
    Los dobles de E/S como primeros gestores de una sentencia with, o nada si no hay E/S. Todo
    test que llama al objetivo los necesita: si no, la llamada haría la E/S de verdad.
    """
    return f"{patch_clause(targets)}, " if targets else ""


def _with_arg(plan: CallPlan, index: int, expr: str) -> str:
    """Los argumentos del plan con el posicional index sustituido por expr."""
    positional = list(plan.positional)
    positional[index] = expr
    return ", ".join([*positional, *plan.keywords])


# ---------------------------------------------------------------------------
# Emisor unittest
# ---------------------------------------------------------------------------

def _emit_unittest_fallback_assert(test_code: List[str], ind: str, spec: TargetSpec) -> None:
    kind, type_name = fallback_kind(spec)
    if kind == "isinstance":
        test_code.append(f"{ind}self.assertIsInstance(result, {type_name})")
    elif kind == "is_none":
        test_code.append(f"{ind}self.assertIsNone(result)")
    elif kind == "not_none":
        test_code.append(f"{ind}self.assertIsNotNone(result)")
        test_code.append(f"{ind}# Valor exacto desconocido: fíjalo a mano o genera la suite con --record.")
    else:
        test_code.append(f"{ind}# Valor desconocido: este test solo comprueba que no hay excepción.")
        test_code.append(f"{ind}# Fíjalo a mano o genera la suite con --record.")
        test_code.append(f"{ind}_ = result")


def _emit_unittest_result_asserts(
    test_code: List[str],
    ind: str,
    resolved: Tuple[Optional[Outcome], str, List[str], TargetSpec],
) -> None:
    outcome, source, targets, spec = resolved
    if outcome is not None and outcome[0] == "value":
        test_code.append(f"{ind}# {SOURCE_COMMENT[source]}")
        if outcome[1] == "None":
            test_code.append(f"{ind}self.assertIsNone(result)")
            return
        method = "assertAlmostEqual" if is_float_literal(outcome[1]) else "assertEqual"
        test_code.append(f"{ind}self.{method}(result, {outcome[1]})")
        return
    if outcome is not None and outcome[0] == "type":
        test_code.append(f"{ind}# {SOURCE_COMMENT[source]}")
        test_code.append(f'{ind}self.assertEqual(type(result).__name__, "{outcome[1]}")')
        return
    if targets:
        expected = io_assertion(spec)
        if expected == "called":
            test_code.append(f"{ind}self.assertTrue({io_called_expr(targets)}, \"no usa la E/S sustituida\")")
        elif expected == "none":
            test_code.append(f"{ind}self.assertIsNone(result)")
        else:
            test_code.append(f"{ind}# Con la E/S sustituida el valor depende de los dobles: basta con que no falle.")
        return
    _emit_unittest_fallback_assert(test_code, ind, spec)


def _emit_unittest_skipped(test_code: List[str], name: str, label: str, reason: str) -> None:
    test_code.append(f"    def test_{name}_happy_path(self):")
    test_code.append(f'        """{label}: no se puede probar sin completarlo a mano."""')
    test_code.append(f"        self.skipTest({reason!r})")
    test_code.append("")


def _emit_unittest_happy_path(
    test_code: List[str],
    spec: TargetSpec,
    resolved: Tuple[Optional[Outcome], str, List[str]],
) -> None:
    outcome, source, targets = resolved
    raises_outcome = outcome is not None and outcome[0] == "raises"

    name = f"test_{spec.name}_sample_input_raises" if raises_outcome else f"test_{spec.name}_happy_path"
    test_code.append(f"    def {name}(self):")
    test_code.append(f'        """{spec.label} con valores de ejemplo."""')
    test_code.append("        # Arrange")
    test_code.extend(_setup_lines(spec, "        ", "self.skipTest"))
    ind = "        "
    expected = io_assertion(spec) if targets and outcome is None else ""
    if targets:
        test_code.append(f"        # E/S sustituida por dobles: {', '.join(targets)}")
        test_code.append(f"        with {patch_clause(targets, named=expected == 'called')}:")
        ind = "            "
    if raises_outcome and outcome is not None:
        test_code.append(f"{ind}# Act & Assert: {RAISES_COMMENT[source]}")
        if outcome[2]:
            test_code.append(f"{ind}with self.assertRaisesRegex({outcome[1]}, {_regex_literal(outcome[2])}):")
        else:
            test_code.append(f"{ind}with self.assertRaises({outcome[1]}):")
        test_code.append(f"{ind}    {spec.call()}")
    else:
        test_code.append(f"{ind}# Act")
        fake_io = bool(targets) and outcome is None
        statement = f"result = {spec.call()}" if not fake_io or expected == "none" else spec.call()
        test_code.extend(_call_lines(spec, ind, statement, "self.skipTest", fake_io))
        test_code.append(f"{ind}# Assert")
        _emit_unittest_result_asserts(test_code, ind, (outcome, source, targets, spec))
    test_code.append("")


def _emit_unittest_invalid_input(test_code: List[str], spec: TargetSpec, targets: List[str]) -> None:
    rejection = expected_rejection(spec)
    if rejection is None:
        return
    test_code.append(f"    def test_{spec.name}_invalid_input(self):")
    test_code.append(f'        """Entrada inválida para {spec.label}: la función la valida y la rechaza."""')
    test_code.append("        # Arrange")
    test_code.extend(_setup_lines(spec, "        ", "self.skipTest"))
    test_code.append("        # Act & Assert")
    doubles = _with_doubles(targets)
    if rejection.pattern:
        test_code.append(f"        with {doubles}self.assertRaisesRegex({rejection.exceptions}, {rejection.pattern}):")
    else:
        test_code.append(f"        with {doubles}self.assertRaises({rejection.exceptions}):")
    test_code.append(f"            {spec.call(_with_arg(spec.plan, rejection.position, rejection.value))}")
    test_code.append("")


def emit_unittest_call_tests(test_code: List[str], spec: TargetSpec, recorded: Optional[Dict[str, Outcome]] = None) -> None:
    """Emite los métodos de prueba unittest (happy path e invalid input) para un objetivo."""
    if spec.skip:
        _emit_unittest_skipped(test_code, spec.name, spec.label, spec.skip)
        return
    outcome, source = _spec_outcome(spec, recorded)
    outcome, targets = absorb_blocked(outcome, io_targets(spec.meta.get("io_calls") or []))
    _emit_unittest_happy_path(test_code, spec, (outcome, source, targets))
    _emit_unittest_invalid_input(test_code, spec, targets)


def _emit_unittest_instantiation(test_code: List[str], cls_name: str, ctx: SampleContext) -> None:
    expr, skip = instantiation_for(cls_name, ctx)
    if expr is None:
        _emit_unittest_skipped(test_code, f"{cls_name}_instantiation", cls_name, skip or "")
        return
    test_code.append(f"    def test_{cls_name}_instantiation(self):")
    test_code.append(f'        """Instanciación básica de {cls_name}."""')
    if construction_assumed(cls_name, ctx):
        test_code.extend([
            "        try:",
            f"            obj = {expr}",
            f"        except {_MISFIT} as exc:",
            '            self.skipTest(f"No se pudo crear el objeto con valores supuestos: {exc}")',
        ])
    else:
        test_code.append(f"        obj = {expr}")
    test_code.append(f"        self.assertIsInstance(obj, {cls_name})")
    test_code.append("")


def render_unittest_suite(
    source_filepath: str,
    output_test_filepath: str,
    visitor: UnitTestGenerator,
    recorded: Dict[str, Outcome],
) -> str:
    """Renderiza el archivo completo de una suite unittest."""
    ctx = SampleContext(visitor.tree, visitor.project)
    specs = build_targets(visitor, ctx)
    dotted, _ = module_import(source_filepath)
    module_name = dotted.rsplit(".", 1)[-1]
    class_name = "".join(part.capitalize() for part in module_name.replace("-", "_").split("_"))
    body = [
        f"class Test{class_name}QA(unittest.TestCase):",
        "    def setUp(self):",
        '        """Sin red, con la entrada estándar vacía y con un límite de tiempo: ningún test se queda esperando."""',
        '        for target, new in (("socket.socket.connect", _qa_local_connect),',
        '                            ("socket.getaddrinfo", _qa_local_getaddrinfo), ("sys.stdin", _qa_empty_stdin())):',
        "            patcher = patch(target, new)",
        "            patcher.start()",
        "            self.addCleanup(patcher.stop)",
        "        self.addCleanup(_qa_time_limit(self.skipTest))",
        "",
        "    def tearDown(self):",
        "        pass",
        "",
    ]
    for spec in specs:
        emit_unittest_call_tests(body, spec, recorded=recorded)
    for cls_name, _, methods in visitor.classes:
        if not methods:
            _emit_unittest_instantiation(body, cls_name, ctx)
    if not visitor.functions and not visitor.classes:
        body.append("    def test_module_importable(self):")
        body.append('        """El módulo se importa correctamente."""')
        body.append("        self.assertIsNotNone(True)")
        body.append("")
    body.append("if __name__ == '__main__':")
    body.append("    unittest.main()")

    header = ["import io", "import signal", "import socket", "import threading", "import unittest"]
    if any(spec.is_async for spec in specs if not spec.skip):
        header.append("import asyncio")
    header.append("from unittest.mock import mock_open, patch" if _uses_open_double(specs)
                  else "from unittest.mock import patch")
    if recorded:
        header.extend(RECORDED_HEADER)
    header.extend(import_header(source_filepath, output_test_filepath, ctx.used_names, ctx.used_modules,
                                ctx.foreign_imports))
    return "\n".join([*header, "", "", *_ISOLATION_HELPERS, "", "", *body])


# ---------------------------------------------------------------------------
# Emisor pytest
# ---------------------------------------------------------------------------

class _PytestCase(NamedTuple):
    """Lo que comparten todos los tests pytest de un objetivo: su descripción, su resultado y su E/S."""

    spec: TargetSpec
    outcome: Optional[Outcome]
    source: str
    io_targets: List[str]

    @property
    def safe_id(self) -> str:
        """El nombre del objetivo como parte de un identificador de test."""
        return self.spec.name.replace(".", "_")

    @property
    def func_node(self) -> Optional[ast.AST]:
        """El nodo de la función o el método, para analizar su cuerpo."""
        return self.spec.func_node


def build_pytest_case(spec: TargetSpec, recorded: Optional[Dict[str, Outcome]]) -> _PytestCase:
    """Prepara el caso normalizado a partir del cual se emiten las pruebas pytest."""
    outcome, source = _spec_outcome(spec, recorded)
    outcome, targets = absorb_blocked(outcome, io_targets(spec.meta.get("io_calls", [])))
    return _PytestCase(spec, outcome, source, targets)


def _value_assertion(value: str) -> str:
    if value in ("None", "True", "False"):
        return f"assert result is {value}"
    if is_float_literal(value):
        return f"assert result == pytest.approx({value})"
    return f"assert result == {value}"


def _fallback_assertion_line(spec: TargetSpec) -> str:
    kind, type_name = fallback_kind(spec)
    if kind == "isinstance":
        return f"assert isinstance(result, {type_name})"
    if kind == "is_none":
        return "assert result is None"
    if kind == "not_none":
        return "assert result is not None"
    return "_ = result  # sin aserción de valor: solo se comprueba que no hay excepción"


def _nominal_assertion(case: _PytestCase) -> List[str]:
    """Comentario y aserción del caso nominal, de la fuente más fiable disponible."""
    outcome = case.outcome
    if outcome is not None and outcome[0] == "value":
        return [f"# Assert: {SOURCE_COMMENT[case.source]}", _value_assertion(outcome[1])]
    if outcome is not None and outcome[0] == "type":
        return [f"# Assert: {SOURCE_COMMENT[case.source]}", f'assert type(result).__name__ == "{outcome[1]}"']
    if case.io_targets:
        expected = io_assertion(case.spec)
        if expected == "called":
            return ["# Assert: la función delega en la E/S sustituida", f"assert {io_called_expr(case.io_targets)}"]
        if expected == "none":
            return ["# Assert: la función no devuelve nada", "assert result is None"]
        return ["# Assert: con la E/S sustituida el valor depende de los dobles; basta con que no falle", "_ = result"]
    if case.spec.access == "property":
        return ["# Assert: la propiedad se puede leer (fija su valor a mano o usa --record)", "_ = result"]
    return [
        "# Assert: solo lo verificable sin conocer el valor (fíjalo a mano o usa --record)",
        _fallback_assertion_line(case.spec),
    ]


def _emit_pytest_skipped(lines: List[str], name: str, reason: str) -> None:
    lines.extend([
        f"def test_{name}_happy_path() -> None:",
        f"    pytest.skip({reason!r})",
        "",
    ])


def _emit_pytest_nominal(lines: List[str], case: _PytestCase) -> None:
    """Caso nominal: el valor esperado se calcula del cuerpo o se graba; nunca se adivina por el nombre."""
    spec = case.spec
    raises_outcome = case.outcome is not None and case.outcome[0] == "raises"
    test_name = f"test_{case.safe_id}_sample_input_raises" if raises_outcome else f"test_{case.safe_id}_happy_path"
    lines.append(f"def {test_name}(qa_workspace) -> None:")
    lines.append("    # Arrange: inicializar entorno aislado y argumentos nominales de entrada")
    lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
    lines.append("    _ = qa_workspace")
    ind = "    "
    # Si se comprueba que delega en los dobles, el valor no se mira: sin result = no queda una
    # variable sin usar (F841) en la suite.
    named = bool(case.io_targets) and case.outcome is None and io_assertion(spec) == "called"
    if case.io_targets:
        lines.append(f"    # E/S sustituida por dobles: {', '.join(case.io_targets)}")
        lines.append(f"    with {patch_clause(case.io_targets, named=named)}:")
        ind = "        "
    if raises_outcome and case.outcome is not None:
        lines.append(f"{ind}# Act y Assert: {RAISES_COMMENT[case.source]}")
        match = _regex_literal(case.outcome[2]) if case.outcome[2] else 'r".*"'
        lines.append(f"{ind}with pytest.raises({case.outcome[1]}, match={match}):")
        lines.append(f"{ind}    {spec.call()}")
    else:
        lines.append(f"{ind}# Act: invocar la función objetivo con valores válidos")
        fake_io = bool(case.io_targets) and case.outcome is None
        statement = spec.call() if named else f"result = {spec.call()}"
        lines.extend(_call_lines(spec, ind, statement, "pytest.skip", fake_io))
        lines.extend(f"{ind}{line}" for line in _nominal_assertion(case))
    lines.append("")


def _boundary_body(case: _PytestCase, call: str, first_assumed: bool) -> List[str]:
    """
    Con un valor límite la función puede devolver algo o rechazarlo con una de las excepciones
    previstas: también un assert de validación, o un OSError cuando el valor es una ruta ("" no
    existe; 2.048 caracteres son un nombre demasiado largo). Solo se afirma sobre el valor lo que es seguro:
    None si nunca devuelve nada y not None si siempre termina devolviendo un valor. Si puede
    devolver None por algún camino, o si su E/S está sustituida, no se afirma nada sobre el valor:
    basta con que no lance otra excepción.
    """
    raises = declared_raises(case.spec, reachable=True)
    exc_tuple = ", ".join(sorted({name for name, _ in raises}
                                 | {"ArithmeticError", "AssertionError", "LookupError", "OSError", "TypeError",
                                    "ValueError"}))
    kind = fallback_kind(case.spec)[0]
    assign = ""
    if case.io_targets:
        value_check = ["    # La E/S está sustituida: el valor depende de los dobles y no se afirma."]
    elif kind == "none":
        value_check = ["    # Puede devolver None por algún camino: no se afirma nada sobre el valor."]
    else:
        assign = "res = "
        value_check = ["    assert res is None" if kind == "is_none" else "    assert res is not None"]
    # Un rechazo tiene que explicar el motivo, salvo las excepciones que la función lanza sin
    # mensaje (raise KeyError(), o un assert sin texto), cuyo texto es vacío.
    silent = sorted({name for name, msg in raises if msg == ""}
                    | ({"AssertionError"} if case.spec.meta.get("bare_assert") else set()))
    message_check = f"    assert str(exc) or isinstance(exc, ({', '.join(silent)},))" if silent else "    assert str(exc)"
    body = ["try:", f"    {assign}{call}", *value_check, f"except ({exc_tuple}) as exc:", message_check]
    if first_assumed:
        body.extend([
            "except AttributeError as exc:",
            '    pytest.skip(f"El valor límite no es del tipo que espera la función: {exc}")',
        ])
    return body


def _emit_pytest_boundary(lines: List[str], case: _PytestCase) -> None:
    """Valores frontera parametrizados del primer parámetro, según su clase de valor."""
    spec = case.spec
    if spec.access == "property" or spec.plan.first is None:
        return
    param, sample = spec.plan.first
    values = boundary_values(sample, param.arg)
    if param.arg in spec.meta.get("durations", []):
        # Una duración de 10**6 segundos dejaría el test esperando once días.
        values = [(b_id, value) for b_id, value in values if b_id != "large_num"]
    if not values:
        return
    rows = ", ".join(value for _, value in values)
    row_ids = ", ".join(f'"{b_id}"' for b_id, _ in values)
    lines.append(f'@pytest.mark.parametrize("boundary_value", [{rows}], ids=[{row_ids}])')
    lines.append(f"def test_{case.safe_id}_boundary_values(boundary_value) -> None:")
    lines.append(f"    # Arrange: asignar a {param.arg} los valores frontera provistos por pytest")
    lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
    lines.append("    # Act y Assert: comprobar respuesta coherente o rechazo tipado con detalle")
    call = spec.call(spec.plan.with_first("boundary_value"))
    # Los elementos de una lista o un dict sin tipo conocido son una suposición, como su valor.
    guessed = sample.assumed or param.arg in spec.plan.assumed or (sample.kind in ("list", "dict") and sample.item is None)
    body = _boundary_body(case, call, guessed)
    if case.io_targets:
        lines.append(f"    with {patch_clause(case.io_targets)}:")
        lines.extend(f"        {b}" for b in body)
    else:
        lines.extend(f"    {b}" for b in body)
    lines.append("")


def _emit_pytest_adversarial(lines: List[str], case: _PytestCase) -> None:
    """Escenarios hostiles: tipo de excepción exacto y mensaje con match, o None en el primer parámetro."""
    spec = case.spec
    if spec.access == "property" or spec.plan.first is None:
        return
    rejection = expected_rejection(spec)
    if rejection is not None:
        match_kw = f", match={rejection.pattern}" if rejection.pattern else ""
        lines.append(f"def test_{case.safe_id}_adversarial_raises_exact_error() -> None:")
        lines.append("    # Arrange: preparar argumento hostil que dispara la validación de dominio")
        lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
        lines.append("    # Act y Assert: exigir tipo exacto y mensaje esperado en pytest.raises")
        lines.append(f"    with {_with_doubles(case.io_targets)}pytest.raises({rejection.exceptions}{match_kw}):")
        lines.append(f"        {spec.call(_with_arg(spec.plan, rejection.position, rejection.value))}")
        lines.append("")
        return
    param, _ = spec.plan.first
    if param.arg not in spec.meta.get("none_unsafe", []) or accepts_none(param, None):
        return
    lines.append(f"def test_{case.safe_id}_adversarial_none_input() -> None:")
    lines.append(f"    # Arrange: sustituir {param.arg} por None (el cuerpo lo usa sin comprobarlo)")
    lines.extend(_setup_lines(spec, "    ", "pytest.skip"))
    lines.append("    # Act y Assert: exigir excepción explícita ante referencia nula")
    exceptions = ", ".join(_none_input_exceptions(case))
    lines.append(f"    with {_with_doubles(case.io_targets)}pytest.raises(({exceptions}), match={_none_input_match(case)}):")
    lines.append(f"        {spec.call(spec.plan.with_first('None'))}")
    lines.append("")


# Lo que suele lanzar Python al operar con None donde se esperaba un valor, y el assert con el que
# una función valida su entrada.
_NONE_INPUT_EXCEPTIONS = ("TypeError", "ValueError", "AttributeError", "KeyError", "ZeroDivisionError",
                          "AssertionError")


def _none_input_exceptions(case: _PytestCase) -> List[str]:
    """Las excepciones que la función lanza de forma explícita y, después, las que lanza Python con None."""
    declared = sorted({name for name, _ in declared_raises(case.spec, reachable=True)} - set(_NONE_INPUT_EXCEPTIONS))
    return [*declared, *_NONE_INPUT_EXCEPTIONS]


def _none_input_match(case: _PytestCase) -> str:
    """Se exige un mensaje, salvo si la función lanza alguna excepción sin él (raise KeyError(), assert x)."""
    silent = any(msg == "" for _, msg in case.spec.meta.get("raises_reachable") or case.spec.meta.get("raises") or [])
    return 'r".*"' if silent or case.spec.meta.get("bare_assert") else 'r".+"'


def _emit_pytest_property(lines: List[str], case: _PytestCase) -> None:
    spec = case.spec
    lines.extend([
        "if _HAS_HYPOTHESIS:",
        "    @given(st.integers(min_value=-10000, max_value=10000), st.integers(min_value=-10000, max_value=10000))",
        f"    def test_{case.safe_id}_property_integers(x_val: int, y_val: int) -> None:",
        "        # Arrange & Act: evaluar invariante sobre enteros generados aleatoriamente",
        *_setup_lines(spec, "        ", "pytest.skip"),
        f"        res = {spec.call('x_val, y_val')}",
        "        # Assert: el resultado sigue siendo numérico (int o float)",
        "        assert isinstance(res, (int, float))",
        "",
    ])


def _emit_pytest_async(lines: List[str], case: _PytestCase) -> None:
    """Corrutinas: agotamiento de tiempo, cancelación cooperativa y ejecución concurrente."""
    spec = case.spec
    target, args = spec.call_target, spec.plan.arg_str
    setup = _setup_lines(spec, "    ", "pytest.skip") or ["    # Función a nivel de módulo: no requiere instanciación previa."]
    gather = [f"        batch = await asyncio.gather({target}({args}), {target}({args}))"]
    if spec.plan.assumed:
        gather = [
            "        try:",
            f"            batch = await asyncio.gather({target}({args}), {target}({args}))",
            f"        except {_MISFIT} as exc:",
            '            pytest.skip(f"Los valores supuestos no encajan con la función: {exc}")',
        ]
    lines.extend([
        f"def test_{case.safe_id}_async_timeout_cancellation_and_gather() -> None:",
        "    # Arrange: definir estado inicial para las pruebas del ciclo de vida asyncio",
        *setup,
        "    async def _slow_op(*_args, **_kwargs):",
        "        await asyncio.sleep(0.2)",
        f"        return await {target}({args})",
        "    async def _run_checks() -> None:",
        "        # Act y Assert: validar expiración de timeout mediante wait_for",
        "        with pytest.raises((TimeoutError, asyncio.TimeoutError)):",
        "            await asyncio.wait_for(_slow_op(), timeout=0.001)",
        "        # Act y Assert: validar propagación limpia de asyncio.CancelledError",
        f"        task = asyncio.create_task({target}({args}))",
        "        task.cancel()",
        "        try:",
        "            await task",
        "        except asyncio.CancelledError:",
        "            assert task.cancelled()",
        "        # Act y Assert: comprobar ejecución concurrente con asyncio.gather",
        *gather,
        "        assert len(batch) == 2",
        *([f"    with {patch_clause(case.io_targets)}:", "        asyncio.run(_run_checks())"] if case.io_targets
          else ["    asyncio.run(_run_checks())"]),
        "",
    ])


def _emit_pytest_io_fault(lines: List[str], case: _PytestCase) -> None:
    """
    E/S que falla: todas las llamadas con efectos se sustituyen y lanzan OSError. Si quedara
    alguna sin sustituir, el test la ejecutaría de verdad (un rmtree real, por ejemplo).
    """
    spec = case.spec
    faulty = ", ".join(
        f'patch("{t}", autospec=True, side_effect=OSError("io_fault")) as io_{i}'
        for i, t in enumerate(case.io_targets)
    )  # nombrados: el test comprueba si la función llegó a usarlos
    misfit = []
    if spec.plan.assumed:
        misfit = [
            f"        except {_MISFIT} as exc:",
            '            pytest.skip(f"Los valores supuestos no encajan con la función: {exc}")',
        ]
    lines.extend([
        f"def test_{case.safe_id}_isolated_io_fault() -> None:",
        "    # Arrange: dobles con autospec que simulan la indisponibilidad de la E/S",
        *(_setup_lines(spec, "    ", "pytest.skip") or ["    # Función a nivel de módulo: no requiere instanciación previa."]),
        f"    with {faulty}:",
        "        # Act y Assert: la función gestiona el fallo o lo propaga con un error tipado y descriptivo",
        "        try:",
        f"            {spec.call()}",
        "        except (OSError, RuntimeError, ValueError) as exc:",
        "            assert str(exc)",
        *misfit,
        f"        if not ({io_called_expr(case.io_targets)}):",
        '            pytest.skip("Con los valores de ejemplo la función no llega a la E/S sustituida.")',
        "",
    ])


def emit_pytest_function(lines: List[str], spec: TargetSpec, recorded: Optional[Dict[str, Outcome]] = None) -> None:
    """Emite todos los tests pytest (nominal, frontera, adversario, propiedades, async y E/S)."""
    if spec.skip:
        _emit_pytest_skipped(lines, spec.name.replace(".", "_"), spec.skip)
        return
    case = build_pytest_case(spec, recorded)
    _emit_pytest_nominal(lines, case)
    if spec.access == "property":
        return
    _emit_pytest_boundary(lines, case)
    _emit_pytest_adversarial(lines, case)
    names = spec.plan.names
    if case.outcome is not None and case.outcome[0] == "value" and not spec.plan.keywords \
            and is_pure_binop(case.func_node, names):  # type: ignore[arg-type]
        _emit_pytest_property(lines, case)
    if spec.is_async:
        _emit_pytest_async(lines, case)
    if case.io_targets:
        _emit_pytest_io_fault(lines, case)


def _emit_pytest_instantiation(lines: List[str], cls_name: str, ctx: SampleContext) -> None:
    expr, skip = instantiation_for(cls_name, ctx)
    if expr is None:
        _emit_pytest_skipped(lines, f"{cls_name}_instantiation", skip or "")
        return
    setup = [f"    obj = {expr}"]
    if construction_assumed(cls_name, ctx):
        setup = [
            "    try:",
            f"        obj = {expr}",
            f"    except {_MISFIT} as exc:",
            '        pytest.skip(f"No se pudo crear el objeto con valores supuestos: {exc}")',
        ]
    lines.extend([
        f"def test_{cls_name}_instantiation(qa_workspace) -> None:",
        "    # Arrange",
        "    _ = qa_workspace",
        "    # Act",
        *setup,
        "    # Assert",
        f"    assert isinstance(obj, {cls_name})",
        "",
    ])


def render_pytest_suite(
    source_filepath: str,
    output_test_filepath: str,
    visitor: UnitTestGenerator,
    recorded: Dict[str, Outcome],
) -> str:
    """Renderiza el archivo completo de una suite pytest adversaria."""
    ctx = SampleContext(visitor.tree, visitor.project)
    specs = build_targets(visitor, ctx)
    dotted, _ = module_import(source_filepath)
    body: List[str] = [
        "@pytest.fixture(autouse=True)",
        "def _qa_isolation(monkeypatch):",
        '    """Sin red, con la entrada estándar vacía y con un límite de tiempo: ningún test se queda esperando."""',
        '    monkeypatch.setattr(socket.socket, "connect", _qa_local_connect)',
        '    monkeypatch.setattr(socket, "getaddrinfo", _qa_local_getaddrinfo)',
        '    monkeypatch.setattr(sys, "stdin", _qa_empty_stdin())',
        "    disarm = _qa_time_limit(pytest.skip)",
        "    yield",
        "    disarm()",
        "",
        "",
        "@pytest.fixture",
        "def qa_workspace(tmp_path, monkeypatch):",
        '    """Fixture modular con setup/teardown (yield) y aislamiento de entorno."""',
        '    monkeypatch.setenv("QA_TEST_MODE", "1")',
        "    sandbox = tmp_path / 'qa_sandbox'",
        "    sandbox.mkdir(exist_ok=True)",
        "    yield {'sandbox': sandbox, 'monkeypatch': monkeypatch}",
        "    _ = (MagicMock, AsyncMock)  # Referencia disponible para extensibilidad segura con spec",
        "",
        "",
    ]
    for spec in specs:
        emit_pytest_function(body, spec, recorded=recorded)
    for cls_name, _, methods in visitor.classes:
        if not methods:
            _emit_pytest_instantiation(body, cls_name, ctx)
    if not visitor.functions and not visitor.classes:
        body.extend([
            "def test_module_importable(qa_workspace) -> None:",
            "    # Arrange",
            "    assert qa_workspace['sandbox'].is_dir()",
            "    # Act & Assert",
            "    spec = MagicMock(spec=dict)",
            "    assert spec is not None",
            "",
        ])

    text = "\n".join(body)
    hypothesis = [
        "try:",
        "    from hypothesis import given, strategies as st",
        "    _HAS_HYPOTHESIS = True",
        "except ImportError:",
        "    _HAS_HYPOTHESIS = False",
        "",
    ] if "_HAS_HYPOTHESIS" in text else []
    header = [
        f'"""Suite de pruebas pytest adversaria generada para {dotted}."""',
        *(["import asyncio"] if "asyncio." in text else []),
        "import io",
        "import signal",
        "import socket",
        "import threading",
        "from unittest.mock import " + ", ".join(
            ["AsyncMock", "MagicMock", *(["mock_open"] if _uses_open_double(specs) else []),
             *(["patch"] if "patch(" in text else [])]),
        "import pytest",
        "",
        *hypothesis,
        *(RECORDED_HEADER if recorded else []),
        *import_header(source_filepath, output_test_filepath, ctx.used_names, ctx.used_modules, ctx.foreign_imports),
        "",
        "",
        *_ISOLATION_HELPERS,
        "",
        "",
    ]
    return "\n".join([*header, *body])


def write_suite(source_filepath: str, output_test_filepath: str, *, framework: str, record: bool) -> str:
    """Visita la fuente y escribe la suite unittest o pytest en output_test_filepath."""
    from .ast_inspector import read_and_parse
    from .expected_values import record_outcomes

    try:
        tree = read_and_parse(source_filepath)
    except (FileNotFoundError, IsADirectoryError, SyntaxError, UnicodeDecodeError, OSError):
        return ""
    visitor = UnitTestGenerator(source_filepath)
    visitor.visit(tree)
    recorded = record_outcomes(source_filepath, recording_calls(visitor)) if record else {}
    render = render_pytest_suite if framework == "pytest" else render_unittest_suite
    content = render(source_filepath, output_test_filepath, visitor, recorded)
    os.makedirs(os.path.dirname(os.path.abspath(output_test_filepath)), exist_ok=True)
    with open(output_test_filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return output_test_filepath

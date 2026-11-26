"""
Piezas internas del agente qa: el intérprete que calcula los resultados esperados, la
grabación, las reglas de calidad de suites, los valores de muestra y la fachada del generador.

El intérprete se prueba contra Python: para cada caso, el resultado estático tiene que ser el
mismo que da ejecutar la función, y en lo que no sabe evaluar tiene que rendirse (None) en vez
de inventar un valor que el test generado afirmaría.
"""
import ast
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.qa import expected_values as ev  # noqa: E402
from agentes.qa import sample_values as sv  # noqa: E402
from agentes.qa.test_generator import QATestGenerator  # noqa: E402
from agentes.qa.test_runner import QATestRunner  # noqa: E402


def _func(src: str) -> ast.FunctionDef:
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def _arg_names(func: ast.FunctionDef):
    return [a.arg for a in func.args.args]


def _real_outcome(src: str, samples):
    """Lo que da ejecutar la función de verdad, con la misma forma que static_outcome."""
    namespace: dict = {}
    exec(compile(src, "<caso>", "exec"), namespace)  # agentes: ignore[dynamic-exec] - código fijo del propio test
    args = [ast.literal_eval(s) for s in samples]
    try:
        value = namespace["f"](*args)
    except Exception as exc:  # noqa: BLE001 - el tipo de la excepción es justo lo que se compara
        return ("raises", type(exc).__name__, str(exc))
    return ("value", repr(value), "")


# --- Intérprete estático ------------------------------------------------------------------

EVALUABLES = {
    "subíndice": ("def f(x):\n    return x[1]", ["[1, 2, 3]"]),
    "slice": ("def f(x):\n    return x[1:3]", ["[1, 2, 3]"]),
    "slice con paso": ("def f(x):\n    return x[::-1]", ["'abc'"]),
    "tupla, lista y set": ("def f(x):\n    return (x, [x], {x})", ["1"]),
    "dict": ("def f(x):\n    return {'a': x, 'b': [x]}", ["1"]),
    "f-string con conversión y formato": ("def f(x):\n    return f'{x!r:>6}|{x}|{x!s}|{x!a}'", ["'ñ'"]),
    "asignación anotada, += y pass": ("def f(x):\n    y: int = x\n    y += 2\n    pass\n    return y", ["1"]),
    "and, or y not con cortocircuito": ("def f(x, y):\n    return x and y, x or y, not x, y and x", ["0", "3"]),
    "comparación encadenada": ("def f(x):\n    return 1 < x < 3, 5 < x < 10", ["2"]),
    "operadores unarios y potencias pequeñas": ("def f(x):\n    return -x, +x, ~x, x ** 3, x << 2", ["5"]),
    "builtins sin efectos": ("def f(x):\n    return len(x), abs(-3), min(x), sorted(x), round(2.5)", ["[4, 2]"]),
    "IndexError": ("def f(x):\n    return x[10]", ["[1]"]),
    "ZeroDivisionError": ("def f(x):\n    return 1 / x", ["0"]),
    "raise con mensaje": ("def f(x):\n    if x < 0:\n        raise ValueError('negativo')\n    return x", ["-1"]),
    "raise sin argumentos": ("def f(x):\n    raise KeyError()", ["1"]),
    "docstring y literal suelto": ('def f(x):\n    """Doc."""\n    "nota"\n    return x', ["7"]),
}


@pytest.mark.parametrize("src, samples", EVALUABLES.values(), ids=EVALUABLES.keys())
def test_el_interprete_da_lo_mismo_que_ejecutar(src, samples):
    func = _func(src)
    assert ev.static_outcome(func, _arg_names(func), samples) == _real_outcome(src, samples)


NO_EVALUABLES = {
    "potencia enorme": ("def f(x):\n    return x ** 100", ["2"]),
    "desplazamiento enorme": ("def f(x):\n    return x << 100", ["2"]),
    "operador @": ("def f(x):\n    return x @ x", ["2"]),
    "lista con *": ("def f(x):\n    return [*x]", ["[1]"]),
    "dict con **": ("def f(x):\n    return {**x}", ["{}"]),
    "llamada con *": ("def f(x):\n    return len(*x)", ["[[1]]"]),
    "atributo": ("def f(x):\n    return x.real", ["1"]),
    "comprensión": ("def f(x):\n    return [i for i in x]", ["[1]"]),
    "bucle": ("def f(x):\n    for i in x:\n        pass\n    return x", ["[1]"]),
    "nombre desconocido": ("def f(x):\n    return y", ["1"]),
    "builtin no permitido": ("def f(x):\n    return print(x)", ["1"]),
    "valor no literal": ("def f(x):\n    return float('inf')", ["1"]),
    "raise de una variable": ("def f(x):\n    e = ValueError('x')\n    raise e", ["1"]),
}


@pytest.mark.parametrize("src, samples", NO_EVALUABLES.values(), ids=NO_EVALUABLES.keys())
def test_el_interprete_se_rinde_en_lo_que_no_sabe_evaluar(src, samples):
    func = _func(src)
    assert ev.static_outcome(func, _arg_names(func), samples) is None


def test_static_outcome_sin_funcion_o_con_muestras_que_no_encajan():
    func = _func("def f(x, y):\n    return x + y")
    assert ev.static_outcome(None, [], []) is None
    assert ev.static_outcome(func, ["x", "y"], ["1"]) is None
    assert ev.static_outcome(func, ["x", "y"], ["1", "no es un literal("]) is None


@pytest.mark.parametrize("src", ["def f(x):\n    raise ValueError(x)", "def f(x):\n    raise ValueError"])
def test_raise_sin_un_mensaje_literal_lo_deja_sin_mensaje(src):
    """El tipo se conoce y el mensaje no se afirma: el test generado comprobará solo el tipo."""
    assert ev.static_outcome(_func(src), ["x"], ["5"]) == ("raises", "ValueError", None)


@pytest.mark.parametrize("valor, esperado", [
    (1, True), ([1, (2, "a")], True), ({"k": {1, 2}}, True), (None, True),
    (float("nan"), False), (float("inf"), False), (object(), False), ([object()], False),
])
def test_is_literal(valor, esperado):
    assert ev.is_literal(valor) is esperado


@pytest.mark.parametrize("src, esperado", [
    ("def f(x) -> None:\n    print(x)", ("is_none", "")),
    ("def f(x) -> int:\n    return g(x)", ("isinstance", "int")),
    ("def f(x):\n    yield x", ("none", "")),
    ("def f(x):\n    print(x)", ("is_none", "")),
    ("def f(x):\n    return None", ("is_none", "")),
    ("def f(x):\n    return g(x)", ("not_none", "")),
    ("def f(x):\n    if x:\n        return g(x)\n    print(x)", ("none", "")),
    ("def f(x):\n    def g():\n        return 1\n    print(g)", ("is_none", "")),
])
def test_fallback_assertion(src, esperado):
    assert ev.fallback_assertion(_func(src)) == esperado


def test_fallback_assertion_sin_funcion():
    assert ev.fallback_assertion(None) == ("none", "")


@pytest.mark.parametrize("src, esperado", [
    ("def f():\n    return random.choice([1, 2])", True),
    ("def f():\n    return secrets.token_hex()", True),
    ("def f():\n    return time.time()", True),
    ("def f():\n    return obtener()[0]", False),
    ("def f(x):\n    return x + 1", False),
])
def test_uses_nondeterminism(src, esperado):
    assert ev.uses_nondeterminism(_func(src), {"time.time"}) is esperado


def test_uses_nondeterminism_sin_funcion():
    assert ev.uses_nondeterminism(None, {"time.time"}) is False


# --- Grabación --------------------------------------------------------------------------------

def test_grabar_sin_llamadas_no_lanza_ningun_proceso(tmp_path):
    assert ev.record_outcomes(str(tmp_path / "no_existe.py"), {}) == {}


def test_grabar_un_modulo_que_termina_el_proceso(tmp_path):
    mod = tmp_path / "sale.py"
    mod.write_text("import os\nos._exit(3)\n\n\ndef f():\n    return 1\n", encoding="utf-8")
    with pytest.raises(ev.RecordingError, match="No se pudo grabar"):
        ev.record_outcomes(str(mod), {"f": "f()"})


def test_grabar_una_funcion_que_no_termina(tmp_path):
    mod = tmp_path / "eterno.py"
    mod.write_text("def f():\n    while True:\n        pass\n", encoding="utf-8")
    with pytest.raises(ev.RecordingError, match="superó 1 s"):
        ev.record_outcomes(str(mod), {"f": "f()"}, timeout=1)


# --- Calidad de suites --------------------------------------------------------------------------

SUITE = '''import unittest
from unittest import mock

import pytest


def test_tautologia():
    assert True


class T(unittest.TestCase):
    def test_assert_true(self):
        self.assertTrue(True)

    def test_raises_generico(self):
        with self.assertRaises(Exception):
            hacer()

    def test_raises_con_tupla_generica(self):
        with self.assertRaises((ValueError, BaseException)):
            hacer()

    def test_mock_sin_spec(self):
        doble = mock.MagicMock()
        doble.assert_not_called()

    def test_mock_con_spec(self):
        doble = mock.MagicMock(spec=dict)
        doble.assert_not_called()

    def test_patch_sin_autospec_de_un_privado(self):
        with mock.patch("modulo._interno"):
            self.assertEqual(1, 1 + 0)

    def test_patch_object_de_un_privado(self):
        with mock.patch.object(Clase, "_secreto", autospec=True):
            self.assertIsNotNone(Clase)


def test_omitido():
    pytest.skip("no aplica")


def test_falla_a_proposito():
    pytest.fail("pendiente")


def test_raises_de_timeout_sin_match():
    with pytest.raises((TimeoutError, asyncio.TimeoutError)):
        esperar()


def test_usa_monkeypatch(monkeypatch):
    monkeypatch.setattr("os.getcwd", lambda: "/")
    assert open("x").read()
'''


def test_calidad_de_suite_detecta_cada_antipatron(tmp_path):
    suite = tmp_path / "test_suite.py"
    suite.write_text(SUITE, encoding="utf-8")
    findings = QATestRunner.audit_test_suite_quality(str(suite))["findings"]
    by_rule = {}
    for line, rule, level, msg in findings:
        by_rule.setdefault(rule, []).append(msg)
    assert any("assertTrue(True)" in m for m in by_rule["WEAK-ASSERT"])
    assert any("assert True" in m for m in by_rule["WEAK-ASSERT"])
    generic = " ".join(by_rule["GENERIC-RAISES"])
    assert "test_raises_generico" in generic and "test_raises_con_tupla_generica" in generic
    assert "test_raises_de_timeout_sin_match" not in generic, "las de timeout no necesitan match"
    mocks = " ".join(by_rule["UNSAFE-MOCK"])
    assert "test_mock_con_spec" not in mocks
    assert "Mockeo del método privado '_secreto'" in mocks
    # El test con monkeypatch está aislado: su open() no cuenta como E/S real.
    assert not any("test_usa_monkeypatch" in m for msgs in by_rule.values() for m in msgs)


def test_calidad_de_suite_reconoce_los_dobles_importados_como_modulo(tmp_path):
    """`from unittest import mock` y después mock.MagicMock() o mock.patch() es de lo más habitual."""
    suite = tmp_path / "test_suite.py"
    suite.write_text(SUITE, encoding="utf-8")
    mocks = " ".join(m for _, rule, _, m in QATestRunner.audit_test_suite_quality(str(suite))["findings"]
                     if rule == "UNSAFE-MOCK")
    assert "test_mock_sin_spec" in mocks
    assert "Mockeo de miembro privado 'modulo._interno'" in mocks and "autospec=True" in mocks


def test_calidad_de_suite_ilegible(tmp_path):
    assert "no existe" in QATestRunner.audit_test_suite_quality(str(tmp_path / "test_x.py"))["error"]
    rota = tmp_path / "test_rota.py"
    rota.write_text("def (:\n", encoding="utf-8")
    assert "Error auditando calidad" in QATestRunner.audit_test_suite_quality(str(rota))["error"]


def test_ejecutar_una_suite_que_no_existe_o_que_es_un_directorio(tmp_path):
    assert "no existe" in QATestRunner.run_unittest_suite(str(tmp_path / "test_x.py"))["error"]
    assert "No se pudo abrir" in QATestRunner.run_unittest_suite(str(tmp_path))["error"]


def test_cobertura_estimada_de_una_suite_ilegible(tmp_path):
    assert QATestRunner.estimate_function_coverage(str(tmp_path / "test_x.py")) == {"error": "no se pudo leer test file"}


# --- Valores de muestra ---------------------------------------------------------------------------

@pytest.mark.parametrize("anotacion, esperado", [
    ("'str'", '"sample"'), ("Optional[int]", "1"), ("int | None", "1"), ("None | str", '"sample"'),
    ("List[int]", "[]"), ("Callable[[], int]", None), ("'Desconocido'", None),
])
def test_muestra_segun_la_anotacion(anotacion, esperado):
    assert sv.annotation_sample(ast.parse(anotacion, mode="eval").body) == esperado


@pytest.mark.parametrize("nombre, esperado", [
    ("user_name", '"sample"'), ("item_count", "1"), ("cliente_id", "1"), ("cosa", "1"),
])
def test_muestra_segun_el_nombre(nombre, esperado):
    assert sv.sample_for_arg(nombre) == esperado


@pytest.mark.parametrize("nombre, anotacion, nominal, primero", [
    ("items", "list", "[]", "empty_list"), ("datos", None, "{}", "empty_dict"),
    ("porcentaje", None, "10", "zero_percent"), ("n", None, "5", "zero"), ("s", "str", '"a"', "empty_str"),
])
def test_casos_limite_por_tipo_o_nombre(nombre, anotacion, nominal, primero):
    assert sv.boundary_samples_for_param(nombre, anotacion, nominal)[0][0] == primero


def test_matriz_de_escenarios_incluye_metodos_y_funciones_sin_argumentos(tmp_path):
    mod = tmp_path / "mod.py"
    mod.write_text("class C:\n    def m(self, x):\n        return x\n\n\ndef sin_args():\n    return 1\n",
                   encoding="utf-8")
    matrix = sv.build_scenario_matrix(str(mod))
    targets = {s["target"] for s in matrix}
    assert {"C.m", "sin_args"} <= targets
    assert any(s["scenario"] == "unexpected_extra_arg" for s in matrix if s["target"] == "sin_args")
    rota = tmp_path / "rota.py"
    rota.write_text("def (:\n", encoding="utf-8")
    assert sv.build_scenario_matrix(str(rota)) == []


# --- Fachada del generador: alias de compatibilidad -----------------------------------------------

def test_los_alias_privados_del_generador_siguen_delegando(tmp_path):
    """Los nombres privados de antes de la modularización se conservan y dan lo mismo."""
    mod = tmp_path / "mod.py"
    mod.write_text("def doble(x: int) -> int:\n    return x * 2\n", encoding="utf-8")
    arg = ast.parse("def f(user_name): pass").body[0].args
    assert isinstance(QATestGenerator._read_and_parse(str(mod)), ast.Module)
    assert QATestGenerator._boundary_samples_for_param("n", None, "1") == sv.boundary_samples_for_param("n", None, "1")
    assert QATestGenerator._annotation_sample(ast.Name(id="int")) == "1"
    assert QATestGenerator._sample_for_arg_node(arg.args[0]) == '"sample"'
    assert QATestGenerator._samples_from_arginfo(arg, ["user_name"])[1] == ["user_name"]
    assert QATestGenerator._sample_for_arg("cliente_id") == "1"
    assert QATestGenerator._is_float_literal("1.5") and not QATestGenerator._is_float_literal("1")
    assert QATestGenerator._io_targets([]) == []
    assert QATestGenerator._absorb_blocked(None, []) == (None, [])
    assert "patch(" in QATestGenerator._patch_clause(["os.remove"])
    assert QATestGenerator._io_called_expr(["os.remove"])
    visitor, recorded = QATestGenerator._visit(str(mod), record=False)
    assert recorded == {} and QATestGenerator._recording_calls(visitor)
    func = _func("def doble(x):\n    return x * 2")
    assert QATestGenerator._outcome_for("doble", func, ["x"], ["2"], {})[0] == ("value", "4", "")
    assert QATestGenerator._visit(str(tmp_path / "no_existe.py"), record=False) is None


# --- Suites generadas: formas del código analizado -------------------------------------------

# Formas habituales del código analizado.
FORMAS_BASE = '''class Vacia:
    pass


class ConInit:
    def __init__(self, valor=1):
        self.valor = valor


def no_devuelve(x):
    print(x)


def objeto(x):
    return Vacia()


async def doble(x):
    return x * 2
'''

# Una función que siempre lanza con un mensaje no literal y otra que solo devuelve valor en una
# rama: las dos suites tienen que tratarlas bien.
FORMAS = FORMAS_BASE + '''

def siempre_falla(x):
    raise RuntimeError(x)


def a_veces(x):
    if x > 5:
        return [x]
    print(x)
'''


def _run_suite(args, cwd):
    import subprocess

    return subprocess.run([sys.executable, "-m", *args], capture_output=True, text=True, cwd=str(cwd))


def _pytest_suite(tmp_path, source, record=False):
    src = tmp_path / "formas.py"
    src.write_text(source, encoding="utf-8")
    suite = tmp_path / "test_formas_pytest.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite), record=record)
    return suite.read_text(encoding="utf-8"), _run_suite(["pytest", "-q", "-p", "no:cacheprovider", suite.name], tmp_path)


@pytest.mark.parametrize("record", [False, True], ids=["estatico", "grabado"])
def test_suite_unittest_generada_para_cada_forma_pasa(tmp_path, record):
    src = tmp_path / "formas.py"
    src.write_text(FORMAS, encoding="utf-8")
    unit = tmp_path / "test_formas_unit.py"
    QATestGenerator.generate_test_suite(str(src), str(unit), record=record)
    body = unit.read_text(encoding="utf-8")
    assert "def test_Vacia_instantiation" in body and "import asyncio" in body
    assert "self.assertIsNone(result)" in body
    if record:
        # Se graba también el mensaje de la excepción y el tipo del objeto devuelto.
        assert 'with self.assertRaisesRegex(RuntimeError, r"1"):' in body
        assert 'self.assertEqual(type(result).__name__, "Vacia")' in body
    else:
        assert "with self.assertRaises(RuntimeError):" in body
        assert "Valor exacto desconocido" in body
        # a_veces solo devuelve valor en una rama: no hay nada seguro que afirmar, y se dice.
        assert "este test solo comprueba que no hay excepción" in body
    run = _run_suite(["unittest", "-q", unit.stem], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr


@pytest.mark.parametrize("record", [False, True], ids=["estatico", "grabado"])
def test_suite_pytest_generada_para_cada_forma_pasa(tmp_path, record):
    body, run = _pytest_suite(tmp_path, FORMAS, record)
    assert "assert result is None" in body
    if record:
        assert 'assert type(result).__name__ == "Vacia"' in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_suite_pytest_con_none_respeta_las_excepciones_de_la_funcion(tmp_path):
    source = ("def procesa(datos):\n    total = len(datos)\n    if total > 100:\n"
              "        raise RuntimeError('demasiados')\n    return total\n")
    body, run = _pytest_suite(tmp_path, source)
    assert "pytest.raises((RuntimeError, TypeError, ValueError, AttributeError, KeyError, ZeroDivisionError, " \
           'AssertionError), match=r".+")' in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_suite_pytest_sin_test_de_none_si_el_parametro_no_se_usa_sin_comprobar(tmp_path):
    """Solo se exige rechazar None si el cuerpo usa el parámetro en algo que falla con None."""
    sources = [
        "def siempre_falla(x):\n    raise RuntimeError(x)\n",               # solo se pasa a otra función
        "def normaliza(nivel):\n    return str(nivel or '').upper()\n",       # nivel or '' admite None
        "def opcional(x=None):\n    return x\n",                              # None por defecto
        "def guarda(x):\n    if x is None:\n        return 0\n    return x + 1\n",
        "def depende(flag, x):\n    if flag:\n        return 0\n    return x + 1\n",  # flag decide antes
    ]
    for source in sources:
        body, run = _pytest_suite(tmp_path, source)
        assert "adversarial_none_input" not in body, source
        assert run.returncode == 0, run.stdout + run.stderr


def test_suite_pytest_con_none_no_exige_mensaje_si_la_funcion_lanza_sin_el(tmp_path):
    source = "def busca(tabla, clave):\n    if clave not in tabla:\n        raise KeyError()\n    return tabla[clave]\n"
    body, run = _pytest_suite(tmp_path, source)
    assert 'match=r".*"' in body and 'match=r".+"' not in body
    # Con un valor límite, KeyError() sin mensaje también es un rechazo válido.
    assert "assert str(exc) or isinstance(exc, (KeyError,))" in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_suite_pytest_no_exige_valor_si_la_funcion_puede_devolver_none(tmp_path):
    body, run = _pytest_suite(tmp_path, "def a_veces(x):\n    if x > 5:\n        return [x]\n    print(x)\n")
    assert "Puede devolver None por algún camino" in body
    assert run.returncode == 0, run.stdout + run.stderr


def test_suite_de_un_modulo_sin_funciones_ni_clases(tmp_path):
    src = tmp_path / "constantes.py"
    src.write_text("LIMITE = 10\n", encoding="utf-8")
    unit = tmp_path / "test_constantes_unit.py"
    QATestGenerator.generate_test_suite(str(src), str(unit))
    assert "def test_module_importable" in unit.read_text(encoding="utf-8")
    suite = tmp_path / "test_constantes_pytest.py"
    QATestGenerator.generate_pytest_suite(str(src), str(suite))
    run = _run_suite(["pytest", "-q", "-p", "no:cacheprovider", suite.name], tmp_path)
    assert run.returncode == 0, run.stdout + run.stderr


def test_is_float_literal_con_texto_que_no_es_literal():
    assert QATestGenerator._is_float_literal("no es literal(") is False


# --- Payloads adversarios ------------------------------------------------------------------------

def test_payloads_adversarios_para_bool_objetos_y_tipos_desconocidos():
    from agentes.qa.api_contract_testing import APIContractTester

    schema = {"activo": bool, "owner": {"name": str}, "raw": bytes}
    payloads = dict(APIContractTester.generate_adversarial_payloads(schema))
    assert payloads["boundary_zero_or_empty"] == {"activo": False, "owner": {}, "raw": {}}
    assert payloads["boundary_negative_unicode"] == {"activo": True, "owner": {"name": None}, "raw": None}
    assert payloads["extreme_nan_giant"] == {"activo": False, "owner": {"name": "sample"}, "raw": {}}
    assert payloads["bool_as_int_or_type_trap"] == {"activo": "true", "owner": [], "raw": None}
    assert payloads["unexpected_extra_key"] == {"activo": True, "owner": {"name": "sample"}, "raw": {},
                                                "__unexpected_extra__": "adversarial"}


SUITE_OMISIONES = '''import unittest

import pytest


class T(unittest.TestCase):
    def test_omitido_en_unittest(self):
        self.skipTest("no aplica")

    def test_omitido_con_excepcion(self):
        raise unittest.SkipTest("no aplica")

    def test_omitido_dentro_de_un_with(self):
        with open("x"):
            self.skipTest("no aplica")

    def test_omite_solo_a_veces(self):
        try:
            hacer()
        except TypeError:
            self.skipTest("no encaja")


def test_omite_solo_a_veces_en_pytest():
    try:
        hacer()
    except TypeError:
        pytest.skip("no encaja")


def test_omite_a_veces_pero_comprueba():
    try:
        res = hacer()
    except TypeError:
        pytest.skip("no encaja")
    assert res == 1
'''


def test_calidad_de_suite_trata_igual_las_omisiones_de_pytest_y_unittest(tmp_path):
    """Un test que se omite siempre no necesita aserciones; uno que solo se omite a veces, sí."""
    suite = tmp_path / "test_omisiones.py"
    suite.write_text(SUITE_OMISIONES, encoding="utf-8")
    weak = " ".join(m for _, rule, _, m in QATestRunner.audit_test_suite_quality(str(suite))["findings"]
                    if rule == "WEAK-ASSERT")
    for siempre in ("test_omitido_en_unittest'", "test_omitido_con_excepcion'", "test_omitido_dentro_de_un_with'"):
        assert siempre not in weak
    assert "test_omite_solo_a_veces'" in weak and "test_omite_solo_a_veces_en_pytest'" in weak
    assert "test_omite_a_veces_pero_comprueba" not in weak

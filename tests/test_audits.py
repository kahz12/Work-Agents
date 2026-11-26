"""
Auditorías de audits.py: qué auditor le toca a cada archivo, la fusión de hallazgos entre
motores y qué pasa cuando un archivo no se puede leer.
"""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentes.common import audits  # noqa: E402
from agentes.common.findings import Finding  # noqa: E402


@pytest.mark.parametrize("nombre, tipo", [
    ("Dockerfile", "docker"), ("Dockerfile.prod", "docker"), ("app.dockerfile", "docker"),
    ("api.service", "systemd"), ("requirements-dev.txt", "deps"), ("package.json", "deps"),
    ("ci.yml", "yaml"), ("values.yaml", "yaml"), (".env", "env"), (".env.local", "env"), ("prod.env", "env"),
    ("app.log", "logs"), ("test_api.py", "tests"), ("api_test.py", "tests"), ("api.py", None), ("README.md", None),
])
def test_tipo_de_auditoria_por_el_nombre(nombre, tipo):
    assert audits.detect_kind(os.path.join("sub", nombre)) == tipo


def test_auditar_un_tipo_que_no_existe(tmp_path):
    with pytest.raises(ValueError, match="no reconocido"):
        audits.audit_file(str(tmp_path / "README.md"))


def test_auditar_systemd_package_json_y_suites(tmp_path):
    service = tmp_path / "api.service"
    service.write_text("[Service]\nExecStart=/usr/bin/api\n", encoding="utf-8")
    assert {f.rule_id for f in audits.audit_file(str(service))} == {"SYSTEMD"}
    pkg = tmp_path / "package.json"
    pkg.write_text('{"dependencies": {"left-pad": "^1.3.0"}}', encoding="utf-8")
    [npm] = audits.audit_file(str(pkg))
    assert (npm.rule_id, npm.level) == ("DEPS-NPM", "MEDIO") and "left-pad" in npm.message
    suite = tmp_path / "test_x.py"
    suite.write_text("def test_a():\n    assert True\n", encoding="utf-8")
    assert any("WEAK-ASSERT" in f.message for f in audits.audit_file(str(suite)))
    broken = tmp_path / "test_roto.py"
    broken.write_text("def (:\n", encoding="utf-8")
    [error] = audits.audit_file(str(broken))
    assert (error.level, error.rule_id) == ("ERROR", "TEST-QUALITY")


def test_secretos_de_un_archivo_que_no_se_pudo_escanear(tmp_path, monkeypatch):
    from agentes.defensive.config_manager import ConfigManager

    path = str(tmp_path / "x.py")

    def explota(p):
        raise RuntimeError("disco roto")

    monkeypatch.setattr(ConfigManager, "scan_file_for_secrets", staticmethod(explota))
    [finding] = audits.scan_secrets(path)
    assert (finding.level, finding.rule_id) == ("ERROR", "SECRET-SCAN-ERROR") and "disco roto" in finding.message
    monkeypatch.setattr(ConfigManager, "scan_file_for_secrets", staticmethod(lambda p: [(0, "", "sin permiso")]))
    [finding] = audits.scan_secrets(path)
    assert finding.rule_id == "SECRET-SCAN-ERROR" and "sin permiso" in finding.message


def test_fusion_indica_los_otros_motores_que_lo_detectaron():
    ast_finding = Finding("a.py", 4, "ALTO", "Uso de 'except Exception: pass' que silencia errores.", "SAST-ALTO")
    solid = Finding("a.py", 4, "ALTO", "[EXCEPTION-HYGIENE] Bloque 'except' silencia la excepción con 'pass'.",
                    "SOLID-EXCEPTION-HYGIENE")
    bandit = Finding("a.py", 4, "BAJO", "[bandit] Try, Except, Pass detected.", "SAST-BAJO")
    [merged] = audits.merge_duplicates([ast_finding, solid, bandit])
    assert merged.message.startswith("Uso de 'except Exception: pass'")
    assert merged.message.endswith("Detectado también por: SOLID, bandit.")
    assert merged.level == "MEDIO", "silenciar excepciones se calibra como fiabilidad, no seguridad"

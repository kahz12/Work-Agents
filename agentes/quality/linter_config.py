import json
import os


class LinterConfigGenerator:
    """
    Writes baseline configuration files for linters and formatters: flake8, pyproject.toml
    (black, isort, mypy) and ESLint.
    """

    FLAKE8_DEFAULT_CONFIG = """[flake8]
max-line-length = 100
exclude = .git,__pycache__,build,dist,.venv,venv
ignore = E203, W503
select = C,E,F,W,B,B950
"""

    PYPROJECT_TOML_CONFIG = """[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[tool.black]
line-length = 100
target-version = ['py310']

[tool.isort]
profile = "black"
line_length = 100

[tool.mypy]
python_version = "3.10"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
"""

    ESLINT_DEFAULT_CONFIG = {
        "env": {
            "browser": True,
            "es2021": True,
            "node": True
        },
        "extends": [
            "eslint:recommended"
        ],
        "parserOptions": {
            "ecmaVersion": 12,
            "sourceType": "module"
        },
        "rules": {
            "no-unused-vars": "warn",
            "no-console": "off",
            "eqeqeq": "error",
            "curly": "error"
        }
    }

    @staticmethod
    def generate_flake8_config(target_dir: str) -> str:
        """
        Write .flake8 into target_dir, overwriting any existing file, and return its path.
        """
        filepath = os.path.join(target_dir, ".flake8")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(LinterConfigGenerator.FLAKE8_DEFAULT_CONFIG)
        return filepath

    @staticmethod
    def generate_pyproject_toml(target_dir: str) -> str:
        """
        Write a pyproject.toml with black, isort and mypy settings into target_dir, overwriting
        any existing file, and return its path. Callers that must not clobber an existing
        project file (the CLI) check for it first.
        """
        filepath = os.path.join(target_dir, "pyproject.toml")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(LinterConfigGenerator.PYPROJECT_TOML_CONFIG)
        return filepath

    @staticmethod
    def generate_eslint_config(target_dir: str) -> str:
        """
        Write .eslintrc.json into target_dir, overwriting any existing file, and return its path.
        """
        filepath = os.path.join(target_dir, ".eslintrc.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(LinterConfigGenerator.ESLINT_DEFAULT_CONFIG, f, indent=2)
        return filepath

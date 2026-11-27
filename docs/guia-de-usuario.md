# Guía de usuario de Work-Agents

**Español** | [English](user-guide.md)

Esta guía describe Work-Agents 3.2.3 de principio a fin: instalación, cada comando con todas sus
opciones, las reglas que aplica cada auditor, el formato de los informes, la integración
continua y el uso de los agentes como biblioteca de Python. Para una visión general, consulta
el [README](../README.es.md).

> **Nota sobre el idioma.** La interfaz de línea de comandos, sus mensajes y los informes que
> genera están en inglés. Los ejemplos de salida de esta guía se muestran tal cual y la sección
> [Cómo leer la salida](#cómo-leer-la-salida) traduce todos los términos que vas a ver.

## Contenido

- [Introducción](#introducción)
- [Instalación](#instalación)
- [Conceptos básicos](#conceptos-básicos)
- [Cómo leer la salida](#cómo-leer-la-salida)
- [Primeros pasos](#primeros-pasos)
- [Analizar un proyecto](#analizar-un-proyecto)
  - [`pipeline`](#pipeline) · [`analyze`](#analyze) · [`secrets`](#secrets) · [`vulns`](#vulns) · [`audit`](#audit) · [`metrics`](#metrics)
- [Generar y corregir](#generar-y-corregir)
  - [`generate`](#generate) · [`fix`](#fix)
- [Probar](#probar)
  - [`test`](#test) · [`testability`](#testability) · [`contract`](#contract)
- [Operar](#operar)
  - [`health`](#health) · [`sla`](#sla) · [`serve`](#serve)
- [Utilidades](#utilidades)
  - [`password`](#password) · [`demo`](#demo) · [`list`](#list) · [`doctor`](#doctor) · [`help`](#help)
- [Catálogo de reglas](#catálogo-de-reglas)
- [Informes y formatos](#informes-y-formatos)
- [Línea base](#línea-base)
- [Silenciar un hallazgo en su línea](#silenciar-un-hallazgo-en-su-línea)
- [Integración continua](#integración-continua)
- [Uso como biblioteca](#uso-como-biblioteca)
- [Red y privacidad](#red-y-privacidad)
- [Solución de problemas](#solución-de-problemas)
- [Limitaciones](#limitaciones)

---

## Introducción

Work-Agents es una herramienta de línea de comandos que audita proyectos Python desde tres
ángulos:

- **Seguridad (DevSecOps)**: código inseguro, secretos expuestos, dependencias con
  vulnerabilidades conocidas y configuración de infraestructura débil.
- **Calidad y pruebas (QA)**: complejidad, diseño, rendimiento, testabilidad y calidad de las
  suites de tests, además de generar tests nuevos.
- **Operación (SRE)**: sondas de salud, tasas de error, métricas para Prometheus y análisis de
  logs.

Internamente está dividida en ocho agentes, cada uno un subpaquete de `agentes`:

| Agente      | Responsabilidad                                                                 |
|-------------|---------------------------------------------------------------------------------|
| `defensive` | Sanitización de entrada, hashing de contraseñas, CSRF, tokens HMAC, RBAC, rate limiting, auditoría de `.env` y detección de secretos. |
| `quality`   | Análisis estático (motor AST y Bandit), SARIF, vulnerabilidades (OSV), corrección de versiones (PyPI) y configuración de linters. |
| `hardening` | Plantillas y auditoría de Nginx, Caddy, Dockerfile, Kubernetes y systemd.        |
| `refactor`  | Métricas de complejidad, heurísticas SOLID, rendimiento y diagramas Mermaid.     |
| `qa`        | Generación y ejecución de tests, testabilidad y pruebas de contrato de API.      |
| `sre`       | Logs estructurados, anomalías en logs, sondas de salud, Prometheus y alertas.    |
| `devops`    | GitHub Actions, GitLab CI, Docker Compose, Helm y validación de YAML.            |
| `docs`      | OpenAPI 3.0.3, Swagger UI y manuales Markdown.                                   |

No hace falta conocer los agentes para usar la herramienta: el comando `agentes` los combina
en tareas concretas. Los agentes solo importan si quieres [usarlos desde Python](#uso-como-biblioteca).

**Lo que Work-Agents no hace.** No ejecuta el código que analiza (salvo `test` y
`generate tests --record`, que lo hacen por diseño), no modifica tu código fuente (solo `fix`
reescribe un `requirements.txt` cuando se lo pides) y no envía código a ningún servicio.

---

## Instalación

### Requisitos

- Python 3.9, 3.10, 3.11, 3.12 o 3.13 (el CI prueba las cinco versiones).
- Dependencias obligatorias, que se instalan solas: `PyYAML>=6.0`, `packaging>=21.0` y, en
  Python 3.9 y 3.10, `tomli>=1.1`.
- El CI se ejecuta en Linux. La herramienta es Python puro, pero algunas funciones dependen del
  sistema: la carga media de `health` solo existe en sistemas tipo Unix (en otros se muestra
  como 0).

### Instalación desde el repositorio

El paquete no está publicado en PyPI. Se recomienda un entorno virtual:

```bash
git clone https://github.com/kahz12/Work-Agents.git
cd Work-Agents
python3 -m venv .venv
source .venv/bin/activate          # en Windows: .venv\Scripts\activate
pip install -e .
```

`-e` (modo editable) hace que los cambios en el repositorio se apliquen sin reinstalar. Para
una instalación normal, quita `-e`.

### Instalación directa desde Git

Sin clonar el repositorio, por ejemplo en un trabajo de CI:

```bash
pip install "git+https://github.com/kahz12/Work-Agents.git"
pip install "agentes-devsecops[all] @ git+https://github.com/kahz12/Work-Agents.git"   # con extras
```

### Extras

Los extras son opcionales. Cada uno mejora un motor que ya funciona sin él:

| Extra    | Paquetes                | Sin el extra                                                  | Con el extra                                     |
|----------|-------------------------|---------------------------------------------------------------|--------------------------------------------------|
| `crypto` | argon2-cffi, bcrypt     | `password hash` usa PBKDF2-HMAC-SHA256 con 600 000 iteraciones. | Usa Argon2 (o bcrypt si solo está bcrypt).       |
| `sast`   | bandit                  | El análisis estático usa solo el motor AST propio.            | Bandit se ejecuta además del motor AST.          |
| `dev`    | pytest, ruff, pyflakes, coverage | No puedes ejecutar los tests ni el lint del repositorio.      | `pytest -q` y `ruff check .` funcionan.          |
| `all`    | Todos los anteriores    |                                                               |                                                  |

```bash
pip install -e ".[crypto,sast]"
pip install -e ".[all]"
```

### Uso sin instalar

Si prefieres no instalar el paquete, instala solo las dependencias y usa el lanzador:

```bash
pip install -r requirements.txt
python3 agentes_cli.py pipeline .
```

`python3 -m agentes` también funciona si el directorio del repositorio está en el `PYTHONPATH`.

### Comprobar la instalación

```bash
agentes --version
agentes doctor
```

`doctor` muestra qué componentes están instalados y cuáles faltan:

```text
AGENTES v3.2.3 diagnostics
==========================

  Component    Status    Detail
  Python       OK        3.14.4
  PyYAML       OK        YAML and Kubernetes validation
  bandit       optional  pip install bandit   (without it, the built-in AST engine is used)
  argon2-cffi  optional  pip install argon2-cffi
  bcrypt       OK        password hashing with bcrypt
  pytest       OK        run generated pytest suites

Password hashing  bcrypt
Demo output       next to each agent (set AGENTES_WORKDIR to change it)
Terminal colour   off

[OK] Ready to use. The optional components add features, but they are not required.
To install them all: pip install -e ".[all]"
```

Cada fila es un componente (`Component`) con su estado (`Status`: `OK`; `optional`, opcional y
no instalado; `MISSING`, obligatorio y no instalado) y para qué sirve o cómo instalarlo. Debajo de
la tabla: el algoritmo de hashing de contraseñas activo, dónde escriben las demos y si el color
está activado. `doctor` devuelve `1` solo si falta un componente obligatorio (Python 3.9+ o
PyYAML).

### Actualizar desde la versión 2

En la versión 3 los paquetes pasaron a vivir bajo `agentes/`. Si actualizas una instalación
antigua, reinstala:

```bash
git pull
pip install -e .
```

Las opciones `--pypi` y `--default-version` de `fix` se siguen aceptando para no romper
scripts, pero ya no tienen efecto.

### Desinstalar

```bash
pip uninstall agentes-devsecops
```

---

## Conceptos básicos

### Hallazgos

Todo lo que detecta un auditor es un **hallazgo** con estos campos:

| Campo     | Contenido                                                                            |
|-----------|--------------------------------------------------------------------------------------|
| `file`    | Archivo (o URL, en la auditoría de cabeceras).                                       |
| `line`    | Línea, empezando en 1. Es `0` cuando no aplica: una directiva que falta, una cabecera HTTP, el archivo entero. |
| `level`   | Severidad, ver la tabla siguiente.                                                   |
| `message` | Descripción y recomendación, en inglés.                                              |
| `rule_id` | Identificador de la regla, ver el [catálogo de reglas](#catálogo-de-reglas).         |
| `category` | `security` (riesgo de seguridad) o `quality` (fiabilidad, mantenibilidad o rendimiento). Solo en la salida JSON de los comandos y en `pipeline.json`. |

### Seguridad y calidad del código

La consola separa los hallazgos en dos secciones, **Security** (seguridad) y **Code quality** (calidad del código), para
que un riesgo de seguridad no quede escondido entre docstrings que faltan. Si un análisis que
busca problemas de seguridad (`pipeline`, `analyze`) no encuentra ninguno, lo dice:

```text
[OK] No security findings.

Code quality (87): 68 medium, 19 low
```

Son de calidad las métricas y los principios SOLID, el rendimiento, la calidad de los tests,
los errores de sintaxis de Python o YAML y estas reglas del análisis estático: docstrings,
demasiados argumentos, argumentos por defecto mutables, `open()` fuera de un `with`, las
capturas de excepciones (`except:`, `except Exception`, silenciar con `pass`), las llamadas
bloqueantes en `async def`, el estado global y el exceso de ramas. Todo lo demás (secretos,
infraestructura, dependencias, vulnerabilidades, cabeceras, logs y el resto del análisis
estático) es de seguridad. La categoría no cambia la severidad ni el código de salida.

### Severidades

De más a menos grave (los nombres de nivel aparecen tal cual en JSON y SARIF):

| Nivel         | Bloqueante | Significado                                                              |
|---------------|------------|--------------------------------------------------------------------------|
| `CRITICAL`    | Sí         | Riesgo grave y directo: `eval`, `pickle.loads`, `os.system`, trazas de excepción o falta de memoria en logs. |
| `ERROR`       | Sí         | No se pudo analizar algo (archivo ilegible, manifiesto corrupto). No se da por limpio. |
| `HIGH`        | Sí         | Riesgo importante: `shell=True`, SQL construido a mano, secretos, contenedor como root. |
| `MEDIUM`      | No         | Conviene corregirlo, pero no bloquea: falta de `timeout`, hash débil, imagen sin versión. |
| `LOW`         | No         | Mejora recomendada: docstrings, `assert` fuera de tests, `>=` en dependencias. |
| `INFO`        | No         | Informativo. No se muestra en la consola.                                |
| `OK`          | No         | Comprobación superada. No se muestra en la consola.                      |

"Bloqueante" significa que el hallazgo hace fallar los comandos que fallan por hallazgos altos
o críticos (`pipeline`, `audit`, `vulns`, `analyze --fail-on-high`...).

### Códigos de salida

| Código | Significado                                                                          |
|--------|--------------------------------------------------------------------------------------|
| `0`    | Todo correcto, o el comando es informativo (`metrics`, `testability`).               |
| `1`    | Hay hallazgos que hacen fallar el comando, tests que no pasan, un endpoint que no cumple su contrato, una sonda caída o un error inesperado. |
| `2`    | Error de uso: ruta inexistente, opción desconocida, comando mal escrito, combinación de opciones no válida o falta de red en un comando que la necesita. |
| `130`  | Interrumpido con Ctrl+C.                                                             |

Cada comando detalla abajo en qué casos devuelve `1`.

### Opciones comunes

| Opción        | Disponible en                                                      | Efecto                                                    |
|---------------|--------------------------------------------------------------------|-----------------------------------------------------------|
| `-h`, `--help`| Todos                                                              | Ayuda del comando, con ejemplos.                          |
| `--json`      | Todos salvo `generate`, `serve`, `demo`, `list` y `help`           | Imprime el resultado en JSON en vez del resumen.          |
| `--limit N`   | `pipeline`, `analyze`, `secrets`, `vulns`, `audit`, `metrics`, `fix`, `test`, `testability` | Máximo de elementos por lista. Por defecto 20. `0` muestra todos. |
| `--offline`   | `pipeline`, `analyze`, `vulns`, `fix`, `password`                  | No hace consultas de red. Equivale a `AGENTES_OFFLINE=1`. |
| `--no-color`  | Todos                                                              | Desactiva el color.                                       |

`agentes --version` (o `-V`) muestra la versión y `agentes --list` (o `-l`) equivale a
`agentes list`.

### Variables de entorno

| Variable           | Efecto                                                                                       |
|--------------------|----------------------------------------------------------------------------------------------|
| `AGENTES_OFFLINE`  | Con `1`, `true`, `yes`, `si` o `sí`, desactiva toda consulta de red (OSV, PyPI, Have I Been Pwned). |
| `AGENTES_WORKDIR`  | Directorio donde las demos escriben sus archivos (ver [`demo`](#demo)).                      |
| `AGENTES_DEBUG`    | Si está definida, un error inesperado muestra la traza completa en vez de un mensaje breve.  |
| `NO_COLOR`         | Si está definida, desactiva el color (convención [no-color.org](https://no-color.org)).      |

El color solo se usa cuando la salida es un terminal: al redirigir a un archivo o a otro
programa se desactiva solo.

### Rutas en la salida

Las rutas se muestran relativas al directorio actual si están cerca (hasta dos niveles hacia
arriba); si no, relativas al proyecto analizado; y si no, absolutas. En los informes JSON las
rutas son absolutas; en SARIF, relativas a la raíz del proyecto.

### Directorios que se saltan

Al recorrer un directorio, todos los comandos de análisis ignoran:

- `.git`, `__pycache__`, `node_modules`, `build`, `dist` y `reports`.
- Las cachés `.mypy_cache`, `.pytest_cache` y `.ruff_cache`.
- Los directorios `*.egg-info`.
- Los entornos virtuales: `.venv`, `venv`, cualquier nombre que empiece por `venv` o `.venv`
  y cualquier directorio que contenga un `pyvenv.cfg`, se llame como se llame.
- El directorio de informes indicado con `-o`.

Ten en cuenta que un directorio llamado `reports` siempre se salta, aunque contenga código.

### Errores y sugerencias

Un comando mal escrito sugiere el más parecido y termina con `2`:

```text
$ agentes piplene .
Error: Unknown command: 'piplene'.
  Did you mean 'pipeline'? Run 'agentes' to see every command.
```

Los errores de argumentos también se explican (en inglés) e indican cómo pedir ayuda. Si
algo falla de forma inesperada, `AGENTES_DEBUG=1 agentes ...` muestra la traza completa.

---

## Cómo leer la salida

La salida del CLI está en inglés. Esta sección traduce todo lo que vas a ver.

### Etiquetas de estado

| Etiqueta | Significado                                                            |
|----------|------------------------------------------------------------------------|
| `[OK]`   | Correcto.                                                              |
| `[WARN]` | Aviso: conviene leerlo, pero no cambia el resultado.                   |
| `[FAIL]` | Fallo: el comando terminará con un código distinto de 0.               |
| `Error:` | Error de uso o del entorno (se escribe en stderr, código de salida 2). |

### Tabla del pipeline

| Inglés                                                   | Español                                                    |
|----------------------------------------------------------|------------------------------------------------------------|
| `Stage` / `Status` / `Summary`                           | Etapa / Estado / Resumen                                   |
| `OK` / `FAILED` / `SKIPPED`                              | Correcta / Fallida / Omitida                               |
| `Static analysis`                                        | Análisis estático                                          |
| `Secrets`                                                | Secretos                                                   |
| `Metrics and SOLID`                                      | Métricas y SOLID                                           |
| `OpenAPI documentation`                                  | Documentación OpenAPI                                      |
| `Infrastructure and dependencies`                        | Infraestructura y dependencias                             |
| `Dependency vulnerabilities`                             | Vulnerabilidades en dependencias                           |
| `N SAST findings (M high/critical) in X of Y files`      | N hallazgos SAST (M altos o críticos) en X de Y archivos   |
| `without Bandit (AST engine only; install the 'sast' extra)` | Bandit no está instalado (solo motor AST; instala el extra `sast`) |
| `possible secrets/insecure settings` / `(+N config)`     | posibles secretos o configuración insegura; N archivos de configuración añadidos |
| `skipped: no web framework detected`                     | omitida: no se detectó ningún framework web                |
| `skipped: offline mode · N manifests not checked`        | omitida: modo sin conexión, N manifiestos sin comprobar    |
| `not checked`                                            | sin comprobar (no hay nada con versión exacta)             |
| `Security (6): 4 high, 2 medium`                         | Seguridad (6): 4 altos, 2 medios                           |
| `Code quality (N)`                                       | Calidad del código (N)                                     |
| `Reports`                                                | Informes                                                   |
| `No blocking findings.`                                  | Sin hallazgos bloqueantes.                                 |
| `There are blocking findings (exit code 1).`             | Hay hallazgos bloqueantes (código de salida 1).            |
| `Baseline X: N accepted findings are not counted.`       | Línea base X: N hallazgos aceptados no cuentan.            |
| `N entries no longer match anything: regenerate the baseline to drop them.` | N entradas ya no coinciden con nada: regenera la línea base para retirarlas. |

### Hallazgos

| Inglés                                      | Español                                              |
|---------------------------------------------|------------------------------------------------------|
| `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]` | crítico, alto, medio, bajo                           |
| `***REDACTED***`                            | Parte enmascarada de un secreto.                     |
| `Fixed in X.`                               | Corregido en la versión X.                           |
| `No fixed version published.`               | No hay ninguna versión corregida publicada.          |
| `Also detected by: bandit`                  | También lo detectó Bandit (hallazgo fusionado).      |
| `[bandit]` al principio del mensaje         | El hallazgo viene solo de Bandit.                    |
| `Line N:`                                   | Línea N del manifiesto.                              |

### Otros comandos

| Comando    | Inglés                                                         | Español                                        |
|------------|----------------------------------------------------------------|------------------------------------------------|
| `metrics`  | `Files`, `Lines of code`, `Functions`                          | Archivos, Líneas de código, Funciones          |
| `metrics`  | `Average cyclomatic / cognitive complexity`                    | Complejidad ciclomática / cognitiva media      |
| `metrics`  | `Most complex files`, `Most complex functions`, `Recommendations` | Archivos más complejos, Funciones más complejas, Recomendaciones |
| `test`     | `Run`, `Passed`, `Failed`, `Errors`, `Skipped`                 | Ejecutados, Correctos, Fallidos, Con error, Omitidos |
| `test`     | `Pass rate`, `Duration`, `Estimated coverage`                  | Tasa de éxito, Duración, Cobertura estimada    |
| `health`   | `Probe`, `Disk`, `Load`, `MB free`                             | Sonda, Disco, Carga, MB libres                 |
| `password` | `strong`, `acceptable`, `weak`                                 | fuerte, aceptable, débil                       |
| `fix`      | `Proposed changes`, `Applied changes`, `Unchanged`             | Cambios propuestos, Cambios aplicados, Sin cambios |
| `contract` | `Check`, `Detail`, `Status Code`, `Latency SLA`, `JSON Schema` | Comprobación, Detalle, Código de estado, SLA de latencia, Esquema JSON |
| `doctor`   | `Component`, `Detail`, `optional`, `MISSING`                   | Componente, Detalle, opcional, falta           |

### Mensajes de error habituales

| Inglés                                                  | Español                                              |
|---------------------------------------------------------|------------------------------------------------------|
| `Path does not exist: X`                                | No existe la ruta X.                                 |
| `Expected a .py file`                                   | Se esperaba un archivo `.py`.                        |
| `X already exists and was not overwritten.`             | X ya existe y no se ha sobrescrito (usa `--force`).  |
| `Unknown command` / `Did you mean ...?`                 | Comando desconocido / ¿Querías decir ...?            |
| `The following arguments are required`                  | Faltan argumentos obligatorios.                      |
| `... but offline mode is on.`                           | ... pero está activo el modo sin conexión.           |
| `Could not query OSV`                                   | No se pudo consultar OSV.                            |

---

## Primeros pasos

Este recorrido usa un proyecto pequeño con problemas a propósito. Tarda unos minutos.

### 1. Preparar un proyecto de ejemplo

```text
mi_proyecto/
├── app/
│   ├── main.py          API Flask con una ruta, un subprocess con shell=True y yaml.load
│   └── settings.py      DB_URL = "postgres://admin:<contraseña>@db:5432/app"
├── Dockerfile           FROM python:latest, sin USER
├── requirements.txt     flask==2.0.0 y requests sin versión
└── .env                 DEBUG=true y SECRET_KEY=changeme
```

### 2. Auditoría completa

```bash
agentes pipeline mi_proyecto
```

```text
Audit of mi_proyecto
====================

  Stage                            Status   Summary
  Static analysis                  FAILED   2 SAST findings (2 high/critical) in 2 of 2 files ·
                                            without Bandit (AST engine only; install the 'sast'
                                            extra)
  Secrets                          FAILED   1 possible secrets/insecure settings in 2 of 2 files (+1
                                            config)
  Metrics and SOLID                OK       avg_cyclomatic=1.0 avg_cognitive=0.0 · 2 files · 0 SOLID
                                            findings
  OpenAPI documentation            OK       flask: 1 routes in 2 files
  Infrastructure and dependencies  FAILED   3 findings (1 high/critical) in 2 infra/deps/YAML files
  Dependency vulnerabilities       SKIPPED  skipped: offline mode · 1 manifests not checked

Security (6): 4 high, 2 medium
  [HIGH]   mi_proyecto/Dockerfile
           The Dockerfile has no 'USER <non_root_user>' instruction. The container will run as root
           by default.
  [HIGH]   mi_proyecto/app/main.py:18
           Subprocess started with 'shell=True' (command injection risk).
  [HIGH]   mi_proyecto/app/main.py:24
           Unsafe use of 'yaml.load()' without SafeLoader (use yaml.safe_load).
  [HIGH]   mi_proyecto/app/settings.py:1
           Credential inside a connection URL: DB_URL =
           "postgres://admin:***REDACTED***@db:5432/app"
  [MEDIUM] mi_proyecto/Dockerfile:1
           Base image uses ':latest' or no pinned tag. Specify the exact version.
  [MEDIUM] mi_proyecto/requirements.txt:2
           [requests] Line 2: dependency 'requests' does not pin a version (==x.y.z). Installs can
           pick up unwanted changes.

Reports
  HTML     mi_proyecto/reports/pipeline.html
  JSON     mi_proyecto/reports/pipeline.json
  SARIF    mi_proyecto/reports/pipeline.sarif
  OpenAPI  mi_proyecto/reports/openapi.json

[FAIL] There are blocking findings (exit code 1).
Open mi_proyecto/reports/pipeline.html in a browser for the details.
```

(Esta salida es de una ejecución con `--offline`. Con conexión, la última etapa consulta OSV.)

Cómo leerla:

1. **La tabla de etapas** resume cada análisis. `FAILED` indica que la etapa tiene hallazgos
   bloqueantes; `SKIPPED`, que no se pudo o no tenía sentido ejecutarla.
2. **Los hallazgos** van de más a menos graves, con archivo y línea. Los valores de los secretos
   salen enmascarados (`***REDACTED***`).
3. **Los informes** quedan en `mi_proyecto/reports/`. El HTML es el más cómodo para revisar.
4. **El código de salida** es `1` porque hay hallazgos altos y un secreto.

### 3. Corregir y repetir

Cambia `shell=True` por una lista de argumentos, usa `yaml.safe_load`, mueve la URL de la base
de datos a una variable de entorno, añade `USER` al Dockerfile y fija `requests==<versión>`.
Repite `agentes pipeline mi_proyecto` hasta ver `[OK] No blocking findings.`

### 4. Revisar lo que el pipeline no cubre

El `.env` no se audita en el pipeline (solo se busca en él algún secreto real). Para revisar
sus opciones:

```bash
agentes audit mi_proyecto/.env
```

```text
Audit of mi_proyecto/.env
=========================
Kind: env · Items checked: 1

Security (2): 2 high
  [HIGH] mi_proyecto/.env
         [DEBUG] The 'DEBUG' option is enabled. It must be disabled in production.
  [HIGH] mi_proyecto/.env
         [SECRET_KEY] The value of 'SECRET_KEY' is insecure or a known default ('changeme'). Use
         environment variables.
```

`agentes audit mi_proyecto` revisa de una vez infraestructura, dependencias, `.env` y logs.

### 5. Siguientes pasos

- Genera tests para un módulo: `agentes generate tests --source app/calc.py`.
- Si el proyecto ya tiene hallazgos aceptados, crea una [línea base](#línea-base).
- Integra el pipeline en tu [CI](#integración-continua).

---

## Analizar un proyecto

### `pipeline`

```text
agentes pipeline PATH [-o DIR] [--no-fail] [--max-files N] [--no-bandit]
                      [--baseline FILE | --write-baseline FILE]
                      [--offline] [--json] [--limit N] [--no-color]
```

Auditoría completa de un directorio o archivo. Es el comando principal y el recomendado para
CI.

#### Opciones

| Opción                     | Por defecto      | Efecto                                                                         |
|----------------------------|------------------|--------------------------------------------------------------------------------|
| `PATH`                     | (obligatorio)    | Directorio o archivo a auditar. Con un archivo, la raíz del proyecto es su directorio. |
| `-o`, `--output DIR`       | `PATH/reports`   | Directorio de informes. Se crea si no existe y se excluye del análisis.        |
| `--no-fail`                | desactivado      | Las etapas de análisis estático, infraestructura y vulnerabilidades no fallan por hallazgos altos o críticos. Los secretos siguen haciendo fallar. |
| `--max-files N`            | todos            | Analiza como mucho N archivos `.py` (en orden alfabético de ruta). El resumen y el informe indican cuántos quedaron fuera. |
| `--no-bandit`              | desactivado      | Usa solo el motor AST. Bandit abre un subproceso por archivo, así que en proyectos grandes es lo que más tarda. |
| `--baseline FILE`       | ninguno          | Los hallazgos registrados en la línea base no cuentan. Ver [Línea base](#línea-base). |
| `--write-baseline FILE` | ninguno          | Guarda los hallazgos bloqueantes y los secretos actuales como línea base y termina con `0`. No se puede combinar con `--baseline`. |
| `--offline`                | desactivado      | No consulta OSV: la etapa de vulnerabilidades queda omitida.                   |
| `--json`                   | desactivado      | Imprime el informe completo (el mismo que `pipeline.json`) en vez del resumen. |
| `--limit N`                | 20               | Máximo de hallazgos listados en consola. `0` lista todos. No afecta a los informes. |

#### Etapas

Las seis etapas se ejecutan siempre, en este orden. El nombre interno (entre paréntesis) es
el que aparece en el informe JSON.

**1. Análisis estático** (`quality_sast`)

- Analiza los `.py` encontrados (respetando `--max-files`).
- Motores: el [motor AST propio](#análisis-estático-motor-ast) siempre y, si está instalado y
  no se usa `--no-bandit`, Bandit. Los hallazgos de ambos sobre la misma línea y tema se funden
  en uno que indica "Also detected by: bandit".
- Si Bandit falta, el resumen lo dice: `without Bandit (AST engine only; install the 'sast' extra)`.
- Estado `FAILED` si hay hallazgos bloqueantes (salvo con `--no-fail`).

**2. Secretos** (`defensive_secrets`)

- Busca secretos en los `.py` analizados y en los archivos de configuración del árbol:
  `.env`, `.env.*` y las extensiones `.env`, `.yml`, `.yaml`, `.json`, `.toml`, `.ini`, `.cfg`,
  `.conf`, `.sh` y `.sql`. El resumen indica cuántos archivos de configuración se añadieron
  (`(+1 config)`).
- Excluye los propios informes (`pipeline.json`, `analyze.json`, `openapi.json`, `*.sarif`) y el
  archivo indicado en `--baseline` o `--write-baseline`.
- Un archivo que no se puede leer cuenta como `ERROR` (regla `SECRET-SCAN-ERROR`): no se da
  por limpio.
- Estado `FAILED` si hay al menos un secreto o un archivo ilegible, **también con `--no-fail`**.
- Detalle de los patrones en [Secretos](#secretos).

**3. Métricas y SOLID** (`refactor_metrics`)

- Calcula complejidad ciclomática y cognitiva media por función, líneas de código y ratio de
  comentarios.
- Aplica las heurísticas [SOLID y de diseño](#solid-y-diseño) y las de
  [rendimiento](#rendimiento) del catálogo. En el pipeline los hallazgos de rendimiento se
  registran siempre como `MEDIUM`.
- Si un hallazgo SOLID repite lo que ya detectó el análisis estático en la misma línea, no se
  cuenta dos veces.
- **No afecta al código de salida.** Sus hallazgos aparecen en la lista y en los informes como
  información para refactorizar. El estado solo es `FAILED` si ningún archivo se pudo analizar.
- Las recomendaciones de refactor quedan en el informe JSON (`stages[].recommendations`), con
  el mismo criterio que en [`metrics`](#metrics): las de promedios una sola vez y las de una línea
  concreta con su archivo, relativo a la raíz del proyecto (`pkg/app.py:12`).

**4. Documentación OpenAPI** (`documentation`)

- Solo se ejecuta si algún archivo importa un framework web: FastAPI, Flask, Starlette,
  Django, aiohttp, Bottle, Sanic, Tornado, Falcon, Quart, Litestar, Pyramid, CherryPy,
  Connexion o Responder. Si no, queda `SKIPPED`: en un proyecto que no es web, una función
  `get_*` no es un endpoint.
- Reconoce las rutas declaradas con decoradores de Flask (`@app.route`) y FastAPI (`@app.get`,
  `@router.post`...). Si encuentra al menos una, escribe `openapi.json` en el directorio de
  informes.
- No afecta al código de salida.

**5. Infraestructura y dependencias** (`infra_and_deps`)

- Audita `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `*.service`, `requirements*.txt`,
  `package.json` y todo `*.yml` / `*.yaml`.
- Excluye las plantillas de Helm (archivos YAML dentro de `templates/` junto a un `Chart.yaml`),
  que no son YAML válido hasta que Helm las procesa.
- Reglas en [Dockerfile](#dockerfile), [systemd](#systemd), [YAML y Kubernetes](#yaml-y-kubernetes)
  y [Dependencias declaradas](#dependencias-declaradas).
- Estado `FAILED` si hay hallazgos bloqueantes (salvo con `--no-fail`).
- No audita los `.env` (eso lo hace `audit`).

**6. Vulnerabilidades en dependencias** (`dependency_vulns`)

- Consulta en OSV las dependencias con versión exacta y los paquetes instalados en el entorno
  virtual del proyecto. Detalle en [`vulns`](#vulns).
- Estados posibles:
  - `OK`: no hay manifiestos ni entornos, o no hay vulnerabilidades bloqueantes.
  - `SKIPPED`: modo sin conexión, OSV no responde, o no hay nada comprobable (todas las
    dependencias usan rangos y no hay entorno ni archivo de bloqueo). En este último caso el
    resumen dice "not checked" en lugar de un "OK" engañoso.
  - `FAILED`: hay vulnerabilidades altas o críticas (salvo con `--no-fail`).
- Una etapa omitida nunca hace fallar el pipeline.

#### Código de salida

`pipeline` devuelve `1` si ocurre cualquiera de estas cosas:

- Hay hallazgos bloqueantes en el análisis estático, en la infraestructura o en las
  vulnerabilidades, y no se usa `--no-fail`.
- Hay al menos un secreto o un archivo ilegible en la etapa de secretos (siempre).

En cualquier otro caso devuelve `0`. Con `--write-baseline` devuelve siempre `0`. Con
`--baseline`, los hallazgos aceptados no cuentan para nada de lo anterior.

#### Informes

En el directorio de informes quedan:

| Archivo          | Contenido                                                              |
|------------------|------------------------------------------------------------------------|
| `pipeline.json`  | Informe completo: etapas, métricas, hallazgos y rutas de los artefactos. Ver [formato](#pipelinejson). |
| `pipeline.html`  | Resumen para el navegador: tabla de etapas y tabla de hallazgos.       |
| `pipeline.sarif` | Hallazgos en SARIF 2.1.0, para GitHub Code Scanning y editores.        |
| `openapi.json`   | Solo si la etapa de documentación encontró rutas.                      |

Los archivos se sobrescriben en cada ejecución.

#### Ejemplos

```bash
agentes pipeline .                                       # proyecto del directorio actual
agentes pipeline ./src -o ./reports                      # informes fuera del proyecto
agentes pipeline . --no-bandit --max-files 500           # proyecto grande, más rápido
agentes pipeline . --offline                             # sin red
agentes pipeline . --no-fail                             # solo los secretos hacen fallar
agentes pipeline . --json | jq '.stages[] | {name, status}'
```

#### Velocidad en proyectos grandes

Lo que más tarda es Bandit (un subproceso por archivo) y, con conexión,
la consulta a OSV. Para acelerar: `--no-bandit`, `--offline` en ejecuciones locales y
`--max-files` para pruebas rápidas. El motor AST por sí solo analiza cientos de archivos en
segundos.

---

### `analyze`

```text
agentes analyze PATH [-o DIR] [--fail-on-high] [--no-bandit] [--offline] [--json] [--limit N]
```

Ejecuta solo tres partes del pipeline: el análisis estático de Python, la auditoría de
infraestructura y dependencias, y la consulta de vulnerabilidades. No busca secretos, no
calcula métricas y no genera OpenAPI.

| Opción               | Por defecto    | Efecto                                                          |
|----------------------|----------------|-----------------------------------------------------------------|
| `PATH`               | (obligatorio)  | Archivo o directorio.                                           |
| `-o`, `--output DIR` | `PATH/reports` | Directorio de informes.                                         |
| `--fail-on-high`     | desactivado    | Devuelve `1` si hay hallazgos altos o críticos.                 |
| `--no-bandit`        | desactivado    | Usa solo el motor AST.                                          |
| `--offline`          | desactivado    | No consulta OSV.                                                |
| `--json`, `--limit`  |                | Ver [opciones comunes](#opciones-comunes).                      |

Escribe `analyze.json` (objetivo y hallazgos) y `analyze.sarif`. **Devuelve `0` aunque haya
hallazgos**, salvo con `--fail-on-high`; si hay hallazgos altos y no se usa la opción, lo
recuerda al final. No admite línea base.

```bash
agentes analyze ./src
agentes analyze app.py -o ./reports --fail-on-high
```

---

### `secrets`

```text
agentes secrets PATH [--json] [--limit N]
```

Busca claves, tokens y contraseñas.

- Con un **archivo**, lo analiza sea cual sea su extensión.
- Con un **directorio**, analiza los `.py` y los archivos de configuración (las mismas
  extensiones que la etapa de secretos del pipeline).

Los valores siempre salen enmascarados: se conservan como mucho los tres primeros caracteres y
el resto se sustituye por `***REDACTED***`; en una URL de conexión se oculta solo la contraseña.

```text
$ agentes secrets .
Secret scan of .
================
Files scanned: 3

Security (1): 1 high
  [HIGH] app/settings.py:1
         Credential inside a connection URL: DB_URL = "postgres://admin:***REDACTED***@db:5432/app"

Values are shown masked. If a secret was ever published, rotate it as well as deleting it.
```

Devuelve `1` si encuentra al menos un secreto o un archivo ilegible.

Este comando no aplica línea base ni excluye ningún archivo del árbol: si el proyecto contiene
una línea base con secretos aceptados, `secrets` puede marcarla (ver
[Solución de problemas](#secrets-marca-la-línea-base)).

```bash
agentes secrets .
agentes secrets .env
agentes secrets ./config --json
```

---

### `vulns`

```text
agentes vulns PATH [--json] [--limit N]
```

Comprueba en [OSV](https://osv.dev) si las dependencias tienen vulnerabilidades conocidas.
**Necesita conexión**: con `--offline` o `AGENTES_OFFLINE=1` termina con `2`.

#### Qué comprueba

Por orden de fiabilidad:

1. **Entornos virtuales del proyecto**: la propia raíz o cualquier subcarpeta directa que
   contenga un `pyvenv.cfg` (por ejemplo `.venv/`). Se leen los paquetes instalados con su
   versión exacta: son los que de verdad se ejecutan.
2. **Manifiestos** del árbol, con su versión exacta:

| Archivo               | Ecosistema | Qué se lee                                             |
|-----------------------|------------|--------------------------------------------------------|
| `requirements*.txt`   | PyPI       | Dependencias fijadas con `==`.                         |
| `pyproject.toml`      | PyPI       | Dependencias del proyecto fijadas con `==`.            |
| `poetry.lock`         | PyPI       | Todas las versiones bloqueadas.                        |
| `Pipfile.lock`        | PyPI       | Todas las versiones bloqueadas.                        |
| `package.json`        | npm        | Dependencias con versión exacta.                       |
| `package-lock.json`   | npm        | Todas las versiones bloqueadas.                        |

Las dependencias declaradas con rangos (`>=`, `<`, `^`, `~`) no se pueden comprobar por sí
solas, porque no se sabe qué versión se instala. Si no hay nada comprobable, el comando lo dice
y devuelve `0`:

```text
[WARN] No dependency was checked: all 4 declared ones use ranges, and there is no installed environment or lock file with exact versions.
Create the project's .venv or a lock file (poetry.lock, Pipfile.lock, pinned requirements) and run it again.
```

#### Resultado

Cada vulnerabilidad es un hallazgo con regla `VULN-<id OSV>` y un mensaje con el paquete, la
versión, el identificador (el CVE si existe), el resumen y la versión que lo corrige:

```text
  [MEDIUM] requirements.txt:1
           requests 2.32.4 — CVE-2026-25645: Requests has Insecure Temp File Reuse in its
           extract_zipped_paths() utility function. Fixed in 2.33.0.
```

La severidad se toma de la base de datos de avisos de GitHub (GHSA): `CRITICAL`, `HIGH`,
`MEDIUM` y `LOW` se mantienen y `MODERATE` pasa a `MEDIUM`. Si el aviso no indica severidad, se
trata como `HIGH`.

Si un rango declarado impide instalar la versión corregida (por ejemplo `urllib3<2` cuando la
corrección está en `2.2.2`), aparece en una sección final:

```text
Constraints that block installing the fix
  - urllib3<2 in pyproject.toml: the fix needs 2.2.2. Raise the upper bound.
```

#### Código de salida

`1` si hay alguna vulnerabilidad alta o crítica; `0` si no, o si no había nada comprobable;
`2` si no hay manifiestos ni entornos, si está activo el modo sin conexión o si OSV no responde.

```bash
agentes vulns .
agentes vulns requirements.txt
agentes vulns package-lock.json --json
```

---

### `audit`

```text
agentes audit PATH|URL [--type TYPE] [--json] [--limit N]
```

Audita un archivo suelto, un directorio o las cabeceras de una URL. El tipo se deduce del
nombre:

| Objetivo                                         | Tipo      | Qué revisa                                                     |
|--------------------------------------------------|-----------|----------------------------------------------------------------|
| `Dockerfile`, `Dockerfile.*`, `*.dockerfile`     | `docker`  | Usuario root, imagen sin versión, `sudo`, `chmod 777`.         |
| `*.service`                                      | `systemd` | Directivas de aislamiento que faltan o están desactivadas.     |
| `requirements*.txt`, `package.json`              | `deps`    | Dependencias sin versión fija.                                 |
| `*.yml`, `*.yaml`                                | `yaml`    | Sintaxis y, en manifiestos `kind: Pod`, el contexto de seguridad. |
| `.env`, `.env.*`, `*.env`                        | `env`     | Depuración activa y claves débiles o por defecto.              |
| `*.log`                                          | `logs`    | Trazas de excepción, errores 5xx, falta de memoria, fallos de autenticación y de conexión. |
| `test_*.py`, `*_test.py`                         | `tests`   | Calidad de la suite de tests.                                  |
| `http://...`, `https://...`                      | `headers` | Cabeceras de seguridad HTTP que faltan.                        |
| Un directorio                                    | varios    | Todo lo anterior salvo suites de tests y URLs, archivo por archivo. |

Las reglas de cada tipo están en el [catálogo](#catálogo-de-reglas).

| Opción         | Efecto                                                                                      |
|----------------|---------------------------------------------------------------------------------------------|
| `--type TYPE`  | Fuerza el tipo: `auto` (por defecto), `docker`, `systemd`, `deps`, `yaml`, `env`, `logs`, `tests` o `headers`. Solo se aplica a un archivo o URL; con un directorio termina con `2`. |

Notas:

- Un archivo cuyo tipo no se reconoce termina con `2` y pide `--type`. Para código Python que
  no es una suite de tests, usa `analyze`.
- **Plantillas de `.env`.** Si el nombre contiene `example`, `sample`, `template`, `dist`,
  `tpl` o `defaults` (`.env.example`, `.env.sample`...), los valores vacíos o de ejemplo son lo
  correcto y no se marcan. Solo se informa, como `LOW`, de `DEBUG` o `TESTING` activados por
  defecto.
- La lectura de un `.env` no exporta nada al entorno del proceso.
- **URLs.** Se hace una petición `GET` con un tiempo de espera de 8 segundos. Las cabeceras se
  revisan aunque el servidor responda con un error 4xx o 5xx.

Devuelve `1` si hay hallazgos altos o críticos.

```bash
agentes audit Dockerfile
agentes audit .env
agentes audit app.log
agentes audit tests/test_api.py
agentes audit https://example.com
agentes audit ./infra
agentes audit mi.conf --type systemd
```

---

### `metrics`

```text
agentes metrics PATH [--json] [--limit N]
```

Métricas de mantenibilidad de un archivo `.py` o de todos los de un directorio (incluidos los
tests). Es informativo: **siempre devuelve `0`** (salvo error de uso, por ejemplo un
directorio sin archivos `.py`).

Muestra, en este orden:

1. **Totales**: archivos, líneas de código, funciones y complejidad ciclomática y cognitiva
   media por función.
2. **Archivos con mayor complejidad** (si hay más de uno), ordenados por complejidad
   ciclomática media.
3. **Funciones más complejas**: las 10 primeras (todas con `--limit 0`), coloreadas según la
   complejidad ciclomática: hasta 5 es simple, de 6 a 10 conviene vigilarla y más de 10 pide
   dividirla.
4. **Hallazgos** [SOLID y de diseño](#solid-y-diseño) y de [rendimiento](#rendimiento), con su
   severidad original (a diferencia del pipeline, donde el rendimiento siempre es `MEDIUM`).
5. **Recomendaciones** de refactor, de dos tipos:
   - Las de promedios (complejidad ciclomática o cognitiva media alta, menos de un 5 % de
     documentación) se valoran sobre todo lo analizado, como los totales, y salen una sola vez.
   - Las de una línea concreta (hallazgos SOLID y de rendimiento) indican el archivo y la línea,
     por ejemplo `[DESIGN SRP - src/app/screens.py:412]`.

   Si hay más que el límite, se indica cuántas quedan sin mostrar. La valoración `[EXCELLENT]`
   solo aparece si no hay ninguna recomendación ni ningún hallazgo, incluidos los archivos que
   no se pudieron analizar.

```text
Metrics for .
=============
Files                          3
Lines of code                  17
Functions                      4
Average cyclomatic complexity  1.5
Average cognitive complexity   0.25

Most complex files
  Lines  Funcs  Cyclom.  Cognit.  File
      4      1      3.0      1.0  calc.py
     12      3      1.0      0.0  app/main.py
      1      0      1.0      0.0  app/settings.py

Most complex functions
  Cyclom.  Cognit.  Function
        3        1  descuento  (calc.py:4)
        1        0  get_user  (app/main.py:11)
        1        0  archive  (app/main.py:16)
        1        0  load_settings  (app/main.py:21)
  Reference: up to 5 is simple, 6 to 10 is worth watching, above 10 calls for splitting it up.

Recommendations
  - [EXCELLENT] The analysed code meets every maintainability, reliability, performance and SOLID
    threshold.
```

**Complejidad ciclomática**: número de caminos independientes de una función (1 más cada
`if`, `for`, `while`, `except` y operador booleano). **Complejidad cognitiva**: cuánto cuesta
leerla; penaliza más el anidamiento que la simple cantidad de ramas.

Con `--json` devuelve `totals`, `files` (por archivo), `functions` (con `cyclomatic` y
`cognitive`), `findings` y `recommendations`.

---

## Generar y corregir

### `generate`

```text
agentes generate [TYPE] [-o OUTPUT] [--force] [opciones del tipo]
```

Sin `TYPE`, lista los tipos disponibles. Cada tipo tiene una salida por defecto, relativa al
directorio actual; `-o` la cambia.

**Nunca sobrescribe.** Si la salida ya existe, se detiene con `2` y pide `--force` o otra ruta
con `-o`. La excepción es `linters`, que conserva los archivos existentes y escribe solo los
que faltan.

#### Opciones

| Opción                    | Por defecto           | Tipos                                    | Efecto                                       |
|---------------------------|-----------------------|------------------------------------------|----------------------------------------------|
| `-o`, `--output OUTPUT`   | según el tipo         | todos                                    | Archivo o directorio de salida.              |
| `--force`                 | desactivado           | todos                                    | Sobrescribe la salida si ya existe.          |
| `--source FILE`        | ninguno               | `openapi`, `swagger`, `docs`, `diagram`, `tests` | Archivo Python de origen (obligatorio en estos tipos). |
| `--service NOMBRE`        | `web`                 | `compose`, `helm`, `k8s`, `openapi`, `swagger` | Nombre del servicio o del chart, o título de la API. |
| `--image IMAGEN`          | `myorg/myapp:1.0.0`   | `compose`, `helm`, `k8s`                 | Imagen de contenedor.                        |
| `--port PORT`           | `8080`                | `compose`, `helm`                        | Puerto del servicio.                         |
| `--mem-limit LÍMITE`      | `512m`                | `compose`                                | Límite de memoria.                           |
| `--cpus N`                | `0.50`                | `compose`                                | Límite de CPU.                               |
| `--domain DOMINIO`        | `example.com`         | `nginx`, `caddy`                         | Dominio del servidor.                        |
| `--csp POLÍTICA`          | `default-src 'self';` | `nginx`, `caddy`                         | Valor de `Content-Security-Policy`.          |
| `--framework`             | `unittest`            | `tests`                                  | `unittest` o `pytest`.                       |
| `--record`                | desactivado           | `tests`                                  | Graba los valores reales ejecutando el módulo. |
| `--naming-convention`     | desactivado           | `openapi`, `swagger`                     | Trata como rutas las funciones `get_`, `post_`, `put_` y `delete_`. |

#### Tipos de infraestructura

**`compose`** (salida: `docker-compose.yml`)

Un servicio de Docker Compose endurecido:

- `read_only: true` con un `tmpfs` en `/tmp`.
- `security_opt: no-new-privileges:true`.
- `mem_limit` y `cpus` (aplican con `docker compose` v2), `mem_reservation: 128m` y un bloque
  `deploy.resources` equivalente para Docker Swarm.
- `restart: unless-stopped`, el puerto publicado y una red propia.
- Con la imagen por defecto, el servicio se construye desde `Dockerfile.hardened` (genéralo con
  `generate dockerfile`). Si indicas `--image`, usa esa imagen en lugar de construir.

```bash
agentes generate compose --service api --image myorg/api:1.2.0 --port 8000 --mem-limit 256m --cpus 0.25
```

**`helm`** (salida: directorio `chart/`)

Un chart con `Chart.yaml`, `values.yaml` y `templates/deployment.yaml`. El contenedor no se
ejecuta como root (`runAsNonRoot`), no puede escalar privilegios
(`allowPrivilegeEscalation: false`) y elimina todas las capabilities (`drop: [ALL]`). Para
decidir si sobrescribe, se comprueba si existe `Chart.yaml` en el destino.

```bash
agentes generate helm -o ./chart --service api --image myorg/api:1.2.0 --port 8000
helm install api ./chart
```

**`k8s`** (salida: `pod.yaml`)

Un manifiesto de Pod llamado `<servicio>-hardened` con:

- `runAsNonRoot: true`, usuario y grupo `10001`, `fsGroup: 10001` y perfil seccomp
  `RuntimeDefault`.
- Por contenedor: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true` y
  `capabilities.drop: [ALL]`.
- Recursos: límites de `500m` de CPU y `512Mi` de memoria; peticiones de `100m` y `128Mi`.

**`dockerfile`** (salida: `Dockerfile.hardened`)

Dockerfile multietapa sobre `python:3.10-slim`: una etapa instala las dependencias de
`requirements.txt` y la final copia el resultado, crea el usuario `appuser` (UID y GID 10001),
le da la propiedad de `/app` y se ejecuta con `USER appuser`. Expone el puerto 8080 y arranca
`python3 main.py`: ajusta la versión de Python, el puerto y el comando a tu aplicación.

**`systemd`** (salida: `app.service`)

Unidad con `User=appuser`, `Restart=on-failure` y estas directivas de aislamiento:
`NoNewPrivileges=true`, `ProtectSystem=strict` (con `ReadWritePaths` para logs y `/tmp`),
`ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`, `ProtectKernelTunables=true`,
`ProtectKernelModules=true` y `CapabilityBoundingSet=` vacío. Ajusta `WorkingDirectory`,
`ExecStart` y `ReadWritePaths` (por defecto apuntan a `/opt/mi_aplicacion`).

**`nginx`** (salida: `nginx.conf`)

Bloque `server` en el puerto 443 con HTTP/2, solo TLS 1.2 y 1.3, cifrados ECDHE con GCM,
`server_tokens off`, seis cabeceras de seguridad (`Content-Security-Policy`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` con
`preload`, `Referrer-Policy` y `Permissions-Policy`) y límites de tamaño de búferes y de cuerpo
(10 MB). **No incluye las directivas `ssl_certificate` y `ssl_certificate_key`**: añádelas con
las rutas de tus certificados.

```bash
agentes generate nginx --domain midominio.com --csp "default-src 'self'; img-src 'self' data:"
```

**`caddy`** (salida: `Caddyfile`)

Lo mismo para Caddy v2: TLS 1.2 y 1.3, las seis cabeceras, eliminación de la cabecera `Server`
y `file_server`. Caddy obtiene los certificados de forma automática.

#### Tipos de CI y calidad

**`github-actions`** (salida: `.github/workflows/devsecops.yml`)

Workflow que se ejecuta en `push` y `pull_request` sobre `main` y `master`, con Python 3.12:
un trabajo de auditoría (ruff para errores de lint y estilo, y Bandit) y un
trabajo de tests (`python -m unittest discover`).

**`gitlab-ci`** (salida: `.gitlab-ci.yml`)

Pipeline con tres etapas: `lint` (flake8 con líneas de 100 caracteres), `test` (unittest) y
`security` (Bandit), con caché de pip.

**`linters`** (salida: directorio actual)

Escribe tres archivos en el directorio indicado:

- `.flake8`: líneas de 100 caracteres y exclusión de entornos y builds.
- `pyproject.toml`: configuración de black (100 caracteres), isort (perfil black) y mypy
  (`disallow_untyped_defs`).
- `.eslintrc.json`: `eslint:recommended` con `eqeqeq` y `curly` como errores.

Los archivos que ya existen se conservan (con un aviso), así que no pisa tu `pyproject.toml`;
`--force` los reemplaza.

#### Tipos de documentación

**`openapi`** (salida: `openapi.json`)

Especificación OpenAPI 3.0.3 a partir de un archivo Python, sin importarlo ni ejecutarlo:

- Reconoce las rutas declaradas con decoradores de Flask (`@app.route`) y FastAPI (`@app.get`,
  `@router.post`...).
- Con `--naming-convention`, también las funciones con prefijo `get_`, `post_`, `put_` o
  `delete_`. Si no hay decoradores pero sí funciones con esos prefijos, el comando lo sugiere.
- Las anotaciones de tipo se convierten en parámetros y esquemas.
- Si no hay ninguna ruta, la especificación queda vacía y se avisa: no se inventa ningún
  endpoint.
- Formato según la salida: `.yaml` o `.yml` escribe YAML; `.json` escribe JSON; cualquier otra
  ruta se trata como directorio y se escribe `openapi.json` dentro.
- `--service` fija el título de la API.

```bash
agentes generate openapi --source app.py
agentes generate openapi --source app.py -o openapi.yaml --service "API de pedidos"
```

**`swagger`** (salida: `swagger_ui.html`)

Página HTML con Swagger UI y la especificación incluida. Los recursos de Swagger UI se cargan
desde un CDN, así que necesita conexión para mostrarse.

**`docs`** (salida: `DOCS.md`)

Manual en Markdown con los módulos, clases y funciones del archivo y sus docstrings.

**`diagram`** (salida: `diagrama.md`)

Diagrama de clases en Mermaid: cada clase con sus primeros cinco métodos (y una nota con
cuántos más tiene) y las relaciones de herencia. Si la salida termina en `.md`, se envuelve en
un bloque ` ```mermaid ` con un título, listo para verse en GitHub.

#### Tipo `tests`

```bash
agentes generate tests --source app.py                       # unittest, test_app.py junto a app.py
agentes generate tests --source app.py --framework pytest
agentes generate tests --source app.py --record
```

Genera una suite con casos nominales, de borde y de error por cada función pública. La salida
por defecto es `test_<fuente>.py` en el mismo directorio que la fuente.

- **unittest** (por defecto): una clase `TestCase` con un test nominal y, si la función valida
  su entrada, un test de entrada inválida con `assertRaisesRegex`.
- **pytest**: tests parametrizados con valores de borde y casos adversarios. Si
  [Hypothesis](https://hypothesis.readthedocs.io) está instalado, añade tests de propiedades;
  si no, la suite funciona igual.

**De dónde salen los valores esperados.** El generador no adivina qué devuelve una función a
partir de su nombre. Cada aserción sale de una de estas fuentes:

1. **El cuerpo de la función**, cuando es puro (asignaciones, `if`, `return` y `raise` sobre
   los parámetros y unos pocos builtins como `len` o `abs`). Se calcula sin ejecutar el código.
   Ejemplo real:

   ```python
   def descuento(precio: float, porcentaje: float) -> float:
       if porcentaje < 0 or porcentaje > 100:
           raise ValueError("porcentaje fuera de rango")
       return precio - precio * porcentaje / 100
   ```

   genera:

   ```python
   def test_descuento_happy_path(self):
       result = descuento(100.0, 10.0)
       # Value computed from the function body.
       self.assertAlmostEqual(result, 90.0)

   def test_descuento_invalid_input(self):
       with self.assertRaisesRegex(ValueError, r"porcentaje\ fuera\ de\ rango"):
           descuento(100.0, -1)
   ```

2. **La ejecución real**, con `--record`. Importa el módulo en un proceso aparte y graba lo que
   devuelve cada función. Son tests de caracterización: fijan el comportamiento actual, sea
   correcto o no, así que conviene revisarlos. Se omiten las funciones con E/S o resultados no
   deterministas.
3. **Solo lo verificable**, en el resto de casos: el tipo anotado, que devuelva `None` o que no
   devuelva `None`.

**De dónde salen los valores de ejemplo.** Solo se pasan los argumentos obligatorios; los que
tienen valor por defecto se quedan con el suyo. Para cada uno, de más a menos fiable:

1. **Su anotación de tipo**, incluidos los contenedores (`List[int]` recibe `[1]`,
   `Dict[str, int]` recibe `{"sample": 1}`), `Optional`, `Union`, `Literal`, los alias de tipo y
   tipos de la biblioteca estándar como `Path`, `Decimal` o `datetime`. Las clases del módulo se
   construyen con valores de su tipo: las dataclasses y `NamedTuple` con sus campos
   obligatorios, los enums con su primer miembro (`list(Color)[0]`).
2. **Cómo lo usa el cuerpo**: si se recorre, se indexa, se le llama `.lower()` o se le suma un
   número.
3. **Su nombre** (`precio` recibe `100.0`, `email` recibe `"user@example.com"`, `path` recibe
   `"/tmp/test.txt"`...).

Los valores de 2 y 3 son supuestos, y el test lo dice en un comentario. Si no encajan con la
función (`TypeError` o `AttributeError`), el test se omite con el motivo en vez de fallar: no
saber construir un buen ejemplo no es un fallo del código. Un parámetro anotado con un tipo que
no se sabe construir no recibe un valor inventado de otro tipo: su test se omite y pide
completarlo a mano.

Los métodos se llaman sobre un objeto creado con esos mismos valores; los `@staticmethod` y
`@classmethod`, sobre la clase, y las propiedades se leen sin llamarlas. Las clases abstractas y
los `Protocol` no se instancian. La suite importa el módulo por su nombre completo dentro del
paquete (`from app.servicios.pagos import ...`) y añade su raíz a `sys.path` relativa a la
suite, así que funciona desde cualquier directorio y con imports relativos.

**Qué no se prueba.** Las funciones que leen `sys.argv` o terminan el proceso (`sys.exit`,
`raise SystemExit`) se prueban por su línea de órdenes: su test se omite y lo dice. Los tests de
entrada `None` solo se generan si el cuerpo usa el parámetro sin comprobarlo y su tipo no admite
`None`.

**Efectos secundarios.** Todo lo que tiene efectos se sustituye por dobles con `autospec`, así
que los tests generados no escriben, borran, mueven, lanzan procesos ni se conectan a la red:

- Abrir, escribir, borrar, mover o renombrar archivos (`open`, `os.remove`, `shutil.rmtree`,
  `Path.unlink`, `Path.write_text`...) y cambiar permisos.
- Procesos (`subprocess`, `os.system`) y red (`requests`, `urllib`, `socket`, `http.client`,
  `httpx`, `aiohttp`).

Se detectan importen como importen (`import shutil as sh`, `from os import remove as rm`) y se
propagan: si una función llama a un helper del módulo (o a un método de `self`) que borra, su
test también sustituye esa llamada. Las excepciones de esos helpers también se propagan: el
test de valores límite acepta la que lanza un helper privado al validar.

- `open()` se sustituye por un archivo vacío (`mock_open(read_data="")`): un doble genérico
  devolvería otro doble en `read()` y un parser podría no terminar nunca.
- Con la E/S sustituida no se afirma el valor devuelto, que depende de los dobles. Si la función
  no puede procesar sus datos simulados (`json.loads` de un doble), el test se omite. El test de
  fallo de E/S se omite si la función no llega a usarla con los valores de ejemplo.
- Además, cada test corre sin red y con la entrada estándar vacía. Una llamada de red que el
  análisis no ve, porque la hace otro módulo, falla con `OSError` como si no hubiera red, y quien
  lea la entrada estándar la encuentra vacía en vez de quedarse esperando. Las conexiones a
  `localhost` siguen funcionando.

**Seguridad de `--record`.** Mientras graba, bloquea escribir, borrar, mover, lanzar procesos y
abrir conexiones, aunque ocurran en otro módulo. Si una función lo intenta, no se graba su
resultado y su test sustituye esas llamadas. No escribe `__pycache__` en el proyecto y avisa si
el módulo intenta escribir al importarse. No es un sandbox para código hostil: es una red de
seguridad para código normal.

Después de generar, el comando sugiere el siguiente paso (`agentes test test_app.py` o
`pytest test_app.py`).

---

### `fix`

```text
agentes fix FILE [--dry-run] [--json] [--limit N]
```

Fija las versiones de un `requirements.txt` y revisa las vulnerabilidades resultantes.
**Necesita conexión** (consulta PyPI y OSV); con `--offline` termina con `2`.

| Línea original          | Resultado                                                                 |
|-------------------------|---------------------------------------------------------------------------|
| `flask`                 | `flask==<última versión publicada>`                                       |
| `flask>=2.0`            | `flask==<última versión que cumple >=2.0>`                                |
| `flask~=2.2`            | `flask==<última 2.x que cumple ~=2.2>`                                    |
| `flask>2.0`             | `flask==<última versión que cumple >2.0>`                                 |
| `flask==2.0.0`          | Sin cambios (pero se revisan sus vulnerabilidades).                       |

La versión elegida es la más reciente que cumple lo declarado, es estable (sin versiones
preliminares), no está retirada (*yanked*) y se puede instalar en tu versión de Python. Los
marcadores de entorno (`; python_version < "3.11"`) y los comentarios se conservan.

Lo que no se puede resolver (paquete inexistente, ninguna versión cumple el rango) se deja
como está y se explica en la sección "Unchanged" (sin cambios). Nunca se inventa una versión.

Después consulta en OSV todas las versiones fijadas, nuevas y antiguas, y lista las
vulnerabilidades con la versión que las corrige. Las versiones que ya estaban fijadas no se
cambian: actualízalas a mano a la versión corregida.

```text
$ agentes fix requirements.txt --dry-run
Proposed changes in requirements.txt
====================================

  - flask>=2.0
  + flask==3.1.3
  ...
```

Las versiones concretas dependen de lo publicado en PyPI en el momento de ejecutarlo.

| Opción      | Efecto                                                    |
|-------------|-----------------------------------------------------------|
| `--dry-run` | Muestra los cambios sin modificar el archivo.             |

Devuelve `1` si alguna de las versiones resultantes tiene una vulnerabilidad alta o crítica.

---

## Probar

### `test`

```text
agentes test FILE [-v] [--json] [--limit N]
```

Ejecuta una suite **unittest** y evalúa sus resultados, su cobertura estimada y su calidad.

- Ejecuta el archivo con el cargador de unittest, en el mismo proceso, añadiendo su directorio
  al `sys.path` para que pueda importar el módulo que prueba. Esto ejecuta el código del
  proyecto.
- **Cobertura estimada**: qué funciones públicas del módulo probado tienen algún test, según
  los nombres. Es una estimación por nombres, no una medición de líneas ejecutadas; para eso usa
  `coverage.py`.
- **Calidad de la suite**: aplica las reglas de [calidad de tests](#calidad-de-suites-de-tests).

```text
Tests in test_calc.py
=====================
Run        2
Passed     2
Failed     0
Errors     0
Skipped    0
Pass rate  100.0%
Duration   0.001 s

Estimated coverage
  1 of 1 public functions in 'calc' have at least one test (100.0%).
  This is an estimate based on names, not a measurement of executed lines.

[OK] All tests pass.
```

| Opción            | Efecto                                                     |
|-------------------|------------------------------------------------------------|
| `-v`, `--verbose` | Muestra la traza completa de cada test que falla (por defecto, solo la última línea). |
| `--limit N`       | Máximo de hallazgos de calidad listados.                    |

Devuelve `1` si algún test falla o da error, o si no se encontró ningún test. Para suites de
pytest, usa `pytest` directamente; `agentes audit test_x.py` revisa la calidad de cualquier
suite sin ejecutarla.

---

### `testability`

```text
agentes testability FILE [--matrix] [--json] [--limit N]
```

Detecta qué dificulta probar un módulo, sin ejecutarlo: estado global mutable, dependencias
creadas dentro de las funciones, E/S mezclada con lógica y llamadas no deterministas. Las
reglas están en [Testabilidad](#testabilidad).

Con `--matrix` añade una matriz de escenarios sugeridos por función, en hasta cuatro categorías:

- `HAPPY PATH`: entrada nominal y contrato de salida.
- `BOUNDARY / EDGE CASE`: cero, `-1`, cadenas vacías, Unicode, `NaN` o infinito, colecciones
  vacías.
- `ADVERSARIAL / ERROR`: entradas nulas o de tipo incorrecto, con error controlado esperado.
- `CONCURRENCY / I/O FAULT`: solo en funciones que hacen E/S o son `async`. La E/S se simula
  para que falle (o la corrutina agota su tiempo) y el error debe propagarse tras la limpieza.

```text
Suggested test scenarios (17)
  Function       Category                 Scenario and expected result
  get_user       HAPPY PATH               nominal_valid: Runs without raising and returns exactly
                                          the contracted output.
  get_user       BOUNDARY / EDGE CASE     boundary_zero: Handles the extreme boundary (0, -1, empty
                                          or Unicode) without failing silently.
  ...
```

Es informativo: siempre devuelve `0`.

---

### `contract`

```text
agentes contract URL [--method M] [--status N] [--schema FILE] [--strict]
                     [--max-ms MS] [--timeout S] [--header 'Name: value'] [--body JSON] [--json]
```

Hace una petición HTTP real a un endpoint y comprueba su contrato.

| Opción                   | Por defecto | Efecto                                                                  |
|--------------------------|-------------|-------------------------------------------------------------------------|
| `URL`                    |             | Debe empezar por `http://` o `https://`.                                 |
| `--method`               | `GET`       | Método HTTP.                                                            |
| `--status CODE`        | `200`       | Código de estado esperado.                                              |
| `--schema FILE`       | ninguno     | JSON con los tipos esperados en la respuesta.                           |
| `--strict`               | desactivado | Con `--schema`, rechaza los campos que no estén en el esquema.          |
| `--max-ms MS`            | `500`       | Tiempo de respuesta máximo en milisegundos.                             |
| `--timeout S`            | `5`         | Tiempo de espera de la conexión en segundos.                            |
| `--header 'Name: value'` | ninguna   | Cabecera a enviar. Se puede repetir.                                    |
| `--body JSON`            | ninguno     | Cuerpo de la petición. Si es JSON válido se envía como JSON; si no, como texto. |

Comprobaciones que se muestran: `Status Code`, `SLA Latencia` y, con `--schema`,
`Esquema JSON`. Si la petición no se puede completar, aparece `HTTP Request` como fallo.

**Formato del esquema.** Un JSON con el tipo de cada campo:

```json
{"id": "int", "name": "str", "tags": ["str"], "owner": {"email": "str"}}
```

- Tipos admitidos: `str` (o `string`), `int` (`integer`), `float` (`number`), `bool`
  (`boolean`), `list` (`array`) y `dict` (`object`).
- Una lista se declara con un solo tipo: `["str"]` exige que todos los elementos sean texto.
- Un objeto anidado se declara con otro objeto.
- La comparación es estricta: `true` no cuenta como `int`, y un número entero como `10` no
  cuenta como `float`.

```bash
agentes contract https://api.example.com/health
agentes contract https://api.example.com/users/1 --schema usuario.json --max-ms 300
agentes contract https://api.example.com/users --method POST \
  --header "Authorization: Bearer $TOKEN" --body '{"name": "Ana"}' --status 201
```

Devuelve `0` si se cumplen todas las comprobaciones y `1` si falla alguna.

---

## Operar

### `health`

```text
agentes health [--disk PATH] [--min-free-mb MB] [--tcp HOST:PORT] [--http URL]
               [--expect-status CODE] [--json]
```

Comprueba el estado del sistema con varias sondas:

| Sonda   | Opción                        | Por defecto | Falla si                                              |
|---------|-------------------------------|-------------|-------------------------------------------------------|
| Disco   | `--disk`, `--min-free-mb`     | `/`, 100 MB | El espacio libre es menor que el mínimo o la ruta no existe. |
| Carga   | (siempre)                     |             | Nunca: es informativa (media del último minuto).      |
| TCP     | `--tcp HOST:PORT`           | sin sonda   | No se puede abrir la conexión en 2 segundos.          |
| HTTP    | `--http URL`, `--expect-status` | sin sonda, 200 | No responde en 3 segundos o el código no es el esperado. |

Estado resultante:

- `HEALTHY`: todas las sondas están bien.
- `DEGRADED`: falla una sonda externa (TCP o HTTP), pero el disco está bien.
- `UNHEALTHY`: falla el disco.

Un 4xx o un 5xx es una respuesta, no una caída: con `--expect-status 503` (un servicio en
mantenimiento, por ejemplo) la sonda HTTP pasa si el servidor responde 503.

Si `/` no tiene espacio libre aparente (por ejemplo, en un contenedor con el sistema de
archivos de solo lectura), se mide el disco del directorio actual.

```bash
agentes health
agentes health --tcp localhost:5432 --http https://example.com/healthz
agentes health --disk /var/lib/docker --min-free-mb 2048 --json
```

Devuelve `0` solo si el estado es `HEALTHY`.

---

### `sla`

```text
agentes sla --total N --errors N [--max-rate PCT] [--json]
```

Calcula la tasa de errores (`errors / total * 100`) y la compara con el máximo permitido
(`--max-rate`, por defecto 5 %). Hay alerta si la tasa **supera** el máximo; igualarlo no
alerta.

```text
$ agentes sla --total 12000 --errors 340
[OK] Error rate 2.83%: within the 5.0% limit.
```

Devuelve `1` si hay alerta. Con `--total 0` no hay tasa que evaluar y devuelve `0`. Si
`--errors` es negativo o mayor que `--total`, termina con `2`.

---

### `serve`

```text
agentes serve [--host HOST] [--port PORT]
```

Levanta un servidor HTTP con dos endpoints (por defecto en `127.0.0.1:9100`):

| Ruta                     | Respuesta                                                                       |
|--------------------------|---------------------------------------------------------------------------------|
| `/metrics`               | Métricas en formato de texto de Prometheus (`text/plain; version=0.0.4`).       |
| `/healthz` (o `/health`) | JSON con el resultado de las sondas de `health`. Código `200` si el estado es `HEALTHY` y `503` en cualquier otro caso. |
| Cualquier otra           | `404` con un JSON que lista las rutas válidas.                                  |

Métricas expuestas:

| Métrica                     | Tipo    | Significado                                                |
|-----------------------------|---------|------------------------------------------------------------|
| `app_requests_total`        | counter | Peticiones atendidas por el servidor.                      |
| `app_requests_errors_total` | counter | Peticiones con respuesta `404` o `503`.                    |
| `app_uptime_seconds`        | gauge   | Segundos desde que arrancó el proceso.                     |

La sonda de disco de `/healthz` usa un mínimo de 1 MB. Al escuchar en todas las interfaces
(`--host 0.0.0.0` o `::`) avisa de que el servidor es accesible desde la red. Si el puerto está
ocupado, termina con `2` y sugiere otro. Se detiene con Ctrl+C. El nombre anterior,
`serve-sre`, sigue funcionando.

Configuración de Prometheus:

```yaml
scrape_configs:
  - job_name: agentes
    static_configs:
      - targets: ["localhost:9100"]
```

Para probarlo en un contenedor endurecido (solo lectura, `no-new-privileges`, 256 MB y media
CPU):

```bash
docker compose -f docker-compose.demo.yml up --build
curl http://localhost:9100/metrics
```

---

## Utilidades

### `password`

```text
agentes password check|hash|verify [HASH] [--stdin] [--offline] [--json]
```

La contraseña se pide de forma interactiva y sin mostrarla, para que no quede en el historial
del shell. En scripts, `--stdin` la lee de la entrada estándar (una línea).

#### `password check`

Puntúa la contraseña de 0 a 6 y la busca en filtraciones conocidas.

```text
$ agentes password check --offline
Password (not echoed):
[FAIL] Password is weak (2 of 6 points).
  - It is based on a very common password ('password'): one of the first an attacker tries.
Known breaches (Have I Been Pwned): not checked (no connection or --offline mode).
```

**Cómo se puntúa:**

1. **Composición** (hasta 6 puntos): 2 por 12 o más caracteres (1 si tiene entre 8 y 11) y 1
   por cada tipo presente: mayúsculas, minúsculas, números y símbolos.
2. **Frases largas**: con 16 caracteres o más la puntuación mínima es 5, y con 20 o más es 6,
   aunque no tenga símbolos ni números.
3. **Penalizaciones** por lo que un atacante prueba primero:
   - Base muy conocida, también con sustituciones (`P4ssw0rd`, `Adm1n`, `Qwerty2024!`):
     máximo 2 puntos.
   - Secuencia de teclado o alfabética de 4 o más caracteres (`qwer`, `1234`, `abcd`): -2.
   - Repeticiones (`aaaa`, `abcabc`): -1, y máximo 1 punto si es un bloque corto repetido.
   - Un año entre 1950 y 2049: -1.

| Puntos | Valoración                |
|--------|---------------------------|
| 6      | `strong` (fuerte)         |
| 5      | `acceptable` (aceptable)  |
| 0 a 4  | `weak` (débil)            |

`Password123!` cumple todas las reglas de composición y se marca como débil.

Además consulta [Have I Been Pwned](https://haveibeenpwned.com/Passwords) por k-anonimato: solo
se envían los 5 primeros caracteres del hash SHA-1, nunca la contraseña. Devuelve `0` si la
contraseña es aceptable o fuerte y no aparece en filtraciones; `1` en otro caso.

#### `password hash`

Pide la contraseña dos veces y escribe el hash en la salida estándar (y solo el hash, para
poder capturarlo). Los avisos (contraseña débil, filtrada o uso de PBKDF2) van a la salida de
errores.

| Motor  | Cuándo                                | Formato del hash                                      |
|--------|---------------------------------------|-------------------------------------------------------|
| Argon2 | Con `argon2-cffi` instalado           | `argon2:$argon2id$v=19$...`                           |
| bcrypt | Con `bcrypt` y sin `argon2-cffi`      | `bcrypt:$2b$12$...`                                   |
| PBKDF2 | Sin ninguno de los dos                | `pbkdf2:sha256:600000:<sal en base64>:<hash en base64>` |

PBKDF2-HMAC-SHA256 usa 600 000 iteraciones, el mínimo que recomienda OWASP, y una sal
aleatoria de 16 bytes.

```bash
agentes password hash > hash.txt
```

#### `password verify`

```bash
agentes password verify 'argon2:$argon2id$v=19$m=65536,t=3,p=4$...'
```

Pon el hash entre comillas simples para que el shell no interprete los `$`. Devuelve `0` si la
contraseña coincide y `1` si no. La comparación es en tiempo constante. Si el hash es de PBKDF2
con menos iteraciones de las recomendadas, o de PBKDF2 cuando hay Argon2 o bcrypt disponibles,
avisa de que conviene regenerarlo. Para verificar un hash de Argon2 o bcrypt hace falta tener
instalado el paquete correspondiente.

---

### `demo`

```text
agentes demo AGENT|all
```

Ejecuta la demostración de un agente (`defensive`, `quality`, `hardening`, `refactor`, `qa`,
`sre`, `devops` o `docs`) con datos de ejemplo; `all` las ejecuta todas. `agentes qa` equivale
a `agentes demo qa`.

Las demos escriben archivos de muestra (informes, tests generados, configuraciones). Dónde:

1. Si `AGENTES_WORKDIR` está definida, en `$AGENTES_WORKDIR/<agente>`.
2. En un clon del repositorio, junto al `main.py` del agente (esos archivos están en
   `.gitignore`).
3. En una instalación de solo lectura, en `./<agente>` dentro del directorio actual.

```bash
AGENTES_WORKDIR=/tmp/agentes-demo agentes demo all
```

### `list`

Lista los ocho agentes con su paquete y una descripción.

### `doctor`

Revisa la instalación: versión de Python, PyYAML, Bandit, argon2-cffi, bcrypt y pytest, el
motor de hashing activo, dónde escriben las demos y si el color está activo. Ver
[Comprobar la instalación](#comprobar-la-instalación). Con `--json` devuelve los mismos datos
estructurados.

### `help`

`agentes help` muestra la pantalla de inicio con todos los comandos; `agentes help COMMAND`
equivale a `agentes COMMAND -h`.

---

## Catálogo de reglas

Cada tabla indica la condición que dispara la regla, la severidad y observaciones. Los mensajes
exactos aparecen en inglés en la salida.

### Análisis estático (motor AST)

Regla en los informes: `SAST-<LEVEL>` (por ejemplo `SAST-HIGH`).

| Condición                                                                  | Severidad | Observaciones                                       |
|----------------------------------------------------------------------------|-----------|-----------------------------------------------------|
| Llamada a `eval()` o `exec()`                                              | CRITICAL  |                                                     |
| `pickle.loads()`                                                           | CRITICAL  | Deserialización de datos no confiables.             |
| `os.system()` u `os.popen()`                                               | CRITICAL  | Inyección de comandos.                              |
| `subprocess.Popen/run/call` con `shell=True`                               | HIGH      |                                                     |
| `yaml.load()` sin `SafeLoader` ni `CSafeLoader`                            | HIGH      | Usa `yaml.safe_load`.                               |
| `execute()` o `executemany()` con SQL construido con `+`, `%`, f-string o `.format` | HIGH | Usa parámetros de la consulta.                 |
| `requests` o `httpx` con `verify=False`                                    | HIGH      | TLS sin verificar.                                  |
| Secreto escrito en el código: asignación, anotación, clave de diccionario o argumento con nombre (`password=`, `api_key=`, `token`...) | HIGH | No se aplica en archivos de test. Ignora valores de menos de 8 caracteres, vacíos, `<...>`, `$VAR`, `{...}` y rellenos como `changeme`, `your-...`, `example`, `dummy`, `xxxx`. |
| `random.*` para generar material sensible (variables con `password`, `token`, `secret`, `nonce`, `salt`, `otp`...) | HIGH | Usa el módulo `secrets`. |
| `except:` sin tipo                                                         | HIGH      | Captura también `SystemExit` y `KeyboardInterrupt`. |
| `except Exception: pass` (o `...`)                                         | MEDIUM    | Calibrado: fiabilidad, no seguridad.                |
| `except Exception:` que descarta el error                                  | MEDIUM    | No se marca si relanza (`raise`) o registra la traza (`logger.exception`, `exc_info=True`). |
| `except Exception as e:` que usa `e` (lo informa o lo guarda)              | LOW       | Habitual en una frontera: CLI, SDK, hilo.           |
| `hashlib.md5()` o `hashlib.sha1()` sin `usedforsecurity=False`             | MEDIUM    | Si no protege nada (caché, checksums), pásale `usedforsecurity=False`. |
| `requests` o `httpx` sin `timeout`                                         | MEDIUM    | Riesgo de bloqueo indefinido.                       |
| `urllib.request.urlopen` sin `timeout`                                     | MEDIUM    | Se resuelve el import: un `urlopen` de otra biblioteca no cuenta. |
| Llamada bloqueante (`requests`, `urlopen`, `time.sleep`) dentro de `async def` | MEDIUM |                                                     |
| `open()` fuera de un `with`                                                | MEDIUM    | No se marca si se cierra en un `finally`, en todos los `except` y el `else`, o con `ExitStack.enter_context`. |
| `open()` con una ruta construida con f-string, `+` o `%`                   | MEDIUM    | Valida la ruta contra *path traversal*.             |
| `os.path.exists()` o `isfile()` seguido de `open()` para escribir sobre la misma variable | MEDIUM   | Condición de carrera TOCTOU. Leer después de comprobar no se marca. |
| `render` o `from_string` de Jinja                                          | MEDIUM    | Revisa el autoescape.                               |
| Función con más de 5 argumentos                                            | MEDIUM    | Sin contar `self` y `cls`.                          |
| Argumento por defecto mutable (lista, diccionario o conjunto)              | MEDIUM    | Usa `None`.                                         |
| Función pública sin docstring                                              | LOW       | No se aplica en archivos de test ni a `_privadas`.  |
| `assert` fuera de tests                                                    | LOW       | `python -O` elimina los `assert`.                   |

Se consideran archivos de test `test_*.py`, `*_test.py` y `conftest.py`.

**Bandit.** Si está instalado, sus hallazgos se añaden con el prefijo `[bandit]` y su propia
severidad. Consulta la [documentación de Bandit](https://bandit.readthedocs.io) para su lista
de reglas.

**Fusión y calibración.** Bandit, el motor AST y el auditor SOLID a veces detectan lo mismo en
la misma línea. Esos hallazgos se agrupan por tema (excepciones silenciadas, captura amplia,
hash débil, `eval`/`exec`, shell, `pickle`, `yaml.load`, `assert`, SQL) y se funden en uno: se
conserva el mensaje del motor AST, la severidad más grave del grupo y una nota "Also detected
by" (también detectado por). Después se calibra la severidad por tema: silenciar excepciones y MD5/SHA-1 quedan en
`MEDIUM` y `assert` en `LOW`; `eval`, `pickle` y `shell=True` mantienen la suya.

### Secretos

Regla: `SECRET`. Todos los secretos son `HIGH`. Un archivo ilegible genera `SECRET-SCAN-ERROR`
con nivel `ERROR`.

**Patrones de proveedor** (prácticamente sin falsos positivos, se aplican en todos los
archivos, también en tests):

| Proveedor o tipo               | Forma reconocida                                         |
|--------------------------------|----------------------------------------------------------|
| AWS                            | Claves `AKIA...` y `ASIA...` (20 caracteres) y claves secretas de 40 caracteres asignadas a una variable `aws_*secret*`. |
| GitHub                         | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` y `github_pat_`.  |
| Slack                          | Tokens `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` y webhooks `hooks.slack.com/services/...`. |
| Stripe                         | `sk_live_`, `sk_test_`, `rk_live_` y `rk_test_`.         |
| Google                         | Claves de API `AIza...`.                                 |
| Anthropic                      | `sk-ant-...`.                                            |
| OpenAI                         | `sk-...` (20 o más caracteres).                          |
| SendGrid                       | `SG.xxx.yyy`.                                            |
| npm, PyPI, GitLab              | `npm_...`, `pypi-...` y `glpat-...`.                     |
| Clave privada                  | Cabecera `-----BEGIN ... PRIVATE KEY-----`.              |
| JWT                            | Tres segmentos base64url que empiezan por `eyJ`.         |
| Token tipo Discord             | Tres segmentos de 24, 6 y 27 caracteres.                 |
| URL de conexión                | `postgres://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://` o `ftp://` con usuario y contraseña. |
| Cabecera Authorization         | `Authorization` o `Proxy-Authorization` con `Basic` o `Bearer` y un valor de 16 o más caracteres. |

**Patrones genéricos**: una clave con nombre de credencial (`api_key`, `secret`, `password`,
`passwd`, `passphrase`, `token`, `auth_token`, `credential`, `access_key`, `client_secret`,
`private_key` y variantes) asignada a un valor entre comillas, en sintaxis de Python, JSON,
YAML o similar. Para evitar falsos positivos, los genéricos:

- No se aplican en archivos de test.
- Ignoran los valores de menos de 8 caracteres, vacíos, `<...>`, `{{...}}`, `%s`, `$VAR` o
  `${VAR}`, los que empiezan por `your-`, `my-` o `tu-`, los que contienen `example`,
  `placeholder`, `changeme`, `dummy`, `sample`, `fake`, `redacted`, `todo`... y los valores
  `none`, `null`, `true`, `false`, `test` o `demo`.
- Ignoran las claves que nombran un campo (`password_field`, `token_name`, `secret_label`...)
  y las que tienen el mismo valor que su nombre.

En todos los casos se saltan las líneas de comentario (`#`, `//`, `-- `, `;`, `/*`, `* `) y se
informa de un solo hallazgo por línea, el del patrón más específico.

### Dockerfile

Regla: `DOCKERFILE`.

| Condición                                              | Severidad | Línea |
|--------------------------------------------------------|-----------|-------|
| No hay ninguna instrucción `USER` con un usuario distinto de root | HIGH | 0 |
| `USER root` o `USER 0`                                 | HIGH      | sí    |
| `USER` sin usuario                                     | HIGH      | sí    |
| `FROM` sin imagen                                      | HIGH      | sí    |
| `sudo` o `chmod 777`                                   | HIGH      | sí    |
| `FROM` con `:latest` o sin etiqueta de versión         | MEDIUM    | sí    |

### systemd

Regla: `SYSTEMD`. Se ignoran las líneas comentadas: una directiva comentada no protege nada.

| Directiva          | Valor esperado     | Severidad si falta o está desactivada |
|--------------------|--------------------|---------------------------------------|
| `NoNewPrivileges`  | `true`             | HIGH                                  |
| `ProtectSystem`    | cualquiera activo (`strict`, `full`, `true`) | MEDIUM         |
| `ProtectHome`      | `true`             | MEDIUM                                |
| `PrivateTmp`       | `true`             | LOW                                   |

Se considera desactivada con `false`, `no`, `off`, `0` o vacía.

### YAML y Kubernetes

| Condición                                                        | Regla     | Severidad |
|------------------------------------------------------------------|-----------|-----------|
| YAML que PyYAML no puede leer, con la línea del error            | `YAML`    | HIGH      |
| Pod sin `spec.securityContext.runAsNonRoot: true`                | `K8S-POD` | HIGH      |
| Contenedor sin `allowPrivilegeEscalation: false`                 | `K8S-POD` | HIGH      |
| Contenedor sin `readOnlyRootFilesystem: true`                    | `K8S-POD` | MEDIUM    |
| Contenedor sin `capabilities.drop: [ALL]`                        | `K8S-POD` | MEDIUM    |

Una tabulación solo es un error donde YAML no la admite (en la indentación o como separador); en
comentarios, entre comillas o dentro de un bloque literal es válida.

El contexto de seguridad se revisa en los documentos de tipo `Pod` (regla `K8S-POD`) y en los
que crean pods: `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `ReplicationController`,
`Job` y `CronJob` (regla `K8S-WORKLOAD`). En un archivo con varios documentos se revisa cada uno.

### Cabeceras HTTP

Regla: `HTTP-HEADERS`. Se marca cada cabecera que falta:

| Cabecera                    | Severidad | Valor recomendado                                    |
|-----------------------------|-----------|------------------------------------------------------|
| `Content-Security-Policy`   | HIGH      | `default-src 'self'; script-src 'self'; object-src 'none';` |
| `X-Frame-Options`           | HIGH      | `DENY`                                               |
| `X-Content-Type-Options`    | MEDIUM    | `nosniff`                                            |
| `Strict-Transport-Security` | MEDIUM    | `max-age=31536000; includeSubDomains; preload`       |
| `Referrer-Policy`           | MEDIUM    | `strict-origin-when-cross-origin`                    |
| `Permissions-Policy`        | MEDIUM    | `geolocation=(), microphone=(), camera=()`           |

### Archivos `.env`

Regla: `ENV`.

| Condición                                                                 | Severidad |
|---------------------------------------------------------------------------|-----------|
| `DEBUG` o `TESTING` con `true`, `1` o `yes`                                | HIGH      |
| Clave que contiene `secret`, `key`, `token` o `password` con valor `admin`, `123456`, `secret`, `changeme`, `default` o `root` | HIGH |
| La misma clave con un valor de menos de 16 caracteres                      | MEDIUM    |

Los valores vacíos se consideran sin definir y no se marcan. En plantillas
(`.env.example`...) solo se informa de `DEBUG`/`TESTING` activados, como `LOW`.

### Logs

Regla: `LOG`. Se informa del primer patrón que coincide en cada línea, con un fragmento de
hasta 80 caracteres.

| Patrón                                                                 | Severidad |
|------------------------------------------------------------------------|-----------|
| `Traceback (most recent call last)`                                    | CRITICAL  |
| `MemoryError`, `OutOfMemoryError` u `Out of memory`                    | CRITICAL  |
| Respuesta HTTP 5xx (`HTTP/1.1" 500`...)                                 | HIGH      |
| `ConnectionRefusedError`, `DatabaseConnectionError` o `TimeoutError`   | HIGH      |
| `Authentication failed`, `Invalid password` o `Failed login`           | MEDIUM    |

### Dependencias declaradas

| Archivo             | Condición                                 | Regla      | Severidad |
|---------------------|-------------------------------------------|------------|-----------|
| `requirements*.txt` | Sin versión                               | `DEPS-PIP` | MEDIUM    |
| `requirements*.txt` | Con `>=` o `~=`                           | `DEPS-PIP` | LOW       |
| `package.json`      | Versión con `^`, `~` o `*`                | `DEPS-NPM` | MEDIUM    |
| `package.json`      | JSON inválido                             | `DEPS-NPM` | ERROR     |

Un `>=` o `~=` no se marca si el `pyproject.toml` del mismo directorio declara esa dependencia:
el requirements.txt copia el contrato del paquete, y una biblioteca no debe fijar versiones
exactas. Para fijarlas en una aplicación, usa un archivo de bloqueo o `agentes fix`.

Las vulnerabilidades conocidas son otra regla (`VULN-<id>`), descrita en [`vulns`](#vulns). Si
un manifiesto no se puede leer al buscarlas, se informa como `VULN-READ-ERROR` con nivel
`ERROR`.

### SOLID y diseño

Regla: `SOLID-<principio>`.

| Principio            | Condición                                                          | Severidad |
|----------------------|--------------------------------------------------------------------|-----------|
| `SRP`                | Clase con más de 10 métodos                                        | MEDIUM    |
| `OCP`                | Función con más de 12 ramas `if/elif` (el umbral de ruff y pylint) | MEDIUM    |
| `DIP`                | Instanciación directa de una clase dentro de `__init__`            | LOW       |
| `GUARD`              | Más de 3 niveles de anidamiento                                    | MEDIUM    |
| `STATE-SAFETY`       | Argumento por defecto mutable                                      | HIGH      |
| `STATE-SAFETY`       | Uso de `global`                                                    | MEDIUM    |
| `EXCEPTION-HYGIENE`  | `except:` sin tipo                                                 | HIGH      |
| `EXCEPTION-HYGIENE`  | `except` que solo hace `pass` o `...`                              | HIGH (MEDIUM en el pipeline) |
| `EXCEPTION-HYGIENE`  | Captura amplia que devuelve `None` en silencio                     | HIGH (MEDIUM en el pipeline) |
| `EXCEPTION-HYGIENE`  | `raise NuevaExcepcion()` dentro de `except` sin `from exc`         | HIGH      |
| `DATA-CONTRACT`      | `@dataclass` sin `slots=True`                                      | LOW       |

En el pipeline estos hallazgos no cambian el código de salida.

### Rendimiento

Regla: `PERF`. En el pipeline todos se registran como `MEDIUM`; en `metrics` conservan la
severidad de esta tabla.

| Condición                                                                     | Severidad |
|-------------------------------------------------------------------------------|-----------|
| Búsqueda con `in` sobre una lista o tupla literal dentro de un bucle          | HIGH      |
| `.pop(0)` o `.insert(0, ...)` dentro de un bucle (usa `collections.deque`)   | HIGH      |
| `re.compile()` con el mismo patrón en cada vuelta de un bucle                 | HIGH      |
| Llamada bloqueante dentro de `async def`                                      | HIGH      |
| Petición HTTP dentro de un bucle (patrón N+1)                                 | HIGH      |
| Operación de base de datos dentro de un bucle (patrón N+1)                    | HIGH      |
| Concatenación `s += ...` de cadenas dentro de un bucle                        | MEDIUM    |
| `.readlines()` (carga el archivo entero en memoria)                           | MEDIUM    |

`.pop(0)` e `.insert(0, ...)` fuera de un bucle no se marcan, ni anteponer una ruta a
`sys.path`. `re.compile` en un bucle no se marca si el patrón cambia en cada vuelta. Tampoco se
marca `in` sobre unas pocas constantes (hasta 8) ni sobre valores que cambian en cada vuelta del
bucle.

### Calidad de suites de tests

Regla: `TEST-QUALITY`. Se aplica en `test` y en `audit` sobre archivos de test.

| Código            | Condición                                                                   | Severidad |
|-------------------|-----------------------------------------------------------------------------|-----------|
| `WEAK-ASSERT`     | Test sin ninguna aserción (salvo los marcados como *skip*)                  | HIGH      |
| `WEAK-ASSERT`     | `assert True`, `assertTrue(True)` o comparación de dos constantes iguales   | HIGH      |
| `GENERIC-RAISES`  | `assertRaises(Exception)` o `pytest.raises(Exception)` (también `BaseException`) | HIGH |
| `GENERIC-RAISES`  | `pytest.raises(...)` sin `match=`                                           | MEDIUM    |
| `UNISOLATED-IO`   | Llamada real a `requests.*`, `urllib.request.*`, `urlopen`, `sqlite3.*` o `time.sleep` en un test sin `patch`, `monkeypatch` ni `Mock` | HIGH |
| `UNSAFE-MOCK`     | `Mock()` o `MagicMock()` sin `spec` ni `spec_set`                           | MEDIUM    |
| `UNSAFE-MOCK`     | `patch()` sin `autospec`, `spec`, `spec_set` ni `new`                       | MEDIUM    |
| `UNSAFE-MOCK`     | `patch` o `patch.object` sobre un miembro privado (`_algo`)                 | MEDIUM    |

### Testabilidad

Regla: `TESTABILITY`. Se aplica en `testability`.

| Código              | Condición                                                                    | Severidad |
|---------------------|------------------------------------------------------------------------------|-----------|
| `GLOBAL-STATE`      | `global` dentro de una función, o mutación de una variable del módulo (`CACHE[k] = v`, `ITEMS.append(x)`) | HIGH |
| `MIXED-IO`          | Función que mezcla lógica (condiciones, bucles, operaciones) con E/S directa | HIGH      |
| `NON-DETERMINISTIC` | `time.time`, `time.monotonic`, `time.perf_counter`, `time.sleep`, `datetime.now`, `datetime.utcnow`, `date.today`, `uuid.uuid4`, `random.*` u `os.getenv` | MEDIUM |
| `NON-DETERMINISTIC` | Lectura directa de `os.environ[...]`                                         | MEDIUM    |
| `HARDCODED-DEP`     | Una función crea una instancia de un colaborador en vez de recibirla. Se reconoce por el nombre de la clase: palabras como `Client`, `Service`, `Repository`, `Session`, `Engine`, `Connection`, `Database`, `Cache`, `Gateway` o `Adapter` (`UserRepository()`, `HttpClient()`) | MEDIUM |

---

## Informes y formatos

### `pipeline.json`

Esquema `agentes.pipeline.v1`. Campos de primer nivel:

| Campo           | Tipo    | Contenido                                                         |
|-----------------|---------|-------------------------------------------------------------------|
| `schema`        | texto   | `"agentes.pipeline.v1"`.                                          |
| `target`        | texto   | Ruta absoluta analizada.                                          |
| `timestamp`     | texto   | Fecha y hora UTC en ISO 8601.                                     |
| `status`        | texto   | `"ok"` o `"fail"`.                                                |
| `exit_code`     | entero  | `0` o `1`.                                                        |
| `stages`        | lista   | Una entrada por etapa, en orden.                                  |
| `python_files`  | entero  | Archivos `.py` encontrados.                                       |
| `files_scanned` | entero  | Archivos `.py` analizados.                                        |
| `files_skipped` | entero  | Archivos que quedaron fuera por `--max-files`.                    |
| `findings`      | lista   | Todos los hallazgos (objetos con `file`, `line`, `level`, `message`, `rule_id` y `category`). |
| `findings_by_category` | objeto | Cuántos hallazgos hay de cada categoría: `security` y `quality`. |
| `inline_suppressed` | entero | Hallazgos [silenciados en su línea](#silenciar-un-hallazgo-en-su-línea). |
| `baseline`      | objeto  | Solo con `--baseline`: `file`, `suppressed` (aceptados) y `unused` (entradas que ya no aparecen). |
| `artifacts`     | objeto  | Rutas de `json`, `html` y `sarif`.                                |

Cada etapa tiene `name`, `status` (`ok`, `fail` o `skipped`), `summary` y `findings_count`, más
campos propios:

| Etapa               | Campos adicionales                                                              |
|---------------------|---------------------------------------------------------------------------------|
| `quality_sast`      | `files_scanned`, `files_total`, `files_skipped`, `engine` (`"bandit+ast"` o `"ast"`). |
| `defensive_secrets` | `scan_errors`, `extra_config_files`, `files_scanned`, `files_total`, `files_skipped`. |
| `refactor_metrics`  | `files_analyzed`, `metrics` (líneas, comentarios, funciones, complejidades medias), `recommendations`, `errors`. |
| `documentation`     | `files_analyzed`, `frameworks`, `errors`.                                       |
| `infra_and_deps`    | `files_scanned`.                                                                |
| `dependency_vulns`  | `manifests`, `environments`, `dependencies_checked`, `dependencies_unpinned`, `installed_packages`, `blocked_fixes`. |

Ejemplos con `jq`:

```bash
jq '.stages[] | {name, status, summary}' reports/pipeline.json
jq '[.findings[] | select(.level == "HIGH" or .level == "CRITICAL")] | length' reports/pipeline.json
jq -r '.findings[] | "\(.level)\t\(.file):\(.line)\t\(.rule_id)"' reports/pipeline.json
```

### `pipeline.sarif` y `analyze.sarif`

SARIF 2.1.0 con un único *run*. Herramienta: `AGENTES-Pipeline` o `AGENTES-Analyze`. Cada
hallazgo es un resultado con `ruleId`, mensaje y ubicación (ruta relativa a la raíz del
proyecto con `/` como separador, y línea; `1` si el hallazgo no tiene línea). Correspondencia
de severidades:

| Severidad                      | Nivel SARIF |
|--------------------------------|-------------|
| `CRITICAL`, `HIGH`, `ERROR`     | `error`     |
| `MEDIUM`                       | `warning`   |
| `LOW`                          | `note`      |

Cada regla lleva la etiqueta `security` o `maintainability` en `properties.tags`. Las de
seguridad llevan además `security-severity` (9,5 crítico, 8,0 alto, 5,5 medio, 2,0 bajo), que
es lo que GitHub Code Scanning usa para clasificarlas como alertas de seguridad y darles su
gravedad.

GitHub Code Scanning, Visual Studio Code (extensión SARIF Viewer) y otras herramientas leen
este formato directamente.

### `pipeline.html`

Página autónoma (sin recursos externos) con la tabla de etapas y la tabla de hallazgos
(archivo, línea, nivel, tipo, regla y mensaje). Todo el contenido procedente del proyecto analizado
se escapa.

### Salida `--json` de cada comando

| Comando       | Campos principales                                                                |
|---------------|-----------------------------------------------------------------------------------|
| `pipeline`    | El informe completo descrito arriba.                                              |
| `analyze`     | `target`, `files`, `findings`, `inline_suppressed`, `vulnerability_check`, `artifacts`. |
| `secrets`     | `target`, `files_scanned`, `findings`, `inline_suppressed`.                       |
| `vulns`       | `target`, `manifests`, `environments`, `status` (`ok`, `fail` o `unchecked`), `dependencies_checked`, `dependencies_unpinned`, `installed_packages`, `findings`, `inline_suppressed`, `blocked_fixes`. |
| `audit`       | `target`, `kind`, `files`, `findings`, `inline_suppressed`.                       |
| `metrics`     | `target`, `totals`, `files`, `functions`, `findings`, `recommendations`, `inline_suppressed`. |
| `fix`         | `file`, `dry_run`, `corrections`, `changes`, `unresolved`, `vulnerabilities`, `vulnerability_check_error`. |
| `test`        | `tests_run`, `passed`, `failures`, `errors`, `skipped`, `pass_rate_percentage`, `duration_seconds`, `failure_details`, `coverage`. |
| `testability` | `file`, `findings`, `scenarios`.                                                  |
| `contract`    | `passed`, `elapsed_ms`, `assertions` y los datos de la respuesta.                 |
| `health`      | `status`, `checks` (una entrada por sonda), `probe_duration_ms` y datos del sistema. |
| `sla`         | `total`, `errors`, `error_rate_pct`, `max_rate_pct`, `alert`.                     |
| `password`    | `check`: `score`, `max_score`, `strength`, `feedback`, `breaches`. `hash`: `hash`, `backend`, `score`, `breaches`. `verify`: `valid`, `needs_rehash`. |
| `doctor`      | `version`, `checks`, `crypto_backend`, `workdir`.                                 |

En `breaches`, `null` significa que no se pudo comprobar (sin conexión) y `0` que no aparece en
filtraciones.

---

## Línea base

La línea base sirve para adoptar Work-Agents en un proyecto que ya tiene hallazgos, o que contiene
datos de prueba que lo parecen (como un corpus de secretos falsos): el CI falla solo con lo
nuevo.

### Crearla

```bash
agentes pipeline . --write-baseline .agentes-baseline.json
```

```text
[OK] Baseline written to .agentes-baseline.json: 4 findings accepted.
The 2 medium or low findings are not stored, because they never fail the pipeline.
Review the file before committing it: everything it lists will stop failing the analysis.
```

Solo se guardan los hallazgos que harían fallar el análisis: los bloqueantes y todos los
secretos. Los medios y bajos no hacen falta.

### Usarla

```bash
agentes pipeline . --baseline .agentes-baseline.json
```

Los hallazgos aceptados no cuentan para el estado de las etapas ni para el código de salida, y
no aparecen en la lista ni en los informes. La consola indica cuántos se aceptaron:

```text
Baseline .agentes-baseline.json: 3 accepted findings are not counted.
  1 entries no longer match anything: regenerate the baseline to drop them.
```

### Cómo identifica los hallazgos

Cada hallazgo se identifica por una huella (los 20 primeros caracteres de un SHA-256) de su
regla, su archivo relativo a la raíz y su mensaje sin números de línea. Por eso:

- La línea base sigue valiendo aunque el código se desplace.
- Si cambias el mensaje (por ejemplo, otra variable con un secreto distinto), el hallazgo es
  nuevo.
- Si un mismo hallazgo aparece más veces de las registradas, las apariciones de más son nuevas.

### Formato

```json
{
  "schema": "agentes.baseline.v1",
  "generated_by": "agentes 3.2.3",
  "note": "Reviewed and accepted findings. Regenerate with: agentes pipeline . --write-baseline <file>",
  "entries": [
    {
      "fingerprint": "930d4decba31c0168a75",
      "rule_id": "SAST-HIGH",
      "file": "app/main.py",
      "level": "HIGH",
      "message": "Subprocess started with 'shell=True' (command injection risk)."
    }
  ]
}
```

Solo cuenta `fingerprint`; el resto de campos sirven para revisar el archivo. Para retirar un
hallazgo aceptado, borra su entrada o regenera el archivo.

### Buenas prácticas

- **Revísala antes de versionarla.** Todo lo que contiene deja de bloquear.
- Regenérala cuando la consola indique entradas sin usar, para que no acepte en el futuro un
  hallazgo que ya se corrigió.
- El archivo contiene fragmentos enmascarados de los secretos aceptados. Con `--baseline` el
  pipeline lo excluye de la búsqueda de secretos; sin esa opción, o con `agentes secrets`, se
  analiza como cualquier otro JSON (ver [Solución de problemas](#secrets-marca-la-línea-base)).
- Este repositorio usa la suya (`.agentes-baseline.json`) en el CI para auditarse a sí mismo.

---

## Silenciar un hallazgo en su línea

Para aceptar un hallazgo concreto y dejar el motivo junto al código, añade un comentario en la
línea que indica el hallazgo:

```python
resultado = eval(expr)  # agentes: ignore[dynamic-exec] - la expresión se valida antes
except Exception:  # agentes: ignore - frontera del SDK, cualquier error se informa
```

- `# agentes: ignore` silencia todo lo que se señale en esa línea.
- `# agentes: ignore[REGLA, ...]` silencia solo las reglas indicadas. Cada una puede ser el
  `rule_id` del JSON (`SECRET`, `SOLID-GUARD`, `DEPS-PIP`...) o su prefijo (`SAST`, `SOLID`,
  `K8S`), el `ruleId` del SARIF, que es el que muestra GitHub Code Scanning (`SAST-SHELL`,
  `SAST-TOCTOU`...), o el nombre de la regla: `broad-except`, `bare-except`,
  `exception-swallow`, `mutable-default`, `blocking-async`, `weak-hash`, `dynamic-exec`, `shell`,
  `pickle`, `yaml-load`, `assert`, `sql`, `docstring`, `too-many-args`, `open-without-with`,
  `toctou`, `path-traversal`, `no-timeout`, `tls-verify`, `jinja`, `insecure-random`,
  `hardcoded-secret`, `global-state` y `too-many-branches`.

También se respetan los comentarios de ruff/flake8 y Bandit cuando su código equivale a una regla
propia, para no repetir la justificación con dos sintaxis:

| Comentario              | Silencia                                                       |
|-------------------------|----------------------------------------------------------------|
| `# noqa: BLE001`        | `except Exception` (también otros códigos: `E722`, `B006`, `S602`, `PLR0913`, `D103`...) |
| `# noqa` sin códigos    | Nada: suele estar por otra herramienta y ocultaría hallazgos de seguridad. |
| `# nosec B602`          | La regla equivalente de Bandit (`B101`, `B307`, `B324`, `B608`...). |
| `# nosec` sin códigos   | Todo el análisis estático (SAST) de la línea, como en Bandit, pero no los secretos. |

Un secreto solo se silencia de forma explícita, con `# agentes: ignore` o
`# agentes: ignore[SECRET]`.

Los hallazgos silenciados no cuentan para el estado ni para el código de salida y no aparecen en
los informes, pero la consola dice cuántos hay y el JSON los cuenta en `inline_suppressed`:

```text
4 findings suppressed inline (# agentes: ignore, noqa or nosec) are not shown.
```

Los hallazgos sin línea (un archivo entero, un documento de Kubernetes, una cabecera HTTP) solo
se pueden aceptar con la [línea base](#línea-base). En el pipeline, lo silenciado en su línea se
descuenta antes de aplicar la línea base.

---

## Integración continua

### GitHub Actions

```yaml
name: Auditoría
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write        # necesario para subir SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/kahz12/Work-Agents.git"
      - run: agentes pipeline . -o reports --baseline .agentes-baseline.json
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/pipeline.sarif
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: auditoria
          path: reports/
```

- `if: always()` sube el informe aunque el paso anterior falle por los hallazgos.
- Los hallazgos aparecen en la pestaña Security y como anotaciones en los pull requests.
- Para instalar Bandit, usa `pip install "agentes-devsecops[sast] @ git+https://github.com/kahz12/Work-Agents.git"`.
  Si generas la línea base con un motor, úsalo también en el CI (este repositorio usa
  `--no-bandit` en ambos casos), porque Bandit y el motor AST no producen exactamente los mismos
  hallazgos.

### GitLab CI

```yaml
auditoria:
  image: python:3.12-slim
  script:
    - pip install "git+https://github.com/kahz12/Work-Agents.git"
    - agentes pipeline . -o reports --baseline .agentes-baseline.json
  artifacts:
    when: always
    paths:
      - reports/
```

### Hook local antes de cada commit

Un `.git/hooks/pre-commit` que impide confirmar secretos:

```bash
#!/bin/sh
agentes secrets . --no-color || {
  echo "Hay posibles secretos. Revisa la salida anterior antes de confirmar."
  exit 1
}
```

Hazlo ejecutable con `chmod +x .git/hooks/pre-commit`.

### Recomendaciones

- Usa `--offline` en las ejecuciones que no deban depender de la red y un trabajo separado,
  con conexión, para las vulnerabilidades (`agentes vulns .`).
- Guarda `reports/` como artefacto para revisar el HTML.
- Usa `--json` y `jq` para construir tus propias reglas de bloqueo.

---

## Uso como biblioteca

Los agentes son paquetes de Python que puedes importar. La interfaz principal es el CLI; esta
sección muestra las clases más útiles. Todos los ejemplos están probados con la versión 3.2.3.

### Ejecutar el pipeline

```python
from agentes.common.orchestrator import run_pipeline

report, exit_code = run_pipeline(
    "./mi_proyecto",
    output_dir="./reports",          # None: <proyecto>/reports
    fail_on_high=True,               # False equivale a --no-fail
    max_files=None,
    prefer_bandit=False,             # False equivale a --no-bandit
    check_vulnerabilities=False,     # False: sin OSV. None: consulta salvo AGENTES_OFFLINE=1
    baseline=None,                   # ruta a una línea base
)
print(report["status"], len(report["findings"]))
```

### Auditorías sueltas

```python
from agentes.common import audits

for f in audits.audit_file("Dockerfile"):          # el tipo se deduce del nombre
    print(f.level, f.rule_id, f.line, f.message)

audits.audit_file("mi.conf", "systemd")             # tipo explícito
audits.scan_secrets("app/settings.py")              # lista de Finding
audits.sast(["app/main.py"], prefer_bandit=False)   # análisis estático
```

Cada resultado es un `agentes.common.findings.Finding` con `file`, `line`, `level`, `message`,
`rule_id`, las propiedades `blocking` y `silent`, y `to_dict()`.

### Contraseñas, tokens y permisos

```python
from agentes.defensive.auth_manager import AuthManager, RateLimiter

h = AuthManager.hash_password("correct horse battery staple")
AuthManager.verify_password("correct horse battery staple", h)     # True
AuthManager.needs_rehash(h)                                          # False
AuthManager.evaluate_password_strength("Password123!")
# (2, ["It is based on a very common password ('password'): ..."])

# Token anti-CSRF ligado a la sesión (30 minutos por defecto)
token = AuthManager.create_csrf_token(secret_key, "sesion-1")
AuthManager.verify_csrf_token(token, secret_key, "sesion-1")        # True

# Token firmado con HMAC (1 hora por defecto)
tok = AuthManager.create_secure_token({"sub": "ana"}, secret_key)
ok, payload, motivo = AuthManager.verify_secure_token(tok, secret_key)

# RBAC
AuthManager.check_permission(["editor"], "write", {"editor": ["read", "write"]})   # True

# Rate limiting por ventana deslizante, en memoria
limiter = RateLimiter(max_requests=5, window_seconds=60)
limiter.is_allowed("203.0.113.7")
```

Usa una `secret_key` larga y aleatoria (por ejemplo `secrets.token_hex(32)`), nunca escrita en
el código.

### Validación de entrada

```python
from agentes.defensive.input_sanitizer import InputSanitizer

InputSanitizer.sanitize_html("<script>x</script>")       # '&lt;script&gt;x&lt;/script&gt;'
InputSanitizer.validate_safe_path("/srv/data", "../etc/passwd")   # None: fuera del directorio
InputSanitizer.validate_email("ana@example.com")         # True
InputSanitizer.sanitize_integer("42", min_val=0, max_val=100)     # 42
InputSanitizer.validate_json_schema(
    {"id": 1, "tags": ["a"]}, {"id": int, "tags": [str]}, reject_extra_keys=True,
)                                                         # (True, [])
```

### Logs estructurados y sondas

```python
from agentes.sre.structured_logger import StructuredLogger
from agentes.sre.health_checker import SystemHealthChecker
from agentes.sre.alerting_engine import AlertingEngine

log = StructuredLogger("api")
print(log.info("login", {"user": "ana", "password": "x"}, trace_id="t-1"))
# {"timestamp": "...", "service": "api", "level": "INFO", "message": "login",
#  "trace_id": "t-1", "context": {"user": "ana", "password": "***MASKED***"}}

SystemHealthChecker.check_health(tcp_host="localhost", tcp_port=5432)["status"]
AlertingEngine.evaluate_error_rate(12000, 340, 5.0)      # (False, "OK: ...")
```

El logger enmascara las claves `password`, `secret`, `token`, `authorization` y `api_key` a
cualquier profundidad del contexto, y genera un `trace_id` si no se indica.

### Generadores

```python
from agentes.docs.openapi_generator import OpenAPIGenerator
from agentes.devops.docker_compose_generator import DockerComposeGenerator
from agentes.hardening.k8s_hardening import K8sHardening

spec = OpenAPIGenerator.generate_openapi_spec("app/main.py", title="Mi API")
OpenAPIGenerator.export_spec_to_yaml(spec, "openapi.yaml")

DockerComposeGenerator.generate_compose_file("docker-compose.yml", service_name="api", port=8000)
yaml_text = K8sHardening.generate_hardened_pod_manifest(name="api", image="myorg/api:1.2.0")
```

---

## Red y privacidad

El análisis de código es local: ningún comando envía código fuente. Tres funciones consultan
servicios externos:

| Función                                                | Servicio                 | Qué se envía                                                   |
|--------------------------------------------------------|--------------------------|----------------------------------------------------------------|
| Vulnerabilidades (`pipeline`, `analyze`, `vulns`, `fix`) | `api.osv.dev`          | Ecosistema, nombre y versión de cada dependencia comprobable.  |
| Elección de versiones (`fix`)                          | `pypi.org`               | Nombre de cada paquete.                                        |
| Contraseñas filtradas (`password check` y `hash`)      | `api.pwnedpasswords.com` | Los 5 primeros caracteres del hash SHA-1 de la contraseña.     |

Además, `audit URL`, `contract`, `health --http` y `health --tcp` se conectan a los destinos
que tú indicas.

`--offline` o `AGENTES_OFFLINE=1` desactivan las tres consultas externas:

- El pipeline marca la etapa de vulnerabilidades como `SKIPPED` y no falla por ello.
- `password` indica que la filtración no se pudo comprobar.
- `vulns` y `fix`, que no tienen sentido sin red, terminan con `2`.

Los tests del repositorio no usan la red: activan el modo sin conexión y simulan las respuestas.

---

## Solución de problemas

### El resumen dice "without Bandit"

Bandit no está instalado o no está en el `PATH` del entorno. Instálalo con
`pip install -e ".[sast]"`. Si prefieres no usarlo, añade `--no-bandit` y el aviso desaparece.

### La etapa de vulnerabilidades dice "not checked"

Todas tus dependencias usan rangos (`flask>=2.0`) y no hay un entorno virtual ni un archivo de
bloqueo. Soluciones, de más a menos fiable:

1. Crea el entorno del proyecto (`python -m venv .venv` e instala las dependencias): se
   comprobarán los paquetes instalados.
2. Usa un archivo de bloqueo (`poetry.lock`, `Pipfile.lock`) o un `requirements.txt` fijado
   (`agentes fix requirements.txt` lo fija por ti).

### La etapa de vulnerabilidades sale omitida

Estás sin conexión, has usado `--offline` o `AGENTES_OFFLINE` está definida, u OSV no ha
respondido. El resumen indica el motivo.

### Un hallazgo es un falso positivo

- Si es un secreto de ejemplo, usa un valor que lo delate (`changeme`, `<tu-clave>`,
  `${VARIABLE}`) o muévelo a un archivo de test.
- Si es un hash para caché o checksums, pásale `usedforsecurity=False`.
- Si es un hallazgo revisado que debe quedarse, añádelo a una [línea base](#línea-base).

### `secrets` marca la línea base

La línea base guarda los mensajes de los secretos aceptados, con el valor enmascarado, y
algunos de esos mensajes vuelven a coincidir con los patrones. El pipeline la excluye cuando se
le pasa con `--baseline`, pero `agentes secrets .` (o `agentes pipeline .` sin `--baseline`)
analiza todo el árbol y puede marcarla. Ejecuta `secrets` sobre los directorios de código
(`agentes secrets src/`) y pasa siempre `--baseline` al pipeline.

### `generate` no escribe nada

La salida ya existe. Añade `--force` para reemplazarla o elige otra ruta con `-o`.

### `test` no encuentra tests

`test` ejecuta suites **unittest** (clases que heredan de `unittest.TestCase`). Para suites de
pytest, usa `pytest`.

### La página de Swagger UI sale en blanco

Carga Swagger UI desde un CDN: necesita conexión a internet.

### `serve` no arranca

El puerto está ocupado. Usa otro: `agentes serve --port 9200`.

### Los colores ensucian la salida

Se desactivan solos al redirigir. Si no, usa `--no-color` o define `NO_COLOR=1`.

### Error inesperado

Repite el comando con `AGENTES_DEBUG=1` para ver la traza completa y, si es un fallo de la
herramienta, abre una incidencia con ella.

---

## Limitaciones

- **Solo Python.** El análisis de código es para Python. Del resto del proyecto se revisan
  configuración, Dockerfiles, manifiestos y dependencias, incluido `package.json`.
- **Análisis estático.** Los comandos de análisis y `generate` leen el código sin importarlo ni
  ejecutarlo. Solo ejecutan código del proyecto `test` (que corre la suite indicada) y
  `generate tests --record`.
- **Heurísticas.** Las reglas buscan patrones conocidos; no siguen el flujo de datos entre
  funciones. Un análisis limpio no garantiza la ausencia de vulnerabilidades.
- **Versiones exactas.** Las vulnerabilidades se comprueban en versiones exactas: las
  instaladas en el entorno virtual del proyecto y las fijadas en manifiestos o archivos de
  bloqueo. Con solo rangos declarados no se sabe qué versión se instala.
- **Kubernetes.** El contexto de seguridad solo se audita en documentos `kind: Pod`, no en
  `Deployment` u otros controladores.
- **Idioma.** La salida del CLI y los informes están en inglés; la sección
  [Cómo leer la salida](#cómo-leer-la-salida) traduce sus términos.
- **Swagger UI** carga sus recursos desde un CDN.
- **`password`** necesita `argon2-cffi` o `bcrypt` para verificar hashes de esos formatos.

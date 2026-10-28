# jev-sample

Ejemplo de uso del SDK de TypeSafe AI (`typesafe-sdk`) para análisis y
validación de comandos shell.

## Scripts

- [`main.py`](file:///dev/shm/jev-sample/main.py): Ejemplo base de clasificación
  con `system_one`.
- [`hist.py`](file:///dev/shm/jev-sample/hist.py): Analiza los últimos 100
  comandos del historial de la shell (detectando automáticamente `.zsh_history`
  o `.bash_history`), clasificando el nivel de riesgo de seguridad (`reads`,
  `modifies`, `deletes`) y si acceden fuera del directorio de trabajo actual
  (`cwd`).

## Requisitos y Uso

Gestionado con `uv` y recetas de `just`:

```bash
# Verificación de tipos y linting
just check

# Ejecutar el análisis del historial
just run

# O con opciones adicionales directamente
uv run python hist.py --limit 50 --concurrency 10
```

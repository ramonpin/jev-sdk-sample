default: check

check: lint typecheck

typecheck:
    uv run ty check

lint:
    uv run ruff check

fmt:
    uv run ruff format
    uv run ruff check --fix

run:
    uv run python hist.py

# include .env.local
# export $(shell sed 's/=.*//' .env.local)
export PYTHONDONTWRITEBYTECODE=1

local-setup:
	uv sync --group=dev

# Devtools
hooks-install:
	uv run pre-commit install

hooks-upgrade:
	uv run pre-commit autoupdate

hooks-lint:
	uv run pre-commit run --all-files

lint: hooks-lint  # alias

hooks-mypy:
	uv run pre-commit run mypy --all-files

mypy: hooks-mypy  # alias

# Test
test: local-setup
	@uv run pytest

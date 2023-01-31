all: venv test format scan

.PHONY: install
install:
	poetry install

.PHONY: test
test:
	poetry run pytest

.PHONY: format
format:
	poetry run black *.py
	poetry run isort .

.PHONY: lint
lint:
	poetry run black --check *.py
	poetry run isort --check --diff .
	poetry run bandit -c pyproject.toml *.py

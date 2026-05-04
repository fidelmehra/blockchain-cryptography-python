# =============================================================================
# Makefile — blockchain-cryptography-python
# Author: Fidel Mehra
# =============================================================================

PYTHON  := python3
PIP     := pip3
SRC     := src
TESTS   := tests
PORT    := 8000
IMAGE   := blockchain-cryptography-python

.DEFAULT_GOAL := help

.PHONY: help install install-dev clean lint format security test test-cov \
        run docker-build docker-run notebook

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
install:  ## Install production dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

install-dev: install  ## Install dev/test extras
	$(PIP) install ruff black isort bandit[toml] jupyterlab

# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------
clean:  ## Remove caches and build artefacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.ruff_cache'   -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov .coverage coverage.xml

# ---------------------------------------------------------------------------
# Linting & formatting
# ---------------------------------------------------------------------------
lint:  ## Run ruff linter
	ruff check $(SRC)/ $(TESTS)/

format:  ## Auto-format with black + isort
	black $(SRC)/ $(TESTS)/
	isort $(SRC)/ $(TESTS)/

format-check:  ## Check formatting (CI mode)
	black --check $(SRC)/ $(TESTS)/
	isort --check-only $(SRC)/ $(TESTS)/

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
security:  ## Run bandit SAST scan
	bandit -r $(SRC)/ -ll

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
test:  ## Run test suite
	pytest $(TESTS)/ -v

test-cov:  ## Run tests with coverage report
	pytest $(TESTS)/ -v \
	  --cov=$(SRC) \
	  --cov-report=term-missing \
	  --cov-report=html:htmlcov \
	  --cov-fail-under=70

test-fast:  ## Run tests without coverage (faster)
	pytest $(TESTS)/ -v -x

# ---------------------------------------------------------------------------
# Running the API
# ---------------------------------------------------------------------------
run:  ## Launch FastAPI dev server (hot-reload)
	uvicorn src.api.app:app --reload --host 0.0.0.0 --port $(PORT)

run-prod:  ## Launch FastAPI production server
	uvicorn src.api.app:app --host 0.0.0.0 --port $(PORT) --workers 4

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
docker-build:  ## Build Docker image
	docker build -t $(IMAGE):latest .

docker-run:  ## Run Docker container
	docker run --rm -p $(PORT):$(PORT) $(IMAGE):latest

docker-compose-up:  ## Start via docker-compose (if present)
	docker compose up --build

# ---------------------------------------------------------------------------
# Jupyter
# ---------------------------------------------------------------------------
notebook:  ## Start Jupyter Lab
	jupyter lab --notebook-dir=notebooks --port=8888

# ---------------------------------------------------------------------------
# All checks (for CI parity)
# ---------------------------------------------------------------------------
ci: format-check lint security test-cov  ## Run all CI checks locally

.PHONY: help install test lint demo clean

PYTHON ?= python3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev + pdf extras
	$(PYTHON) -m pip install -e ".[pdf,yara,dev]"

test: ## Run the test suite
	$(PYTHON) -m pytest -q

lint: ## Byte-compile all modules as a cheap syntax check
	$(PYTHON) -m compileall -q larvanex samples tests

demo: ## Generate safe samples and scan the suspicious ones
	$(PYTHON) samples/generate_samples.py
	$(PYTHON) -m larvanex --no-network -r samples/suspicious

clean: ## Remove caches and build artefacts
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

.PHONY: help install install-dev test lint demo clean zip ui

help:
	@echo "make install     install the backend in editable mode"
	@echo "make test        run the test suite (no network, no credentials)"
	@echo "make lint        ruff"
	@echo "make demo        run the pipeline over samples/"
	@echo "make ui          install and start the front end"
	@echo "make serve       run the API with reload"

install:
	python -m pip install -e "backend[dev]"

test:
	cd backend && python -m pytest

lint:
	cd backend && ruff check .

demo:
	cd backend && python -m phantom.cli demo --samples-dir ../samples --out ../out
	cd backend && python -m phantom.cli mirror-demo --out ../out

serve:
	uvicorn phantom.main:app --reload --app-dir backend

ui:
	cd frontend && npm install && npm run dev

clean:
	rm -rf out .pytest_cache backend/.pytest_cache **/__pycache__

.PHONY: install test lint smoke docker docker-smoke
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q --cov=attestforge --cov-branch --cov-report=term-missing
lint:
	ruff check src tests
smoke:
	bash scripts/smoke.sh
docker:
	docker build -t attestforge:local .
docker-smoke:
	bash scripts/docker_smoke.sh

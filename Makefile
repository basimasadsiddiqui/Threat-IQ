.PHONY: help install test agents verify keys lint security run-api run-ui seed up down logs clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Create a venv and install dev dependencies
	python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

test:  ## Run the test suite
	.venv/bin/python -m pytest -q

agents:  ## Install LangGraph, LangChain and LangSmith, then verify they run
	.venv/bin/pip install langgraph langchain-core langchain-groq langsmith
	.venv/bin/python scripts/verify_stack.py

verify:  ## Report which agent libraries are actually executing
	.venv/bin/python scripts/verify_stack.py

keys:  ## Check each configured API key against its live service
	.venv/bin/python scripts/check_keys.py

lint:  ## Lint with ruff
	.venv/bin/ruff check threatiq ui tests

security:  ## Static analysis and dependency audit
	.venv/bin/bandit -r threatiq -ll --skip B101
	.venv/bin/pip-audit -r requirements.txt

run-api:  ## Run the API locally with reload
	.venv/bin/uvicorn threatiq.api.main:app --reload --port 8000

run-ui:  ## Run the Streamlit dashboard locally
	.venv/bin/streamlit run ui/app.py

seed:  ## Embed the knowledge base into pgvector (no-op without DATABASE_URL)
	.venv/bin/python scripts/seed_knowledge.py

up:  ## Start the full stack with Docker
	docker compose up -d --build

down:  ## Stop the stack
	docker compose down

logs:  ## Follow container logs
	docker compose logs -f api ui

clean:  ## Remove caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache

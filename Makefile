.PHONY: build up down test lint test-integration

COMPOSE_FILE=infra/docker-compose.yml

build:
	docker compose -f $(COMPOSE_FILE) build

up:
	docker compose -f $(COMPOSE_FILE) up -d

down:
	docker compose -f $(COMPOSE_FILE) down

test:
	pytest

test-integration:
	docker compose -f $(COMPOSE_FILE) up -d zookeeper kafka
	python3 -m pytest tests/integration/test_kafka_topics.py

lint:
	ruff check .

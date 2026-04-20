.PHONY: build up down test lint test-integration

DOCKER ?= docker
COMPOSE_FILE=infra/docker-compose.yml

build:
	$(DOCKER) compose -f $(COMPOSE_FILE) build

up:
	$(DOCKER) compose -f $(COMPOSE_FILE) up -d

down:
	$(DOCKER) compose -f $(COMPOSE_FILE) down

test:
	pytest

test-integration:
	$(DOCKER) compose -f $(COMPOSE_FILE) up -d zookeeper kafka
	python3 -m pytest tests/integration/test_kafka_topics.py

lint:
	ruff check .

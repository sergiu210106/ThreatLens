.PHONY: build up down test lint

COMPOSE_FILE=infra/docker-compose.yml

build:
	docker compose -f $(COMPOSE_FILE) build

up:
	docker compose -f $(COMPOSE_FILE) up -d

down:
	docker compose -f $(COMPOSE_FILE) down

test:
	pytest

lint:
	ruff check .

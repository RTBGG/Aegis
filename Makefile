# Aegis — developer task runner
# Toolchains may live in ~/.local (userspace). Adjust PATH if needed:
#   export PATH="$HOME/.local/go/bin:$HOME/.local/node/bin:$HOME/go/bin:$PATH"

SHELL := /bin/bash
COMPOSE := docker compose

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- Environment -----------------------------------------------------------
.PHONY: env
env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && echo "Created .env — edit secrets before 'make up'")

# --- Docker stack ----------------------------------------------------------
.PHONY: up
up: env ## Build + start the all-in-one stack
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: nuke
nuke: ## Stop the stack and delete volumes (DESTRUCTIVE)
	$(COMPOSE) down -v

.PHONY: ps
ps: ## Show service status
	$(COMPOSE) ps

.PHONY: logs
logs: ## Tail logs (use S=servicename to filter)
	$(COMPOSE) logs -f $(S)

# --- Local compile checks (no Docker) --------------------------------------
.PHONY: build
build: build-cp build-agent build-edge build-dash ## Compile every component locally

.PHONY: build-cp
build-cp: ## go build the control-plane
	cd control-plane && go build ./...

.PHONY: build-agent
build-agent: ## go build the node-agent
	cd node-agent && go build ./...

.PHONY: build-edge
build-edge: ## go build (vet) the custom Caddy modules
	cd edge && go build ./...

.PHONY: build-dash
build-dash: ## Build the Next.js dashboard
	cd dashboard && npm ci && npm run build

.PHONY: tidy
tidy: ## go mod tidy across Go modules
	cd control-plane && go mod tidy
	cd node-agent && go mod tidy
	cd edge && go mod tidy

.PHONY: test
test: ## Run Go unit tests
	cd control-plane && go test ./...
	cd edge && go test ./...

.PHONY: fmt
fmt: ## Format Go code
	cd control-plane && go fmt ./...
	cd node-agent && go fmt ./...
	cd edge && go fmt ./...

# --- DB --------------------------------------------------------------------
.PHONY: migrate
migrate: ## Run DB migrations inside the running api container
	$(COMPOSE) exec api /app/migrate up

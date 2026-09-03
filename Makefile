# gRPC-low-latency
#
# Targets grow as milestones land; see plan.md 6. Today: M0 (spike) and M1 (token).

SHELL := /bin/sh
COMPOSE := docker compose

.PHONY: help env up down logs clean check spike fmt lint test

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

env: ## Generate .env with random PINs (idempotent)
	@./scripts/gen-env.sh

up: env ## Provision the token and run the proxy container
	$(COMPOSE) up --build

down: ## Stop containers, keep the token volume
	$(COMPOSE) down

clean: ## Stop containers AND destroy the token volume
	$(COMPOSE) down -v

logs: ## Tail proxy logs
	$(COMPOSE) logs -f proxy

check: env ## M1 exit check: can the proxy open the shared token read/write?
	$(COMPOSE) run --rm --build proxy

bench: ## Sweep concurrency and report max QPS under the p99 budget
	./scripts/bench-sweep.sh

bench-baseline: ## Same sweep against the M2 single-session baseline
	MODE=single ./scripts/bench-sweep.sh

ceiling: ## Measure the token's own parallel ceiling (no gRPC in the path)
	SOFTHSM2_CONF=$(PWD)/.local/softhsm/softhsm2.conf \
	PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
	TOKEN_LABEL=grpc-low-latency USER_PIN=1234 \
	./proxy/target/release/hsm-ceiling

spike: ## M0 spike: run the PKCS#11 benchmark probe in a container
	docker build -q -f docker/spike/Dockerfile -t gll-spike:m0 . && docker run --rm gll-spike:m0

fmt: ## Format Rust sources
	cd proxy && cargo fmt

lint: ## Clippy with warnings denied
	cd proxy && cargo clippy --all-targets -- -D warnings

test: ## Rust test suite
	cd proxy && cargo test

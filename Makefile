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

certs: ## Generate the local CA, server cert, and per-workload client certs
	@./scripts/gen-certs.sh

up: env certs ## Provision the token and run the proxy container
	$(COMPOSE) up --build

down: ## Stop containers, keep the token volume
	$(COMPOSE) down

clean: ## Stop containers AND destroy the token volume
	$(COMPOSE) down -v

dash: ## Open the Grafana dashboard (stack must be up)
	@echo "Grafana:    http://localhost:$${GRAFANA_PORT:-3000}"
	@echo "Prometheus: http://localhost:$${PROMETHEUS_PORT:-9090}"
	@echo "Raw metrics: http://localhost:$${METRICS_PORT:-9464}/metrics"
	@command -v open >/dev/null && open "http://localhost:$${GRAFANA_PORT:-3000}" || true

logs: ## Tail proxy logs
	$(COMPOSE) logs -f proxy

check: env ## M1 exit check: can the proxy open the shared token read/write?
	$(COMPOSE) run --rm --build proxy

# After any run, compare against best_results.md and update anything beaten.
bench: ## Sweep concurrency and report max QPS under the p99 budget (plaintext)
	./scripts/bench-sweep.sh

bench-tls: certs ## Same sweep with mTLS enabled, to price the security layer
	TLS=on ./scripts/bench-sweep.sh

bench-baseline: ## Same sweep against the M2 single-session baseline
	MODE=single ./scripts/bench-sweep.sh

baseline: ## Go direct-PKCS#11 baseline: serial vs naive-concurrent vs pooled
	@cd baseline && go build -o ../bin/baseline ./...
	@set -a; [ -f .env ] && . ./.env; set +a; \
	 SOFTHSM2_CONF=$(PWD)/.local/softhsm/softhsm2.conf \
	 USER_PIN=$${USER_PIN:?run 'make env' first, or export USER_PIN} \
	 ./scripts/run-baseline.sh

records: ## Compare results against best_results.md and report what changed
	@./scripts/render-results.py --check-records

table: ## Print the current best figures as markdown
	@./scripts/render-results.py --table

ceiling: ## Measure the token's own parallel ceiling (no gRPC in the path)
	@set -a; [ -f .env ] && . ./.env; set +a; \
	 SOFTHSM2_CONF=$(PWD)/.local/softhsm/softhsm2.conf \
	 USER_PIN=$${USER_PIN:?run 'make env' first, or export USER_PIN} \
	 ./proxy/target/release/hsm-ceiling

spike: ## M0 spike: run the PKCS#11 benchmark probe in a container
	docker build -q -f docker/spike/Dockerfile -t gll-spike:m0 . && docker run --rm gll-spike:m0

fmt: ## Format Rust sources
	cd proxy && cargo fmt

lint: ## Clippy with warnings denied
	cd proxy && cargo clippy --all-targets -- -D warnings

test: ## Rust test suite
	cd proxy && cargo test

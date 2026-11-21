# Email Forensics Platform — dev entry points

BACKEND_DIR := backend
FRONTEND_DIR := frontend

.PHONY: api web test typecheck build demo demo-up demo-reset test-pg compose-config docker-build retention-dry-run
api:            ## start FastAPI dev server on :8000
	cd $(BACKEND_DIR) && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

web:            ## start Vite dev server on :5173 (proxies /api to :8000)
	cd $(FRONTEND_DIR) && npm run dev

typecheck:      ## frontend TypeScript check
	cd $(FRONTEND_DIR) && npm run typecheck

test:           ## backend pytest suite
	cd $(BACKEND_DIR) && .venv/bin/python -m pytest tests -q

build:          ## frontend production build
	cd $(FRONTEND_DIR) && npm run build

demo:           ## one-shot e2e smoke: start both, curl health directly + via proxy, stop
	cd $(BACKEND_DIR) && (.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 > /tmp/aipish_backend.log 2>&1 &) && \
	cd ../$(FRONTEND_DIR) && (npx vite --host 127.0.0.1 --port 5173 > /tmp/aipish_frontend.log 2>&1 &) && \
	sleep 6 && \
	echo "backend direct:" && curl -s http://127.0.0.1:8000/api/v1/health && echo && \
	echo "via vite proxy:" && curl -s http://127.0.0.1:5173/api/v1/health && echo && \
	kill $$(lsof -t -iTCP:8000 -iTCP:5173 -sTCP:LISTEN) 2>/dev/null; true

# ── P5i: containers ────────────────────────────────────────────────────────
demo-up:        ## one-command demo: Postgres + backend + nginx with synthetic data (see docs/deployment)
	scripts/demo-up.sh

demo-reset:     ## stop the demo and delete its database volume
	scripts/demo-reset.sh

docker-build:   ## build the backend and web images
	docker build -t aipish-backend:local $(BACKEND_DIR) && docker build -t aipish-web:local $(FRONTEND_DIR)

compose-config: ## validate the compose file with placeholder values (starts nothing)
	POSTGRES_PASSWORD=config-check AIPISH_JWT_SECRET=config-check AIPISH_AUDIT_KEY=config-check \
	  docker compose -f deploy/docker-compose.yml --env-file deploy/env.example config -q && echo "compose config OK"

test-pg:        ## backend suite against a throwaway PostgreSQL (compose profile "test", port 55432)
	POSTGRES_PASSWORD=unused AIPISH_JWT_SECRET=unused AIPISH_AUDIT_KEY=unused \
	  docker compose -f deploy/docker-compose.yml --env-file deploy/env.example --profile test up -d --wait postgres-test
	cd $(BACKEND_DIR) && TEST_DATABASE_URL=postgresql://aipish_test@127.0.0.1:55432/aipish_test \
	  .venv/bin/python -m pytest -q --allow-hosts=127.0.0.1; rc=$$?; cd .. && \
	POSTGRES_PASSWORD=unused AIPISH_JWT_SECRET=unused AIPISH_AUDIT_KEY=unused \
	  docker compose -f deploy/docker-compose.yml --env-file deploy/env.example --profile test rm -sf postgres-test; exit $$rc

retention-dry-run: ## show what the retention policy would purge (changes nothing)
	scripts/retention-run.sh

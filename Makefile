# Email Forensics Platform — dev entry points

BACKEND_DIR := backend
FRONTEND_DIR := frontend

.PHONY: api web test typecheck build demo
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

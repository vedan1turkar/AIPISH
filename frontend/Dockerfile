# syntax=docker/dockerfile:1.7
# AIPISH web (P5i): builds the Vite SPA, then serves it with an unprivileged nginx that also
# reverse-proxies /api to the backend. The UI itself is unchanged; fonts are self-hosted in the build
# (@fontsource), so the container makes no CDN requests.

ARG NODE_IMAGE=node:24.22.3-alpine
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.29.8-alpine

FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM ${NGINX_IMAGE} AS web
LABEL org.opencontainers.image.title="aipish-web" \
      org.opencontainers.image.description="AIPISH SPA + reverse proxy" \
      org.opencontainers.image.source="https://github.com/vedan1turkar/AIPISH"
ENV BACKEND_UPSTREAM=backend:8000 \
    CLIENT_MAX_BODY_SIZE=11m \
    API_READ_TIMEOUT=300s \
    NGINX_ENVSUBST_FILTER="^(BACKEND_UPSTREAM|CLIENT_MAX_BODY_SIZE|API_READ_TIMEOUT)$"
COPY nginx/snippets/ /etc/nginx/snippets/
COPY nginx/templates/ /etc/nginx/templates/
COPY --from=build /src/dist/ /usr/share/nginx/html/
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

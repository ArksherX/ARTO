# ARTO console — build the SPA, serve it with nginx (SPA fallback + /api proxy).
# Build context is the REPO ROOT (needs frontend/ and docs/openapi/):
#   docker build -f frontend/Dockerfile -t arto-console .
FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable
# deps first for layer caching
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
# OpenAPI specs live one level up (gen:api reads ../docs/openapi)
COPY docs/openapi /docs/openapi
COPY frontend/ ./
RUN pnpm gen:api && pnpm build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
# Official nginx image renders /etc/nginx/templates/*.template with envsubst at
# startup. The FILTER limits substitution to our upstream vars so nginx's own
# $uri/$host variables are left intact.
COPY frontend/nginx.conf.template /etc/nginx/templates/default.conf.template
ENV TESSERA_UPSTREAM=http://tessera:8001 \
    VESTIGIA_UPSTREAM=http://vestigia:8002 \
    VERITYFLUX_UPSTREAM=http://verityflux:8003 \
    NGINX_ENVSUBST_FILTER="TESSERA_UPSTREAM|VESTIGIA_UPSTREAM|VERITYFLUX_UPSTREAM"
EXPOSE 80

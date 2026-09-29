# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# deps: install once, reused by both dev and build stages
# ---------------------------------------------------------------------------
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

# ---------------------------------------------------------------------------
# dev: what docker-compose runs locally (live reload against a bind mount)
# ---------------------------------------------------------------------------
FROM deps AS dev
WORKDIR /app
COPY . .
EXPOSE 4200
CMD ["npm", "start", "--", "--host", "0.0.0.0"]

# ---------------------------------------------------------------------------
# build: production bundle
# ---------------------------------------------------------------------------
FROM deps AS build
WORKDIR /app
COPY . .
RUN npm run build -- --configuration production

# ---------------------------------------------------------------------------
# production: static bundle served by nginx
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine AS production
COPY --from=build /app/dist/frontend/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost/ || exit 1

# syntax=docker/dockerfile:1

FROM node:26-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./
COPY apps/mcp-gateway/package.json ./apps/mcp-gateway/package.json
COPY packages/mcp-core/package.json ./packages/mcp-core/package.json
COPY packages/storage-sqlite/package.json ./packages/storage-sqlite/package.json

RUN npm ci

COPY tsconfig.base.json ./
COPY packages/mcp-core ./packages/mcp-core
COPY packages/storage-sqlite ./packages/storage-sqlite
COPY apps/mcp-gateway ./apps/mcp-gateway

RUN npm run build && npm prune --omit=dev

FROM node:26-slim AS runtime

WORKDIR /app

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=8787
ENV SQLITE_PATH=/data/mcphub.sqlite
ENV USER_INACTIVITY_TTL_DAYS=60

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/mcp-core/package.json ./packages/mcp-core/package.json
COPY --from=builder /app/packages/mcp-core/dist ./packages/mcp-core/dist
COPY --from=builder /app/packages/storage-sqlite/package.json ./packages/storage-sqlite/package.json
COPY --from=builder /app/packages/storage-sqlite/dist ./packages/storage-sqlite/dist
COPY --from=builder /app/apps/mcp-gateway/package.json ./apps/mcp-gateway/package.json
COPY --from=builder /app/apps/mcp-gateway/dist ./apps/mcp-gateway/dist
COPY --from=builder /app/apps/mcp-gateway/bin ./apps/mcp-gateway/bin

RUN mkdir -p /data && chown -R node:node /app /data

USER node

EXPOSE 8787

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT ?? '8787') + '/health').then((r) => { if (!r.ok) process.exit(1); }).catch(() => process.exit(1));"]

CMD ["node", "apps/mcp-gateway/bin/server.mjs"]

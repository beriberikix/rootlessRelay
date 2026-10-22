# Node 24 is the current LTS line. Bump deliberately; the sqlite3 native
# module ships prebuilt binaries per Node ABI and is rebuilt by `npm ci`.
# Debian 13 (trixie): the sqlite3 6.x prebuilt binary needs glibc 2.38 or
# newer, and bookworm has 2.36.
FROM node:24-trixie-slim

ENV NODE_ENV=production
WORKDIR /app

# Install production dependencies first so this layer caches across code changes.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# Runtime files only; tests, benchmarks, secrets and local state are excluded
# by .dockerignore.
COPY . .

# Persistent state (the admin user database) lives on a volume at /data.
RUN mkdir -p /data && chown -R node:node /data /app

# Container-appropriate defaults. The image runs in hosted mode (authentication
# required, egress policy on, inbound rules off); set RELAY_MODE=local for the
# original single-operator behavior. TLS is expected to terminate at a reverse
# proxy or load balancer in front of the container, so the relay speaks plain
# WebSocket here. Set ENABLE_WSS=true and mount key.pem/cert.pem into /app to
# terminate TLS inside the container instead. LOG_LEVEL=0 keeps the data plane
# from logging every packet.
ENV RELAY_MODE=hosted \
    LOG_LEVEL=0 \
    ENABLE_WSS=false \
    WS_BIND_ADDRESS=0.0.0.0 \
    WS_PORT=8086 \
    ADMIN_BIND_ADDRESS=0.0.0.0 \
    ADMIN_PORT=8001 \
    PROXY_BIND_ADDRESS=127.0.0.1 \
    PROXY_PORT=8080 \
    ADMIN_AUTH_DB_PATH=/data/admin_auth.sqlite

USER node

EXPOSE 8086 8001

# Readiness: the public listener answers /healthz with 200 (503 while shutting down).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get({host:'127.0.0.1',port:process.env.WS_PORT,path:'/healthz'},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "relay.js"]

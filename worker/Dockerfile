FROM node:20-slim

WORKDIR /app

# install deps
COPY package.json package-lock.json* ./
# if lockfile exists, use ci; else install
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

# app
COPY server.js ./server.js

ENV PORT=8080
EXPOSE 8080
CMD ["node", "server.js"]

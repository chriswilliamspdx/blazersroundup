FROM node:20-slim
WORKDIR /app

# Copy manifest files
COPY package.json package-lock.json* ./

# If a lockfile exists, use npm ci; otherwise use npm install
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev --no-audit --no-fund; \
    fi

# Copy app code
COPY server.js ./server.js

EXPOSE 8080
CMD ["node","server.js"]

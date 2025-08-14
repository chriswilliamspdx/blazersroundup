FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY server.js ./server.js
EXPOSE 8080
CMD ["npm","start"]

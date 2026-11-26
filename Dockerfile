FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.mjs ./

ENV PORT=10000
EXPOSE 10000

CMD ["node", "server.mjs"]

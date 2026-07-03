FROM node:20-alpine
WORKDIR /app
COPY package.json index.js ./
# No dependencies — the bridge uses only Node built-ins (readline, fetch).
ENTRYPOINT ["node", "index.js"]

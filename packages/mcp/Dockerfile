# node:22, matching the platform's own runtime floor (v2.51.0 raised AppCrane to
# Node 22; this image was left on 20, which is the shape of a dependency that
# quietly outlives its support window).
FROM node:22-alpine
WORKDIR /app
COPY package.json index.js ./
# No dependencies — the bridge uses only Node built-ins (readline, fetch).

# Non-root, because AppCrane refuses app-provided Dockerfiles that omit USER
# (services/dockerfileValidator.js) and had no business exempting its own image.
# This process holds a user's GitHub PAT in its environment and speaks JSON-RPC
# over stdio; it needs to read two files it does not own and open outbound HTTPS.
# `node` is the unprivileged user the official image already ships.
USER node

ENTRYPOINT ["node", "index.js"]

FROM node:24-slim

WORKDIR /app

# Install dependencies first (cached unless package files change).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# Copy source + committed circuit files (verification keys, docs).
COPY src/ ./src/
COPY circuits/*.json circuits/*.md circuits/*.txt ./circuits/
COPY scripts/download-artifacts.sh ./scripts/download-artifacts.sh

# Download the official circuit artifacts (.wasm/.zkey, gitignored) and
# verify their checksums at build time. node:24-slim ships no curl, and
# the download script needs it — install it first.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN bash scripts/download-artifacts.sh

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "src/server.js"]

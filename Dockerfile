# Argus runtime: Node + Foundry, so the audit engine can compile and run
# real Foundry PoCs against forked chains inside the container.

FROM node:22-bookworm-slim

# System deps: git (clone target repos), curl/ca-certificates (fetch verified
# source from explorer APIs, download foundry), jq (parse explorer JSON), bash.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates jq bash \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge / cast / anvil) to a stable location on PATH.
ENV FOUNDRY_DIR=/root/.foundry
ENV PATH=/root/.foundry/bin:$PATH
RUN curl -L https://foundry.paradigm.xyz | bash && foundryup

WORKDIR /app

# Install node deps first for layer caching.
COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install --omit=dev

# Build.
COPY tsconfig.json ./
COPY src ./src
RUN npm install typescript --no-save && npx tsc

# Workspaces (per-job sandboxes) live here; mount a Railway volume at /app/workspaces
# in prod so they survive within a deploy (they're throwaway per job anyway).
RUN mkdir -p /app/workspaces

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/index.js"]

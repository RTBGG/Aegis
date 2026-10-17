# Aegis dashboard (Next.js standalone). Build context = ./dashboard
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

FROM node:22-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . ./
ENV NEXT_TELEMETRY_DISABLED=1
# Rewrites (/api/* -> control plane) are compiled into routes-manifest.json at
# build time, so the proxy target must be provided as a build arg, not runtime
# env. Defaults to localhost for `next dev`; compose passes api:8080.
ARG API_PROXY=http://localhost:8080
ENV API_PROXY=$API_PROXY
RUN npm run build

FROM node:22-slim AS run
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]

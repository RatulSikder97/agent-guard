# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN pnpm build && pnpm prune --prod

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json LICENSE ./
COPY examples ./examples
RUN mkdir -p /state && chown node:node /state
USER node
VOLUME ["/state"]
EXPOSE 8787
ENTRYPOINT ["node", "/app/dist/cli.js"]
# Streamable HTTP mode; mount your config at /config/agent-guard.yaml.
# Inside a container the listener must bind 0.0.0.0, which agent-guard only allows with agent tokens.
CMD ["serve", "--config", "/config/agent-guard.yaml", "--state-dir", "/state", "--http", "--host", "0.0.0.0", "--port", "8787"]

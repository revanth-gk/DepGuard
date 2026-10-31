FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
COPY client/package.json ./client/package.json
COPY server/package.json ./server/package.json
RUN npm ci --workspace @depguard/server --include-workspace-root=false --omit=dev
COPY server/src ./server/src
WORKDIR /app/server
ENV NODE_ENV=production
EXPOSE 4000
CMD ["npm", "start"]

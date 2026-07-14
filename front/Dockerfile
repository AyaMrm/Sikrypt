FROM node:20-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ARG VITE_API_BASE=/api

ENV VITE_API_BASE=$VITE_API_BASE

RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.d/99-replace-secrets.sh /docker-entrypoint.d/99-replace-secrets.sh
RUN chmod +x /docker-entrypoint.d/99-replace-secrets.sh
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

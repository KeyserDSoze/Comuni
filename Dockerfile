# Single deployable artifact: modular .NET API + React static frontend
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb AS backend
WORKDIR /build
COPY src/backend/ src/backend/
RUN dotnet publish src/backend/Applications/Api/Comuni.Api.csproj -c Release -o /out --no-self-contained

# Build React from the same root npm workspace/lockfile used in CI.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS frontend
WORKDIR /web
COPY package.json package-lock.json ./
COPY src/frontend/package.json ./src/frontend/package.json
RUN npm ci --no-audit --no-fund
COPY src/frontend/ ./src/frontend/
RUN npm run build --workspace @comuni/frontend

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:bfd912c83295ce66d4b706ebb8541b9f14259b0e76fbb88b2751f58ce2399d2e
WORKDIR /app
COPY --from=backend /out ./
COPY --from=frontend /web/src/frontend/dist ./wwwroot/
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "Comuni.Api.dll"]

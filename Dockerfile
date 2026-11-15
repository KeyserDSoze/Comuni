# Single deployable artifact: modular .NET API + React static frontend
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS backend
WORKDIR /build
COPY src/backend/ src/backend/
RUN dotnet publish src/backend/Applications/Api/Comuni.Api.csproj -c Release -o /out --no-self-contained

FROM node:22-alpine AS frontend
WORKDIR /web
COPY src/frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY src/frontend/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=backend /out ./
COPY --from=frontend /web/dist ./wwwroot/
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "Comuni.Api.dll"]

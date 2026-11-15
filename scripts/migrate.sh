#!/usr/bin/env bash
set -euo pipefail
# Run from repository root. Requires dotnet 10 SDK and dotnet-ef (see .config/dotnet-tools.json).
: "${ConnectionStrings__Default:?Set ConnectionStrings__Default for the target PostgreSQL}"
# The runner may have several SDK versions and this operation must work on a fresh checkout.
# Explicitly restore both design-time and startup projects before invoking dotnet-ef.
dotnet restore src/backend/Infrastructures/Comuni.Infrastructures.csproj
dotnet restore src/backend/Applications/Api/Comuni.Api.csproj
dotnet tool restore
dotnet tool run dotnet-ef database update \
  --project src/backend/Infrastructures/Comuni.Infrastructures.csproj \
  --startup-project src/backend/Applications/Api/Comuni.Api.csproj

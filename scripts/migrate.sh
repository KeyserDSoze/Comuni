#!/usr/bin/env bash
set -euo pipefail
# Run from repository root. Requires dotnet 10 SDK and dotnet-ef (see .config/dotnet-tools.json).
: "${ConnectionStrings__Default:?Set ConnectionStrings__Default for the target PostgreSQL}"
dotnet tool restore
dotnet tool run dotnet-ef database update \
  --project src/backend/Infrastructures/Comuni.Infrastructures.csproj \
  --startup-project src/backend/Applications/Api/Comuni.Api.csproj

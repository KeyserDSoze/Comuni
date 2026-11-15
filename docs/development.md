# Avvio locale

## Docker Compose (applicazione completa)
1. Copiare `docker/.env.example` in `docker/.env`. Generare **due valori casuali** indipendenti per `POSTGRES_PASSWORD` e `JWT_SIGNING_KEY` (minimo 32 byte per JWT); non committarli.
2. `docker compose -f docker/compose.yml up --build`.
3. Aprire `http://localhost:8080`. L'app ASP.NET distribuisce la SPA compilata e applica/inizializza la migrazione **solo in Development**.
4. Emettere un token dimostrativo, da usare nel form di accesso tecnico:
   `node --env-file=docker/.env scripts/create-dev-token.mjs 11111111-1111-1111-1111-111111111111 Officer`.
5. Provare il Comune senza Protocollo con:
   `node --env-file=docker/.env scripts/create-dev-token.mjs 22222222-2222-2222-2222-222222222222 Reader`.

I token sono JWT HS256 firmati localmente, validi un'ora e mantenuti **solo in memoria React**, non in localStorage. Questi token NON sono un sistema di login reale. Non abilitare secret o issuer demo in produzione. Per la fase OIDC vedere ADR 0004.

## Frontend per sviluppo con HMR
Avviare l'API su `http://localhost:8080` con PostgreSQL disponibile e le stesse variabili d'ambiente; poi `cd src/frontend && npm install && npm run dev`, aprire `http://localhost:5173` (proxy API incluso). Per test browser: `npx playwright install chromium && npm run test:e2e`.

## Backend e migrazioni
Requisiti: .NET SDK 10, Node 22, Docker Compose. Aggiornare lo schema mediante `ConnectionStrings__Default="..." bash scripts/migrate.sh`. L'uso manuale delle migrazioni è obbligatorio prima dei deployment in produzione: il bootstrap automatico esiste solo in Development.

## TDD
Test rapidi: `dotnet test tests/backend/Comuni.UnitTests/Comuni.UnitTests.csproj`. Test di integrazione: PostgreSQL reale e `TEST_DATABASE_CONNECTION="..." dotnet test tests/backend/Comuni.Api.Tests/Comuni.Api.Tests.csproj`; usare un **database disposable**. Playwright usa mocking degli endpoint per testare i permessi UI indipendentemente dal backend.

# Avvio locale

## Docker Compose (applicazione completa)
1. Copiare `docker/.env.example` in `docker/.env`. Generare **due valori casuali** indipendenti per `POSTGRES_PASSWORD` e `JWT_SIGNING_KEY` (minimo 32 byte per JWT); non committarli.
2. `docker compose -f docker/compose.yml up --build`.
3. Aprire `http://localhost:8080`. L'app ASP.NET distribuisce la SPA compilata e applica/inizializza la migrazione **solo in Development**.
4. Emettere un token dimostrativo, da usare nel form di accesso tecnico:
   `node --env-file=docker/.env scripts/create-dev-token.mjs 11111111-1111-1111-1111-111111111111 local-developer`.
5. Per provare **Amministrazione → Protocollo** con membership Admin dimostrativa, generare il token (solo ambiente Development):
   `node --env-file=docker/.env scripts/create-dev-token.mjs 11111111-1111-1111-1111-111111111111 local-admin`.
6. Provare il Comune senza Protocollo con:
   `node --env-file=docker/.env scripts/create-dev-token.mjs 22222222-2222-2222-2222-222222222222 local-developer`.

Il `sub` del JWT demo è `local-developer` (oppure `local-admin` per un Admin di prova del solo Comune Aurora); i ruoli effettivi (Officer in Aurora, Reader in Borgo; Admin per il solo `local-admin` di Aurora) derivano da `platform.organization_memberships`. Il claim `role` non è fonte di autorizzazione. Il seed delle membership esiste **solo in Development**, non nel deploy Azure.

I token sono JWT HS256 firmati localmente, validi un'ora e mantenuti **solo in memoria React**, non in localStorage. Questi token NON sono un sistema di login reale. `Authentication:Mode=DevelopmentJwt` è ammesso solo in Development/Testing; la produzione usa `Authentication:Mode=Oidc` con Authority HTTPS e Audience e **rifiuta** il segreto demo. Il frontend richiede ancora l'inserimento manuale del JWT: non esiste un login OIDC end-to-end. Vedere ADR 0007 e issue #2.

## Frontend per sviluppo con HMR
Avviare l'API su `http://localhost:8080` con PostgreSQL disponibile e le stesse variabili d'ambiente; poi dalla root `npm install && npm run dev --workspace @comuni/frontend`, aprire `http://localhost:5173` (proxy API incluso). Per test browser: `npx playwright install chromium && npm run test:e2e --workspace @comuni/frontend`.

## Backend e migrazioni
Requisiti: .NET SDK 10, Node 22, Docker Compose. Aggiornare lo schema mediante `ConnectionStrings__Default="..." bash scripts/migrate.sh`. L'uso manuale delle migrazioni è obbligatorio prima dei deployment in produzione: il bootstrap automatico esiste solo in Development.

## TDD
Test rapidi: `dotnet test tests/backend/Comuni.UnitTests/Comuni.UnitTests.csproj`. Test di integrazione: PostgreSQL reale e `TEST_DATABASE_CONNECTION="..." dotnet test tests/backend/Comuni.Api.Tests/Comuni.Api.Tests.csproj`; usare un **database disposable**. Playwright usa mocking degli endpoint per testare i permessi UI indipendentemente dal backend.

## Credenziale locale di verifica RLS

Generare e configurare in `docker/.env` anche `TENANT_PROOF_KEY` (minimo 32 byte casuali, ad esempio `openssl rand -hex 32`). Docker Compose la passa soltanto al backend, **non** al frontend. In Development il bootstrap EF migra e memorizza la chiave nella tabella privata dopo `MigrateAsync`; in Production il bootstrap è esterno e il ruolo runtime non può mai scriverla. Dopo la modifica della chiave locale, riavviare il servizio Development, che aggiorna la chiave nel database demo. Vedere ADR 0013; non utilizzare la chiave di esempio in produzione.

## Verifica locale delle chiavi tenant versionate

`Security__TenantProofKeyId` è facoltativo; quando manca, il signer emette prove legacy a quattro campi (soltanto in presenza di un record DB `legacy` autorizzato). Per provare il nuovo protocollo usare un database migrato, effettuare lo staging con `TENANT_PROOF_KEY_ID` e `TENANT_PROOF_KEY` nell'ambiente del processo owner e lanciare `psql -f scripts/postgres/stage-tenant-proof-key.sql`. Impostare poi entrambe le variabili `Security__TenantProofKeyId`/`Security__TenantProofKey` nell'API. Non fare test con segreti di produzione. La CI copre staging ripetuto, revoca, unit tests del signer e verifier sotto PostgreSQL 17.

## Login browser OIDC (ADR 0020, issue #26)

In **DevelopmentJwt** è disponibile soltanto il form tecnico JWT locale. In **Production/Oidc**, l'API pubblica `GET /api/v1/auth/browser`; il frontend presenta il pulsante di accesso solo se il server dichiara un provider browser completo. Senza provider OIDC browser configurato il form manuale **non compare** e la UI presenta `Accesso OIDC non configurato`.

Per un futuro IdP di **test**, registrare un client pubblico browser con Authorization Code + PKCE S256 (senza client secret), URI di redirect esatta `http://127.0.0.1:5173/` per i soli test locali, oppure `https://<origine portale>/` per ambiente autorizzato, e CORS per il token endpoint. Impostare lato API **quattro impostazioni non segrete** `Authentication__BrowserClientId`, `Authentication__BrowserAuthorizationEndpoint`, `Authentication__BrowserTokenEndpoint`, `Authentication__BrowserScope` oltre ad Authority/Audience già previsti. Il token deve essere un **access token per l'audience API**, firmato RS256, con `organization_id` e `sub` mappati a membership PostgreSQL effettive; `id_token` non autorizza gli endpoint. Tutte le configurazioni browser devono essere complete oppure assenti, altrimenti l'API rifiuta l'avvio.

Nessun IdP è registrato/provisionato in questa repository; i test Playwright eseguono mock. Le variabili Terraform `authentication_browser_*` hanno default vuoto (login disabilitato) e sono valorizzate nel GitHub Environment tramite `OIDC_BROWSER_*`, **senza secrets**. Evitare di mettere client secret, refresh token o access token in Terraform, Github Variables o bundle frontend.

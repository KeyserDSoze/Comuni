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
Avviare l'API su `http://localhost:8080` con PostgreSQL disponibile e le stesse variabili d'ambiente; poi dalla root `npm ci && npm run dev --workspace @comuni/frontend`, aprire `http://localhost:5173` (proxy API incluso). Per test browser: `npx playwright install chromium && npm run test:e2e --workspace @comuni/frontend`.

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

## Amministrazione Reader/Officer locale (ADR 0021 / #27)

Nel Docker Compose Development il soggetto demo `local-admin` di Comune Aurora ha già ruolo Admin. Con il token DevelopmentJwt generato nello step 5 di questa guida, aprire **Amministrazione → Membri del Comune** per aggiungere/disattivare/riattivare `Reader` o `Officer` mediante un `sub` **già noto**. Non è un'invito/registrazione IdP e non consente gestire Admin, SPID/CIE o accedere agli altri Comuni. Le membership sono persistite nel PostgreSQL condiviso, gli eventi di modifica sono transazionali e l'accesso cambia alla richiesta successiva.

Quando si applicano le migrazioni in Production/test con ruolo runtime separato, eseguire `202611150008_RuntimeMembershipRoleGuard` con l'owner prima di riconcedere i privilegi colonnari tramite `scripts/postgres/provision-runtime-role.sql`; l'API runtime non deve eseguire DDL né creare membership Admin. Nessun provisioning utenti automatico in produzione: verificare in anticipo `issuer` e `sub` nel provider reale prima di concedere una membership.

## Collegamento issuer/sub OIDC dopo migration 0009 (ADR 0022 / #28)

**Fail-closed per il passaggio a OIDC:** `identity_issuer` su `platform.organization_memberships` è nullable, ma solo una membership con issuer esatto può consentire un JWT OIDC. Le righe esistenti senza issuer restano nel DB per i vecchi test e il controllo operativo, **non** vengono associate automaticamente al nuovo provider. Questo può bloccare anche ogni Admin se la prima migrazione è eseguita senza una fase di onboarding sicura. Preparare un elenco di `organization_id`, `role`, `sub` e **issuer HTTPS canonico attestato** dal provider, sottoposto ad approvazione dell'operatore e audit del change esterno.

Procedura prevista per un futuro ambiente di test/non reale:
1. Verificare formalmente il provider tramite discovery HTTPS attendibile, audience dell'API, token RS256 valido, `sub` e `iss` esatti e membership preesistenti. Mai usare email o username per indovinare il `sub`.
2. Con credenziali **owner solo su runner privato** e change ticket approvato, pianificare le modifiche alla membership specifica; verificare che l'Admin non perda l'unico accesso e che non ci siano due provider che riutilizzano lo stesso sub. Il runtime non ha i privilegi per `UPDATE(identity_issuer)`. Non c'è un comando automatico di backfill in repository.
3. Dopo l'aggiornamento approvato del binding (e un eventuale audit operativo esterno), usare **token di test temporanei** del provider, verificare un accesso consentito e rifiuti per issuer NULL/diverso, confermare il tenant isolato con RLS; solo successivamente abilitare il login. Pianificare rollback in caso di issuer errato e non attivare mai un fallback a issuer NULL.
4. L'Admin già collegato all'IdP può usare `PUT /api/v1/admin/memberships/Reader|Officer` per **nuove** assegnazioni, senza poter scegliere l'issuer. Se il subject/ruolo era presente con issuer differente, riceve 409 e deve richiedere una procedura owner con verifica del provider.

Questo runbook è **una specifica per una futura procedura autorizzata**: nessun IdP reale, tenant live o owner provisioning è stato eseguito. La reale creazione e verifica di utenti/identità resta #2.

## Installazioni npm riproducibili (ADR 0024 / #30)

Dalla root usare sempre `npm ci` dopo il clone (Node.js 22 e npm 10). `npm ci` rifiuta manifest e lockfile incoerenti e non aggiorna il lockfile. Il file `package-lock.json` versionato nella root risolve anche il workspace `src/frontend`: **non** installare separatamente dentro la cartella frontend e non creare un secondo lockfile.

Per aggiornare consapevolmente le dipendenze, modificare i manifest, eseguire dalla **root** `npm install --package-lock-only --ignore-scripts` con un registry affidabile, esaminare le differenze di lockfile incluse URL e integrity SHA-512, quindi verificare `npm ci`, build e Playwright prima di committare manifest e lock insieme. Non usare `npm audit fix` come aggiornamento non revisionato. La CI su `main` riesegue `npm ci` in frontend e Docker, oltre all'audit npm runtime.

## Test tecnico bootstrap primo Admin (#31)

Lo script `scripts/postgres/bootstrap-initial-admin.sql` è riservato all'owner su una organization **già esistente e priva di Admin**; non usarlo sui seed Development con Admin legacy. La CI PostgreSQL 17 esegue `InitialAdminBootstrapTests` con organization e subject sintetici e `psql` presente nel runner; non c'è alcun IdP reale. Prima di una procedura autorizzata consultare ADR 0025 e `docs/deployment.md`. Il bootstrap richiede esplicitamente issuer, subject, organization UUID, change ticket e reviewer esterni: non è un backfill automatico e non è accessibile dalla SPA/API.


## Provisioning tecnico di organizzazioni (ADR 0026 / #32)

Per **nuove** organization con UUID verificato, il runner PostgreSQL owner può usare `scripts/postgres/provision-organization.sql` dopo aver valorizzato `COMUNI_PROVISION_ORGANIZATION_ID`, `COMUNI_PROVISION_ORGANIZATION_NAME`, `COMUNI_PROVISION_CHANGE_TICKET`, `COMUNI_PROVISION_APPROVER`. Richiede change e revisore approvati esternamente; nessun segreto, dato personale o password nel repository. Vedere `docs/deployment.md` per comando `psql`, TLS, guardie owner e verifiche post-esecuzione. Lo script non assegna ruoli: il primo Admin si crea in un passaggio **separato** (ADR 0025) solo dopo verifica issuer/sub IdP. La riga `protocol` nasce disabled e può essere attivata esclusivamente da un Admin autenticato via l'API già presente; tutti i test CI usano organizzazioni sintetiche.


## Test lifecycle Comune (#33 / ADR 0027)

`scripts/postgres/set-organization-suspension.sql` implementa soltanto transizioni approvate offline `suspend`/`reactivate` con `COMUNI_LIFECYCLE_ORGANIZATION_ID`, `COMUNI_LIFECYCLE_ACTION`, `COMUNI_LIFECYCLE_CHANGE_TICKET`, `COMUNI_LIFECYCLE_APPROVER` e `COMUNI_LIFECYCLE_REASON_CODE`. Non è un endpoint API o un bottone Admin, e non eseguirlo come `comuni_app_runtime`. In CI `OrganizationLifecycleTests` verifica PostgreSQL reale, psql e blocchi 403 su un Comune sintetico; la riattivazione non riabilita membership disattivate o moduli. Leggere il runbook `docs/deployment.md` e ADR 0027 prima di qualunque change; provider e autorizzazioni dell'operatore non sono presenti nel repository.


## Gate identità Superadmin read-only (#34 / ADR 0028)

`/api/v1/platform/session` è un endpoint di verifica del proprio ruolo **esclusivamente OIDC** (non un accesso ai dati dei Comuni): richiede JWT RS256 verificato senza `organization_id` e riga owner-managed `platform.platform_operators` `is_active=TRUE`, non un claim JWT `role`. La migration EF `202611150010_PlatformOperatorIdentityBoundary` crea tabella e funzione booleana; dopo ogni migrazione eseguire lo script di provisioning runtime per il grant `EXECUTE` sulla funzione senza accesso alla tabella. In modalità DevelopmentJwt il test deve essere 403 senza alcun seed; le fixture OIDC RSA e il DB locale PostgreSQL generano soli operatori sintetici. Non inserire identità/ruoli Superadmin manualmente su DB reale: manca il processo di approval e onboarding.


## Test della gestione owner-only operatori piattaforma (#35 / ADR 0029)

Il nuovo script `scripts/postgres/manage-platform-operator.sql` opera unicamente su identità globali `iss+sub` verificate **esternamente** dopo un change indipendente; accetta `COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER`, `COMUNI_PLATFORM_OPERATOR_SUBJECT`, `COMUNI_PLATFORM_OPERATOR_ACTION` (`enroll`/`revoke`), `COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET` e `COMUNI_PLATFORM_OPERATOR_APPROVER`. Non eseguirlo nel normale processo web/SPA, con credenziali `comuni_app_runtime` o in production senza operatori e processo di approvazione autorizzato. I test sintetici `PlatformOperatorEnrollmentTests` usano PostgreSQL reale con login owner, `psql`, IdP RSA simulato e runtime a privilegi minimi; verificano audit globali, invalid input, concorrenza, revoca, reintegro e denial runtime. Consultare il runbook in `docs/deployment.md` e ADR 0029, senza scrivere credenziali e dati personali in repository, log e ticket GitHub.

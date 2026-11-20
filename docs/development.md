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

**Soltanto in Development/Testing**, `Security__TenantProofKeyId` è facoltativo; quando manca, il signer demo emette prove legacy a quattro campi (soltanto in presenza di un record DB `legacy` autorizzato). **In Production e in ogni ambiente ospitato**, il controllo #47 richiede invece un ID esplicito, valido e diverso da `legacy` prima dell'avvio dell'API; il verifier PostgreSQL può continuare ad accettare vecchie prove legacy nel grace approvato finché l'owner non le ritira. Per provare il nuovo protocollo usare un database migrato, effettuare lo staging con `TENANT_PROOF_KEY_ID` e `TENANT_PROOF_KEY` nell'ambiente del processo owner e lanciare `psql -f scripts/postgres/stage-tenant-proof-key.sql`. Impostare poi entrambe le variabili `Security__TenantProofKeyId`/`Security__TenantProofKey` nell'API. Non fare test con segreti di produzione. La CI copre staging ripetuto, revoca, unit tests del signer e verifier sotto PostgreSQL 17.

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


## SPA Superadmin read-only (ADR 0030 / #36)

Per testare la prima area `/platform` nella **stessa React**, usare `npm ci && npm run build --workspace @comuni/frontend && npm run test:e2e --workspace @comuni/frontend`. I test Playwright fanno mock degli endpoint OIDC e di `GET /api/v1/platform/session`/context, senza credenziali reali. Il menu Superadmin dipende **solo dalla risposta backend valida**, non da `role` JWT, tenant id, query URL o storage; token solo RAM, riverifica on focus e navigazione, rimozione view dopo deny e logout. In DevelopmentJwt non si attiva mai la sessione piattaforma, anche inserendo un JWT falso. Nessuna tabella/modulo/API è stata creata dalla UI. Per i requisiti operativi e rischio XSS vedere ADR 0020/0028–0030, `docs/security.md` e `docs/api.md`. Un provider IdP reale, Azure live e MFA non sono verificati.


## Inventario Superadmin globale, opt-in in testing (#37 / ADR 0031)

Con PostgreSQL 17 migrated, eseguire `scripts/postgres/provision-platform-read-role.sql` **come owner** passando `PLATFORM_READ_DB_PASSWORD` da env; il database deve restare unico. `PlatformInventory__Enabled=true` e `ConnectionStrings__PlatformRead` sono richiesti per abilitare il nuovo endpoint; l'username dev/test deve essere **esattamente** `comuni_platform_reader` e la password **differente** dal runtime comunale/owner. `TEST_PLATFORM_DATABASE_CONNECTION` è un input **solo test**: `OidcApiFactory` lo usa prima del bootstrap della API in ambiente Testing per attivare la funzionalità, mentre Production e Development la lasciano OFF se non esplicitamente configurata. Non usare credenziali owner per la lettura.

`PlatformInventoryApiTests` verifica paginazione su 2+ Comuni, output minimale, 401/403/400, change di stato membership, audit atomico, SQL injection e **differenza tra i due login PostgreSQL**. `tests/frontend/platform-inventory.spec.ts` verifica con mock Playwright tabella della stessa area Superadmin, pulsante `Carica altri Comuni`, errori, revoca 403 che cancella i dati, IT/EN e tema. `npm ci && npm run build --workspace @comuni/frontend && npm run test:e2e --workspace @comuni/frontend` e `dotnet test tests/backend/Comuni.Api.Tests/Comuni.Api.Tests.csproj` sono i comandi locali, con PostgreSQL e credenziali CI-like predisposti. Se il flag non è attivo il backend risponde 503 e il frontend non mostra alcun inventario, senza fallback insicuri.

Questo non fornisce un frontend per gestire i Comuni: niente CRUD, impersonificazione, login IdP live, Azure staging reale o compliance normativa. Vedere ADR 0031, `docs/deployment.md` e `docs/security.md`.


## Admin municipale: consultazione degli ultimi 25 eventi audit (#41 / ADR 0035)

La PWA unica dispone ora nell'area **Amministrazione** della tabella read-only `Attività recenti del Comune`. Il frontend richiede `GET /api/v1/admin/audit` soltanto quando il `GET /api/v1/context` verificato presenta il ruolo `Admin`; la **vera autorizzazione** rimane sull'API, con membership PostgreSQL, stato Comune e RLS HMAC firmata. La risposta contiene esattamente `id`, `action`, `resourceType` e `occurredAt` dei **25 eventi più recenti**; niente actor/correlation/resource IDs, query arbitrary, export, rosters o consultazione globale.

**Ordine provisioning/test:** eseguire migrazioni con schema owner, quindi rieseguire **come owner** `scripts/postgres/provision-runtime-role.sql` con `RUNTIME_DB_PASSWORD` da secret manager; il file ripristina una grant SELECT a **cinque colonne** della tabella audit ma non SELECT tabella completa. Non modificare le policy RLS né usare la connessione owner nel runtime. Dopo il provisioning, verificare `tests/backend/Comuni.Api.Tests/MunicipalAuditApiTests.cs`, `RuntimeDatabasePrivilegesTests.cs` e `npm ci && npm run test:e2e --workspace @comuni/frontend`. L'URL non accetta `organizationId`, `limit`, `after` o altri parametri: tutti i tentativi danno 400. La vista non sostituisce log di sicurezza/audit compliance né una funzione di export istituzionale; vedere ADR 0035 e `docs/security.md`.

## #42 — Ogni lettura Admin dell'audit viene tracciata (ADR 0036)

Dalla #42 un `GET /api/v1/admin/audit` autorizzato 200 registra nella stessa signed-RLS transaction `platform.audit.consulted`. La `MunicipalAuditService` Business inoltra soltanto l'organization verificata; `OrganizationAuditReader.ListRecentAndRecordAsync` in Infrastructure costruisce l'evento tramite `ICurrentActorContext` della stessa richiesta, poi esegue SELECT dei 25 metadata e `SaveChangesAsync` dell'audit. L'evento **non** è mostrato nella propria risposta, ma può comparire al refresh successivo. Query 400 e accessi anonimi/Reader/Officer 401/403 non scrivono eventi. Lo stesso componente Admin React mostra una nota IT/EN che spiega il logging, senza nuove API o permessi. Test xUnit con role PostgreSQL ristretto e signed proof verificano commit/rollback; Playwright controlla la nota. Nessuna modifica agli endpoint di impersonificazione, al login o alla conservazione/retention.


## #43 — New-organization registration, owner-only (ADR 0037)

L'ambiente PostgreSQL 17 locale/test usa il nuovo `scripts/postgres/register-organization.sql` per creare una organization con UUID fornito dal runner, nome verificato, audit `platform.organization.registered`, **Protocollo off** e nessun Admin. Imposta in un ambiente privato `COMUNI_REGISTER_ORGANIZATION_ID`, `COMUNI_REGISTER_ORGANIZATION_NAME`, `COMUNI_REGISTER_CHANGE_TICKET` e `COMUNI_REGISTER_APPROVER`; lancia `psql -X -q -v ON_ERROR_STOP=1 -f ...` come **owner**, mai come runtime. Il bootstrap del primo Admin OIDC avviene tramite `bootstrap-initial-admin.sql` distinto; dal completamento della #44 è necessaria anche la separata `activate-organization.sql` owner prima che l'Admin possa accedere e attivare i moduli. Test `OrganizationRegistrationTests` nella CI backend esercitano input malevoli, conflitti, transazioni concorrenti, sospensione e login runtime ristretto. La registrazione #43 non richiede API/routes React, grant o risorse Azure; la successiva #44 aggiunge **una migration** e un gate di autorizzazione, senza nuovi servizi; non usare su Comuni reali senza il processo esterno di onboarding autorizzato.


## #44 — Organization activation gate e lifecycle a tre stati (ADR 0038)

La migration PostgreSQL 0013 mappa `is_activated` con default TRUE per i Comuni legacy (preserva preexisting active/suspended) e CHECK `is_activated OR NOT is_suspended`. `register-organization.sql` (#43) ora crea `created`, non ancora operativo. `bootstrap-initial-admin.sql` (#31) assegna il primo Admin OIDC senza aprire la API; `activate-organization.sql` owner-only con ticket/reviewer validati esegue la transizione created→active e audit `platform.organization.activated` in una transaction. Solo da active l'API consente accesso con membership attiva; Protocollo richiede ancora la propria feature flag enabled. `set-organization-suspension.sql` resta riservato al post-activation e rifiuta created.

Test in `OrganizationActivationTests` con PostgreSQL e psql reali: created 403 anche dopo Admin, activation con issuer HTTPS + modules disabled, concurrent/idempotent, runtime UPDATE denied, CHECK pending/suspended, vista inventory nonoperativa e legacy backfill. La PWA React Superadmin usa il compat flag `isSuspended` per indicare *Non operativo*, non uno stato esatto. Nessun CRUD cross-Comune aggiunto o deploy Azure reale. Per ambienti privati seguire `docs/deployment.md`; non lanciare owner scripts con password in argv o con `psql -a/-e`.

## #51 — Configurazione SQL per ambienti ospitati (ADR 0044)

Il database locale continua a essere PostgreSQL; `Development` e `Testing` possono usare `Host=localhost` o il container Docker Compose senza CA Azure per i test. Negli altri ambienti il bootstrap valida **prima di EF** `ConnectionStrings:Default`: host FQDN del server Azure PostgreSQL Flexible Server nel formato `<server>.postgres.database.azure.com`, ruolo `comuni_app_runtime` e `SSL Mode=VerifyFull;Trust Server Certificate=false`; non sono validi IP, alias privati, hostname multipli, `Require`, `VerifyCA` o `Trust Server Certificate=true`. Configurare l'FQDN *reale* e il trust delle root CA in Azure, senza segreti nel repository. Vedere ADR 0043/0044 e `docs/deployment.md`. L'host può risolvere a un indirizzo privato tramite DNS/VNet, ma il nome presentato al verificatore TLS deve restare quello certificato; la presenza dei soli metadati URI Key Vault non garantisce una connessione reale sicura. Le revisioni stable già distribuite non sono convertite automaticamente.

## #52 — Runtime PostgreSQL: hostname di riferimento indipendente (ADR 0045)

In `Production`, `Staging` e ogni altro ambiente ospitato, `RuntimePostgresConnectionSettings.Read` richiede **due sorgenti**: `ConnectionStrings:Default` da Key Vault e il metadato `RuntimePostgres:ExpectedHost` derivato dalla risorsa Terraform `azurerm_postgresql_flexible_server.main.fqdn`. Devono combaciare esattamente come FQDN Azure PostgreSQL Flexible Server (ignorando soltanto il casing), oltre a `SSL Mode=VerifyFull;Trust Server Certificate=false`, porta 5432, `comuni_app_runtime` e database. Non scegliere un host di riferimento dalla stringa di connessione stessa o dall'input di un operatore. In `Development`/`Testing` la sorgente host non è obbligatoria, per mantenere i test PostgreSQL locali. Gli smoke Azure e la migrazione stable legacy non sono completati.

## #53 — Contratto dei piani Azure (ADR 0046)

Per il normale sviluppo mantenere una sola API e un solo database. Il workflow di deploy **non** è un bootstrap Terraform general-purpose: in uno staging della candidata è consentito soltanto l'update dell'unica `azurerm_container_app.main`; tutte le altre risorse devono essere `no-op`. Il validatore blocca azioni di creazione, lettura, update, rimozione, drift e output mutati; non inserirle in una release da 0% del traffico. La migrazione dello state per la password storica richiede una procedura e approvazione specifica e non va mescolata con lo staging. Per i test offline eseguire `python3 -m unittest discover -s tests/infra` oltre alle suite .NET 10 e Playwright. Il file di piano Terraform può contenere secret: non stamparlo, caricarlo o copiarlo nel repository.

## #55 — Preparazione del trasferimento della gestione delle secret fuori dallo State (ADR 0048)

Il file `infra/main.tf` continua intenzionalmente a contenere `azurerm_key_vault_secret.postgres_connection` e la dipendenza `.versionless_id`: modificarle adesso provocherebbe una diff in un deployment di staging che ADR 0046 blocca. È disponibile soltanto un validatore di piano, `python3 scripts/azure/check-legacy-postgres-handoff-plan.py`, che consuma JSON da stdin e rifiuta tutte le operazioni Terraform tranne l'eventuale `["forget"]` della singola secret legacy e risorse `["no-op"]`. Non eseguirlo come autorizzazione all'apply e non utilizzare credenziali reali nei test. Il passaggio live richiede approvazione dedicata e preflight di tutte le revisioni #54; ritiro da State, cancellazione del secret e rotazione della password sono tre procedimenti diversi.

## #56 — Non conservare i piani Terraform di stage nel workspace (ADR 0049)

Per rilasci manuali della sola ACA, il workflow crea il piano con `umask 077`, rifiuta piano/symlink preesistenti, verifica via pipe il JSON del piano senza stamparlo e registra prima del comando `plan` un `trap EXIT` che elimina il file binario dopo successo o errore. Non salvare `deploy.tfplan` come Artifact né usarlo per debugging in issue/log: il contenuto può includere password PostgreSQL tratte dal Terraform State. Si tratta di cleanup locale **non di secure erase**. Ogni operazione reale di handoff o ripulitura delle copie storiche dello State richiede un procedimento distinto con operatori autorizzati (#49/#55).

## #57 — Test dei claim identitari non ambigui (ADR 0050)

Ogni `ClaimsPrincipal` che raggiunge un'API comunale deve contenere un unico `organization_id`, un unico `sub` e un unico `iss`; per la piattaforma non deve esistere alcun `organization_id`. I duplicati (anche identici) negano l'autorizzazione prima delle query PostgreSQL e il contesto audit restituisce valori vuoti invece di usare `FindFirst`. Il controllo è centrale in `VerifiedPrincipalIdentity` e viene riutilizzato da policy, middleware transazionale, context e rate limiter. Testare con `UnambiguousPrincipalTests.cs` e la CI PostgreSQL; non dedurre l'abilitazione di un ruolo dal solo JWT. Non sono richiesti nuovi `TF_VAR`, migration o alterazioni di `infra/main.tf`.

## #58 — Test per duplicate JSON JWT con firme reali sintetiche (ADR 0051)

Per le API, oltre a `UnambiguousPrincipalTests` (#57), eseguire `SignedDuplicateJwtPayloadTests` (#58): il primo gruppo costruisce payload JSON verbatim e firma token HS256 test-only, il secondo firma i byte raw RS256 con il `OidcApiFactory` e usa il JWKS sintetico. La policy rifiuta **401** le proprietà JSON duplicate prima della scelta dei claim, anche se ASP.NET Core materializzerebbe un singolo `sub` o `organization_id`. Si validano anche proprietà nested, escape Unicode, JSON malformato e limite 64 KiB, e la compatibilità dei token validi. Il controllo opera sul token dopo validazione JwtBearer, non sul valore libero dell'header Authorization; non conservare token o segreti nei log di test. La chiusura #58 richiede CI 7/7 sulla SHA finale e non implica un IdP reale o una revisione normativa completa.

## #60 — Regressioni JWT JOSE dopo validazione JwtBearer (ADR 0052)

Per la verifica locale eseguire `dotnet test tests/backend/Comuni.Api.Tests/Comuni.Api.Tests.csproj` con PostgreSQL 17 di test e `TEST_DATABASE_CONNECTION` valido. La suite `SignedDuplicateJoseHeaderTests` costruisce JWT compatti HS256 finti (solo `Testing`) e RS256 con chiave/JWKS di prova, controlla duplicati `alg/kid/typ`, escape Unicode, JSON nested e limite header 8 KiB, senza raccogliere token di persone reali. Il guard usa **esclusivamente** i bytes del `SecurityToken` accettato dal framework `JwtBearer`; non analizza il token dell'header Authorization come fonte attendibile. La CI 7/7 prova il codice, non gli IdP o i certificati Azure di produzione. #2/#5/#49 rimangono epiche aperte.

## Lifecycle del provisioning legacy dopo #102 (ADR 0086)

Anche `provision-organization.sql` (procedura legacy owner-only) ora crea **created/is_activated=FALSE**, non active: `bootstrap-initial-admin.sql` associa il primo Admin OIDC ma lascia tutte le route tenant 403; è obbligatoria una distinta `activate-organization.sql` owner per la transizione a active, con evento audit e modulo Protocollo ancora off. `register-organization.sql` resta il percorso canonico per la registrazione pending. Nessun comando di test con valori sintetici equivale a onboarding reale o a verifiche indipendenti di identità/mandato/MFA.

## #113 — Verifica delle consultazioni e dell'actor

I test PostgreSQL con login runtime limitato ora iniettano l'actor sintetico nel `OrganizationAuditReader`, senza passare eventi preassemblati. Verificano che actor/correlation vuoti falliscano prima della SELECT e che il commit contenga solo metadati server-owned; la route reale continua a rifiutare header falsificati. Eseguire la suite xUnit con PostgreSQL 17 e poi l'intera CI su `main`.

## #114 — Metadati audit: nessun Trim implicito

Per costruire `AuditEvent`, passare actor e correlation già verificati/canonici, senza spazi esterni né caratteri di controllo. `AuditEvent.Create` rifiuta tali input anziché normalizzarli; la factory mantiene il valore esatto in PostgreSQL. I metadati di azione e tipo devono essere nomi canonici, non messaggi o contenuto utente; i valori validi di lunghezza entro 160/120/100/128 rispettivamente sono conservati. I controlli JWT, la membership Admin, RLS firmata e l'audit append-only restano obbligatori e separati. I test xUnit e PostgreSQL 17 con dati sintetici coprono queste regole.

## #115 — Gate privacy log pgAudit ROLE/DDL

Per modifiche a `scripts/postgres/provision-{runtime,platform-read}-role.sql` il gate sintetico analizza i log reali PostgreSQL17/pgAudit e fallisce se una singola operazione `CREATE/ALTER ROLE` non reca `<REDACTED>` o contiene parti sensibili del verificatore SCRAM. Eseguire prima `python3 -m unittest tests/infra/test_pgaudit_log_analyzer.py` (via discover di `tests/infra`) e poi la CI completa, che avvia una fixture Docker isolata. L'analizzatore non stampa mai log né canary; non usare valori veri o disabilitare `pgaudit.log`. Per Azure/pgAudit/SIEM live la #92 rimane bloccante.

## #116 — Controllo pgAudit sintetico dell'onboarding

Il bootstrap offline del primo Admin continua a richiedere issuer/sub OIDC approvati separatamente; non è un self-service. La CI esegue gli script `register-organization.sql` e `bootstrap-initial-admin.sql` nel PostgreSQL 17+pgAudit isolato, con valori sintetici da `stream-private-input.py` e senza nuove variabili nell'inventory. Per riprodurre la regressione Python: `python3 -m unittest discover -s tests/infra -p 'test_*.py' -v`; il test integrato è già parte del backend GitHub Actions. Non eseguire l'helper in terminale, non stampare stdout della COPY o log contenenti input, non usare `psql -a/-e`, `set -x`, segreti live o tenant reali. Le verifiche Azure/SIEM/Privacy richiedono attività separate nelle #86/#92/#84.

## #116 — Preflight metadata-only per owner-only OIDC (ADR 0100)

**Solo in ambienti sintetici autorizzati**: il gate pgAudit verifica `register-organization.sql` e `bootstrap-initial-admin.sql` con `pgaudit.log_parameter=off`, mantenendo categorie `role,ddl,write,function` attive e native statement logging. Con `pgaudit.log_parameter=on` gli script falliscono volontariamente prima della `\\copy` e dei DML, con errore statico. Non modificare la configurazione globale del server per rendere verdi i test, non ridurre `pgaudit.log` e non usare variabili di ambiente con dati reali. Una CI che evidenzia canary leak deve rimanere rossa finché la causa non viene corretta; la prova locale non sostituisce l'approvazione del provider Azure/SIEM/Privacy.

## #117 — Preflight pgAudit per activation e secondo Admin OIDC

L'operatore schema-owner (in ambienti solo sintetici/test) deve usare un profilo pgAudit con `pgaudit.log_parameter=off` e mantenere attive le classi `role,ddl,write,function` e il logging nativo degli statement; `activate-organization.sql` ed `enroll-additional-admin.sql` **rifiutano l'on**, prima di avviare `\\copy`. Non spegnere pgAudit per passare i test, non invocare il producer COPY direttamente con stdout su terminale, non abilitare `-a/-e` o shell tracing, non passare OIDC issuer/sub/ticket come argv o SQL literal. Restano invariati l'owner-only, i canali COPY inventariati e il controllo RLS. La verifica CI e le ADR 0100–0101 non abilitano la produzione: #86/#92/#84 e Security/Privacy devono essere verificati con gli operatori, l'IdP e i sistemi di log reali.

## #118 — Preflight pgAudit su revoca e sospensione (ADR 0102)

Negli ambienti *solo sintetici* provati in CI, `revoke-admin.sql` e `set-organization-suspension.sql` devono usare `pgaudit.log_parameter=off` e mantenere tutti gli eventi `role,ddl,write,function`, gli statement PostgreSQL e `COPY` nativi. Se `pgaudit.log_parameter=on`, il guard SQL rifiuta il comando **prima di eseguire l'helper COPY**, con errore statico. Non usare log di statement con `-a/-e`, shell tracing, env dumps né passare OIDC issuer/sub, reviewer, ticket o motivi in argomenti/process log. Il guard non sostituisce verifica dell'approvazione esterna, TLS VerifyFull, gestione IdP/sessioni, review privacy e conservazione dei log Azure. Le due procedure non danno al runtime la facoltà di revocare Admin o sospendere Comuni. Le #86/#92/#84 restano aperte.

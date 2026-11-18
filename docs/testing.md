# Strategia TDD e verifica

Il bootstrap è sviluppato in due incrementi registrati su `main`: specifiche/test iniziali (RED) e codice implementativo (GREEN/Refactor). Le dipendenze .NET e browser Playwright devono essere presenti per la verifica effettiva.

## Matrice minima
| Livello | Caso | Atteso |
| --- | --- | --- |
| Domain | subject vuoto | errore |
| Domain | creazione record | organization non vuota e invariant validi |
| Business | modulo non attivo | use case bloccato |
| Business | list | organization passata esplicitamente |
| API/PostgreSQL | JWT assente | 401 |
| API/PostgreSQL | Reader scrive | 403 |
| API/PostgreSQL | isolamento tra tenant | nessuna lettura incrociata |
| API/PostgreSQL | feature flag disabilitato | 403 |
| Domain | membership valida/invalida e disattivazione | invarianti rispettati |
| API/PostgreSQL | JWT Admin con membership Reader | scrittura 403, context ruolo Reader |
| API/PostgreSQL | membership assente o disattivata | 403 |
| API/PostgreSQL | subject solo nel tenant A usa token per tenant B | 403 |
| API/PostgreSQL | JWT Reader ma membership Officer | scrittura consentita dal ruolo DB |
| Domain | AuditEvent valido, campi obbligatori e minimizzazione | invariant rispettati |
| Business | registrazione associa record a evento audit | stessa organization e resource ID |
| API/PostgreSQL | POST Protocollo riuscita | 1 AuditEvent con actor e correlation del server |
| API/PostgreSQL | tentativi UPDATE/DELETE audit | trigger rifiuta la mutazione |
| API/unit | Production + DevelopmentJwt | startup rifiutato |
| API/unit | Authority OIDC non HTTPS o Audience mancante | startup rifiutato |
| API/integration | RS256 trusted OIDC JWKS locale | 200, membership da PostgreSQL |
| API/integration | issuer, audience, alg HS256 o scadenza errati | 401 |
| API/integration | OIDC valido ma membership assente/Reader che scrive | 403 |
| Frontend/E2E | menu per moduli | menu condizionale |
| Frontend/E2E | accesso Reader | niente azione di creazione |

## Esecuzione
`dotnet test tests/backend/Comuni.UnitTests` per test rapidi.
`TEST_DATABASE_CONNECTION="Host=localhost;Port=5432;Database=comuni_test;Username=comuni;Password=..." dotnet test tests/backend/Comuni.Api.Tests` per integration con PostgreSQL reale.
`npm ci && npx playwright install --with-deps chromium && npm run build --workspace @comuni/frontend && npm run test:e2e --workspace @comuni/frontend`.
GitHub Actions ripete queste verifiche con PostgreSQL service.

| Business/unit | modulazione Admin: modulo sconosciuto, tenant vuoto, audit, no-op | fail-closed / un evento al cambio |
| API/PostgreSQL | Admin elenca/attiva/disattiva Protocollo | stato persistito, API Protocollo 403 quando disattivata |
| API/PostgreSQL | Reader/Officer e JWT con ruolo Admin ma membership Reader | 403 su GET/PUT admin |
| API/PostgreSQL | tenant spoofing da body | secondo Comune invariato |
| API/PostgreSQL | flag già nel valore richiesto | nessun audit aggiuntivo |
| E2E/Playwright | pagina Amministrazione e toggle | visibile solo ad Admin, menu aggiornato, errore visibile su fallimento |

## Test HTTP security (#15)

- Configurazione del limiter: valori invalidi su permit e finestra fanno fallire l'avvio.
- Partizione: un IP dichiarato via `X-Forwarded-For` non aggira la quota; per JWT autenticato il bucket è differenziato per `organization_id` + `sub`.
- Tre richieste API anonime consentite nel fixture di test, la quarta è `429` con `Retry-After`, anche se il client cambia `X-Forwarded-For`.
- Health check `/health/live` non è soggetto al limiter; response headers presenti anche sulle risposte 401; risposte API hanno `Cache-Control: no-store`.
- Tutte le altre verifiche su modulo, ruolo e isolation continuano nella suite di regressione. Test e build nel workflow CI.

## Verifica least-privilege DB (#16)

Il job backend di CI usa PostgreSQL 17, applica migrazioni EF come owner, esegue **due volte** `scripts/postgres/provision-runtime-role.sql` e passa una seconda stringa di connessione `TEST_RUNTIME_DATABASE_CONNECTION` ai test xUnit. Il test `RuntimeDatabasePrivilegesTests` verifica esplicitamente login non amministrativo, privilegi DML per tabella e colonna, blocco di DDL, update di organization e memberships, audit già persistito e lettura della history EF. Un test EF con la connessione **reale del runtime** legge organization/flag/membership e scrive record Protocollo e audit nella transazione attuale. Sono in parallelo i test API/PostgreSQL ordinari con owner di CI, perché devono migrare e seminare dati; il job Azure con rete privata rimane fuori scope.

## PostgreSQL RLS + pooling (#17)

La CI migra lo schema con l'owner, provisiona il login limitato e verifica: `pg_class.relrowsecurity` attivo su cinque tabelle, query SQL **senza contesto** che vedono zero righe sotto `comuni_app_runtime`, `SET LOCAL` che seleziona una sola organization, tentativi di INSERT cross-tenant negati (SQLSTATE `42501`), UPDATE cross-tenant che modifica zero righe, e reset dopo commit/riuso connessione. Un fixture HTTP usa **la stringa runtime limitata** per verificare context e POST/GET Protocollo con middleware tenant. Le restanti suite xUnit e Playwright restano regressione; vedere ADR 0012. I test non dimostrano resistenza a SQL injection: la GUC custom è impostabile dallo stesso ruolo.

## Test di bypass RLS e prove HMAC (#18)

- RED: `set_config('comuni.organization_id', diversoComune, true)` in SQL diretto sotto `comuni_app_runtime` non deve vedere alcuna riga; assertion fabbricata con HMAC falso non dà accesso.
- Unit: proof temporaneo con tenant, nonce casuale, scadenza e firma HMAC; fail-fast senza segreto sicuro.
- PostgreSQL 17: login runtime non può `SELECT platform.tenant_proof_secret`; la funzione SECURITY DEFINER verifica una prova valida senza esporre il secret; ALTER/DDL e cross-tenant INSERT/UPDATE rimangono negati; commit/rollback/pooling non propagano proof tra Comuni.
- HTTP: login JWT + membership effettiva + API Protocollo sotto ruolo runtime limitato; audit transazionale.
- La CI deve applicare migration `202611150006`, provisionare il segreto tramite script `psql`, poi assegnare EXECUTE al runtime.
- I test non costituiscono un penetration test completo; funzione, key rotation, logging e minacce oltre SQL injection devono essere rivalutati prima della produzione.

## Key Vault secret fuori Terraform State (#21)

Il job Terraform CI dopo `terraform validate` esegue `python3 -m unittest discover -s tests/infra -p 'test_*.py' -v` senza account Azure: i test verificano l'assenza della variabile/risorsa che scriveva la chiave HMAC nello state, il blocco `removed` non distruttivo, la sola reference versionless, la rimozione dell'env `TF_VAR_tenant_proof_key` e il preflight prima del `terraform plan`. Una CLI `az` simulata verifica presenza/enabled, disabled, missing e input non valido senza chiedere il valore del secret. I test non coprono la propagazione di Key Vault in Azure, la rotazione della chiave PostgreSQL o il rilascio multi-replica in VNet: #19 e #6 restano aperte.

## Riferimento pinned Key Vault version e preflight metadata-only (#22)

CI Terraform: `tests/infra/test_tenant_secret_version.py` più regressione `test_tenant_secret_boundary.py`. I contratti verificano: variabile Terraform `tenant_proof_secret_version` obbligatoria, Key Vault URI **versionato**, passaggio della versione dall'Environment al Terraform e allo script, blocco di versioni errate, mancanti o disabilitate. La `az` simulata richiede `secret list-versions` con filtro per URI/version esatti; `secret show` è proibito perché potrebbe recuperare anche il valore. Il test Azure reale richiede account e Key Vault configurati e **non** è stato eseguito. xUnit/PostgreSQL, Playwright, Terraform e Docker devono essere verdi insieme per chiudere #22.

## Staging ACA 100% stable / 0% candidate (#23)

I nuovi test `tests/infra/test_staged_rollout.py` verificano con fixture sintetici (senza credenziali Azure) che Terraform dichiari **Multiple**, suffix stable/candidate distinti, pesi 100/0, min replica candidato 1, secret stabile intatta e nuova secret app-scoped versionata usata dal template. Il gate `scripts/azure/check-staged-rollout-plan.py` è esercitato con JSON accettato e rifiuti di assenza prima installazione, creazione/distruzione/replacement, modifica/rimozione di secret già presenti, mismatch versione/key ID e promozione latest. Il gate rifiuta anche la distruzione di altre risorse nel piano. Il job CI Terraform esegue questi test insieme a quelli Key Vault #21/#22, e gli altri job xUnit/PostgreSQL, React/Playwright e Docker restano regression gates. Il test CI **non** dimostra che un piano su una subscription Azure reale produca la stessa struttura: la verifica live va effettuata prima del primo apply.

## Test Azure revisioni reali con fake CLI (#24)

`tests/infra/test_live_revision_verification.py` crea una `az` simulata e prova le tre chiamate metadata-only del verificatore, il caso valido (due revisioni Healthy, numero repliche, immagine esatta, key ID e secret pin corretto, stable 100% / candidate 0%), nonché fail-closed per candidate/stable assente, revisioni duplicate, unhealthy, Failed/Degraded, replica zero, immagini errate, key ID o secret reference sbagliati, autopromozione o terze regole di traffico, errori CLI, mode Single e input non validi. Gli output stdout/stderr della CLI non sono riportati in log applicativi e non vengono chiamati comandi di mutazione del traffico. La CI copre lo script solo con **metadati simulati**: la verifica live Azure tramite `az containerapp revision list`/traffic show verrà eseguita soltanto in un futuro stage autorizzato in subscription (#6/#19).

## Label canary 0% e smoke OIDC/RLS read-only (#25)

I test `tests/infra/test_staged_rollout.py` e `test_live_revision_verification.py` ora richiedono una **label candidata identica al suffix immutabile** solo nella regola latest a peso 0, non sulla stable a 100%; il gate Terraform plan e il verifier metadata Azure falliscono per label errata o mancante.

`tests/infra/test_candidate_smoke.py` usa un opener HTTP mock (nessun token o account Azure reale) per verificare `validate_candidate_url` e `run_smoke`: URL HTTPS `<app>---<label>.<approved environment domain>` senza userinfo, query, fragment o port diversi, nessun redirect, token A/B distinti passati **solo in Authorization** e mai negli URL, soli GET, contesti tenant coerenti e marker synthetic A/B isolati in Protocollo. Dati mancanti o incrociati, JSON corrotto, status non attesi e token ripetuti fanno fallire il test; output non include token o subject. Per l'esecuzione live servono credenziali OIDC reali, due Comuni sintetici e runner approvato. CI e Terraform validate **non sono una verifica Azure reale**.

## OIDC browser Authorization Code + PKCE (issue #26)

La CI esegue `BrowserOidcSettingsTests` (xUnit): demo mode disabilita il browser OIDC, produzione senza valori completi disabilita accesso senza fallback JWT, validazione HTTPS e stesso host authority, scope API delegato + `openid`, rifiuto di `offline_access`, client secret, endpoint con credenziali/query, endpoint insicuri, e `GET /api/v1/auth/browser` anonimo. Il client React è coperto da `tests/frontend/oidc-login.spec.ts`: provider mock HTTPS, Authorization Code + PKCE S256/verifier, stato casuale, POST token con URL callback esatta, scelta del solo access token, rifiuto `state` contraffatto, URL callback pulita, logout e impossibilità di incollare JWT in modalità Oidc non configurata. I test precedenti di dashboard/admin usano l'esplicita modalità `DevelopmentJwt` mock e continuano a verificare le autorizzazioni UI.

Tutti i test OIDC client sono **offline/mock**. Non dimostrano che un IdP reale accetti il redirect, supporti CORS o emetta access token con organization_id e audience, né sostituiscono MFA/provisioning o sicurezza SPID/CIE. I test JWT RS256 backend/PostgreSQL già esistenti validano separatamente il consumo di token, non un flusso provider live.

## Membership Reader/Officer Admin, audit e PostgreSQL RLS (#27)

Il TDD include `MembershipAdministrationTests` (dominio/Business), `MembershipAdministrationApiTests` (PostgreSQL reale: 401 anonimo, 403 Reader/Officer e JWT role spoof, isolamento di due Comuni, aggiornamento immediato membership, validazione ruoli, niente Admin grant, no-op e audit server-originated), `RuntimeDatabasePrivilegesTests` (role allowlist, INSERT/UPDATE colonnari, RLS RESTRICTIVE che nega un INSERT Admin **anche con firmata tenant assertion valida**) e `tests/frontend/admin-memberships.spec.ts` (Admin visualizza/gestisce roster, Admin read-only, Reader senza accesso, errore backend non modifica UI). Il job CI esegue migrazioni DB con ruolo owner, provisioning runtime in PostgreSQL, integrazioni xUnit, React/Playwright, Terraform e Docker. L'esito può essere dichiarato completato solo con tutti i job verdi sul commit `main` finale.

Limitazione: test con JWT DevelopmentJwt e soggetti sintetici; non confermano provisioning o presenza dei nuovi subject in un IdP, inviti, email, MFA, revoca di sessione e audit esterno.

## Identity issuer binding OIDC (#28)

TDD: in `OidcApiTests` un token RS256 con issuer attendibile e membership `identity_issuer` corrispondente legge il contesto; con stesso tenant e `sub` ma issuer NULL o diverso torna **403**, con `iss` JWT non attendibile torna 401. L'Admin OIDC con membership collegata crea Reader con issuer da JWT; i campi `identityIssuer`/`issuer` falsificati nel body vengono ignorati. Il tentativo di riassociare una membership NULL/dell'altro provider produce 409 senza modificare il DB. I test PostgreSQL runtime verificano i permessi INSERT colonnari per issuer, il rifiuto di `UPDATE identity_issuer` (42501) anche con HMAC tenant valida e la RLS che impedisce l'Admin; xUnit domain prova il formato HTTPS. Playwright mostra issuer nel roster e nessun input per modificarlo. Compatibilità demo DevelopmentJwt su membership legacy e le vecchie policy restano verificate dagli altri test.

Tutti i provider OIDC di CI sono **simulati con chiave RSA locale**: nessuna identità del mondo reale, nessun IDP live o Azure. La CI verde non sostituisce test di provisioning con provider effettivo, modifica/rotazione issuer o audit di operatore durante i backfill.

## Gate vulnerabilità dipendenze e CodeQL (#29 / ADR 0023)

Il contratto statico `tests/infra/test_security_scanning.py` (RED prima dell'implementazione) è eseguito dal job Terraform insieme agli altri test infrastrutturali. `dependency-audit` esegue restore NuGet dei progetti di API/integration e unit/domain con metadati vulnerabilità diretti e transitivi e tratta `NU1900`, `NU1903`, `NU1904` come errori; per npm prepara l'albero dipendenze senza script di installazione e fallisce su advisory runtime high/critical. Il job CodeQL usa build C# reale e estrazione JS/TS e pubblica i risultati. Il job Docker ora dipende anche dai due gate di sicurezza. Un cron settimanale ri-esegue l'intera CI per rilevare nuove advisory dopo l'ultimo commit.

**Attenzione:** il contratto offline non interroga NuGet/npm né rileva vulnerabilità del codice. L'effettiva verifica dei gate richiede l'ultima esecuzione CI verde; i CodeQL findings necessitano triage, non sono automaticamente un gate per il loro contenuto. La CI non prova penetration test, scansione della base image o sicurezza Azure live.

## Dependency graph React riproducibile (#30 / ADR 0024)

Il nuovo `tests/infra/test_reproducible_npm.py` verifica (RED → GREEN): lockfile npm v3 alla root, presenza del package workspace `src/frontend` e del link `node_modules/@comuni/frontend`, dipendenze dirette uguali al manifest, URL registry npm e integrity SHA-512 per le transitive, assenza di lockfile secondario e contratti `npm ci` in CI e Docker. `test_security_scanning.py` continua a verificare che l'audit runtime `npm audit --omit=dev --audit-level=high` sia bloccante e che durante lo scanning npm non esegua lifecycle script.

La validazione reale è `npm ci` nel job React/Playwright e nel job SCA: se manifest e lock differiscono, il comando fallisce senza rigenerare il lock. Anche il container Docker parte dalla **root dello stesso workspace** e compila la SPA con `npm run build --workspace`. I gate preesistenti xUnit/PostgreSQL, Terraform, CodeQL e container restano obbligatori. Non garantisce tarball futuri non rimossi dal registry né build bit-per-bit identiche fra toolchain differenti.

## Bootstrap primo Admin OIDC owner-only (#31 / ADR 0025)

La suite xUnit `InitialAdminBootstrapTests` chiama **psql reale** su PostgreSQL 17 con login schema owner, `-X -q -v ON_ERROR_STOP=1` e input sintetici solo in variabili ambiente; verifica bootstrap atomico di una organization attiva priva di Admin, issuer/sub esatti e audit una volta sola; retry idempotente; rifiuto del secondo Admin, della membership legacy disabilitata, di tenant sospesi/assenti, issuer non HTTPS, subject non esatto, ticket/reviewer assenti; concorrenza su uno stesso Comune; rifiuto del login runtime non owner. Il job CI ha già installato `postgresql-client` prima dei test di integrazione e il `TEST_DATABASE_CONNECTION` è un DB disposable. Playwright, CI SCA, CodeQL, Terraform e immagine Docker restano regressioni obbligatorie. Il TDD RED precede lo script e GREEN non è considerato Done fino alla CI verde finale.

Queste prove non verificano che il provider OIDC reale corrisponda agli input o che il change ticket e l'approver siano autenticati: sono prerequisiti operativi esterni. Non è un onboarding automatico di identità o un bootstrap Azure reale.


## TDD provisioning Core organization (#32 / ADR 0026)

`OrganizationProvisioningTests` usa il ruolo PostgreSQL owner sul database disposable con `psql -X -q -v ON_ERROR_STOP=1`, variabili ambiente sintetiche, e verifica: una organization nuova con `is_suspended=FALSE`, flag `protocol=FALSE`, roster membership vuoto, evento audit `platform.organization.created` atomico; `/api/v1/context` restituisce 403 anche per un JWT valido senza membership. Input UUID/nome/ticket/approver mancanti o malformati falliscono senza persistenza. I test coprono apostrofi e contenuti SQL nel nome (nessuna esecuzione arbitraria), duplicati con nome differente, righe preesistenti senza audit, role `comuni_app_runtime` rifiutato, concorrenza su UUID e retry che non resetta i moduli attivati nel frattempo. L'audit è una prova funzionale di atomicità, non una firma di validità giuridica del change.

RED: test pubblicati su `main` prima dello script, CI failure atteso. GREEN: la CI esegue lo script PostgreSQL 17 e mantiene tutti i gate xUnit/PostgreSQL, Playwright, Terraform, SCA/CodeQL e immagine Docker. Nessuna verifica Azure live, identità/approvazione effettivamente attestate o onboarding PA reale.


## TDD lifecycle suspend/reactivate (issue #33 / ADR 0027)

La suite `OrganizationLifecycleTests` usa `psql` e PostgreSQL 17 reali, database owner e `comuni_app_runtime` con credenziali di test separate. Gli xUnit scritti in fase RED verificano: blocco 403 immediato su `/api/v1/context`, gestione membership, gestione moduli, letture e POST Protocollo di un Comune sospeso con JWT ancora valido; altro Comune invariato; riattivazione con le membership e i flag precedenti, lasciando Reader disabilitati 403. `platform.organization.suspended/reactivated` con actor owner, resource UUID, trace ticket sono scritti una sola volta per transizione nello stesso commit; retry e operazioni concorrenti per lo stesso stato restano no-op, senza alterare ruoli, dati o flag. Invalid UUID/tenant sconosciuto, action, ticket, approver o reason malformati/assenti, SQL injection in input, ruolo DB runtime non owner provocano fallimento e **nessuna scrittura**.

La CI finale deve mantenere i gate xUnit/PostgreSQL, React/Playwright, Terraform/test infrastrutturali, SCA NuGet/npm, CodeQL C#/JS e build Docker. Non verifica stop di operazioni già in corso, revoca sessioni OIDC, autenticità dell'approvatore, approvazioni live o Azure.


## Identità Superadmin senza escalation da Admin comunale (ADR 0028 / #34)

La suite `PlatformOperatorApiTests` esegue OIDC **simulato con RSA/JWKS locale** su PostgreSQL 17: la prima fase RED fallisce perché la tabella e l'endpoint non esistono. La fase GREEN richiede 401 per anonimi, 403 per utenti OIDC senza membership globali, Admin comunali, JWT con ruolo `Superadmin` inventato, account disattivati o issuer non coincidenti; e 200 con **solo** `role` per un token OIDC con `iss`+`sub` attivi, ma privo di `organization_id`. Il test opposto dimostra che il token platform non passa `/context`, Admin o Protocollo e che un token con `organization_id` non può usare la rotta platform. `DevelopmentJwt` non conferisce accesso platform. Con un login SQL `comuni_app_runtime` reale, verifica SELECT/INSERT/UPDATE/DELETE su `platform.platform_operators` negati, EXECUTE del predicato consentito e nessun roster leggibile. Gli altri test di isolamento, RLS, xUnit, React/Playwright e CI restano invariati.

Non è un test di enrollment, provider OIDC reale, MFA, impersonificazione, Azure o approvazioni multi-persona. Il roster è popolato **solo sinteticamente** da fixture test mediante login owner PostgreSQL, non dalla SPA né da una API di produzione.


## TDD enrollment Superadmin con audit globale (#35 / ADR 0029)

`PlatformOperatorEnrollmentTests` invoca il comando owner-only `scripts/postgres/manage-platform-operator.sql` con `psql` reale su PostgreSQL 17 disposable, input sintetici e login separati owner/runtime. RED (prima dello script/migration) verifica l'assenza del nuovo comportamento; GREEN verifica: primo `enroll` attiva un OIDC `iss+sub`, endpoint `/api/v1/platform/session` 403→200; `revoke` con nuovo ticket lo riporta a 403 per il **medesimo JWT**; token senza organization non passa le route comunali; una riga per identità e un evento per ogni mutazione. Due enroll/revoke concorrenti sono serializzati senza audit duplicati; retry no-op, nuova approvazione obbligatoria per transizione distinta, reactivation tracciata. Input invalidi/issuer non HTTPS/ticket approver assenti, SQL injection via subject e tentativi runtime vengono respinti o trattati come **testo** senza SQL eseguibile. Il ruolo runtime non può accedere a `platform.platform_operators` o `platform.platform_operator_audit_events`; UPDATE/DELETE/TRUNCATE dell'audit sono rifiutati con SQLSTATE 55000; solo il predicato booleano DB è eseguibile. L'audit minimizza PII tramite UUID random stabili.

CI completa: xUnit/PostgreSQL, React/Playwright, Terraform/test infra, NuGet/npm SCA, CodeQL C#/TypeScript e Docker. Non esiste collaudo con IdP/approvazione umana/Azure reali o verifiche su token provider revocati: il comportamento testato riguarda solo nuove richieste alla API con IdP RSA simulato.


## TDD area Superadmin PWA — frontend Playwright (#36 / ADR 0030)

La nuova suite `tests/frontend/platform-superadmin.spec.ts` esercita il browser reale con OAuth Authorization Code + PKCE S256 e issuer/token endpoint simulati: con OIDC e `GET /api/v1/platform/session` 200 **e** `/api/v1/context` 403 si vede l'area `Superadmin` read-only con un solo ruolo, senza menu Protocollo/Admin, roster e dati di altri Comuni; navigazione su `/platform`, traduzione italiano/inglese, tema chiaro/scuro e logout funzionano nella PWA unica. Per Admin comunale, anche con stringa token che asserisce `role=Superadmin`, la API mock platform 403 non fa apparire il menu. Risposte 401/403, JSON extra non previsto su 200, doppio context 200 e platform 200, accesso anonimo a `/platform` e token DevelopmentJwt falliscono chiusi. Su focus la revoca server 403 nasconde vista/menu. Access token non sono presenti nei browser storage e svaniscono al reload.

Il ciclo TDD avviene su `main`: RED test Playwright prima della UI; GREEN React in seguito; tutti i regressioni (xUnit/PostgreSQL, React build/Playwright, Terraform/infra, SCA NuGet/npm, CodeQL C#/TS e Docker) devono essere verdi allo SHA finale. I mock browser **non validano firme OIDC o PostgreSQL**: tali proprietà rimangono coperte dalle suite backend `PlatformOperatorApiTests`, `PlatformOperatorEnrollmentTests` e RLS, con IdP RSA soltanto simulato. La UI non dimostra conformità WCAG/AgID senza ulteriori audit accessibilità; usa controlli con label/heading/nav e keyboard-friendly button standard.


## TDD inventario globale Superadmin con due login SQL (#37 / ADR 0031)

Suite xUnit/PostgreSQL `PlatformInventoryApiTests`: **RED** prima di migrazione/view e endpoint; **GREEN** dopo. I test usano tre credenziali diverse sullo **stesso PostgreSQL 17 disposable**: schema owner per seed, `comuni_app_runtime` per normale RLS e `comuni_platform_reader` solo inventory. OIDC RS256/JWKS locale; 2+ Comuni sintetici (attivi/sospesi, Protocollo on/off), pagination keyset `limit=1` fino a ultimo cursore, ordine UUID monotono, output esclusivamente `id/name/isSuspended/protocolEnabled`, no count, audit per pagina con risorsa `operator_id`. Verificano 401 anonimo, 403 Admin comunale/role claim falsificato/operatore revocato, 401 issuer/audience/expiry errati, 400 parametri sconosciuti e SQL injection nel cursor; nessun evento audit in caso di input non valido. Verificano anche che `comuni_app_runtime` non possa eseguire SELECT della vista o il resolver globale, mentre `comuni_platform_reader` **non** vede tabelle organizzazioni, membership, documenti o roster, non può leggere/modificare audit ma può inserirlo e vede la sola vista.

La CI migra come owner, provisiona **due volte per idempotenza** `scripts/postgres/provision-platform-read-role.sql` con password di test in ambiente `PLATFORM_READ_DB_PASSWORD` e imposta `TEST_PLATFORM_DATABASE_CONNECTION` soltanto sul job backend. Altri job mantengono test di regressione PostgreSQL/RLS, Terraform, SCA e CodeQL.

Playwright `tests/frontend/platform-inventory.spec.ts` usa mock HTTP: area OIDC platform con tabella e `Carica altri Comuni`, Admin comunale senza inventario, errore 503/Retry, revoca 403 durante paginazione che cancella righe/sessione, tema e i18n. Gli E2E browser non sostituiscono la verifica SQL/JWKS reale dei test backend. Nessuna installazione IdP, credenziali Azure o prova di compliance viene effettuata.


## #38 — Key Vault pinning, Terraform stage e SQL role gate (TDD offline)

Nuovi test RED in `tests/infra/test_platform_inventory_release.py`: flag Terraform default false, nessuna password/connection string come `TF_VAR_*`, riferimento condizionale Key Vault alla versione approvata, workflow dispatch opt-in, preflight **solo metadati** con CLI `az` simulata (versione valida, mancante, disabilitata, input invalido); il piano sintetico staged stable=100%/candidate=0% viene accettato solo con secret/flag/env coerenti e **nello stesso Key Vault** del tenant-proof. I negative cases modificano versione, host, secret duplicato, env inline, route, configurazione inattesa: il validator deve fallire senza stampare URI, credenziali o il piano JSON. La suite `tests/infra/test_platform_read_role_contract.py` aggiunge il contratto RED per il verificatore SQL owner read-only.

GREEN: Terraform crea **solo metadata references**, con `dynamic "secret"` e `dynamic "env"` soltanto se l'inventario è attivato manualmente; script `check-platform-inventory-secret.sh` e estensione `check-staged-rollout-plan.py` applicano le condizioni prima di `terraform apply`. La CI backend con PostgreSQL 17 passa da migrazioni owner e provisioning SQL role ripetuto, poi esegue `scripts/postgres/verify-platform-read-role.sql` come owner prima dei test xUnit `PlatformInventoryApiTests` che verificano ruoli/denials/401/403/audit/paging. I normali test React/Playwright, CodeQL C#/JS-TS, SCA, Docker e Terraform validate rimangono gate verdi obbligatori sullo SHA finale di `main`.

Queste prove sono completamente **offline**: nessun Key Vault o Container Apps reale, nessun secret di connessione production, nessuna lettura della versione Key Vault tramite secret value, nessuna promozione del traffico, nessuna prova SPID/CIE o IdP/MFA production.

## #39 — ACA HMAC candidate secret key <=20 caratteri (ADR 0033)

TDD RED: `test_staged_rollout.py` e `test_live_revision_verification.py` richiedono che il nome candidato HMAC ACA sia `tp-${VERSION[:16]}` (19 caratteri) mentre il secret Key Vault URI conserva **tutti i 32 hex** della versione. Test di collisione: se una versione esistente con stesso prefisso punta a URI diverso, il plan gate rifiuta la modifica senza sovrascrivere una secret application-scoped. GREEN: Terraform e i due tool Python di verifica plan / revision-live condividono l'algoritmo. Non è stata cambiata la secret stable `tenant-proof-key`, i pesi 100% stable/0% candidate, la chiave PostgreSQL o il valore del secret. `terraform validate` e test Azure CLI simulati non dimostrano deploy live: richiedono #19/#6 e approvazione manuale.


## #40 — TDD smoke candidata Superadmin a tre identità (ADR 0034)

`tests/infra/test_candidate_platform_smoke.py` è stato scritto in RED prima del tool `scripts/azure/smoke-candidate-platform.py`. Esegue Python `unittest` con `FakeOpener` e tre token **solo sintetici**, senza rete né credenziali Azure. Contratto: HTTPS soltanto verso esatto `app---label.domain` approvato, niente redirect, proxy, POST/PUT/DELETE, login demo o JWT in query/log; status attesi 401/403/200 per sessione platform e inventario, 403 per contesto comunale di Superadmin; risposta sessione con unico ruolo e inventario con esattamente quattro campi minimizzati. Paginazione UUID monotona/cursor corretto, due UUID sintetici presenti, max 20 pagine, no extra PII/roster, payload JSON malformati/duplicati e fallimenti 503 negati. Input token mancanti o identici, issuer host non autorizzato, URL con query e test d'errore con error messages generici falliscono in modo chiuso. Le suite `test_candidate_smoke.py` (#25) e `test_platform_inventory_release.py` (#38) restano in CI; la nuova smoke non aggiunge test reali di Azure/IdP.

Un eventuale test su candidata autorizzata richiede **prima** verifica live dei metadata ACA, staging 100/0 e credenziali/privilegi PostgreSQL; deve eseguire separatamente smoke due-tenant RLS, platform e verifica manuale dell'audit/revoca. La CI 7/7 verde controlla solo il tooling offline, non conformità o promotion live.


## #41 — TDD dell'audit municipale read-only e permessi PostgreSQL per colonna (ADR 0035)

Test RED: `tests/backend/Comuni.Api.Tests/MunicipalAuditApiTests.cs` crea due+ Comuni sintetici in PostgreSQL e popola 30 eventi di uno e tre dell'altro; controlla GET Admin con **max 25**, ordine timestamp desc, risposta con **esattamente** `id/action/resourceType/occurredAt` (senza UUID Comune, actor IdP, resource ID e correlation); 401 anonimo, 403 Reader/Officer/JWT Admin finto/sospensione, 400 per query e tenant selector non autorizzati, isolamento A/B. Test con connessione SQL `comuni_app_runtime` verificano cinque SELECT colonna, tre SELECT negati (42501), no UPDATE/DELETE e **zero righe senza prova RLS firmata**, anche con impostazione arbitraria della GUC unsigned. La suite esistente `RuntimeDatabasePrivilegesTests` conserva il divieto di leggere i campi riservati; non usa più il precedente `count(*)` come test negativo, perché un grant SELECT per colonna può consentire aggregati sulle colonne autorizzate, sempre filtrati dalla RLS.

Playwright RED: `tests/frontend/admin-audit.spec.ts` verifica nel browser che soltanto un contesto Admin veda la tabella `Attività recenti del Comune`, senza dati personali né pulsanti di export; Reader non richiede la API, error/503 non mostra righe precedenti e consente retry, logout cancella i metadati, lingua IT/EN e tema. GREEN: Business interface + Infrastructure EF read projection, endpoint con `Admin` policy e rigetto di qualunque query, SQL provisioning runtime per colonna, UI unica.

Tutti i test sono condotti su PostgreSQL reale in GitHub Actions e frontend browser Chromium; la CI completa include anche Terraform/infra, SCA, CodeQL e Docker. **Non** dimostrano conformità conservazione, tamper-evidence a livello DBA né IdP/Azure production live.

## #42 — TDD tracciamento consultazioni audit (ADR 0036)

RED xUnit/PostgreSQL `MunicipalAuditConsultationTests.cs`: un GET Admin 200 deve generare **un solo** `platform.audit.consulted` e la consultazione non deve figurare nella risposta corrente; a una seconda lettura compare quella precedente. Devono provenire dal server actor e correlation, mai da `X-Actor-Subject` e `X-Correlation-Id`. Test 401 anonimo, 403 Reader/Officer/claim Admin contraffatto/ente sospeso, 400 query, separazione di due Comuni. RED confermato dai test non ancora implementati. GREEN: Business service + Infrastructure atomici sotto la medesima transaction.

Il test SQL diretto con `TEST_RUNTIME_DATABASE_CONNECTION` (login **`comuni_app_runtime`**, non owner) verifica che l'operazione fuori dalla transaction fallisca, che org non corrispondente sia negata, che con tenant proof firmata un INSERT seguito da **ROLLBACK** non persista e da **COMMIT** persista un solo evento. Playwright `admin-audit.spec.ts` RED/ GREEN verifica avviso IT/EN, nessun token esposto e continuità della navigazione Admin. La CI finale deve essere 7/7 sul commit `main`, comprendendo backend/PostgreSQL, React/Playwright, Terraform, SCA, CodeQL C#/JS-TS e Docker. Nessuna verifica di Azure live, GDPR o WORM.


## #43 — TDD PostgreSQL su registrazione Comune owner-only (ADR 0037)

Suite `tests/backend/Comuni.Api.Tests/OrganizationRegistrationTests.cs` con **psql reale sul PostgreSQL 17 della CI**. RED prima dello script, con sei test inizialmente falliti in assenza del comando. GREEN: inserimento atomico organization/modulo disattivato/audit singolo, zero membership e 403 HTTP senza assegnazione; retry con stessi input no-op; UUID esistente con nome/ticket differenti e organization creata fuori da script non possono essere adottate; invalid input (UUID nullo/zero o SQL injection, denominazione vuota/trim/control/oltre 200, ticket/reviewer non validi) deve fallire senza scritture/echo; connessione login ristretto rifiutata; concorrenza due psql sullo stesso UUID crea solo una organization/modulo/audit; dopo sospensione il retry non riattiva il tenant. Il test aggiuntivo `Registration_precedes_separate_owner_verified_first_Oidc_Admin_bootstrap` esegue lo **script #31** su organizzazione appena registrata, verifica un Admin OIDC vincolato a issuer+sub senza attivare Protocollo.

Gli xUnit sono eseguiti sulla stessa base PostgreSQL disposable dei test API, isolando ogni caso con un GUID sintetico nuovo; nessun IdP, Comune reale o Azure. Tutti e sette i job CI (xUnit/PostgreSQL, React+Playwright regression, Terraform, SCA, CodeQL C#/JS-TS, Docker) devono essere verdi sullo SHA finale di main. Non è necessario introdurre una UI owner-only nell'unica PWA.


## #44 — TDD migration 0013 e attivazione approvata del Comune (ADR 0038)

RED `tests/backend/Comuni.Api.Tests/OrganizationActivationTests.cs`: su PostgreSQL 17 crea un ente #43 e richiede `is_activated=false`, Protocollo false, 403 su `/api/v1/context` e Protocollo **anche dopo** primo Admin OIDC owner #31. Sei test nuovi RED hanno fallito prima di migrazione e script, mentre gli altri 145 test API sono passati. GREEN: migrazione `202611150013_OrganizationActivationGate`, proprietà EF/Domain e filtro `IsOperationalAsync`, registrazione owner pending, attivazione owner con un Admin OIDC, audit singolo e retry, sospensione pending negata. I test confermano: owner activation non abilita moduli, fa passare l'HTTP context di un utente sintetico con membership Testing valida, false/legacy/null issuer e moduli attivi bloccano l'activation, ticket/approver invalidi, unknown/zero ID e account SQL runtime negati, concurrency produce un solo audit, pre-existing active/suspended restano activated. Un test con `comuni_app_runtime` nega UPDATE diretto (42501) e con schema owner nega sospensione di created (23514). Un test di vista globale richiede che un created sia mostrato come non-operativo (`is_suspended=true` nel compat field) e Protocollo false.

La suite #43 è stata adeguata al vincolo created→active→suspended: il replay di un ente sospeso usa una fixture activated/suspended legalmente rappresentabile, senza riattivarlo. Test RED Playwright `tests/frontend/platform-inventory.spec.ts` richiede *Non operativo* per `isSuspended=true`, quindi GREEN i18n IT/EN della stessa React PWA. La CI completa sullo SHA finale comprende xUnit/PostgreSQL, React/Playwright, Terraform, SCA NuGet/npm, CodeQL C#/JS-TS e Docker. Non equivale a prova IdP/Azure live o a conformità amministrativa.

## #45 — Inventario created/active/suspended: TDD RED → GREEN (ADR 0039)

Test RED committati prima dell'implementazione: `PlatformInventoryApiTests` crea tre Comuni sintetici (created/active/suspended) su PostgreSQL 17 disposable ed esige cinque campi nel DTO paginato, con `isSuspended` compatibile, audit per pagina e nessuna identità membro/operatore aggiuntiva. Restano test 401/403, limite 1–25, principal SQL separato e revoca. Playwright verifica etichette *Creato/Attivo/Sospeso* e *Created/Active/Suspended* e nega `lifecycleStatus` incoerente. `test_candidate_platform_smoke.py` controlla allowlist, tre stati e rifiuto valori inattesi. GREEN comprende migration `202611160001_PlatformLifecycleInventory`, `PlatformInventoryStore`, parser UI, i18n e SQL verifier. La CI completa sul commit finale è requisito prima della chiusura #45; test offline non dimostrano autorizzazioni istituzionali reali o rollout Azure.

## #46 — TDD ritiro HMAC con successore obbligatorio (ADR 0040)

`TenantProofRetirementGuardTests` aggiunge su PostgreSQL 17 disposable veri processi `psql` owner per il ritiro di chiavi sintetiche: fallimento senza ID sostitutivo, con stesso ID, sconosciuto, revocato, non ancora attivo, di breve durata e con grace non ammessa; nessuna modifica allo stato del target su rifiuto. Il GREEN richiede successore valido per grace + 300 s, ritiro `0` con revoca e prova RLS precedente negata, successore ancora funzionante, retry incapace di allungare validità/annullare revoca, due ritiri incrociati concurrent che non possono riuscire entrambi, SQL login comunale rifiutato. La CI backend stage/retire ora indica `TENANT_PROOF_REPLACEMENT_KEY_ID=legacy` solo nella fixture sintetica (nessuna rotazione prod). Tutti gli altri job restano obbligatori per chiusura, inclusa la build immagine.

## #47 — TDD startup obbligatoriamente versionato del signer RLS (ADR 0041)

Test RED aggiunti in `TenantProofSigningSettingsTests` (xUnit): `Production` e `Staging` devono rifiutare `Security:TenantProofKeyId` assente/vuoto/whitespace/`legacy` e non stampare la HMAC; solo `Development`/`Testing` mantengono la prova demo a quattro campi. Un ID valido genera una prova con cinque parti e il key ID autenticato, ID malformati e chiave debole sono respinti. `test_production_tenant_key_id.py` controlla che Terraform non abbia più un ID di default, ne vieti il legacy e che `Program.cs` usi il gate prima della registrazione dei servizi. RED → GREEN è verificato da GitHub Actions sullo SHA dei rispettivi commit; la suite completa xUnit/PostgreSQL, React/Playwright, Terraform/Python, SCA, CodeQL e Docker deve essere verde sulla HEAD per chiudere la #47. I test offline non verificano Azure, l'IdP o il pairing HMAC con un secret reale.

## #48 — TDD certificato e hostname per PlatformRead (ADR 0042)

La suite RED `tests/backend/Comuni.Api.Tests/PlatformInventoryTlsSettingsTests.cs` istanzia `PlatformInventorySettings.Read` senza aprire socket DB: rifiuta in `Production`, `Staging` e `Preview` il reader globale con SSL disabilitato/Prefer/Require/VerifyCA, `Trust Server Certificate=true` anche insieme a VerifyFull, e un ruolo/database/host diversi o auth non OIDC. Accetta soltanto VerifyFull senza trust bypass per hosted, mantenendo `Development` e `Testing` con connessioni PostgreSQL sintetiche senza TLS obbligatorio e l'inventario disabilitato senza credenziale. Il test Python `tests/infra/test_platform_inventory_tls.py` blocca regressioni di contratto statico e l'uso di credenziali plain Terraform. GREEN implementa il guard in `PlatformInventorySettings`; gli altri test PostgreSQL/RLS, React/Playwright, Terraform, CodeQL, SCA e Docker devono superare **7/7** sullo SHA `main` finale prima di chiudere #48. Questo test **non** può verificare una CA o un server Azure reale.

## #50 — TDD stage PostgreSQL runtime candidate versionato (ADR 0043)

RED commit `d918ab5` introduce `tests/infra/test_runtime_postgres_candidate.py`: il contratto obbliga una nuova versione Key Vault di 32 hex per l'**esclusiva** connessione runtime della ACA candidata, con nome app-scoped `pg-<16hex>` e URI versionato `postgres-runtime-connection/<32hex>` nello stesso vault dell'HMAC. Il fake Azure CLI simula preflight metadata-only enabled/disabled/assente/invalid input, senza valori reali. I piani sintetici positivi e negativi verificano: no URI versionless/altro vault, no password inline, no uso della stable `postgres-connection`, no duplicati/collisioni di prefisso, no mutazioni/rimozioni di secret già presenti, no UPDATE della vecchia risorsa Terraform contenente password, presenza `ConnectionStrings__Default` dalla nuova secret. Le suite `test_staged_rollout.py` e `test_platform_inventory_release.py` usano ora la stessa fixture candidata e continuano a verificare stable=100%, candidate=0% e isolamento dell'inventario opzionale. `test_live_revision_verification.py` controlla il `secretRef` della connessione nella revisione candidata simulata, senza credenziali.

GREEN usa Terraform, workflow manuale, preflight e gate di piano/post-stage; la CI deve eseguire Python unittest, `terraform validate`, xUnit/.NET10 con PostgreSQL 17, Playwright, SCA, CodeQL e build Docker sullo SHA finale prima di chiudere la #50. L'accettazione del metadata `SSL Mode=VerifyFull` **non** viene certificata dai test offline: lo script non può leggere il valore del secret e la futura guardia `ConnectionStrings:Default` dell'API, la verifica della CA e il test Azure/VNet sono ancora requisiti aperti della #49/#6.

## #51 — TDD della verifica TLS del runtime comunale al bootstrap (ADR 0044)

RED: `tests/backend/Comuni.Api.Tests/RuntimePostgresConnectionSettingsTests.cs` usa connection string puramente sintetiche e verifica rifiuto di `Disable`, `Allow`, `Prefer`, `Require`, `VerifyCA`, `Trust Server Certificate=true`, IP/local/multi-host/alias DNS/suffissi fasulli, ruolo owner o `comuni_platform_reader`, porta non 5432, database/password vuoti, input Npgsql invalido e secret esposti. Accetta `VerifyFull` con FQDN Azure e ruolo `comuni_app_runtime` in `Production`/`Staging`/altri hosted. `Development`/`Testing` conservano le normali suite PostgreSQL 17 senza infrastruttura PKI. `tests/infra/test_runtime_postgres_startup.py` controlla che `Program.cs` usi la guardia prima dell'inventario Superadmin e di EF e che il secret Terraform stable non venga cambiato. GREEN: nuova logica `RuntimePostgresConnectionSettings.Read` e registrazione nel Program; evitare log di informazioni nella connessione. 

Sono necessari tutti i gate CI sullo **stesso commit finale `main`**: test xUnit unit/integration PostgreSQL, build e Playwright frontend, test Python/terraform validate, CodeQL C#/TypeScript, audit dipendenze, build immagine Docker. I test offline non aprono una sessione TLS Azure, non provano CA/SAN reali, non leggono i byte Key Vault e non autorizzano il go-live. Il percorso stable/versionless e la rimozione dallo state restano attività aperte in #49.

## #52 — TDD di identità esatta dell'istanza Azure PostgreSQL (ADR 0045)

RED: `RuntimePostgresExpectedHostTests` xUnit richiede un `RuntimePostgres:ExpectedHost` separato dal segreto per ogni ambiente hosted; respinge metadato assente/whitespace/alterato, endpoint valido ma di **altro** PostgreSQL Azure, IP/alias/multihost e non emette segreti o hostname nei messaggi di errore. I test `Development` e `Testing` continuano a usare un PostgreSQL 17 disposable senza expected-host. `test_runtime_postgres_exact_host.py` esercita piani Terraform sintetici con `planned_values.root_module.resources` di `azurerm_postgresql_flexible_server.main`, rifiutando absent/duplicate/mismatch, secretRef, e UPDATE del database managed. `test_staged_rollout.py`, `test_runtime_postgres_candidate.py` e gli altri contratti continuano a verificare secret immutabili, no inlining e traffico 100/0. `test_live_revision_verification.py` simula la lettura CLI del FQDN della risorsa PostgreSQL ARM, l'assenza dei permessi, un server divergente e i metadati della candidata malevoli, senza chiamate mutative.

GREEN: guardia `RuntimePostgresConnectionSettings`, wiring Terraform del metadato server-owned, plan gate e verificatore live con risposta sintetica Azure CLI. L'evidenza richiede **tutti e 7** i job CI sullo SHA HEAD (xUnit/PostgreSQL, React/Playwright, Terraform/Python, SCA, CodeQL C#/JS e Docker). I test non aprono connessioni reali a Azure, non leggono la password Key Vault e non dimostrano la CA effettiva, DNS/VNet o recovery: restano #49/#5/#6.

## #53 — TDD del gate Terraform a una sola mutazione (ADR 0046)

Test Python `tests/infra/test_aca_stage_immutable_infrastructure.py` (RED → GREEN) usa piani JSON **solo sintetici** e si integra in `python -m unittest discover -s tests/infra` del job `Terraform validate`. La fixture valida contiene un singolo UPDATE di `azurerm_container_app.main` e tutte le altre risorse no-op, conservando il metadato managed PostgreSQL e i secret Key Vault pin-ati. I casi negativi contengono CREATE/UPDATE/DELETE/REPLACE/READ su risorse Key Vault, RBAC, SQL e DB, VNet/subnet, ACR, resource group o altra Container App, duplicazioni, azioni malformate, drift esterno e cambi agli output Terraform. Le stringhe di prova utilizzano un sentinel sintetico e i test ne controllano l'assenza da stdout/stderr. È verificato che il workflow applichi lo **stesso** `deploy.tfplan` revisionato dal gate, senza altri apply né promozione automatica del traffico.

GREEN è una piccola modifica al solo `scripts/azure/check-staged-rollout-plan.py`. Le suite backend xUnit/PostgreSQL, React/Playwright, CodeQL, SCA e Docker devono essere tutte verdi sullo SHA `main` finale prima della chiusura di #53. Le prove offline non eseguono `terraform apply`, non ispezionano lo state in Azure e non dimostrano che il segreto storico sia stato eliminato: #49 resta aperta.

## #54 — TDD dell'inventario delle revisioni prima del retirement PostgreSQL legacy (ADR 0047)

`tests/infra/test_legacy_postgres_retirement_preflight.py` usa un eseguibile `az` sintetico per simulare esclusivamente `containerapp revision list --all` e `containerapp revision show`. Il test RED manca inizialmente del tool. GREEN richiede un caso valido di revisione attiva + inattiva con secret `pg-<16hex>`, e casi avversariali con legacy `postgres-connection` referenziata da revisione attiva, inattiva o altra variabile, connessione inline, secret non versionato, mancanza/duplicazione della connessione, secondo container, revisioni duplicate, schema API incompleto, lista vuota, nessuna active, Azure CLI non disponibile/JSON malformato e parametri non validi. I test richiedono l'assenza di comandi mutativi o letture di secret, e che nessun sentinel/URI/identificatore di revisione sia presente nei messaggi di errore.

Le verifiche unit Python sono **offline** e non attestano l'inventario delle revisioni effettivamente conservate nel tenant Azure. Il test automatizzato non è stato collegato alla release `deploy.yml`: è una precondition operator-only di un successivo cambio non distruttivo, che il gate di staging #53 oggi blocca intenzionalmente. Prima di chiudere #54 servono Python/Terraform, xUnit/.NET10/PostgreSQL17, React/Playwright, CodeQL C#/JS-TS, audit dipendenze e Docker **7/7 sulla HEAD `main`**. La cancellazione del segreto, la migrazione Terraform State e la rotazione password restano requisiti aperti della #49.

## #55 — TDD gate offline per `removed destroy=false` del secret legacy (ADR 0048)

RED `tests/infra/test_legacy_postgres_handoff_plan.py` richiede che un validatore separato accetti un JSON Terraform sintetico con **un** `["forget"]` sul solo `azurerm_key_vault_secret.postgres_connection`, `azurerm_container_app.main` `["no-op"]` e tutte le altre risorse `["no-op"]`. Test negativi rifiutano `delete`, `create`, `update`, altri `forget`, `resource_drift`, `output_changes`, indirizzi duplicati, vecchia app-scoped secret modificata o mancante, conversione in password inline, URI versione/host falsi, `before` incompleto e `after` non nullo. Le sentinelle sintetiche non devono apparire in stderr/stdout. GREEN è `scripts/azure/check-legacy-postgres-handoff-plan.py`, lettura JSON solo via stdin senza Azure CLI, Terraform apply, state rm o side effects.

L'invariante testato include **nessuna modifica** a `infra/main.tf` (la risorsa legacy è ancora presente) e `.github/workflows/deploy.yml` (nessuna chiamata al nuovo gate dal workflow di staging, che blocca comunque ogni `forget`). Tutti i job CI devono risultare verdi sulla HEAD `main`: Terraform/Python, PostgreSQL17/.NET10, Playwright, CodeQL, SCA e Docker. Il piano reale, le permission e lo State remoto non vengono usati nei test e devono essere verificati successivamente tramite runbook e approvazione di sicurezza #49.

## #56 — TDD del cleanup del piano di staging ACA (ADR 0049)

RED: `tests/infra/test_sensitive_stage_plan_cleanup.py` estrae direttamente lo script `run: |` del workflow `.github/workflows/deploy.yml` e lo esegue in una directory temporanea con finti eseguibili `terraform` e `python3` (nessun Azure, State o DB). Prova successo e fallimento indipendente di `plan`, `show`, gate e `apply`, oltre alla presenza di un file preesistente o un symlink non fidato. Impone `set -euo pipefail`, `umask 077` (**0600** per il piano), registrazione del `trap EXIT` prima di plan, pulizia automatica alla fine di ogni percorso, niente output della sentinel-password e nessun apply se la verifica precedente è fallita. La logica originale di `check-staged-rollout-plan.py`, il vincolo `stable=100%/candidate=0%` e tutte le suite PostgreSQL/React rimangono invariati.

GREEN modifica soltanto lo step del workflow; la CI `main` deve superare **7/7** job sull'ultimo commit: Terraform validate/Python, .NET10/xUnit con PostgreSQL17, React/Playwright, SCA, CodeQL C#/JS-TS e Docker. Il test non simula crash di host o `SIGKILL`; la pulizia non è sicura contro attaccanti con controllo del runner e non altera State Terraform, cronologia o password reali. #49/#5/#6 rimangono aperte.

## #57 — TDD di univocità dei claim JWT nel Core API (ADR 0050)

RED `tests/backend/Comuni.Api.Tests/UnambiguousPrincipalTests.cs` crea `ClaimsPrincipal` **sintetici autenticati** con due `organization_id` uguali o di Comuni diversi, due `sub` uguali o discordanti, due `iss` uguali o discordanti; per Superadmin verifica coppie `iss/sub` duplicate e identità tenantless. Prima del fix i vari `FindFirst` avrebbero autorizzato usando il primo claim; i test impongono invece che `OrganizationRoleHandler` e `PlatformOperatorHandler` neghino senza chiamare alcun store e che context tenant/audit e rate limiter non producano identità arbitrarie. GREEN introduce `VerifiedPrincipalIdentity` e sostituisce il recupero dei claim in tutti i confini dell'API. Le prove positive preservano le richieste con unica identità.

La CI del commit **RED** deve fallire nei test API/.NET+PostgreSQL; il commit GREEN deve superare i test xUnit con PostgreSQL 17, build React/Playwright, Terraform/Python, CodeQL C#/JS-TS, NuGet/npm SCA e build Docker, tutti **7/7 sul commit finale di main**. Questi test validano la semantica del principal ASP.NET Core e non sostituiscono integrazione IdP/OIDC, verifica di duplicati JSON all'ingresso del JWT, prova TLS/CA o tenant isolation su Azure reale.

## #58 — TDD dei JWT firmati con proprietà JSON duplicate prima dei claim (ADR 0051)

RED `tests/backend/Comuni.Api.Tests/SignedDuplicateJwtPayloadTests.cs`: gli esperimenti usano un **JWT compatto firmato realmente** con payload JSON costruito verbatim. L'API `Testing/DevelopmentJwt` viene esercitata con HMAC HS256 sintetico; la factory `OidcApiFactory` firma bytes raw RS256 e usa un JWKS finto in memoria (nessun IdP o rete esterna). La prova del parser originario dimostra acceptance/200 o 403 di token con `organization_id`, `sub`, `iss`, `aud` duplicati (sia uguali che discordanti), prima della materializzazione di `ClaimsPrincipal`; sono inclusi `role` duplicato effettivamente, duplicati dentro oggetti e array, chiavi escaped `\\u0073ub`, payload firmati troppo grandi e JSON non conforme. I controlli positivi richiedono ancora 200 per token validi HS256 Testing e RS256 OIDC finto. I test di configurazione impongono `OnTokenValidated` in entrambe le modalità, non solo in Development.

GREEN: `JwtPayloadDuplicatePropertyGuard` usa i bytes del `SecurityToken` già verificato da JwtBearer, con parser `System.Text.Json` e nomi univoci case-sensitive a ogni livello, profondità 32 e payload 64 KiB; in caso di errore `context.Fail` rifiuta senza loggare token/identità. I controlli già esistenti di issuer/audience/firma/scadenza, binding OIDC e membership PostgreSQL/RLS non si riducono. La CI finale sulla **esatta HEAD `main`** deve verificare tutti i sette job: xUnit PostgreSQL17/.NET10, React/Playwright, Terraform/Python, CodeQL C#/JS-TS, SCA NuGet/npm e Docker. Nessun test documentato è una validazione di provider IdP/CA/MFA live.

## #60 — TDD contro header JOSE duplicati nei JWT firmati (ADR 0052)

RED `SignedDuplicateJoseHeaderTests.cs` in `tests/backend/Comuni.Api.Tests` estende le prove #58 con compact JWT firmati realmente. I casi HS256 esistono soltanto nella factory locale `ApiFactory` Testing: `alg` e `typ` ripetuti, `kid` uguali o discordanti, `\\u0061lg` unescaped equivalente ad `alg`, nomi duplicati dentro oggetti/array e header sintetico oltre **8 KiB**. RS256 è firmato dalla `OidcApiFactory.RawSignedToken(rawPayload, rawHeader)` con RSA effimera e JWKS in memoria, non con un servizio IdP reale; anche il JOSE `kid`, `alg`, `typ` e proprietà custom duplicate devono essere rifiutati. I test interrogano `JwtPayloadDuplicatePropertyGuard.IsAcceptable(new JsonWebToken(compact))` oltre alla vera API, perché il parser potrebbe rifiutare o normalizzare autonomamente alcuni header: il controllo post-parser deve comunque funzionare. Verifiche positive richiedono `true` e HTTP `200` per header singolo firmato e corretto.

GREEN estende `JwtPayloadDuplicatePropertyGuard` senza secondo verificatore crittografico, validando header 8 KiB/payload 64 KiB con controllo JSON univoco, max depth 32, dopo `JwtBearerEvents.OnTokenValidated`. RED [CI GitHub Actions 43857061009](https://github.com/KeyserDSoze/Comuni/actions/runs/43857061009) mostra fallimenti xUnit backend sul parser header mentre infra/frontend sono verdi. La CI finale deve avere **7/7 job** sullo stesso SHA HEAD: PostgreSQL 17/.NET 10/xUnit, React/Playwright, Terraform/Python, SCA NuGet/npm, CodeQL C#/JS-TS e Docker. La correttezza dei token OIDC emessi da un IdP produttivo, della CA/VNet e l'isolamento su Azure reale non è dimostrata dai fake locali.

## #61 — TDD fail-closed per settings ACA condivisi (ADR 0053)

RED: `tests/infra/test_aca_shared_scope_guard.py` prova su piani Terraform sintetici che il gate preesistente consentiva di variare l'identity della Container App, il registry, l'environment, le impostazioni ingress non-traffic e la identity del secret Key Vault con URI invariato. La fixture di `test_staged_rollout.py` include ora identity UserAssigned, registry e ingress esistenti con copie indipendenti before/after.

GREEN: `check-staged-rollout-plan.py` blocca tutte le mutazioni condivise e richiede UAI coerente per i nuovi secret; rimangono intatti il vincolo Container App-only, lo stage 100/0 e il controllo del FQDN del DB. La suite viene eseguita dal job CI infrastruttura (`python -m unittest discover -s tests/infra -p 'test_*.py'`), oltre ai test xUnit PostgreSQL, frontend Playwright, SCA/CodeQL e Docker per completare l'incremento. Sono soltanto contract tests offline; non attestano il deploy Azure.

## #62 — TDD sui parametri di autenticazione della candidata (ADR 0054)

RED: `tests/infra/test_aca_candidate_oidc_env.py` esercita `check-staged-rollout-plan.py` con piani JSON sintetici per `ASPNETCORE_ENVIRONMENT` non Production, `Authentication__Mode` DevelopmentJwt o non Oidc, Authority HTTP/con URL userinfo/query/fragment/vuota, audience non valida, `DOTNET_ENVIRONMENT` e alias/duplicati case-insensitive e `__`/`:` su OIDC, RLS e SQL. Le fixture `test_staged_rollout.py` riproducono l'env hosted Production/Oidc presente in Terraform e conservano i casi avversariali precedenti. I test del gate RED dimostrano l'accettazione non sicura prima del fix, senza stampare stringhe sentinel.

GREEN: `validate_hosted_oidc_environment` valida tutte le entry e le chiavi normalizzate **prima dei controlli delle secret**; gli errori non riportano i valori del piano. Verificare la suite Python completa nella CI insieme ai test xUnit/PostgreSQL, React/Playwright, CodeQL, SCA e Docker sullo stesso SHA `main` (7/7). I test sono offline: non collaudano un IdP effettivo, CA/Key Vault/ACA reali o lo smoke multi-tenant in Azure.

## #63 — Test RED→GREEN del binding immagine candidata / commit / ACR managed (ADR 0055)

I test Python `tests/infra/test_aca_candidate_image_preapply.py` usano solo JSON sintetico: accettano `<synthetic.azurecr.io>/comuni:<SHA40>` quando è coerente con `azurerm_container_registry.main` del plan, rigettano `latest`, registry estranei, repo/tag/digest manipolati, immagine nulla o mancante, ACR incompleto/duplicato/di tipo non valido, SHA non canonico/differente e `init_container` che tenta di eseguire immagini non approvate. Sono previsti sentinel antileak. La fixture comune `test_staged_rollout.py` include il registry managed, l'immagine e uno SHA di test, e tutti i wrapper delle vecchie suite inviano al gate il nuovo argomento obbligatorio `--source-commit-sha`. Il workflow CI di staging deve usare esplicitamente `GITHUB_SHA` prima dell'`apply`, non valori dal piano.

Il RED verifica l'accettazione non sicura nel gate originario; il GREEN introduce il controllo tra i gate che precedono l'`apply`. Sono richiesti test infra Python/Terraform, .NET10+xUnit PostgreSQL, React/Playwright, CodeQL C#/TS, audit NuGet/npm e Docker (7/7) sullo **stesso SHA finale main** prima di chiudere #63. Nessun test offline attesta il contenuto crittografico del tag ACR, digest, provenance o rollout Azure reale.

## #64 — TDD digest ACR verificato, piano Terraform e post-stage ACA (ADR 0056)

RED in `tests/infra/test_aca_pushed_digest.py`: fake `az` on `PATH`, stdout Docker sintetico e GITHUB_ENV privato. Deve fallire quando manca lo script, il registry risponde con digest differente, mancante/multiplo/malformato, repository/tag non coerenti, output push ambiguo, SHA/ACR/host alterato, file mancante o CLI fallita. Il contenuto di `GITHUB_ENV` non cambia se la verifica fallisce. GREEN: solo Docker receipt esatto + manifest ACR identico producono `TF_VAR_image` e `CANDIDATE_IMAGE_DIGEST`, senza divulgare stdout/stderr dei comandi.

RED in `tests/infra/test_aca_digest_plan_guard.py`: solo immagine `<managedACR>/comuni@sha256:<64hex>` uguale all'argomento digest approvato è valida; tag `:<GITHUB_SHA>`, altri repository/host, digest sbagliato, valore assente/malformato, init container, OIDC non Production, SQL stable e source commit metadata falsato devono essere rifiutati. La fixture comune e i test infra precedenti usano ora digest sintetico più `Release__SourceCommitSha` a 40 hex; il fake shell `test_sensitive_stage_plan_cleanup.py` riceve anche `CANDIDATE_IMAGE_DIGEST` per continuare a provare cleanup `EXIT`, `umask 077` e `pipefail`. RED→GREEN anche per `test_live_revision_verification.py` (digest URI accettata, tag non accettati dal post-stage), con fake `az containerapp`.

Definizione Done **offline**: suite Python/Terraform, xUnit .NET10/PostgreSQL17, React/Playwright, CodeQL C#/JS-TS, audit NuGet/npm e build Docker tutti 7/7 sullo **stesso commit main**. Non è un test live di ACR/ACA/Key Vault, né una attestazione SBOM/SLSA/firma: esercitare separatamente ambiente reale e revoche RBAC prima di produzione.

## #66 — TDD per signed provenance OCI e identity GitHub/Sigstore (ADR 0057)

Il RED in `tests/infra/test_aca_signed_provenance.py` invoca il vero script (inizialmente mancante) con un **fake `gh` locale**, senza rete, GitHub token reale o ACR. Simula CLI non disponibile/fallita, firma/issuer/repository/workflow non verificati, auth mancante, subject/digest sbagliati, predicate non SLSA, output non JSON/vuoto/oversized, source SHA differente anche a parità dei primi 12 caratteri, branch diverso da main, host e nome repository non approvati. L'asserzione di regressione controlla che il comando `gh attestation verify` porti tutti i flag di identità e provenienza, che `actions/attest` abbia i permessi minimi e che la firma e il verifier precedano sempre `terraform plan`. I test vietano di riportare sentinel e digest/credenziali nell'errore.

Il GREEN usa `scripts/azure/verify-image-provenance.py` (metadata non sensibili e verifiche `gh` + subject JSON) insieme ai gate esistenti per digest, OIDC, RLS, Key Vault, source SHA, stable 100%/candidate 0% e cleanup del piano. La CI conclusiva è definita dai sette job sul medesimo SHA `main` (xUnit/PostgreSQL17, React/Playwright, Terraform/Python, CodeQL C#/JS, NuGet/npm SCA, Docker). Il fake **non verifica firme reali**: l'integrazione Sigstore/GitHub Attestations e l'uso di ACR reale devono essere provati dal primo deploy approvato (issue #65/#6), senza dichiarare production-ready in base alla sola CI.

## #67 — TDD Trivy/SPDX CVE gate e signed SBOM OCI (ADR 0058)

RED: `tests/infra/test_aca_sbom_cve_gate.py` esegue i veri checker (inizialmente assenti), con Trivy JSON/SPDX 2.3 e output `gh` simulati: verifica positivo pulito con package OS/language, LOW/MEDIUM ammessi; fallimenti per UNKNOWN/HIGH/CRITICAL anche senza versione fix, scanner/report/DB mancanti, report senza risultati o pacchetti, `ArtifactName` diverso, `artifactType` non container, SPDX vuota/errata, URI/tag malformati e sentinelle nei log. Fake `gh attestation verify` con repository/signer/main/full SHA/predicate SPDX e digest esatti: firma mancante, CLI error, JSON spoofato/oversized e repository/ref non approvati sono rifiutati. Nessuna richiesta di rete, ACR o token reale.

GREEN: `scripts/azure/check-image-sbom-scan.py` valida il JSON Trivy e la SPDX prodotta dallo stesso report prima del passo di firma; `verify-image-sbom-attestation.py` delega le firme Sigstore al vero `gh attestation verify` in produzione ma, in test, controlla gli argomenti del fake e i subject verificati. Un test controlla l'ordine del workflow: setup Trivy → scansione sull'URI digest → SBOM SPDX → attestazione firmata → verifica pre-plan → Terraform plan. Restano intatti i test di RLS/OIDC/Key Vault, cleanup file sensibili, full source SHA e split stable 100%/candidate 0%.

Definition of Done dell'incremento: **7/7 CI** sull'ultimo commit di `main` (Terraform/Python, xUnit/PostgreSQL, React/Playwright, CodeQL C#/JS, audit NuGet/npm, Docker). I test della CI usano JSON e CLI mock, **non** una scansione reale né una firma Sigstore/live Azure: prima della produzione ripetere il gate sull'immagine in ACR e verificare la disponibilità degli advisory DB.

## #68 — TDD lock di ACR tag e manifest con fault injection offline (ADR 0059)

`tests/infra/test_aca_acr_tag_manifest_lock.py` aggiunge un fake rigoroso di `az` su PATH che registra l'intera sequenza di chiamate senza rete: digest attuale del tag → lock del solo tag `comuni:<SHA>` → lock del solo manifest `comuni@sha256:<digest>` → rilettura digest → lettura `changeableAttributes` tag → lettura `changeableAttributes` manifest. Il test positivo obbliga gli attributi JSON *booleani* `writeEnabled=false`, `deleteEnabled=false` e `readEnabled=true`, senza update della repository intera. I casi RED negano tag mutato prima/dopo lock, SHA/registry/host/repo/immagine/digest errati, errori di ciascuna delle sei chiamate, attributi nulli/malformati/non persistiti o read disabilitato; nessuna diagnostica CLI sentinel è riportata. La fixture non effettua operazioni Azure reali.

Il workflow deve chiamare lo script **dopo** il resolver del digest da Docker push/ACR, **prima** di Trivy, firma SLSA/SPDX e Terraform plan. GREEN conserva test precedenti e controlli di RLS/OIDC/Key Vault/stable 100%-candidate 0%. Per completare l'issue servono i sette job verdi sullo **stesso SHA finale di main** (Terraform/Python, xUnit/PostgreSQL, React/Playwright, CodeQL C#/JS, SCA NuGet/npm, Docker).

Questa CI verifica i **contratti di comando**, non la reale persistenza del lock ACR o il modello IAM del principal OIDC. La prima prova reale con owner Azure è necessaria per la #65/#6; non è permesso dichiarare produzione sicura in base ai fake.

## #69 — TDD preflight read-only ACR RBAC e ruoli per UAI/runner (ADR 0060)

La suite `tests/infra/test_aca_acr_rbac_preflight.py` installa un fake rigoroso del comando `az` in una directory temporanea su PATH: cinque chiamate attese **di sola lettura** (`az acr show`, `az identity show`, `az ad sp show`, due `az role assignment list` per principal ID), con flag identici a quelli della CLI e controllo anti-leak del sentinel. Il test positivo verifica registry Basic/RBAC, admin disabilitato, `AcrPull` per la UAI e `AcrPush` per il deployer OIDC **distinto**. RED: il verifier e il passo pre-push non esistevano; GREEN: script fail closed e invocazione dopo login. Le matrici avversariali rifiutano `rbac-abac`, admin true, host/ID/prefix spoofati, client e object ID sovrapposti, ruolo non presente, privilegio ereditato, assegnazione condizionata, errori in tutte le cinque chiamate e JSON malformati, senza mai mutare ruoli.

Un test protegge anche Terraform: esiste solo l'assegnazione `AcrPull` alla managed identity dell'app, non `AcrPush`. La CI Python/Terraform, xUnit/PostgreSQL, React/Playwright, CodeQL C#/JS, SCA NuGet/npm e Docker devono essere **7/7 verdi sullo stesso SHA finale di `main`** prima di chiudere #69.

Questa CI verifica esclusivamente la forma delle chiamate e risposte simulate; non effettua autenticazione reale Entra/Azure, test `docker pull` come ACA o prova dei permessi per modificare i lock ACR. La parent #65 e le issue #5/#6/#49 restano aperte per least privilege live e go-live.

## #71 — TDD handoff federated OIDC e riduzione esposizione secret Terraform (ADR 0061)

RED in `tests/infra/test_azure_oidc_session_handoff.py`: il vero tool inizialmente assente `check-azure-oidc-session.py` riceve risposte fake di `az account show` e deve validare un `servicePrincipal` con ID client attivo, tenant e subscription esatti; negare login utente, managed identity non approvata, stesso client build/infra, altro SP, ID malformati, tenant/sub errati, assenza login, CLI failure, risposte nulle/array/oversized e sentinel leakage. RED esteso in `test_aca_acr_rbac_preflight.py`: prima delle query Azure i clientId builder e infra devono essere diversi; la verifica RBAC richiede `AcrPull` per UAI runtime e `AcrPush` per builder.

GREEN: tre `azure/login@v2` sul medesimo workflow: infra RBAC preflight → build/push/lock/Trivy/Sigstore → infra Terraform; `az logout` e `az account clear` tra le fasi, `docker logout` prima della fase Terraform, `check-azure-oidc-session.py` obbligatorio dopo ogni login. Test statici controllano identità e ordine, secret `AZURE_ACR_PUSH_CLIENT_ID` disponibile solo da GitHub Environment, controllo **repo/main/dispatch prima del primo login**, nessun client da input. Le password `TF_VAR_postgres_admin_password` e `TF_VAR_postgres_runtime_password` non devono comparire nel job env o nella fase build e sono inserite solo nello step `Plan and stage candidate`. Tutti i precedenti test su digest OCI, scan CVE, firmatari, RLS/OIDC/Key Vault e plan cleanup continuano a girare.

Definizione di Done del software: CI 7/7 allo stesso SHA `main` (Python Terraform, xUnit/PostgreSQL, React/Playwright, CodeQL C#/JS, audit NuGet/npm e Docker). **I mock non provano** FIC Azure, reale `az account show` del runner o permessi ARM/ACR, né un isolamento del job: serve approvazione di un owner, provisioning separato e test live/rollback della #70 prima di dichiarare il rilascio sicuro in Azure.

## #73 — TDD OAuth2 ACR per Docker con token in memoria e fake HTTPS (ADR 0062)

RED in `tests/infra/test_acr_oauth_data_plane_login.py`: script `login-acr-oauth.py` e invocazione del workflow inizialmente assenti. La suite usa `subprocess.run` e `urllib.request.build_opener` falsi (nessuna rete, Azure o Docker). Il test positivo pretende il comando `az account get-access-token --resource https://containerregistry.azure.net`, il `POST https://<managedACR>.azurecr.io/oauth2/exchange` con `grant_type=access_token`, `service`/tenant coerenti, rifiuto di tutti i redirect, risposta ACR contenente `refresh_token` e `docker login --username 00000000-0000-0000-0000-000000000000 --password-stdin`. Matrice RED/GREEN per registry host/tenant falsi, CLI non disponibile, token mancanti/malformati, HTTP 30x/4xx/5xx, errore rete, JSON null/list/oversized, refresh token non valido, Docker failure e sentinel leak. L'URI non può puntare a host/protocollo/porta diversi; stdout/stderr della CLI, AAD token, ACR refresh token e credenziali non devono finire nei log.

Il contratto workflow impone la chiamata OAuth2 dopo il guard OIDC builder e **prima** di Docker build/push; vieta `az acr login` e preserva `docker logout` prima di Terraform. Nessun cambiamento ai test dei gate digest OCI, ACR tag+manifest lock, Trivy/SPDX, SLSA, segreti PostgreSQL o stable 100%-candidate 0%.

Per chiudere la #73 servono i sette job CI verdi sullo stesso SHA finale di `main`: Python/Terraform, xUnit .NET10/PostgreSQL, React/Playwright, CodeQL C#/JS, NuGet/npm audit e build Docker. **La CI offline non dimostra autorizzazioni ACR o token reali**, quindi #72 resta aperta, e nessuna produzione può essere dichiarata pronta sulla base dei mock.

## #74 — RED→GREEN REST data-plane ACR e regressioni lock/digest (ADR 0063)

RED in `tests/infra/test_acr_registry_data_plane_rest.py`: il client HTTPS condiviso inizialmente mancante. Prove con fake Entra CLI `get-access-token`, OAuth2 exchange e token repository-scoped; pretendono path/host `<ACR>.azurecr.io` esatti, `scope=repository:comuni:pull,push`, Bearer soltanto su GET/PATCH, no redirect, timeouts e body JSON `{"writeEnabled":false,"deleteEnabled":false}`. Negano registry/tenant/sha/digest malformati e risultati con repository/tag/digest diversi. Verificano che il workflow rimanga build OIDC prima di Docker/metadata lock e che i due script non usino `az acr manifest/repository`.

Le suite esistenti sono migrate, senza rimuovere i casi avversariali: `test_aca_pushed_digest.py` usa il finto data-plane per controllare digest del receipt, singolo tag, mismatch/ambiguità e **GITHUB_ENV invariato in caso di rifiuto**; `test_aca_acr_tag_manifest_lock.py` usa fake HTTPS per il lock indipendente di tag e digest, con fault injection su ciascun exchange, GET, PATCH e read-back, permessi nulli/stringhe, tag mutato e valori malformati, vietando sblocchi e URL repository-wide. Le versioni precedenti usavano un fake `az acr`, non più appropriato dopo la migrazione.

Definizione di Done del codice: CI 7/7 sul medesimo SHA `main` (Python/Terraform, xUnit .NET10/PostgreSQL, React/Playwright, CodeQL C#/JS, audit NuGet/npm e build Docker). I test **non** eseguono token exchange ACR reale, gestione IAM, PATCH su registry, Terraform apply o smoke ACA: per dichiarare chiusa la #74 e #72 serve l'owner con un registry di prova autorizzato e riscontri verificabili. Un successo CI non sostituisce la prova dei permessi data-plane del principal con solo `AcrPush`.

## #75 — Test RED→GREEN auditor ACR read-only a scope pull (ADR 0064)

RED: `tests/infra/test_acr_readonly_lock_attestation.py` richiedeva nuova interfaccia `ACRClient(..., read_only=True)`, `verify_locked` e uno script CLI di audit manuale inizialmente assenti. Il fake di `az account get-access-token` e HTTPS ACR non contatta Azure: verifica sequenza OAuth2 `POST /oauth2/exchange`, `POST /oauth2/token` **scope esatto `repository:comuni:pull`**, poi soltanto due REST GET sulla singola repository `comuni`; garantisce che `lock()` e `_request("PATCH",...)` falliscano **prima** di effettuare richieste di rete. Matrici negative: tag digest discordante, manifest non corrispondente, registry spoofato, write/delete ancora abilitati o read disabilitato, attributi mancanti/non booleani, token scadente o nullo e status HTTP errati. Il CLI richiede `image=<managedACR>/comuni@sha256:<digest>` esatta e non espone token/tenant/digest nei messaggi di errore.

GREEN: `acr-registry-data-plane.py` distingue staticamente i due scope fissi (lettura vs writer), `check-acr-readonly-lock.py` è invocabile da operatore autorizzato ma **non** agganciato al workflow di rilascio, che conserva `repository:comuni:pull,push` per blocco tag+manifest. CI 7/7 sullo stesso SHA main: Terraform/Python, xUnit/PostgreSQL, React/Playwright, CodeQL C#/JS, NuGet/npm audit e Docker. Tutte le verifiche in CI restano simulazioni del protocollo, **non** del comportamento IAM reale di ACR né dell'approvazione di deployment/lock su Azure.

## #76 — TDD pin SHA delle Action GitHub su CI/deploy (ADR 0065)

`tests/infra/test_github_action_sha_pins.py` è eseguito da `python3 -m unittest discover -s tests/infra -p 'test_*.py' -v` nel job Terraform. RED: i due workflow usavano ancora `@v2/@v3/@v4`, e i nuovi test rifiutavano i riferimenti mobili. GREEN: ogni `uses:` dei workflow è un ref a un **commit revisionato** di 40 hex e il test di handoff OIDC aggiornato verifica il commit pin di `azure/login`. La matrice avversariale rifiuta tag mobili, branch `main`, SHA abbreviata o differente, `docker://`, `./local`, action/owner non in allowlist, expression dinamiche, e assenza di un uso obbligatorio (14 in CI, 8 in deploy). I tag annotati GitHub non devono essere scambiati con commit SHA (ADR 0065).

La chiusura richiede la CI completa **7/7 sulla stessa HEAD di `main`**: Terraform/Python, unit xUnit e integrazioni reali PostgreSQL, React/Playwright, CodeQL C# e JS/TS, audit NuGet/npm e Docker build. Questo test è statico: non prova l'assenza di vulnerabilità nel codice dell'action, nei tool caricati dalle action, nella macchina runner o nelle immagini base; nessuna operazione Azure viene eseguita per verificarlo.

## #77 — TDD pin digest OCI multiarch verificati per Docker SDK/Node/ASP.NET (ADR 0066)

Il test `tests/infra/test_immutable_docker_base_digests.py` è stato committato **prima** del pin delle immagini (RED su `main`): richiede esattamente tre FROM, `backend` SDK 10.0, `frontend` Node 22 Alpine e ASP.NET Runtime 10.0, ciascuno con **sha256 indice completo** presente in una allowlist revisionata, rifiutando SHA sconosciuti, uppercase, più stage, ARG/ONBUILD o source registry diversi. Controlla anche che CI e deploy usino entrambi `docker build --platform linux/amd64` e non accettino `--build-arg BASE_IMAGE` o platform dinamica. Nei test RED i digest allowlisted iniziali erano intenzionalmente vuoti e i workflow ancora senza piattaforma esplicita.

Per raccogliere **evidenza reale dei tre sha256** è stato aggiunto temporaneamente un probe CI in sola lettura con `docker buildx imagetools inspect` delle sorgenti MCR e Docker Hub; il run [43911157458](https://github.com/KeyserDSoze/Comuni/actions/runs/43911157458), job Terraform, mostra il digest completo dell'indice e i child manifest linux/amd64: `fe0fd4e9...` SDK, `1314fb30...` Node, `bfd912c8...` ASP.NET. GREEN: Dockerfile `FROM tag@sha256` esatti, allowlist test riempita con gli stessi valori, piattaforma amd64 in `ci.yml` e `deploy.yml`, probe temporaneo eliminato. La CI finale deve eseguire tutte le suite Python/Terraform, xUnit/PostgreSQL, React/Playwright, CodeQL C#/JS, NuGet/npm audit e **real Docker build** sul medesimo SHA `main`; nessun test ACR/ACA live viene eseguito.

Un digest indice pinnato e un Docker build CI verde non verificano la firma del publisher, non sostituiscono scansioni di CVE periodiche e non garantiscono che la stessa base sia aggiornata dopo una patch upstream: qualsiasi cambio deve attraversare un nuovo ciclo TDD e review. #65 rimane aperta per tali requisiti.

## #78 — TDD delle action Node24, commit SHA ufficiali e regressioni OIDC (ADR 0067)

\`tests/infra/test_github_action_sha_pins.py\` applica una allowlist di commit SHA verificati via API Git refs upstream, e controlla le occorrenze previste nei due workflow. RED iniziale: passaggio del contratto \`checkout@v5\`/\`setup-terraform@v4\` prima dei YAML, [CI 43915493531](https://github.com/KeyserDSoze/Comuni/actions/runs/43915493531) con failure attese. GREEN parziale: nuove SHA nei workflow, [CI 43915868402](https://github.com/KeyserDSoze/Comuni/actions/runs/43915868402) 7/7.

L'ispezione degli esatti file \`action.yml\` ha rilevato tre **ulteriori** action su Node20. Secondo RED: suite aggiornata per \`setup-dotnet@v5\`, \`setup-node@v5\`, \`Azure/login@v3\` con SHA verificati e controllo di tre login OIDC in \`test_azure_oidc_session_handoff.py\`; [CI 43916452331](https://github.com/KeyserDSoze/Comuni/actions/runs/43916452331) con errori attesi. GREEN completo: 3 setup-dotnet e 2 setup-node nel CI, 3 Azure Login nel deploy, 7 checkout e 2 Terraform in totale, tutti con pin reviewed e runtime \`node24\`. Conservare il test anti-\`@vN\`, ref non revisionati e action rimossa; \`node-version: '22'\` per la SPA deve rimanere invariato. \`Azure/login@v3\` nel deploy è controllato **staticamente** in CI ma **non** eseguito contro Entra reale.

Criterio di completamento software: **sette job CI verdi sul medesimo SHA HEAD di \`main\`**: Terraform e test Python infra, backend xUnit/PostgreSQL, React/Playwright, CodeQL C#/JS, NuGet/npm advisory e build Docker linux/amd64 da basi digest-pinned. Il verde offline non attesta alcuna Federated Identity Credential Azure, token emesso, permesso ACR/Key Vault o \`terraform apply\`; queste verifiche richiedono approvazione owner ed erano già tracciate nelle issue P0 Azure.

## Gate GitHub CI vincolato alla SHA prima del deploy Azure (#79)

La suite `tests/infra/test_release_ci_preflight.py` (job Terraform validate) copre RED→GREEN dell'API read-only GitHub Actions con HTTPS simulato: verifica i sette job esatti e lo stesso SHA/run; rifiuta run assenti, multipli, pending, failed, PR/dispatch, SHA o repo sbagliati, job skipped/duplicati o sconosciuti, JSON ambiguo o oversized, redirect e errori remoti con output privati. Valida anche il contratto dello step in `deploy.yml`: `actions: read`, invocazione prima di Azure OIDC e push/plan. Il run `CI` del repository eseguito sullo SHA finale è il controllo end-to-end offline dei test, non una verifica Azure live del workflow manuale. Vedere [ADR 0068](../adr/0068-release-same-sha-ci-gate.md) e [runbook](deployment.md).

## Secondo Admin OIDC owner-only (#80, ADR 0069)

`tests/backend/Comuni.Api.Tests/AdditionalAdminEnrollmentTests.cs` esercita PostgreSQL 17 e `psql` reale nella CI backend: prima crea una organization sintetica e un primo Admin tramite la procedura owner-only esistente; poi richiede l'aggiunta di un secondo `iss+sub`, audit atomico ed esatto retry no-op. Rifiuta conflitti di issuer/ticket/identity, organization non operativa o senza Admin valido, ruoli misti, credenziale `comuni_app_runtime`, input invalidi e owner non autorizzato; controlla concorrenza su una stessa organization, approvazione riusata e quoting letterale di subject con aspetto SQL. Nessun test usa identità o dati comunali reali.

Il test RED è stato committato su `main` **prima** dello script e deve fallire senza `enroll-additional-admin.sql`. GREEN richiede backend xUnit + PostgreSQL, più i restanti job regressione CI (React/Playwright, Terraform, SCA, CodeQL C#/JS, Docker): chiudere #80 solo dopo 7/7 job success sul commit finale. Le verifiche non provano identità del revisore, prova legale del mandato, revoche in IdP o produzione pronta.

## Revoca Admin OIDC owner-only e blocco ultimo Admin (#81, ADR 0070)

La suite RED-first `tests/backend/Comuni.Api.Tests/AdminRevocationTests.cs` esercita PostgreSQL 17 e `psql` con schema owner e con ruolo runtime. Valida: revoca di un Admin con altro Admin OIDC attivo, audit atomico pseudonimo e retry esatto no-op; blocco ultimo Admin anche in presenza di Reader; due revoche concorrenti che lasciano un Admin; retry concorrenti; ticket/issuer/identity errati; status created/suspended, target inattivo, legacy unbound, input manipolati, divieto runtime, scope cross-tenant. Un test usa fixture OIDC locale **RS256**: prima della revoca il token permette `/api/v1/context` e `/api/v1/admin/modules`, e dopo la revoca lo **stesso token** restituisce 403 alle nuove richieste mentre l'altro Admin rimane autorizzato.

Ogni test usa organization sintetiche nel database temporaneo CI; nessuna identità reale, approvazione effettiva o chiamata Azure/IdP. Playwright già esistente è regression gate; non è prevista UI aggiuntiva. Valutare completamento solo dopo CI 7/7 sullo SHA definitivo di `main`. Vedere [ADR 0070](../adr/0070-owner-only-admin-oidc-revocation.md).

## Inventory Superadmin: regressione paginazione scalabile (#82)

La suite `PlatformInventoryApiTests.Oidc_platform_operator_can_page_safely_over_minimized_metadata_and_audit_each_read` non presume più che il database sintetico contenga meno di 100 Comuni. I test PostgreSQL CI aggiungono organization anche da altre classi; il vecchio `limit=1`/`pages < 100` causava falso FAIL quando si introducevano nuove suite Core (#81). Ora consulta l'inventory con `limit=25` consentito dall'API, legge e valida **ogni riga** e controllo di sicurezza, rifiuta ID duplicati o cursori che non avanzano, controlla che il numero totale dei risultati coincida con le organization presenti nel database di test e che il numero di eventi `platform.organizations.listed` coincida con il numero di pagine. Il limite anti-loop deriva dalla cardinalità osservata e non da una costante arbitraria. Non modifica endpoint, RLS o SQL reader. Vedere [issue #82](https://github.com/KeyserDSoze/Comuni/issues/82).

## Recupero del secondo Admin dopo revoca owner-only (#83, ADR 0071)

`tests/backend/Comuni.Api.Tests/AdminRecoveryTests.cs` è stato committato **RED prima della modifica SQL**: usa PostgreSQL 17/psql reali e fixture RS256 OIDC solo locale per l'intera catena bootstrap primo Admin → aggiunta secondo Admin → revoca auditata del primo → aggiunta di una **nuova** identità. I test verificano che il soggetto revocato riceva ancora 403 con token già firmato, che vecchia membership e audit siano immutati, che il nuovo Admin e l'Admin superstite possano usare l'API, retry idempotente e serializzazione concorrente. Negative: riattivazione di vecchio subject anche con issuer nuovo, reuse di ticket di bootstrap/revoca/grant, collisione con Reader/Officer, storico inattivo non auditato o audit duplicato, legacy issuer NULL, Comune created/suspended, login runtime, tenanti distinti e controllo sintattico degli input.

La CI esegue anche regressioni xUnit/PostgreSQL, Playwright, Terraform, SCA, CodeQL e build Docker; il verde deve riferirsi al **commit finale di main**. Non ci sono credenziali o identità di Comuni reali; nessuna prova di IdP/approvatore effettivo, rollout Azure o conformità PA.

## Emergency staging del singolo Admin OIDC sospeso (#85 / ADR 0072)

La suite `tests/backend/Comuni.Api.Tests/EmergencyAdminStagingTests.cs` è stata introdotta **RED** prima di `scripts/postgres/stage-emergency-admin-replacement.sql`. Esegue test xUnit contro PostgreSQL 17 e `psql` owner/runtime, con JWT RS256 OIDC firmati localmente. Test positivi: Comune inizialmente attivo con un solo Admin, sospensione owner-only e 403 immediato, stage transazionale e audit duplicemente collegato allo stesso incident, mantenimento della sospensione e dei moduli, vecchio e nuovo token entrambi 403 fino a separato change di riattivazione, successivo 403 del compromesso e 200 del nuovo Admin; retry identico senza ulteriore audit. Negative: tenant non suspended, senza evento di sospensione, created/missing, due Admin attivi, Admin inattivo o legacy, target con Reader, reviewer uguali/mancanti, issuer o ticket/subject invalidi, login runtime, cross-tenant, incident/target riusati e due staging concorrenti, e rifiuto se il subject compromesso possiede **anche** Reader/Officer (accesso residuo post-riattivazione). Playwright, CodeQL, supply chain, Terraform e build Docker restano gate di regressione CI 7/7 sullo SHA finale.

I reviewer sono stringhe sintetiche di test, non identità legalmente verificate; i test **non** collaudano IdP/SPID/CIE, MFA, operatori reali, Azure o un Comune reale. Lo scenario break-glass completo resta nella #84.

## Controllo SQL text e log server per dati privati nello staging owner-only (#88 / ADR 0073)

In `EmergencyAdminStagingTests.cs` i test RED richiedono che lo script #85 non contenga interpolation `:'emergency_*'`, che usi temp table `ON COMMIT DROP` e che il client legga l'envelope da un comando Python di allowlist fisso `\\copy FROM PROGRAM`. Un test xUnit/PostgreSQL 17 chiama lo staging dopo sospensione usando un `sub` SQL-like sintetico e `PGOPTIONS` con `log_statement=all`, ispeziona i **log Docker del container PostgreSQL della CI** e verifica presenza di `statement: COPY` e **assenza del canary**; richiede che la procedura preservi audit e tenant. Non è una scansione di SIEM/IdP live. In locale senza Docker la verifica del log server è dichiaratamente non eseguibile; nella CI GitHub la mancanza di log Docker è un FAIL.

La suite Python stdlib `tests/infra/test_private_psql_copy.py` viene eseguita nel job Terraform validate: input allowlist, encoding round-trip di subject SQL-like, assenza di variabili extra, errori statici senza echo per input null/empty/oversized, comando non supportato fail-closed e guard statico anti SQL literal. Un fallimento o helper mancante interrompe `psql ON_ERROR_STOP=1` e rollback. Tutte le suite xUnit/RS256/Playwright/Terraform/SCA/CodeQL/Docker restano gate 7/7 sullo SHA finale di `main`; il test di statement logging non elimina la necessità di verifiche reali per #86/#84.

## TDD COPY privato delle chiavi tenant proof (#90 / ADR 0074)

I test RED Python `tests/infra/test_private_psql_copy.py` verificano la presenza obbligatoria di `\\copy ... FROM PROGRAM` e temp table `ON COMMIT DROP` in bootstrap legacy e staging versionato, nessuna interpolazione `:'tenant_proof_key'`, `:'new_key'`, `:'new_key_id'`, allowlist con esatte variabili `TENANT_PROOF_KEY` e `TENANT_PROOF_KEY_ID`, payload base64(JSON) singolo e errori statici su input assente, vuoto o troppo lungo.

`tests/backend/Comuni.Api.Tests/TenantProofPrivateCopyTests.cs` esegue `psql` con PostgreSQL 17 reale e prova idempotenza legacy/versioned, mismatch, chiave revocata, validazione ID, runtime SQL negato, staging concorrente senza overwrite, nessun secret in output. Nel test canary, il server è configurato per `log_statement=all`, `log_parameter_max_length=-1` e `log_parameter_max_length_on_error=-1`: il log reale del container deve mostrare `statement: COPY` senza valore della chiave sintetica. L'attestazione richiede Docker log disponibile nella CI GitHub; non è una prova su Azure PostgreSQL/Key Vault/pgaudit. Restano regressioni `TenantProofRotationTests`, `TenantProofRetirementGuardTests`, `RuntimeDatabasePrivilegesTests`, Playwright e gli altri job della CI 7/7 sullo SHA finale. Per password/ruoli separati seguire #91.

## Password ruoli SQL senza plaintext statement: test RED/GREEN (#91, ADR 0075)

Il test RED Python `tests/infra/test_private_psql_copy.py` impone che `stream-private-input.py runtime-role|platform-role` legga **solo** una variabile rispettivamente da `RUNTIME_DB_PASSWORD`/`PLATFORM_READ_DB_PASSWORD`, generi un solo `SCRAM_VERIFIER` salted con 4096 iterazioni e nessun plaintext; verifica indipendentemente usando hashlib/HMAC PBKDF2, sale diverso su retry, formato corretto, input assenti/brevi/non-ASCII/eccessivi rifiutati. I due SQL owner-only devono usare `\\copy ... FROM PROGRAM`, temp table `ON COMMIT DROP`, senza `:'runtime_password'` / `:'platform_password'` o `\\gexec`; `test_platform_read_role_contract.py` controlla il confine spostato e le stesse restrizioni least privilege.

Il test xUnit `PostgresRolePrivatePasswordTests.cs` esercita contro PostgreSQL 17 reale i due script, rotazione e retry, verifier osservato nel catalogo riservato `pg_authid`, login Npgsql SCRAM effettivo, privilegi runtime/Reader, SQL runtime negato, input assenti/corti/Unicode respinti, ripristino della password CI originaria con `finally` per non contaminare altre suite. Per un canary password sintetico il test abilita via `PGOPTIONS` `log_statement=all`, `log_parameter_max_length=-1`, `log_parameter_max_length_on_error=-1`, ispeziona i log PostgreSQL container e richiede `statement: COPY` senza plaintext. Log o container non consultabili **fanno fallire la CI**, ma in un ambiente locale privo di Docker la prova è segnalata come indisponibile. Regressioni xUnit/RLS, Playwright, Terraform, CodeQL, SCA e Docker rimangono gate 7/7 sul medesimo SHA di `main`. I test non coprono audit DDL pgaudit/Azure, Key Vault, SIEM o un ruolo SQL live; #86/#49/#6 restano aperte.

## Gate pgAudit ROLE/DDL reale su PostgreSQL 17 (#92, ADR 0076)

La prova test-first `tests/infra/test_pgaudit_role_log_contract.py` richiede un test eseguibile e bloccante, non soltanto un'ispezione del sorgente. Nel job backend CI, prima degli xUnit API, `tests/postgres/pgaudit/Dockerfile` prepara un PostgreSQL 17 Debian **isolato** con il package PGDG `postgresql-17-pgaudit`; `tests/postgres/pgaudit/verify_role_audit.py` avvia un database temporaneo con `shared_preload_libraries=pgaudit`, crea l'estensione, applica le migrazioni EF e chiama i **veri script owner-only** di runtime e platform reader.

Le sessioni usano `pgaudit.log=role,ddl,write,function` e `pgaudit.log_parameter=on` oltre a `log_statement=all` / `log_parameter_max_length=-1` / `log_parameter_max_length_on_error=-1`. Devono apparire nei log `AUDIT: SESSION` per `ROLE,CREATE ROLE`, `ROLE,ALTER ROLE`, `ROLE,GRANT` con nome del ruolo, `<REDACTED>` per il verificatore, nonché `statement: COPY`. La prova legge lo **stderr reale** di `docker logs` in memoria e rifiuta canary password/verifier recuperati da `pg_authid` in qualsiasi riga. Testa anche login SCRAM effettivi, rotazione con nuovo sale, input mancante/rollback e credenziali runtime senza autorizzazioni. In caso di failure l'output stampato è unicamente diagnostica di fase, mai log grezzi, verifier o secret.

**Limite:** il test prova il comportamento della versione pgAudit nel container CI, **non** la redazione in Azure/pgAuditLogToFile/SIEM/APM, dump di memoria o SQL proxy. La #92 rimane aperta finché sono soddisfatti anche i prerequisiti reali di sicurezza, privacy e gestione degli operatori. Nessun nuovo runtime SQL grant, API o database di produzione.

## Enrollment Admin dopo staged break-glass e riattivazione separata (#87, ADR 0077)

Il test RED PostgreSQL 17 + `psql` `PostEmergencyAdminEnrollmentTests.cs` copre: sospensione owner auditata, sostituzione emergency del solo Admin su Comune sospeso, riattivazione con change owner indipendente e enrollment di un secondo Admin con un solo `platform.membership.admin.added` (retry no-op); vecchio token OIDC ancora 403, nuovo Admin 200 e assenza di accessi cross-organization. Prima di GREEN la CI ha avuto **2 fallimenti attesi su 340 test** nell'API, documentando il gap originario. Test di regressione fail-closed: duplicati/orfani negli audit `emergency.revoked/staged`, incident ticket riutilizzato, tenant non riattivato, subject già presente, SQL runtime, concorrenza di due enrollment con lo stesso ticket. Lo script verificato resta **owner-only offline**; le prove OIDC sono con JWKS/chiavi locali e non autenticazione reale. La CI 7/7 sul commit conclusivo rimane necessaria per chiudere la issue. Nessuna abilitazione produzione fino a #84, #86, IdP verificato, audit e approvazioni esterne; vedere ADR 0077.

## #94 — Enrollment owner-only OIDC senza issuer/sub in statement SQL (ADR 0078)

RED prima del codice: `tests/infra/test_admin_enrollment_private_copy.py` richiede `\\copy FROM PROGRAM ... add-admin`, una riga base64(JSON) con **solo** cinque `COMUNI_ADD_ADMIN_*`, nessun `:'add_admin_*'` e input mancanti/eccessivi rigettati senza echo; il primo run Terraform ha fallito sulle due condizioni attese. La suite xUnit/PostgreSQL 17 `AdditionalAdminEnrollmentTests.Additional_Admin_issuer_and_subject_do_not_appear_in_Postgres_statement_logs` usa `PGOPTIONS` con `log_statement=all`, parametri completi e un subject sintetico unico: interroga i veri log del container CI, richiede `statement: COPY`, vieta il subject nei log, ed evita di stampare il testo dei log in caso di errore. Fixture `AdminRecoveryTests` e `AdditionalAdminEnrollmentTests` eseguono `psql` dalla root del checkout affidabile, come già `PostEmergencyAdminEnrollmentTests`.

GREEN cambia esclusivamente il trasporto dati dello script `enroll-additional-admin.sql`, non l'autorizzazione e non i dati persistiti. Test di regressione: #80/#83/#87, JWT OIDC sintetici, tenant e RLS, concurrency, 7 job CI (backend PostgreSQL, Playwright, CodeQL C#/JS, dipendenze, Terraform, Docker). Il test per i log richiede Docker nella CI, ma in esecuzione locale priva di container non può dimostrare l'assenza di leakage. Base64 rimane reversibile: test offline diversi da autorizzazione Security/Privacy reale (#84/#86/#92).

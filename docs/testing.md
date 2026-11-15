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

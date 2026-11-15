# Architettura implementata — prima vertical slice

```mermaid
flowchart LR
    B["Browser / React PWA"] -->|"HTTPS / JWT"| A["Unica ASP.NET Core API"]
    A --> C["Business: ProtocolService"]
    C --> D["Domains: ProtocolRecord"]
    C --> I["Infrastructure: EF Core repositories"]
    I --> P[("PostgreSQL")]
    A --> O["OrganizationDirectory / Feature flags"]
    O --> I
    A --> S["Static React assets"]
```

## Confini e dipendenze
- `Comuni.Domains`: dominio puro, nessuna dipendenza EF o ASP.NET.
- `Comuni.Business`: interfacce di repository/directory e use case; dipende solo da Domains.
- `Comuni.Infrastructures`: PostgreSQL EF Core, query filters, repository e migrazioni.
- `Comuni.Api`: composition root, JWT, policies, endpoints REST OpenAPI, host per SPA.

## Flusso sicurezza
1. Middleware valida firma HS256, issuer, audience e lifetime.
2. Policy `Read` / `Write` verifica `organization_id` valido, `sub`, **organization esistente e non sospesa**, e **membership attiva/ruolo nel database**. Il claim JWT `role` non viene utilizzato per i permessi.
3. `HttpCurrentOrganization` estrae organization solo dal Principal autenticato; `OrganizationRoleHandler` controlla `platform.organization_memberships`.
4. `ProtocolService` verifica `organization_modules` nel DB.
5. Repository esprime `organizationId` nella query e EF impone query filter; SaveChanges rifiuta mismatch tenant.
6. Frontend riceve il contesto `/api/v1/context` e mostra solo i moduli abilitati (non è un confine di sicurezza).

La sospensione è persistita in `platform.organizations.is_suspended` (ADR 0008): un token valido non bypassa il blocco. La gestione amministrativa della sospensione non è ancora esposta e resta parte del lifecycle/Superadmin (#3/#10). Il database è condiviso con schemi `platform` e `protocol`, incluse membership tenant-scoped (GUID, subject, role, is_active). Il bootstrap migra e semina due organization solo in ambiente Development. In produzione non c'è seed automatico. Le operazioni admin/gestione organization richiederanno accessi separati e audit dedicato.

## Audit transazionale — prima slice

La registrazione dei metadati Protocollo genera un `AuditEvent` in `Domains/Audit`; il `ProtocolService` associa actor e correlation dal contesto API verificato. Il repository salva `protocol.records` e `platform.audit_events` in **un'unica transazione EF/PostgreSQL**: se uno dei due salvataggi fallisce, non deve apparire un record isolato. Eventi senza contenuto documentale. La tabella ha filtri EF per organization e trigger anti-modifica per UPDATE/DELETE/TRUNCATE; non protegge da DBA superuser né offre prova crittografica, retention o endpoint di consultazione. ADR 0006.

## Confine trust OIDC (ADR 0007)

`AuthenticationConfiguration` è valutata all'avvio e fallisce chiusa. Solo Development/Testing possono scegliere `DevelopmentJwt` con HS256 locale; la Production richiede `Oidc`, Authority HTTPS e Audience. `JwtBearer` verifica access token RS256 tramite metadati OIDC e chiavi JWKS (con refresh in caso di rotazione chiavi). `sub` e `organization_id` restano claim validati dal provider; i ruoli sono ricavati dalle membership attive nel database. Il binding identity provider/organization in un onboarding amministrato non è ancora presente: issue #2 ancora aperta. Non esistono sessioni/login frontend o federazione SPID/CIE.

## Moduli gestiti da Admin Comune (ADR 0009)

`ModuleAdministrationService` è un use case del Core: valida il nome del modulo installato e costruisce l'audit usando l'actor del JWT validato. `ModuleAdministrationRepository` usa EF scoped per organization; aggiorna `platform.organization_modules` e crea `platform.audit_events` in un'unica transazione PostgreSQL. La policy `Admin` è verificata dall'handler che controlla le membership del DB, oltre allo stato operativo del Comune. La SPA React espone l'area amministrativa soltanto ad Admin e rilegge il context server dopo ogni modifica; menu e API riflettono il nuovo flag. Eventuali modifiche da altri operatori richiedono un refresh; la gestione concorrenza distribuita e le dipendenze tra moduli sono future attività dell'epica #3.

## Protezioni HTTP incrementali (ADR 0010)

Il middleware di header opera **prima** di autenticazione e rifiuti, così che 401/403/429 ricevano le intestazioni di sicurezza. Il rate limiter globale ASP.NET Core è inserito soltanto nel ramo `/api`, **dopo** la validazione JWT e **prima** delle policy autorizzative: può partizionare richieste valide per Comune/operatore senza fidarsi dei claim prima della validazione. Il traffico anonimo è per IP socket. Health e PWA non sono soggetti a quota. Finestra e limite sono configurabili e validati all'avvio, nessuna infrastruttura distribuita aggiuntiva (vedere ADR 0010 e #15).

## PostgreSQL: role runtime vs owner delle migrazioni (ADR 0011)

La connessione `ConnectionStrings__Default` per l'API di **produzione** viene provisionata dal Terraform con `comuni_app_runtime`, un login PostgreSQL non owner. Il provisioning SQL esplicito avviene **dopo** le migrazioni EF applicate dal ruolo amministrativo, prima del rollout app. Gli adapter EF continuano a usare un'unica istanza logica di PostgreSQL e la stessa API; la barriera dei privilegi DB riduce l'impatto di un errore applicativo e la RLS transaction-local dell'ADR 0012 filtra le righe sotto l'account runtime non owner. La GUC unsigned dell'ADR 0012 è stata sostituita dalle asserzioni HMAC dell'ADR 0013; vedere #5/#6 per security review e migrazione remota.

## RLS e ciclo di vita transazione per richiesta — ADR 0012

Il middleware API legge l'organization **soltanto** dal Principal JWT già validato. In una transazione EF (creata dopo l'autenticazione, prima delle policy) esegue il comando parametrizzato `set_config('comuni.organization_id', tenant, true)`: il valore è `SET LOCAL`, visibile solo nella transazione che contiene le query EF. Autorizzazione, query del Core/Protocollo e scritture audit partecipano alla **stessa** transazione; i repository evitano nested transaction e mantengono commit atomico se invocati fuori dall'HTTP. Le richieste negate non eseguono commit. Cinque tabelle sono sotto RLS; `platform.audit_events` rimane INSERT-only per l'account runtime. Lo scope e il ciclo di vita del pool sono testati con SQL diretto su PostgreSQL 17. Il bypass owner/superuser e la GUC custom modificabile impediscono di presentare questo meccanismo come confine inviolabile sotto SQL injection: la #5 rimane aperta.

## Verifica RLS delle prove firmate (ADR 0013)

Il ruolo applicativo condiviso non firma asserzioni tenant: la singola API .NET le firma con HMAC-SHA256, ottenendo la chiave dal Key Vault. La transazione salva solo la prova firmata in `comuni.tenant_assertion`. Le policy RLS chiamano la funzione PostgreSQL `platform.verified_tenant_id()` `SECURITY DEFINER`, la quale legge la chiave privata dalla tabella `tenant_proof_secret` (non accessibile a `comuni_app_runtime`), verifica HMAC e scadenza, poi restituisce UUID o NULL. Il solo cambio di `comuni.organization_id` non modifica più l'identità. Nessun nuovo servizio, database o frontend: migrazione 0006, bootstrap del segreto condiviso e policy SQL aggiornate. Rimangono i rischi di un processo API compromesso, riuso di assertion catturate, superuser e disponibilità durante la rotazione.

## Boundary Key Vault / Terraform per la HMAC del tenant (ADR 0015)

La chiave HMAC viene creata e ruotata esclusivamente mediante un workflow operativo esterno, approvato: **Terraform non legge né scrive il valore** e fornisce a Container Apps solo un riferimento versionless al secret. Il `removed` block con `destroy=false` tutela le installazioni che precedentemente avevano il secret nello state. La CI impedisce regressioni del contratto e verifica il preflight con metadata-only. L'ordine Key Vault → DB staging → nuova revisione API → verifica → revoca non è ancora orchestrato né collaudato in Azure. Vedere #19 e #6.

## Pinning del secret HMAC RLS in Container Apps — ADR 0016

Il deploy usa una **versioned Key Vault URI** nella secret reference di Azure Container Apps, senza esporre la chiave nella configurazione Terraform. La coppia `tenant_proof_key_id` (ID logico nel verifier PostgreSQL) e `tenant_proof_secret_version` (versione immutabile della risorsa Key Vault) appartiene al piano di rilascio. Prima di plan/apply un controllo `az keyvault secret list-versions` verifica solo enabled per quella versione; il valore è risolto esclusivamente dalla managed identity applicativa. La CI non testa un deployment live e `revision_mode Single` non supporta una fase di validazione parallela delle nuove repliche: vedere #19 e #6.

## Canary staging di revisioni Container Apps (ADR 0017)

La stessa singola Container App API/React passa alla modalità `Multiple` con revision suffix immutabile per commit e **nessun inoltro automatico del traffico pubblico alla latest**. Lo stable revision suffix è input esplicito e la secret HMAC precedente conserva il proprio nome/Key Vault version; la candidata usa un nome nuovo di app-scoped secret e una versione pin distinta. Un gate Python su Terraform plan JSON controlla le modifiche ammesse prima di apply, per evitare che Terraform alteri la stable o altre risorse critiche. La parte di *promotion* e relativi smoke test non è implementata: #19/#6.

## Gate metadata-only dopo lo staging ACA (ADR 0018)

Il workflow approvato di release conserva il blocco anti-distruzione di Terraform e, dopo apply, verifica in Azure le revisioni reali senza alterare il 100%/0% del traffico. Il verificatore legge stato/routing/identità configurata con Azure CLI, mai valori Key Vault, e controlla immagine SHA + key ID/secret reference della candidata. La verifica è uno step obbligatorio prima di pianificare smoke HTTP/RLS e promozione, che restano fuori scope. Un fallimento non implica rollback automatico, dato che lo stage deve essere già a 0% di traffico.

## Canary label e smoke read-only su candidata (ADR 0019)

La regola ACA del template candidato pesa **0%** ma ottiene `label = candidate_revision_suffix`, esponendo un FQDN di revisione distinto dall'URL stabile dell'app. Il piano Terraform e il verifier live verificano il binding; la label non è un'API diversa né un nuovo servizio. Un tool di smoke read-only permette, quando un IdP reale sarà configurato, di interrogare **la stessa API** tramite la label con due token OIDC per due Comuni sintetici, verificando autorizzazione e accesso ai metadati Protocollo. Nessun token è incorporato nell'immagine o nella pipeline CI, e lo smoke non promuove la candidata. #19/#6 conservano il controllo di promozione, rollback e collaudo Azure.

## Client browser PKCE e API unica (ADR 0020)

Un **solo** frontend React effettua OAuth2 Authorization Code + PKCE S256 verso un provider OIDC configurato dinamicamente dall'unica API ASP.NET (`GET /api/v1/auth/browser`). In `Production` la UI **non mostra** il campo JWT manuale; la API continua a usare `JwtBearer` RS256/JWKS e le membership PostgreSQL, senza nuova app, servizio o database. Stato PKCE temporaneo/sessionStorage, access token in RAM (nessun refresh token); callback ripulita prima dello scambio. L'issuer reale deve essere registrato esternamente e il browser client deve poter usare CORS sul token endpoint. Il modello browser conserva rischio XSS; un BFF/cookie HttpOnly nella stessa API rimane opzione preferibile da valutare prima del go-live.

## Provisioning amministrativo membership Reader/Officer (ADR 0021)

Nel Core `MembershipAdministrationService` implementa la validazione di tenant/ruolo/soggetto e l'attribuzione server-side degli eventi di audit; `MembershipAdministrationRepository` effettua UPSERT/UPDATE parametrizzati su `platform.organization_memberships` e insert append-only `platform.audit_events` nella stessa transazione PostgreSQL (anche quando la transazione è aperta dal middleware JWT/RLS). L'API unica pubblica `GET/PUT /api/v1/admin/memberships` dietro policy Admin, e lo stesso frontend React ospita la gestione nell'area Amministrazione. L'IdP non viene mutato né invocato. La migrazione 0008 aggiunge policy RLS restrittive per proibire all'account runtime la scrittura di ruoli Admin anche in presenza di SQL injection; il ruolo runtime dispone di grant colonnari soltanto. Gestione Admin/last-admin e identity binding sono incrementi distinti (#2/#3/#10).

## Membership vincolata a issuer OIDC (ADR 0022)

Il confine auth separa due modalità. `Oidc` richiede che `issuer + subject + organization_id` provenienti dal Principal JWT validato corrispondano alla membership persistita con `identity_issuer` non-NULL (migrazione 0009). `DevelopmentJwt` consente per demo le righe senza issuer, ma non si può attivare in Production. `OrganizationRoleHandler` e `/api/v1/context` interrogano la stessa `OrganizationMembershipStore` con `iss` autenticato; la policy PostgreSQL RLS rimane tenant-scoped. Il service Admin passa l'issuer del JWT verificato al repository, e il repository usa un INSERT con binding immutabile e verifica di conflitto su righe legacy; spostare una riga tra provider richiede autorizzazione operativa separata. La UI mostra issuer in sola lettura; una sola API, un React e lo stesso PostgreSQL.

## Boundary iniziale per l'Admin OIDC (ADR 0025 / #31)

Quando non esiste ancora un Admin di Comune, non viene introdotta una scorciatoia API/SPA né un secondo identity service. Un runner owner con change ticket verificato fuori dal sistema aggiunge **una sola membership Admin** con `identity_issuer`+`subject` esatti e audit atomico nello stesso PostgreSQL, serializzando la riga organization. Il login runtime continua a non poter scrivere Admin. Ogni operazione successiva passa per la stessa API e membership RLS esistenti; il provider esterno e la console Superadmin rimangono attività distinte.


## Creazione isolata dei Comuni — bootstrap offline (ADR 0026 / #32)

Il Core non espone ancora la creazione cross-tenant all'API: un comando `psql` eseguibile **solo con owner dello schema** crea una organization e un flag `protocol=FALSE` con un evento di audit in un'unica transazione, acquisendo un advisory lock per UUID. Le membership sono vuote; il contesto tenant e i permessi continuano a essere imposti da JWT verificato, membership PostgreSQL, RLS firmata e stato organization, non da un parametro client. Il bootstrap del primo Admin OIDC (ADR 0025) è **una operazione distinta** subordinata alla verifica esterna della persona. La console Superadmin, l'approvazione real-time e il lifecycle completo di Comuni rimangono #3/#10; una sola API .NET, un React e un PostgreSQL.


## Lifecycle sicurezza Comune — stato sospeso (#33 / ADR 0027)

Il Core dispone già di `is_suspended` e del controllo authorization server-side per richiesta (ADR 0008), ma l'operatore in possesso del change approvato deve applicare le transizioni **solo con un runner owner PostgreSQL offline**. Lo script gestisce un singolo tenant esistente e scrive `platform.organization.suspended` o `platform.organization.reactivated` atomico e una sola volta per cambio di stato, serializzando `SELECT FOR UPDATE`. Non introduce una seconda API, un frontend separato, tabelle nuove o un ruolo multi-tenant accessibile dalla SPA; l'Admin comunale non può gestire l'accesso degli altri Comuni. I flag moduli e le membership rimangono invariati. La console Superadmin e la gestione platform RBAC, revoca OIDC e audit regolamentare richiedono incrementi successivi nelle epiche #3/#4/#10.


## Confine OIDC identità piattaforma, senza impersonificazione (#34 / ADR 0028)

Una nuova policy `PlatformOperator` è **separata** dalle policy `Read/Write/Admin` basate su organization. La piattaforma accetta un JWT OIDC RS256 con `iss`+`sub` validi e senza alcun `organization_id` solo per una risposta minimale `GET /api/v1/platform/session`. Lo stato attivo si legge tramite funzione booleana PostgreSQL `SECURITY DEFINER`, non da un claim JWT o dalle membership comunali. L'app runtime non ha permessi di lettura del roster platform. Token comunali con organization claim non passano la policy platform; token platform non passano i vincoli tenant. **Nessuna operazione cross-tenant è esposta** in questa slice. L'area UI Superadmin, l'approvazione degli operatori, il catalogo globale e l'impersonificazione sono ancora requisiti aperti.


## Operator lifecycle e audit globale — confine platform (#35 / ADR 0029)

Dopo la verifica OIDC del `PlatformOperatorHandler` (ADR 0028), lo stato di un Superadmin è una riga persistita `platform.platform_operators` disgiunta da membership tenant. La sola mutation consentita in questa slice viene dall'owner PostgreSQL tramite `scripts/postgres/manage-platform-operator.sql`, **non** da SPA, Admin Comune o API. Un lock advisory su `iss+sub` protegge il primo inserimento, poi una row lock le revoche/riattivazioni; ogni transizione scrive **nello stesso commit** l'evento `platform.operator.enrolled/revoked/reactivated` nel nuovo audit globale `platform.platform_operator_audit_events` privo di `organization_id`. La correlazione usa un `operator_id` UUID casuale non ricavabile con un semplice dizionario dal subject. I trigger PostgreSQL impediscono UPDATE/DELETE/TRUNCATE ordinari, ma il proprietario dello schema resta amministrativamente privilegiato. L'unica API, l'unica React PWA e l'unico PostgreSQL non cambiano. La futura console Superadmin richiede altro lavoro per RBAC, audit delle consultazioni, approvazioni reali e impersonificazione.

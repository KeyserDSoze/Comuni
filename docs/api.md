# API REST — primo incremento

Base path: `/api/v1`; OpenAPI: `/openapi/v1.json` (generato da ASP.NET Core).

## Autenticazione
 `Authorization: Bearer <JWT>`. Solo in Development/Testing è disponibile HS256 locale (`DevelopmentJwt`); in Production l'API accetta esclusivamente access token RS256 validati da un issuer OIDC HTTPS tramite metadata/JWKS (ADR 0007). `organization_id` = GUID e `sub` = identità esterna. **La policy legge i ruoli effettivi (`Admin`, `Officer`, `Reader`) da `platform.organization_memberships`, solo membership attive**. Il claim `role`, anche se presente nel JWT, non conferisce privilegi. L'organization deriva **solo** dall'identità verificata. La validazione OIDC è implementata, ma l'emissione/ottenimento reale del token, login frontend, onboarding e ruoli amministrativi restano da sviluppare (ADR 0005/0007 e issue #2).

| Metodo | Endpoint | Ruoli | Note |
| --- | --- | --- | --- |
| GET | `/health/live` | pubblico | liveness |
| GET | `/health/ready` | pubblico | verifica DB |
| GET | `/api/v1/context` | tutti | organizationName, roles, modules attivi |
| GET | `/api/v1/protocol/records` | tutti | ultimi 100 metadati della propria org, solo se protocol attivo |
| POST | `/api/v1/protocol/records` | Admin/Officer | body `{"subject":"..."}`; ritorna 201, solo se protocol attivo |

Tutti gli endpoint protetti rifiutano token assente/non valido (401), membership assente/disabilitata o ruolo non autorizzato (403) o organization_id non valido (403). Una organization assente o sospesa riceve 403 per tutte le API protette, indipendentemente da JWT e membership (ADR 0008); health/live e health/ready restano anonimi. Il modulo inattivo restituisce 403. Il body di registrazione accetta subject non vuoto e massimo 250 caratteri. Non include documenti digitali, segnature, registri legali né protocollazione a norma.

## Dati
PostgreSQL: `platform.organizations` (colonna `is_suspended`, default false), `platform.organization_modules`, `platform.organization_memberships`, `protocol.records`. Nelle tabelle tenant-owned è presente `organization_id`; EF impone un filtro per organization in lettura e una guardia sulle scritture. Le migrazioni versionate sono in `Infrastructures/Persistence/Migrations`.

## Audit (issue #11)

La `POST /api/v1/protocol/records` completata con 201 registra anche un evento interno `protocol.record.created` in `platform.audit_events`, **nella stessa transazione**. Identità (`sub`) e correlation provengono dal server, non da campi request o header arbitrari. Le richieste 401/403/validation error non registrano documenti e non creano questo evento. Nessun endpoint pubblico di lettura o modifica del registro audit è previsto in questa slice. Il payload audit non include oggetto del documento o token.

## Amministrazione moduli per Comune (issue #13)

Gli endpoint amministrativi richiedono una **membership Admin attiva** nel PostgreSQL della organization derivata esclusivamente dal JWT validato:

| Metodo | Endpoint | Ruoli | Risultato |
| --- | --- | --- | --- |
| GET | `/api/v1/admin/modules` | Admin | Lista degli stati dei moduli installati del proprio Comune (per ora `protocol`) |
| PUT | `/api/v1/admin/modules/protocol` | Admin | Body `{"enabled":true|false}`, stato aggiornato in PostgreSQL e restituito |

Anonimo: 401. Reader/Officer o organization sospesa: 403. Modulo non riconosciuto: 404. Campo `enabled` assente: 400. Il corpo non può scegliere il Comune da aggiornare; un eventuale `organizationId` inviato dal client è ignorato. Il cambio effettivo produce un evento audit `platform.module.protocol.enabled` o `platform.module.protocol.disabled` **nella stessa transazione**; una ripetizione identica è idempotente e non aggiunge audit. L'abilitazione è controllata lato backend in ogni use case: l'endpoint Protocollo restituisce 403 dopo la disattivazione.

## Hardening HTTP (#15)

Una finestra fissa in-memory per replica limita soltanto gli endpoint `/api`: default **120 richieste per 60 secondi** per identità JWT validata (`organization_id` + `sub`) o IP della connessione per richieste anonime. Superata la quota, risposta `429 Too Many Requests` con `Retry-After` (secondi, valore conservativo). Non fare retry aggressivo. `/health/live`, `/health/ready` e asset statici PWA non sono limitati. Non fidarsi di `X-Forwarded-For` fornito dai client.

API incluse risposte 401/403/429 sono `Cache-Control: no-store`. Gli header di protezione browser si applicano a tutte le risposte. Questo non sostituisce WAF/edge e quote centralizzate per deployment multipli.

## Configurazione login browser OIDC (slice #26 di #2)

| Metodo | Endpoint | Autenticazione | Risultato |
| --- | --- | --- | --- |
| GET | `/api/v1/auth/browser` | pubblico | `mode`, `enabled` e, solo se abilitato, metadati pubblici del client OAuth (issuer, clientId, authorizationEndpoint, tokenEndpoint, scope) |

La risposta **non** contiene token, client secret, organization_id, ruoli o credenziali. Con `DevelopmentJwt` (solo Development/Testing) restituisce `{"mode":"DevelopmentJwt","enabled":false,...}` e il frontend mostra il form JWT tecnico. In `Oidc` senza configurazione browser completa restituisce `{"mode":"Oidc","enabled":false,...}`: il form JWT è **nascosto**, e il login è esplicitamente non configurato. Quando è abilitato, il browser inizia un Authorization Code flow con PKCE `S256`, scambia il codice **direttamente** con il token endpoint dell'IdP per un `access_token` e lo usa sulle API esistenti `Authorization: Bearer`. Il backend rimane l'unica fonte di ruoli e dell'organization.

Per attivare un client browser: `Authentication:BrowserClientId`, `Authentication:BrowserAuthorizationEndpoint`, `Authentication:BrowserTokenEndpoint`, `Authentication:BrowserScope` devono essere **tutti** valorizzati e gli endpoint devono essere HTTPS sullo stesso host di `Authentication:Authority`; `BrowserScope` deve includere `openid` e uno scope API delegato senza `offline_access`. Non esiste né è accettato alcun `Authentication:BrowserClientSecret`. La risposta OAuth non costituisce autorizzazione: la API valida ancora JWT RS256 (issuer, aud, firma, exp) e membership PostgreSQL in ogni richiesta. L'endpoint pubblico è soggetto al rate limiter della API.

## Gestione membership comunali — Reader/Officer (ADR 0021, #27)

Gli endpoint di gestione sono accessibili **solo** a una membership `Admin` **attiva nel database** del Comune estratto dal JWT verificato; lo stato di sospensione dell'ente rimane un blocco per tutta l'API. Il ruolo JWT non conferisce autorizzazioni.

| Metodo | Endpoint | Accesso | Risposta |
| --- | --- | --- | --- |
| `GET` | `/api/v1/admin/memberships` | Admin Comune | `[{ "subject": "idp-sub", "role": "Reader", "enabled": true }, ...]`, include Admin in sola lettura |
| `PUT` | `/api/v1/admin/memberships/Reader` | Admin Comune | `{"subject":"idp-sub","enabled":true/false}` |
| `PUT` | `/api/v1/admin/memberships/Officer` | Admin Comune | stesso contratto |

Il `PUT` attiva/crea o disattiva la membership per il `sub` **esatto, case-sensitive** fornito dal gestore IdP. I cambiamenti sono idempotenti; disattivare una membership assente restituisce `404`, riattivare una esistente aggiorna lo stato. Input mancante/malformato e ruoli `Admin`, `Superadmin` o arbitrari restituiscono `400`; anonimo `401`, Reader/Officer senza Admin nel DB `403`. Il body non può scegliere `organization_id` o `actor`: anche se tali proprietà sono presenti, non cambiano il contesto derivato dal JWT. Subject 1–160 caratteri, senza controlli o spazi esterni.

L'Admin **non può assegnare, disattivare o riattivare il ruolo Admin** tramite questi endpoint. La gestione del primo/ultimo amministratore è un workflow separato da progettare con elevazione, verifica IdP e audit (epiche #3/#10). Il comando assegna **solo una riga di membership**: non crea una persona nel provider esterno e **non verifica ancora l'esistenza del sub**; non usare per concedere privilegi a identità non verificate.

## Associazione membership OIDC a issuer e sub (#28 / ADR 0022)

In produzione `Authentication:Mode=Oidc` ogni operazione protetta richiede un JWT access valido con `iss` e `sub`, un Comune `organization_id` verificato e una membership DB `organization_id + subject + identity_issuer` **esattamente corrispondente**, attiva e autorizzata. Le righe legacy con `identity_issuer=NULL` non conferiscono diritti OIDC. In `DevelopmentJwt` le membership tecniche senza issuer restano utilizzabili per i test locali, senza introdurre una scorciatoia in produzione.

- `GET /api/v1/admin/memberships` include ora il campo pubblico `issuer: string|null` per ciascun ruolo; l'Admin lo vede in sola lettura.
- `PUT /api/v1/admin/memberships/{Reader|Officer}` conserva `{"subject":"...", "enabled":true|false}`. L'issuer **non** è ammesso come selettore utente: è ricavato dal claim `iss` del JWT **già verificato** dell'Admin. Proprietà extra nel JSON, incluso `issuer` o `identityIssuer`, non modificano il binding.
- Se esiste già una riga `(organization_id, subject, role)` con issuer diverso o NULL in modalità OIDC, il PUT **rifiuta il riassociamento** con `409 Conflict` (code `identity_issuer_mismatch`); la procedura di verifica del provider/migrazione deve essere autorizzata separatamente. No-op con lo stesso issuer non aggiunge audit.

La PK attuale non permette che un medesimo `subject` abbia la stessa membership `role` contemporaneamente presso due issuer nello stesso Comune. Il repository supporta **un solo provider fidato** per l'API; nessun alias/multi-provider o automatismo di trasferimento autorizzazioni è disponibile.

## Provisioning primo Admin (nessuna API, #31)

Il primo Admin OIDC non è assegnabile da HTTP, né dal menu Amministrazione, né dagli endpoint Reader/Officer. Esiste solo uno script owner PostgreSQL offline `scripts/postgres/bootstrap-initial-admin.sql`, con issuer/sub attestati esternamente, organization già attiva e vuota di Admin, approvazione change separata e audit atomico. Le policy API per Reader/Officer, il JWT OIDC e il divieto runtime di assegnare Admin restano invariati. Vedere ADR 0025 e `docs/deployment.md` per prerequisiti e rischio di una membership illegittima.


## Onboarding organization (nessun endpoint HTTP, #32)

La creazione di una nuova organization **non è** accessibile agli Admin comunali né al browser. `scripts/postgres/provision-organization.sql` è un'operazione owner-only offline (ADR 0026) con UUID e nome approvati esternamente; inserisce `platform.organizations`, il flag `protocol` **disabled** e l'audit `platform.organization.created` atomicamente, senza creare membership. Un nuovo Comune resta 403 per tutte le route tenant protette finché non è predisposto un primo Admin OIDC tramite il diverso strumento owner (#31 / ADR 0025), e il Protocollo richiede successiva attivazione Admin. Nessun endpoint Superadmin o tenant override è stato aggiunto.


## Stato sospensione Comune — effetto API (#33, ADR 0008/0027)

Non è stato aggiunto alcun endpoint HTTP di sospensione o riattivazione: questa operazione è accessibile **solo** allo schema owner PostgreSQL tramite `scripts/postgres/set-organization-suspension.sql` con autorizzazione esterna, change ticket e audit transazionale. Ogni **nuova** richiesta tenant protetta a un Comune sospeso restituisce 403 (anche Admin/Protocollo e anche con un JWT firmato già valido), indipendentemente dai suoi moduli o membership. `/health/live` e `/health/ready` rimangono endpoint di monitoraggio non tenant. La riattivazione non modifica i moduli, i ruoli o i token: restituisce l'accesso soltanto alle membership ancora attive, sui moduli ancora abilitati. Non equivale a revoca OIDC o arresto di richieste in volo.


## Identity platform-only (slice Superadmin, #34 / ADR 0028)

| Metodo | Endpoint | Policy | Risultato |
| --- | --- | --- | --- |
| `GET` | `/api/v1/platform/session` | `PlatformOperator` | `{"role":"Superadmin"}` **solo per il proprio access token OIDC platform** |

L'endpoint è **sola lettura** e non restituisce utenti o enti: **non** esistono ancora `POST/PUT/DELETE`, elenco Comuni, toggle moduli cross-tenant o impersonificazione. Risposte: nessun/invalid JWT **401**; JWT OIDC valido ma senza attivazione `iss+sub` in `platform.platform_operators`, con issuer errato, membership solo comunale, record disabilitato oppure contenente `organization_id`: **403**. `DevelopmentJwt` non può conferire privilegi platform neppure con `role=Superadmin`. I claim `role` e `groups` non attribuiscono privilegi; l'ID del tenant non può essere selezionato tramite body/query/header.

Il token platform **privo del claim `organization_id`** non soddisfa nessuna policy comunale: `/context`, `/admin/*` e `/protocol/*` continuano a rispondere 403. L'accesso 200 a questa rotta non conferisce permessi applicativi oltre alla lettura del proprio stato. Un IdP reale, l'onboarding/approval e i permessi Superadmin granulari rimangono lavori futuri.


## Enrollment e revoca degli operatori Superadmin (#35 / ADR 0029)

Nessun nuovo endpoint HTTP. La concessione/revoca di `platform.platform_operators` è una procedura **offline con ruolo proprietario PostgreSQL** (`scripts/postgres/manage-platform-operator.sql`), subordinata a verifica `iss+sub` presso l'IdP affidabile, MFA e change approvato da un secondo operatore **all'esterno del software**. Un'assegnazione non si deduce da `role=Superadmin` nel JWT o dal ruolo Admin comunale. `GET /api/v1/platform/session` continua a restituire soltanto `{"role":"Superadmin"}` per coppie OIDC esatte e attive, senza accesso cross-tenant: dopo il `revoke` la **richiesta successiva** riceve 403 con lo stesso JWT validato. `PUT/POST/DELETE /api/v1/platform/*` non sono introdotti. La tabella audit globale append-only `platform.platform_operator_audit_events` non ha `organization_id`, non è leggibile dal runtime ed è priva di dati identificativi in chiaro; non esiste API di consultazione/audit globale. Vedere ADR 0029 e `docs/deployment.md`.


## Frontend Superadmin di sola lettura (#36 / ADR 0030)

L'unica React PWA utilizza **l'endpoint esistente** `GET /api/v1/platform/session`; nessuna nuova API o permesso di elenco/CRUD cross-Comune è stato introdotto. Con il browser OIDC Authorization Code + PKCE, il token API in memoria viene verificato **indipendentemente** per contesto comunale (`GET /api/v1/context`) e sessione piattaforma. Per visualizzare il menu e la pagina `/platform` è indispensabile una risposta piattaforma **200, esattamente `{"role":"Superadmin"}`**, e il contesto comunale negato. La sessione piattaforma non usa `organization_id` in URL/body/storage e non legge dati comunali. Le risposte 401/403, errori, payload con proprietà extra, esiti tenant/platform ambigui e token DeveloperJwt non permettono l'accesso alla vista.

Il percorso `/platform` è una navigazione **client-side**; un deep link non ignora la policy backend. Prima di navigare e su focus della pagina viene riverificata la sessione, per nascondere l'area alla revoca. Logout e refresh richiedono un nuovo login OIDC; il ruolo visualizzato non è un'autorizzazione a consultare gli enti. Vedere ADR 0030.


## Superadmin: inventario Comuni a metadati minimi (#37 / ADR 0031)

`GET /api/v1/platform/organizations?limit=10&after=<uuid>` — unica API .NET 10, **sola lettura**. È protetta dalla policy **`PlatformOperator`** già verificata su RS256/JWKS e sul database (issuer+sub attivi, senza `organization_id`). In aggiunta l'inventario richiede `PlatformInventory:Enabled=true` e la connessione **dedicata** `comuni_platform_reader`; per default è disabilitato (503 per un operatore autorizzato, 401/403 per token non autorizzati). Non esiste alcun fallback alla connessione comunale, alla credenziale owner o alla modalità DevelopmentJwt.

Risposta `200`:

```json
{
  "organizations": [
    {
      "id": "11111111-1111-1111-1111-111111111111",
      "name": "Comune di esempio",
      "isSuspended": false,
      "protocolEnabled": false,
      "lifecycleStatus": "active"
    }
  ],
  "nextCursor": null
}
```

La lista è ordinata per UUID crescente; `limit` predefinito 10, ammesso **1–25**. `after` è facoltativo, UUID non nullo nel formato canonico; `nextCursor` è l'ID dell'ultima riga restituita solo se esiste un'altra pagina. Niente `count` né ricerca nome o parametri di tenant. Query sconosciute/duplicate, limit fuori intervallo e cursor malformato danno **400**, senza leggere enti o inserire audit. Token anonimi/errati danno **401/403**. L'endpoint non legge né restituisce utenti, ruoli, documenti, tributi, operatori globali o dati sensibili. Il backend scrive un evento append-only `platform.organizations.listed` per ogni pagina riuscita, con ID opaco dell'operatore e correlation random, nella stessa transazione della SELECT. La UI in `/platform` mostra una tabella e un pulsante per le pagine successive, ma è **solo presentazione** e non attribuisce diritti.

Non sono disponibili endpoint per creazione, modifica, sospensione/riattivazione o impersonificazione. Vedere ADR 0031, `docs/deployment.md` e `docs/security.md`.


## Admin Comune: ultimi eventi di audit in sola lettura (#41 / ADR 0035)

`GET /api/v1/admin/audit` è accessibile **solo con membership Admin attiva nel DB** del Comune derivato dal JWT verificato; l'organization sospesa, Reader/Officer, Superadmin privo di tenant o JWT con ruolo Admin contraffatto restano 401/403. La risposta è **un array JSON** con massimo **25 eventi**, ordinati per `occurredAt DESC, id DESC`, con *esattamente* quattro campi:

```json
[
  {
    "id": "11111111-1111-1111-1111-111111111111",
    "action": "platform.module.protocol.disabled",
    "resourceType": "platform.module",
    "occurredAt": "2026-11-16T09:00:00Z"
  }
]
```

Sono **esclusi** `actorSubject` (identità IdP), `correlationId`, `resourceId`, `organizationId`, testo Protocollo, payload e ogni informazione dell'audit globale. **Qualsiasi query string** (anche `limit`, `organizationId`, `subject`, `after`) restituisce 400: non sono previsti filtro, offset, export o consultazione cross-organization. Il controllo Server Admin, l'EF query filter e la policy RLS con assertion HMAC firmata sono obbligatori. Le normali API di modifica rimangono invariate; l'endpoint non modifica dati di business; dal completamento della #42 **registra atomicamente ogni consultazione riuscita** (ADR 0036). Vedere ADR 0035. La nuova sezione `Attività recenti del Comune` è integrata in **Amministrazione** nella stessa React PWA, solo per Admin, con traduzione IT/EN ed error/retry.

## #42 — Tracciamento delle consultazioni del registro comunale (ADR 0036)

Ogni `GET /api/v1/admin/audit` autorizzato e riuscito con HTTP 200 registra nella **stessa transazione PostgreSQL** della lettura un evento `platform.audit.consulted` (`resourceType=platform.audit`, `resourceId=organizationId`). Actor e correlation sono costruiti da JWT verificato e contesto del server; non da header o query forniti dal client. La risposta conserva al massimo 25 eventi ed **esattamente** `id/action/resourceType/occurredAt`. La consultazione corrente non compare nella risposta in corso ma può comparire alla successiva. Query arbitrarie 400 e accessi 401/403 **non** generano eventi di consultazione. Nessun export, impersonificazione o accesso globale, nessun nuovo ruolo DB. Vedere ADR 0036; la funzione non soddisfa requisiti legali di conservazione o retention.


## Registrazione di un nuovo Comune — owner-only, nessuna API HTTP (#43 / ADR 0037)

La creazione iniziale di una organization avviene **esclusivamente** mediante `scripts/postgres/register-organization.sql` eseguito offline dal proprietario delle tabelle Core, previa verifica indipendente di identità e mandato del Comune. **Non esiste** `POST /api/v1/platform/organizations` o un endpoint CRUD di creazione accessibile via JWT Superadmin o Admin comunale. L'API continua a negare l'accesso a qualsiasi organization priva di membership attiva (403), anche se una registration owner l'ha inserita nel database. La nuova organization nasce con `is_suspended=false`, una riga catalogo `protocol.enabled=false`, **zero membership** e un evento append-only `platform.organization.registered`. Il primo Admin OIDC può essere aggiunto **solo dopo** con `bootstrap-initial-admin.sql` (#31) e approvazione distinta; il modulo Protocollo resta disabilitato fino a un'esplicita operazione Admin autorizzata. Le stringhe ticket/reviewer non sono esposte in alcuna nuova API. Non dichiarare questa fase come onboarding legale: il lifecycle tecnico è esteso dalla successiva #44/ADR 0038, mentre il workflow autorizzativo completo resta aperto.


## #44 — Stati espliciti created / active / suspended (ADR 0038)

Il lifecycle della organization è governato dal backend PostgreSQL e **non** da parametri del browser. Il nuovo `is_activated` produce tre stati validi: `created` = `is_activated=false,is_suspended=false`; `active` = `true,false`; `suspended` = `true,true`. Tutte le route tenant-scoped (`/context`, Protocollo, amministrazione moduli/membership/audit) richiedono **is_activated=true AND is_suspended=false**, oltre a membership e JWT validati: un Comune `created` è **403 anche dopo il bootstrap del primo Admin OIDC**. La nuova migration 0013 assegna `is_activated=true` ai Comuni legacy per non interromperne i permessi già esistenti.

Nessun nuovo endpoint HTTP di onboarding/activation: `register-organization.sql` crea `created`; `bootstrap-initial-admin.sql` associa issuer+sub OIDC come passo separato; `activate-organization.sql` è owner-only e può marcare `active` dopo approvazione esterna. `set-organization-suspension.sql` non può usare `reactivate` su pending. Dopo activation nessun modulo viene acceso automaticamente. Con la #45/ADR 0039 l'inventario Superadmin include il quinto campo read-only `lifecycleStatus` (`created`/`active`/`suspended`). `isSuspended=true` rimane compatibilmente **non operativo** per `created` oppure `suspended`, mentre la PWA mostra *Creato / Attivo / Sospeso* (Created / Active / Suspended). Nessun accesso aggiuntivo ai dati dei Comuni. Non aggiungere un client selector `organizationId` per scavalcare il gate.

## #45 — Contratto inventory lifecycleStatus (ADR 0039)

La vista protetta espone cinque colonne nell'ordine `id,name,is_suspended,protocol_enabled,lifecycle_status`. L'API restituisce cinque campi JSON per organization e mantiene `isSuspended` con la semantica precedente: `false` solo per `active`; `true` per `created` e `suspended`. Il nuovo `lifecycleStatus` è un enum **read-only** derivato da PostgreSQL, non un parametro mutabile dal client. Il limite 1–25, il cursor UUID, i 401/403/503, la query whitelist, i permessi SQL separati e l'audit restano invariati. Il payload è additivo, ma i vecchi client che validano **esattamente quattro chiavi** non lo accettano: effettuare deploy API+frontend coordinato e invalidazione cache **prima** di abilitare il flag (default OFF), senza promettere compatibilità con SPA cached o consumer esterni. Rollback dell'API tramite feature OFF e change owner-reviewed; dettagli in `docs/deployment.md`.

## Aggiunta di un secondo Admin OIDC — nessun endpoint HTTP (#80)

L'operazione `scripts/postgres/enroll-additional-admin.sql` è **owner-only e offline** (ADR 0069), subordinata a change e verifica esterna di issuer+subject; non è invocabile dal browser, da `comuni_app_runtime`, da un normale Admin comunale o da un token Superadmin. Non sono introdotti `POST/PUT/DELETE /api/v1/platform/administrators` né modifiche alle API di membership: `PUT /api/v1/admin/memberships/{role}` continua a gestire **solo Reader/Officer** e un Admin non può assegnare privilegi Admin da sé. La procedura crea, nella stessa transazione, una seconda membership Admin e un evento audit pseudonimo; non tocca il primo Admin e non gestisce revoche/impersonificazione.

## Revoca di un Admin OIDC — solo offline, nessuna nuova API (#81)

La revoca `scripts/postgres/revoke-admin.sql` è consentita soltanto allo schema owner PostgreSQL, previo change verificato esternamente (ADR 0070). Non sono disponibili endpoint HTTP per revocare/riattivare Admin; `PUT /api/v1/admin/memberships/{role}` continua a limitarsi a Reader/Officer. La membership Admin viene soltanto marcata inattiva con audit transazionale, senza modificare il token firmato o emettere un nuovo token. La policy API esistente rivalida membership da PostgreSQL a ogni nuova richiesta: un JWT OIDC ancora valido ma con Admin inattivo riceve 403 per `/api/v1/context` e `/api/v1/admin/*`, mentre gli altri Admin autorizzati conservano l'accesso. L'ultimo Admin attivo non può essere revocato da questa procedura.

## Sostituzione Admin dopo revoca — owner-only, nessun endpoint HTTP (#83)

L'enrollment `scripts/postgres/enroll-additional-admin.sql` (ADR 0071) accetta ora un **nuovo** `issuer+sub` quando il Comune è attivo, permane un altro Admin OIDC attivo e le vecchie revoche owner-only hanno audit coerente ed univoco. È **solo procedura PostgreSQL owner con change a quattro occhi esterno**, non API/browser e non diritto conferito al Superadmin o all'Admin comunale. Non riattiva membership Admin revocate e non permette a `PUT /api/v1/admin/memberships/{role}` di gestire `Admin` (resta Reader/Officer soltanto). Le API `/api/v1/context` e `/api/v1/admin/*` continuano a valutare le membership vere ad ogni nuova richiesta: l'ex Admin riceve 403, il nuovo soggetto con token OIDC valido e binding server-side può ricevere 200.

## Staging emergenziale dell'unico Admin OIDC — nessuna API pubblica (#85)

`scripts/postgres/stage-emergency-admin-replacement.sql` è una **procedura PostgreSQL owner-only offline** per Comune già sospeso con audit precedente; non è invocabile dal frontend o da Superadmin/API. Non altera `is_suspended`, feature flags, token OIDC né RLS: disattiva il solo Admin compromesso, aggiunge una nuova membership Admin e due audit in un'unica transazione, con `issuer+sub` e incident approvati *esternamente*. L'API valida ancora server-side la membership per ogni nuova richiesta, ma il Comune rimane inaccessibile (403) anche al nuovo Admin finché il lifecycle non è riattivato con un diverso change owner. L'identità vecchia rimane 403 anche dopo la riattivazione. Nessun `POST /api/v1/platform/admin-recovery`, grant Admin self-service, impersonificazione o bypass tenant introdotto; runbook e limiti in [ADR 0072](../adr/0072-suspended-sole-admin-emergency-staging.md).

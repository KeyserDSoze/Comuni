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

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

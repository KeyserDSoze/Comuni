# API REST — primo incremento

Base path: `/api/v1`; OpenAPI: `/openapi/v1.json` (generato da ASP.NET Core).

## Autenticazione
`Authorization: Bearer <JWT>`. Firmato HS256, issuer e audience configurati; `organization_id` = GUID e `role` = `Admin`, `Officer` o `Reader`. L'organization deriva **solo** dall'identità verificata. La gestione OIDC dell'utenza reale è una fase successiva (ADR 0004).

| Metodo | Endpoint | Ruoli | Note |
| --- | --- | --- | --- |
| GET | `/health/live` | pubblico | liveness |
| GET | `/health/ready` | pubblico | verifica DB |
| GET | `/api/v1/context` | tutti | organizationName, roles, modules attivi |
| GET | `/api/v1/protocol/records` | tutti | ultimi 100 metadati della propria org, solo se protocol attivo |
| POST | `/api/v1/protocol/records` | Admin/Officer | body `{"subject":"..."}`; ritorna 201, solo se protocol attivo |

Tutti gli endpoint protetti rifiutano token assente/non valido (401), ruolo non autorizzato (403) o organization_id non valido (403). Il modulo inattivo restituisce 403. Il body di registrazione accetta subject non vuoto e massimo 250 caratteri. Non include documenti digitali, segnature, registri legali né protocollazione a norma.

## Dati
PostgreSQL: `platform.organizations`, `platform.organization_modules`, `protocol.records`. Nelle tabelle tenant-owned è presente `organization_id`; EF impone un filtro per organization in lettura e una guardia sulle scritture. Le migrazioni versionate sono in `Infrastructures/Persistence/Migrations`.

# ADR 0002 — Isolamento organization, autorizzazioni, feature flags

- Stato: Accepted
- Data: 2026-11-15

## Decisione
`organization_id` è letto da un claim del JWT **validato**; il client non può scegliere il tenant tramite body/query/header. La policy valida la presenza del GUID. Le query EF per dati tenant-owned hanno filtro globale per organization e i repository esprimono esplicitamente il tenant. `SaveChanges` rifiuta entità di un'altra organization. I moduli sono configurati per Comune in `organization_modules`, verificati sul backend prima di ogni use case. Ruoli: `Admin`, `Officer`, `Reader`. **Amendment ADR 0005:** il JWT contiene solo identità e organization; per le policy `Read`/`Write` i ruoli derivano da membership PostgreSQL attive, non dal claim `role` token. API e UI rispettano le autorizzazioni, ma la sicurezza si applica soltanto sul server.

## Verifiche obbligatorie
Test unitari su invarianti e use case, integrazione PostgreSQL per cross-organization, JWT invalido, 401/403, modulo disabilitato, scrittura fuori tenant. Il filtro EF non esonera da test su query raw SQL, amministrazione e operazioni batch.

## Limiti
Database condiviso: isolamento applicativo, non database-per-tenant. Valutare PostgreSQL RLS come difesa ulteriore dopo analisi di connection pooling e operation context; non considerarlo già attivo.

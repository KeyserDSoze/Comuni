# ADR 0012 — PostgreSQL RLS con contesto tenant transaction-local

- Stato: Accepted, prima implementazione di difesa in profondità (#17, epica #5 ancora aperta)
- Data: 2026-11-15
- Relazione: ADR 0002, 0005, 0006, 0008, 0011
- Fonti tecniche: https://www.postgresql.org/docs/17/ddl-rowsecurity.html ; https://www.postgresql.org/docs/17/sql-createpolicy.html ; https://www.npgsql.org/doc/basic-usage.html

## Problema

I filtri globali EF e le membership PostgreSQL #1 isolano le query previste dall'app, ma fino a #17 una query SQL diretta sotto il ruolo `comuni_app_runtime` poteva leggere tutte le organization. #16 ha ridotto i GRANT senza introdurre filtri per riga.

## Decisione

Abilitiamo tramite migrazione append-only `202611150005_TenantRowLevelSecurity` la **Row-Level Security** su `platform.organizations` (`id`), `platform.organization_modules`, `platform.organization_memberships`, `platform.audit_events` e `protocol.records` (`organization_id`). Per ognuna: policy `USING` e `WITH CHECK` che confrontano il campo tenant con `NULLIF(current_setting('comuni.organization_id', true), '')::uuid`; senza impostazione, SELECT restituisce zero e INSERT/UPDATE non soddisfano le policy. I GRANT DML del ruolo runtime rimangono limitati dall'ADR 0011.

Dopo la validazione JWT, un middleware HTTP per `/api` ottiene il tenant dal Principal autenticato, apre una transazione EF e invoca `set_config('comuni.organization_id', organizationId, true)` **parametrizzato**, equivalente a `SET LOCAL`. Questa transazione include le autorizzazioni `Read/Write/Admin`, le query del dominio e il salvataggio audit; le scritture dei repository non creano nested transaction. Al commit/rollback il valore viene eliminato dal contesto PostgreSQL e il connection pooling non trasferisce il tenant al successivo utente. Richieste senza GUID autenticato non ricevono un contesto DB.

Owner/superuser PostgreSQL bypassano di norma RLS, e **non usiamo FORCE RLS** perché migrazioni, seed controllati e manutenzione devono operare con ruolo privilegiato separato. L'applicazione di produzione deve sempre usare il login non owner `comuni_app_runtime`. La CI valida policy, SQL diretto A/B/no-context, INSERT/UPDATE cross-tenant, reset del valore sul pool, e un percorso HTTP con credenziale runtime.

## Limiti e sicurezza residua

**Questa è una barriera contro query non contestualizzate o errori applicativi, NON contro SQL arbitrario eseguibile sotto il login condiviso**: PostgreSQL permette al ruolo runtime di invocare `set_config` per modificare una custom GUC; una SQL injection sufficientemente potente potrebbe cambiare `comuni.organization_id` e bypassare la policy. Prima del go-live occorre progettare binding trusted non falsificabile (o ruolo/connessione segregati per tenant), valutare l'impatto sul pooling Npgsql, valutare leak per foreign keys e constraint, effettuare threat modeling e pen-test. Non dichiarare isolamento rigoroso garantito per dati personali reali finché la #5 non chiude.

La transazione per richiesta può trattenere la connessione per tutta la durata dell'endpoint: misurare pool saturation, timeout e latenza sotto carico. Tutte le nuove tabelle tenant-owned dovranno ottenere una policy esplicita e test RLS. Il deploy Azure e le migrazioni in VNet non sono ancora stati verificati (#6).

# ADR 0011 — Separare ruolo runtime PostgreSQL e owner delle migrazioni

- Stato: Accepted — incrementale, sotto-issue #16 della #5/#6
- Data: 2026-11-15
- Relazione: ADR 0001, 0002, 0003, 0005, 0006, 0009
- Specifiche PostgreSQL 17: https://www.postgresql.org/docs/17/sql-grant.html e https://www.postgresql.org/docs/17/ddl-schemas.html
- Azure PostgreSQL Flexible Server: https://learn.microsoft.com/en-us/azure/postgresql/security/security-manage-database-users

## Contesto

La configurazione Terraform passava al runtime della API la connessione privilegiata `comuniadmin`, necessaria alla creazione del database. Il runtime dell'API non deve poter eseguire DDL né gestire gli utenti del database.

## Decisione

Manteniamo una sola API, uno schema logico per dominio e **un unico PostgreSQL**, separando le credenziali:
- `comuniadmin`/schema-owner: provisioning e migrazioni EF da un job/operatore in rete privata.
- `comuni_app_runtime`: login PostgreSQL non proprietario, senza privilegi admin o membership di altri ruoli. Provisioning idempotente via `scripts/postgres/provision-runtime-role.sql` **dopo le migrazioni**. Password letta da variabile `RUNTIME_DB_PASSWORD` del runner, non presente nel repository e non stampata.
- GRANT in allowlist esplicita: USAGE schemi `platform`/`protocol`; SELECT `organizations`, `organization_modules`, `organization_memberships`, `protocol.records`; INSERT `protocol.records`/`audit_events`; UPDATE della sola colonna `organization_modules.enabled`. Nessun grant futuro automatico su nuove tabelle e nessun diritto sulla storia EF.
- Terraform mantiene la credenziale amministrativa solo per la risorsa PostgreSQL; la stringa di connessione pubblicata su Key Vault per la app usa il runtime e `var.postgres_runtime_password` separata. La password runtime è sensibile nel Terraform State e richiede RBAC/audit; futuro Entra DB auth da valutare.
- I test xUnit/CI creano la struttura con l'owner, eseguono due volte il provisioning e si collegano davvero con `comuni_app_runtime` per validare operazioni EF consentite e `42501` su DDL, utenti e audit.

## Conseguenze e rischi residui

1. **Questo non è RLS.** Il login runtime condiviso può leggere righe di tutti i tenant dai SELECT concessi se qualcuno bypassa i repository. #5 dovrà introdurre policy PostgreSQL RLS fail-closed, binding del tenant verificato, transazioni `SET LOCAL` e disciplina del connection pooling; si valuteranno i rischi di `SET` lato ruolo e di SQL injection prima di attivare RLS.
2. Il deployment Azure non esegue automaticamente migrazioni/provisioning. Serve un job autorizzato dentro la VNet prima che Container Apps possa connettersi con il nuovo ruolo; #6 rimane aperta. Una prima applicazione senza provision produce indisponibilità (fail closed).
3. Il runtime non può migrare o aggiungere nuovi moduli. Nuove migrazioni richiedono revisione del provisioning/grant e test nuovi.
4. Il ruolo owner e i segreti di Terraform rimangono sensibili. Rotazione delle credenziali già usate in ambienti precedenti, telemetria e backup/restore verificati prima del go-live.
5. Solo Docker Compose Development continua a usare il proprietario per `MigrateAsync` e seed dimostrativo; non replica la sicurezza di produzione.

## Aggiornamento ADR 0012

La vertical slice #17 ha successivamente introdotto RLS su cinque tabelle tenant-owned e un contesto applicativo SET LOCAL per transazione. Le avvertenze storiche sull'assenza di RLS sopra descrivono lo stato **prima della #17**; restano validi i rischi di owner bypass e SQL injection che può modificare la custom GUC. Vedere ADR 0012 e #5.

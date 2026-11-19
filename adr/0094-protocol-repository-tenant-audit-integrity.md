# ADR 0094 — Protocollo: coerenza semantica audit e tenant anche nel repository

- Data: 2026-11-19.
- Stato: **Accepted per la vertical slice sintetica del Protocollo**; non equivale a protocollo informatico a norma.
- Issue: #111, sotto-attività di #4 (audit), #5 (isolamento), #8 (Protocollo).
- Continuità architetturale: ADR 0002 (tenant firmato), ADR 0006 (transazione + audit), ADR 0092 (moduli), ADR 0093 (membership).

## Problema

La Business API `ProtocolService.RegisterAsync` produce il corretto evento `protocol.record.created` per una registrazione; il repository `ProtocolRepository.AddAsync` controllava solo gli ID di Comune e record. Un futuro chiamante o errore nel refactor poteva salvare nella **stessa transazione** una registrazione Protocollo e un evento di tipo `platform.membership`, una falsa revoca o una action `protocol.record.deleted`. Una transazione atomica non garantisce che la descrizione dell'azione corrisponda alla modifica. Anche `ProtocolRepository.ListAsync` filtrava per ID e dipendeva dal filtro EF/RLS senza rigettare esplicitamente il parametro organization non corrispondente al contesto.

## Decisione

1. `ProtocolRepository.ListAsync(organizationId)` rifiuta `Guid.Empty` e `db.CurrentOrganizationId != organizationId` con eccezione fissa `UnauthorizedAccessException` **prima** di eseguire la query. Il filtro EF per `organization_id`, la prova tenant HMAC e le policy RLS PostgreSQL rimangono necessari e invariati.
2. `ProtocolRepository.AddAsync(record, audit)` applica lo stesso controllo sul `record.OrganizationId` **prima** di aprire la propria transazione e prima di qualsiasi insert. Verifica `record.Id != Guid.Empty`, `audit.OrganizationId == record.OrganizationId`, `audit.ResourceId == record.Id`, `audit.Action == "protocol.record.created"` e `audit.ResourceType == "protocol.record"`. In caso di incongruenza rifiuta con un errore statico senza scrivere né il record né l'evento.
3. Conservare integralmente il modello: `ProtocolRecord.Register` convalidato in Domains, feature flag Protocollo e ruolo in API/Business, identità attore dal JWT validato via `ICurrentActorContext`, middleware transaction-scoped e `TenantDatabaseTransaction`, transazione locale firmata solo quando non esiste una transazione HTTP, `SaveChangesAsync` condiviso da record e audit, fallback senza schema owner, grant SQL limitati e audit append-only. Nessuna nuova tabella, migration, permesso, endpoint o UI.
4. **TDD RED→GREEN su `main`:** `tests/backend/Comuni.Api.Tests/ProtocolRepositoryIntegrityTests.cs` esercita il repository con il vero login `comuni_app_runtime`, prova di tenant firmata, due organizzazioni sintetiche. Casi negativi: action audit diversa o di altri domini, tipo `platform.module`, resource ID e organization audit alterati, record di un altro tenant, lettura con GUID vuoto o tenant differente; tutti devono fallire prima di DML e senza inserire eventi. Casi positivi: record e audit validi persistono insieme, rollback annulla entrambi, creazione in transazione locale autonoma ma firmata funziona, nessun effetto sull'altro Comune. Commit test RED `bf06612f`, fix GREEN `5c415f29`. La definizione di Done richiede **sette job GitHub Actions verdi sullo stesso SHA finale di `main`** dopo questo ADR.

## Limiti

Questa è una **vertical slice tecnica**, non un protocollo informatico conforme: non implementa segnatura, classificazione/fascicolazione, registro giornaliero, documenti immodificabili, conservazione e requisiti CAD/AgID. L'audit non è firmato crittograficamente contro il proprietario PostgreSQL, e il controllo repository non autentica da solo il chiamante, non sostituisce RLS, privacy review o retention. #4, #5 e #8 restano aperte, così come la verifica di PostgreSQL/Azure in ambienti reali autorizzati.

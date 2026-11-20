# ADR 0115 — Rilettura del flag sotto lock SQL quando EF ha entità tracciate

- Data: 2026-11-20
- Stato: Accepted per il Core sotto PostgreSQL 17 con dati sintetici; gate CI completo sul commit finale richiesto.
- Issue: #131 (follow-up #129), epiche #3/#4/#5.
- Precedenti: ADR 0009, 0013, 0092, 0112, 0113.
- Riferimenti: [EF Core tracking vs no-tracking](https://learn.microsoft.com/en-us/ef/core/querying/tracking), [EF Core reload](https://learn.microsoft.com/en-us/dotnet/api/microsoft.entityframeworkcore.changetracking.entityentry.reloadasync), [PostgreSQL 17 explicit locking](https://www.postgresql.org/docs/17/explicit-locking.html).

## Problema

L'ADR 0113 acquisisce `SELECT ... FOR UPDATE` sulla riga `organization_modules` **prima** della query EF che controlla `Enabled`. Questo serializza i writer PostgreSQL, ma una query **tracking** non sovrascrive automaticamente un'entità `OrganizationModule` già nel `ChangeTracker` dello stesso `DbContext`. Se la riga è stata letta prima della transizione committata da un'altra transazione, EF può restituire il vecchio `Enabled` anche dopo il lock. Una richiesta che dovrebbe essere un no-op produce quindi `Updated` e un evento audit non corrispondente a una transizione reale.

## Decisione

1. Il repository conserva `RequireCurrentOrganization`, la whitelist del catalogo, il contratto dell'audit, la transazione signed-RLS e il `SELECT ... FOR UPDATE` **parametrizzato** per organizzazione e modulo. Non si spostano le autorizzazioni sull'interfaccia e non si cambia la semantica degli endpoint.
2. Dopo il lock, una volta risolta l'entità EF, il repository esegue `db.Entry(module).ReloadAsync(cancellationToken)` **nella stessa transazione**. Questo rilegge `Enabled` dal server e aggiorna l'istanza eventualmente già tracciata. Se il reload distacca l'entità, il risultato è `NotFound`, senza scrittura né audit. Solo lo stato così riletto viene confrontato con il valore richiesto. Il lock resta valido fino a commit/rollback.
3. Nessun `UPDATE` e nessun evento per `Unchanged`; la vera transizione aggiorna il flag e aggiunge l'audit nello stesso commit. Il secondo Comune non viene letto o alterato. Nessuna migrazione, grant, servizio o modifica ai moduli `planned`.
4. La test suite PostgreSQL17 crea due Comuni sintetici e due `DbContext` con login runtime limitato e tenant assertion HMAC. Il primo traccia il vecchio flag, il secondo cambia flag/audit e committa; il primo richiede il **medesimo** nuovo stato. Deve ottenere `Unchanged`, un solo evento per la disabilitazione e uno per la successiva riabilitazione, mentre l'altro Comune rimane intatto. Il test è reale e ripetibile, non basato su un mock EF.

## Evidenza TDD e limiti

RED: commit [`eb3aba8`](https://github.com/KeyserDSoze/Comuni/commit/eb3aba8a81a66d5c9847e4518e22406ae7539ec2), [CI 44824915021](https://github.com/KeyserDSoze/Comuni/actions/runs/44824915021): 381 API passati, **uno fallito atteso** (`Expected: Unchanged; Actual: Updated`); unit, frontend/Playwright, Terraform e CodeQL senza regressioni. Per GREEN occorre la CI completa di 7 job sullo SHA HEAD finale, quindi chiusura #131.

Il fix protegge il percorso di repository anche se un futuro use case popola il ChangeTracker prima del toggle. Non introduce versioni HTTP/ETag né risolve race tra lifecycle owner-only e richieste già autorizzate, manomissione da DB owner, test multi-replica Azure, retention WORM o compliance CAD/AgID/GDPR. #3/#4/#5 rimangono aperte.

# ADR 0096 — Consultazione audit con actor verificato nel repository

- Data: 2026-11-20.
- Stato: **Accepted come hardening applicativo**, non audit forense completo.
- Issue: #113; epiche #4 e #5.
- ADR correlate: 0006, 0035, 0036 e 0095.

## Problema

Dopo #112, il port pubblico richiedeva un evento di consultazione ma riceveva ancora un `AuditEvent` assemblato da un chiamante. `OrganizationAuditReader` convalidava organization, risorsa, tipo e azione, **non** che `actor_subject` e `correlation_id` coincidessero con la richiesta autenticata. Un futuro use case interno poteva produrre un evento semanticamente coerente ma attribuito a un altro soggetto. L'atomicità SQL non corregge una falsa attribuzione.

## Decisione

1. **Nessun evento da input:** `IOrganizationAuditReader.ListRecentAndRecordAsync(Guid organizationId, CancellationToken)` è l'unica operazione pubblica. La query senza audit rimane privata.
2. **Actor/correlation all'ultimo confine applicativo:** `OrganizationAuditReader` dipende da `ICurrentActorContext` tramite la stessa DI scoped dell'API e genera internamente `AuditEvent.Create(organizationId, actor.ActorSubject, "platform.audit.consulted", "platform.audit", organizationId, actor.CorrelationId)`. `MunicipalAuditService` convalida il tenant e delega; non crea né trasferisce l'evento. Identità o correlazione mancanti falliscono prima della lettura.
3. **Sicurezza e transazione invariati:** il repository rifiuta GUID nullo o mismatch rispetto a `db.CurrentOrganizationId`, esige una transazione SQL già aperta dalla request con tenant proof HMAC, restituisce 25 soli record minimi ordinati, poi salva l'append audit. Il middleware committa solo le richieste HTTP riuscite. Nessuna transazione non firmata autonoma, bypass owner, nuova tabella, migration, GRANT, secret, endpoint o modifica frontend.
4. **TDD su main:** commit RED `5f77af9`, GitHub Actions `44712891064`: 368 test API passati e un fallimento atteso `Assert.Equal() Failure: Collections differ`. Il GREEN aggiorna il metodo e le prove PostgreSQL runtime per usare attori test scoped, preservando cross-tenant, commit/rollback, assenza della lettura senza audit, JSON con quattro soli campi, 401/403/400. La chiusura richiede sette job CI verdi sullo stesso SHA finale.

## Limiti

La DI non autentica indipendentemente il chiamante: sono necessari JWT e membership Admin verificati dal backend, contesto transazionale RLS e confidenza nel processo server. Un processo compromesso, accesso SQL diretto o DB owner possono continuare a minare la tracciabilità. Sono fuori scope pgAudit/SIEM, retention, catena di hash o WORM, impersonificazione, identity provider reale e Azure live; nessuna conformità CAD/AgID/GDPR è attestata.

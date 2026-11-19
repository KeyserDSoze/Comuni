# ADR 0006 — Audit minimo append-only e transazionale in PostgreSQL

- Stato: Accepted (issue #11, sotto-incremento di #4)
- Data: 2026-11-15
- Relazione: integra ADR 0001/0002/0005

## Decisione
`Domains/Audit/AuditEvent` contiene identificatore evento, `organization_id`, `actor_subject`, `action`, `resource_type`, `resource_id`, `correlation_id`, `occurred_at`. **Nessun subject del documento, corpo della richiesta, JWT, indirizzo IP o dati personali superflui.** L'attore deriva esclusivamente dal `sub` del JWT validato; la correlation è `HttpContext.TraceIdentifier` generata lato server.

`ProtocolService` produce `protocol.record.created` per ogni creazione riuscita, mentre `ProtocolRepository` salva il metadato e il relativo audit in una sola transazione database. Se uno fallisce, rollback di entrambi. `ComuniDbContext` filtra eventi per organization e rifiuta update/delete EF, e la migrazione `202611150003` crea trigger PostgreSQL che vietano UPDATE, DELETE e TRUNCATE sulla tabella `platform.audit_events`.

Nessuna API pubblica di lettura/scrittura audit viene esposta. Le eventuali consultazioni e le azioni platform-admin richiederanno autorizzazioni distinte, oltre all'audit dei loro accessi.

## Trade-off, confini di fiducia e limitazioni
- La protezione tramite trigger non è tamper-evidence crittografica: un superuser o owner DB privilegiato può rimuovere o aggirare le protezioni. L'app usa oggi una connessione DB troppo privilegiata; correggere in #5.
- Eventi storici pre-migrazione non sono retroattivamente popolati; audit copre **solo la creazione Protocollo** dopo rollout. Non registra consultazioni, accessi negati o altre azioni; #4 rimane aperta.
- L'actor è un `sub` tecnico fornito dall'attuale autenticazione JWT demo; provider OIDC e IAM reale restano aperti in #2.
- Occorre stabilire retention, backup/restores, accessi di consultazione, log privacy-safe e time source prima del go-live.
- La transazione esplicita evita un documento privo del relativo evento nel flusso applicativo, non garantisce audit di DML bypassando il repository (future query raw/other module paths devono essere controllate).

## Correzione difensiva successiva — modulo Protocollo (#109 / ADR 0092)

Il principio di transazione atomica documento/stato+audit non basta se il chiamante passa un'azione audit semanticamente incompatibile con la modifica. Il repository di amministrazione moduli ora verifica nel confine Infrastructure `moduleKey`, `audit.Action`, `audit.ResourceType`, `audit.OrganizationId`, `audit.ResourceId` e uguaglianza con `CurrentOrganizationId` prima di eseguire SQL. I test PostgreSQL con runtime ristretto e tenant assertion firmata esercitano anche rollback, idempotenza e impossibilità di cambiare un altro Comune. Non estende le garanzie verso DB owner/superuser, retention o prova crittografica di integrità; vedere ADR 0092.

# ADR 0116 — Retry canonico della registrazione vincolato a unico evento owner

- Data: 2026-11-21
- Stato: Accepted per SQL owner-only e PostgreSQL17/psql sintetici; CI GREEN finale richiesta prima della chiusura.
- Issue: #132, epiche #3 (Core), #4 (audit), #5 (isolamento).
- Dipendenze: ADR 0037/0038 (registration/lifecycle), ADR 0084 (private COPY), ADR 0114 (legacy provisioning provenance). Il percorso canonico resta `scripts/postgres/register-organization.sql`.

## Problema

`register-organization.sql` già rifiutava ticket differenti per un retry dello stesso UUID e nome, ma ricercava solo gli eventi `platform.organization.registered` che **coincidevano** con resource e ticket. Non verificava che l'evento fosse dell'owner SQL, né rifiutava un secondo evento `registered` con ticket/resource non corrispondente. Un audit originario fabbricato o ambiguo veniva perciò adottato come completamento idempotente. È lo stesso genere di problema di provenance risolto per il vecchio `provision-organization.sql` dall'ADR 0114, ma nello script canonico.

## Decisione

1. Mantenere il ruolo schema-owner, il controllo formato UUID/nome/ticket/reviewer, `pg_advisory_xact_lock`, `SELECT ... FOR UPDATE` sull'organizzazione, input `\\copy` da programma client statico, `pgaudit.log_parameter` guard e transazione SQL già esistenti. Il ramo **prima registrazione** resta identico: Comune `created`, Protocollo disabilitato, nessuna membership e singolo audit `registered` atomico.
2. Nel solo ramo **retry**, contare **tutti** gli eventi con `organization_id=v_org` e `action='platform.organization.registered'`, senza filtrarli preliminarmente per ticket/resource. Richiedere `COUNT(*)=1` e `COUNT(*) FILTER (...)=1` per la **stessa singola riga** con `resource_type='platform.organization'`, `resource_id=v_org`, `correlation_id='register:' || v_ticket`, `actor_subject='db-owner:' || current_user`. Nome e riga Protocollo devono continuare a coincidere/esistere.
3. Una riga con attore non-owner, ticket diverso, risorsa incoerente o audit di registrazione duplicato è rifiutata **prima di qualsiasi mutazione**; niente inserimento automatico, riparazione o cancellazione di audit. Nessun dettaglio nome/ticket/approvatore nell'errore. Un retry autentico rimane no-op anche se dopo la registrazione il Comune è stato attivato/sospeso o i suoi moduli sono cambiati; nessun flag/ruolo/audit viene ripristinato.
4. TDD con `OrganizationRegistrationTests` e vere sessioni `psql` owner su PostgreSQL17: RED caso manuale con unico evento matched per ticket/resource ma actor estraneo; RED caso canonico con evento supplementare `registered` di ticket diverso. Entrambi hanno exit code **0 errato** prima del fix; GREEN richiede codice nonzero, snapshot DB immutati e privacy degli output. Confermare retry valido e suite di regressione RLS, pgAudit e frontend. Nessuna migrazione, API, ruolo, grant, modulo aggiuntivo o uso Azure.

## Evidenze e limiti

RED: commit [`31765ae`](https://github.com/KeyserDSoze/Comuni/commit/31765ae8029f25f715ff0162d2e93ddeb2dd155b), [CI 44882241647](https://github.com/KeyserDSoze/Comuni/actions/runs/44882241647): 56 unit, **382 API passed e 2 expected failures** (`Expected: Not 0, Actual: 0`); Playwright/Terraform/SCA/CodeQL verdi, Docker saltato per API RED. GREEN richiede 7/7 job successo sullo stesso HEAD `main`.

Questa è **coerenza audit/provenance interna**, non validazione del change ticket in sistema esterno, identità reviewer, autenticità del Comune, firme probatorie, immutabilità contro owner/DBA compromesso, messa in sicurezza di COPY base64 o conformità CAD/GDPR/AgID. #3/#4/#5/#84/#86/#92 restano aperte.

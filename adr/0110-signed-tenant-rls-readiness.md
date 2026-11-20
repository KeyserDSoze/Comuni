# ADR 0110 — Readiness API con verifica della firma tenant RLS

- Data: 2026-11-20
- Stato: Accepted per il codice API e la fixture PostgreSQL sintetica; produzione Azure da verificare
- Issue: #126, dipendenze aperte #5/#19/#49/#6
- Precedenti: ADR 0013/0014 (assertion firmate e rotazione), ADR 0109 (audit pgAudit)

## Problema e decisione

Prima della #126 la route `GET /health/ready` eseguiva solo `db.Database.CanConnectAsync()`. Una revisione ACA con PostgreSQL raggiungibile ma `Security:TenantProofKey` / `Security:TenantProofKeyId` errati, revocati o fuori finestra continuava a rispondere 200 benché le query tenant fossero bloccate dalla funzione `platform.verified_tenant_id()`.

La readiness ora riceve il **medesimo `TenantProofSigner` dell'API** e, sotto il suo login SQL configurato, apre una transazione usa-e-getta. Genera un UUID casuale **non associato a un Comune**, firma un `comuni.tenant_assertion` con key ID e MAC HMAC, crea anche la versione identica con ultimo nibble del MAC alterato, e verifica tramite SQL statico **soltanto** `SELECT platform.verified_tenant_id()`: la prova alterata deve produrre NULL, quella valida l'UUID esatto. L'asserzione viene passata a `set_config(..., true)` come parametro EF/Npgsql, non come literal SQL. Non sono letti o inseriti tenant, ruoli, documenti, firme DB né token OIDC. Nessun privilegio nuovo.

La transazione non viene mai committata: rollback esplicito sul successo e dispose/rollback in ogni altro percorso, senza GUC persistente sul pool. Verifier non disponibile, firma sbagliata, DB non raggiungibile, grants mancanti o qualsiasi risultato inconsistente provocano HTTP **503** con diagnostica opaca; `/health/live` resta indipendente e HTTP 200. `Cache-Control: no-store` evita cache HTTP dello stato readiness anche per 503.

## TDD e prova

RED test-first [`82bb4b4`](https://github.com/KeyserDSoze/Comuni/commit/82bb4b45f0f559e4e75ae7604104d7b9cd785249) inizialmente fallito per la configurazione minimal hosting anticipata dell'API; fixture corretta e RED ripetuto [`baf5804`](https://github.com/KeyserDSoze/Comuni/commit/baf580486c8b8dee7de53e86e4060d897ab8263e) nella [CI 44776728804](https://github.com/KeyserDSoze/Comuni/actions/runs/44776728804): PostgreSQL17 reale, **370/371 API verdi**, unico failure corretto `Expected ServiceUnavailable / Actual OK` con chiave errata. I test veri inseriscono una key sintetica attiva, verificano corretto/mismatch/revoca owner-only, liveness indipendente, assenza del contesto dopo rollback e DB offline. GREEN richiede CI **7/7 sul medesimo SHA HEAD main** incluse xUnit, PostgreSQL, pgAudit, Playwright, Python/Terraform, CodeQL e container.

## Limiti espliciti

Un 200 significa solo che la **specifica istanza API** riesce a produrre una prova RLS accettata dal **singolo PostgreSQL interpellato in quell'istante** e che una MAC alterata viene respinta. Non prova isolamento e CRUD reali di due Comuni, revoca OIDC, disponibilità di tutte le repliche, Key Vault, trust CA/TLS, Azure PostgreSQL, multiregion, rotazione zero-downtime o safety del deployment. Sono indispensabili smoke autorizzati stable/candidate con due tenant sintetici e rollback documentato; nessun Azure apply o secret reale è stato utilizzato.

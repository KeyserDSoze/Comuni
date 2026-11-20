# Test PostgreSQL17/pgAudit — full-envelope owner COPY (#124)

## Scopo

Regressione di privacy del **record completo** `base64(JSON)` inviato con `\\copy` client-side dalle dodici procedure owner-only non-SCRAM, complementare al gate SCRAM #123.

## Prove

- `tests/infra/test_pgaudit_owner_copy_envelope_privacy.py`: genera tre envelope sintetici (identity, signing key e retirement) e verifica la reversibilità, l'assenza di lunghe sottostringhe canary individuali, accettazione dell'audit metadata-only e rifiuto del record intero nel server log **o** in stdout/stderr client. Inventari vuoti o non validi devono fallire senza echo; il test statico assicura che il runner reale raccolga inputs e output e chiami la scansione.
- `tests/postgres/pgaudit/verify_role_audit.py`: eseguito nel job Backend della CI, con PostgreSQL 17 e vera estensione pgAudit nel container disposable. Oltre a CREATE/ALTER ROLE SCRAM, opera su onboarding, lifecycle, operatori, signing key, staging emergenza e retirement veri, input sintetici/rollback/replay; conserva le verifiche di audit FUNCTION/WRITE/ROLE/DDL e native COPY. Al termine richiede 12 nomi di procedure distinti e controlla tutti gli envelope canonici conservati **solo in memoria**, confrontandoli con server logs aggregati e client output privati.
- RED: [commit `a93398d`](https://github.com/KeyserDSoze/Comuni/commit/a93398d2d6596f9b85c0aa6f68180887fd585a59), [run 44763889786](https://github.com/KeyserDSoze/Comuni/actions/runs/44763889786), **5 failure e 11 error** nel gate Terraform/Python (funzione e acquisizione assenti; due imperfezioni della prima fixture sistemate). Non copiare raw CI assert output: una delle assert statiche RED incorporava erroneamente testo sorgente nelle diagnostiche, sostituita con errore costante.
- GREEN: funzionalità `574ace4`, test fixture rettificata `0f69c3c`. Chiusura soltanto dopo **7/7 job success** su un singolo SHA HEAD di `main`, tra cui xUnit/PostgreSQL17/pgAudit, Playwright, Python/Terraform, CodeQL, dependency audit e container.

## Limiti

Il test riconosce l'**esatta** serializzazione del producer, non decomposizioni e riconversioni arbitrarie del payload. Non esegue provisioning Azure, Key Vault, SQL proxy, APM, SIEM, audit log esterni, approvazione Privacy, retention né rotazione multi-replica. Non stampare dati sensibili o risultati raw sul job, nei commenti GitHub o in troubleshooting. Per evidenze di produzione mantenere #86/#92 e le issue Azure aperte.

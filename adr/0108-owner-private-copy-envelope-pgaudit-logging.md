# ADR 0108 — Controllo dell'intero envelope COPY owner-only nella prova pgAudit

- Data: 2026-11-20.
- Stato: **Accepted per il gate CI offline PostgreSQL 17/pgAudit**; nessuna autorizzazione di uso Azure/produzione.
- Issue: #124 (sottoissue #86/#92, correlate #89/#19/#5). Segue ADR 0073, 0074, 0099–0107.
- Riferimenti: [PostgreSQL 17 psql](https://www.postgresql.org/docs/17/app-psql.html), [pgAudit README](https://github.com/pgaudit/pgaudit/blob/main/README.md), [PostgreSQL 17 logging](https://www.postgresql.org/docs/17/runtime-config-logging.html).

## Contesto e threat model

Il producer `scripts/postgres/stream-private-input.py` trasmette i valori delle dodici operazioni owner-only **non-SCRAM** come un singolo record CSV contenente `base64(JSON)` canonico (`ensure_ascii=True`, `separators=(",", ":")`, `sort_keys=True`). Valori come issuer OIDC, subject, change approval, chiavi HMAC, identificativi di rotazione e reviewer sono sensibili. La codifica base64 è reversibile e **non garantisce privacy**: il record completo può contenere simultaneamente più valori. I controlli fino alla #123 riconoscevano i singoli canary in chiaro o in base64, ma non necessariamente la forma in cui viene trasferito **l'intero** oggetto JSON.

Anche se `pgaudit.log_parameter=off` protegge dal logging dei valori dei parametri secondo il profilo testato, un errore, una nuova configurazione, un proxy o collector potrebbe pubblicare il payload completo. Il gate deve rilevare tale regressione senza disattivare `pgaudit.log` o ridurre il logging SQL.

## Decisione implementativa

1. Il runner `tests/postgres/pgaudit/verify_role_audit.py` registra **solo in memoria** una copia del dizionario di input sintetico a ogni invocazione di `private_owner_script`, incluso il tentativo negato prima della COPY, replay e rollback. Registra anche tutto l'output `psql` stdout+stderr in memoria; non stampa valori/SQL logs.
2. Il runner conserva l'identità dello script eseguito e blocca l'esito positivo se i **12 nomi distinct** della allowlist non sono stati esercitati. Non cambia la lista dei produttori, il formato `COPY`, la loro transazionalità o i privilegi.
3. A valle di tutte le prove PostgreSQL17/pgAudit già esistenti, il nuovo `assert_private_copy_envelopes_absent` ricostruisce **l'esatto** `base64(JSON)` di ciascun tentativo usando lo stesso ordinamento e escaping del producer, e cerca la sua presenza nei `docker logs` server e negli output raccolti del client. Rifiuta inventari vuoti o malformati. La diagnostica è costante, senza payload, sorgente SQL, derivati e frammenti del log.
4. L'analizzatore opera **in aggiunta**, non al posto, dei test individuali di valori in chiaro/base64, delle verifiche `pgAudit FUNCTION/WRITE/ROLE/DDL`, `statement: COPY`, preflight `pgaudit.log_parameter=off` non-SCRAM, gate SCRAM con redazione `CREATE/ALTER ROLE` e `pgaudit.log_parameter=on` della #123. Nessun cambiamento al runtime, alle migrazioni o al frontend.
5. TDD: test-first RED [`a93398d`](https://github.com/KeyserDSoze/Comuni/commit/a93398d2d6596f9b85c0aa6f68180887fd585a59), [Actions 44763889786](https://github.com/KeyserDSoze/Comuni/actions/runs/44763889786): gate Terraform/Python fallito (5 failure e 11 error per funzione/instrumentazione mancanti e due imprecisioni del test; nessun payload pubblicato intenzionalmente). GREEN iniziale [`574ace4`](https://github.com/KeyserDSoze/Comuni/commit/574ace4e781a235bdb1a8b75e8658db698368e01), poi correzione delle due imprecisioni test [`0f69c3c`](https://github.com/KeyserDSoze/Comuni/commit/0f69c3c528805e8785198c4e7ca628234a71a5e4). Chiudere #124 **solo con GitHub Actions 7/7 successful sul medesimo SHA finale HEAD `main`**.

## Invarianti, limiti e responsabilità

Questa è una prova sintetica della rappresentazione **esatta** usata dal producer client `COPY`, non una scoperta generale di leak: frammenti, compressione, codifiche a più strati, trasformazioni/troncamenti di SQL proxy, APM, collector e SIEM possono eluderla. La prova non certifica Azure Flexible Server, pgAuditLogToFile, TLS/Key Vault, gestione DBA, policy di retention, privacy o rotazione reale multi-replica. La capacità di vedere/verificare i payload del test non implica che l'API runtime possa leggerli: restano invariati i privilegi e l'isolamento RLS. Nessuna risorsa Azure, password o chiave reale è coinvolta. Review Security/Privacy e prove nel sistema di logging Azure realmente autorizzato rimangono requisiti di #92/#86/#89/#19.

# ADR 0088 — Inventario verificabile di tutti i canali COPY owner-only

- Data: 2026-11-18.
- Stato: **Accepted come contratto statico TDD offline**, non autorizza uso con identità o chiavi reali.
- Issue: #105, sottoattività di #86. Riferimenti ADR 0073–0087 e #88–#103.
- Fonti: https://www.postgresql.org/docs/17/app-psql.html, https://www.postgresql.org/docs/17/sql-copy.html, https://www.postgresql.org/docs/17/runtime-config-logging.html.

## Problema

Dopo gli hardening incrementali, **14 script** PostgreSQL offline owner-only accettano identità, approvazioni, dati Comune, password SQL, HMAC e metadati di revoca tramite operazioni separate di `stream-private-input.py`. I test specifici di una procedura non impediscono che una nuova procedura `\\getenv` torni a interpolare valori `:'name'` dentro SQL o che uno script diverga dalla allowlist dell'helper.

## Decisione

1. Manifest versionato `docs/security/owner-only-psql-private-input-inventory.json` v1: esattamente **14 script / 14 operazioni** 1:1, 54 nomi di variabili ambiente (non valori), classificazione del rischio e issue di riferimento. Il manifest è un oggetto di **review**, non un permesso per eseguire procedure in produzione.
2. `tests/infra/test_owner_psql_copy_inventory.py` usa `ast.parse` e `ast.literal_eval` per confrontare l'assegnazione letterale `INPUTS` nell'helper **senza importarlo né eseguire codice**. L'insieme degli script/operazioni è dichiarato esplicitamente nel test: nuove procedure richiedono revisione del test, del manifest, della relativa ADR e degli xUnit PostgreSQL 17.
3. Ogni file inventariato deve usare una **sola** `\\copy pg_temp.comuni_private_input(payload) FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py <operation>' WITH (FORMAT csv)` statica lato client, `\\set ON_ERROR_STOP on`, `BEGIN`, TEMP `ON COMMIT DROP` e lettura SQL della TEMP. Vietate interpolazioni `:'var'` in SQL attivo e `\\echo :` degli input. Dieci preflight `\\getenv` richiedono corrispondenza esatta delle env; quattro script per password/chiavi leggono input solo nell'helper. Commenti storici non sono interpretati come SQL attivo.
4. La discovery `scripts/postgres/*.sql` blocca nuovi file con `\\getenv`, helper COPY o interpolazione `:'var'` non inclusi nel manifest. Due **mutazioni sintetiche in memoria** provano la reiezione di literal e programmi client non revisionati. Restano i limiti client 1024 byte/campo, busta JSON 8192 byte ed errore statico senza echo.
5. TDD direttamente su `main`: test RED `3a795795`, run GitHub Actions `44312536458` con fallimento atteso `reviewed owner input inventory missing`; test fixture corretto `9d4b4e7f`; GREEN manifest `03d5f448`, job Terraform/Python già passato nella run `44312793277`. L'intero 7/7 resta da verificare **sullo SHA finale**, dopo questo ADR e docs; solo allora chiudere #105.
6. Nuovi script owner-only devono aggiornare **prima** test/manifest e regressioni xUnit; vincolo documentato in `AGENTS.md` e `docs/issues.md`. Nessun nuovo endpoint, servizio, schema, GRANT, cambio RLS o applicazione separata.

## Limiti

Guardia sintattica ≠ prova di riservatezza: **base64(JSON) è reversibile**. Il protocollo COPY, TEMP, error context, pgAudit, APM, SQL proxy, backup, Azure/SIEM e retention possono esporre metadati o input. Lo schema-owner può bypassare le procedure; sono obbligatori authorization, identity proof/MFA, TLS VerifyFull, audit e review Security/Privacy in ambienti reali. #86/#49/#84/#92 e #5/#6 restano aperte, senza attestazioni di go-live o conformità. Nessun dato reale utilizzato.

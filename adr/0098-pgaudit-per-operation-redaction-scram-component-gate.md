# ADR 0098 — Verifica completa della redazione ROLE e dei componenti SCRAM nei log pgAudit

- Data: 2026-11-20.
- Stato: **Accepted come hardening del gate CI sintetico**, non attestazione di sicurezza dei log Azure.
- Issue: #115 (sotto-issue di #92); dipendenze #86/#89 e ADR 0075–0076.
- Riferimenti: [PostgreSQL 17 pg_authid](https://www.postgresql.org/docs/17/catalog-pg-authid.html); [PostgreSQL 17 password authentication](https://www.postgresql.org/docs/17/auth-password.html); [pgAudit sorgente](https://github.com/pgaudit/pgaudit/blob/main/pgaudit.c); [pgAudit regression output](https://github.com/pgaudit/pgaudit/blob/main/expected/pgaudit.out).

## Problema

ADR 0076 esegue già i veri script di provisioning su un cluster PostgreSQL 17/pgAudit usa-e-getta con logging `ROLE,DDL,WRITE,FUNCTION` e `log_statement=all`. Il controllo `assert_audits` tuttavia verificava solo la presenza di **una** riga ROLE con `<REDACTED>`: uno dei CREATE/ALTER ROLE dei due login poteva perdere la redazione senza fare fallire il gate. Il confronto degli interi verifier `SCRAM-SHA-256$...` e plaintext escludeva solo un valore completo; sale, StoredKey o ServerKey separati potevano essere registrati senza essere rilevati. Un frammento isolato non è necessariamente sufficiente a ricostruire la password, ma resta materiale sensibile e non deve finire in log/collector.

## Decisione

1. Per `comuni_app_runtime` e `comuni_platform_reader`, il test richiede **per ogni evento osservato** `AUDIT: SESSION, ..., ROLE, CREATE ROLE` e `ROLE, ALTER ROLE` con ruolo corrispondente la marcatura `<REDACTED>`. Non basta più una redazione in un'altra riga. Il test continua a richiedere gli eventi di GRANT e `statement: COPY`: non è permesso rendere verde il gate disabilitando il logging.
2. Prima di validare gli eventi, estrarre dai verifier realmente letti da `pg_authid` sale, StoredKey e ServerKey base64 nel formato PostgreSQL 17. Rifiutare formati malformati, decodifica non canonica o lunghezze incompatibili (sale almeno 16 byte, keys 32 byte), senza pubblicare l'input. Cercare **in ogni riga dei log** password, verifier completo e ciascuna componente; una qualunque corrispondenza provoca failure generica, senza stampare materiale, contesto di query o server log.
3. **Test-first RED reale su main:** nuovo `tests/infra/test_pgaudit_log_analyzer.py` esercita il parser con fixture sintetica non segreta: quattro subtest che rimuovono una sola redazione e tre subtest che aggiungono un componente SCRAM senza il verifier intero. Commit RED `156865600681f2cdf7c14fb54a46fa0757d2cfe9`; [Actions 44718146768](https://github.com/KeyserDSoze/Comuni/actions/runs/44718146768): job Terraform/Python fallito con **sette casi attesi** `AssertionError not raised`. Il positivo conserva redazioni complete, eventi ROLE/GRANT e COPY, e i negativi esistenti per password/verifier interi.
4. **GREEN** modifica soltanto l'analizzatore della fixture `tests/postgres/pgaudit/verify_role_audit.py` e i test sintetici. La stessa prova reale PostgreSQL17/pgAudit rimane obbligatoria prima della suite API: provisioning CREATE/ALTER di due login, login SCRAM, rotazione con sale nuovo, rollback, deny runtime, audit DDL e logging standard. La definizione di done richiede **7 job GitHub Actions verdi sullo stesso SHA finale di main** comprendente test, codice e ADR.
5. Non sono modificati PostgreSQL di produzione, migrazioni, SQL provisioning, GRANT, secret, credenziali, API .NET/React, Terraform apply né Azure.

## Limiti

La ricerca dei componenti base64 completi è volutamente una **verifica specifica**: non garantisce rilevazione di frammenti troncati, encoding alternativo, un `pg_authid` esfiltrato, COPY payload, errori di estensioni fuori dal cluster CI o diagnostica di componenti Azure. Il controllo esamina il testo aggregato disponibile da `docker logs` e non certifica il data plane Azure, pgAuditLogToFile, collector, proxy, APM, SIEM, retention, privacy, MFA/change approval, accessi a pg_authid né rotazione senza downtime. La #92 resta **OPEN** fino alla review e alle prove con autorizzazioni/ambiente reale; se il test individua un leak, il job deve fallire senza ridurre il logging.

# ADR 0107 — Gate SCRAM pgAudit: envelope COPY reversibile e stdout/stderr psql

- Data: 2026-11-20.
- Stato: **Accepted per gate CI sintetico PostgreSQL 17/pgAudit**; non è certificazione di logging Azure.
- Issue: #123, sottoissue di #92, correlata a #89/#86/#5.
- ADR precedenti: 0075 (SCRAM client), 0076 (pgAudit ROLE), 0098 (redazione per evento/componenti), 0106 (metadata-only applicabile alle procedure non-role).
- Riferimenti: [PostgreSQL 17 pg_authid](https://www.postgresql.org/docs/17/catalog-pg-authid.html), [logging PostgreSQL 17](https://www.postgresql.org/docs/17/runtime-config-logging.html), [pgAudit README](https://github.com/pgaudit/pgaudit/blob/main/README.md).

## Threat model e problema

I provisioner `provision-runtime-role.sql` e `provision-platform-read-role.sql` generano nel processo client il verifier SCRAM con sale casuale e lo inoltrano con `psql \\copy FROM PROGRAM`: trasporto con **base64(JSON({"SCRAM_VERIFIER": verifier}))**, non crittografia. `CREATE/ALTER ROLE` ricevono il verifier tramite DDL dinamico. Il test precedente cercava password, verifier e componenti SCRAM in chiaro in `docker logs` e richiedeva `<REDACTED>` su ogni evento ROLE, ma **non cercava le forme reversibili** né ispezionava sistematicamente l'output client psql (in particolare stderr di operazioni negate).

Un envelope intero può rivelare un verifier senza contenerne il testo in chiaro, e quindi non attiva la ricerca per il verifier o per StoredKey/ServerKey. Un verifier compromesso può facilitare attacchi offline a password deboli. Nessun valore di produzione deve essere passato al test.

## Decisione

1. Estendere `assert_audits(server_log, verifiers, passwords, client_output="")` per rifiutare **sia in log server sia nell'output combinato stdout/stderr del client**: plaintext, intero verifier, componenti salt/StoredKey/ServerKey canonici, base64(verifier/password), e l'esatto envelope COPY base64(JSON) del verifier generato dall'helper. Controlli e diagnostica non devono mai stampare log o valori.
2. La fixture reale PostgreSQL 17/pgAudit mantiene `pgaudit.log=role,ddl,write,function`, `pgaudit.log_parameter=on`, `log_statement=all`, `log_parameter_max_length=-1` e `log_parameter_max_length_on_error=-1`. Non si deve rendere verde il test disattivando audit. Le policy di preflight `pgaudit.log_parameter=off` delle altre dodici procedure **non si applicano** automaticamente ai provisioner ROLE.
3. Acquisire in memoria gli output client di **entrambi i ruoli** su CREATE, ALTER, input mancante/abort e runtime-denied, incluso stderr. Registrare tutti i password canary sintetici, anche il tentativo negato, prima della scansione dei risultati finali. `script()` non pubblica i contenuti in CI.
4. Mantenere i controlli esistenti di redazione per evento `CREATE ROLE`/`ALTER ROLE`, pgAudit `GRANT` e `statement: COPY`, login SCRAM, sale diverso dopo rotazione, transazione/rollback, owner-only, privilegi SQL e RLS invariati.
5. TDD: RED iniziale [f13240f](https://github.com/KeyserDSoze/Comuni/commit/f13240fc52318edd0e028c24fff34b2d54268862), RED isolato [8fd46ba](https://github.com/KeyserDSoze/Comuni/commit/8fd46ba4cfdd71d3a6bcae74d3aa30810ae6de95), [Actions RED 44750344128](https://github.com/KeyserDSoze/Comuni/actions/runs/44750344128), Terraform/Python con **2 failure** perché l'envelope è ignorato e **7 error** per nuova interfaccia client non ancora implementata. Correzione del gate [35adffe](https://github.com/KeyserDSoze/Comuni/commit/35adffe564c16d6d32dff06451f303ad6fca8537). La chiusura della #123 richiede **7 job GREEN sullo stesso SHA finale HEAD main**.

## Limiti e confini

Le rappresentazioni controllate sono quelle note dal codice di trasporto e dai componenti SCRAM canonici; encoding annidati, chunking, troncamenti, trasformazioni del collector, dump `pg_authid`, process tracing, SIEM, APM, log PostgreSQL Azure/pgAuditLogToFile, TLS, secret rotation multi-replica e retention **non sono attestati**. Le credenziali restano sensibili in memoria e nel catalogo owner. Nessuna modifica a database di produzione, ruoli effettivi, grants, migration, API, frontend, Terraform o Azure. Richiesti DBA, security review, change approval e prove separate in un ambiente Azure autorizzato prima dell'uso reale. `#92/#89/#86` restano aperte.

# pgAudit PostgreSQL 17 — sicurezza del file logging collector (issue #125)

**Solo CI sintetica.** Il controllo usa lo stesso cluster usa-e-getta dei test pgAudit ROLE/DDL ed envelope COPY. I dati di test non sono chiavi né identità di Comuni reali.

## Confine di osservabilità

`docker logs` può non contenere gli eventi che PostgreSQL, con `logging_collector=on`, deposita nei propri file. PostgreSQL 17 espone il file corrente tramite `pg_current_logfile()`; l'estensione pgAudit usa il sistema di logging standard PostgreSQL. Quindi un gate che guarda soltanto stdout/stderr del container non copre necessariamente la destinazione file. Riferimento: https://www.postgresql.org/docs/17/runtime-config-logging.html

Il nuovo gate termina la fixture principale #123/#124, modifica la configurazione **del solo container**, riavvia, verifica `logging_collector=on`, `log_destination=stderr` e l'unico nome approvato `log/audit-ci.log`. Con `docker exec cat` legge il file unicamente in memoria, non come artifact GitHub e non lo stampa. Vengono ruotate ancora le due password SCRAM sintetiche con i veri script; viene stagiata una nuova signing key fittizia tramite lo script owner-only. Prima di un esito positivo sono necessari due eventi redatti `ROLE,ALTER ROLE`, `GRANT`, `FUNCTION,DO`, `WRITE,INSERT`, native `statement: COPY`, esito login, nessun verifier/componenti/base64 e nessun envelope privato nel file o nell'output psql.

I **due** provisioner SCRAM rimangono con `pgaudit.log_parameter=on` e redazione ROLE. Il percorso signing key resta `pgaudit.log_parameter=off` soltanto per i valori, con preflight pre-COPY. Non disabilitare `log_statement=all` o `pgaudit.log=role,ddl,write,function` in questa verifica per un PASS artificiale. Il file deve essere reale e contenere eventi del periodo successivo al riavvio: non considerare un `docker logs` preesistente come prova del collector.

## Blocco del rilascio reale

Per Azure occorrono ancora owner DBA, ambiente autorizzato e review Security/Privacy di **ogni destinazione effettiva**: `pgAuditLogToFile` o equivalenti del servizio, Azure Monitor / SIEM, APM, proxy, debug, log di errore e connection pool, retention, backup, RBAC Key Vault, PIM, accesso a `pg_authid`, TLS VerifyFull, rollout/rollback. Non trasferire payload o log grezzi in issue, Actions o dashboard. Una fuga rilevata blocca il provisioning reale, non giustifica la rimozione dei log. Dipendenze aperte #92/#86/#89/#19/#5.

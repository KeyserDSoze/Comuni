# Provisioning SCRAM PostgreSQL — boundary dei log e trasporto client COPY

**Ambito:** runbook di sicurezza offline per #123 / ADR 0107, estensione dei controlli #92. Nessun uso produzione autorizzato da questo documento.

I due provisioner `scripts/postgres/provision-runtime-role.sql` e `provision-platform-read-role.sql` sono eseguiti esclusivamente come schema owner. L'helper `scripts/postgres/stream-private-input.py` genera il verifier SCRAM-SHA-256 nel client e lo trasporta in un unico record base64(JSON) tramite `\\copy`. **Base64 non nasconde il verifier.** Il database lo memorizza in `pg_authid`; i log ROLE/DDL, quelli nativi, il client psql e i sistemi esterni sono superfici di esposizione distinte.

## Controllo operativo minimo per la fixture CI

- Cluster PostgreSQL 17/pgAudit **disposable**, password e ruoli di test fittizi, logging `role,ddl,write,function` e statement/event error attivi, `pgaudit.log_parameter=on` **soltanto nel percorso SCRAM**.
- Ogni evento `CREATE ROLE`/`ALTER ROLE` deve riportare metadata ROLE e `<REDACTED>`; GRANT e COPY devono rimanere auditati. Il gate fallisce su verifier, plaintext, componenti SCRAM, base64 diretto e l'envelope client esatto, sia nei server log raccolti sia in stdout/stderr psql.
- Nessuna stampa dei `docker logs`, dell'output `psql`, del verifier, dei campi JSON o dei secret in diagnosi CI. Utilizzare solo messaggi statici e bool di risultato. Controllare sia successi sia input mancante/rollback e utente runtime negato.
- I 12 percorsi owner-only non-role hanno policy metadata-only propria (ADR 0100–0106); **non copiare il loro preflight pgAudit sui due provisioner SCRAM** senza un'analisi distinta della redazione ROLE.

## Preflight prima di un eventuale ambiente reale

L'owner DBA e Security/Privacy devono verificare configurazione effettiva dell'estensione PostgreSQL Azure, `pgAuditLogToFile`, `log_statement`, error context, pooler/proxy, APM, agent, SIEM/collector, policy di retention/redazione, accessi `pg_authid`, TLS VerifyFull, autorizzazioni e change approval. Eseguire una prova negativa con segreti **sintetici e autorizzati**, controllando il dato raccolto da ogni destinazione, non solo la CLI o la CI. Prevedere rollback, ruoli separati, credenziali temporanee e impatto della rotazione sulle connessioni.

**Stop condition:** qualsiasi verifier o envelope reversibile rilevato richiede blocco del provisioning reale e review; non disattivare audit per forzare un PASS. Il test offline non prova l'assenza di leaking nei servizi esterni, né garantisce zero downtime. Seguire #92/#89/#19 e il runbook Azure generale.

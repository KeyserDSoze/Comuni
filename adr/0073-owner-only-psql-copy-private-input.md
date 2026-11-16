# ADR 0073 — Trasporto input owner-only tramite client-side psql COPY STDIN, senza SQL literal

- Data: 2026-11-16.
- Stato: Accepted **solo come incremento offline/test sintetici** per staging emergenza #85; non certifica gestione di PII/segreti in produzione.
- Issue: #88, sottotask di #86; collegato a #84/#85, ADR 0069–0072.
- Riferimenti ufficiali: [PostgreSQL 17 psql \\copy](https://www.postgresql.org/docs/17/app-psql.html), [PostgreSQL 17 COPY](https://www.postgresql.org/docs/17/sql-copy.html), [PostgreSQL 17 error reporting e log](https://www.postgresql.org/docs/17/runtime-config-logging.html).

## Evidenza della vulnerabilità

Il percorso precedente usava `psql \\getenv` seguito da SQL `set_config('comuni.emergency_subject', :'emergency_subject', true)`. La forma quotata `:'var'` protegge da injection, ma **il valore appare come literal nel testo della query ricevuta dal server PostgreSQL**. `psql -q` non sopprime né `log_statement=all`, né `log_min_error_statement`, né estensioni di audit lato server.

Le **query con parametri Npgsql non risolvono automaticamente** il rischio: in PostgreSQL 17 `log_statement` può includere i bind parameters e `log_parameter_max_length=-1` è il default, mentre `log_parameter_max_length=0` ne esclude il logging ordinario ma è una impostazione privilegiata. Cambiare il logging del server soltanto per far passare un test (`SET log_statement=none`, `log_min_error_statement=PANIC`) non costituisce una misura di accountability sicura.

## Decisione ristretta a #88

1. Per **`scripts/postgres/stage-emergency-admin-replacement.sql` soltanto**, sostituire la query con `:'emergency_*'` e introduzione di:
   - `CREATE TEMP TABLE pg_temp.comuni_private_input(payload text NOT NULL) ON COMMIT DROP` nella medesima transazione;
   - `psql \\copy ... FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py emergency' WITH (FORMAT csv)`, con comando statico e non interpolabile da alcun input;
   - un unico record testuale **base64(JSON)** trasportato dallo stdout del programma **locale al client psql** al protocollo `COPY ... FROM STDIN` del server, non come SQL statement;
   - `WITH private_json AS (...) SELECT set_config(..., secret ->> 'COMUNI_EMERGENCY_*', true) ... \\gset`, dove il valore è letto dalla tabella temporanea, **non** da literal nel testo SQL.
2. L'helper `stream-private-input.py` è un executable **allowlist**: accetta esattamente l'operazione statica `emergency`, legge soltanto le nove variabili `COMUNI_EMERGENCY_*` revisionate, rifiuta assenze, stringhe vuote, valori e payload oversize con **errore statico**, non legge segreti collaterali, non include identity in argv, command string, report o stderr. Il processo figlio non deve essere eseguito direttamente con stdout su un terminale. Niente valori in shell interpolation, filename, GitHub issue o log client.
3. Base64 **non cifra e non anonimizza**. Python e `psql` mantengono input in memoria; il protocollo e la temp table contengono l'envelope reversibile. L'esecuzione richiede trusted checkout, directory di lavoro nella **root del repository**, Python3, runner privato, rete TLS e credenziale schema-owner PostgreSQL. L'operazione è disabilitata per l'account runtime e non è invocabile dalle API. La tabella temporanea viene eliminata al commit/rollback e non modifica lo schema applicativo.
4. I controlli funzionali preesistenti (`current_user` owner, Comune sospeso con audit, uno e solo uno Admin attivo, nessun residuo Reader/Officer del principal compromesso, collisioni, lock `organizations ... FOR UPDATE`, doppio audit atomico, idem retry, divieto riattivazione) restano **immutati**. Tutti i dati sono ancora validati nel `DO` server-side con errori statici. Si continua ad auditare l'azione, l'actor e il ticket, usando fingerprint pseudonimi e senza issuer/sub in chiaro.
5. TDD: test statico rifiuta ogni `:'emergency_*'` e richiede COPY+temp; test xUnit/PostgreSQL con `PGOPTIONS='-c log_statement=all ...'` usa un subject sentinel, legge i **log effettivi del container PostgreSQL 17 della CI** e richiede che il COPY statement sia presente ma il subject no. I test Python stdlib sulla allowlist convalidano un record CSV/base64, round-trip di stringhe SQL-like, rifiuto di input mancanti/eccessivi ed errore senza echo; tutti i precedenti test RS256/OIDC, audit, concurrency, RLS e Playwright restano gate.
6. Fuori scope: migrazione degli altri script owner-only (bootstrap, enrollment, revoca, platform operator, lifecycle, provisioning, signing material) e inventario/compliance dei sistemi di audit. **La #86 resta aperta** per tali percorsi, verifica logging reale, RLS, Key Vault, SIEM e privacy review. **La #84 resta aperta** per identity proof e doppia approvazione IdP reale.

## Garanzie e limiti operativi

Nella configurazione testata (PostgreSQL 17, `log_statement=all`) il server registra la query statica `COPY ... FROM STDIN` e il codice SQL di policy, non un `SELECT set_config(..., 'subject')` con il subject in chiaro. **Questa non è una garanzia universale di assenza di dati nei log**: altri logger/estensioni, `COPY` error details, tracce di rete, psql debug, process tracing, SQL audit con payload e dump di memoria possono includere valori o il base64 reversibile. TLS, configurazioni effettive di log, retention, accessi e regole privacy/SIEM vanno verificati sul deployment reale, insieme a corretta identificazione degli approvatori, prima di permettere uso con PII.

Non disattivare logging di sicurezza per nascondere incidenti; mantenere audit append-only owner-only e correlazione incidente. Non invocare Python direttamente in terminale e non acquisire/copiare stdout della sua sorgente segreta. Se Python, il checkout o il `COPY` falliscono, `psql -v ON_ERROR_STOP=1` deve interrompere e rollback della transazione senza alcun grant Admin. Le vecchie procedure non migrate **non diventano sicure** per effetto di questa ADR.

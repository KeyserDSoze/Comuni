# ADR 0078 — Enrollment Admin OIDC owner-only tramite COPY privato e log SQL senza issuer/sub letterali

- Data: 2026-11-18.
- Stato: **Accepted per incremento sintetico/offline**; non autorizza operazioni amministrative su identità reali prima delle verifiche P0 #86 e #84.
- Issue: #94 (sotto-issue #86), mantiene #87 e ADR 0077; riusa il canale già definito nell'ADR 0073 (#88).
- Specifiche: [psql `\\copy`](https://www.postgresql.org/docs/17/app-psql.html), [PostgreSQL COPY](https://www.postgresql.org/docs/17/sql-copy.html), [logging PostgreSQL 17](https://www.postgresql.org/docs/17/runtime-config-logging.html).

## Motivo della modifica

La revisione #87 ha conservato `SELECT set_config('comuni.add_admin_subject', :'add_admin_subject', true)` in `enroll-additional-admin.sql`. Il quoting `psql` evita injection ma serializza il valore dell'issuer/sub nel testo SQL PostgreSQL. Il server lo può registrare sotto `log_statement=all` o in audit SQL; nasconderlo solo nello stdout `psql -q` non è sufficiente. L'helper già introdotto per l'emergenza (#88) consente di trasportare il valore dall'ambiente *privato del client* usando `\\copy` e il protocollo COPY, senza convertirlo in literal SQL.

## Decisione e confini

1. **Solo enrollment owner-only.** Aggiornare `scripts/postgres/enroll-additional-admin.sql`; mantenere i guard #80/#83/#87, il lock sulla riga organization, lo stato active, le verifiche sulle revoche ordinarie/emergency e i due audit accoppiati, i blocchi su replay/collisione e l'INSERT audit atomico. Non aggiungere endpoint, claims, privilegi, schema, migrazioni o feature flags. Il login `comuni_app_runtime` rimane non autorizzato.
2. Creare nella **transazione esistente** una tabella `pg_temp.comuni_private_input(payload text NOT NULL) ON COMMIT DROP`; invocare soltanto la stringa statica `\\copy ... FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py add-admin' WITH (FORMAT csv)`. L'helper locale accetta solo cinque environment variables `COMUNI_ADD_ADMIN_*` già richieste; in caso di missing, empty o input >1024 byte deve fallire prima di emettere qualsiasi riga, con errore **costante** senza echo né traceback. L'helper non legge o inoltra tutto l'ambiente del runner.
3. La riga unica trasporta `base64(JSON)`, decodificata nella query server-side **statica** `convert_from(decode(payload, 'base64'), 'UTF8')::jsonb` e passata ai cinque `set_config` transaction-local mediante `secret ->> 'KEY'`. Non compariranno più interpolazioni `:'add_admin_*'` nel testo SQL; `\\getenv` resta un preflight lato client e non converte il valore in SQL. L'owner-only `DO` continua a validare stringhe e autorizzazioni come prima.
4. **Base64 non è crittografia**: il payload è leggibile dalla sessione PostgreSQL e dai processi client/DB in memoria, da dump, da un proxy che catturi il protocollo COPY o da logging di payload. Usare `psql -X -q -v ON_ERROR_STOP=1`, **mai** `-a/-e`, shell tracing, stampa dell'helper, command string dinamiche o materiale reale in CI. Il client `psql` deve avere come working directory un **checkout fidato della root del repository**. Connessione PostgreSQL TLS con cert/hostname validati, credenziali owner temporanee, approvazioni e log accessibili solo a operatori autorizzati.
5. Non attenuare `log_statement` o `pgAudit` per nascondere i rischi. I test xUnit/PostgreSQL 17 con `PGOPTIONS` impongono `log_statement=all` e massima conservazione parametri e acquisiscono soltanto in memoria i log **reali** del service container; richiedono `statement: COPY` e assenza di un subject canary. Il test Python stdlib in CI richiede SQL senza literal, allowlist exact, round-trip di una stringa SQL-like e fallimento sanitizzato. NON pubblicare log server grezzi anche in caso di fallimento.
6. I test di regressione dell'Admin (bootstrap, secondo Admin, revoca, emergency, enrollment dopo riattivazione) e il resto della CI rimangono bloccanti. Test-first RED commit #94 antecedente al cambiamento SQL; completamento soltanto con **7/7 job verdi sullo stesso SHA di main**. Le fixture che usano lo script risolvono `WorkingDirectory` dalla root del repository.

## Fuori scope e responsabilità

Il resto degli script (bootstrap iniziale, revoca, lifecycle, platform operator, onboarding organizzazioni e altri owner-only) usa ancora approcci non interamente migrati: **#86 resta aperta**. Una prova nel container PostgreSQL 17 con `log_statement=all` NON certifica che pgAudit Azure, SIEM, log errori, proxy, tracce dei payload COPY, backup, IdP reale o audit esterno non conservino dati: richiedono verifica sul deployment e approvazione Security/Privacy. Le stringhe ticket/reviewer non autenticano la persona, e non sostituiscono MFA, controllo a quattro occhi e revoca sessioni IdP (#84). I digest `md5(org|Admin|sub|issuer)::uuid` sono pseudonimi, non dati anonimi per GDPR. In caso di qualsiasi dubbio lasciare il Comune sospeso e bloccare il change.

## Estensione distinta: bootstrap iniziale (#95 / ADR 0079)

Il riferimento al bootstrap iniziale come script *non migrato* era corretto alla data di questo ADR. La #95 / ADR 0079 ha successivamente riutilizzato il canale COPY per il **primo** Admin OIDC, preservando un'altra policy di authorization; la #86 resta aperta per revoca, lifecycle, altri owner-only e verifiche Azure/SIEM. Non confondere i due workflow né la loro approvazione umana.

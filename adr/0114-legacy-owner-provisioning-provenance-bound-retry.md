# ADR 0114 — Retry del provisioning legacy legato al ticket originario e all'audit owner

- Data: 2026-11-20
- Stato: Accepted per test sintetici PostgreSQL 17/psql in CI; NON autorizza onboarding live
- Issue: #130; epiche #3 (Core), #4 (audit), #5 (sicurezza tenant)
- Relazioni: ADR 0026 (provisioning legacy), ADR 0085 (trasporto COPY privato), ADR 0086 (nuovo Comune pending), ADR 0112 (catalogo moduli). Il percorso canonico è `scripts/postgres/register-organization.sql`.

## Contesto / gap

Il retry owner-only in `scripts/postgres/provision-organization.sql` accettava un Comune già presente se nome, riga `protocol` e un singolo evento `platform.organization.created` con resource type/id corretti erano presenti. **Non verificava** che l'evento fosse stato registrato dal proprietario SQL né che il suo `correlation_id` fosse `bootstrap:<change ticket presentato nella nuova richiesta>`. Una seconda richiesta con lo stesso ID/nome e **ticket diverso** terminava con successo senza cambiare righe; questo avrebbe potuto essere interpretato erroneamente come conferma di un change non corrispondente a quello originale. Anche una riga owner/manuale con audit somigliante ma attore errato poteva essere adottata come retry.

## Decisione

1. Lasciare invariato il percorso canonico `register-organization.sql` e il ramo che crea un nuovo Comune (`is_suspended=FALSE`, `is_activated=FALSE`, nessuna membership, un'unica riga `protocol` con flag FALSE, evento `platform.organization.created` con `actor_subject='db-owner:' || current_user`, `correlation_id='bootstrap:' || v_ticket`).
2. Nel ramo **retry** del vecchio script, dopo advisory lock UUID e `SELECT ... FOR UPDATE` su `platform.organizations`, verificare in transazione **esattamente un evento `created`** appartenente a quella organization/resource/type e **esattamente un evento corrispondente** sia al ticket corrente (`bootstrap:` + ticket) sia all'attore schema-owner corrente (`db-owner:` + `current_user`). Il modulo Protocollo deve essere presente; il nome deve coincidere esattamente. Un record legacy/manuale senza provenance coerente, un altro ticket, o due eventi originari **falliscono fail-closed**.
3. Per un **retry realmente identico** lasciare invariato il no-op: mai reimpostare flag Protocollo, memberships, stato active/suspended, nome o audit. Le verifiche di syntactic UUID, ticket, approver, nome e proprietario SQL sono invariati. La procedura **non controlla** l'esistenza del change in un sistema autorizzativo esterno: tale approvazione indipendente deve precedere ogni esecuzione.
4. Nessun log o errore contenente identificativi: errore fisso, guard `pgaudit.log_parameter=off` prima del COPY; i quattro input vengono trasportati come `\copy ... FROM PROGRAM` con busta privata client-side base64(JSON) reversibile; nessuna interpolazione SQL di variabili client. Non si introducono grants runtime, nuova tabella, migration EF, API, ruolo Superadmin o azioni Azure. Un DBA/schema-owner malevolo può falsificare audit e approvazioni: **non** affermare che il controllo provi una firma o la realtà del mandato.
5. TDD xUnit con PostgreSQL17 e `psql` reali: RED dimostra **successo errato** dello stesso id/nome con ticket B e di una riga manuale con evento `created` ma attore non-owner, nonostante ticket A coerente; GREEN richiede rifiuto nonzero senza cambiare alcun dato e senza esporre canary privati. Retry corretto e continuazione `created → first Admin OIDC synthetic → active` devono continuare a funzionare. Chiudere solo con GitHub Actions **7/7 success sul medesimo SHA HEAD `main`**.

## Limiti

Il controllo è un vincolo di **coerenza provenance interna**, non un registro probatorio, una validazione di approvazione o di reviewer indipendente, una garanzia GDPR/AgID o una protezione contro un database owner compromesso. Non si memorizza né verifica l'identità del reviewer e **non** si pretende di riconoscerla. Il comando `register-organization.sql` rimane preferibile e i 11 domini `planned` restano inattivi. Nessuna operazione su Azure, Comuni reali, Key Vault o identità OIDC reali. #3/#4/#5/#84/#86/#92 rimangono aperte.

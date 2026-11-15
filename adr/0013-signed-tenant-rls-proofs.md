# ADR 0013 — Tenant proof HMAC per RLS, chiave privata nel database

- Stato: Accepted come incremento della #18; il go-live resta bloccato da #5/#6 e da review di sicurezza completa
- Data: 2026-11-15
- Integra e supera la custom GUC dell'ADR 0012
- Fonti: PostgreSQL 17 https://www.postgresql.org/docs/17/pgcrypto.html ; https://www.postgresql.org/docs/17/sql-createfunction.html ; https://www.postgresql.org/docs/17/ddl-rowsecurity.html

## Problema e threat model

La policy RLS introdotta in #17 confrontava `organization_id` con `current_setting('comuni.organization_id')`. Qualsiasi SQL arbitrario eseguibile come `comuni_app_runtime` poteva cambiare tale setting e selezionare un altro Comune, vanificando l'isolamento. La minaccia da mitigare qui è **SQL injection con poteri di eseguire query sotto il login PostgreSQL runtime, ma senza accesso alla memoria applicativa né alle chiavi di Key Vault/owner DB**. Un processo ASP.NET compromesso, un utente già autorizzato a più tenant con assertion esposte, DBA/superuser e attacchi su rete/log sono minacce ulteriori.

## Decisione

Manteniamo una sola API, un solo React e un unico PostgreSQL con un login SQL runtime non owner. L'API, dopo validazione JWT, genera una prova breve `tenantId:N|expiresUnix|nonce:N|HMAC_SHA256` mediante una chiave random di almeno 32 byte dal Key Vault. La firma viene calcolata esclusivamente nel processo API. `TenantDatabaseTransaction` crea una transazione e imposta tramite parametro SQL `comuni.tenant_assertion` **SET LOCAL**; niente key/plaintext secret in SQL runtime, JWT, body API o browser.

La migration `202611150006_SignedTenantRlsProof` installa `pgcrypto`, una tabella `platform.tenant_proof_secret` leggibile solo dall'owner, e una funzione `platform.verified_tenant_id()` `SECURITY DEFINER`, search_path fissato su schemi fidati, che calcola HMAC e verifica scadenza prima di ritornare UUID. Le policy `USING`/`WITH CHECK` delle 5 tabelle tenant-owned confrontano il proprio tenant con **questo UUID verificato**, non con la GUC vecchia. Un `GRANT EXECUTE` esplicito abilita il verifier al solo `comuni_app_runtime`; nessuna funzione di signing SQL è esposta, nessun SELECT/UPDATE alla tabella della chiave. Secret dell'API e DB sono installati da due percorsi con credenziali separate, e DEV seed è soltanto per demo.

## Conseguenze e rischi

**Beneficio misurabile:** impostare arbitrariamente una GUC SQL unsigned, presentare MAC fasulli o scegliere UUID di un altro Comune in query non permette più a SQL sotto l'account runtime di leggere righe cross-tenant, in assenza di una proof valida per quel tenant. Niente stato dopo commit/rollback/pool. Previsti test reali in CI su PostgreSQL 17 con login non owner.

**Rischi residui e ipotesi operative:**
- Una SQL injection che ottenesse una **prova valida di un altro tenant** potrebbe ripeterla fino alla scadenza (finestra di tre minuti); compromettere il processo app o la chiave renderebbe possibile firmare qualsiasi tenant. Non è una difesa contro RCE/compromissione DBA o secret store.
- `SECURITY DEFINER` richiede audit di owner, search_path, temp schema, GRANT EXECUTE e versioni pgcrypto; un errore potrebbe creare escalation. La verifica del MAC non promette resistenza timing-side-channel crittografica in PostgreSQL.
- L'estensione `pgcrypto` va abilitata in Azure Flexible Server; i nuovi segreti rendono bootstrap e **rotazione zero-downtime** non banali, dato che versioni diverse dell'app e del DB potrebbero usare chiavi discordanti. Non implementiamo doppia chiave/rotation protocol in questo incremento.
- Tenant claims da IdP reale, access control, foreign-key side channels, connessioni multiple, prepared statements, pool saturation, estensioni e nuovi domini richiedono ulteriori test/threat modeling. La #5 e la #6 restano aperte; la #18 può essere chiusa solo con test avversariali e review dei requisiti originari.
- Un deployment Azure reale e la conformità di settore/GDPR/AgID **non sono stati verificati**. La CI usa esclusivamente PostgreSQL di test e chiavi chiaramente non-produttive.

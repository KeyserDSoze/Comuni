# Strategia TDD e verifica

Il bootstrap è sviluppato in due incrementi registrati su `main`: specifiche/test iniziali (RED) e codice implementativo (GREEN/Refactor). Le dipendenze .NET e browser Playwright devono essere presenti per la verifica effettiva.

## Matrice minima
| Livello | Caso | Atteso |
| --- | --- | --- |
| Domain | subject vuoto | errore |
| Domain | creazione record | organization non vuota e invariant validi |
| Business | modulo non attivo | use case bloccato |
| Business | list | organization passata esplicitamente |
| API/PostgreSQL | JWT assente | 401 |
| API/PostgreSQL | Reader scrive | 403 |
| API/PostgreSQL | isolamento tra tenant | nessuna lettura incrociata |
| API/PostgreSQL | feature flag disabilitato | 403 |
| Domain | membership valida/invalida e disattivazione | invarianti rispettati |
| API/PostgreSQL | JWT Admin con membership Reader | scrittura 403, context ruolo Reader |
| API/PostgreSQL | membership assente o disattivata | 403 |
| API/PostgreSQL | subject solo nel tenant A usa token per tenant B | 403 |
| API/PostgreSQL | JWT Reader ma membership Officer | scrittura consentita dal ruolo DB |
| Domain | AuditEvent valido, campi obbligatori e minimizzazione | invariant rispettati |
| Business | registrazione associa record a evento audit | stessa organization e resource ID |
| API/PostgreSQL | POST Protocollo riuscita | 1 AuditEvent con actor e correlation del server |
| API/PostgreSQL | tentativi UPDATE/DELETE audit | trigger rifiuta la mutazione |
| API/unit | Production + DevelopmentJwt | startup rifiutato |
| API/unit | Authority OIDC non HTTPS o Audience mancante | startup rifiutato |
| API/integration | RS256 trusted OIDC JWKS locale | 200, membership da PostgreSQL |
| API/integration | issuer, audience, alg HS256 o scadenza errati | 401 |
| API/integration | OIDC valido ma membership assente/Reader che scrive | 403 |
| Frontend/E2E | menu per moduli | menu condizionale |
| Frontend/E2E | accesso Reader | niente azione di creazione |

## Esecuzione
`dotnet test tests/backend/Comuni.UnitTests` per test rapidi.
`TEST_DATABASE_CONNECTION="Host=localhost;Port=5432;Database=comuni_test;Username=comuni;Password=..." dotnet test tests/backend/Comuni.Api.Tests` per integration con PostgreSQL reale.
`npm install && npx playwright install --with-deps chromium && npm run build --workspace @comuni/frontend && npm run test:e2e --workspace @comuni/frontend`.
GitHub Actions ripete queste verifiche con PostgreSQL service.

| Business/unit | modulazione Admin: modulo sconosciuto, tenant vuoto, audit, no-op | fail-closed / un evento al cambio |
| API/PostgreSQL | Admin elenca/attiva/disattiva Protocollo | stato persistito, API Protocollo 403 quando disattivata |
| API/PostgreSQL | Reader/Officer e JWT con ruolo Admin ma membership Reader | 403 su GET/PUT admin |
| API/PostgreSQL | tenant spoofing da body | secondo Comune invariato |
| API/PostgreSQL | flag già nel valore richiesto | nessun audit aggiuntivo |
| E2E/Playwright | pagina Amministrazione e toggle | visibile solo ad Admin, menu aggiornato, errore visibile su fallimento |

## Test HTTP security (#15)

- Configurazione del limiter: valori invalidi su permit e finestra fanno fallire l'avvio.
- Partizione: un IP dichiarato via `X-Forwarded-For` non aggira la quota; per JWT autenticato il bucket è differenziato per `organization_id` + `sub`.
- Tre richieste API anonime consentite nel fixture di test, la quarta è `429` con `Retry-After`, anche se il client cambia `X-Forwarded-For`.
- Health check `/health/live` non è soggetto al limiter; response headers presenti anche sulle risposte 401; risposte API hanno `Cache-Control: no-store`.
- Tutte le altre verifiche su modulo, ruolo e isolation continuano nella suite di regressione. Test e build nel workflow CI.

## Verifica least-privilege DB (#16)

Il job backend di CI usa PostgreSQL 17, applica migrazioni EF come owner, esegue **due volte** `scripts/postgres/provision-runtime-role.sql` e passa una seconda stringa di connessione `TEST_RUNTIME_DATABASE_CONNECTION` ai test xUnit. Il test `RuntimeDatabasePrivilegesTests` verifica esplicitamente login non amministrativo, privilegi DML per tabella e colonna, blocco di DDL, update di organization e memberships, audit già persistito e lettura della history EF. Un test EF con la connessione **reale del runtime** legge organization/flag/membership e scrive record Protocollo e audit nella transazione attuale. Sono in parallelo i test API/PostgreSQL ordinari con owner di CI, perché devono migrare e seminare dati; il job Azure con rete privata rimane fuori scope.

## PostgreSQL RLS + pooling (#17)

La CI migra lo schema con l'owner, provisiona il login limitato e verifica: `pg_class.relrowsecurity` attivo su cinque tabelle, query SQL **senza contesto** che vedono zero righe sotto `comuni_app_runtime`, `SET LOCAL` che seleziona una sola organization, tentativi di INSERT cross-tenant negati (SQLSTATE `42501`), UPDATE cross-tenant che modifica zero righe, e reset dopo commit/riuso connessione. Un fixture HTTP usa **la stringa runtime limitata** per verificare context e POST/GET Protocollo con middleware tenant. Le restanti suite xUnit e Playwright restano regressione; vedere ADR 0012. I test non dimostrano resistenza a SQL injection: la GUC custom è impostabile dallo stesso ruolo.

## Test di bypass RLS e prove HMAC (#18)

- RED: `set_config('comuni.organization_id', diversoComune, true)` in SQL diretto sotto `comuni_app_runtime` non deve vedere alcuna riga; assertion fabbricata con HMAC falso non dà accesso.
- Unit: proof temporaneo con tenant, nonce casuale, scadenza e firma HMAC; fail-fast senza segreto sicuro.
- PostgreSQL 17: login runtime non può `SELECT platform.tenant_proof_secret`; la funzione SECURITY DEFINER verifica una prova valida senza esporre il secret; ALTER/DDL e cross-tenant INSERT/UPDATE rimangono negati; commit/rollback/pooling non propagano proof tra Comuni.
- HTTP: login JWT + membership effettiva + API Protocollo sotto ruolo runtime limitato; audit transazionale.
- La CI deve applicare migration `202611150006`, provisionare il segreto tramite script `psql`, poi assegnare EXECUTE al runtime.
- I test non costituiscono un penetration test completo; funzione, key rotation, logging e minacce oltre SQL injection devono essere rivalutati prima della produzione.

## Key Vault secret fuori Terraform State (#21)

Il job Terraform CI dopo `terraform validate` esegue `python3 -m unittest discover -s tests/infra -p 'test_*.py' -v` senza account Azure: i test verificano l'assenza della variabile/risorsa che scriveva la chiave HMAC nello state, il blocco `removed` non distruttivo, la sola reference versionless, la rimozione dell'env `TF_VAR_tenant_proof_key` e il preflight prima del `terraform plan`. Una CLI `az` simulata verifica presenza/enabled, disabled, missing e input non valido senza chiedere il valore del secret. I test non coprono la propagazione di Key Vault in Azure, la rotazione della chiave PostgreSQL o il rilascio multi-replica in VNet: #19 e #6 restano aperte.

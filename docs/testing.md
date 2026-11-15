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

## Riferimento pinned Key Vault version e preflight metadata-only (#22)

CI Terraform: `tests/infra/test_tenant_secret_version.py` più regressione `test_tenant_secret_boundary.py`. I contratti verificano: variabile Terraform `tenant_proof_secret_version` obbligatoria, Key Vault URI **versionato**, passaggio della versione dall'Environment al Terraform e allo script, blocco di versioni errate, mancanti o disabilitate. La `az` simulata richiede `secret list-versions` con filtro per URI/version esatti; `secret show` è proibito perché potrebbe recuperare anche il valore. Il test Azure reale richiede account e Key Vault configurati e **non** è stato eseguito. xUnit/PostgreSQL, Playwright, Terraform e Docker devono essere verdi insieme per chiudere #22.

## Staging ACA 100% stable / 0% candidate (#23)

I nuovi test `tests/infra/test_staged_rollout.py` verificano con fixture sintetici (senza credenziali Azure) che Terraform dichiari **Multiple**, suffix stable/candidate distinti, pesi 100/0, min replica candidato 1, secret stabile intatta e nuova secret app-scoped versionata usata dal template. Il gate `scripts/azure/check-staged-rollout-plan.py` è esercitato con JSON accettato e rifiuti di assenza prima installazione, creazione/distruzione/replacement, modifica/rimozione di secret già presenti, mismatch versione/key ID e promozione latest. Il gate rifiuta anche la distruzione di altre risorse nel piano. Il job CI Terraform esegue questi test insieme a quelli Key Vault #21/#22, e gli altri job xUnit/PostgreSQL, React/Playwright e Docker restano regression gates. Il test CI **non** dimostra che un piano su una subscription Azure reale produca la stessa struttura: la verifica live va effettuata prima del primo apply.

## Test Azure revisioni reali con fake CLI (#24)

`tests/infra/test_live_revision_verification.py` crea una `az` simulata e prova le tre chiamate metadata-only del verificatore, il caso valido (due revisioni Healthy, numero repliche, immagine esatta, key ID e secret pin corretto, stable 100% / candidate 0%), nonché fail-closed per candidate/stable assente, revisioni duplicate, unhealthy, Failed/Degraded, replica zero, immagini errate, key ID o secret reference sbagliati, autopromozione o terze regole di traffico, errori CLI, mode Single e input non validi. Gli output stdout/stderr della CLI non sono riportati in log applicativi e non vengono chiamati comandi di mutazione del traffico. La CI copre lo script solo con **metadati simulati**: la verifica live Azure tramite `az containerapp revision list`/traffic show verrà eseguita soltanto in un futuro stage autorizzato in subscription (#6/#19).

## Label canary 0% e smoke OIDC/RLS read-only (#25)

I test `tests/infra/test_staged_rollout.py` e `test_live_revision_verification.py` ora richiedono una **label candidata identica al suffix immutabile** solo nella regola latest a peso 0, non sulla stable a 100%; il gate Terraform plan e il verifier metadata Azure falliscono per label errata o mancante.

`tests/infra/test_candidate_smoke.py` usa un opener HTTP mock (nessun token o account Azure reale) per verificare `validate_candidate_url` e `run_smoke`: URL HTTPS `<app>---<label>.<approved environment domain>` senza userinfo, query, fragment o port diversi, nessun redirect, token A/B distinti passati **solo in Authorization** e mai negli URL, soli GET, contesti tenant coerenti e marker synthetic A/B isolati in Protocollo. Dati mancanti o incrociati, JSON corrotto, status non attesi e token ripetuti fanno fallire il test; output non include token o subject. Per l'esecuzione live servono credenziali OIDC reali, due Comuni sintetici e runner approvato. CI e Terraform validate **non sono una verifica Azure reale**.

## OIDC browser Authorization Code + PKCE (issue #26)

La CI esegue `BrowserOidcSettingsTests` (xUnit): demo mode disabilita il browser OIDC, produzione senza valori completi disabilita accesso senza fallback JWT, validazione HTTPS e stesso host authority, scope API delegato + `openid`, rifiuto di `offline_access`, client secret, endpoint con credenziali/query, endpoint insicuri, e `GET /api/v1/auth/browser` anonimo. Il client React è coperto da `tests/frontend/oidc-login.spec.ts`: provider mock HTTPS, Authorization Code + PKCE S256/verifier, stato casuale, POST token con URL callback esatta, scelta del solo access token, rifiuto `state` contraffatto, URL callback pulita, logout e impossibilità di incollare JWT in modalità Oidc non configurata. I test precedenti di dashboard/admin usano l'esplicita modalità `DevelopmentJwt` mock e continuano a verificare le autorizzazioni UI.

Tutti i test OIDC client sono **offline/mock**. Non dimostrano che un IdP reale accetti il redirect, supporti CORS o emetta access token con organization_id e audience, né sostituiscono MFA/provisioning o sicurezza SPID/CIE. I test JWT RS256 backend/PostgreSQL già esistenti validano separatamente il consumo di token, non un flusso provider live.

## Membership Reader/Officer Admin, audit e PostgreSQL RLS (#27)

Il TDD include `MembershipAdministrationTests` (dominio/Business), `MembershipAdministrationApiTests` (PostgreSQL reale: 401 anonimo, 403 Reader/Officer e JWT role spoof, isolamento di due Comuni, aggiornamento immediato membership, validazione ruoli, niente Admin grant, no-op e audit server-originated), `RuntimeDatabasePrivilegesTests` (role allowlist, INSERT/UPDATE colonnari, RLS RESTRICTIVE che nega un INSERT Admin **anche con firmata tenant assertion valida**) e `tests/frontend/admin-memberships.spec.ts` (Admin visualizza/gestisce roster, Admin read-only, Reader senza accesso, errore backend non modifica UI). Il job CI esegue migrazioni DB con ruolo owner, provisioning runtime in PostgreSQL, integrazioni xUnit, React/Playwright, Terraform e Docker. L'esito può essere dichiarato completato solo con tutti i job verdi sul commit `main` finale.

Limitazione: test con JWT DevelopmentJwt e soggetti sintetici; non confermano provisioning o presenza dei nuovi subject in un IdP, inviti, email, MFA, revoca di sessione e audit esterno.

## Identity issuer binding OIDC (#28)

TDD: in `OidcApiTests` un token RS256 con issuer attendibile e membership `identity_issuer` corrispondente legge il contesto; con stesso tenant e `sub` ma issuer NULL o diverso torna **403**, con `iss` JWT non attendibile torna 401. L'Admin OIDC con membership collegata crea Reader con issuer da JWT; i campi `identityIssuer`/`issuer` falsificati nel body vengono ignorati. Il tentativo di riassociare una membership NULL/dell'altro provider produce 409 senza modificare il DB. I test PostgreSQL runtime verificano i permessi INSERT colonnari per issuer, il rifiuto di `UPDATE identity_issuer` (42501) anche con HMAC tenant valida e la RLS che impedisce l'Admin; xUnit domain prova il formato HTTPS. Playwright mostra issuer nel roster e nessun input per modificarlo. Compatibilità demo DevelopmentJwt su membership legacy e le vecchie policy restano verificate dagli altri test.

Tutti i provider OIDC di CI sono **simulati con chiave RSA locale**: nessuna identità del mondo reale, nessun IDP live o Azure. La CI verde non sostituisce test di provisioning con provider effettivo, modifica/rotazione issuer o audit di operatore durante i backfill.

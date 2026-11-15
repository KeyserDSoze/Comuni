# ADR 0034 — Smoke read-only a tre identità del candidato ACA per inventario Superadmin

- Stato: Accepted come tooling manuale con test **offline**; non attesta staging Azure, MFA o autorizzazioni reali (#40)
- Data: 2026-11-16
- Dipendenze: ADR 0019, 0028–0033; issue #2/#5/#6/#10/#19/#37/#38/#40
- Riferimenti: [Azure Container Apps revision labels](https://learn.microsoft.com/en-us/azure/container-apps/revisions), [Azure Container Apps networking](https://learn.microsoft.com/en-us/azure/container-apps/networking), [RFC 9700 OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700)

## Problema

La #38 permette di predisporre una candidata Azure Container Apps 0% con inventario globale read-only, dopo provisioning owner-approved del login PostgreSQL separato. L'ADR 0019 dispone già di `smoke-candidate-oidc.py` che prova la RLS di **due identità comunali**, ma non le policy della console Superadmin, la segregazione della sessione senza `organization_id`, la proiezione globale a soli 4 campi o la paginazione. Health 200 o `terraform validate` non dimostrano l'isolamento delle tre identità. Non è ammissibile inserire un JWT Superadmin permanente nei Secrets del workflow o consentire al runner di emettere/ottenere token senza il processo di approvazione IdP.

## Decisione

1. Aggiungere un **secondo tool manuale separato** `scripts/azure/smoke-candidate-platform.py`: riutilizza il validatore URL ACA canonico e la policy HTTPS/TLS CA/no-redirect del tool ADR 0019, ma interroga solo endpoint **GET**. Tre access token OIDC brevi, **distinti**, ottenuti esternamente per due soggetti di Comuni sintetici e un operatore Superadmin senza tenant, arrivano soltanto come `COMUNI_SMOKE_OIDC_TOKEN_A`, `_B`, `_PLATFORM` nella memoria del runner privato. Non accetta credenziali dal CLI, URL/query, argomenti del browser o repository e non tenta OIDC token exchange. Lo script è read-only e non esegue né impersonificazione né revoca del roster.
2. **Host e trasporto stretti:** l'origine HTTPS deve essere esattamente la label immutabile `https://<app>---<r+sha12>.<ACA environment domain approvato>`, verificata a monte contro i metadati Azure e dopo il gate 100% stabile/0% candidata. Niente redirect o proxy ambientali; TLS su CA standard, timeout, size cap e JSON parsing con rifiuto di chiavi duplicate. Qualunque errore stampa soltanto un messaggio generico, mai JWT, subject/issuer, nomi o UUID dell'inventario.
3. **Verifica incrociata obbligatoria:**
   - `/health/ready` anonimo 200;
   - `/api/v1/platform/session`: anonimo **401**, comunale A **403**, comunale B **403**, operatore platform **200** con esattamente `{"role":"Superadmin"}`;
   - `/api/v1/context`: operatore platform **403** (nessuna membership fittizia nel Comune);
   - `/api/v1/platform/organizations?limit=2`: anonimo **401**, comunale A e B **403**, platform **200** con paging.
4. **Output minimizzato e scansione limitata**: ogni pagina deve avere esattamente `organizations` e `nextCursor`, ognuna al massimo 2 righe `id,name,isSuspended,protocolEnabled` e nessun campo aggiuntivo (roster/audit/documenti/token). UUID v4 canonici/non nulli, booleani, nome non vuoto/max 200 e senza caratteri di controllo. UUID strettamente crescenti, nessun duplicato, `nextCursor` coerente con ultima riga, massimo **20 pagine (40 righe)**; i due UUID sintetici approvati devono comparire entrambi. Se il dataset supera il limite, **fallire**; il tool non è un enumeratore di produzione. I nomi vengono controllati in RAM ma non conservati o loggati.
5. **Revoca e audit restano una verifica manuale distinta:** lo script non esegue owner-only `revoke` per evitare mutazioni su identità reali o di collaudo. Il change approvato deve verificare esternamente che una revoca DB faccia passare la richiesta API successiva a 403 e che le pagine riuscite abbiano audit pseudonimo globale con correlation. Uno smoke GET, anche verde, non prova app-side audit al database né la validità della verifica RSA/JWKS dell'IdP reale.
6. **TDD e CI:** RED `tests/infra/test_candidate_platform_smoke.py` con risposte HTTP fake e scenari di challenge OIDC, 403 cross-role, JSON non conforme, duplicati, leak, cursori, URL host errato e token identici; GREEN script manuale; full CI 7/7. Nessun Azure CLI, Key Vault value, token reale o runner VNet viene usato nei test. `Deploy to Azure` **non** esegue automaticamente lo smoke: prima servono IDP/MFA, credenziali SQL e segreti Key Vault approvati dal proprietario.

## Alternative scartate e limiti

Unire questo percorso alla smoke dei due tenant o a `terraform apply` introdurrebbe un rischio di distribuzione automatica e confonderebbe i contesti. Accettare URL non confrontato ai metadati ACA permetterebbe esfiltrazione dei tre token. Aggiungere SELECT dei record personali o invocare endpoint di mutazione durante la smoke violerebbe il principio di minimizzazione. Il tool **non può** dimostrare che il token sia stato emesso da un IdP affidabile: lo verifica la API; il runner deve acquisirlo per una procedura esterna autorizzata, con attenzione al fatto che la label candidate è pubblicamente raggiungibile se l'ingress lo permette.

Il completamento di #40 dimostra soltanto la correttezza offline del tooling e dei contratti di sicurezza; **#38 resta OPEN** per provisioning PostgreSQL e Key Vault live, approvazione, deployment ACA 0%, verifica SQL reale, token IdP/MFA reali, audit, rollout/rollback e monitoraggio. Non dichiarare conformità normativa, zero-downtime o prontezza production.

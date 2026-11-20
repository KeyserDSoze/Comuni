# ADR 0111 — Partizioni rate limiter per identità composita issuer+subject

- Data: 2026-11-20
- Stato: Accepted per il Core single-API e per i test sintetici .NET; sicurezza distribuita da verificare
- Issue: #127 (collegata a #5, #2 e #10). Precedenti: ADR 0010 (HTTP API protection), ADR 0022 (identity OIDC issuer binding), ADR 0031 (PlatformOperator separato)

## Contesto / minaccia

Il limiter ASP.NET Core della API unica usa già `UseAuthentication()` prima di `UseRateLimiter()`. Però `ApiProtectionSettings.PartitionKey` costruiva `tenant:{organization_id}:{sub}` e ignorava il claim `iss` validato. Due identità con **stesso Comune e subject ma issuer diverso** condividerebbero una quota; inoltre tutte le identità piattaforma `iss+sub` senza `organization_id` ricadevano nella stessa partizione dell'IP (es. operatori Superadmin dietro NAT). Le quote non sono autorizzazioni, ma non devono accoppiare identità indipendenti. La API hosted oggi valida una sola Authority OIDC alla volta: il caso simultaneo multi-issuer è una difesa anticipatoria contro evoluzioni/migrazioni dell'IdP, **non** un exploit dimostrato nel deployment corrente.

## Decisione

1. Il parser centralizzato `VerifiedPrincipalIdentity.TryMunicipal` definisce l'identità comunale **esatta** `(organization_id, iss, sub)`; `TryPlatform` definisce l'identità tenantless **esatta** `(iss, sub)` con divieto di qualunque claim `organization_id`. Questi parser erano già condivisi da policy API, audit e RLS: non aggiungere header/route/body/claim di ruolo come autorità, né concedere privilegi di piattaforma tramite il limiter.
2. Creare due namespace di quota `tenant:<fingerprint>` e `platform:<fingerprint>`; la funzione comune serializza i componenti in forma case-sensitive con **prefissi di lunghezza** per impedire ambiguità da delimitatori (`iss=a:b,sub=c` contro `iss=a,sub=b:c`). Calcolare SHA-256 e usare esattamente 64 cifre hex minuscole; non incorporare `iss`, `sub` né l'UUID del Comune in chiaro nella chiave in memoria.
3. Principali anonimi, token invalidi, manca il singolo issuer/subject, duplicati anche identici, `organization_id` non-GUID o ambiguo tornano alla quota per **peer IP** della connessione; non fidarsi di `X-Forwarded-For`. Il ruolo `Superadmin` nel JWT non seleziona una quota platform senza autenticazione/identità strutturata. `PlatformOperatorHandler` resta obbligatorio per ogni endpoint Superadmin: il limiter **non** verifica l'appartenenza alla roster platform.
4. Limit, durata, 429, Retry-After, cache no-store, middleware order, esclusione di `/health` e asset statici, numero API/frontends e SQL invariati. I fingerprint sono per partizione locale in RAM; SHA-256 **non è anonimizzazione** e non è cifratura se le chiavi diventano visibili a log o telemetry. Non stamparle.
5. TDD test-first RED [`2f35291`](https://github.com/KeyserDSoze/Comuni/commit/2f35291a62d2ba03c5059e5a88f16f5d0332b9b5), [CI 44807542710](https://github.com/KeyserDSoze/Comuni/actions/runs/44807542710): **2 test falliti e 373 API test superati**, su issuer multipli e piattaforma tenantless. Correzione tipo `params` della fixture [`7f12a18`](https://github.com/KeyserDSoze/Comuni/commit/7f12a18fbc5e78537a3e004924f43d6d279abc43). Fix `b7b2777`, serializzazione invariant `2a799af`. Chiudere solo con **7/7 GitHub Actions success sullo stesso SHA HEAD main**.
   
## Limiti e rollout

Non è un limiter distribuito cross-replica/ACA, non protegge da bot che variano IP o possiedono molte identità firmate, non supplisce WAF/edge quota trusted proxy, non verifica un IdP reale federato multiplo, MFA, autorizzazione PlatformOperator, SIEM e policy GDPR. Scansioni e test CI dimostrano il contratto ASP.NET Core e la regressione, **non** un deployment reale Azure. Dipendenze #2/#5/#10 restano aperte.

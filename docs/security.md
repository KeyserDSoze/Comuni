# Sicurezza: baseline e gap obbligatori prima del go-live

## Baseline presente
- API con modalità di trust separate: `DevelopmentJwt` HS256 consentito **solo** in Development/Testing; in Production `Oidc` richiede Authority HTTPS, Audience, verifica firma asimmetrica RS256 tramite JWKS, issuer e lifetime. Non è consentito riutilizzare il segreto demo su Azure.
- Claim `organization_id` e `sub` esclusivamente dal token validato; autorizzazione contro membership attive **persistite in PostgreSQL** con ruoli `Admin`, `Officer`, `Reader`, indipendentemente dal claim `role` JWT.
- Policy API e controlli feature flag server side; isolamento tenant EF (query filter + guardia SaveChanges).
- Sospensione organization (ADR 0008, #14): una organization assente o sospesa riceve 403 per tutte le API protette, anche con JWT valido e membership attiva; la policy legge PostgreSQL a ogni richiesta. Nessun endpoint di gestione della sospensione è attualmente esposto.
- Token demo nel browser solo in RAM, nessuna persistenza in localStorage. Seed utenti/membership solo in ambiente Development.
- Azure: database su subnet privata, Key Vault, RBAC, Managed Identity, ACR con admin disabilitato.
- CI: unit test DDD e test API con PostgreSQL reale per cross-organization; E2E Playwright per autorizzazioni UI.
- **Audit iniziale (#11):** creazione di metadati del Protocollo con evento `protocol.record.created` nella stessa transazione PostgreSQL; solo actor, organization, action, resource ID, correlation e timestamp; niente subject del documento. Trigger del DB bloccano UPDATE, DELETE e TRUNCATE (ma non un superuser). Nessuna API di lettura audit in questa slice.

## Non ancora implementato — blocchi per produzione reale
- Il backend può **validare** access token OIDC ma mancano ancora il provider effettivamente collegato, login frontend con authorization code/PKCE o BFF, flussi SPID/CIE, onboarding/provisioning delle memberships per Comune, revoca sessioni, MFA e test contro un provider reale. La revoca di membership **blocca nuove autorizzazioni** ma non revoca di per sé JWT esterni.
- Audit di **tutti** gli eventi amministrativi e consultazioni sensibili; consultazione autorizzata, retention, accesso least-privilege e tamper evidence indipendente dal DB. L'evento iniziale del Protocollo **non** rende il sistema audit-complete o tamper-proof.
- Lifecycle completo organization e sospensione/riattivazione amministrativa con audit (#3/#10): il flag di sospensione è al momento soltanto una barriera API; nessuna console Superadmin lo gestisce.
- Rate limiting, security headers, threat modeling, OWASP ASVS, scansioni SAST/SCA e gestione vulnerabilità continuativa.
- Test end-to-end completi su Azure, segreti/chiavi ruotati, backup/restore verificati, monitoraggio e alerting.
- Policy GDPR, ruoli titolare/responsabile, minimizzazione e cifratura dati, retention, DPIA ove dovuta.
- Protocollo a norma, documenti, segnatura, fascicolazione, conservazione, interoperabilità AgID.
- PostgreSQL RLS come difesa in profondità, permessi DB least privilege al posto dell'account admin.
- Rete privata/endpoint Blob e Key Vault, firewall, WAF e policy aziendali da definire.

**Non trattare il modulo Protocollo demo come registro ufficiale né inserire dati personali reali.**

## Flusso amministrativo dei moduli — #13

Il ruolo `Admin` è conferito da una membership attiva e verificata lato backend tramite `OrganizationRoleRequirement`, non dal JWT. Solo l'organization autenticata può consultare/modificare la propria configurazione `protocol`; nessun override del tenant da route, header o body. Aggiornamento feature flag e audit sono transazionali, con esito immediato nelle verifiche backend. La UI filtra il menu ma non costituisce confine di sicurezza. Questa slice **non** abilita operazioni platform/Superadmin, né una gestione generalizzata di cataloghi e dipendenze: #3 e #10 rimangono aperte.

## Protezioni HTTP iniziali — issue #15

Le richieste `/api` sono limitate mediante il rate limiter **in memoria per replica** di ASP.NET Core con finestra fissa (default **120 richieste/60 secondi**), senza coda, 429 e `Retry-After`. Le richieste con JWT valido sono partizionate per coppia `organization_id` e `sub`; richieste anonime/non autenticate per IP della connessione **senza fidarsi di X-Forwarded-For**. Health check e asset PWA sono esclusi. Parametri `Security:ApiRateLimit:PermitLimit` (1–10000) e `Security:ApiRateLimit:WindowSeconds` (1–3600) hanno validazione fail-fast.

Risposte API incluse 401/403/429: `Cache-Control: no-store`, `Pragma: no-cache`. Tutte le risposte: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy` restrittiva, CSP con script/worker solo dalla stessa origine e `frame-ancestors 'none'`. La CSP consente ancora CSS inline (`style-src 'unsafe-inline'`) per compatibilità e richiede revisione con il frontend definitivo.

**Limiti obbligatori per il go-live:** con più repliche ACA la quota **non è globale**; istanze diverse non condividono contatori. Dietro reverse proxy l'IP visto da Kestrel potrebbe essere quello del proxy, con effetto di aggregazione sui client anonimi; non prendere mai `X-Forwarded-For` senza restringere i proxy fidati. Difesa DDoS, WAF, limiti edge, load test, proxy chain attendibile, HSTS e redirect HTTPS gestiti in frontiera richiedono configurazione/validazione Azure separata. Queste protezioni **non** risolvono PostgreSQL RLS e privilegi DB (resta aperta #5).

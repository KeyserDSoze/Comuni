# Sicurezza: baseline e gap obbligatori prima del go-live

## Baseline presente
- Token JWT con firma, issuer, audience e scadenza validati.
- Claim `organization_id` esclusivamente dal token validato; ruoli `Admin`, `Officer`, `Reader`.
- Policy API e controlli feature flag server side; isolamento tenant EF (query filter + guardia SaveChanges).
- Token demo nel browser solo in RAM, nessuna persistenza in localStorage.
- Azure: database su subnet privata, Key Vault, RBAC, Managed Identity, ACR con admin disabilitato.
- CI: unit test DDD e test API con PostgreSQL reale per cross-organization; E2E Playwright per autorizzazioni UI.

## Non ancora implementato — blocchi per produzione reale
- Federazione OIDC e flussi SPID/CIE, provisioning utenti e memberships autorizzate per Comune, revoche e MFA.
- Audit di eventi amministrativi e consultazioni sensibili; log privacy-safe e tamper evidence ove necessario.
- Rate limiting, security headers, threat modeling, OWASP ASVS, scansioni SAST/SCA e gestione vulnerabilità continuativa.
- Test end-to-end completi su Azure, segreti/chiavi ruotati, backup/restore verificati, monitoraggio e alerting.
- Policy GDPR, ruoli titolare/responsabile, minimizzazione e cifratura dati, retention, DPIA ove dovuta.
- Protocollo a norma, documenti, segnatura, fascicolazione, conservazione, interoperabilità AgID.
- PostgreSQL RLS come difesa in profondità, permessi DB least privilege al posto dell'account admin.
- Rete privata/endpoint Blob e Key Vault, firewall, WAF e policy aziendali da definire.

**Non trattare il modulo Protocollo demo come registro ufficiale né inserire dati personali reali.**

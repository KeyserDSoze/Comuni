# ADR 0004 — JWT per la vertical slice, OIDC per la fase successiva

- Stato: Superseded by ADR 0007 (solo modalità JWT demo in Development/Testing)
- Data: 2026-11-15

## Decisione
L'API valida JWT firmati HS256 con issuer e audience configurati; claim obbligatorio `organization_id` e ruolo applicativo. Il token demo è generato **fuori dall'API** tramite uno script CLI con chiave locale presente solo in sviluppo. Nessun endpoint di autenticazione anonimo che emetta token. **Aggiornamento (ADR 0007):** la modalità HS256 demo non può più essere usata in Production. In Production sono obbligatori Authority OIDC HTTPS e Audience e la validazione delle firme tramite JWKS.

## Evoluzione richiesta
Prima di utenti reali: provider OpenID Connect, provisioning organizzazioni e memberships, gestione ruoli server-side per organization, scadenze/revoche/sessioni, audit e autenticazione cittadini tramite integrazioni riconosciute (SPID/CIE ove applicabile). JWT auto-emessi e ruoli fidati nei claim non sono una gestione identità definitiva.

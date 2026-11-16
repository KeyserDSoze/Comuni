# ADR 0069 — Enrollment owner-only del secondo Admin OIDC senza bypass tenant

- Data: 2026-11-16.
- Stato: Accepted per procedura e test PostgreSQL sintetici; autorizzazioni e identità reali **non** collaudate.
- Issue: #80; sotto #3/#2/#10/#4, estende ADR 0021/0022/0025/0037/0038.
- Riferimenti: [PostgreSQL row-level locks](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS), [PostgreSQL transactions](https://www.postgresql.org/docs/current/tutorial-transactions.html), [OIDC Core issuer+subject](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStabilityAndUniqueness).

## Motivazione

Il bootstrap #31 aggiunge **esattamente il primo** Admin e deve rifiutare il secondo. Il runtime comunale può concedere solo Reader/Officer per policy API e PostgreSQL RLS restrittiva. Per garantire resilienza prima di implementare trasferimento/revoca di un Admin e prima di un Superadmin con permessi granulari serve una via controllata per aggiungere una **seconda membership Admin OIDC verificata**, senza creare una rotta cross-tenant, auto-concedersi privilegi o disattivare la prima identità.

## Decisione

1. Nuovo **script offline owner-only** `scripts/postgres/enroll-additional-admin.sql`. Il processo autorizzato usa il login schema-owner delle tabelle `platform.organizations`, `platform.organization_memberships`, `platform.audit_events` tramite `psql -X -q -v ON_ERROR_STOP=1`, su rete privata PostgreSQL con TLS. L'API .NET, il frontend React e l'account SQL `comuni_app_runtime` **non** espongono o possono invocare tale procedura.
2. Input da variabili ambiente: `COMUNI_ADD_ADMIN_ORGANIZATION_ID` (UUID canonico, non-zero), `COMUNI_ADD_ADMIN_IDENTITY_ISSUER` (HTTPS issuer OIDC esatto), `COMUNI_ADD_ADMIN_SUBJECT` (subject esatto, non vuoto/controlli), `COMUNI_ADD_ADMIN_CHANGE_TICKET` e `COMUNI_ADD_ADMIN_APPROVER`. Un reviewer distinto deve validare *fuori dalla piattaforma* identità del Comune, ownership della persona, issuer/sub, ruoli, MFA, mandato e approvazione del change. La presenza/formato di una stringa ticket/reviewer **non prova** approvazione autentica: no produzione senza procedura esterna indipendente.
3. In una **sola transazione** verificare che il login sia lo schema owner; bloccare la riga `organizations` con `SELECT ... FOR UPDATE` per serializzare l'intero lifecycle degli Admin del Comune; richiedere `is_activated=true`, `is_suspended=false`, almeno un Admin OIDC già attivo e nessuna riga Admin disattivata/legacy/unbound. Non riattivare il Comune, la membership né il modulo Protocollo. Un target già presente in un altro ruolo (Reader/Officer) richiede cambiamento separato esplicitamente approvato: niente elevazione silenziosa.
4. Per un target **non ancora iscritto** inserire la sola membership `Admin`, `is_active=true`, `identity_issuer=issuer`; nello stesso commit aggiungere un evento append-only `platform.membership.admin.added`, con `actor=db-owner:<login>`, `resourceType=platform.membership`, `resourceId=md5(org|Admin|sub|issuer)::uuid` pseudonimo, `correlationId=admin-enroll:<ticket>`. Non registrare sub, issuer, approver, secret o credential nel registro audit; il resource ID è pseudonimo, **non** anonimizzato.
5. Retry idempotente solo se il target Admin è **esattamente** `issuer+sub` attivo e nel registro esiste **un solo** audit di questa azione con stesso ticket/resource. Ticket riutilizzato per un target differente, issuer differente, Admin derivato da bootstrap, record ambiguo o cambio ticket: rifiuto, senza scritture. Lo script non revoca né sostituisce amministratori; l'ultimo Admin non può essere perso attraverso questo percorso.
6. Le variabili non compaiono in argv, query dinamiche o log. I dati entrano in SQL tramite quoting `:'var'` di `psql` e `set_config(..., true)` transaction-scoped; nessun `SECURITY DEFINER`, grant extra al runtime o sblocco RLS. Errori con messaggi statici.
7. RED/Green con xUnit + PostgreSQL e `psql`: success/retry, concorrenza stesso ticket, role conflict, owner check, lifecycle, errori e audit; le suite esistenti di API, React/Playwright, CodeQL, Terraform, supply chain e container restano gate CI 7/7 sul commit finale.

## Esclusioni

Non è CRUD amministratori attraverso la UI; non implementa un IdP, verifica OIDC live, approval workflow a quattro occhi all'interno della piattaforma, revoca/ultimo Admin, impersonificazione o integrazioni PA. La #80 è una piccola slice verificabile di #3 e lascia le epiche #2/#3/#4/#10 aperte. Non usare script con identità reali senza revisione del processo e dell'IdP; niente migrazione di schema o deploy Azure automatico.

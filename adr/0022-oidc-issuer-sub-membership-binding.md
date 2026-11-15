# ADR 0022 — Isolamento delle identità OIDC per coppia issuer + subject

- Stato: Accepted come **controllo backend e migration** (#28), senza collegare un IdP reale
- Data: 2026-11-15
- Dipendenze: ADR 0002, 0005, 0007, 0011–0013, 0020–0021; issue #2 / #3 / #5
- Fonte: [OpenID Connect Core 1.0 §5.7 — Claim Stability and Uniqueness](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStabilityAndUniqueness)

## Contesto

OIDC specifica che il subject è unico **solo nel contesto dell'issuer**: il riferimento dell'utente è la coppia esatta `iss + sub`. Le membership esistenti selezionate per `organization_id + sub` possono risultare ambigue durante una sostituzione di IdP o se due provider riutilizzano uno stesso `sub`. Il backend già convalida la firma/issuer/audience del JWT prima delle policy, ma l'associazione al database era subject-only. Collegare automaticamente tutte le membership storiche al nuovo Authority sarebbe un'assunzione non verificata sulla titolarità dell'identità.

## Decisione

- La migration EF 0009 introduce `identity_issuer` VARCHAR(512) nullable sulla tabella esistente `platform.organization_memberships`, con vincolo di formato HTTPS (quando valorizzato). **Nessun default/backfill automatico.** La PK attuale rimane `(organization_id, subject, role)`, dato che nel bootstrap è supportato un solo provider trusted; non introduciamo ora un modello multi-provider.
- In `Authentication:Mode=Oidc`, la `OrganizationRoleHandler` legge `iss` dal Principal **dopo** JwtBearer RS256/JWKS e chiede alla `OrganizationMembershipStore` esclusivamente le righe `organization_id + subject + IdentityIssuer == iss + IsActive`. L'assenza di issuer o un valore diverso restituisce nessun ruolo e quindi 403. Anche `GET /context` usa lo stesso store. Il JWT con issuer non trusted è già 401 prima della query membership.
- In `Authentication:Mode=DevelopmentJwt` (solo ambienti Development/Testing) il filtro issuer non è obbligatorio per mantenere i seed e test demo. Questo fallback **non** è abilitabile in Production.
- La creazione di Reader/Officer da un Admin OIDC imposta `identity_issuer` esclusivamente dal `iss` autenticato dell'Admin, non dal client o da una email. La colonna è **immutabile via runtime SQL**: l'account applicativo ha `INSERT(identity_issuer)` ma non `UPDATE(identity_issuer)`. L'UPSERT su membership già presente verifica l'issuer; se differente o NULL rifiuta con `409`, senza mutare riga o audit. Solo la procedura di owner provisioning, con verifica del sub/issuer reale e autorizzazione separata, può aggiornare il binding legacy.
- La dashboard Admin mostra l'issuer della membership **in sola lettura**. Nessuna modifica del JWT, cambio tenant client-side o nuovo frontend/database.

## Alternative e rischi residui

La migrazione automatica `identity_issuer = Authority` è stata scartata: avrebbe potuto trasferire diritti a soggetti diversi. Supportare più issuer per lo stesso subject/role richiederebbe una chiave composta con issuer e un onboarding diverso: rimandato a una nuova ADR quando sarà necessario. Il confronto del claim è **esatto**, non normalizza path/case/URL: deve corrispondere al valore `iss` emesso dal provider.

**Rischio operativo importante:** se non si preparano i binding issuer degli Admin/utenti prima dell'attivazione OIDC, tutte le membership con issuer NULL diventano inaccessibili (403) per i JWT OIDC; non è possibile risolverlo tramite fallback insicuro. Documentare prerequisiti, approvazione e piano di rollback nel runbook; la migrazione additiva può essere applicata prima del collegamento IdP. La pagina Admin non è uno strumento di verifica della titolarità di un nuovo subject: serve un processo di onboarding reale con il provider e controlli sulla prima membership Admin.

Il codice è coperto in CI da xUnit PostgreSQL, token RS256/JWKS mock, restrizioni del ruolo runtime, Playwright e Terraform/Docker. **Non sono stati verificati** identity lifecycle/OIDC provider live, SPID/CIE, MFA, revoca, BFF, PII/retention, provisioning Azure o conformance per la Pubblica Amministrazione. Le epiche #2/#5/#3 rimangono aperte.

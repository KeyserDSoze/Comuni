# Comuni

Piattaforma cloud-native multi-organization per i Comuni italiani: **Modular Monolith** .NET 10 + PostgreSQL, frontend React/TypeScript e deployment **esclusivamente Azure**.

> Stato: progetto in avvio. L'incremento iniziale realizza la fondazione multi-organization e un **modulo Protocollo dimostrativo** per validare isolamento, permessi e feature flags; non costituisce un sistema di protocollo informatico conforme alle regole AgID.

## Convenzioni non negoziabili

- Si lavora **direttamente su `main`**, senza branch di lavoro o pull request obbligatorie.
- DDD e dipendenze controllate: `Applications` → `Business` → `Domains`; `Infrastructures` implementa i contratti applicativi.
- Un'unica API REST .NET 10, un solo PostgreSQL, un unico frontend React + Vite, senza microservizi.
- Ogni dato applicativo è isolato per `organization_id`; l'identità del Comune proviene esclusivamente dal JWT validato, **mai** da header arbitrari o dal body. I ruoli autorizzativi derivano da membership attive in PostgreSQL, non dai claim di ruolo.
- Moduli, autorizzazioni e interfaccia sono configurati per organization.
- **TDD: Red → Green → Refactor.** Prima test, poi codice. Nessuna feature completa senza suite verde.
- ADR e documentazione devono evolvere insieme al codice. Terraform è la fonte di verità per l'infrastruttura Azure.

Vedere [AGENTS.md](AGENTS.md), [ADR](adr/) e [documentazione](docs/).

## Obiettivo del primo incremento

Una piccola vertical slice verificabile: autenticazione JWT, organization context, gestione abilitazione moduli, lettura/creazione di metadati di documenti del Protocollo, frontend responsive e test di isolamento/permessi. Le integrazioni con ANPR, PagoPA, SEND, PDND, conservazione e le funzionalità legali di protocollo sono **fuori da questa prima slice**.

## Esecuzione locale (dopo il bootstrap)

Requisiti: Docker + Compose. Usare `docker compose -f docker/compose.yml up --build`, quindi aprire `http://localhost:8080`. Per ottenere un token *solo di sviluppo* vedere `docs/development.md`. I test backend richiedono .NET 10 e PostgreSQL; quelli E2E richiedono Node e Playwright.

L'accesso applicativo definitivo tramite un identity provider OIDC e SPID/CIE non è incluso in questo primo incremento; nessuna credenziale predefinita è autorizzata in produzione.

## Roadmap e limiti

La vertical slice attuale è **dimostrativa, non pronta per dati comunali reali**. Consultare [mappa domini](docs/domains.md), [architettura](docs/architecture.md), [sicurezza](docs/security.md) e [deploy Azure](docs/deployment.md). Per il frontend usare npm workspace dalla root: `npm install && npm run build --workspace @comuni/frontend`.

## Issue tracking

Le [GitHub Issues](https://github.com/KeyserDSoze/Comuni/issues) sono la fonte di verità per roadmap, stato, dipendenze e criteri di accettazione. Prima di ogni sessione verificare issue e CI di `main`. Vedere [convenzioni di issue](docs/issues.md).

## Identità API (in corso)

La modalità di produzione ora richiede `Authentication:Mode=Oidc`, `Authentication:Authority=https://...`, `Authentication:Audience=...` per validare token RS256 tramite JWKS (ADR 0007). In Development/Testing soltanto, i token demo HS256 restano disponibili con `DevelopmentJwt`. Non è un login OIDC completo: l'interfaccia non possiede ancora un flusso OAuth e manca il provider reale, oltre al provisioning utenti per Comune (issue #2).

## Amministrazione comunale — prima slice (#13)

Un utente con membership `Admin` attiva può accedere alla voce **Amministrazione** del portale e attivare/disattivare il modulo Protocollo del proprio Comune. Il cambiamento è persistito su PostgreSQL, auditato e verificato dal backend. Non sono ancora implementati il catalogo completo né Superadmin. In Development il seed include l'utente dimostrativo `local-admin` con ruolo Admin sul solo Comune Aurora: il token si genera con lo script CLI indicato in [docs/development.md](docs/development.md). Non usare questo token fuori dallo sviluppo.

## Accesso PostgreSQL in produzione (ADR 0011)

Il runtime su Azure usa la credenziale separata `comuni_app_runtime` e non quella del proprietario/migratore del database. Il provisioning SQL idempotente e i GRANT limitati sono in `scripts/postgres/provision-runtime-role.sql`; la procedura e le dipendenze di bootstrap sono in [docs/deployment.md](docs/deployment.md). **L'isolamento RLS per singolo Comune non è ancora implementato**: restano bloccanti #5 e #6 per un deployment affidabile con dati reali.

## RLS PostgreSQL — difesa in profondità (#17)

Una migrazione EF abilita policy Row-Level Security sulle cinque tabelle tenant-owned e un middleware .NET 10 imposta il Comune con `SET LOCAL` nella transazione della richiesta, evitando che il contesto sopravviva nel pool delle connessioni. [ADR 0012](adr/0012-transaction-scoped-rls.md). **Attenzione:** il login runtime condiviso può falsificare la variabile PostgreSQL con SQL arbitrario; il sistema non è ancora adatto a dati personali reali. La #5 resta aperta per completare questo confine.

## Protezione del contesto tenant contro SQL diretto (#18)

La RLS PostgreSQL ora verifica una **prova HMAC temporanea** generata dall'API: il ruolo runtime non può firmare un tenant alternativo soltanto impostando `comuni.organization_id`. Le prove richiedono una chiave condivisa tra API e verifier DB, memorizzata in Key Vault e tabella privata PostgreSQL. [ADR 0013](adr/0013-signed-tenant-rls-proofs.md). Per Development configurare `TENANT_PROOF_KEY` casuale in `docker/.env`. Non è ancora prova di sicurezza completa contro tutte le minacce o di deploy Azure.

## Segreti RLS e Terraform (#21)

Il secret HMAC `tenant-proof-key` deve essere installato **fuori da Terraform** in Azure Key Vault. Il deploy controlla solo che il secret esista e sia abilitato, senza recuperare il valore; lo stato Terraform nuovo non lo gestisce più. Vedere [ADR 0015](adr/0015-external-tenant-signing-secret.md) e [docs/deployment.md](docs/deployment.md). Gli snapshot storici Terraform possono contenere la vecchia chiave e devono essere gestiti/ruotati. Le issue #19 e #6 rimangono aperte; nessun rollout Azure è stato verificato.

## Key Vault secret versionate per RLS (#22)

Il deployment API su Azure usa `TENANT_PROOF_SECRET_VERSION` (versione esatta della Key Vault secret `tenant-proof-key`, 32 hex), non più la latest automatica. La versione è metadata, la chiave HMAC **non** è inserita in Terraform. Un preflight metadata-only usa `az keyvault secret list-versions` e fallisce se la versione prevista non è abilitata. [ADR 0016](adr/0016-pinned-tenant-proof-secret-version.md). La rotazione multi-replica e il deploy Azure reale restano aperti nella #19/#6.

## Staging revisioni Azure in sicurezza (#23)

Il workflow di deploy predispone una revisione candidata in Azure Container Apps con **0% di traffico pubblico** e mantiene **100%** sulla revisione stabile preesistente. Ogni candidata usa un riferimento Key Vault con nome/versione distincti, senza mutare la secret della stable. Un controllo su piano Terraform blocca promozioni automatiche e cambi distruttivi. Leggere [ADR 0017](adr/0017-zero-traffic-aca-staging.md) e [runbook](docs/deployment.md): **non** è un workflow di bootstrap o promozione e non è stato testato su Azure reale; #19/#6 rimangono aperte.

## Check revisioni Azure dopo lo staging (#24)

La pipeline `Deploy to Azure` ora verifica **dopo Terraform apply** che la revisione stabile riceva ancora il 100% del traffico e che la nuova candidata (0%) sia attiva e sana, con immagine del commit e configurazione HMAC pin esatta. Il controllo è di sola lettura e non può promuovere/revocare una revisione. Vedere [ADR 0018](adr/0018-live-aca-staging-verification.md) e [docs/deployment.md](docs/deployment.md). La verifica è testata in CI con CLI Azure simulata, non ancora provata in una subscription reale.

## Canary revision con smoke OIDC/RLS read-only (#25)

La revisione candidata (0% traffico ordinario) riceve una **label immutabile** per commit e quindi un URL dedicato a test controllati. `scripts/azure/smoke-candidate-oidc.py` permette a un operatore di verificare contesti e isolamento Protocollo con due token OIDC reali e due Comuni **sintetici**, senza creare documenti e senza spostare traffico. [ADR 0019](adr/0019-immutable-canary-label-and-oidc-smoke.md), [runbook](docs/deployment.md). Non sono ancora stati effettuati smoke su Azure reale o login tramite IdP reale; label e token devono essere accessibili solo a operatori autorizzati.

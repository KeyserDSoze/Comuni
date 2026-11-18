# ADR 0027 — Sospensione e riattivazione controllate, owner-only e audit atomico

- Stato: Accepted come vertical slice offline del Core (#33), **non console Superadmin né identity provider reale**
- Data: 2026-11-15
- Dipendenze: ADR 0001, 0002, 0006, 0008, 0011–0013, 0022, 0025–0026; issue #3/#4/#5/#10/#14/#31/#32
- Riferimenti: [PostgreSQL row-level locks](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS), [PostgreSQL transactions](https://www.postgresql.org/docs/17/tutorial-transactions.html), [psql variable quoting](https://www.postgresql.org/docs/17/app-psql.html#APP-PSQL-INTERPOLATION)

## Contesto

L'ADR 0008 ha già introdotto `platform.organizations.is_suspended` e la policy ASP.NET che controlla il flag **ogni richiesta protetta** (membership/ruolo non bastano). L'ADR 0026 crea nuove organizzazioni offline, ma lo stato era modificabile solo con SQL manuale senza audit. La console Superadmin con una identità platform e impersonificazione non è ancora autorizzata né implementata. Evitare una API cross-tenant o un permesso sul ruolo PostgreSQL condiviso.

## Decisione

- `scripts/postgres/set-organization-suspension.sql` realizza solo le transizioni `suspend` e `reactivate` di organizzazioni **già esistenti**, usando un runner privato PostgreSQL e l'account **owner di `platform.organizations` e `platform.audit_events`**. Il login `comuni_app_runtime` non possiede UPDATE su organizations, e lo script verifica anche ownership a runtime. Non sono introdotti API endpoint, frontend diversi, nuovi ruoli applicativi o migrazioni.
- Richiedere **cinque variabili ambientali**: `COMUNI_LIFECYCLE_ORGANIZATION_ID` (UUID valido/non zero), `COMUNI_LIFECYCLE_ACTION` (esattamente `suspend` o `reactivate`), `COMUNI_LIFECYCLE_CHANGE_TICKET`, `COMUNI_LIFECYCLE_APPROVER` e `COMUNI_LIFECYCLE_REASON_CODE` (codice di motivazione sanitizzato). Un **operatore approvato indipendentemente** deve verificare identità dell'ente, competenze, legittimità e azioni sul ticket prima dell'esecuzione; il tool controlla soltanto forma e presenza degli input, non attesta l'autenticità dell'approvazione né la condizione dell'IdP.
- Un'unica transazione PostgreSQL con `SET LOCAL` da variabili psql `:'var'` quoted, senza SQL dinamico/echo, verifica owner, input, esistenza del Comune, poi acquisisce `SELECT ... FOR UPDATE` sulla riga organization. Azioni concorrenti sullo stesso Comune sono serializzate; per transizione effettiva aggiorna `is_suspended` e inserisce `platform.audit_events` **nello stesso commit**. Azioni `platform.organization.suspended`/`platform.organization.reactivated`, actor `db-owner:<current_user>`, resource type `platform.organization`, resource id UUID, correlation `lifecycle:<change-ticket>`. La motivazione/reviewer si documentano **nel change esterno**, non in audit o log in chiaro.
- Se lo stato richiesto coincide con quello attuale è **no-op** idempotente senza nuovi eventi; Comune inesistente/UUID non valido/action ignota o approvazioni malformate fanno fallire la transazione e non modificano alcuna riga. Non cambiare module flags, membership, organization name o dati di dominio. La riattivazione **non** abilita servizi né membership: un utente disabilitato rimane 403.
- La policy lato API già esistente prevale sul modulo e sul JWT validato: ogni nuova richiesta protetta di un Comune sospeso è 403, anche con token già emesso. L'altra organization non subisce modifiche. Nessuna deviazione da isolamento RLS e da un solo DB PostgreSQL, una API .NET 10, una React SPA.

## Rischi e limiti

Non è una revoca OIDC, non invalida necessariamente **operazioni già in volo** o sessioni nell'IdP. L'effetto 403 è verificato per **nuove autorizzazioni/richieste** dopo commit; operazioni di emergenza potrebbero richiedere mitigazioni infrastrutturali aggiuntive. Il superuser/owner PostgreSQL rimane potente: change ticket, approver e reason sono attestazioni esterne non firmate, e il loro uso non sostituisce RBAC platform, separation of duties, human approval verificabile o recovery/audit federato. Una successiva vera console Superadmin richiede identità platform-level, policy, workflow e audit definiti in #3/#10. Non dichiarare go-live Azure, conformità GDPR/AgID, SPID/CIE, login reale, BFF o rotazione senza ulteriori controlli.

## Nota di compatibilità input e logging SQL (#98 / ADR 0082)

Il riferimento originale a `SET LOCAL` tramite `psql :'var'` descrive **la prima versione**, non la procedura attuale. La sospensione/riattivazione owner-only ora legge cinque campi allowlisted via `\copy` client-side e TEMP table, senza inviare i valori come literal delle statement. Il blocco owner, il lock, il 403 sulle nuove richieste, l'audit append-only e l'idempotenza restano invariati. Il payload base64(JSON) COPY è reversibile, e non sono attestati Azure/pgAudit/SIEM, identity proof e privacy review (#86/#84/#92).

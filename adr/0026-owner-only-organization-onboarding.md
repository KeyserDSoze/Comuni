# ADR 0026 — Onboarding tecnico owner-only di una organization con moduli spenti

- Stato: Accepted come **bootstrap operativo offline**, non console Superadmin né provisioning di Comuni reali (#32)
- Data: 2026-11-15
- Dipendenze: ADR 0001, 0002, 0005, 0006, 0008, 0009, 0011–0013, 0022, 0025; issue #2/#3/#4/#5/#10/#31
- Riferimenti: [PostgreSQL advisory locks](https://www.postgresql.org/docs/17/explicit-locking.html#ADVISORY-LOCKS), [PostgreSQL transaction control](https://www.postgresql.org/docs/17/tutorial-transactions.html), [psql variables and SQL interpolation](https://www.postgresql.org/docs/17/app-psql.html#APP-PSQL-INTERPOLATION).

## Problema

Il primo Admin OIDC può ora essere associato con il runner owner tramite lo script ADR 0025, ma l'organizzazione alla quale associarlo era creata manualmente. Un inserimento senza invarianti non crea il flag `protocol` e non traccia l'evento di onboarding; ripetere il comando può alterare stato o feature già configurate. L'applicazione multi-organization non deve permettere a un Admin comunale di creare altri tenant né a un normale token JWT di scegliersi un organization ID.

## Decisione

- `scripts/postgres/provision-organization.sql` è un comando `psql` **offline, riservato all'owner delle tabelle** `platform.organizations`, `platform.organization_modules` e `platform.audit_events`. Non introdurre API web, frontend supplementari, schema nuovo, policy permissive o gestione di secret.
- L'operatore deve avere un change ticket approvato da un revisore indipendente e verificare **fuori dal repository** che l'ente sia autorizzato all'onboarding. Sono obbligatori in variabili ambiente `COMUNI_PROVISION_ORGANIZATION_ID` (UUID predeterminato e non vuoto), `COMUNI_PROVISION_ORGANIZATION_NAME` (1–200 caratteri, senza whitespace esterni o controllo), `COMUNI_PROVISION_CHANGE_TICKET` e `COMUNI_PROVISION_APPROVER` (riferimenti sanitizzati). L'app controlla solo il formato, non la reale identità dell'approvatore né il titolo giuridico del Comune.
- Una singola transazione con `SET LOCAL`, psql escaped literals `:'name'` e controllo owner crea `platform.organizations` con `is_suspended = FALSE`, *nessuna membership*, e una sola `platform.organization_modules` con `module_key='protocol', enabled=FALSE`; nel medesimo commit scrive l'evento append-only `platform.organization.created`, attore `db-owner:<current_user>`, resource ID = UUID del Comune, correlation ID = riferimento change. Non scrive il nome nell'audit né mostra input nei log psql in modalità `-X -q`.
- Dopo #102 il nuovo Comune nasce **created (`is_activated=FALSE`)**, non è operativo neppure dopo il collegamento del primo Admin OIDC con la procedura distinta ADR 0025: JWT con `organization_id` non bypassa membership e gate lifecycle. Le API protette restano 403 fino a un **separato change owner-only** `activate-organization.sql` (ADR 0038); Protocollo resta disabilitato anche dopo, fino all'abilitazione esplicita di un Admin autorizzato. La frase storica sulla nascita già attiva è superata.
- Poiché prima dell'inserimento non esiste alcuna riga da bloccare, il tool serializza le richieste concorrenti allo stesso UUID con `pg_advisory_xact_lock(hashtextextended(uuid, 0))` e poi controlla la riga con `FOR UPDATE`. Collisioni di hash serializzano eventualmente UUID indipendenti, senza mischiarli; un altro percorso di provisioning non coordinato deve comunque essere rifiutato tramite provenance.
- Il retry a **stesso UUID e stesso nome** è no-op solo se esiste esattamente un audit di `platform.organization.created` per la risorsa e il flag `protocol` è già presente. Non ripristina moduli, membership, sospensione né configurazioni mutate nel frattempo. UUID esistente con nome diverso, riga manuale senza audit o flag mancante = errore fail-closed, senza `ON CONFLICT DO UPDATE` indiscriminato.
- Il runtime SQL `comuni_app_runtime` non è owner e non ha INSERT su organizations. I test xUnit contro PostgreSQL 17 verificano rifiuti, injection, isolamento via API, retry e concorrenza.

## Alternative e limiti

Il percorso Superadmin con identità platform-level, approvazioni, lifecycle completo di sospensione/riattivazione e gestione catalogo rimane #3/#10. L'owner DB è un account privilegiato, quindi il sistema **non** sostituisce un workflow di approval con separazione dei compiti: senza validazione umana esterna una persona con accesso owner potrebbe creare Comuni illegittimi. L'UUID è deciso esternamente in modo verificabile; l'assenza di utenti attivi è condizione necessaria, non garanzia sufficiente di autorizzazione. Nessun IdP, Azure deployment, ANPR/SPID/CIE o onboarding reale è stato verificato. Una migrazione di dati già esistenti richiede un piano distinto, senza backfill automatico.

## Rettifica del trasporto legacy degli input (#101, ADR 0085)

La menzione storica di `psql :'name'` e `SET LOCAL` riflette la versione originaria. Lo script owner-only `provision-organization.sql` ora acquisisce **esattamente** i quattro `COMUNI_PROVISION_*` dall'helper statico `stream-private-input.py provision-organization` tramite client-side `\\copy`, tabella TEMP `ON COMMIT DROP` e `set_config(...,true)` con query statica, senza interpolare il nome Comune, UUID, ticket e revisore come SQL literal. Il blocco `DO $provision$` e i suoi controlli owner/lock/audit/tenant/modulo restano invariati. **Il lifecycle legacy (organizzazione nata attivata, senza membri) non cambia**: preferire la distinta registration pending di ADR 0037/0038/0084 per nuovi flussi.

La prova PostgreSQL17 con `log_statement=all` controlla soltanto che i canary di nome/ticket/reviewer non siano nel **testo degli statement**; il payload base64 JSON è reversibile e non è garantita riservatezza da protocolli COPY, TEMP, proxy, pgAudit, Azure, SIEM o backup. #86/#84/#49/#92 e review Security/Privacy restano blocchi reali.

## Rettifica del lifecycle dello script legacy (#102, ADR 0086)

L'ADR 0026 è precedente alla migration 0013. Con `is_activated BOOLEAN NOT NULL DEFAULT TRUE`, lo script legacy originale che ometteva il flag poteva creare **nuovi** enti active senza `platform.organization.activated`. Dal fix #102, il singolo INSERT di `provision-organization.sql` specifica `is_activated=FALSE` e conserva tutte le altre regole owner/advisory lock/anti-adoption/flag off/membership zero/audit `platform.organization.created` della procedura originale. Il bootstrap del primo Admin OIDC non dà accesso: soltanto `activate-organization.sql` con change separato può passare a active; non attiva automaticamente il Protocollo.

**Non** cambiare il DEFAULT TRUE della migration o rieseguire UPDATE sui tenant storici; i Comuni già attivi e sospesi devono conservare esattamente i loro stati. Preferire la registrazione canonica `register-organization.sql` (ADR 0037/0084) per il lifecycle futuro. Sono state aggiunte regressioni xUnit/PostgreSQL17 e Python statiche; test live Azure/IdP/privacy non sono inclusi. #84/#86/#49/#92 rimangono blocchi di go-live.

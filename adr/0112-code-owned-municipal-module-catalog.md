# ADR 0112 — Catalogo moduli code-owned e servizio pianificato fail-closed

- Data: 2026-11-20
- Stato: **Accepted per il Core e test PostgreSQL17/Playwright sintetici**; attivazione reale di domini e conformità normative non dichiarate.
- Issue: [#128](https://github.com/KeyserDSoze/Comuni/issues/128), sottoissue di #3 (Core) e #5 (isolamento). Dipendenze: ADR 0009 (Admin moduli), ADR 0092 (integrità audit), ADR 0013 (RLS), ADR 0111 (rate limiter).
- Repository: una API .NET 10, un frontend React/PWA, un PostgreSQL. Nessuna nuova applicazione, schema, migrazione o grant.

## Problema

Il Core esponeva soltanto la riga `protocol` in `GET /api/v1/admin/modules`, senza catalogo dei domini futuri. Inoltre il contesto `GET /api/v1/context` riceveva tutte le righe `platform.organization_modules` con `enabled=true`, anche se il codice non implementava quel modulo. Una scrittura owner/seed/migrazione errata che impostasse `archive=true` avrebbe potuto presentare l'Archivio come servizio attivo; il filtro della navigazione React non è sufficiente come barriera applicativa.

## Decisione

1. Il Core espone una sola sorgente **code-owned** `ModuleCatalog` nel Business layer, con 12 moduli applicativi dell'ecosistema (Core non è un flag tenant). I descrittori sono stabili, ordinati per key, con `key`, `name`, `status`, `enabled`, `configurable` e `dependsOn`. La key `protocol` è l'unico modulo implementato (`status=available`); gli altri 11 sono **planned** e senza endpoint, dati, flag effettivi, funzioni o autorizzazioni. Tutte le dipendenze sono `[]` perché non è stata approvata alcuna relazione intermodulo per funzioni non implementate: evitare dipendenze speculative. Le key future sono riservate come vocabolario preliminare, non promessa di disponibilità normativa.
2. `GET /api/v1/admin/modules/catalog` richiede **la stessa policy backend Admin** del Comune del `GET /admin/modules` già esistente. La query passa attraverso store tenant-scoped con filtri EF e RLS firmata; non ammette tenant selector dal client, né legge altri Comuni. `configurable` per `protocol` è true solo se esiste una riga persistita di flag per il Comune; `enabled` viene dalla stessa riga. Una organization non ancora provisionata per Protocollo avrà `available` ma `configurable=false`.
3. La whitelist centrale `IsImplemented` viene applicata al Business `SetEnabledAsync`, al repository di amministrazione, all'accesso `IOrganizationModuleStore.IsEnabledAsync` **e** all'elenco `EnabledModulesAsync` della directory usata dal contesto. Un flag `archive=true` inserito owner DB resta memorizzato per una futura migrazione autorizzata, ma non diventa una feature attiva o configurabile. `PUT /api/v1/admin/modules/archive` resta 404 e non scrive audit. La riga Protocollo continua ad essere persistita, transazionale, auditata, tenant-scoped e disabilita ogni use case immediatamente quando spenta.
4. React usa il catalogo dalla **stessa API**, mostrando in italiano/inglese i domini pianificati senza bottoni, azioni o menu attivo. Solo le righe `available && configurable` espongono il toggle; cambiamento rilegge catalogo e contesto. Il vecchio GET `/admin/modules` resta compatibile e limitato a Protocollo.
5. Per aggiungere ogni dominio futuro serve un ADR distinto, modello dati isolato, API e autorizzazioni server-side, migrazione/grants RLS, dipendenze esplicite validate, test TDD e UI nello stesso frontend. **Non** basta cambiare una riga DB o una etichetta del catalogo.

## TDD / verifiche

RED: [`8826fe8`](https://github.com/KeyserDSoze/Comuni/commit/8826fe876ae9a6627168b5edec2e674b2a97e30b), [Actions 44811608046](https://github.com/KeyserDSoze/Comuni/actions/runs/44811608046), PostgreSQL17 **375 API passati / 3 failure attesi** e Playwright **1 failure atteso** su Archivio pianificato. Il test prova Admin/Reader/Officer/anonimo/JWT forged, due Comuni, flag `archive=true` artificiale e PUT future negati. GREEN richiede **7/7 GitHub Actions success sullo stesso HEAD main**, con xUnit/PostgreSQL17/pgAudit, React/Playwright, Terraform/Python, CodeQL, SCA e build immagine.

## Limiti / considerazioni operative

Il catalogo è **descrittivo, non un entitlement** contrattuale o un catalogo dei servizi PA conforme AgID. Protocollo rimane dimostrativo e non un registro a norma. Lo stato planned non attiva conservazione, archiviazione, TARI, ANPR, ecc. La gestione centralizzata Superadmin delle disponibilità e dipendenze, le feature flags per componenti future, migrazioni e provisioning completo, OIDC live, Azure e GDPR/AgID rimangono nelle epiche #3/#5/#10/#2 e nei futuri domini. Nessuna risorsa Azure modificata, nessun dato personale reale.

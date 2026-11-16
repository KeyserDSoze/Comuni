# ADR 0039 — Inventario Superadmin con lifecycleStatus esatto e compatibilità fail-closed

- Stato: Accepted **per implementazione offline opt-in**, non per go-live Azure.
- Data: 2026-11-16
- Issue: #45, sotto #3/#10, dipendenza #38.
- Dipendenze: ADR 0031, 0034, 0038; sicurezza degli ADR 0012–0014.
- Fonti: [PostgreSQL CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html), [PostgreSQL GRANT](https://www.postgresql.org/docs/current/sql-grant.html), [EF Core migrations](https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/).

## Decisione

La registrazione owner-only (#44) distingue `created`, `active`, `suspended`, ma l'inventario globale mostra `isSuspended` come **non operativo** per entrambi i casi created e suspended. Senza cambiare authorization tenant, esponiamo lo stato tecnico come **metadato amministrativo minimale**: string enum obbligatoria, read-only `lifecycleStatus` con solo `created|active|suspended`.

1. La migrazione owner `202611160001_PlatformLifecycleInventory` aggiunge **in coda** `lifecycle_status` alla vista `platform.platform_organization_inventory` con `CREATE OR REPLACE VIEW ... WITH (security_barrier=true)`. La proiezione è `CASE NOT is_activated → created; is_suspended → suspended; ELSE active`; il constraint Core già vieta `is_activated=false,is_suspended=true`. I precedenti campi `id,name,is_suspended,protocol_enabled` sono mantenuti nell'ordine e nei tipi originali. `is_suspended` resta `o.is_suspended OR NOT o.is_activated`, un campo di compatibilità **non operativa**.
2. Il principal `comuni_platform_reader` continua a leggere **solo questa vista** e ad appendere audit con colonne limitate, dopo risoluzione OIDC issuer+sub attiva; `comuni_app_runtime` non ottiene accesso alla vista o al resolver. Niente identity issuer, subject, membership, utenti, documenti, ticket, nomi operatori, record Protocollo o secret nel payload. Il verificatore SQL READ ONLY richiede cinque colonne esatte e respinge qualsiasi sesta. Audit, transaction boundary, cursor UUID, limite 1–25 e blocchi 401/403/503 rimangono invariati.
3. La stessa rotta **GET /api/v1/platform/organizations** emette la quinta proprietà `lifecycleStatus` per ciascuna riga, senza mutazione lifecycle via HTTP. La PWA valida il valore e la coerenza col boolean legacy e visualizza Creato/Attivo/Sospeso e Created/Active/Suspended. Lo smoke candidata valida lo stesso allowlist in sola lettura.
4. **Compatibilità reale:** consumer JSON tolleranti alle chiavi extra conservano `isSuspended` con semantica invariata; i client che verificano *esattamente quattro* proprietà (incluso il vecchio bundle PWA) **rifiutano** la nuova risposta. Pertanto la modifica è *additiva con coordinamento obbligatorio*, **non** backwards-compatible per tutti i client. Poiché l'inventario Azure è **OFF di default** e non è stato verificato un client production, la sola sequenza consentita è migration owner + verifica SQL, stage 0% di API e PWA insieme, smoke e controllo cache/assenza di vecchi consumer, approvazione change, **solo poi** eventuale attivazione #38. Se esistono consumer esterni non aggiornabili, versionare l'endpoint prima del rollout.
5. **Rollback:** prima disabilitare il flag; `Down` usa `DROP VIEW ... RESTRICT` e ricrea la vista precedente in singola transazione, ripristinando il GRANT se il reader esiste. Non forza `CASCADE`, non modifica `is_activated`, non elimina audit e rifiuta dipendenze SQL non approvate.
6. **TDD:** RED xUnit/PostgreSQL a tre Comuni e principal distinti, Playwright etichette IT/EN + rifiuto stato incoerente, smoke Python allowlist e stato; GREEN con view/DTO/parser/UI, SQL verifier, docs e CI completa su HEAD.

## Alternative e limiti

Usare `isSuspended` come semplice flag sospeso avrebbe fatto apparire `created` attivo nei vecchi client: **rifiutato** (fail-open). Aggiungere `is_activated` grezzo o mutazioni lifecycle al browser avrebbe allargato lo scope: **rifiutato**. Non servono una API o un database separati. La vista globale owner-context implica più rischio del normale percorso RLS: secondo login e privacy review restano obbligatori. Nessuna prova di compliance GDPR/AgID, IdP/MFA reale o installazione Azure è inclusa; #38, #5 e #10 restano aperte.

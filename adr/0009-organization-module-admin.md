# ADR 0009 — Abilitazione dei moduli per organization da Admin Comune

- Stato: Accepted — vertical slice #13 dell'epica #3
- Data: 2026-11-15
- Relazione: ADR 0001, 0002, 0005, 0006, 0008

## Contesto
I moduli erano configurabili solo tramite SQL/seed, non tramite API e UI. Ogni Comune deve poter gestire le funzionalità per le quali è abilitato senza acquisire poteri sulla piattaforma o accedere ad altri Comuni.

## Decisione
Due endpoint nella **stessa API**: `GET /api/v1/admin/modules`, `PUT /api/v1/admin/modules/protocol`. Entrambi richiedono la policy backend `Admin`, soddisfatta soltanto da membership attiva per `organization_id` e `sub` del token validato; la policy rispetta anche lo stato sospeso del Comune (ADR 0008). Non si ammette `organizationId` in route o query e un eventuale campo nel body non influenza la scelta del tenant. La whitelist dei moduli in questa fase comprende solo `protocol`.

Il `ModuleAdministrationService` applica i vincoli di dominio; il repository cerca la riga nell'organization corrente usando il filtro EF. In caso di cambiamento, stato e `AuditEvent` (`platform.module.protocol.enabled`/`disabled`, actor e correlation server-side, resource ID organization) sono persistiti nella **stessa transazione**. Il no-op non produce audit. Il Protocollo applica il flag in ogni use case sul backend, indipendentemente dalla visibilità del menu React.

React mostra la sezione Amministrazione solo per utenti con ruolo Admin ricevuto dal context API; in caso di modifica rilegge il contesto.

## Limiti e prossimi passi
- Non è un catalogo generale: dipendenze tra domini, configurazioni granulari, provisioning delle organization, membership management e Superadmin restano nelle issue #3/#10.
- La verifica dell'identità usa il modello OIDC validazione backend (ADR 0007), ma login e provisioning reali restano aperti nella #2.
- Gestione di conflitti concorrenti, ottimistic locking e notifiche di modifica tra sessioni possono essere aggiunti quando più amministratori operano contemporaneamente.
- I trigger audit bloccano alterazioni ordinarie ma non garantiscono immutabilità contro privilegi DBA; vedere #4/#5.

## Evoluzione ADR 0021

La console Admin della stessa React SPA include ora anche gestione membership Reader/Officer, indipendente dalle feature flag di modulo. L'API usa la stessa policy Admin e il medesimo contesto JWT verificato, senza scope cross-organization.

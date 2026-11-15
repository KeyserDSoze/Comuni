# ADR 0005 — Ruoli per organization persistiti in PostgreSQL

- Stato: Accepted (vertical slice Core, issue #1)
- Data: 2026-11-15
- Relazione: integra ADR 0002 e ADR 0004

## Contesto
Nel bootstrap il server validava `organization_id` dal JWT, ma la policy ASP.NET concedeva ruoli da claim `role` firmati. In assenza di una fonte server-side per le membership, un operatore non può essere disabilitato o declassato immediatamente senza riemettere token.

## Decisione
Aggiungiamo `platform.organization_memberships`: PK (`organization_id`, `subject`, `role`), `is_active` e FK verso organization, ruoli ammessi `Admin`, `Officer`, `Reader`.

L'identità validata fornisce `sub` e `organization_id`. La policy ASP.NET usa un AuthorizationHandler scoped che cerca le membership **attive**, tenant-scoped, nel PostgreSQL. L'assenza di membership, organization o sub validi nega accesso (**fail closed**). Il claim `role` JWT non è consultato. `/api/v1/context` restituisce gli stessi ruoli persistiti utilizzati dal backend. Gli admin potranno modificare le membership tramite API protette e auditabili in un incremento successivo.

L'unica API e il database rimangono invariati nella loro forma architetturale; la nuova migrazione EF Core è append-only. In ambiente Development e nei test il seed fittizio è intenzionale, mai su Azure Production.

## Conseguenze e limitazioni
- Cambio/disable membership ha effetto sulla richiesta successiva, a costo di una query DB per ogni autorizzazione. Possibile cache solo con revoca/invalidation robusta.
- `organization_id` è ancora un claim JWT validato: non c'è ancora selezione organization per utenti multi-Comune, né provider OIDC reale.
- Non è un IAM completo: creazione/mutazione membership e registrazione identità sono bloccate fino a OIDC, audit e API di amministrazione autorizzate.
- `Roles` è un insieme applicativo nel DB; in futuro servono permessi granulari per moduli e workflow.
- Isolamento tenant a livello query filter applicativo, non PostgreSQL RLS; resta aperta issue #5.

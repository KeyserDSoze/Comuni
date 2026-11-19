# ADR 0092 — Integrità semantica e contesto tenant nel repository dei moduli

- Data: 2026-11-19.
- Stato: **Accepted come difesa applicativa aggiuntiva testata con PostgreSQL sintetico**, non come attestazione legale del registro audit.
- Issue: #109, sotto-attività delle epiche #4 (audit), #3 (Core) e #5 (tenant isolation).
- Continuità architetturale: ADR 0002 (tenant authorization), ADR 0006 (append-only audit), ADR 0035 e 0036 (consultazione audit).

## Difetto

`ModuleAdministrationService` genera l'evento corretto a partire dall'azione `enabled`, ma `ModuleAdministrationRepository.SetEnabledAsync` controllava soltanto `audit.OrganizationId` e `audit.ResourceId`. Un nuovo chiamante interno, un errore di refactor o un audit preassemblato errato poteva quindi rendere il Protocollo `disabled` ed inserire nella **stessa transazione** `platform.module.protocol.enabled`, oppure un evento riferito a una membership. La coerenza transazionale non implica coerenza **semantica**. `ListAsync` filtrava con EF e RLS, senza rifiutare esplicitamente il mismatch sul `CurrentOrganizationId` del repository.

## Decisione

1. **Fail-closed del contesto tenant.** Entrambe le operazioni `ListAsync(organizationId)` e `SetEnabledAsync` esigono un GUID non vuoto e uguaglianza con `ComuniDbContext.CurrentOrganizationId`. Un mismatch genera `UnauthorizedAccessException` **prima** di interrogare il database. Rimangono necessari e inalterati il filtro EF `organization_id`, la transazione tenant firmata `SET LOCAL` e le policy RLS PostgreSQL: nessun override di organization da URL/body e nessun ruolo privilegiato.
2. **Audit strutturato per l'operazione.** Prima di ogni query o modifica, il repository accetta soltanto `moduleKey == "protocol"`, `audit.OrganizationId == organizationId`, `audit.ResourceId == organizationId`, `audit.ResourceType == "platform.module"`, e azione esatta `platform.module.protocol.enabled` o `platform.module.protocol.disabled` in base al valore booleano richiesto. Eventi di altre operazioni, azioni invertite, modulo non installato, ID discordanti sono rifiutati con un errore fisso, senza inserire evento o toccare il flag.
3. **Confine API invariato.** `ModuleAdministrationService` continua a limitare la route ai moduli installati e a generare il solo `AuditEvent` corretto tramite `ICurrentActorContext` (actor JWT verificato e correlation server-generated). La API `GET /api/v1/admin/modules` e `PUT /api/v1/admin/modules/{moduleKey}` mantiene lo stesso contratto: autenticazione Admin backend, modulo sconosciuto 404, flag invariato idempotente e nessun evento aggiunto sul no-op.
4. **Atomicità invariata.** La transazione SQL firmata gestita dal middleware o dal repository salva cambio flag ed audit insieme; rollback annulla entrambi. Nessuna migration, grant, nuovo endpoint, nuova tabella o schema. Il runtime SQL ristretto non acquisisce permessi sul tenant vicino.
5. **TDD RED→GREEN su `main`.** `tests/backend/Comuni.Api.Tests/ModuleAdministrationIntegrityTests.cs` esercita il repository con **vero login `comuni_app_runtime` e tenant assertion firmata**, usando due Comuni sintetici e verifiche dirette via schema-owner solo per preparare/osservare dati di test. I negativi includono action invertita, action di membership, resource type/ID/organization incoerenti, modulo sconosciuto, tenant estraneo e GUID vuoto; `ListAsync` rifiuta lettura cross-tenant. I positivi verificano commit flag + 1 evento, no-op senza duplicazione, rollback e riabilitazione, sempre senza influenzare il secondo Comune. Test commit RED `980b8da1`, GREEN `08f65a2d`, più verifica esistente API/Playwright. Chiusura #109 solo con **sette job GitHub Actions verdi sul medesimo SHA finale di `main`**.

## Limiti

L'audit rimane protetto solo dai trigger append-only, dalla RLS e dalle autorizzazioni del runtime; non è una catena di hash, una firma del DB owner o un registro di conservazione a norma. Il repository non può autenticare autonomamente l'identità OIDC del chiamante: tale verifica appartiene all'API e a `ICurrentActorContext`; un owner PostgreSQL privilegiato può alterare schema o log. Questa slice non copre l'audit globale Superadmin, l'impersonificazione, eventi di accesso negato, retention, WORM, GDPR/AgID, SIEM/pgAudit o Azure live. Le epiche #4/#3/#5 e i relativi gate Security/Privacy restano aperti.

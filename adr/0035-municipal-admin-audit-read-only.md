# ADR 0035 — Consultazione audit minimale e tenant-scoped riservata all'Admin del Comune

- Stato: Accepted come **prima lettura di metadati audit**, non registro di conservazione a norma (#41).
- Data: 2026-11-16
- Dipendenze: ADR 0002, 0006, 0008, 0009, 0011–0014, 0021–0022, 0031–0034; issue #3/#4/#5/#41.
- Riferimenti: [PostgreSQL column privileges](https://www.postgresql.org/docs/current/ddl-priv.html), [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html), [ASP.NET Core policy authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies).

## Problema

Gli endpoint Protocollo e amministrazione generano eventi append-only nella tabella `platform.audit_events`, con `organization_id` e policy RLS legate alla prova HMAC firmata. I dati sono scritti soltanto dal runtime SQL, che finora **non poteva leggerli**. L'Admin di un Comune non dispone quindi di alcuna evidenza di base delle azioni sul proprio ente. Aprire una lettura completa della tabella aggiungerebbe rischio: l'evento contiene `actor_subject` (identificativo IdP), `correlation_id`, `resource_id` e `organization_id`. Un eventuale SELECT globale bypassando EF/RLS potrebbe esporre log di altri Comuni.

## Decisione

1. **Un'unica API .NET 10 e la stessa PWA React**: aggiungere `GET /api/v1/admin/audit`, soltanto `RequireAuthorization("Admin")`. La policy server verifica **membership Admin attiva sul DB del Comune, tenant nel JWT validato e Comune non sospeso**. Non vi è alcuna route global platform audit o rapporto fra tenant; il ruolo Superadmin *senza organization_id* non soddisfa Admin municipale.
2. **Proiezione minima di quattro campi**: `[{id,action,resourceType,occurredAt}]`, senza `actorSubject`, `correlationId`, `resourceId`, `organizationId`, subject Protocollo o dati del JWT. Gli eventi sono ordinati per `occurredAt DESC, id DESC` con limite **fisso 25**, senza filtro/testo/cursor/offset/counter, e il backend risponde **400** a qualsiasi query parameter (anche `organizationId`, `limit` o `actor`). Nessun parametro del browser può selezionare un Comune.
3. **Least privilege nel medesimo PostgreSQL**: dopo le migrazioni, lo script owner `scripts/postgres/provision-runtime-role.sql` revoca tutte le grants e riapplica `GRANT SELECT (id,organization_id,action,resource_type,occurred_at) ON platform.audit_events TO comuni_app_runtime`. Non dà **SELECT sulla tabella intera** né accesso alle colonne `actor_subject`, `resource_id` e `correlation_id`. Il runtime può continuare a INSERT completo per creare gli eventi, ma mai UPDATE/DELETE/TRUNCATE; gli audit globali `platform.platform_operator_audit_events` restano inaccessibili.
4. **Doppio isolamento**: `OrganizationAuditReader` usa `ComuniDbContext` scoped con filtro EF sull'organization derivata dal contesto HTTP e predicato esplicito `organization_id`. Il middleware firma una prova tenant `SET LOCAL comuni.tenant_assertion` nella stessa transazione prima dell'autorizzazione/lettura; RLS PostgreSQL ne verifica la firma HMAC. Senza questa prova, con GUC unsigned o sessione untrusted, la query restituisce zero righe. Nessun `IgnoreQueryFilters`, `SECURITY DEFINER` nuovo, SQL owner né seconda connessione privileged.
5. **UI minimizzata**: nella **pagina Amministrazione esistente** dell'Admin comunale, una tabella mostra azione, tipo risorsa, data/ora, con lingua IT/EN, tema chiaro/scuro, loading, empty/error e retry esplicito. Dopo errori o logout i precedenti metadati sono cancellati. Non esistono export, filtri, query arbitrarie, identificazione diretta dell'attore o opzioni di modifica/impersonificazione.
6. **TDD e verifica**: test RED xUnit/PostgreSQL con 2+ organizzazioni, 30 eventi e bound 25, Admin/Reader/Officer/anonimo, ruolo JWT contraffatto, sospensione, query manipolata e permessi PostgreSQL per colonna. Test RED Playwright per UI Admin/Reader, privacy, retry, logout, lingua e tema. GREEN codice, aggiornamento documentazione e CI 7/7 su `main`. I test API che usano owner devono essere **integrati** dai test diretti sul ruolo ristretto: un owner test da solo non proverebbe l'isolamento SQL.

## Alternative scartate

- `GRANT SELECT ON platform.audit_events` globale, oppure aggiunta di `actor_subject`/correlation all'API: aumenta l'esposizione di PII e il blast radius; rifiutato.
- Consultazione audit tramite role owner o Superadmin global reader di #37: bypass di confini tenant non necessario; rifiutato.
- Far dipendere la consultazione dell'audit dal flag Protocollo: azioni admin restano rilevanti quando Protocollo è disabilitato; rifiutato.
- Paginazione / filtro arbitrario / export: rinviato fino a UX, compliance, retention e audit delle consultazioni specificati; la prima vista rimane volutamente breve.

## Limiti e rischi

Un attaccante che compromettesse la firma tenant dell'app potrebbe impersonare il contesto SQL, e il DB owner/superuser può alterare il registro nonostante i trigger; il SELECT di un subset di colonne non garantisce prova di integrità crittografica o retention. Anche `action` e `resourceType` sono metadata e richiedono revisione GDPR/necessità. La tabella non è un registro di protocollo legale, non è un log completo di ogni lettura e non prevede consultazione storica. La nuova grant owner deve essere riapplicata nell'ambiente dopo la migrazione; **nessun rollout Azure live** è stato effettuato. Le epiche #4 e #5 rimangono aperte.

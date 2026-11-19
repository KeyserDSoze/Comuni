# ADR 0095 — Eliminare la lettura pubblica non tracciata dell'audit comunale

- Data: 2026-11-19.
- Stato: **Accepted come contratto applicativo fail-closed**, non attestazione di audit crittografico.
- Issue: #112; epiche #4 audit e #5 tenant isolation.
- ADR collegate: 0002 (tenant), 0006 (audit atomico), 0035 (proiezione minima), 0036 (consultazione registrata), 0092–0094 (integrità nei repository).

## Problema

ADR 0036 garantisce che il percorso HTTP `GET /api/v1/admin/audit` crei un evento `platform.audit.consulted` nella stessa transazione firmata RLS della lettura. Tuttavia `IOrganizationAuditReader` esponeva anche il metodo `ListRecentAsync` **senza audit**, implementato pubblicamente da `OrganizationAuditReader`. Un nuovo use case Business o chiamante interno poteva quindi effettuare una lettura delle attività amministrative del proprio Comune, dentro una transazione RLS valida, **senza lasciare la traccia prevista dal contratto**. La sola correttezza della route non impediva tale regressione.

## Decisione

1. **Unica operazione pubblica di consultazione nel port Business:** `IOrganizationAuditReader` espone esclusivamente `ListRecentAndRecordAsync(Guid organizationId, AuditEvent consultation, CancellationToken)`. Il metodo di supporto `OrganizationAuditReader.ListRecentAsync` diventa `private`: non è più invocabile da altri servizi o come API pubblica Infrastructure. Nessun endpoint nuovo, nessuna modifica ai campi HTTP, nessun bypass per Reader/Officer o Superadmin.
2. **Stessa semantica in database:** `ListRecentAndRecordAsync` richiede `CurrentOrganizationId` uguale al tenant, `consultation.OrganizationId/ResourceId` corrispondenti, action esatta `platform.audit.consulted`, resource type `platform.audit` e **transazione già attiva**. Esegue query bounded a 25 elementi e proiezione di soli `id,action,resourceType,occurredAt`, poi `AuditEvents.AddAsync` e `SaveChangesAsync` nello stesso scope. Il middleware HTTP effettua commit soltanto dopo successo. La consultazione in corso non appare nella propria risposta.
3. **Test runtime aggiornati, non rimossi:** i test PostgreSQL17 che sondavano le cinque colonne di SELECT, RLS e isolamento tenant tramite il vecchio metodo pubblico utilizzano ora `ListRecentAndRecordAsync` con evento sintetico e **transazione firmata**. Conservano controlli su numero e forma degli eventi, rifiuto di altri Comuni, revoca di accesso a actor/correlation/resource e rollback dell'evento aggiunto durante il probe. La suite esistente `MunicipalAuditConsultationTests` dimostra anche la creazione durevole di una consultazione dopo commit e il rifiuto di chiamate fuori transazione.
4. **Guardia TDD sulla superficie pubblica:** `MunicipalAuditReaderContractTests` verifica con reflection l'assenza di `ListRecentAsync` sia sull'interfaccia Business sia sulla classe Infrastructure e la presenza del solo percorso tracciato. Commit RED `97510259`; nella run GitHub Actions `44626872434` il job backend ha fallito come previsto con `Assert.Null() Failure: Value is not null` mentre gli altri 368 test backend passavano. Commit GREEN `2bf35246`, con modifica dei due contratti e delle precedenti chiamate dei test. Chiudere #112 soltanto dopo **7/7 job CI verdi sul medesimo SHA finale `main`**, inclusa questa ADR.
5. **Sicurezza preservata:** actor e correlation provenienti da `ICurrentActorContext` lato server e da JWT verificato; query effettiva eseguita dal runtime SQL limitato con tenant proof HMAC transaction-local. Nessuna migration, GRANT, owner fallback, ruolo privilegiato, nuovo UI flow o segreto.

## Limiti e confini

Rimuovere la lettura dal **contratto C#** impedisce il bypass accidentale dei normali use case Business, **non** impedisce ad altri percorsi Infrastructure di emettere direttamente SQL sotto un login valido, né al DB owner di leggere/alterare i dati. Il runtime PostgreSQL conserva per design il SELECT su sole cinque colonne e il filtro RLS firmato. La protezione totale contro consultazioni dirette richiederebbe gate SQL e audit delle query via pgAudit/SIEM, valutazione dei permessi, retention e governance; tali requisiti restano nelle epiche #4/#5/#92. Nessuna prova di accesso reale IdP/Azure, conservazione a norma o conformità GDPR/AgID è rivendicata.

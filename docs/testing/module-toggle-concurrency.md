# Test TDD concorrenza moduli su PostgreSQL 17 (#129)

La suite `tests/backend/Comuni.Api.Tests/ConcurrentModuleAdministrationTests.cs` verifica realmente, non con un mock, l'idempotenza concorrente del repository modulo Protocollo. Usa la connessione PostgreSQL **schema owner solo per seed, gate del test e lettura dell'esito**. Ciascuno dei due writer usa `comuni_app_runtime` non-owner, un proprio `DbContext`, la propria connessione SQL e una transazione con prova HMAC del Comune. Non vengono utilizzate organizzazioni reali, account IdP, chiavi di produzione o servizi Azure.

Il test sintetico:
1. Inserisce due Comuni A/B con Protocollo acceso. L'owner della fixture prende un `SELECT ... FOR UPDATE` sulla riga A ed evita che nessuno dei due worker possa aggiornare la stessa riga.
2. Avvia due toggle **disable** su connessioni runtime indipendenti; non rilascia il gate finché `pg_stat_activity` non osserva **entrambi in attesa di lock** per un nome applicativo random della sola fixture. Il gate è bounded con timeout e viene sempre rilasciato in `finally`.
3. Si aspetta una risposta `Updated` e una `Unchanged`, A disabilitato e **un solo audit di disabilitazione**. B resta abilitato e privo di eventi. Ripete analogamente con due toggle **enable**: un audit addizionale di abilitazione per A, B invariato.
4. Tutti i test di idempotenza sequenziale, blocchi di modulo planned, alterazione audit, cross-tenant RLS e login runtime esistenti devono continuare a passare.

Gate: prima un commit RED su `main` che mostri il difetto reale (due `Updated`/due audit o equivalente), poi implementazione GREEN senza aggirare le policy. Conclusione solo con **sette job GitHub Actions success sullo stesso SHA finale HEAD `main`**: PostgreSQL17/pgAudit incluso collector, xUnit backend, Playwright React, Terraform/Python, CodeQL C#/TS, NuGet/npm SCA e Docker image.

Il test controlla una concorrenza organizzata e riproducibile, non prova prestazioni a molti nodi, provider OIDC live, ETag, retention o integrità rispetto a un superuser DB.

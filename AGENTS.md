# Istruzioni per agenti di sviluppo

1. Operare **sempre su `main`**. Non creare branch né PR per il normale sviluppo; verificare prima lo stato corrente del branch.
2. **GitHub Issues come fonte di verità:** all'inizio di ogni turno controllare issue aperte/chiuse, priorità, dipendenze e ultima CI `main`; scegliere una issue, commentare lo stato e collegare commit con `#numero`. Creare issue per ogni modifica significativa non tracciata; chiuderla come completed soltanto dopo criteri di accettazione e CI verde. Non dichiarare di controllare in background; lo stato viene verificato durante le sessioni di lavoro.
3. Prima di introdurre modifiche architetturali leggere `adr/`, `docs/` e questo file. Ogni decisione nuova richiede un ADR.
4. Backend .NET 10: unica `Applications/Api`, use case in `Business`, regole ed entità pure in `Domains`, adapter e EF in `Infrastructures`. Vietate dipendenze Domains → Infrastructure/API.
5. Multi-organization **fail closed**: organization ID solo da JWT validato; ogni read/write deve essere confinato alla organization. Non esporre override tenant client-side. Controlli di ruolo e modulo lato API e Business.
6. Applicare rigorosamente TDD: test che fallisce (Red), implementazione minima (Green), refactor; includere test per tenant, ruolo, modulo. Non definire completata una feature con test non eseguiti o falliti.
7. UI React TypeScript, Vite PWA, Tailwind e componenti shadcn/ui. Tema chiaro/scuro, i18n it/en, navigazione autorizzata dal contesto API.
8. PostgreSQL ed EF Core con migrazioni versionate. No SQLite o database alternativo neppure nei test d'integrazione. Niente microservizi o code per il bootstrap.
9. Azure soltanto; Terraform dichiarativo, identità gestite e Key Vault. Segreti mai committati. Docker Compose è solo per locale.
10. Modificare documentazione, contratti API, test e codice nello stesso incremento. Segnalare chiaramente le verifiche non eseguite.
11. Non dichiarare conformità AgID, GDPR, SPID/CIE, ANPR, PagoPA o PDND prima di realizzare e verificare i requisiti pertinenti.
12. Ogni nuovo script PostgreSQL owner-only che legge input privati deve adottare COPY client-side statico e aggiornare il manifest `docs/security/owner-only-psql-private-input-inventory.json`, il test `tests/infra/test_owner_psql_copy_inventory.py`, gli xUnit pertinenti e l'ADR (ADR 0088). Vietati `psql :'value'`, echo input e bypass audit/privilegi.

## Comandi

- Backend: `dotnet test tests/backend/Comuni.UnitTests/Comuni.UnitTests.csproj` e `dotnet test tests/backend/Comuni.Api.Tests/Comuni.Api.Tests.csproj` (secondo comando richiede `TEST_DATABASE_CONNECTION`).
- Frontend: `npm ci && npm run build --workspace @comuni/frontend && npm run test:e2e --workspace @comuni/frontend`.
- Locale: `docker compose -f docker/compose.yml up --build`.

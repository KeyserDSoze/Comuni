# Istruzioni per agenti di sviluppo

1. Operare **sempre su `main`**. Non creare branch né PR per il normale sviluppo; verificare prima lo stato corrente del branch.
2. Prima di introdurre modifiche architetturali leggere `adr/`, `docs/` e questo file. Ogni decisione nuova richiede un ADR.
3. Backend .NET 10: unica `Applications/Api`, use case in `Business`, regole ed entità pure in `Domains`, adapter e EF in `Infrastructures`. Vietate dipendenze Domains → Infrastructure/API.
4. Multi-organization **fail closed**: organization ID solo da JWT validato; ogni read/write deve essere confinato alla organization. Non esporre override tenant client-side. Controlli di ruolo e modulo lato API e Business.
5. Applicare rigorosamente TDD: test che fallisce (Red), implementazione minima (Green), refactor; includere test per tenant, ruolo, modulo. Non definire completata una feature con test non eseguiti o falliti.
6. UI React TypeScript, Vite PWA, Tailwind e componenti shadcn/ui. Tema chiaro/scuro, i18n it/en, navigazione autorizzata dal contesto API.
7. PostgreSQL ed EF Core con migrazioni versionate. No SQLite o database alternativo neppure nei test d'integrazione. Niente microservizi o code per il bootstrap.
8. Azure soltanto; Terraform dichiarativo, identità gestite e Key Vault. Segreti mai committati. Docker Compose è solo per locale.
9. Modificare documentazione, contratti API, test e codice nello stesso incremento. Segnalare chiaramente le verifiche non eseguite.
10. Non dichiarare conformità AgID, GDPR, SPID/CIE, ANPR, PagoPA o PDND prima di realizzare e verificare i requisiti pertinenti.

## Comandi

- Backend: `dotnet test tests/backend/Comuni.UnitTests/Comuni.UnitTests.csproj` e `dotnet test tests/backend/Comuni.Api.Tests/Comuni.Api.Tests.csproj` (secondo comando richiede `TEST_DATABASE_CONNECTION`).
- Frontend: `cd src/frontend && npm ci && npm run build && npx playwright test`.
- Locale: `docker compose -f docker/compose.yml up --build`.
